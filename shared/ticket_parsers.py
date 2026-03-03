"""正規表現パーサー群（外部API呼び出しなし）。"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from shared.constants import (
    MSG_FORMAT_EXPLOITED,
    MSG_FORMAT_SIDFM,
    MSG_FORMAT_UNKNOWN,
    PRODUCT_EXTRACT_PATTERNS,
)

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# テキスト判定ユーティリティ
# ------------------------------------------------------------------


def looks_like_internal_artifact(text: str) -> bool:
    """モデル内部のアーティファクト（ツール呼び出し名、メタデータ等）を判定する。"""
    t = (text or "").strip()
    if not t:
        return False
    lowered = t.lower()
    bad_tokens = (
        "gemini-",
        "tool_code",
        "tool code",
        "tool_name",
        "on_demand",
        "<ctrl",
        "function_call",
        "assistant_response",
    )
    if any(token in lowered for token in bad_tokens):
        return True
    if re.search(r"<[^>]{2,32}>", t):
        return True
    return False


def contains_specific_vuln_signal(text: str) -> bool:
    t = (text or "").lower()
    if not t:
        return False
    if re.search(r"\bcve-\d{4}-\d{4,9}\b", t):
        return True
    if re.search(r"\bghsa-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}\b", t):
        return True
    if "cvss" in t:
        return True
    if "sid.softek.jp" in t or "nvd.nist.gov" in t:
        return True
    vuln_domains = (
        "cve.mitre.org",
        "security-next.com",
        "fortiguard.com",
        "sec.cloudapps.cisco.com",
        "motex.co.jp",
        "jvn.jp",
        "jpcert.or.jp",
        "redhat.com",
        "ubuntu.com",
        "debian.org",
        "github.com/advisories",
        "osv.dev",
        "nvd.nist.gov",
    )
    if any(domain in t for domain in vuln_domains):
        return True
    if "脆弱性" in text and ("http://" in t or "https://" in t):
        return True
    return False


def is_summary_low_quality(summary: str) -> bool:
    weak_summary_tokens = (
        "はい、承知",
        "承知いたしました",
        "ご依頼のメール内容",
        "判断しました",
        "以下に",
        "テンプレート",
        "作成します",
    )
    return (
        (not summary)
        or len(summary) < 10
        or any(token in summary for token in weak_summary_tokens)
        or ("脆弱性" not in summary and "ペネトレ" not in summary and "アップグレード" not in summary)
    )


def has_ticket_sections(text: str) -> bool:
    body = (text or "").strip()
    return "【起票用（コピペ）】" in body and "【判断理由】" in body


def is_low_quality_ticket_output(text: str) -> bool:
    body = (text or "").strip()
    if not body:
        return True
    if "【起票用（コピペ）】" not in body:
        return True
    if "詳細: 要確認" not in body:
        return False
    weak_phrases = ("承知", "了解", "テンプレート", "以下に", "作成します")
    if any(phrase in body for phrase in weak_phrases) and not contains_specific_vuln_signal(body):
        return True
    return False


# ------------------------------------------------------------------
# メッセージフォーマット分類
# ------------------------------------------------------------------


def classify_message_format(text: str) -> str:
    """通知メッセージのフォーマットを分類する。"""
    t = (text or "").strip()
    head = t[:500]
    if "【悪用された脆弱性】" in head:
        return MSG_FORMAT_EXPLOITED
    if "[SIDfm]" in head:
        return MSG_FORMAT_SIDFM
    return MSG_FORMAT_UNKNOWN


# ------------------------------------------------------------------
# SIDfm エントリ抽出
# ------------------------------------------------------------------


def extract_sidfm_entries(source_text: str) -> list[dict[str, Any]]:
    text = (source_text or "").strip()
    if not text:
        return []

    # 不可視Unicode文字を正規化
    text = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff]", "", text)
    text = re.sub(r"[\u00a0\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u205f\u3000]", " ", text)

    # Google Chat が単一行で配信する場合の改行復元
    if text.count("\n") < 5 and len(text) > 300:
        text = re.sub(r"(?<=\s)(\d{1,2}\s+\d{5,8}\s+(?:10(?:\.\d{1,2})?|[0-9](?:\.\d{1,2})?)\s+)", r"\n\1", text)
        text = re.sub(r"(?=○No\.\d)", "\n", text)
        text = re.sub(r"(?=ID:\d{4,8})", "\n", text)
        text = re.sub(r"(?=https://sid\.softek\.jp/filter/sinfo/\d)", "\n", text)
        text = re.sub(r"(?=◆――)", "\n", text)
        text = re.sub(r"(?=―――――)", "\n", text)
        logger.warning("[diag:sidfm] single-line text detected, restored line breaks: lines_after=%d", text.count("\n") + 1)

    entries: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    lines = text.splitlines()
    logger.warning("[diag:sidfm] total_lines=%d first_200_chars=%r", len(lines), text[:200])

    # 1) SIDfm一覧テーブル: "1 62977  9.4 AlmaLinux ..."
    row_pat = re.compile(r"^\s*\d+\s+(\d{4,8})\s+(10(?:\.\d{1,2})?|[0-9](?:\.\d{1,2})?)\s+(.+?)\s*$")
    candidate_lines = [raw for raw in lines if re.search(r"\d{4,8}", raw) and re.search(r"[0-9]\.[0-9]", raw)]
    logger.warning("[diag:sidfm] candidate_lines_with_id_and_cvss=%d samples=%r", len(candidate_lines), candidate_lines[:5])
    for raw in lines:
        m = row_pat.match(raw)
        if not m:
            continue
        vuln_id, cvss_s, title = m.group(1), m.group(2), m.group(3).strip()
        if vuln_id in seen_ids:
            continue
        seen_ids.add(vuln_id)
        try:
            cvss = float(cvss_s)
        except Exception:
            cvss = None
        entries.append({"id": vuln_id, "cvss": cvss, "title": title, "url": f"https://sid.softek.jp/filter/sinfo/{vuln_id}"})

    # 2) 本文ブロック: "ID:62977 ... CVSSv3: 9.4"
    block_pat = re.compile(r"ID:(\d{4,8}).*?CVSSv3:\s*(10(?:\.\d{1,2})?|[0-9](?:\.\d{1,2})?)", re.IGNORECASE)
    for i, raw in enumerate(lines):
        m = block_pat.search(raw)
        if not m:
            continue
        vuln_id, cvss_s = m.group(1), m.group(2)
        if vuln_id in seen_ids:
            continue
        try:
            cvss = float(cvss_s)
        except Exception:
            cvss = None
        title = ""
        url = ""
        for j in range(i + 1, min(i + 12, len(lines))):
            candidate = lines[j].strip()
            if not candidate:
                continue
            if not title and "http" not in candidate and "AlmaLinux" in candidate:
                title = re.sub(r"\s+", " ", candidate).strip()
            if "https://sid.softek.jp/filter/sinfo/" in candidate:
                url = re.search(r"https://sid\.softek\.jp/filter/sinfo/\d+", candidate).group(0)  # type: ignore[union-attr]
                break
        if not url:
            url = f"https://sid.softek.jp/filter/sinfo/{vuln_id}"
        seen_ids.add(vuln_id)
        entries.append({"id": vuln_id, "cvss": cvss, "title": title or "要確認", "url": url})

    # 3) SIDfm ID without index: "62977  9.4 AlmaLinux ..."
    noindex_pat = re.compile(r"^\s*(\d{5,8})\s+(10(?:\.\d{1,2})?|[0-9](?:\.\d{1,2})?)\s+(.+?)\s*$")
    for raw in lines:
        m = noindex_pat.match(raw)
        if not m:
            continue
        vuln_id, cvss_s, title = m.group(1), m.group(2), m.group(3).strip()
        if vuln_id in seen_ids:
            continue
        seen_ids.add(vuln_id)
        try:
            cvss = float(cvss_s)
        except Exception:
            cvss = None
        entries.append({"id": vuln_id, "cvss": cvss, "title": title, "url": f"https://sid.softek.jp/filter/sinfo/{vuln_id}"})

    logger.warning("[diag:sidfm] extracted_entries=%d entries=%r", len(entries), [(e.get("id"), e.get("cvss"), e.get("title", "")[:40]) for e in entries])

    def _key(item: dict[str, Any]) -> tuple[float, str]:
        score = item.get("cvss")
        return (float(score) if isinstance(score, (int, float)) else -1.0, str(item.get("id") or ""))

    return sorted(entries, key=_key, reverse=True)


# ------------------------------------------------------------------
# AlmaLinux バージョン・リンク関連
# ------------------------------------------------------------------


def extract_almalinux_versions_from_text(text: str) -> list[str]:
    versions = sorted(
        {m.group(1) for m in re.finditer(r"almalinux\s*([0-9]{1,2})", text or "", re.IGNORECASE)},
        key=lambda x: int(x),
        reverse=True,
    )
    return versions


def build_entries_from_sid_links_fallback(source_text: str, sid_links: list[str]) -> list[dict[str, Any]]:
    if not sid_links:
        return []
    text = source_text or ""
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for link in sid_links:
        m = re.search(r"/sinfo/(\d+)", link)
        if not m:
            continue
        vuln_id = m.group(1)
        if vuln_id in seen:
            continue
        seen.add(vuln_id)
        cvss = None
        ver = ""
        title = "要確認"
        block_pat = re.compile(
            rf"(?:ID[:：]\s*{re.escape(vuln_id)}.*?CVSSv3[:：]?\s*([0-9](?:\.[0-9])?).*?AlmaLinux\s*([0-9]{{1,2}}).*?{re.escape(link)})",
            re.IGNORECASE | re.DOTALL,
        )
        bm = block_pat.search(text)
        if bm:
            try:
                cvss = float(bm.group(1))
            except Exception:
                cvss = None
            ver = str(bm.group(2) or "").strip()
            title = f"AlmaLinux {ver} の脆弱性" if ver else "AlmaLinux の脆弱性"
        entries.append(
            {
                "id": vuln_id,
                "cvss": cvss,
                "title": title,
                "url": link,
                "os_version": ver or "要確認",
            }
        )
    return entries


def group_sid_links_by_almalinux_version(source_text: str, sid_links: list[str]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    text = source_text or ""
    for link in sid_links:
        link = str(link or "").strip()
        if not link:
            continue
        escaped = re.escape(link)
        mm = re.search(
            rf"(AlmaLinux\s*([0-9]{{1,2}}).{{0,260}}?{escaped}|{escaped}.{{0,260}}?AlmaLinux\s*([0-9]{{1,2}}))",
            text,
            re.IGNORECASE | re.DOTALL,
        )
        version = ""
        if mm:
            version = str(mm.group(2) or mm.group(3) or "").strip()
        if not version:
            id_match = re.search(r"/sinfo/(\d+)", link)
            vuln_id = id_match.group(1) if id_match else ""
            if vuln_id:
                vm = re.search(
                    rf"ID[:：]\s*{re.escape(vuln_id)}.*?AlmaLinux\s*([0-9]{{1,2}})",
                    text,
                    re.IGNORECASE | re.DOTALL,
                )
                if vm:
                    version = str(vm.group(1) or "").strip()
        if version:
            key = f"AlmaLinux{version}"
            grouped.setdefault(key, [])
            if link not in grouped[key]:
                grouped[key].append(link)
    return grouped


# ------------------------------------------------------------------
# 製品名抽出
# ------------------------------------------------------------------


def extract_product_names_quick(text: str) -> list[str]:
    """通知テキストから製品名を軽量抽出（SBOM照合用）。"""
    lowered = (text or "").lower()
    products: list[str] = []
    if "almalinux" in lowered:
        products.append("AlmaLinux")
    if re.search(r"fortios|fortigate", lowered):
        products.append("FortiGate")
    if re.search(r"cisco\s*asa", lowered):
        products.append("Cisco")
    for pattern, name in PRODUCT_EXTRACT_PATTERNS:
        if re.search(pattern, lowered):
            if name not in products:
                products.append(name)
    return products


def check_product_in_sbom(product_name: str, sbom_names: set[str]) -> bool:
    """SIDfmの製品名がSBOMに登録されているか柔軟にマッチング。"""
    lowered = product_name.lower().strip()
    if not lowered:
        return False
    for sbom_name in sbom_names:
        if lowered in sbom_name or sbom_name in lowered:
            return True
    return False


# ------------------------------------------------------------------
# 依頼概要推定
# ------------------------------------------------------------------


def infer_request_summary_from_source(source_text: str) -> str:
    text = (source_text or "").strip()
    if not text:
        return "脆弱性確認及び該当バージョンの対応願い"
    lower = text.lower()
    product_patterns = [
        (r"almalinux", "AlmaLinux"),
        (r"fortios|fortigate", "FortiOS"),
        (r"cisco\s*asa", "Cisco ASA"),
        (r"amazon\s*linux", "Amazon Linux"),
        (r"lanscope", "LANSCOPE"),
        (r"\bios\b|iphone", "Apple iOS"),
        (r"windows", "Windows"),
    ]
    for pattern, name in product_patterns:
        if re.search(pattern, lower):
            if name == "Apple iOS":
                return "Apple iOS のアップグレード"
            return f"{name} の脆弱性確認及び該当バージョンの対応願い"
    return "脆弱性確認及び該当バージョンの対応願い"


# ------------------------------------------------------------------
# 期限算出
# ------------------------------------------------------------------


def extract_base_date_from_source(source_text: str) -> datetime:
    text = (source_text or "").strip()
    m = re.search(r"SIDfm\s*\((\d{4})/(\d{2})/(\d{2})\)", text)
    if m:
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
        try:
            return datetime(y, mo, d, tzinfo=timezone.utc)
        except Exception:
            pass
    return datetime.now(timezone.utc)


def add_business_days(base: datetime, days: int) -> datetime:
    current = base
    added = 0
    while added < max(0, days):
        current = current + timedelta(days=1)
        if current.weekday() < 5:
            added += 1
    return current


def infer_due_date_from_policy(source_text: str, max_cvss: float | None) -> tuple[str, str]:
    base = extract_base_date_from_source(source_text)
    text = (source_text or "").lower()
    exploit_signal = ("悪用実績" in source_text) or ("エクスプロイトコード" in source_text) or ("exploit" in text)
    is_public_resource = any(token in text for token in ("fortigate", "cisco asa", "zeem", "メールサーバ", "mail server", "公開サーバ", "公開リソース", "インターネット公開", "dmz", "almalinux 9", "almalinux9"))

    if max_cvss is None or max_cvss < 8.0:
        return "対応不要", "CVSS 8.0未満または不明のため対応不要"
    if is_public_resource and max_cvss >= 9.0 and exploit_signal:
        due = add_business_days(base, 5)
        return due.strftime("%Y/%m/%d"), "社内方針: 公開リソース×CVSS9.0以上×悪用実績あり(5営業日)"
    if is_public_resource and max_cvss >= 8.0:
        due = add_business_days(base, 10)
        return due.strftime("%Y/%m/%d"), "社内方針: 公開リソース×CVSS8.0以上(10営業日)"
    month = base.month + 3
    year = base.year + (month - 1) // 12
    month = ((month - 1) % 12) + 1
    day = min(base.day, 28)
    due = datetime(year, month, day, tzinfo=timezone.utc)
    return due.strftime("%Y/%m/%d"), "社内方針: 内部リソース×CVSS8.0以上(3か月)"


# ------------------------------------------------------------------
# JSON抽出ユーティリティ
# ------------------------------------------------------------------


def extract_first_json_object(text: str) -> str:
    body = (text or "").strip()
    if not body:
        return ""
    start = body.find("{")
    if start < 0:
        return ""
    depth = 0
    for i in range(start, len(body)):
        ch = body[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return body[start : i + 1]
    return ""
