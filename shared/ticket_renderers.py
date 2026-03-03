"""テンプレート整形・監査モジュール。"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable

from shared.constants import DEFAULT_REMEDIATION_TEXT, TICKET_FORBIDDEN_PHRASES
from shared.ticket_parsers import (
    has_ticket_sections,
    is_summary_low_quality,
    looks_like_internal_artifact,
)

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# 起票テンプレート組立
# ------------------------------------------------------------------


def infer_ticket_detail_from_facts(facts: dict[str, Any]) -> str:
    product_line = "\n".join(facts["products"]) if facts["products"] else "要確認"
    links = facts["vuln_links"] or ["要確認"]
    grouped_links: dict[str, list[str]] = {}
    pre_grouped = facts.get("grouped_vuln_links")
    if isinstance(pre_grouped, dict):
        for k, vals in pre_grouped.items():
            key = str(k or "").strip()
            if not key:
                continue
            urls = [str(v).strip() for v in (vals or []) if str(v).strip()]
            if urls:
                grouped_links[key] = list(dict.fromkeys(urls))
    for e in facts.get("entries", []):
        title = str(e.get("title") or "")
        url = str(e.get("url") or "").strip()
        if not url:
            continue
        m = re.search(r"(AlmaLinux\s*[0-9]{1,2})", title, re.IGNORECASE)
        key = m.group(1).replace(" ", "") if m else ""
        if key:
            grouped_links.setdefault(key, [])
            if url not in grouped_links[key]:
                grouped_links[key].append(url)
    if grouped_links:
        def _sort_key(k: str) -> tuple[int, str]:
            m = re.search(r"([0-9]{1,2})$", k)
            return (-(int(m.group(1)) if m else -1), k.lower())

        parts: list[str] = []
        for key in sorted(grouped_links.keys(), key=_sort_key):
            parts.append(key)
            parts.extend(grouped_links[key])
            parts.append("")
        links_line = "\n".join(parts).strip()
    else:
        links_line = "\n".join(links)
    if facts["scores"]:
        max_score = facts["max_score"]
        cvss_line = f"{max_score:.1f}"
    else:
        cvss_line = "要確認"
    split_note = ""
    if int(facts.get("due_group_count") or 1) > 1:
        split_note = (
            "\n\n【備考】\n"
            "通知内で納期が異なる脆弱性が含まれるため、本起票は同一納期グループでまとめています。"
        )

    return (
        "【対象の機器/アプリ】\n"
        f"{product_line}\n\n"
        "【脆弱性情報】（リンク貼り付け）\n"
        f"{links_line}\n\n"
        "【CVSSスコア】\n"
        f"{cvss_line}\n\n"
        "【依頼内容】\n"
        f"{facts.get('remediation_text') or DEFAULT_REMEDIATION_TEXT}\n\n"
        "【対応完了目標】\n"
        f"{facts.get('due_date') or '要確認'}"
        f"{split_note}"
    )


def infer_reasoning_from_facts(facts: dict[str, Any]) -> str:
    product_text = " / ".join(facts["products"]) if facts["products"] else "要確認"
    links_count = len(facts["vuln_links"])
    entries_count = len(facts.get("entries", []))
    all_entries_count = int(facts.get("all_entries_count") or entries_count)
    if facts["scores"]:
        scores_text = ", ".join(f"{s:.1f}" for s in facts["scores"])
    else:
        scores_text = "要確認"
    base = (
        "【判断理由】\n"
        f"- 通知本文から対象製品を抽出: {product_text}\n"
        f"- 通知本文から脆弱性エントリを抽出: {all_entries_count}件（起票対象: {entries_count}件）\n"
        f"- 参照URLを抽出: {links_count}件\n"
        f"- CVSSを抽出: {scores_text}\n"
        f"- SBOM照合で対象AlmaLinuxバージョンを適用: {', '.join(facts.get('sbom_alma_versions') or ['未適用'])}\n"
        f"- 対応完了目標を算出: {facts.get('due_date') or '要確認'}（{facts.get('due_reason') or '根拠不足'}）"
    )
    remediation_reasoning = str(facts.get("remediation_reasoning") or "").strip()
    remediation_risk = str(facts.get("remediation_risk_notes") or "").strip()
    if remediation_reasoning or remediation_risk:
        base += "\n\n【依頼内容チェック（AI）】"
        if remediation_reasoning:
            base += f"\n判定理由: {remediation_reasoning}"
        if remediation_risk:
            base += f"\n注意点: {remediation_risk}"
    return base


def build_ticket_text_from_parts(summary: str, detail: str, reasoning: str) -> str:
    return (
        "【起票用（コピペ）】\n"
        "大分類: 017.脆弱性対応（情シス専用）\n"
        "小分類: 002.IT基盤チーム\n"
        f"依頼概要: {summary}\n"
        f"詳細:\n{detail}\n\n"
        f"{reasoning}"
    ).strip()


# ------------------------------------------------------------------
# 監査
# ------------------------------------------------------------------


def audit_ticket_candidate(
    summary: str,
    detail: str,
    reasoning: str,
    facts: dict[str, Any] | None = None,
) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if not summary or is_summary_low_quality(summary):
        errors.append("summary_low_quality")
    for line in ("【対象の機器/アプリ】", "【脆弱性情報】", "【CVSSスコア】", "【依頼内容】", "【対応完了目標】"):
        if line not in detail:
            errors.append(f"missing_section:{line}")
    urls = re.findall(r"https?://[^\s)>\]|]+", detail)
    if not urls:
        errors.append("missing_url")
    if any(not (u.startswith("https://sid.softek.jp/filter/sinfo/") or "nvd.nist.gov" in u) for u in urls):
        errors.append("unexpected_url_domain")
    score_match = re.search(r"【CVSSスコア】\s*[\r\n]+([0-9](?:\.[0-9])?)", detail)
    if not score_match:
        errors.append("missing_cvss_numeric")
    else:
        try:
            v = float(score_match.group(1))
            if not (0.0 <= v <= 10.0):
                errors.append("cvss_out_of_range")
        except Exception:
            errors.append("cvss_parse_error")
    lowered = (summary + "\n" + detail + "\n" + reasoning).lower()
    for phrase in TICKET_FORBIDDEN_PHRASES:
        if phrase.lower() in lowered:
            errors.append(f"forbidden_phrase:{phrase}")
    if isinstance(facts, dict):
        # マルチバージョン監査: 通知内に実際に2バージョン以上のエントリがある場合のみ検査
        grouped = facts.get("grouped_vuln_links") or {}
        actual_versions_in_ticket = len(grouped) if isinstance(grouped, dict) else 0
        if actual_versions_in_ticket >= 2:
            alma_lines = re.findall(r"^AlmaLinux[0-9]{1,2}\s*$", detail, flags=re.MULTILINE)
            if len(set(alma_lines)) < 2:
                errors.append("missing_multiversion_target_lines")
            sid_urls = [u for u in urls if u.startswith("https://sid.softek.jp/filter/sinfo/")]
            if len(set(sid_urls)) < 2:
                errors.append("missing_multiversion_urls")
        all_entries_count = int(facts.get("all_entries_count") or 0)
        sid_links_count = len([u for u in (facts.get("vuln_links") or []) if str(u).startswith("https://sid.softek.jp/filter/sinfo/")])
        if all_entries_count == 0 and sid_links_count >= 2:
            errors.append("entry_extraction_inconsistent_with_links")
    return len(errors) == 0, errors


# ------------------------------------------------------------------
# AI最終レビュー（Agent Engine DIで呼び出し）
# ------------------------------------------------------------------


def ai_final_review_with_value_lock(
    summary: str,
    detail: str,
    reasoning: str,
    agent_query_fn: Callable[[str, str], str] | None = None,
    history_key: str = "pipeline",
) -> str:
    """AIで可読性を改善する。agent_query_fn が None の場合はスキップ。"""
    base_text = build_ticket_text_from_parts(summary, detail, reasoning)

    if agent_query_fn is None:
        return base_text

    prompt = (
        "以下の起票文を、値を変えずに可読性だけ改善してください。"
        "禁止: 値改変・項目追加削除。許可: 改行や句読点の軽微調整のみ。\n\n"
        f"{base_text}"
    )
    try:
        reviewed = agent_query_fn(prompt, history_key)
    except Exception as exc:
        logger.warning("AI final review failed, using base text: %s", exc)
        return base_text

    normalized = _format_ticket_like_response(reviewed, detail)
    if "【起票用（コピペ）】" not in normalized or "【判断理由】" not in normalized:
        return base_text

    # value-lock check
    required_tokens = [f"依頼概要: {summary}", "大分類: 017.脆弱性対応（情シス専用）", "小分類: 002.IT基盤チーム"]
    if any(tok not in normalized for tok in required_tokens):
        return base_text
    base_cvss = re.search(r"【CVSSスコア】\s*[\r\n]+([0-9](?:\.[0-9])?)", base_text)
    norm_cvss = re.search(r"【CVSSスコア】\s*[\r\n]+([0-9](?:\.[0-9])?)", normalized)
    if base_cvss and (not norm_cvss or norm_cvss.group(1) != base_cvss.group(1)):
        return base_text
    base_due = re.search(r"【対応完了目標】\s*[\r\n]*(.+)", base_text)
    norm_due = re.search(r"【対応完了目標】\s*[\r\n]*(.+)", normalized)
    if base_due and (not norm_due or norm_due.group(1).strip() != base_due.group(1).strip()):
        return base_text
    base_urls = set(re.findall(r"https://sid\.softek\.jp/filter/sinfo/\d+", base_text))
    norm_urls = set(re.findall(r"https://sid\.softek\.jp/filter/sinfo/\d+", normalized))
    if base_urls and base_urls != norm_urls:
        return base_text
    base_reason_match = re.search(r"【判断理由】[\s\S]*$", base_text)
    norm_reason_match = re.search(r"【判断理由】[\s\S]*$", normalized)
    if base_reason_match:
        if not norm_reason_match or norm_reason_match.group(0).strip() != base_reason_match.group(0).strip():
            return base_text
    return normalized


def _format_ticket_like_response(text: str, source_detail: str = "") -> str:
    """AIレビュー結果を起票フォーマットに整形する。"""
    body = (text or "").strip()
    if not body:
        return body
    if looks_like_internal_artifact(body):
        return ""
    has_copy = "【起票用（コピペ）】" in body
    has_reason = "【判断理由】" in body
    if has_copy and has_reason:
        return body
    return body


# ------------------------------------------------------------------
# 悪用脆弱性用メッセージ
# ------------------------------------------------------------------


def build_exploited_update_message(analysis: dict[str, Any]) -> str:
    """悪用された脆弱性に対するアップデート推奨メッセージ。"""
    product = analysis.get("product_name") or "（不明）"
    cves = analysis.get("cve_ids") or []
    cve_str = ", ".join(cves) if cves else "（CVE番号なし）"
    comment = analysis.get("comment") or ""
    lines = [
        "⚠ 悪用が確認された脆弱性です。速やかなアップデートを推奨します。",
        "",
        f"【対象製品】\n{product}",
        "",
        f"【CVE】\n{cve_str}",
    ]
    if comment:
        lines.append("")
        lines.append(f"【AIコメント】\n{comment}")
    lines.append("")
    lines.append("速やかに最新バージョンへのアップデートをお願いします。")
    return "\n".join(lines)


def build_exploited_not_target_message(analysis: dict[str, Any]) -> str:
    """悪用された脆弱性だがWindows/Apple以外 → 対応不要メッセージ。"""
    product = analysis.get("product_name") or "（不明）"
    return (
        "ℹ️ 対応不要\n\n"
        "対応不要と判断しました。\n\n"
        f"【検出された製品】\n{product}\n\n"
        "【判断理由】\nWindows / Apple 以外の製品のため、対応対象外です。"
    )


def build_update_notification_message(analysis: dict[str, Any]) -> str:
    """脆弱性情報の更新通知に対するアップデート確認メッセージ。"""
    product = analysis.get("product_name") or "（不明）"
    cves = analysis.get("cve_ids") or []
    cve_str = ", ".join(cves) if cves else "（CVE番号なし）"
    comment = analysis.get("comment") or ""
    lines = [
        "脆弱性情報の更新通知です。内容を確認の上、アップデートの要否を判断してください。",
        "",
        f"【対象製品】\n{product}",
        "",
        f"【CVE】\n{cve_str}",
    ]
    if comment:
        lines.append("")
        lines.append(f"【AIコメント】\n{comment}")
    lines.append("")
    lines.append("必要に応じて最新バージョンへのアップデートをご検討ください。")
    return "\n".join(lines)


def build_update_not_target_message(analysis: dict[str, Any]) -> str:
    """脆弱性情報の更新通知だがWindows/Apple以外 → 対応不要メッセージ。"""
    product = analysis.get("product_name") or "（不明）"
    return (
        "ℹ️ 対応不要\n\n"
        "対応不要と判断しました。\n\n"
        f"【検出された製品】\n{product}\n\n"
        "【判断理由】\nWindows / Apple 以外の製品のため、対応対象外です。"
    )


def build_low_quality_ticket_message() -> str:
    return (
        "起票データの根拠情報が不足しているため、このままでは誤起票の可能性があります。\n"
        "次の形式で同一スレッドに貼り付けてください。\n\n"
        "1) 脆弱性通知本文（CVE / CVSS / 対象製品 / 参照URL を含む）\n"
        "2) 最後に「この内容で起票用を作成して」と送信\n\n"
        "十分な情報が確認でき次第、起票用データを再生成します。"
    )
