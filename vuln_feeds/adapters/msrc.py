"""Microsoft Security Response Center (MSRC) アダプター。

ソース: https://msrc.microsoft.com/update-guide
API: MSRC CVRF API — https://api.msrc.microsoft.com/cvrf/v3.0/
差分取得: 月次セキュリティ更新 (Patch Tuesday) ベース
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from typing import Any

from shared.vuln_schema import AffectedProduct, VulnEntry, cvss_to_severity

from .base import BaseSourceAdapter, get_secret_value, http_get_json

logger = logging.getLogger(__name__)

_MSRC_API_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0"

# CVE-ID パターン
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class MsrcAdapter(BaseSourceAdapter):
    """Microsoft MSRC CVRF API アダプター。"""

    source_id = "msrc"
    default_poll_interval_minutes = 30

    def __init__(self) -> None:
        self._api_key = get_secret_value(
            ["MSRC_API_KEY"], secret_name="vuln-agent-msrc-api-key"
        )

    def fetch_recent(self, since: datetime) -> list[VulnEntry]:
        """MSRC API から since を含む月のセキュリティ更新を取得する。"""
        # MSRC は月次更新のため、since の年月を使用
        update_id = since.strftime("%Y-%b")  # e.g., "2024-Jun"

        headers: dict[str, str] = {}
        if self._api_key:
            headers["api-key"] = self._api_key

        try:
            updates = self._fetch_updates_list(headers)
        except Exception as exc:
            logger.error("MSRC updates list fetch failed: %s", exc)
            return []

        # since 以降の更新を特定
        target_updates = _filter_updates_since(updates, since)
        if not target_updates:
            logger.info("MSRC: no updates found since %s", since.isoformat())
            return []

        all_entries: list[VulnEntry] = []
        seen_ids: set[str] = set()

        for update_id in target_updates:
            try:
                entries = self._fetch_update_detail(update_id, headers, since)
                for entry in entries:
                    nid = entry.normalize_id()
                    if nid not in seen_ids:
                        seen_ids.add(nid)
                        all_entries.append(entry)
            except Exception as exc:
                logger.warning("MSRC update %s fetch failed: %s", update_id, exc)

        logger.info("MSRC: %d entries from %d updates", len(all_entries), len(target_updates))
        return all_entries

    def _fetch_updates_list(self, headers: dict[str, str]) -> list[dict[str, Any]]:
        """利用可能な更新一覧を取得する。"""
        url = f"{_MSRC_API_BASE}/updates"
        data = http_get_json(url, headers=headers)
        return data.get("value") or []

    def _fetch_update_detail(
        self, update_id: str, headers: dict[str, str], since: datetime
    ) -> list[VulnEntry]:
        """特定の更新に含まれる脆弱性詳細を取得する。"""
        url = f"{_MSRC_API_BASE}/cvrf/{update_id}"
        data = http_get_json(url, headers=headers)
        return _parse_cvrf_document(data, since)


def _filter_updates_since(
    updates: list[dict[str, Any]], since: datetime
) -> list[str]:
    """since 以降のアップデート ID を抽出する。"""
    result: list[str] = []
    for update in updates:
        update_id = (update.get("ID") or "").strip()
        release_date_str = (update.get("InitialReleaseDate") or "").strip()
        if not update_id:
            continue

        release_date = _parse_iso_date(release_date_str)
        if release_date and release_date >= since:
            result.append(update_id)

    return result


def _parse_cvrf_document(
    doc: dict[str, Any], since: datetime
) -> list[VulnEntry]:
    """CVRF ドキュメントから VulnEntry リストを生成する。"""
    entries: list[VulnEntry] = []

    vulnerabilities = doc.get("Vulnerability") or []
    product_tree = doc.get("ProductTree") or {}

    # ProductID → 製品名マッピング構築
    product_map = _build_product_map(product_tree)

    for vuln in vulnerabilities:
        entry = _normalize_msrc_vuln(vuln, product_map, since)
        if entry is not None:
            entries.append(entry)

    return entries


def _build_product_map(product_tree: dict[str, Any]) -> dict[str, str]:
    """ProductTree から ProductID → 製品名 のマッピングを構築する。"""
    product_map: dict[str, str] = {}

    # FullProductName
    for item in product_tree.get("FullProductName") or []:
        pid = (item.get("ProductID") or "").strip()
        name = (item.get("Value") or "").strip()
        if pid and name:
            product_map[pid] = name

    # Branch 内の製品
    for branch in product_tree.get("Branch") or []:
        _extract_branch_products(branch, product_map)

    return product_map


def _extract_branch_products(branch: dict[str, Any], product_map: dict[str, str]) -> None:
    """再帰的に Branch から製品を抽出する。"""
    for item in branch.get("Items") or []:
        if "ProductID" in item:
            pid = (item.get("ProductID") or "").strip()
            name = (item.get("Value") or "").strip()
            if pid and name:
                product_map[pid] = name
        if "Items" in item:
            _extract_branch_products(item, product_map)


def _normalize_msrc_vuln(
    vuln: dict[str, Any],
    product_map: dict[str, str],
    since: datetime,
) -> VulnEntry | None:
    """CVRF Vulnerability を VulnEntry に正規化する。"""
    cve_id = (vuln.get("CVE") or "").strip()
    if not cve_id or not _CVE_PATTERN.match(cve_id):
        return None

    title_elem = vuln.get("Title") or {}
    title = (title_elem.get("Value") or "").strip() if isinstance(title_elem, dict) else str(title_elem).strip()

    # Notes からDescription抽出
    description = ""
    for note in vuln.get("Notes") or []:
        if isinstance(note, dict):
            note_type = (note.get("Type") or "").strip()
            if note_type == "Description":
                description = (note.get("Value") or "").strip()
                break

    # RevisionHistory から日付取得
    revision_history = vuln.get("RevisionHistory") or []
    published = ""
    last_modified = ""
    for rev in revision_history:
        rev_date = (rev.get("Date") or "").strip()
        if rev_date:
            if not published:
                published = rev_date
            last_modified = rev_date

    # CVSS スコア
    cvss_score = _extract_msrc_cvss(vuln)
    severity = cvss_to_severity(cvss_score)

    # 影響製品
    products = _extract_msrc_products(vuln, product_map)

    # exploit 情報
    exploit_confirmed = False
    threats = vuln.get("Threats") or []
    for threat in threats:
        threat_type = (threat.get("Type") or "")
        desc = (threat.get("Description") or {})
        desc_val = (desc.get("Value") or "") if isinstance(desc, dict) else str(desc)
        if "Exploited:Yes" in desc_val or "exploitation detected" in desc_val.lower():
            exploit_confirmed = True

    return VulnEntry(
        vuln_id=cve_id,
        aliases=[],
        title=title or cve_id,
        description=description,
        published=published,
        last_modified=last_modified or published,
        source="msrc",
        source_url=f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}",
        cvss_score=cvss_score,
        severity=severity,
        affected_products=products,
        exploit_confirmed=exploit_confirmed,
        vendor_advisory_id=cve_id,
        vendor_severity=_extract_msrc_severity(vuln),
    )


def _extract_msrc_cvss(vuln: dict[str, Any]) -> float | None:
    """MSRC 脆弱性から CVSS スコアを抽出する。"""
    cvss_sets = vuln.get("CVSSScoreSets") or []
    for score_set in cvss_sets:
        base_score = score_set.get("BaseScore")
        if base_score is not None:
            try:
                return float(base_score)
            except (TypeError, ValueError):
                pass
    return None


def _extract_msrc_severity(vuln: dict[str, Any]) -> str | None:
    """MSRC 脆弱性からベンダーSeverityを抽出する。"""
    threats = vuln.get("Threats") or []
    for threat in threats:
        threat_type = threat.get("Type")
        if threat_type == 3:  # Impact
            desc = threat.get("Description") or {}
            return (desc.get("Value") or "") if isinstance(desc, dict) else str(desc)
    return None


def _extract_msrc_products(
    vuln: dict[str, Any], product_map: dict[str, str]
) -> list[AffectedProduct]:
    """MSRC 脆弱性から影響製品を抽出する。"""
    products: list[AffectedProduct] = []
    seen: set[str] = set()

    # ProductStatuses から抽出
    statuses = vuln.get("ProductStatuses") or []
    for status in statuses:
        for pid in status.get("ProductID") or []:
            pid = (pid or "").strip()
            if pid and pid not in seen:
                seen.add(pid)
                product_name = product_map.get(pid, pid)
                products.append(
                    AffectedProduct(
                        vendor="Microsoft",
                        product=product_name,
                    )
                )

    return products


def _parse_iso_date(date_str: str) -> datetime | None:
    """ISO8601 日付文字列をパースする。"""
    date_str = (date_str or "").strip()
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except ValueError:
        return None
