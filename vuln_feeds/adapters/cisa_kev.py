"""CISA Known Exploited Vulnerabilities (KEV) Catalog アダプター。

ソース: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
API: JSON catalog (全件ダウンロード)
特徴: 悪用が確認された脆弱性のみを収録。exploit_confirmed=True が確定。
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from shared.vuln_schema import AffectedProduct, VulnEntry, cvss_to_severity

from .base import BaseSourceAdapter, http_get_json

logger = logging.getLogger(__name__)

_KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CisaKevAdapter(BaseSourceAdapter):
    """CISA KEV Catalog アダプター。

    KEV カタログは JSON 全件ダウンロード方式。
    差分取得 API がないため、全件取得して since 以降をフィルタする。
    """

    source_id = "cisa_kev"
    default_poll_interval_minutes = 30

    def fetch_recent(self, since: datetime) -> list[VulnEntry]:
        """KEV カタログから since 以降に追加されたエントリを取得する。"""
        try:
            catalog = http_get_json(_KEV_CATALOG_URL)
        except Exception as exc:
            logger.error("CISA KEV catalog fetch failed: %s", exc)
            return []

        vulnerabilities = catalog.get("vulnerabilities") or []
        logger.info(
            "CISA KEV: fetched catalog with %d total entries", len(vulnerabilities)
        )

        entries: list[VulnEntry] = []
        for vuln in vulnerabilities:
            entry = _normalize_kev_entry(vuln)
            if entry is None:
                continue

            # dateAdded でフィルタ
            date_added = _parse_date(vuln.get("dateAdded", ""))
            if date_added and date_added < since:
                continue

            entries.append(entry)

        logger.info("CISA KEV: %d new entries since %s", len(entries), since.isoformat())
        return entries


def _normalize_kev_entry(vuln: dict[str, Any]) -> VulnEntry | None:
    """KEV エントリを VulnEntry に正規化する。"""
    cve_id = (vuln.get("cveID") or "").strip()
    if not cve_id:
        return None

    vendor = (vuln.get("vendorProject") or "").strip()
    product = (vuln.get("product") or "").strip()
    vuln_name = (vuln.get("vulnerabilityName") or "").strip()
    short_desc = (vuln.get("shortDescription") or "").strip()
    date_added = (vuln.get("dateAdded") or "").strip()
    due_date = (vuln.get("dueDate") or "").strip()
    known_ransomware = (vuln.get("knownRansomwareCampaignUse") or "").strip()
    notes = (vuln.get("notes") or "").strip()

    # KEV にはCVSSスコアが含まれないため None
    # NVD アダプターで補完されることを想定
    title = vuln_name or f"{vendor} {product} vulnerability"
    description = short_desc
    if known_ransomware and known_ransomware.lower() == "known":
        description += " [ランサムウェアキャンペーンでの悪用確認]"
    if notes:
        description += f" ({notes})"

    affected = []
    if vendor or product:
        affected.append(
            AffectedProduct(
                vendor=vendor,
                product=product,
            )
        )

    return VulnEntry(
        vuln_id=cve_id,
        aliases=[],
        title=title,
        description=description,
        published=_to_iso(date_added),
        last_modified=_to_iso(date_added),
        source="cisa_kev",
        source_url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        cvss_score=None,  # KEV にはスコアなし
        severity="低",  # NVD補完前のデフォルト
        exploit_confirmed=True,  # KEV 掲載 = 悪用確認済み
        exploit_code_public=False,  # KEV では明示されない
        kev_due_date=due_date,
        affected_products=affected,
        vendor_advisory_id=None,
        vendor_severity=None,
        vendor_fixed_versions=[],
    )


def _parse_date(date_str: str) -> datetime | None:
    """YYYY-MM-DD 形式の日付を UTC datetime に変換する。"""
    date_str = (date_str or "").strip()
    if not date_str:
        return None
    try:
        from datetime import timezone
        return datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _to_iso(date_str: str) -> str:
    """YYYY-MM-DD を ISO8601 形式に変換する。"""
    dt = _parse_date(date_str)
    if dt is None:
        return ""
    return dt.isoformat()
