"""Zabbix セキュリティアドバイザリ スクレイピングアダプター。

ソース: https://www.zabbix.com/security_advisories
方式: Playwright + Gemini Flash (vuln_scraper サービス経由)
ポーリング間隔: 6時間
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

from shared.vuln_schema import AffectedProduct, VulnEntry, cvss_to_severity

from .base import BaseSourceAdapter
from .scraper_client import scrape_url

logger = logging.getLogger(__name__)

_ZABBIX_ADVISORY_URL = "https://www.zabbix.com/security_advisories"

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_ZBX_PATTERN = re.compile(r"ZBX-\d{4,}", re.IGNORECASE)

_EXTRACTION_PROMPT = """以下の Zabbix セキュリティアドバイザリのページテキストから、
各脆弱性を JSON 配列で抽出してください。

各エントリに以下のフィールドを含めてください:
- vuln_id: CVE-ID (例: CVE-2024-1234)
- zbx_id: ZBX-ID (例: ZBX-25001)
- title: タイトル
- description: 説明
- severity: 深刻度 (Critical/High/Medium/Low)
- cvss_score: CVSS スコア (数値)
- affected_versions: 影響バージョン
- fixed_versions: 修正バージョン
- published_date: 公開日

JSON 配列のみを返してください。

ページテキスト:
"""


class ZabbixAdapter(BaseSourceAdapter):
    """Zabbix セキュリティアドバイザリ スクレイピングアダプター。"""

    source_id = "zabbix"
    default_poll_interval_minutes = 360  # 6時間

    def fetch_recent(self, since: datetime) -> list[VulnEntry]:
        """Zabbix アドバイザリページをスクレイピングして脆弱性を取得する。"""
        try:
            raw_vulns = scrape_url(
                url=_ZABBIX_ADVISORY_URL,
                source_id="zabbix",
                extraction_prompt=_EXTRACTION_PROMPT,
            )
        except Exception as exc:
            logger.error("Zabbix scrape failed: %s", exc)
            return []

        entries: list[VulnEntry] = []
        for raw in raw_vulns:
            entry = _normalize_zabbix_vuln(raw, since)
            if entry is not None:
                entries.append(entry)

        logger.info("Zabbix: %d entries scraped", len(entries))
        return entries


def _normalize_zabbix_vuln(raw: dict[str, Any], since: datetime) -> VulnEntry | None:
    """スクレイピング結果を VulnEntry に正規化する。"""
    vuln_id = (raw.get("vuln_id") or "").strip()
    zbx_id = (raw.get("zbx_id") or "").strip()
    title = (raw.get("title") or "").strip()
    description = (raw.get("description") or "").strip()
    severity_raw = (raw.get("severity") or "").strip()
    published = (raw.get("published_date") or "").strip()
    affected_versions = (raw.get("affected_versions") or "").strip()
    fixed_versions = (raw.get("fixed_versions") or "").strip()

    if not vuln_id and not zbx_id:
        return None

    # 日付フィルタ
    pub_dt = _parse_date(published)
    if pub_dt and pub_dt < since:
        return None

    # CVSS スコア
    cvss_score: float | None = None
    raw_score = raw.get("cvss_score")
    if raw_score is not None:
        try:
            cvss_score = float(raw_score)
        except (TypeError, ValueError):
            pass

    if cvss_score is None:
        cvss_score = _severity_label_to_cvss(severity_raw)

    # 主キー
    if not vuln_id:
        vuln_id = zbx_id
    aliases: list[str] = []
    if vuln_id != zbx_id and zbx_id:
        aliases.append(zbx_id)

    fixed_list = [v.strip() for v in fixed_versions.split(",") if v.strip()] if fixed_versions else []

    return VulnEntry(
        vuln_id=vuln_id,
        aliases=aliases,
        title=title or vuln_id,
        description=description,
        published=pub_dt.isoformat() if pub_dt else "",
        last_modified=pub_dt.isoformat() if pub_dt else "",
        source="zabbix",
        source_url=_ZABBIX_ADVISORY_URL,
        cvss_score=cvss_score,
        severity=cvss_to_severity(cvss_score),
        affected_products=[
            AffectedProduct(
                vendor="Zabbix",
                product="Zabbix",
                versions=affected_versions,
            )
        ],
        vendor_advisory_id=zbx_id or None,
        vendor_severity=severity_raw or None,
        vendor_fixed_versions=fixed_list,
    )


def _severity_label_to_cvss(label: str) -> float | None:
    """severity ラベルから概算 CVSS を返す。"""
    mapping = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5}
    return mapping.get(label.lower())


def _parse_date(date_str: str) -> datetime | None:
    """日付文字列をパースする。"""
    date_str = (date_str or "").strip()
    if not date_str:
        return None
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        pass
    # YYYY-MM-DD
    try:
        dt = datetime.strptime(date_str[:10], "%Y-%m-%d")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None
