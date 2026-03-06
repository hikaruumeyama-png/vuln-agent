"""SKYSEA Client View セキュリティ情報 スクレイピングアダプター。

ソース: https://www.skyseaclientview.net/news/
方式: Playwright + Gemini Flash (vuln_scraper サービス経由)
ポーリング間隔: 6時間
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

from shared.vuln_schema import AffectedProduct, VulnEntry, cvss_to_severity

from .base import BaseSourceAdapter
from .scraper_client import scrape_url

logger = logging.getLogger(__name__)

_SKYSEA_URL = os.environ.get(
    "SKYSEA_ADVISORY_URL",
    "https://www.skyseaclientview.net/news/",
)

_EXTRACTION_PROMPT = """以下の SKYSEA Client View のニュース・セキュリティ情報ページから、
脆弱性・セキュリティアップデートに関する情報を JSON 配列で抽出してください。

各エントリに以下のフィールドを含めてください:
- vuln_id: CVE-ID があれば (例: CVE-2024-1234)、なければアドバイザリID
- title: タイトル
- description: 説明
- severity: 深刻度 (Critical/High/Medium/Low)
- affected_versions: 影響バージョン
- fixed_versions: 修正バージョン
- published_date: 公開日 (YYYY-MM-DD)
- source_url: 個別ページURL

JSON 配列のみを返してください。

ページテキスト:
"""


class SkySEAAdapter(BaseSourceAdapter):
    """SKYSEA Client View セキュリティ情報 スクレイピングアダプター。"""

    source_id = "skysea"
    default_poll_interval_minutes = 360  # 6時間

    def fetch_recent(self, since: datetime) -> list[VulnEntry]:
        """SKYSEA セキュリティページをスクレイピングして脆弱性を取得する。"""
        try:
            raw_vulns = scrape_url(
                url=_SKYSEA_URL,
                source_id="skysea",
                extraction_prompt=_EXTRACTION_PROMPT,
            )
        except Exception as exc:
            logger.error("SKYSEA scrape failed: %s", exc)
            return []

        entries: list[VulnEntry] = []
        for raw in raw_vulns:
            entry = _normalize_skysea_vuln(raw, since)
            if entry is not None:
                entries.append(entry)

        logger.info("SKYSEA: %d entries scraped", len(entries))
        return entries


def _normalize_skysea_vuln(raw: dict[str, Any], since: datetime) -> VulnEntry | None:
    """スクレイピング結果を VulnEntry に正規化する。"""
    vuln_id = (raw.get("vuln_id") or "").strip()
    title = (raw.get("title") or "").strip()
    description = (raw.get("description") or "").strip()
    severity_raw = (raw.get("severity") or "").strip()
    affected_versions = (raw.get("affected_versions") or "").strip()
    fixed_versions = (raw.get("fixed_versions") or "").strip()
    published = (raw.get("published_date") or "").strip()
    source_url = (raw.get("source_url") or "").strip()

    if not vuln_id and not title:
        return None
    if not vuln_id:
        vuln_id = title[:60]

    # 日付フィルタ
    pub_dt = _parse_date(published)
    if pub_dt and pub_dt < since:
        return None

    cvss_score = _severity_label_to_cvss(severity_raw)
    fixed_list = [v.strip() for v in fixed_versions.split(",") if v.strip()] if fixed_versions else []

    return VulnEntry(
        vuln_id=vuln_id,
        aliases=[],
        title=title or vuln_id,
        description=description,
        published=pub_dt.isoformat() if pub_dt else "",
        last_modified=pub_dt.isoformat() if pub_dt else "",
        source="skysea",
        source_url=source_url or _SKYSEA_URL,
        cvss_score=cvss_score,
        severity=cvss_to_severity(cvss_score),
        affected_products=[
            AffectedProduct(
                vendor="Sky",
                product="SKYSEA Client View",
                versions=affected_versions,
            )
        ],
        vendor_severity=severity_raw or None,
        vendor_fixed_versions=fixed_list,
    )


def _severity_label_to_cvss(label: str) -> float | None:
    mapping = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5}
    return mapping.get(label.lower())


def _parse_date(date_str: str) -> datetime | None:
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
    try:
        dt = datetime.strptime(date_str[:10], "%Y-%m-%d")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None
