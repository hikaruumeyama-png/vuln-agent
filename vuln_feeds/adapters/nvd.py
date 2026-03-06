"""NIST NVD API v2.0 アダプター。

ソース: https://nvd.nist.gov/developers/vulnerabilities
API: REST v2.0 (lastModStartDate / lastModEndDate で差分取得)
APIキー: あり (vuln-agent-nvd-api-key)。キーなしだと 5 req/30sec、ありだと 50 req/30sec。
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any
from urllib import parse

from shared.vuln_schema import AffectedProduct, VulnEntry, cvss_to_severity

from .base import BaseSourceAdapter, http_get_json, get_secret_value

logger = logging.getLogger(__name__)

_NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_RESULTS_PER_PAGE = 100
# APIキーなし: 5 req / 30 sec = 6秒間隔、APIキーあり: 50 req / 30 sec = 0.6秒間隔
_RATE_LIMIT_NO_KEY = 6.0
_RATE_LIMIT_WITH_KEY = 0.7


class NvdAdapter(BaseSourceAdapter):
    """NIST NVD API v2.0 アダプター。"""

    source_id = "nvd"
    default_poll_interval_minutes = 30

    def __init__(self) -> None:
        raw_key = get_secret_value(
            ["NVD_API_KEY"],
            secret_name="vuln-agent-nvd-api-key",
        )
        # placeholder やダミー値は無効として扱う
        self._api_key = raw_key if raw_key and raw_key != "placeholder" else ""

    def fetch_recent(self, since: datetime) -> list[VulnEntry]:
        """NVD API から since 以降に更新された CVE を差分取得する。"""
        now = datetime.now(timezone.utc)
        # NVD API は UTC の ISO8601 フォーマットを要求
        start = since.strftime("%Y-%m-%dT%H:%M:%S.000")
        end = now.strftime("%Y-%m-%dT%H:%M:%S.000")

        entries: list[VulnEntry] = []
        start_index = 0
        rate_limit = _RATE_LIMIT_WITH_KEY if self._api_key else _RATE_LIMIT_NO_KEY

        while True:
            params: dict[str, str | int] = {
                "lastModStartDate": start,
                "lastModEndDate": end,
                "resultsPerPage": _RESULTS_PER_PAGE,
                "startIndex": start_index,
            }
            url = f"{_NVD_API_BASE}?{parse.urlencode(params)}"
            headers: dict[str, str] = {}
            if self._api_key:
                headers["apiKey"] = self._api_key

            try:
                payload = http_get_json(url, headers=headers)
            except Exception as exc:
                logger.error(
                    "NVD API fetch failed (startIndex=%d): %s", start_index, exc
                )
                break

            vulnerabilities = payload.get("vulnerabilities") or []
            total_results = payload.get("totalResults", 0)

            for vuln_wrapper in vulnerabilities:
                entry = _normalize_nvd_entry(vuln_wrapper)
                if entry is not None:
                    entries.append(entry)

            start_index += len(vulnerabilities)
            logger.info(
                "NVD: fetched %d/%d (startIndex=%d)",
                len(entries),
                total_results,
                start_index,
            )

            if start_index >= total_results or not vulnerabilities:
                break

            # レート制限
            time.sleep(rate_limit)

        logger.info("NVD: %d entries since %s", len(entries), since.isoformat())
        return entries


def _normalize_nvd_entry(vuln_wrapper: dict[str, Any]) -> VulnEntry | None:
    """NVD API レスポンスの1件を VulnEntry に正規化する。"""
    cve = vuln_wrapper.get("cve") or {}
    cve_id = (cve.get("id") or "").strip()
    if not cve_id:
        return None

    descriptions = cve.get("descriptions") or []
    description = _pick_description(descriptions)

    metrics = cve.get("metrics") or {}
    cvss_info = _extract_cvss(metrics)
    cvss_score = cvss_info.get("base_score")
    cvss_vector = cvss_info.get("vector_string")
    severity = cvss_to_severity(cvss_score)

    references = cve.get("references") or []
    source_url = ""
    for ref in references:
        url = (ref.get("url") or "").strip()
        if url:
            source_url = url
            break
    if not source_url:
        source_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    # 影響製品 (configurations/nodes から CPE を抽出)
    affected = _extract_affected_products(cve.get("configurations") or [])

    # エイリアス: NVD は sourceIdentifier に GHSA 等が入ることがある
    aliases: list[str] = []
    source_identifier = (cve.get("sourceIdentifier") or "").strip()
    if source_identifier and source_identifier != cve_id:
        if source_identifier.startswith("GHSA-") or source_identifier.startswith("CVE-"):
            aliases.append(source_identifier)

    published = (cve.get("published") or "").strip()
    last_modified = (cve.get("lastModified") or "").strip()

    return VulnEntry(
        vuln_id=cve_id,
        aliases=aliases,
        title=description[:200] if description else cve_id,
        description=description,
        published=published,
        last_modified=last_modified,
        source="nvd",
        source_url=source_url,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        severity=severity,
        exploit_confirmed=False,  # NVD 単体では悪用情報なし (KEV で補完)
        exploit_code_public=False,
        kev_due_date=None,
        affected_products=affected,
    )


def _pick_description(descriptions: list[dict[str, Any]]) -> str:
    """NVD の descriptions から英語説明を優先して取得する。"""
    if not descriptions:
        return ""
    en = [d for d in descriptions if (d.get("lang") or "").lower() == "en"]
    target = en[0] if en else descriptions[0]
    return (target.get("value") or "").strip()


def _extract_cvss(metrics: dict[str, Any]) -> dict[str, Any]:
    """NVD metrics から CVSS 情報を抽出する。v3.1 > v3.0 > v2 の優先順。"""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key) or []
        if not metric_list:
            continue
        first = metric_list[0] if isinstance(metric_list[0], dict) else {}
        cvss_data = first.get("cvssData") or {}
        return {
            "version": cvss_data.get("version"),
            "base_score": cvss_data.get("baseScore"),
            "base_severity": cvss_data.get("baseSeverity") or first.get("baseSeverity"),
            "vector_string": cvss_data.get("vectorString"),
        }
    return {}


def _extract_affected_products(
    configurations: list[dict[str, Any]],
) -> list[AffectedProduct]:
    """NVD configurations から影響製品リストを抽出する。"""
    products: list[AffectedProduct] = []
    seen_cpes: set[str] = set()

    for config in configurations:
        for node in config.get("nodes") or []:
            for cpe_match in node.get("cpeMatch") or []:
                criteria = (cpe_match.get("criteria") or "").strip()
                if not criteria or criteria in seen_cpes:
                    continue
                if not cpe_match.get("vulnerable", False):
                    continue
                seen_cpes.add(criteria)

                parts = criteria.split(":")
                # cpe:2.3:a:vendor:product:version:...
                vendor = parts[3] if len(parts) > 3 else ""
                product = parts[4] if len(parts) > 4 else ""
                version = parts[5] if len(parts) > 5 else "*"

                version_range = ""
                vs = (cpe_match.get("versionStartIncluding") or "").strip()
                ve = (cpe_match.get("versionEndExcluding") or "").strip()
                vei = (cpe_match.get("versionEndIncluding") or "").strip()
                if vs and ve:
                    version_range = f">={vs}, <{ve}"
                elif vs and vei:
                    version_range = f">={vs}, <={vei}"
                elif ve:
                    version_range = f"<{ve}"
                elif vei:
                    version_range = f"<={vei}"
                elif version and version != "*":
                    version_range = version

                products.append(
                    AffectedProduct(
                        vendor=vendor.replace("_", " "),
                        product=product.replace("_", " "),
                        versions=version_range,
                        cpe=criteria,
                    )
                )

    return products
