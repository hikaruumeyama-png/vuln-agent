"""OSV.dev API アダプター。

ソース: https://osv.dev/
API: REST POST https://api.osv.dev/v1/query
差分取得: ecosystem ごとにクエリし、modified タイムスタンプでフィルタ
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

from shared.vuln_schema import AffectedProduct, VulnEntry, cvss_to_severity

from .base import BaseSourceAdapter, http_post_json

logger = logging.getLogger(__name__)

_OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_OSV_VULN_URL = "https://api.osv.dev/v1/vulns"

# SBOM で使用される ecosystem の一覧 (環境変数で上書き可能)
_DEFAULT_ECOSYSTEMS = [
    "PyPI",
    "npm",
    "Maven",
    "Go",
    "NuGet",
    "RubyGems",
    "crates.io",
    "Packagist",
    "AlmaLinux",
    "Rocky Linux",
    "Debian",
    "Alpine",
]


class OsvAdapter(BaseSourceAdapter):
    """OSV.dev API アダプター。"""

    source_id = "osv"
    default_poll_interval_minutes = 30

    def __init__(self) -> None:
        eco_str = os.environ.get("OSV_ECOSYSTEMS", "").strip()
        if eco_str:
            self._ecosystems = [e.strip() for e in eco_str.split(",") if e.strip()]
        else:
            self._ecosystems = _DEFAULT_ECOSYSTEMS

    def fetch_recent(self, since: datetime) -> list[VulnEntry]:
        """OSV API から since 以降に更新された脆弱性を取得する。

        OSV の /v1/query は ecosystem ごとにクエリする必要がある。
        modified タイムスタンプで差分をフィルタする。
        """
        all_entries: list[VulnEntry] = []
        seen_ids: set[str] = set()

        for ecosystem in self._ecosystems:
            entries = self._query_ecosystem(ecosystem, since)
            for entry in entries:
                nid = entry.normalize_id()
                if nid not in seen_ids:
                    seen_ids.add(nid)
                    all_entries.append(entry)

        logger.info("OSV: %d total entries across %d ecosystems", len(all_entries), len(self._ecosystems))
        return all_entries

    def _query_ecosystem(self, ecosystem: str, since: datetime) -> list[VulnEntry]:
        """単一 ecosystem の脆弱性をクエリする。"""
        # OSV /v1/query はパッケージ指定が必須のため、
        # ecosystem 全体の最新脆弱性取得には /v1/query:batch を使うか、
        # 個別パッケージ名が必要。
        # ここでは ecosystem レベルで GCS ダンプからの差分取得を行う。
        # 代替: 既知パッケージリストを SBOM から取得してクエリする。
        try:
            return self._query_via_ecosystem_dump(ecosystem, since)
        except Exception as exc:
            logger.warning("OSV ecosystem dump failed for %s: %s", ecosystem, exc)
            return []

    def _query_via_ecosystem_dump(
        self, ecosystem: str, since: datetime
    ) -> list[VulnEntry]:
        """OSV の ecosystem zip を使って差分取得する。

        OSV は GCS に ecosystem ごとの全件 JSON を公開している:
        https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip

        ただし全件ダウンロードは重いため、ここでは
        /v1/query API をパッケージレベルで使うアプローチに切り替える。
        SBOM に登録されたパッケージのみを対象にクエリする。
        """
        packages = _get_sbom_packages_for_ecosystem(ecosystem)
        if not packages:
            return []

        entries: list[VulnEntry] = []
        for pkg_name in packages:
            try:
                vulns = self._query_package(ecosystem, pkg_name)
                for v in vulns:
                    # modified でフィルタ
                    modified = v.get("modified") or v.get("published") or ""
                    if modified and _parse_timestamp(modified) and _parse_timestamp(modified) < since:
                        continue
                    entry = _normalize_osv_vuln(v, ecosystem)
                    if entry:
                        entries.append(entry)
            except Exception as exc:
                logger.warning("OSV query failed for %s/%s: %s", ecosystem, pkg_name, exc)

        return entries

    def _query_package(self, ecosystem: str, package_name: str) -> list[dict[str, Any]]:
        """OSV API でパッケージの脆弱性一覧を取得する。"""
        body = {"package": {"ecosystem": ecosystem, "name": package_name}}
        result = http_post_json(_OSV_QUERY_URL, body)
        return result.get("vulns") or []


def _get_sbom_packages_for_ecosystem(ecosystem: str) -> list[str]:
    """SBOM から指定 ecosystem のパッケージ名リストを取得する。

    SBOM の type フィールドを ecosystem にマッピングして抽出。
    """
    ecosystem_to_type = {
        "PyPI": "pypi",
        "npm": "npm",
        "Maven": "maven",
        "Go": "golang",
        "NuGet": "nuget",
        "RubyGems": "gem",
        "crates.io": "cargo",
        "Packagist": "composer",
        "AlmaLinux": "rpm",
        "Rocky Linux": "rpm",
        "Debian": "deb",
        "Alpine": "apk",
    }
    target_type = ecosystem_to_type.get(ecosystem, ecosystem.lower())

    try:
        from agent.tools.sheets_tools import _load_sbom

        sbom = _load_sbom()
        names: list[str] = []
        seen: set[str] = set()
        for entry in sbom:
            pkg_type = (entry.get("type") or "").strip().lower()
            name = (entry.get("name") or "").strip()
            if pkg_type == target_type and name and name not in seen:
                seen.add(name)
                names.append(name)
        return names
    except Exception as exc:
        logger.debug("SBOM load failed for ecosystem %s: %s", ecosystem, exc)
        return []


def _normalize_osv_vuln(vuln: dict[str, Any], ecosystem: str) -> VulnEntry | None:
    """OSV API のレスポンスを VulnEntry に正規化する。"""
    osv_id = (vuln.get("id") or "").strip()
    if not osv_id:
        return None

    summary = (vuln.get("summary") or "").strip()
    details = (vuln.get("details") or "").strip()
    aliases = [a.strip().upper() for a in (vuln.get("aliases") or []) if a.strip()]
    published = (vuln.get("published") or "").strip()
    modified = (vuln.get("modified") or "").strip()

    # 主キーの決定: CVE があればそちらを vuln_id にする
    vuln_id = osv_id
    cve_aliases = [a for a in aliases if a.startswith("CVE-")]
    if cve_aliases:
        vuln_id = cve_aliases[0]
        remaining = [a for a in aliases if a != vuln_id]
        if osv_id.upper() != vuln_id:
            remaining.insert(0, osv_id.upper())
        aliases = remaining

    # CVSS スコア抽出
    cvss_score = _extract_osv_cvss(vuln)
    severity_str = cvss_to_severity(cvss_score)

    # 影響製品
    affected_products = _extract_osv_affected(vuln)

    # ソースURL
    refs = vuln.get("references") or []
    source_url = ""
    for ref in refs:
        url = (ref.get("url") or "").strip()
        if url:
            source_url = url
            break
    if not source_url:
        source_url = f"https://osv.dev/vulnerability/{osv_id}"

    return VulnEntry(
        vuln_id=vuln_id,
        aliases=aliases,
        title=summary or osv_id,
        description=details or summary,
        published=published,
        last_modified=modified or published,
        source="osv",
        source_url=source_url,
        cvss_score=cvss_score,
        severity=severity_str,
        affected_products=affected_products,
    )


def _extract_osv_cvss(vuln: dict[str, Any]) -> float | None:
    """OSV の severity / database_specific から CVSS スコアを抽出する。"""
    # severity フィールド (OSV v1)
    severity_list = vuln.get("severity") or []
    for sev in severity_list:
        if isinstance(sev, dict) and sev.get("type") == "CVSS_V3":
            score_str = sev.get("score", "")
            if score_str:
                try:
                    return float(score_str)
                except ValueError:
                    pass
    # database_specific から探す
    db_specific = vuln.get("database_specific") or {}
    for key in ("cvss_score", "cvss", "severity_score"):
        val = db_specific.get(key)
        if val is not None:
            try:
                return float(val)
            except (TypeError, ValueError):
                pass
    return None


def _extract_osv_affected(vuln: dict[str, Any]) -> list[AffectedProduct]:
    """OSV の affected フィールドから影響製品を抽出する。"""
    products: list[AffectedProduct] = []
    for affected in vuln.get("affected") or []:
        pkg = affected.get("package") or {}
        ecosystem = (pkg.get("ecosystem") or "").strip()
        name = (pkg.get("name") or "").strip()
        purl_str = (pkg.get("purl") or "").strip()

        # バージョン範囲
        ranges = affected.get("ranges") or []
        version_str = ""
        fixed_versions: list[str] = []
        for r in ranges:
            for event in r.get("events") or []:
                if "fixed" in event:
                    fixed = event["fixed"]
                    fixed_versions.append(fixed)
                    if not version_str:
                        version_str = f"<{fixed}"

        if not version_str:
            versions_list = affected.get("versions") or []
            if versions_list:
                version_str = ", ".join(versions_list[:5])

        if name:
            products.append(
                AffectedProduct(
                    vendor=ecosystem,
                    product=name,
                    versions=version_str,
                    purl=purl_str,
                )
            )

    return products


def _parse_timestamp(ts: str) -> datetime | None:
    """ISO8601 タイムスタンプをパースする。"""
    ts = (ts or "").strip()
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
