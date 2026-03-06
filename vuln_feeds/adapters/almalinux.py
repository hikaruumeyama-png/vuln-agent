"""AlmaLinux Errata API アダプター。

ソース: https://errata.almalinux.org/
API: AlmaLinux Errata API — https://errata.almalinux.org/
差分取得: updated_date パラメータでフィルタ
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

from shared.vuln_schema import AffectedProduct, VulnEntry, cvss_to_severity

from .base import BaseSourceAdapter, http_get_json

logger = logging.getLogger(__name__)

# AlmaLinux Errata API エンドポイント
_ERRATA_API_BASE = "https://errata.almalinux.org"

# CVE-ID パターン
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# 対象メジャーバージョン (環境変数で上書き可能)
_ALMA_VERSIONS = ["8", "9"]


class AlmaLinuxAdapter(BaseSourceAdapter):
    """AlmaLinux Errata API アダプター。"""

    source_id = "almalinux"
    default_poll_interval_minutes = 30

    def fetch_recent(self, since: datetime) -> list[VulnEntry]:
        """AlmaLinux Errata API から since 以降のセキュリティエラッタを取得する。"""
        all_entries: list[VulnEntry] = []
        seen_ids: set[str] = set()

        for version in _ALMA_VERSIONS:
            try:
                entries = self._fetch_version_errata(version, since)
                for entry in entries:
                    nid = entry.normalize_id()
                    if nid not in seen_ids:
                        seen_ids.add(nid)
                        all_entries.append(entry)
            except Exception as exc:
                logger.warning("AlmaLinux errata fetch failed for v%s: %s", version, exc)

        logger.info("AlmaLinux: %d errata entries", len(all_entries))
        return all_entries

    def _fetch_version_errata(self, version: str, since: datetime) -> list[VulnEntry]:
        """特定バージョンのエラッタを取得する。"""
        # AlmaLinux は JSON ファイルでエラッタを公開
        url = f"{_ERRATA_API_BASE}/{version}/errata.json"

        try:
            data = http_get_json(url)
        except Exception as exc:
            logger.warning("AlmaLinux errata.json fetch failed for v%s: %s", version, exc)
            return []

        errata_list = data if isinstance(data, list) else data.get("errata") or data.get("data") or []
        if isinstance(data, dict) and not errata_list:
            # 全体が dict の場合、値がリストの最初のキーを探す
            for v in data.values():
                if isinstance(v, list):
                    errata_list = v
                    break

        entries: list[VulnEntry] = []
        for erratum in errata_list:
            if not isinstance(erratum, dict):
                continue

            # セキュリティエラッタのみ
            err_type = (erratum.get("type") or erratum.get("updateinfo_type") or "").strip().lower()
            if err_type and err_type != "security":
                continue

            entry = _normalize_erratum(erratum, version, since)
            if entry is not None:
                entries.append(entry)

        return entries


def _normalize_erratum(
    erratum: dict[str, Any], version: str, since: datetime
) -> VulnEntry | None:
    """AlmaLinux エラッタを VulnEntry に正規化する。"""
    errata_id = (
        erratum.get("id")
        or erratum.get("updateinfo_id")
        or erratum.get("errata_id")
        or ""
    ).strip()
    if not errata_id:
        return None

    title = (erratum.get("title") or erratum.get("summary") or "").strip()
    description = (erratum.get("description") or "").strip()
    issued_raw = erratum.get("issued_date") or erratum.get("issued") or ""
    updated_raw = erratum.get("updated_date") or erratum.get("updated") or ""
    issued_str = _extract_date_value(issued_raw)
    updated_str = _extract_date_value(updated_raw)
    severity_raw = (erratum.get("severity") or "").strip()

    # 日付フィルタ
    issued_dt = _parse_date(issued_str)
    updated_dt = _parse_date(updated_str)
    ref_dt = updated_dt or issued_dt
    if ref_dt and ref_dt < since:
        return None

    # CVE 抽出 (references フィールド内の type="cve" エントリ)
    cve_list = erratum.get("CVEs") or erratum.get("cves") or erratum.get("references") or []
    cve_ids: list[str] = []
    if isinstance(cve_list, list):
        for cve_item in cve_list:
            if isinstance(cve_item, str):
                cve_match = _CVE_PATTERN.search(cve_item)
                if cve_match:
                    cve_ids.append(cve_match.group(0).upper())
            elif isinstance(cve_item, dict):
                # AlmaLinux 形式: {"type": "cve", "id": "CVE-...", "title": "CVE-..."}
                cve_type = str(cve_item.get("type") or "").lower()
                cve_id = (cve_item.get("id") or cve_item.get("title") or cve_item.get("cve") or "").strip()
                if cve_type == "cve" and _CVE_PATTERN.match(cve_id):
                    cve_ids.append(cve_id.upper())
                elif _CVE_PATTERN.match(cve_id):
                    cve_ids.append(cve_id.upper())

    # タイトル/説明からも抽出
    text_blob = f"{title} {description}"
    for m in _CVE_PATTERN.findall(text_blob):
        cve_upper = m.upper()
        if cve_upper not in cve_ids:
            cve_ids.append(cve_upper)

    # 主キー決定
    vuln_id = errata_id
    aliases: list[str] = []
    if cve_ids:
        vuln_id = cve_ids[0]
        aliases = [errata_id] + cve_ids[1:]
    else:
        aliases = []

    # severity マッピング
    cvss_score = _severity_to_approx_cvss(severity_raw)
    severity = cvss_to_severity(cvss_score)

    # 影響パッケージ
    products = _extract_packages(erratum, version)

    published_iso = issued_dt.isoformat() if issued_dt else ""
    updated_iso = updated_dt.isoformat() if updated_dt else published_iso

    return VulnEntry(
        vuln_id=vuln_id,
        aliases=aliases,
        title=title or errata_id,
        description=description,
        published=published_iso,
        last_modified=updated_iso,
        source="almalinux",
        source_url=f"https://errata.almalinux.org/{version}/{errata_id}.html",
        cvss_score=cvss_score,
        severity=severity,
        affected_products=products,
        vendor_advisory_id=errata_id,
        vendor_severity=severity_raw or None,
    )


def _extract_packages(erratum: dict[str, Any], version: str) -> list[AffectedProduct]:
    """エラッタから影響パッケージを抽出する。"""
    products: list[AffectedProduct] = []
    seen: set[str] = set()

    packages_raw = erratum.get("packages") or erratum.get("pkglist") or []

    # AlmaLinux 形式: packages が dict (collection) の場合、中の packages リストを取得
    pkg_list: list[Any] = []
    if isinstance(packages_raw, dict):
        inner = packages_raw.get("packages") or []
        if isinstance(inner, list):
            pkg_list = inner
        else:
            # collection 名をタイトルとして使う
            name = (packages_raw.get("name") or packages_raw.get("shortname") or "").strip()
            if name:
                pkg_list = [name]
    elif isinstance(packages_raw, list):
        # リストの各要素が dict (collection) の場合を処理
        for item in packages_raw:
            if isinstance(item, dict):
                inner = item.get("packages") or []
                if isinstance(inner, list):
                    pkg_list.extend(inner)
                else:
                    name = (item.get("name") or "").strip()
                    if name:
                        pkg_list.append(name)
            else:
                pkg_list.append(item)

    for pkg in pkg_list:
        if isinstance(pkg, str):
            name = pkg.strip()
        elif isinstance(pkg, dict):
            name = (pkg.get("name") or pkg.get("filename") or "").strip()
        else:
            continue

        if name and name not in seen:
            seen.add(name)
            products.append(
                AffectedProduct(
                    vendor="AlmaLinux",
                    product=name,
                    versions=f"AlmaLinux {version}",
                )
            )

    return products


def _severity_to_approx_cvss(severity: str) -> float | None:
    """AlmaLinux severity ラベルから概算 CVSS スコアを返す。"""
    severity_map: dict[str, float] = {
        "critical": 9.5,
        "important": 7.5,
        "moderate": 5.0,
        "low": 2.5,
    }
    return severity_map.get(severity.lower())


def _extract_date_value(raw: Any) -> str:
    """AlmaLinux の日付フィールドから文字列値を抽出する。

    MongoDB 形式 {"$date": epoch_ms} とプレーン文字列の両方に対応。
    """
    if isinstance(raw, dict):
        # {"$date": 1654646400000} 形式
        epoch_ms = raw.get("$date")
        if epoch_ms is not None:
            try:
                return str(int(epoch_ms))  # _parse_date で Unix timestamp として処理
            except (TypeError, ValueError):
                pass
        return ""
    return str(raw).strip() if raw else ""


def _parse_date(date_str: str) -> datetime | None:
    """日付文字列をパースする (ISO / Unix timestamp 対応)。"""
    date_str = (date_str or "").strip()
    if not date_str:
        return None

    # Unix timestamp (整数 / ミリ秒)
    try:
        ts = int(date_str)
        # ミリ秒の場合 (13桁以上) は秒に変換
        if ts > 1e12:
            ts = ts // 1000
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except (ValueError, OSError):
        pass

    # ISO8601
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
