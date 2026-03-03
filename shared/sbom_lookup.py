"""BigQuery SBOM検索モジュール。"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from shared.infra import get_config, get_project_id
from shared.ticket_parsers import check_product_in_sbom, extract_product_names_quick

logger = logging.getLogger(__name__)

_SBOM_ALMA_VERSION_CACHE: dict[str, Any] = {"versions": None, "fetched_at": None}
_SBOM_PRODUCT_CACHE: dict[str, Any] = {"names": None, "fetched_at": None}


def get_sbom_almalinux_versions() -> set[str]:
    cached_versions = _SBOM_ALMA_VERSION_CACHE.get("versions")
    fetched_at = _SBOM_ALMA_VERSION_CACHE.get("fetched_at")
    now = datetime.now(timezone.utc)
    if isinstance(cached_versions, set) and isinstance(fetched_at, datetime):
        if (now - fetched_at).total_seconds() < 600:
            return set(cached_versions)

    table_id = get_config("BQ_SBOM_TABLE_ID", "vuln-agent-bq-sbom-table-id", "").strip()
    if not table_id:
        return set()
    try:
        from google.cloud import bigquery

        client = bigquery.Client(project=get_project_id() or None)
        query = f"""
            SELECT DISTINCT os_version AS alma_ver
            FROM `{table_id}`
            WHERE os_name = 'almalinux' AND os_version IS NOT NULL
        """
        rows = list(client.query(query).result())
        versions = {str((r.get("alma_ver") if isinstance(r, dict) else getattr(r, "alma_ver", "")) or "").strip() for r in rows}
        versions = {v for v in versions if v}
        _SBOM_ALMA_VERSION_CACHE["versions"] = set(versions)
        _SBOM_ALMA_VERSION_CACHE["fetched_at"] = now
        return versions
    except Exception as exc:
        logger.warning("[diag:sbom] Failed to load AlmaLinux versions from SBOM table: %s", exc)
        return set()


def get_sbom_product_names() -> set[str]:
    """BQ SBOMテーブルから製品名(name列)をDISTINCTで取得。10分キャッシュ。"""
    cached_names = _SBOM_PRODUCT_CACHE.get("names")
    fetched_at = _SBOM_PRODUCT_CACHE.get("fetched_at")
    now = datetime.now(timezone.utc)
    if isinstance(cached_names, set) and isinstance(fetched_at, datetime):
        if (now - fetched_at).total_seconds() < 600:
            return set(cached_names)

    table_id = get_config("BQ_SBOM_TABLE_ID", "vuln-agent-bq-sbom-table-id", "").strip()
    if not table_id:
        return set()
    try:
        from google.cloud import bigquery

        client = bigquery.Client(project=get_project_id() or None)
        query = f"""
            SELECT DISTINCT LOWER(name) AS product_name
            FROM `{table_id}`
            WHERE type IN ('application', 'os', 'network')
        """
        rows = list(client.query(query).result())
        names = {
            str((r.get("product_name") if isinstance(r, dict) else getattr(r, "product_name", "")) or "").strip()
            for r in rows
        }
        names = {n for n in names if n}
        _SBOM_PRODUCT_CACHE["names"] = set(names)
        _SBOM_PRODUCT_CACHE["fetched_at"] = now
        return names
    except Exception as exc:
        logger.warning("[diag:sbom] Failed to load product names from SBOM table: %s", exc)
        return set()


def check_sbom_registration(source_text: str) -> tuple[bool, list[str], str]:
    """SBOMに製品が登録されているかチェック。

    Returns:
        (should_skip, detected_products, reason)
        - should_skip=True → 対応不要
        - should_skip=False → チケット生成続行
    """
    products = extract_product_names_quick(source_text)
    if not products:
        return False, [], ""
    if any("almalinux" in p.lower() for p in products):
        return False, products, ""
    sbom_names = get_sbom_product_names()
    if not sbom_names:
        return False, products, ""
    matched = any(check_product_in_sbom(p, sbom_names) for p in products)
    if matched:
        return False, products, ""
    return True, products, "SBOMに登録されていない製品のため、自社環境に該当なしと判断"


def build_sbom_not_registered_message(products: list[str], reason: str) -> str:
    """SBOM未登録製品に対する対応不要メッセージを構築。"""
    products_str = ", ".join(products) if products else "（製品を特定できませんでした）"
    return (
        "対応不要と判断しました。\n\n"
        f"【検出された製品】\n{products_str}\n\n"
        f"【判断理由】\n{reason}\n\n"
        "もし対象環境に該当製品がある場合はお知らせください。"
    )
