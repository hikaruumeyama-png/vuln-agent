"""脆弱性取り込みプロセッサー。

Pub/Sub から受信した VulnEntry を処理する:
1. SBOM照合 (affected_products からマッチ)
2. 該当あり → 担当者特定 → Chat通知 → 履歴記録
3. 該当なし → ログのみ (通知しない)
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any

# shared/ と agent/ を import パスに追加
_ROOT_DIR = os.path.join(os.path.dirname(__file__), "..")
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, os.path.normpath(_ROOT_DIR))

from shared.vuln_schema import VulnEntry

logger = logging.getLogger(__name__)


def process_vuln_entry(entry: VulnEntry) -> dict[str, Any]:
    """VulnEntry を処理し、SBOM照合と通知を行う。

    Returns:
        {"status": "notified" | "no_match" | "error", ...}
    """
    vuln_id = entry.normalize_id()
    logger.info("Processing vuln entry: %s (source=%s)", vuln_id, entry.source)

    # 1. SBOM 照合
    matched_entries = _match_sbom(entry)

    if not matched_entries:
        logger.info("No SBOM match for %s, logging only", vuln_id)
        _mark_dedup(vuln_id, sbom_matched=False, skip_reason="no_sbom_match")
        _log_history(entry, matched_entries=[], status="no_match")
        return {"status": "no_match", "vuln_id": vuln_id}

    # 2. 通知送信
    try:
        notify_result = _send_notification(entry, matched_entries)
    except Exception as exc:
        logger.error("Notification failed for %s: %s", vuln_id, exc)
        _mark_dedup(vuln_id, sbom_matched=True, skip_reason=f"notify_error: {exc}")
        return {"status": "error", "vuln_id": vuln_id, "message": str(exc)}

    # 3. 完了フラグ更新
    _mark_dedup(vuln_id, sbom_matched=True)

    return {
        "status": "notified",
        "vuln_id": vuln_id,
        "matched_count": len(matched_entries),
        "notify_result": notify_result,
    }


def _match_sbom(entry: VulnEntry) -> list[dict[str, Any]]:
    """affected_products を使って SBOM を照合する。"""
    try:
        from agent.tools.sheets_tools import search_sbom_by_purl, search_sbom_by_product
    except ImportError:
        logger.error("Cannot import SBOM search tools")
        return []

    all_matched: list[dict[str, Any]] = []
    seen_keys: set[str] = set()

    for product in entry.affected_products:
        results: list[dict[str, Any]] = []

        # PURL があれば優先
        if product.purl:
            result = search_sbom_by_purl(product.purl)
            results.extend(result.get("matched_entries") or [])

        # 製品名 + バージョンで検索
        if product.product:
            result = search_sbom_by_product(
                product_name=product.product,
                version_range=product.versions if product.versions else None,
            )
            results.extend(result.get("matched_entries") or [])

        # ベンダー名でも検索 (製品名が空の場合)
        if not product.product and product.vendor:
            result = search_sbom_by_product(product_name=product.vendor)
            results.extend(result.get("matched_entries") or [])

        # 重複除去して追加
        for r in results:
            key = f"{r.get('purl', '')}:{r.get('version', '')}:{r.get('name', '')}"
            if key not in seen_keys:
                seen_keys.add(key)
                all_matched.append(r)

    return all_matched


def _send_notification(
    entry: VulnEntry,
    matched_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    """既存の send_vulnerability_alert を呼び出して Chat 通知を送信する。"""
    try:
        from agent.tools.chat_tools import send_vulnerability_alert
    except ImportError:
        logger.error("Cannot import chat_tools")
        return {"status": "error", "message": "chat_tools import failed"}

    # 影響システム・担当者を集約
    affected_systems = list({
        e.get("system_name", "")
        for e in matched_entries
        if e.get("system_name")
    })
    owners = list({
        e.get("owner_email", "")
        for e in matched_entries
        if e.get("owner_email")
    })

    # リンク情報の構築
    links: dict[str, str] = {}
    if entry.source_url:
        links[entry.title or entry.vuln_id] = entry.source_url
    if entry.vuln_id.upper().startswith("CVE-"):
        links["NVD"] = f"https://nvd.nist.gov/vuln/detail/{entry.vuln_id}"
    if entry.vendor_advisory_id:
        links[f"ベンダーアドバイザリ ({entry.vendor_advisory_id})"] = entry.source_url

    # 対策テキストの構築
    remediation_parts: list[str] = []
    if entry.vendor_fixed_versions:
        remediation_parts.append(
            "修正バージョン: " + ", ".join(entry.vendor_fixed_versions)
        )
    remediation_parts.append(
        "上記脆弱性情報をご確認いただき、該当バージョンの場合は"
        "バージョンアップのご対応をお願いいたします。"
    )
    remediation = "\n".join(remediation_parts)

    # ソース名 (resource_type 判定用)
    source_name = ""
    if entry.affected_products:
        source_name = entry.affected_products[0].product or entry.affected_products[0].vendor

    result = send_vulnerability_alert(
        vulnerability_id=entry.vuln_id,
        title=entry.title,
        severity=entry.severity,
        affected_systems=affected_systems,
        cvss_score=entry.cvss_score,
        description=entry.description[:1000] if entry.description else None,
        remediation=remediation,
        owners=owners,
        resource_type="internal",  # デフォルトは内部リソース
        exploit_confirmed=entry.exploit_confirmed,
        exploit_code_public=entry.exploit_code_public,
        vulnerability_links=links,
        source_name=source_name,
    )
    return result


def _mark_dedup(vuln_id: str, sbom_matched: bool, skip_reason: str = "") -> None:
    """vuln_dedup テーブルの処理完了フラグを更新する。"""
    try:
        from vuln_feeds.dedup import mark_processed
        mark_processed(vuln_id, sbom_matched=sbom_matched, skip_reason=skip_reason)
    except Exception as exc:
        logger.error("mark_dedup failed for %s: %s", vuln_id, exc)


def _log_history(
    entry: VulnEntry,
    matched_entries: list[dict[str, Any]],
    status: str = "notified",
) -> None:
    """BigQuery 履歴テーブルにログを記録する。"""
    try:
        from agent.tools.history_tools import log_vulnerability_history

        affected_systems = list({
            e.get("system_name", "")
            for e in matched_entries
            if e.get("system_name")
        }) or ["(SBOM該当なし)"]

        log_vulnerability_history(
            vulnerability_id=entry.vuln_id,
            title=entry.title,
            severity=entry.severity,
            affected_systems=affected_systems,
            cvss_score=entry.cvss_score,
            description=entry.description[:500] if entry.description else None,
            status=status,
            source=f"vuln_feed:{entry.source}",
        )
    except Exception as exc:
        logger.error("log_history failed for %s: %s", entry.vuln_id, exc)
