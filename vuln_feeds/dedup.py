"""BigQuery ベースの CVE-ID 重複排除。

vuln_dedup テーブルを使い、vuln_id + aliases の集合で
ソース間の重複を検知する。初回のみ NEW を返し、2回目以降は SKIP。
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from google.cloud import bigquery

from shared.vuln_schema import VulnEntry

logger = logging.getLogger(__name__)


class DedupResult(Enum):
    NEW = "new"
    SKIP = "skip"
    ERROR = "error"


def _get_table_id() -> str:
    return (os.environ.get("BQ_VULN_DEDUP_TABLE_ID") or "").strip()


def _get_client() -> bigquery.Client:
    project = (
        os.environ.get("GCP_PROJECT_ID")
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
        or ""
    ).strip() or None
    return bigquery.Client(project=project)


def check_and_register(entry: VulnEntry) -> DedupResult:
    """エントリの重複をチェックし、新規なら登録する。

    Returns:
        DedupResult.NEW  - 新規エントリ。Pub/Sub に publish すべき。
        DedupResult.SKIP - 既知エントリ。sources_seen を更新済み。
        DedupResult.ERROR - テーブル未設定やクエリ失敗。
    """
    table_id = _get_table_id()
    if not table_id:
        logger.warning("BQ_VULN_DEDUP_TABLE_ID is not set, skipping dedup")
        return DedupResult.ERROR

    all_ids = entry.all_ids()
    if not all_ids:
        return DedupResult.ERROR

    try:
        client = _get_client()
        existing = _find_existing(client, table_id, all_ids)

        if existing:
            _update_sources_seen(client, table_id, existing["vuln_id"], entry.source)
            logger.info(
                "Dedup SKIP: %s (first_source=%s, current=%s)",
                entry.vuln_id,
                existing.get("first_source"),
                entry.source,
            )
            return DedupResult.SKIP

        _insert_new(client, table_id, entry)
        logger.info("Dedup NEW: %s (source=%s)", entry.vuln_id, entry.source)
        return DedupResult.NEW

    except Exception as exc:
        logger.error("Dedup error for %s: %s", entry.vuln_id, exc)
        return DedupResult.ERROR


def _find_existing(
    client: bigquery.Client,
    table_id: str,
    all_ids: set[str],
) -> dict[str, Any] | None:
    """vuln_id または aliases が all_ids のいずれかに一致するレコードを検索する。"""
    # パラメータ化クエリで安全に検索
    id_list = list(all_ids)
    query = f"""
        SELECT vuln_id, first_source, sources_seen
        FROM `{table_id}`
        WHERE vuln_id IN UNNEST(@id_list)
           OR EXISTS(
               SELECT 1 FROM UNNEST(aliases) AS a
               WHERE a IN UNNEST(@id_list)
           )
        LIMIT 1
    """
    job_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ArrayQueryParameter("id_list", "STRING", id_list),
        ]
    )
    rows = list(client.query(query, job_config=job_config).result())
    if rows:
        return dict(rows[0])
    return None


def _update_sources_seen(
    client: bigquery.Client,
    table_id: str,
    vuln_id: str,
    new_source: str,
) -> None:
    """既存レコードの sources_seen にソースを追加し、last_updated_at を更新する。"""
    query = f"""
        UPDATE `{table_id}`
        SET
            sources_seen = ARRAY(
                SELECT DISTINCT s FROM UNNEST(
                    ARRAY_CONCAT(sources_seen, [@new_source])
                ) AS s
            ),
            last_updated_at = @now
        WHERE vuln_id = @vuln_id
    """
    now = datetime.now(timezone.utc).isoformat()
    job_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("vuln_id", "STRING", vuln_id),
            bigquery.ScalarQueryParameter("new_source", "STRING", new_source),
            bigquery.ScalarQueryParameter("now", "TIMESTAMP", now),
        ]
    )
    client.query(query, job_config=job_config).result()


def _insert_new(
    client: bigquery.Client,
    table_id: str,
    entry: VulnEntry,
) -> None:
    """新規エントリを vuln_dedup テーブルに DML INSERT する。"""
    now = datetime.now(timezone.utc).isoformat()
    aliases = list(entry.all_ids() - {entry.normalize_id()})

    query = f"""
        INSERT INTO `{table_id}`
            (vuln_id, aliases, first_source, first_seen_at, sources_seen,
             last_updated_at, processed, sbom_matched, skip_reason)
        VALUES
            (@vuln_id, @aliases, @first_source, @now, @sources_seen,
             @now, FALSE, FALSE, NULL)
    """
    job_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("vuln_id", "STRING", entry.normalize_id()),
            bigquery.ArrayQueryParameter("aliases", "STRING", aliases),
            bigquery.ScalarQueryParameter("first_source", "STRING", entry.source),
            bigquery.ScalarQueryParameter("now", "TIMESTAMP", now),
            bigquery.ArrayQueryParameter("sources_seen", "STRING", [entry.source]),
        ]
    )
    client.query(query, job_config=job_config).result()


def mark_processed(
    vuln_id: str,
    sbom_matched: bool,
    skip_reason: str = "",
) -> None:
    """処理完了後にフラグを更新する (vuln_intake から呼び出す)。"""
    table_id = _get_table_id()
    if not table_id:
        return

    try:
        client = _get_client()
        query = f"""
            UPDATE `{table_id}`
            SET processed = TRUE,
                sbom_matched = @sbom_matched,
                skip_reason = @skip_reason,
                last_updated_at = @now
            WHERE vuln_id = @vuln_id
        """
        now = datetime.now(timezone.utc).isoformat()
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("vuln_id", "STRING", vuln_id.strip().upper()),
                bigquery.ScalarQueryParameter("sbom_matched", "BOOL", sbom_matched),
                bigquery.ScalarQueryParameter("skip_reason", "STRING", skip_reason),
                bigquery.ScalarQueryParameter("now", "TIMESTAMP", now),
            ]
        )
        client.query(query, job_config=job_config).result()
    except Exception as exc:
        logger.error("mark_processed failed for %s: %s", vuln_id, exc)
