"""ポーリング状態管理。

各ソースアダプターの最終ポーリング時刻・カーソルを BigQuery に永続化する。
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from google.cloud import bigquery

logger = logging.getLogger(__name__)


def _get_table_id() -> str:
    return (os.environ.get("BQ_VULN_POLL_STATE_TABLE_ID") or "").strip()


_bq_client: bigquery.Client | None = None


def _get_client() -> bigquery.Client:
    global _bq_client
    if _bq_client is not None:
        return _bq_client
    project = (
        os.environ.get("GCP_PROJECT_ID")
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
        or ""
    ).strip() or None
    _bq_client = bigquery.Client(project=project)
    return _bq_client


def get_last_poll(source_id: str) -> dict[str, Any]:
    """ソースの最終ポーリング情報を取得する。

    Returns:
        {"last_poll_at": datetime, "last_cursor": str, ...}
        未登録の場合はデフォルト (24時間前) を返す。
    """
    table_id = _get_table_id()
    if not table_id:
        return _default_state(source_id)

    try:
        client = _get_client()
        query = f"""
            SELECT *
            FROM `{table_id}`
            WHERE source_id = @source_id
            ORDER BY last_poll_at ASC
            LIMIT 1
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("source_id", "STRING", source_id),
            ]
        )
        rows = list(client.query(query, job_config=job_config).result())
        if rows:
            row = dict(rows[0])
            return row
    except Exception as exc:
        logger.error("get_last_poll failed for %s: %s", source_id, exc)

    return _default_state(source_id)


def update_poll_state(
    source_id: str,
    *,
    last_cursor: str = "",
    items_fetched: int = 0,
    items_new: int = 0,
    error_message: str = "",
) -> None:
    """ポーリング結果を記録する。MERGE で UPSERT。"""
    table_id = _get_table_id()
    if not table_id:
        logger.warning("BQ_VULN_POLL_STATE_TABLE_ID is not set, skipping state update")
        return

    now = datetime.now(timezone.utc).isoformat()
    success_at = now if not error_message else None

    try:
        client = _get_client()
        query = f"""
            MERGE `{table_id}` AS target
            USING (SELECT @source_id AS source_id) AS src
            ON target.source_id = src.source_id
            WHEN MATCHED THEN
                UPDATE SET
                    last_poll_at = @now,
                    last_success_at = COALESCE(@success_at, target.last_success_at),
                    last_cursor = COALESCE(NULLIF(@last_cursor, ''), target.last_cursor),
                    items_fetched = @items_fetched,
                    items_new = @items_new,
                    error_message = @error_message
            WHEN NOT MATCHED THEN
                INSERT (source_id, last_poll_at, last_success_at, last_cursor, items_fetched, items_new, error_message)
                VALUES (@source_id, @now, @success_at, @last_cursor, @items_fetched, @items_new, @error_message)
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("source_id", "STRING", source_id),
                bigquery.ScalarQueryParameter("now", "TIMESTAMP", now),
                bigquery.ScalarQueryParameter("success_at", "TIMESTAMP", success_at),
                bigquery.ScalarQueryParameter("last_cursor", "STRING", last_cursor),
                bigquery.ScalarQueryParameter("items_fetched", "INT64", items_fetched),
                bigquery.ScalarQueryParameter("items_new", "INT64", items_new),
                bigquery.ScalarQueryParameter("error_message", "STRING", error_message),
            ]
        )
        client.query(query, job_config=job_config).result()
        logger.info(
            "Poll state updated: source=%s, fetched=%d, new=%d",
            source_id,
            items_fetched,
            items_new,
        )
    except Exception as exc:
        logger.error("update_poll_state failed for %s: %s", source_id, exc)


def _default_state(source_id: str) -> dict[str, Any]:
    """未登録ソースのデフォルト状態 (24時間前から取得開始)。"""
    return {
        "source_id": source_id,
        "last_poll_at": datetime.now(timezone.utc) - timedelta(hours=24),
        "last_success_at": None,
        "last_cursor": "",
        "items_fetched": 0,
        "items_new": 0,
        "error_message": "",
    }
