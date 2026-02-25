"""
BigQuery Tools - 対応履歴の蓄積
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any

from google.cloud import bigquery


def log_vulnerability_history(
    vulnerability_id: str,
    title: str,
    severity: str,
    affected_systems: list[str],
    cvss_score: float | None = None,
    description: str | None = None,
    remediation: str | None = None,
    owners: list[str] | None = None,
    status: str = "notified",
    incident_id: str | None = None,
    occurred_at: str | None = None,
    source: str = "agent",
    extra: dict[str, Any] | None = None,
    due_date: str | None = None,
    due_reason: str | None = None,
    affected_products: list[str] | None = None,
    cve_ids: list[str] | None = None,
    copy_paste_text: str | None = None,
    reasoning_text: str | None = None,
    thread_name: str | None = None,
    space_id: str | None = None,
) -> dict[str, Any]:
    """
    脆弱性の対応履歴をBigQueryに保存します。

    Args:
        vulnerability_id: CVE番号等
        title: 脆弱性のタイトル
        severity: 重大度（緊急/高/中/低）
        affected_systems: 影響を受けるシステム名のリスト
        cvss_score: CVSSスコア（オプション）
        description: 脆弱性の説明（オプション）
        remediation: 推奨される対策（オプション）
        owners: 担当者メールアドレス（オプション）
        status: 対応状況（例: notified/triaging/resolved）
        incident_id: インシデントID（省略時は自動生成）
        occurred_at: 発生日時（ISO8601）。省略時は現在時刻
        source: データの発生源
        extra: 追加情報
        due_date: 対応完了目標（例: "2026/03/10"）
        due_reason: 期限の根拠
        affected_products: 影響製品リスト
        cve_ids: CVE-ID リスト
        copy_paste_text: 起票用コピペセクション
        reasoning_text: 判断理由セクション
        thread_name: Chat スレッド名
        space_id: Chat スペースID

    Returns:
        保存結果
    """
    table_id = (os.environ.get("BQ_HISTORY_TABLE_ID") or "").strip()
    if not table_id:
        return {
            "status": "skipped",
            "message": "BQ_HISTORY_TABLE_ID is not set.",
        }

    vulnerability_id = (vulnerability_id or "").strip()
    title = (title or "").strip()
    severity = (severity or "").strip()
    if not vulnerability_id or not title or not severity:
        return {
            "status": "error",
            "message": "vulnerability_id, title, severity は必須です。",
        }

    affected_systems = _normalize_string_list(affected_systems)
    owners = _normalize_string_list(owners or [])

    incident_id = incident_id or str(uuid.uuid4())
    occurred_at = occurred_at or datetime.now(timezone.utc).isoformat()
    if not _is_valid_iso8601(occurred_at):
        return {
            "status": "error",
            "message": "occurred_at は ISO8601 形式で指定してください。",
            "incident_id": incident_id,
        }

    row = {
        "incident_id": incident_id,
        "vulnerability_id": vulnerability_id,
        "title": title,
        "severity": severity,
        "affected_systems": json.dumps(affected_systems, ensure_ascii=False),
        "cvss_score": cvss_score,
        "description": description,
        "remediation": remediation,
        "owners": json.dumps(owners, ensure_ascii=False),
        "status": status,
        "occurred_at": occurred_at,
        "source": source,
        "extra": json.dumps(extra, ensure_ascii=False) if extra else None,
        "due_date": due_date,
        "due_reason": due_reason,
        "affected_products": json.dumps(affected_products or [], ensure_ascii=False),
        "cve_ids": json.dumps(cve_ids or [], ensure_ascii=False),
        "copy_paste_text": copy_paste_text,
        "reasoning_text": reasoning_text,
        "thread_name": thread_name,
        "space_id": space_id,
    }

    project = (os.environ.get("GCP_PROJECT_ID") or "").strip() or None
    try:
        client = bigquery.Client(project=project)
        errors = client.insert_rows_json(
            table_id,
            [row],
            row_ids=[incident_id],
        )
        if errors:
            return {
                "status": "error",
                "message": "Failed to insert rows into BigQuery.",
                "errors": errors,
                "incident_id": incident_id,
            }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"BigQuery insert failed: {exc}",
            "incident_id": incident_id,
        }

    return {"status": "saved", "incident_id": incident_id, "table_id": table_id}


def recall_vulnerability_history(
    cve_id: str = "",
    owner_email: str = "",
    severity: str = "",
    days_back: int = 90,
    limit: int = 10,
) -> dict[str, Any]:
    """過去の脆弱性対応履歴をBigQueryから検索します。

    Args:
        cve_id: CVE番号で絞り込み（部分一致）。空文字の場合は全件対象。
        owner_email: 担当者メールで絞り込み（部分一致）。
        severity: 重大度で絞り込み（完全一致: 緊急/高/中/低）。
        days_back: 過去何日分を検索するか（デフォルト90日）。
        limit: 最大取得件数（デフォルト10件）。

    Returns:
        dict: {"status": "success", "total_count": int, "records": [...]} or error

    Example:
        recall_vulnerability_history(cve_id="CVE-2024") → 直近90日のCVE-2024*の履歴
    """
    table_id = (os.environ.get("BQ_HISTORY_TABLE_ID") or "").strip()
    if not table_id:
        return {
            "status": "skipped",
            "message": "BQ_HISTORY_TABLE_ID is not set.",
        }

    # サニタイズ
    cve_id = (cve_id or "").strip()
    owner_email = (owner_email or "").strip()
    severity = (severity or "").strip()
    days_back = max(1, min(int(days_back), 3650))
    limit = max(1, min(int(limit), 500))

    conditions: list[str] = [
        f"occurred_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days_back} DAY)",
    ]
    query_params: list[bigquery.ScalarQueryParameter] = []

    if cve_id:
        conditions.append("CONTAINS_SUBSTR(vulnerability_id, @cve_id)")
        query_params.append(
            bigquery.ScalarQueryParameter("cve_id", "STRING", cve_id)
        )
    if owner_email:
        conditions.append("CONTAINS_SUBSTR(owners, @owner_email)")
        query_params.append(
            bigquery.ScalarQueryParameter("owner_email", "STRING", owner_email)
        )
    if severity:
        conditions.append("severity = @severity")
        query_params.append(
            bigquery.ScalarQueryParameter("severity", "STRING", severity)
        )

    where_clause = " AND ".join(conditions)
    query = (
        f"SELECT * FROM `{table_id}` "
        f"WHERE {where_clause} "
        f"ORDER BY occurred_at DESC "
        f"LIMIT {limit}"
    )

    project = (os.environ.get("GCP_PROJECT_ID") or "").strip() or None
    try:
        client = bigquery.Client(project=project)
        job_config = bigquery.QueryJobConfig(query_parameters=query_params)
        rows = client.query(query, job_config=job_config).result()

        records: list[dict[str, Any]] = []
        for row in rows:
            records.append(dict(row))

        return {
            "status": "success",
            "total_count": len(records),
            "records": records,
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"BigQuery query failed: {exc}",
        }


def _normalize_string_list(values: list[str] | tuple[str, ...] | None) -> list[str]:
    if not values:
        return []
    normalized: list[str] = []
    for value in values:
        item = str(value).strip()
        if item:
            normalized.append(item)
    return normalized


def _is_valid_iso8601(value: str) -> bool:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except Exception:
        return False
