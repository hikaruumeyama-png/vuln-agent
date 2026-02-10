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

    Returns:
        保存結果
    """
    table_id = os.environ.get("BQ_HISTORY_TABLE_ID")
    if not table_id:
        return {
            "status": "skipped",
            "message": "BQ_HISTORY_TABLE_ID is not set.",
        }

    incident_id = incident_id or str(uuid.uuid4())
    occurred_at = occurred_at or datetime.now(timezone.utc).isoformat()

    row = {
        "incident_id": incident_id,
        "vulnerability_id": vulnerability_id,
        "title": title,
        "severity": severity,
        "affected_systems": json.dumps(affected_systems, ensure_ascii=False),
        "cvss_score": cvss_score,
        "description": description,
        "remediation": remediation,
        "owners": json.dumps(owners or [], ensure_ascii=False),
        "status": status,
        "occurred_at": occurred_at,
        "source": source,
        "extra": json.dumps(extra, ensure_ascii=False) if extra else None,
    }

    project = os.environ.get("GCP_PROJECT_ID") or None
    client = bigquery.Client(project=project)
    errors = client.insert_rows_json(table_id, [row])
    if errors:
        return {
            "status": "error",
            "message": "Failed to insert rows into BigQuery.",
            "errors": errors,
            "incident_id": incident_id,
        }

    return {"status": "saved", "incident_id": incident_id, "table_id": table_id}
