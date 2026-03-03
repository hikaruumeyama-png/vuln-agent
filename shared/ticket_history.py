"""起票テンプレート履歴記録モジュール。

BigQuery に起票結果を保存する。
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from shared.infra import get_config, get_project_id

logger = logging.getLogger(__name__)

_INCIDENT_ID_PATTERN = re.compile(
    r"\bincident_id[:=\s]*([0-9a-fA-F\-]{8,})\b", re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# ヘルパー
# ---------------------------------------------------------------------------


def _extract_ticket_sections(text: str) -> tuple[str, str]:
    body = (text or "").strip()
    if not body:
        return "", ""
    copy_marker = "【起票用（コピペ）】"
    reason_marker = "【判断理由】"
    incident_marker = "【管理ID】"

    copy_text = ""
    reasoning_text = ""
    copy_idx = body.find(copy_marker)
    reason_idx = body.find(reason_marker)
    incident_idx = body.find(incident_marker)

    if copy_idx >= 0:
        copy_end = len(body)
        if reason_idx > copy_idx:
            copy_end = reason_idx
        elif incident_idx > copy_idx:
            copy_end = incident_idx
        copy_text = body[copy_idx:copy_end].strip()
    if reason_idx >= 0:
        reason_end = len(body)
        if incident_idx > reason_idx:
            reason_end = incident_idx
        reasoning_text = body[reason_idx:reason_end].strip()
    return copy_text, reasoning_text


def _extract_incident_id(text: str) -> str:
    raw = (text or "").strip()
    if not raw:
        return ""
    match = _INCIDENT_ID_PATTERN.search(raw)
    if not match:
        return ""
    return str(match.group(1) or "").strip()


def cvss_to_severity(score: float | None) -> str:
    """CVSSスコアから重大度文字列へ変換する。"""
    if score is None:
        return "要確認"
    if score >= 9.0:
        return "緊急"
    if score >= 7.0:
        return "高"
    if score >= 4.0:
        return "中"
    return "低"


# ---------------------------------------------------------------------------
# 履歴保存
# ---------------------------------------------------------------------------


def save_ticket_record_to_history(
    space_id: str,
    thread_name: str,
    response_text: str,
    source: str = "workspace_events_webhook",
    facts: dict[str, Any] | None = None,
) -> None:
    """起票結果を BigQuery 履歴テーブルに保存する。"""
    table_id = get_config("BQ_HISTORY_TABLE_ID", "vuln-agent-bq-table-id", "").strip()
    if not table_id:
        return
    copy_text, reasoning_text = _extract_ticket_sections(response_text)
    if not copy_text and not reasoning_text:
        return
    try:
        from google.cloud import bigquery
    except Exception:
        return

    incident_id = _extract_incident_id(response_text) or str(uuid.uuid4())
    vuln_match = re.search(
        r"\bCVE-\d{4}-\d{4,7}\b", response_text, flags=re.IGNORECASE,
    )
    vulnerability_id = (vuln_match.group(0).upper() if vuln_match else "").strip()
    if not vulnerability_id:
        seed = re.sub(r"[^A-Za-z0-9]", "", thread_name)[-16:] or "UNKNOWN"
        vulnerability_id = f"THREAD-{seed}"

    summary = "Chat follow-up ticket"
    for line in copy_text.splitlines():
        if "依頼概要" in line and ":" in line:
            summary = line.split(":", 1)[1].strip() or summary
            break

    f = facts or {}
    extra = {
        "space_id": space_id,
        "thread_name": thread_name,
        "ticket_record": {
            "copy_paste_text": copy_text,
            "reasoning_text": reasoning_text,
        },
    }
    cve_ids = [e.get("id") for e in (f.get("entries") or []) if e.get("id")]
    row = {
        "incident_id": incident_id,
        "vulnerability_id": vulnerability_id,
        "title": summary[:500],
        "severity": cvss_to_severity(f.get("max_score")),
        "affected_systems": json.dumps(f.get("products") or [], ensure_ascii=False),
        "cvss_score": f.get("max_score"),
        "description": None,
        "remediation": None,
        "owners": "[]",
        "status": "notified",
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "due_date": f.get("due_date"),
        "due_reason": f.get("due_reason"),
        "affected_products": json.dumps(f.get("products") or [], ensure_ascii=False),
        "cve_ids": json.dumps(cve_ids, ensure_ascii=False),
        "copy_paste_text": copy_text,
        "reasoning_text": reasoning_text,
        "thread_name": thread_name,
        "space_id": space_id,
        "extra": json.dumps(extra, ensure_ascii=False),
    }
    try:
        client = bigquery.Client(project=get_project_id() or None)
        errors = client.insert_rows_json(table_id, [row])
        if errors:
            logger.warning("Failed to save ticket record to history: %s", errors)
    except Exception as exc:
        logger.warning("Failed to save ticket record to history: %s", exc)
