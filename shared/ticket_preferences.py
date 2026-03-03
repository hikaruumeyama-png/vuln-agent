"""起票テンプレート学習システム（Preferences）。

ユーザーの修正履歴からフィールド単位で好みを学習し、
次回の起票テンプレート生成に反映する。
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from shared.infra import get_config, get_project_id

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 定数
# ---------------------------------------------------------------------------

_TICKET_SECTION_MARKERS = (
    "【対象の機器/アプリ】",
    "【脆弱性情報】",
    "【CVSSスコア】",
    "【依頼内容】",
    "【対応完了目標】",
    "【備考】",
)
_TICKET_FIELD_MAP = {
    "【対象の機器/アプリ】": "target_devices",
    "【脆弱性情報】": "vuln_links",
    "【CVSSスコア】": "cvss_score",
    "【依頼内容】": "remediation_text",
    "【対応完了目標】": "due_date",
    "【備考】": "notes",
}

_CORRECTION_DETECT_FIELDS = (
    "remediation_text", "due_date", "target_devices", "cvss_score",
    "request_summary", "vuln_links", "notes",
    "category_major", "category_minor",
)

PREFERENCE_STRONG_THRESHOLD = 3  # correction_count >= 3 でAI上書きしない


# ---------------------------------------------------------------------------
# セクション分割
# ---------------------------------------------------------------------------


def split_ticket_into_sections(ticket_text: str) -> dict[str, str]:
    """起票テンプレートをセクションマーカーで分割し、{field_name: value} のdictを返す。"""
    result: dict[str, str] = {}
    body = (ticket_text or "").strip()
    if not body:
        return result
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("依頼概要:"):
            result["request_summary"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("大分類:"):
            result["category_major"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("小分類:"):
            result["category_minor"] = stripped.split(":", 1)[1].strip()
    all_markers = list(_TICKET_SECTION_MARKERS)
    all_markers.extend(["【判断理由】", "【管理ID】"])
    positions: list[tuple[int, str]] = []
    for marker in all_markers:
        idx = body.find(marker)
        if idx >= 0:
            positions.append((idx, marker))
    positions.sort(key=lambda x: x[0])
    for i, (pos, marker) in enumerate(positions):
        end = positions[i + 1][0] if i + 1 < len(positions) else len(body)
        content = body[pos + len(marker):end].strip()
        content = re.sub(r"^（[^）]*）\s*", "", content).strip()
        field = _TICKET_FIELD_MAP.get(marker, marker)
        result[field] = content
    return result


# ---------------------------------------------------------------------------
# 修正検出
# ---------------------------------------------------------------------------


def detect_correction_fields(
    original: str, revised: str, instruction: str,
) -> list[tuple[str, str, str]]:
    """修正前後のチケットを比較し、変更があった全フィールドを返す。"""
    _ = instruction
    orig_sections = split_ticket_into_sections(original)
    rev_sections = split_ticket_into_sections(revised)
    changes: list[tuple[str, str, str]] = []
    for field in _CORRECTION_DETECT_FIELDS:
        orig_val = orig_sections.get(field, "")
        rev_val = rev_sections.get(field, "")
        if orig_val != rev_val and rev_val:
            changes.append((field, orig_val, rev_val))
    return changes


def determine_pattern_key(
    field_name: str,
    source_text: str = "",
    facts: dict[str, Any] | None = None,
) -> str:
    """修正フィールドに応じたパターンキーを決定する。"""
    if not field_name:
        return "*"
    if field_name == "due_date" and facts:
        max_score = facts.get("max_score")
        if isinstance(max_score, (int, float)):
            if max_score >= 9.0:
                return "cvss>=9.0"
            if max_score >= 7.0:
                return "cvss>=7.0"
    if field_name in ("remediation_text", "target_devices"):
        source = source_text or ""
        for product in ("AlmaLinux", "CentOS", "Ubuntu", "Windows", "Apache", "nginx"):
            if product.lower() in source.lower():
                return product
    return "*"


# ---------------------------------------------------------------------------
# BQ 保存・取得
# ---------------------------------------------------------------------------


def save_ticket_preference(
    space_id: str,
    field_name: str,
    pattern_key: str,
    preferred_value: str,
    original_value: str,
    created_by: str,
) -> None:
    """修正内容をBQのticket_preferencesテーブルに保存。MERGE文で1クエリに統合。"""
    table_id = get_config("BQ_PREFERENCES_TABLE_ID", "vuln-agent-bq-preferences-table-id", "").strip()
    if not table_id or not space_id or not field_name:
        return
    try:
        from google.cloud import bigquery

        project_id = get_project_id() or None
        client = bigquery.Client(project=project_id)
        now = datetime.now(timezone.utc).isoformat()
        preference_id = str(uuid.uuid4())

        merge_query = f"""
            MERGE `{table_id}` T
            USING (SELECT @space_id AS space_id, @field_name AS field_name, @pattern_key AS pattern_key) S
            ON T.space_id = S.space_id AND T.field_name = S.field_name AND T.pattern_key = S.pattern_key
            WHEN MATCHED THEN
                UPDATE SET
                    preferred_value = @preferred_value,
                    original_value = @original_value,
                    correction_count = T.correction_count + 1,
                    updated_at = @updated_at
            WHEN NOT MATCHED THEN
                INSERT (preference_id, space_id, field_name, pattern_key,
                        preferred_value, original_value, correction_count,
                        created_at, updated_at, created_by, extra)
                VALUES (@preference_id, @space_id, @field_name, @pattern_key,
                        @preferred_value, @original_value, 1,
                        @created_at, @updated_at, @created_by, '{{}}')
        """
        merge_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("space_id", "STRING", space_id),
                bigquery.ScalarQueryParameter("field_name", "STRING", field_name),
                bigquery.ScalarQueryParameter("pattern_key", "STRING", pattern_key),
                bigquery.ScalarQueryParameter("preferred_value", "STRING", preferred_value),
                bigquery.ScalarQueryParameter("original_value", "STRING", original_value),
                bigquery.ScalarQueryParameter("updated_at", "TIMESTAMP", now),
                bigquery.ScalarQueryParameter("preference_id", "STRING", preference_id),
                bigquery.ScalarQueryParameter("created_at", "TIMESTAMP", now),
                bigquery.ScalarQueryParameter("created_by", "STRING", created_by or ""),
            ]
        )
        client.query(merge_query, job_config=merge_config).result()
    except Exception as exc:
        logger.warning("save_ticket_preference failed: %s", exc)


def save_correction_as_preference(
    space_id: str,
    original_ticket: str,
    revised_ticket: str,
    instruction: str,
    created_by: str = "",
) -> None:
    """修正成功時に自動的に学習データとしてBQに保存する。"""
    changes = detect_correction_fields(original_ticket, revised_ticket, instruction)
    if not changes or not space_id:
        return
    for field_name, original_value, new_value in changes:
        pattern_key = determine_pattern_key(field_name)
        save_ticket_preference(
            space_id=space_id,
            field_name=field_name,
            pattern_key=pattern_key,
            preferred_value=new_value,
            original_value=original_value,
            created_by=created_by,
        )


def fetch_ticket_preferences(
    space_id: str,
    product_names: list[str] | None = None,
    cvss_score: float | None = None,
) -> dict[str, str]:
    """空間ごとの学習済みプリファレンスをBQから取得し、{field_name: preferred_value} を返す。"""
    table_id = get_config("BQ_PREFERENCES_TABLE_ID", "vuln-agent-bq-preferences-table-id", "").strip()
    if not table_id or not space_id:
        return {}
    try:
        from google.cloud import bigquery

        project_id = get_project_id() or None
        client = bigquery.Client(project=project_id)
        query = f"""
            SELECT field_name, pattern_key, preferred_value, correction_count
            FROM `{table_id}`
            WHERE space_id = @space_id
            ORDER BY correction_count DESC, updated_at DESC
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("space_id", "STRING", space_id),
            ]
        )
        rows = list(client.query(query, job_config=job_config).result())
        if not rows:
            return {}

        candidate_patterns: list[str] = ["*"]
        for p in (product_names or []):
            candidate_patterns.append(p)
        if isinstance(cvss_score, (int, float)):
            if cvss_score >= 9.0:
                candidate_patterns.append("cvss>=9.0")
            if cvss_score >= 7.0:
                candidate_patterns.append("cvss>=7.0")

        result: dict[str, str] = {}
        result_counts: dict[str, int] = {}
        for row in rows:
            field = str(getattr(row, "field_name", "") or "").strip()
            pattern = str(getattr(row, "pattern_key", "") or "").strip()
            value = str(getattr(row, "preferred_value", "") or "").strip()
            count = int(getattr(row, "correction_count", 0) or 0)
            if not field or not value:
                continue
            if pattern not in candidate_patterns:
                continue
            existing_count = result_counts.get(field, -1)
            is_more_specific = (
                pattern != "*"
                and result.get(field)
                and result_counts.get(field, 0) <= count
            )
            is_first = field not in result
            is_higher_count = count > existing_count
            if is_first or is_more_specific or (pattern != "*" and is_higher_count):
                result[field] = value
                result_counts[field] = count
        return result
    except Exception as exc:
        logger.warning("fetch_ticket_preferences failed: %s", exc)
        return {}


def get_preference_correction_counts(space_id: str) -> dict[str, int]:
    """各フィールドのcorrection_countを返す。"""
    table_id = get_config("BQ_PREFERENCES_TABLE_ID", "vuln-agent-bq-preferences-table-id", "").strip()
    if not table_id or not space_id:
        return {}
    try:
        from google.cloud import bigquery

        project_id = get_project_id() or None
        client = bigquery.Client(project=project_id)
        query = f"""
            SELECT field_name, MAX(correction_count) AS max_count
            FROM `{table_id}`
            WHERE space_id = @space_id
            GROUP BY field_name
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("space_id", "STRING", space_id),
            ]
        )
        rows = list(client.query(query, job_config=job_config).result())
        return {
            str(getattr(r, "field_name", "")): int(getattr(r, "max_count", 0) or 0)
            for r in rows
        }
    except Exception as exc:
        logger.warning("get_preference_correction_counts failed: %s", exc)
        return {}


def apply_preferences_to_facts(
    facts: dict[str, Any],
    preferences: dict[str, str],
) -> dict[str, Any]:
    """学習済みプリファレンスをmerged_factsに適用する。"""
    if not preferences:
        return facts
    field_to_fact_key = {
        "remediation_text": "remediation_text",
        "due_date": "due_date",
        "target_devices": "products",
    }
    for field, value in preferences.items():
        fact_key = field_to_fact_key.get(field)
        if not fact_key:
            continue
        if fact_key == "products" and value:
            facts[fact_key] = [v.strip() for v in value.split("\n") if v.strip()]
        else:
            facts[fact_key] = value
    return facts
