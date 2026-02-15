"""
Capability Tools - 現在権限で実行可能な操作の可視化と実行

このモジュールは「権限を増やさず、今の権限で何ができるか」を
エージェント自身が判断できるようにするための補助ツール群です。
"""

from __future__ import annotations

import os
import re
from typing import Any

from google.cloud import bigquery

try:
    from .secret_config import get_config_value
    from .gmail_tools import check_gmail_connection
    from .chat_tools import check_chat_connection
    from .sheets_tools import get_owner_mapping
    from .a2a_tools import list_registered_agents
except ImportError:
    from secret_config import get_config_value
    from gmail_tools import check_gmail_connection
    from chat_tools import check_chat_connection
    from sheets_tools import get_owner_mapping
    from a2a_tools import list_registered_agents


_BQ_FULL_TABLE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_\-:]+\.[A-Za-z0-9_]+\.[A-Za-z0-9_$]+$")
_BQ_SHORT_TABLE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_]+\.[A-Za-z0-9_$]+$")
_BQ_DATASET_ID_PATTERN = re.compile(r"^[A-Za-z0-9_\-:]+\.[A-Za-z0-9_]+$")
_FORBIDDEN_SQL_PATTERN = re.compile(
    r"\b(insert|update|delete|merge|create|drop|alter|truncate|grant|revoke)\b",
    re.IGNORECASE,
)


def get_runtime_capabilities(include_live_checks: bool = True) -> dict[str, Any]:
    """
    エージェントが現時点で実行可能な機能を返す。

    include_live_checks=True の場合、実際に接続確認ツールを呼び出して
    現在権限での可否を返す。
    """
    backend = get_config_value(
        ["SBOM_DATA_BACKEND"],
        secret_name="vuln-agent-sbom-data-backend",
        default="sheets",
    ).strip().lower()

    configured_tables = {
        "sbom": _normalize_table_id(
            get_config_value(
                ["BQ_SBOM_TABLE_ID"],
                secret_name="vuln-agent-bq-sbom-table-id",
                default="",
            )
        ),
        "owner_mapping": _normalize_table_id(
            get_config_value(
                ["BQ_OWNER_MAPPING_TABLE_ID"],
                secret_name="vuln-agent-bq-owner-table-id",
                default="",
            )
        ),
        "history": _normalize_table_id(
            get_config_value(
                ["BQ_HISTORY_TABLE_ID"],
                secret_name="vuln-agent-bq-table-id",
                default="",
            )
            or os.environ.get("BQ_HISTORY_TABLE_ID", "")
        ),
    }

    capabilities = {
        "tool_groups": {
            "gmail": [
                "check_gmail_connection",
                "get_sidfm_emails",
                "get_unread_emails",
                "mark_email_as_read",
            ],
            "sbom": [
                "search_sbom_by_purl",
                "search_sbom_by_product",
                "get_affected_systems",
                "get_owner_mapping",
            ],
            "chat": [
                "check_chat_connection",
                "send_simple_message",
                "send_vulnerability_alert",
                "list_space_members",
            ],
            "history": ["log_vulnerability_history"],
            "a2a": [
                "register_remote_agent",
                "list_registered_agents",
                "call_remote_agent",
                "create_jira_ticket_request",
                "create_approval_request",
            ],
            "capability": [
                "get_runtime_capabilities",
                "inspect_bigquery_capabilities",
                "list_bigquery_tables",
                "run_bigquery_readonly_query",
            ],
        },
        "configuration": {
            "sbom_backend": backend,
            "bigquery_tables": configured_tables,
            "project_id": _get_project_id(),
        },
    }

    if include_live_checks:
        capabilities["live_checks"] = {
            "gmail": _run_safe_check(check_gmail_connection),
            "chat": _run_safe_check(check_chat_connection),
            "owner_mapping": _run_safe_check(get_owner_mapping),
            "a2a_registry": _run_safe_check(list_registered_agents),
        }

    return capabilities


def inspect_bigquery_capabilities(max_tables_per_dataset: int = 50) -> dict[str, Any]:
    """
    現在権限で BigQuery の何ができるかを診断する。

    - 固定テーブル読取可否（SELECT 1）
    - データセット列挙可否
    - テーブル列挙可否
    """
    max_tables = _normalize_limit(max_tables_per_dataset, default=50, max_value=200)
    table_ids = _configured_table_ids()

    try:
        client = _get_bigquery_client()
    except Exception as exc:
        return {"status": "error", "message": f"BigQuery client init failed: {exc}"}

    table_checks = []
    datasets_to_try = set()
    for name, table_id in table_ids.items():
        if not table_id:
            table_checks.append(
                {"name": name, "table_id": "", "readable": False, "message": "not configured"}
            )
            continue
        dataset_ref = _extract_dataset_ref(table_id, client.project or "")
        if dataset_ref:
            datasets_to_try.add(dataset_ref)
        table_checks.append(_check_table_read(client, name, table_id))

    dataset_listing = _try_list_datasets(client)

    table_listing = []
    for dataset_ref in sorted(datasets_to_try):
        table_listing.append(_try_list_tables(client, dataset_ref, max_tables))

    return {
        "status": "success",
        "project_id": client.project,
        "configured_tables": table_ids,
        "table_read_checks": table_checks,
        "dataset_listing": dataset_listing,
        "table_listing": table_listing,
    }


def list_bigquery_tables(dataset_id: str, max_results: int = 100) -> dict[str, Any]:
    """
    指定データセットのテーブル一覧を返す。

    dataset_id は以下を受け付ける:
    - project.dataset
    - dataset（この場合は現在プロジェクト補完）
    """
    limit = _normalize_limit(max_results, default=100, max_value=500)

    try:
        client = _get_bigquery_client()
    except Exception as exc:
        return {"status": "error", "message": f"BigQuery client init failed: {exc}"}

    dataset_ref = _normalize_dataset_ref(dataset_id, client.project or "")
    if not dataset_ref:
        return {
            "status": "error",
            "message": "dataset_id は project.dataset または dataset 形式で指定してください。",
        }

    return _try_list_tables(client, dataset_ref, limit)


def run_bigquery_readonly_query(query: str, max_rows: int = 100) -> dict[str, Any]:
    """
    Read-only SQL (SELECT/WITH) のみ実行する。

    権限拡張なしで、現在の BigQuery 権限で取得できる情報を柔軟に参照するためのツール。
    """
    sql = _normalize_sql(query)
    if not sql:
        return {"status": "error", "message": "query は必須です。"}
    if not _is_readonly_sql(sql):
        return {
            "status": "error",
            "message": "read-only な SELECT/WITH クエリのみ実行可能です。",
        }

    limit = _normalize_limit(max_rows, default=100, max_value=1000)
    sql_with_limit = f"SELECT * FROM ({sql}) LIMIT {limit}"

    try:
        client = _get_bigquery_client()
        rows = client.query(sql_with_limit).result()
        items = []
        for row in rows:
            items.append({key: row.get(key) for key in row.keys()})
        return {
            "status": "success",
            "row_count": len(items),
            "rows": items,
            "applied_limit": limit,
        }
    except Exception as exc:
        return {"status": "error", "message": f"BigQuery query failed: {exc}"}


def _get_project_id() -> str:
    return (
        get_config_value(
            ["GCP_PROJECT_ID", "BQ_PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT"],
            default="",
        ).strip()
        or ""
    )


def _get_bigquery_client() -> bigquery.Client:
    project = _get_project_id() or None
    return bigquery.Client(project=project)


def _configured_table_ids() -> dict[str, str]:
    return {
        "sbom": _normalize_table_id(
            get_config_value(
                ["BQ_SBOM_TABLE_ID"],
                secret_name="vuln-agent-bq-sbom-table-id",
                default="",
            )
        ),
        "owner_mapping": _normalize_table_id(
            get_config_value(
                ["BQ_OWNER_MAPPING_TABLE_ID"],
                secret_name="vuln-agent-bq-owner-table-id",
                default="",
            )
        ),
        "history": _normalize_table_id(
            get_config_value(
                ["BQ_HISTORY_TABLE_ID"],
                secret_name="vuln-agent-bq-table-id",
                default="",
            )
            or os.environ.get("BQ_HISTORY_TABLE_ID", "")
        ),
    }


def _normalize_table_id(raw_table_id: str) -> str:
    table_id = (raw_table_id or "").strip().strip("`")
    if not table_id:
        return ""
    if _BQ_FULL_TABLE_ID_PATTERN.match(table_id) or _BQ_SHORT_TABLE_ID_PATTERN.match(table_id):
        return table_id
    return ""


def _normalize_dataset_ref(raw_dataset: str, default_project: str) -> str:
    dataset = (raw_dataset or "").strip().strip("`")
    if not dataset:
        return ""
    if "." not in dataset:
        if not default_project:
            return ""
        return f"{default_project}.{dataset}"
    if _BQ_DATASET_ID_PATTERN.match(dataset):
        return dataset
    return ""


def _extract_dataset_ref(table_id: str, default_project: str) -> str:
    clean = (table_id or "").strip().strip("`")
    parts = clean.split(".")
    if len(parts) == 3:
        return f"{parts[0]}.{parts[1]}"
    if len(parts) == 2 and default_project:
        return f"{default_project}.{parts[0]}"
    return ""


def _check_table_read(client: bigquery.Client, name: str, table_id: str) -> dict[str, Any]:
    sql = f"SELECT 1 AS ok FROM `{table_id}` LIMIT 1"
    try:
        _ = list(client.query(sql).result())
        return {"name": name, "table_id": table_id, "readable": True}
    except Exception as exc:
        return {
            "name": name,
            "table_id": table_id,
            "readable": False,
            "message": str(exc),
        }


def _try_list_datasets(client: bigquery.Client) -> dict[str, Any]:
    try:
        datasets = [d.dataset_id for d in client.list_datasets()]
        return {"status": "success", "count": len(datasets), "datasets": datasets}
    except Exception as exc:
        return {"status": "error", "message": str(exc), "datasets": []}


def _try_list_tables(client: bigquery.Client, dataset_ref: str, max_results: int) -> dict[str, Any]:
    try:
        tables = []
        for table in client.list_tables(dataset_ref, max_results=max_results):
            tables.append(
                {
                    "table_id": table.table_id,
                    "full_table_id": getattr(table, "full_table_id", ""),
                    "table_type": getattr(table, "table_type", ""),
                }
            )
        return {
            "status": "success",
            "dataset_id": dataset_ref,
            "count": len(tables),
            "tables": tables,
            "max_results": max_results,
        }
    except Exception as exc:
        return {
            "status": "error",
            "dataset_id": dataset_ref,
            "message": str(exc),
            "tables": [],
        }


def _normalize_limit(value: Any, default: int, max_value: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        return default
    if result < 1:
        return 1
    if result > max_value:
        return max_value
    return result


def _normalize_sql(sql: str | None) -> str:
    return (sql or "").strip().rstrip(";").strip()


def _is_readonly_sql(sql: str) -> bool:
    normalized = _normalize_sql(sql)
    if ";" in normalized:
        return False
    lower = normalized.lower()
    if not (lower.startswith("select") or lower.startswith("with")):
        return False
    if _FORBIDDEN_SQL_PATTERN.search(lower):
        return False
    return True


def _run_safe_check(func: Any) -> dict[str, Any]:
    try:
        result = func()
        if isinstance(result, dict):
            return result
        return {"status": "success", "result": result}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}
