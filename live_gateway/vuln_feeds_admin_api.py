"""
脆弱性フィード管理API

BigQuery上の vuln_dedup / vuln_poll_state テーブルに対する
読み取り操作を提供する。Admin UI (/admin) から呼び出される REST API のバックエンド実装。
"""

import logging
from typing import Any

try:
    from .sbom_admin_api import _get_bq_client, _get_config_value, _normalize_table_id
except ImportError:
    from sbom_admin_api import _get_bq_client, _get_config_value, _normalize_table_id

logger = logging.getLogger(__name__)

# ════════════════════════════════════════════════════
# ソースメタデータ定義
# ════════════════════════════════════════════════════

SOURCE_METADATA: dict[str, dict[str, str]] = {
    "cisa_kev":   {"label": "CISA KEV",   "category": "public_db"},
    "nvd":        {"label": "NVD",         "category": "public_db"},
    "jvn":        {"label": "JVN",         "category": "public_db"},
    "osv":        {"label": "OSV",         "category": "public_db"},
    "cisco_csaf": {"label": "Cisco",       "category": "vendor_api"},
    "msrc":       {"label": "MSRC",        "category": "vendor_api"},
    "fortinet":   {"label": "Fortinet",    "category": "vendor_api"},
    "almalinux":  {"label": "AlmaLinux",   "category": "vendor_api"},
    "zabbix":     {"label": "Zabbix",      "category": "web_scraping"},
    "motex":      {"label": "MOTEX",       "category": "web_scraping"},
    "skysea":     {"label": "SKYSEA",      "category": "web_scraping"},
}


# ════════════════════════════════════════════════════
# テーブルID取得ヘルパー
# ════════════════════════════════════════════════════

def _get_vuln_dedup_table_id() -> str:
    """vuln_dedup テーブルIDを取得する（環境変数 → Secret Manager）"""
    raw = _get_config_value(
        ["BQ_VULN_DEDUP_TABLE_ID"],
        secret_name="vuln-agent-bq-vuln-dedup-table-id",
    )
    return _normalize_table_id(raw)


def _get_vuln_poll_state_table_id() -> str:
    """vuln_poll_state テーブルIDを取得する（環境変数 → Secret Manager）"""
    raw = _get_config_value(
        ["BQ_VULN_POLL_STATE_TABLE_ID"],
        secret_name="vuln-agent-bq-vuln-poll-state-table-id",
    )
    return _normalize_table_id(raw)


# ════════════════════════════════════════════════════
# ソース一覧
# ════════════════════════════════════════════════════

def list_vuln_sources() -> dict[str, Any]:
    """
    全ソースのポーリングステータスと dedup 集計を返す。

    SOURCE_METADATA に定義された全ソースを基準にし、
    vuln_poll_state テーブルからポーリング情報を、
    vuln_dedup テーブルからソース別の脆弱性件数を取得して結合する。

    Returns:
        {
            "status": "success",
            "sources": [
                {
                    "source_id": "cisa_kev",
                    "label": "CISA KEV",
                    "category": "public_db",
                    "last_poll_at": "...",
                    "last_success_at": "...",
                    "items_fetched": 42,
                    "items_new": 3,
                    "error_message": "",
                    "total_vulns": 156,
                    "sbom_matched_count": 12,
                }
            ]
        }
    """
    from google.cloud import bigquery

    poll_table = _get_vuln_poll_state_table_id()
    dedup_table = _get_vuln_dedup_table_id()

    # ポーリングステータスの取得
    poll_map: dict[str, dict[str, Any]] = {}
    if poll_table:
        try:
            client = _get_bq_client()
            poll_sql = """
                SELECT
                  source_id,
                  FORMAT_TIMESTAMP('%%Y-%%m-%%dT%%H:%%M:%%SZ', last_poll_at)    AS last_poll_at,
                  FORMAT_TIMESTAMP('%%Y-%%m-%%dT%%H:%%M:%%SZ', last_success_at) AS last_success_at,
                  COALESCE(last_cursor, '')    AS last_cursor,
                  COALESCE(items_fetched, 0)   AS items_fetched,
                  COALESCE(items_new, 0)       AS items_new,
                  COALESCE(error_message, '')   AS error_message
                FROM `{t}`
            """.format(t=poll_table)
            rows = client.query(poll_sql).result()
            for row in rows:
                poll_map[row.source_id] = {
                    "last_poll_at":    row.last_poll_at or "",
                    "last_success_at": row.last_success_at or "",
                    "last_cursor":     row.last_cursor,
                    "items_fetched":   row.items_fetched,
                    "items_new":       row.items_new,
                    "error_message":   row.error_message,
                }
        except Exception as e:
            logger.error("list_vuln_sources poll_state query error: %s", e)
            return {"status": "error", "message": str(e)}

    # dedup テーブルからソース別の脆弱性件数集計
    dedup_map: dict[str, dict[str, int]] = {}
    if dedup_table:
        try:
            client = _get_bq_client()
            dedup_sql = """
                SELECT
                  first_source,
                  COUNT(*)                                          AS total_vulns,
                  COUNTIF(sbom_matched IS TRUE)                     AS sbom_matched_count
                FROM `{t}`
                GROUP BY first_source
            """.format(t=dedup_table)
            rows = client.query(dedup_sql).result()
            for row in rows:
                dedup_map[row.first_source] = {
                    "total_vulns":       row.total_vulns,
                    "sbom_matched_count": row.sbom_matched_count,
                }
        except Exception as e:
            logger.error("list_vuln_sources dedup query error: %s", e)
            return {"status": "error", "message": str(e)}

    # ソースメタデータを基準に結合
    sources: list[dict[str, Any]] = []
    for source_id, meta in SOURCE_METADATA.items():
        poll_info = poll_map.get(source_id, {})
        dedup_info = dedup_map.get(source_id, {})
        sources.append({
            "source_id":          source_id,
            "label":              meta["label"],
            "category":           meta["category"],
            "last_poll_at":       poll_info.get("last_poll_at", ""),
            "last_success_at":    poll_info.get("last_success_at", ""),
            "items_fetched":      poll_info.get("items_fetched", 0),
            "items_new":          poll_info.get("items_new", 0),
            "error_message":      poll_info.get("error_message", ""),
            "total_vulns":        dedup_info.get("total_vulns", 0),
            "sbom_matched_count": dedup_info.get("sbom_matched_count", 0),
        })

    return {"status": "success", "sources": sources}


# ════════════════════════════════════════════════════
# 脆弱性一覧
# ════════════════════════════════════════════════════

def list_vulns(
    source: str = "",
    q: str = "",
    sbom_matched: str = "",
    processed: str = "",
    page: int = 1,
    per_page: int = 50,
) -> dict[str, Any]:
    """
    dedup テーブルから脆弱性エントリ一覧を取得する（ページネーション対応）。

    Args:
        source:       ソースID（空=全ソース、first_source でフィルタ）
        q:            vuln_id の部分一致検索
        sbom_matched: SBOM突合フィルタ ("true" | "false" | "" で全件)
        processed:    処理済みフィルタ ("true" | "false" | "" で全件)
        page:         ページ番号（1始まり）
        per_page:     1ページあたり件数（最大200）

    Returns:
        {
            "status": "success",
            "entries": [...],
            "total": N,
            "page": P,
            "per_page": PP
        }
    """
    from google.cloud import bigquery

    table_id = _get_vuln_dedup_table_id()
    if not table_id:
        return {"status": "error", "message": "BQ_VULN_DEDUP_TABLE_ID が未設定です"}

    per_page = max(1, min(int(per_page), 200))
    page = max(1, int(page))
    offset = (page - 1) * per_page

    try:
        client = _get_bq_client()
        conditions: list[str] = []
        params: list[bigquery.ScalarQueryParameter] = []

        # ソースフィルタ
        if source and source.strip():
            conditions.append("first_source = @source")
            params.append(bigquery.ScalarQueryParameter("source", "STRING", source.strip()))

        # vuln_id 部分一致検索
        if q and q.strip():
            conditions.append("LOWER(vuln_id) LIKE @q")
            params.append(bigquery.ScalarQueryParameter("q", "STRING", f"%{q.lower().strip()}%"))

        # SBOM突合フィルタ
        if sbom_matched == "true":
            conditions.append("sbom_matched IS TRUE")
        elif sbom_matched == "false":
            conditions.append("(sbom_matched IS FALSE OR sbom_matched IS NULL)")

        # 処理済みフィルタ
        if processed == "true":
            conditions.append("processed IS TRUE")
        elif processed == "false":
            conditions.append("(processed IS FALSE OR processed IS NULL)")

        where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        # 件数カウント
        count_sql = "SELECT COUNT(*) AS cnt FROM `{t}` {w}".format(
            t=table_id, w=where_clause
        )
        job_config = bigquery.QueryJobConfig(query_parameters=params)
        total = list(client.query(count_sql, job_config=job_config).result())[0].cnt

        # データ取得
        data_sql = """
            SELECT
              vuln_id,
              aliases,
              COALESCE(first_source, '')   AS first_source,
              FORMAT_TIMESTAMP('%%Y-%%m-%%dT%%H:%%M:%%SZ', first_seen_at)   AS first_seen_at,
              sources_seen,
              FORMAT_TIMESTAMP('%%Y-%%m-%%dT%%H:%%M:%%SZ', last_updated_at) AS last_updated_at,
              COALESCE(processed, FALSE)   AS processed,
              COALESCE(sbom_matched, FALSE) AS sbom_matched,
              COALESCE(skip_reason, '')    AS skip_reason
            FROM `{t}`
            {w}
            ORDER BY first_seen_at DESC
            LIMIT @limit OFFSET @offset
        """.format(t=table_id, w=where_clause)
        params_data = list(params) + [
            bigquery.ScalarQueryParameter("limit", "INT64", per_page),
            bigquery.ScalarQueryParameter("offset", "INT64", offset),
        ]
        job_config_data = bigquery.QueryJobConfig(query_parameters=params_data)
        rows = client.query(data_sql, job_config=job_config_data).result()

        entries = [
            {
                "vuln_id":         row.vuln_id,
                "aliases":         list(row.aliases) if row.aliases else [],
                "first_source":    row.first_source,
                "first_seen_at":   row.first_seen_at or "",
                "sources_seen":    list(row.sources_seen) if row.sources_seen else [],
                "last_updated_at": row.last_updated_at or "",
                "processed":       row.processed,
                "sbom_matched":    row.sbom_matched,
                "skip_reason":     row.skip_reason,
            }
            for row in rows
        ]
        return {
            "status": "success",
            "entries": entries,
            "total": total,
            "page": page,
            "per_page": per_page,
        }
    except Exception as e:
        logger.error("list_vulns error: %s", e)
        return {"status": "error", "message": str(e)}


# ════════════════════════════════════════════════════
# 脆弱性詳細
# ════════════════════════════════════════════════════

def get_vuln_detail(vuln_id: str) -> dict[str, Any]:
    """
    特定の脆弱性の詳細情報を返す。

    Args:
        vuln_id: 脆弱性ID（例: CVE-2024-12345）

    Returns:
        {
            "status": "success",
            "vuln": {
                "vuln_id": "...",
                "aliases": [...],
                "first_source": "...",
                "first_seen_at": "...",
                "sources_seen": [...],
                "last_updated_at": "...",
                "processed": true/false,
                "sbom_matched": true/false,
                "skip_reason": "..."
            }
        }
        or {"status": "error", "message": "..."}
    """
    from google.cloud import bigquery

    table_id = _get_vuln_dedup_table_id()
    if not table_id:
        return {"status": "error", "message": "BQ_VULN_DEDUP_TABLE_ID が未設定です"}

    vuln_id = (vuln_id or "").strip()
    if not vuln_id:
        return {"status": "error", "message": "vuln_id は必須です"}

    try:
        client = _get_bq_client()
        sql = """
            SELECT
              vuln_id,
              aliases,
              COALESCE(first_source, '')   AS first_source,
              FORMAT_TIMESTAMP('%%Y-%%m-%%dT%%H:%%M:%%SZ', first_seen_at)   AS first_seen_at,
              sources_seen,
              FORMAT_TIMESTAMP('%%Y-%%m-%%dT%%H:%%M:%%SZ', last_updated_at) AS last_updated_at,
              COALESCE(processed, FALSE)   AS processed,
              COALESCE(sbom_matched, FALSE) AS sbom_matched,
              COALESCE(skip_reason, '')    AS skip_reason
            FROM `{t}`
            WHERE vuln_id = @vuln_id
            LIMIT 1
        """.format(t=table_id)
        params = [bigquery.ScalarQueryParameter("vuln_id", "STRING", vuln_id)]
        job_config = bigquery.QueryJobConfig(query_parameters=params)
        rows = list(client.query(sql, job_config=job_config).result())

        if not rows:
            return {"status": "error", "message": f"vuln_id '{vuln_id}' が見つかりません"}

        row = rows[0]
        return {
            "status": "success",
            "vuln": {
                "vuln_id":         row.vuln_id,
                "aliases":         list(row.aliases) if row.aliases else [],
                "first_source":    row.first_source,
                "first_seen_at":   row.first_seen_at or "",
                "sources_seen":    list(row.sources_seen) if row.sources_seen else [],
                "last_updated_at": row.last_updated_at or "",
                "processed":       row.processed,
                "sbom_matched":    row.sbom_matched,
                "skip_reason":     row.skip_reason,
            },
        }
    except Exception as e:
        logger.error("get_vuln_detail error: %s", e)
        return {"status": "error", "message": str(e)}
