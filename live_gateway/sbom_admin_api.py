"""
SBOM・担当者マッピング 管理API

BigQueryに対するCRUD操作を提供する。
Admin UI (/admin) から呼び出される REST API のバックエンド実装。
"""

import logging
import os
import re
from typing import Any

logger = logging.getLogger(__name__)

# BQテーブルIDのバリデーション用（sheets_toolsと同じパターン）
_BQ_FULL_TABLE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_\-:]+\.[A-Za-z0-9_]+\.[A-Za-z0-9_$]+$")
_BQ_SHORT_TABLE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_]+\.[A-Za-z0-9_$]+$")


_secret_cache: dict[str, str] = {}


def _get_config_value(env_keys: list[str], secret_name: str = "", default: str = "") -> str:
    """
    設定値を取得する。
    優先順位: 環境変数 → Secret Manager (モジュールレベルキャッシュ) → default
    """
    for key in env_keys:
        val = os.environ.get(key, "").strip()
        if val:
            return val
    if secret_name:
        if secret_name in _secret_cache:
            return _secret_cache[secret_name] or default
        project = os.environ.get("GCP_PROJECT_ID", "").strip()
        if project:
            try:
                from google.cloud import secretmanager
                client = secretmanager.SecretManagerServiceClient()
                name = f"projects/{project}/secrets/{secret_name}/versions/latest"
                response = client.access_secret_version(request={"name": name})
                val = response.payload.data.decode("utf-8").strip()
                _secret_cache[secret_name] = val
                if val:
                    return val
            except Exception as e:
                logger.debug("Secret Manager lookup failed for %s: %s", secret_name, e)
                _secret_cache[secret_name] = ""
    return default


def _normalize_table_id(raw: str) -> str:
    """BigQueryテーブルIDを検証・正規化する"""
    table_id = (raw or "").strip().strip("`")
    if not table_id:
        return ""
    if _BQ_FULL_TABLE_ID_PATTERN.match(table_id):
        return table_id
    if _BQ_SHORT_TABLE_ID_PATTERN.match(table_id):
        return table_id
    logger.error("BigQuery table ID format invalid: %s", table_id)
    return ""


def _get_bq_client():
    """BigQueryクライアントを取得する"""
    try:
        from google.cloud import bigquery
    except ImportError:
        raise RuntimeError("google-cloud-bigquery がインストールされていません")

    project = _get_config_value(
        ["GCP_PROJECT_ID", "BQ_PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT"]
    ) or None
    if not project:
        try:
            from google.auth import default as gauth_default
            _, detected = gauth_default()
            project = (detected or "").strip() or None
        except Exception:
            project = None

    return bigquery.Client(project=project)


def _get_sbom_table_id() -> str:
    """SBOMテーブルIDを取得する（環境変数 → Secret Manager）"""
    raw = _get_config_value(
        ["BQ_SBOM_TABLE_ID"],
        secret_name="vuln-agent-bq-sbom-table-id",
    )
    return _normalize_table_id(raw)


def _get_owner_table_id() -> str:
    """担当者マッピングテーブルIDを取得する（環境変数 → Secret Manager）"""
    raw = _get_config_value(
        ["BQ_OWNER_MAPPING_TABLE_ID"],
        secret_name="vuln-agent-bq-owner-table-id",
    )
    return _normalize_table_id(raw)


# ════════════════════════════════════════════════════
# SBOM CRUD
# ════════════════════════════════════════════════════

def list_sbom(q: str = "", page: int = 1, per_page: int = 50) -> dict[str, Any]:
    """
    SBOMエントリを一覧取得する（ページネーション対応）

    Args:
        q: name/PURLへの部分一致検索クエリ
        page: ページ番号（1始まり）
        per_page: 1ページあたりの件数（最大200）

    Returns:
        {"status": "success", "entries": [...], "total": N, "page": P, "per_page": PP}
    """
    from google.cloud import bigquery

    table_id = _get_sbom_table_id()
    if not table_id:
        return {"status": "error", "message": "BQ_SBOM_TABLE_ID が未設定です"}

    per_page = max(1, min(int(per_page), 200))
    page = max(1, int(page))
    offset = (page - 1) * per_page

    try:
        client = _get_bq_client()
        params: list[bigquery.ScalarQueryParameter] = []

        where_clause = ""
        if q and q.strip():
            where_clause = "WHERE LOWER(COALESCE(name,'')) LIKE @q OR LOWER(COALESCE(purl,'')) LIKE @q"
            params.append(bigquery.ScalarQueryParameter("q", "STRING", f"%{q.lower().strip()}%"))

        count_sql = f"SELECT COUNT(*) AS cnt FROM `{table_id}` {where_clause}"
        job_config = bigquery.QueryJobConfig(query_parameters=params)
        total = list(client.query(count_sql, job_config=job_config).result())[0].cnt

        data_sql = f"""
            SELECT
              COALESCE(type, '')       AS type,
              COALESCE(name, '')       AS name,
              COALESCE(version, '')    AS version,
              COALESCE(release, '')    AS release,
              COALESCE(purl, '')       AS purl,
              COALESCE(os_name, '')    AS os_name,
              COALESCE(os_version, '') AS os_version,
              COALESCE(arch, '')       AS arch
            FROM `{table_id}`
            {where_clause}
            ORDER BY name, version
            LIMIT @limit OFFSET @offset
        """
        params_data = list(params) + [
            bigquery.ScalarQueryParameter("limit", "INT64", per_page),
            bigquery.ScalarQueryParameter("offset", "INT64", offset),
        ]
        job_config_data = bigquery.QueryJobConfig(query_parameters=params_data)
        rows = client.query(data_sql, job_config=job_config_data).result()

        entries = [
            {
                "type": row.type,
                "name": row.name,
                "version": row.version,
                "release": row.release,
                "purl": row.purl,
                "os_name": row.os_name,
                "os_version": row.os_version,
                "arch": row.arch,
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
        logger.error("list_sbom error: %s", e)
        return {"status": "error", "message": str(e)}


def insert_sbom_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """
    SBOMエントリを新規追加する（purl が重複する場合はエラー）

    Args:
        entry: {type, name, version, release, purl, os_name, os_version, arch}

    Returns:
        {"status": "success"} or {"status": "error", "message": "..."}
    """
    from google.cloud import bigquery

    table_id = _get_sbom_table_id()
    if not table_id:
        return {"status": "error", "message": "BQ_SBOM_TABLE_ID が未設定です"}

    purl = (entry.get("purl") or "").strip()

    try:
        client = _get_bq_client()

        # 重複チェック（PURLが指定されている場合のみ）
        if purl:
            check_sql = "SELECT COUNT(*) AS cnt FROM `{t}` WHERE purl = @purl".format(t=table_id)
            check_params = [bigquery.ScalarQueryParameter("purl", "STRING", purl)]
            cnt = list(client.query(
                check_sql,
                job_config=bigquery.QueryJobConfig(query_parameters=check_params)
            ).result())[0].cnt
            if cnt > 0:
                return {"status": "error", "message": f"purl '{purl}' は既に存在します。編集してください。"}

        insert_sql = """
            INSERT INTO `{t}` (type, name, version, release, purl, os_name, os_version, arch)
            VALUES (@type, @name, @version, @release, @purl, @os_name, @os_version, @arch)
        """.format(t=table_id)
        params = [
            bigquery.ScalarQueryParameter("type",       "STRING", (entry.get("type") or "").strip()),
            bigquery.ScalarQueryParameter("name",       "STRING", (entry.get("name") or "").strip()),
            bigquery.ScalarQueryParameter("version",    "STRING", (entry.get("version") or "").strip()),
            bigquery.ScalarQueryParameter("release",    "STRING", (entry.get("release") or "").strip()),
            bigquery.ScalarQueryParameter("purl",       "STRING", purl),
            bigquery.ScalarQueryParameter("os_name",    "STRING", (entry.get("os_name") or "").strip()),
            bigquery.ScalarQueryParameter("os_version", "STRING", (entry.get("os_version") or "").strip()),
            bigquery.ScalarQueryParameter("arch",       "STRING", (entry.get("arch") or "").strip()),
        ]
        client.query(
            insert_sql,
            job_config=bigquery.QueryJobConfig(query_parameters=params)
        ).result()
        logger.info("insert_sbom_entry: purl=%s", purl)
        return {"status": "success"}
    except Exception as e:
        logger.error("insert_sbom_entry error: %s", e)
        return {"status": "error", "message": str(e)}


def update_sbom_entry(old_purl: str, entry: dict[str, Any]) -> dict[str, Any]:
    """
    SBOMエントリを更新する（old_purl で対象を特定）

    Args:
        old_purl: 更新対象の既存purl
        entry: 新しい値 {type, name, version, release, purl, os_name, os_version, arch}

    Returns:
        {"status": "success"} or {"status": "error", "message": "..."}
    """
    from google.cloud import bigquery

    table_id = _get_sbom_table_id()
    if not table_id:
        return {"status": "error", "message": "BQ_SBOM_TABLE_ID が未設定です"}

    old_purl = (old_purl or "").strip()
    new_purl = (entry.get("purl") or "").strip()

    # 旧エントリの特定キー（PURL優先、なければ name/type/version 等で特定）
    old_name = (entry.get("_old_name") or "").strip()
    old_type = (entry.get("_old_type") or "").strip()
    old_version = (entry.get("_old_version") or "").strip()
    old_release = (entry.get("_old_release") or "").strip()

    if not old_purl and not old_name and not old_type:
        return {"status": "error", "message": "更新対象を特定できません（purl または name/type が必要です）"}

    try:
        client = _get_bq_client()

        set_clause = """
              type       = @type,
              name       = @name,
              version    = @version,
              release    = @release,
              purl       = @new_purl,
              os_name    = @os_name,
              os_version = @os_version,
              arch       = @arch"""

        params = [
            bigquery.ScalarQueryParameter("type",       "STRING", (entry.get("type") or "").strip()),
            bigquery.ScalarQueryParameter("name",       "STRING", (entry.get("name") or "").strip()),
            bigquery.ScalarQueryParameter("version",    "STRING", (entry.get("version") or "").strip()),
            bigquery.ScalarQueryParameter("release",    "STRING", (entry.get("release") or "").strip()),
            bigquery.ScalarQueryParameter("new_purl",   "STRING", new_purl),
            bigquery.ScalarQueryParameter("os_name",    "STRING", (entry.get("os_name") or "").strip()),
            bigquery.ScalarQueryParameter("os_version", "STRING", (entry.get("os_version") or "").strip()),
            bigquery.ScalarQueryParameter("arch",       "STRING", (entry.get("arch") or "").strip()),
        ]

        if old_purl:
            where_clause = "WHERE purl = @old_purl"
            params.append(bigquery.ScalarQueryParameter("old_purl", "STRING", old_purl))
        else:
            # PURLなしエントリ: name + type + version + release で特定
            conditions = ["COALESCE(purl,'') = ''"]
            if old_name:
                conditions.append("COALESCE(name,'') = @old_name")
                params.append(bigquery.ScalarQueryParameter("old_name", "STRING", old_name))
            if old_type:
                conditions.append("COALESCE(type,'') = @old_type")
                params.append(bigquery.ScalarQueryParameter("old_type", "STRING", old_type))
            if old_version:
                conditions.append("COALESCE(version,'') = @old_version")
                params.append(bigquery.ScalarQueryParameter("old_version", "STRING", old_version))
            if old_release:
                conditions.append("COALESCE(release,'') = @old_release")
                params.append(bigquery.ScalarQueryParameter("old_release", "STRING", old_release))
            where_clause = "WHERE " + " AND ".join(conditions)

        update_sql = "UPDATE `{t}` SET {s} {w}".format(
            t=table_id, s=set_clause, w=where_clause
        )
        client.query(
            update_sql,
            job_config=bigquery.QueryJobConfig(query_parameters=params)
        ).result()
        logger.info("update_sbom_entry: old_purl=%s new_purl=%s", old_purl, new_purl)
        return {"status": "success"}
    except Exception as e:
        logger.error("update_sbom_entry error: %s", e)
        return {"status": "error", "message": str(e)}


def delete_sbom_entry(
    purl: str = "",
    name: str = "",
    type: str = "",
    version: str = "",
    release: str = "",
    os_name: str = "",
    os_version: str = "",
    arch: str = "",
) -> dict[str, Any]:
    """
    SBOMエントリを削除する。

    purl が指定されている場合は WHERE purl = @purl で削除。
    purl が空の場合は name / type / version / release の組み合わせで削除
    (PURL未設定の古いデータ対応)。

    Args:
        purl:       削除対象のPURL（空の場合はフォールバックキーを使用）
        name:       フォールバック識別キー
        type:       フォールバック識別キー
        version:    フォールバック識別キー
        release:    フォールバック識別キー
        os_name:    フォールバック識別キー（任意）
        os_version: フォールバック識別キー（任意）
        arch:       フォールバック識別キー（任意）

    Returns:
        {"status": "success"} or {"status": "error", "message": "..."}
    """
    from google.cloud import bigquery

    table_id = _get_sbom_table_id()
    if not table_id:
        return {"status": "error", "message": "BQ_SBOM_TABLE_ID が未設定です"}

    purl = (purl or "").strip()

    try:
        client = _get_bq_client()

        if purl:
            # 通常パス: PURLで一意に特定
            delete_sql = "DELETE FROM `{t}` WHERE purl = @purl".format(t=table_id)
            params = [bigquery.ScalarQueryParameter("purl", "STRING", purl)]
            logger.info("delete_sbom_entry by purl: %s", purl)
        else:
            # フォールバック: name + type の組み合わせで削除
            name = (name or "").strip()
            type_ = (type or "").strip()
            if not name and not type_:
                return {"status": "error", "message": "purl または name/type のいずれかが必要です"}

            conditions: list[str] = []
            params: list[bigquery.ScalarQueryParameter] = []

            if name:
                conditions.append("COALESCE(name,'') = @name")
                params.append(bigquery.ScalarQueryParameter("name", "STRING", name))
            if type_:
                conditions.append("COALESCE(type,'') = @type")
                params.append(bigquery.ScalarQueryParameter("type", "STRING", type_))

            version_ = (version or "").strip()
            if version_:
                conditions.append("COALESCE(version,'') = @version")
                params.append(bigquery.ScalarQueryParameter("version", "STRING", version_))

            release_ = (release or "").strip()
            if release_:
                conditions.append("COALESCE(release,'') = @release")
                params.append(bigquery.ScalarQueryParameter("release", "STRING", release_))

            os_name_ = (os_name or "").strip()
            if os_name_:
                conditions.append("COALESCE(os_name,'') = @os_name")
                params.append(bigquery.ScalarQueryParameter("os_name", "STRING", os_name_))

            os_version_ = (os_version or "").strip()
            if os_version_:
                conditions.append("COALESCE(os_version,'') = @os_version")
                params.append(bigquery.ScalarQueryParameter("os_version", "STRING", os_version_))

            arch_ = (arch or "").strip()
            if arch_:
                conditions.append("COALESCE(arch,'') = @arch")
                params.append(bigquery.ScalarQueryParameter("arch", "STRING", arch_))

            # PURLが空のエントリのみ対象（PURLありを誤って削除しない）
            conditions.append("COALESCE(purl,'') = ''")

            delete_sql = "DELETE FROM `{t}` WHERE {w}".format(
                t=table_id, w=" AND ".join(conditions)
            )
            logger.info("delete_sbom_entry by fields: name=%s type=%s version=%s", name, type_, version_)

        client.query(
            delete_sql,
            job_config=bigquery.QueryJobConfig(query_parameters=params)
        ).result()
        return {"status": "success"}
    except Exception as e:
        logger.error("delete_sbom_entry error: %s", e)
        return {"status": "error", "message": str(e)}


def bulk_delete_sbom_entries(entries: list[dict[str, str]]) -> dict[str, Any]:
    """
    SBOMエントリを一括削除する。

    各エントリは purl で特定する。purl が空の場合は name/type/version 等で特定。

    Args:
        entries: 削除対象のリスト [{purl, name, type, version, release, os_name, os_version, arch}, ...]

    Returns:
        {"status": "success", "deleted": N} or {"status": "error", "message": "..."}
    """
    from google.cloud import bigquery

    table_id = _get_sbom_table_id()
    if not table_id:
        return {"status": "error", "message": "BQ_SBOM_TABLE_ID が未設定です"}

    if not entries:
        return {"status": "error", "message": "削除対象が指定されていません"}

    try:
        client = _get_bq_client()
        deleted = 0

        # PURLありエントリをまとめて一括削除
        purls = [
            (e.get("purl") or "").strip()
            for e in entries
            if (e.get("purl") or "").strip()
        ]
        if purls:
            # UNNEST で一括削除
            delete_sql = (
                "DELETE FROM `{t}` WHERE purl IN UNNEST(@purls)"
            ).format(t=table_id)
            params = [bigquery.ArrayQueryParameter("purls", "STRING", purls)]
            result = client.query(
                delete_sql,
                job_config=bigquery.QueryJobConfig(query_parameters=params)
            ).result()
            deleted += result.num_dml_affected_rows or 0

        # PURLなしエントリは個別に削除
        no_purl_entries = [
            e for e in entries
            if not (e.get("purl") or "").strip()
        ]
        for e in no_purl_entries:
            res = delete_sbom_entry(
                purl="",
                name=e.get("name", ""),
                type=e.get("type", ""),
                version=e.get("version", ""),
                release=e.get("release", ""),
                os_name=e.get("os_name", ""),
                os_version=e.get("os_version", ""),
                arch=e.get("arch", ""),
            )
            if res.get("status") == "success":
                deleted += 1

        logger.info("bulk_delete_sbom_entries: deleted %d entries", deleted)
        return {"status": "success", "deleted": deleted}
    except Exception as e:
        logger.error("bulk_delete_sbom_entries error: %s", e)
        return {"status": "error", "message": str(e)}


# ════════════════════════════════════════════════════
# 担当者マッピング CRUD
# ════════════════════════════════════════════════════

def list_owner_mappings(q: str = "") -> dict[str, Any]:
    """
    担当者マッピングを一覧取得する

    Args:
        q: pattern/system_name/owner_email への部分一致検索クエリ

    Returns:
        {"status": "success", "mappings": [...], "total": N}
    """
    from google.cloud import bigquery

    table_id = _get_owner_table_id()
    if not table_id:
        return {"status": "error", "message": "BQ_OWNER_MAPPING_TABLE_ID が未設定です"}

    try:
        client = _get_bq_client()
        params: list[bigquery.ScalarQueryParameter] = []

        where_clause = ""
        if q and q.strip():
            where_clause = (
                "WHERE LOWER(COALESCE(pattern,'')) LIKE @q"
                " OR LOWER(COALESCE(system_name,'')) LIKE @q"
                " OR LOWER(COALESCE(owner_email,'')) LIKE @q"
            )
            params.append(bigquery.ScalarQueryParameter("q", "STRING", f"%{q.lower().strip()}%"))

        sql = """
            SELECT
              COALESCE(NULLIF(TRIM(pattern), ''), '*') AS pattern,
              COALESCE(system_name, '')  AS system_name,
              COALESCE(owner_email, '')  AS owner_email,
              COALESCE(owner_name, '')   AS owner_name,
              COALESCE(notes, '')        AS notes,
              COALESCE(priority, 9999)   AS priority
            FROM `{t}`
            {w}
            ORDER BY COALESCE(priority, 9999), pattern
        """.format(t=table_id, w=where_clause)

        job_config = bigquery.QueryJobConfig(query_parameters=params)
        rows = client.query(sql, job_config=job_config).result()
        mappings = [
            {
                "pattern":     row.pattern,
                "system_name": row.system_name,
                "owner_email": row.owner_email,
                "owner_name":  row.owner_name,
                "notes":       row.notes,
                "priority":    row.priority,
            }
            for row in rows
        ]
        return {"status": "success", "mappings": mappings, "total": len(mappings)}
    except Exception as e:
        logger.error("list_owner_mappings error: %s", e)
        return {"status": "error", "message": str(e)}


def insert_owner_mapping(entry: dict[str, Any]) -> dict[str, Any]:
    """
    担当者マッピングを新規追加する

    Args:
        entry: {pattern, system_name, owner_email, owner_name, notes, priority}

    Returns:
        {"status": "success"} or {"status": "error", "message": "..."}
    """
    from google.cloud import bigquery

    table_id = _get_owner_table_id()
    if not table_id:
        return {"status": "error", "message": "BQ_OWNER_MAPPING_TABLE_ID が未設定です"}

    pattern = (entry.get("pattern") or "").strip()
    if not pattern:
        return {"status": "error", "message": "pattern は必須です"}

    system_name = (entry.get("system_name") or "").strip()

    try:
        client = _get_bq_client()

        # 重複チェック（pattern + system_name の複合キー）
        check_sql = (
            "SELECT COUNT(*) AS cnt FROM `{t}` "
            "WHERE pattern = @pattern AND COALESCE(system_name,'') = @system_name"
        ).format(t=table_id)
        check_params = [
            bigquery.ScalarQueryParameter("pattern",     "STRING", pattern),
            bigquery.ScalarQueryParameter("system_name", "STRING", system_name),
        ]
        cnt = list(client.query(
            check_sql,
            job_config=bigquery.QueryJobConfig(query_parameters=check_params)
        ).result())[0].cnt
        if cnt > 0:
            return {
                "status": "error",
                "message": f"pattern='{pattern}' system_name='{system_name}' の組み合わせは既に存在します"
            }

        priority = entry.get("priority")
        try:
            priority = int(priority)
        except (TypeError, ValueError):
            priority = 9999

        insert_sql = """
            INSERT INTO `{t}` (pattern, system_name, owner_email, owner_name, notes, priority)
            VALUES (@pattern, @system_name, @owner_email, @owner_name, @notes, @priority)
        """.format(t=table_id)
        params = [
            bigquery.ScalarQueryParameter("pattern",     "STRING", pattern),
            bigquery.ScalarQueryParameter("system_name", "STRING", system_name),
            bigquery.ScalarQueryParameter("owner_email", "STRING", (entry.get("owner_email") or "").strip()),
            bigquery.ScalarQueryParameter("owner_name",  "STRING", (entry.get("owner_name") or "").strip()),
            bigquery.ScalarQueryParameter("notes",       "STRING", (entry.get("notes") or "").strip()),
            bigquery.ScalarQueryParameter("priority",    "INT64",  priority),
        ]
        client.query(
            insert_sql,
            job_config=bigquery.QueryJobConfig(query_parameters=params)
        ).result()
        logger.info("insert_owner_mapping: pattern=%s system_name=%s", pattern, system_name)
        return {"status": "success"}
    except Exception as e:
        logger.error("insert_owner_mapping error: %s", e)
        return {"status": "error", "message": str(e)}


def update_owner_mapping(
    old_pattern: str,
    old_system_name: str,
    entry: dict[str, Any],
) -> dict[str, Any]:
    """
    担当者マッピングを更新する（old_pattern + old_system_name で対象を特定）

    Args:
        old_pattern:     更新対象の既存 pattern
        old_system_name: 更新対象の既存 system_name
        entry: 新しい値 {pattern, system_name, owner_email, owner_name, notes, priority}

    Returns:
        {"status": "success"} or {"status": "error", "message": "..."}
    """
    from google.cloud import bigquery

    table_id = _get_owner_table_id()
    if not table_id:
        return {"status": "error", "message": "BQ_OWNER_MAPPING_TABLE_ID が未設定です"}

    old_pattern = (old_pattern or "").strip()
    if not old_pattern:
        return {"status": "error", "message": "old_pattern は必須です"}

    new_pattern = (entry.get("pattern") or "").strip()
    if not new_pattern:
        return {"status": "error", "message": "pattern は必須です"}

    priority = entry.get("priority")
    try:
        priority = int(priority)
    except (TypeError, ValueError):
        priority = 9999

    try:
        client = _get_bq_client()
        update_sql = """
            UPDATE `{t}`
            SET
              pattern     = @pattern,
              system_name = @system_name,
              owner_email = @owner_email,
              owner_name  = @owner_name,
              notes       = @notes,
              priority    = @priority
            WHERE pattern = @old_pattern
              AND COALESCE(system_name, '') = @old_system_name
        """.format(t=table_id)
        params = [
            bigquery.ScalarQueryParameter("pattern",         "STRING", new_pattern),
            bigquery.ScalarQueryParameter("system_name",     "STRING", (entry.get("system_name") or "").strip()),
            bigquery.ScalarQueryParameter("owner_email",     "STRING", (entry.get("owner_email") or "").strip()),
            bigquery.ScalarQueryParameter("owner_name",      "STRING", (entry.get("owner_name") or "").strip()),
            bigquery.ScalarQueryParameter("notes",           "STRING", (entry.get("notes") or "").strip()),
            bigquery.ScalarQueryParameter("priority",        "INT64",  priority),
            bigquery.ScalarQueryParameter("old_pattern",     "STRING", old_pattern),
            bigquery.ScalarQueryParameter("old_system_name", "STRING", (old_system_name or "").strip()),
        ]
        client.query(
            update_sql,
            job_config=bigquery.QueryJobConfig(query_parameters=params)
        ).result()
        logger.info(
            "update_owner_mapping: old=(%s,%s) new=(%s,%s)",
            old_pattern, old_system_name, new_pattern, entry.get("system_name")
        )
        return {"status": "success"}
    except Exception as e:
        logger.error("update_owner_mapping error: %s", e)
        return {"status": "error", "message": str(e)}


def delete_owner_mapping(pattern: str, system_name: str) -> dict[str, Any]:
    """
    担当者マッピングを削除する

    Args:
        pattern:     削除対象のパターン
        system_name: 削除対象のシステム名

    Returns:
        {"status": "success"} or {"status": "error", "message": "..."}
    """
    from google.cloud import bigquery

    table_id = _get_owner_table_id()
    if not table_id:
        return {"status": "error", "message": "BQ_OWNER_MAPPING_TABLE_ID が未設定です"}

    pattern = (pattern or "").strip()
    if not pattern:
        return {"status": "error", "message": "pattern は必須です"}

    try:
        client = _get_bq_client()
        delete_sql = (
            "DELETE FROM `{t}` "
            "WHERE pattern = @pattern AND COALESCE(system_name,'') = @system_name"
        ).format(t=table_id)
        params = [
            bigquery.ScalarQueryParameter("pattern",     "STRING", pattern),
            bigquery.ScalarQueryParameter("system_name", "STRING", (system_name or "").strip()),
        ]
        client.query(
            delete_sql,
            job_config=bigquery.QueryJobConfig(query_parameters=params)
        ).result()
        logger.info("delete_owner_mapping: pattern=%s system_name=%s", pattern, system_name)
        return {"status": "success"}
    except Exception as e:
        logger.error("delete_owner_mapping error: %s", e)
        return {"status": "error", "message": str(e)}
