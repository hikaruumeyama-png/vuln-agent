"""
Google Sheets Tools - SBOM検索

Vertex AI Agent Engine版

シート構成:
  - SBOMシート: type | name | version | release | purl
  - 担当者マッピングシート: pattern | system_name | owner_email | owner_name | notes
"""

import os
import re
import time
import fnmatch
import logging
from typing import Any

from google.cloud import bigquery
from google.oauth2 import service_account
from googleapiclient.discovery import build
from packaging import version as pkg_version

try:
    from .secret_config import get_config_value
except ImportError:
    from secret_config import get_config_value

logger = logging.getLogger(__name__)

# キャッシュ
_sbom_cache = None
_owner_mapping_cache = None
_sbom_cache_timestamp = None
_owner_mapping_cache_timestamp = None
_sbom_cache_backend = None
_owner_mapping_cache_backend = None
_sbom_last_error = ""
_owner_mapping_last_error = ""
_BQ_FULL_TABLE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_\-:]+\.[A-Za-z0-9_]+\.[A-Za-z0-9_$]+$")
_BQ_SHORT_TABLE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_]+\.[A-Za-z0-9_$]+$")


def _get_sbom_data_backend() -> str:
    """
    SBOMデータ取得バックエンドを返す。

    環境変数:
      - SBOM_DATA_BACKEND: sheets | bigquery | auto (default: sheets)

    auto の場合は BigQuery テーブル設定があれば bigquery、なければ sheets を利用。
    """
    configured = get_config_value(
        ["SBOM_DATA_BACKEND"],
        secret_name="vuln-agent-sbom-data-backend",
        default="sheets",
    ).strip().lower()
    if configured not in {"sheets", "bigquery", "auto"}:
        logger.warning("Invalid SBOM_DATA_BACKEND=%s, fallback to sheets", configured)
        return "sheets"

    if configured == "auto":
        sbom_table_id = get_config_value(
            ["BQ_SBOM_TABLE_ID"],
            secret_name="vuln-agent-bq-sbom-table-id",
            default="",
        ).strip()
        owner_table_id = get_config_value(
            ["BQ_OWNER_MAPPING_TABLE_ID"],
            secret_name="vuln-agent-bq-owner-table-id",
            default="",
        ).strip()
        if sbom_table_id and owner_table_id:
            return "bigquery"
        return "sheets"

    return configured


def _get_bigquery_client() -> bigquery.Client:
    """BigQueryクライアントを構築"""
    project = get_config_value(
        ["GCP_PROJECT_ID", "BQ_PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT"],
        default="",
    ).strip() or None
    if not project:
        try:
            from google.auth import default
            _, detected_project = default()
            project = (detected_project or "").strip() or None
        except Exception:
            project = None
    return bigquery.Client(project=project)


_sheets_service = None
_sheets_service_timestamp = None
_SERVICE_CACHE_TTL = 1800  # 30分


def _get_sheets_service():
    """Sheets APIサービスを構築"""
    global _sheets_service, _sheets_service_timestamp

    current_time = time.time()

    if _sheets_service and _sheets_service_timestamp:
        if current_time - _sheets_service_timestamp < _SERVICE_CACHE_TTL:
            return _sheets_service
        logger.info("Sheets service cache expired, re-initializing")
        _sheets_service = None

    sa_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    credentials = None

    if sa_path and os.path.exists(sa_path):
        try:
            credentials = service_account.Credentials.from_service_account_file(
                sa_path,
                scopes=["https://www.googleapis.com/auth/spreadsheets.readonly"]
            )
        except Exception as e:
            logger.error(f"Service account file error: {e}")
            credentials = None

    if not credentials:
        try:
            from google.auth import default
            credentials, _ = default(scopes=["https://www.googleapis.com/auth/spreadsheets.readonly"])
        except Exception as e:
            logger.error(f"Default auth error: {e}")
            raise RuntimeError("Sheets認証に失敗しました。GOOGLE_APPLICATION_CREDENTIALS を確認してください。")

    _sheets_service = build("sheets", "v4", credentials=credentials)
    _sheets_service_timestamp = current_time
    return _sheets_service


def _load_sbom(force_refresh: bool = False) -> list[dict]:
    """
    SBOMデータをロード（キャッシュ対応）
    
    シート構成: type | name | version | release | purl
    """
    global _sbom_cache, _sbom_cache_timestamp, _sbom_cache_backend

    current_time = time.time()
    
    # 5分間キャッシュ
    backend = _get_sbom_data_backend()

    if _sbom_cache and _sbom_cache_timestamp and not force_refresh:
        if _sbom_cache_backend == backend and current_time - _sbom_cache_timestamp < 300:
            return _sbom_cache
    

    if backend == "bigquery":
        sbom_entries = _load_sbom_from_bigquery()
    else:
        sbom_entries = _load_sbom_from_sheets()

    _sbom_cache = sbom_entries
    _sbom_cache_timestamp = current_time
    _sbom_cache_backend = backend
    return sbom_entries


def _load_sbom_from_sheets() -> list[dict]:
    """SBOMをGoogle Sheetsからロード"""
    spreadsheet_id = get_config_value(
        ["SBOM_SPREADSHEET_ID"],
        secret_name="vuln-agent-sbom-spreadsheet-id",
        default="",
    )
    sheet_name = get_config_value(
        ["SBOM_SHEET_NAME"],
        secret_name="vuln-agent-sbom-sheet-name",
        default="SBOM",
    )

    if not spreadsheet_id:
        logger.warning("SBOM_SPREADSHEET_ID not set")
        return []

    try:
        service = _get_sheets_service()

        result = service.spreadsheets().values().get(
            spreadsheetId=spreadsheet_id,
            range=f"{sheet_name}!A:E"  # type, name, version, release, purl
        ).execute()

        rows = result.get("values", [])

        if len(rows) < 2:
            return []

        # ヘッダー行をスキップしてパース
        sbom_entries = []
        for row in rows[1:]:
            while len(row) < 5:
                row.append("")

            sbom_entries.append({
                "type": row[0],
                "name": row[1],
                "version": row[2],
                "release": row[3],
                "purl": row[4],
            })

        logger.info("Loaded %s SBOM entries from Sheets", len(sbom_entries))
        return sbom_entries

    except Exception as e:
        logger.error("Error loading SBOM from Sheets: %s", e)
        return []


def _load_sbom_from_bigquery() -> list[dict]:
    """SBOMをBigQueryからロード"""
    global _sbom_last_error

    table_id = _normalize_bigquery_table_id(
        get_config_value(
            ["BQ_SBOM_TABLE_ID"],
            secret_name="vuln-agent-bq-sbom-table-id",
            default="",
        ),
        "BQ_SBOM_TABLE_ID",
    )
    if not table_id:
        _sbom_last_error = "BQ_SBOM_TABLE_ID が未設定、またはフォーマット不正です。"
        logger.warning(_sbom_last_error)
        return []

    try:
        client = _get_bigquery_client()
        query = f"""
            SELECT
              COALESCE(type, '') AS type,
              COALESCE(name, '') AS name,
              COALESCE(version, '') AS version,
              COALESCE(release, '') AS release,
              COALESCE(purl, '') AS purl
            FROM `{table_id}`
        """
        rows = client.query(query).result()
        sbom_entries = [
            {
                "type": row.type,
                "name": row.name,
                "version": row.version,
                "release": row.release,
                "purl": row.purl,
            }
            for row in rows
        ]
        logger.info("Loaded %s SBOM entries from BigQuery", len(sbom_entries))
        _sbom_last_error = ""
        return sbom_entries
    except Exception as e:
        logger.error("Error loading SBOM from BigQuery: %s", e)
        _sbom_last_error = f"BigQueryからSBOM取得に失敗: {e}"
        return []


def _load_owner_mapping(force_refresh: bool = False) -> list[dict]:
    """
    担当者マッピングをロード（キャッシュ対応）
    
    シート構成: pattern | system_name | owner_email | owner_name | notes
    """
    global _owner_mapping_cache, _owner_mapping_cache_timestamp, _owner_mapping_cache_backend

    current_time = time.time()
    
    # 5分間キャッシュ
    backend = _get_sbom_data_backend()

    if _owner_mapping_cache and _owner_mapping_cache_timestamp and not force_refresh:
        if _owner_mapping_cache_backend == backend and current_time - _owner_mapping_cache_timestamp < 300:
            return _owner_mapping_cache
    

    if backend == "bigquery":
        mappings = _load_owner_mapping_from_bigquery()
    else:
        mappings = _load_owner_mapping_from_sheets()

    # より具体的なパターン（長いパターン）を優先するためにソート
    # ワイルドカード「*」のみは最後に
    mappings.sort(key=lambda x: (x["pattern"] == "*", -len(x["pattern"])))

    _owner_mapping_cache = mappings
    _owner_mapping_cache_timestamp = current_time
    _owner_mapping_cache_backend = backend
    return mappings


def _load_owner_mapping_from_sheets() -> list[dict]:
    """担当者マッピングをGoogle Sheetsからロード"""
    spreadsheet_id = get_config_value(
        ["SBOM_SPREADSHEET_ID"],
        secret_name="vuln-agent-sbom-spreadsheet-id",
        default="",
    )
    owner_sheet_name = get_config_value(
        ["OWNER_SHEET_NAME"],
        secret_name="vuln-agent-owner-sheet-name",
        default="担当者マッピング",
    )

    if not spreadsheet_id:
        logger.warning("SBOM_SPREADSHEET_ID not set")
        return []

    try:
        service = _get_sheets_service()

        result = service.spreadsheets().values().get(
            spreadsheetId=spreadsheet_id,
            range=f"{owner_sheet_name}!A:E"  # pattern, system_name, owner_email, owner_name, notes
        ).execute()

        rows = result.get("values", [])

        if len(rows) < 2:
            return []

        mappings = []
        for row in rows[1:]:
            while len(row) < 5:
                row.append("")

            normalized_pattern = row[0].strip() or "*"
            mappings.append({
                "pattern": normalized_pattern,
                "system_name": row[1],
                "owner_email": row[2],
                "owner_name": row[3],
                "notes": row[4],
            })
        logger.info("Loaded %s owner mappings from Sheets", len(mappings))
        return mappings
    except Exception as e:
        logger.error("Error loading owner mapping from Sheets: %s", e)
        return []


def _load_owner_mapping_from_bigquery() -> list[dict]:
    """担当者マッピングをBigQueryからロード"""
    global _owner_mapping_last_error

    table_id = _normalize_bigquery_table_id(
        get_config_value(
            ["BQ_OWNER_MAPPING_TABLE_ID"],
            secret_name="vuln-agent-bq-owner-table-id",
            default="",
        ),
        "BQ_OWNER_MAPPING_TABLE_ID",
    )
    if not table_id:
        _owner_mapping_last_error = "BQ_OWNER_MAPPING_TABLE_ID が未設定、またはフォーマット不正です。"
        logger.warning(_owner_mapping_last_error)
        return []

    try:
        client = _get_bigquery_client()
        query = f"""
            SELECT
              COALESCE(NULLIF(TRIM(pattern), ''), '*') AS pattern,
              COALESCE(system_name, '') AS system_name,
              COALESCE(owner_email, '') AS owner_email,
              COALESCE(owner_name, '') AS owner_name,
              COALESCE(notes, '') AS notes
            FROM `{table_id}`
        """
        rows = client.query(query).result()
        mappings = [
            {
                "pattern": row.pattern,
                "system_name": row.system_name,
                "owner_email": row.owner_email,
                "owner_name": row.owner_name,
                "notes": row.notes,
            }
            for row in rows
        ]
        logger.info("Loaded %s owner mappings from BigQuery", len(mappings))
        _owner_mapping_last_error = ""
        return mappings
    except Exception as e:
        logger.error("Error loading owner mapping from BigQuery: %s", e)
        _owner_mapping_last_error = f"BigQueryから担当者マッピング取得に失敗: {e}"
        return []


def _find_owner_for_purl(purl: str) -> dict[str, str]:
    """
    PURLに対応する担当者を検索
    
    パターンマッチングの優先度:
    1. より具体的なパターン（長いパターン）を優先
    2. ワイルドカード「*」はデフォルトとして最後に適用
    
    Args:
        purl: Package URL (例: pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1)
    
    Returns:
        {"system_name": "...", "owner_email": "...", "owner_name": "..."}
    """
    mappings = _load_owner_mapping()
    
    for mapping in mappings:
        pattern = mapping["pattern"]
        
        # ワイルドカードパターンマッチング
        # pkg:maven/org.apache.* のようなパターンに対応
        if pattern == "*":
            # デフォルトマッチ
            return {
                "system_name": mapping["system_name"],
                "owner_email": mapping["owner_email"],
                "owner_name": mapping["owner_name"],
            }
        
        # fnmatchでワイルドカードパターンマッチング
        if fnmatch.fnmatch(purl.lower(), pattern.lower()):
            return {
                "system_name": mapping["system_name"],
                "owner_email": mapping["owner_email"],
                "owner_name": mapping["owner_name"],
            }
        
        # 部分一致もサポート（ワイルドカードなしの場合）
        if "*" not in pattern and "?" not in pattern:
            if pattern.lower() in purl.lower():
                return {
                    "system_name": mapping["system_name"],
                    "owner_email": mapping["owner_email"],
                    "owner_name": mapping["owner_name"],
                }
    
    # マッチなし
    return {
        "system_name": "不明",
        "owner_email": "",
        "owner_name": "",
    }


def search_sbom_by_purl(purl_pattern: str) -> dict[str, Any]:
    """
    PURL（Package URL）パターンでSBOMを検索します。
    
    Args:
        purl_pattern: 検索するPURLパターン（部分一致）
                     例: "pkg:maven/org.apache.logging.log4j"
                         "log4j"
    
    Returns:
        マッチしたエントリと影響システム・担当者のリスト
    """
    pattern = (purl_pattern or "").strip()
    if not pattern:
        return {
            "status": "error",
            "matched_entries": [],
            "affected_systems": [],
            "owners": [],
            "total_count": 0,
            "message": "purl_pattern は必須です",
        }

    sbom = _load_sbom()
    
    if not sbom:
        return {
            "matched_entries": [],
            "affected_systems": [],
            "owners": [],
            "total_count": 0,
            "message": _build_sbom_missing_message()
        }
    
    matched = []
    for entry in sbom:
        if entry["purl"] and pattern.lower() in entry["purl"].lower():
            # 担当者情報を付加
            owner_info = _find_owner_for_purl(entry["purl"])
            enriched_entry = {**entry, **owner_info}
            matched.append(enriched_entry)
    
    # 結果を集計
    affected_systems = list(set(e["system_name"] for e in matched if e.get("system_name")))
    owners = list(set(e["owner_email"] for e in matched if e.get("owner_email")))
    
    return {
        "matched_entries": matched,
        "affected_systems": affected_systems,
        "owners": owners,
        "total_count": len(matched),
        "search_criteria": {"purl_pattern": pattern}
    }


def search_sbom_by_product(
    product_type: str | None = None,
    product_name: str | None = None,
    version_range: str | None = None
) -> dict[str, Any]:
    """
    製品情報でSBOMを検索します。
    
    Args:
        product_type: 製品タイプ（npm, maven, pypi等）
        product_name: 製品名（部分一致）
        version_range: 影響バージョン範囲（例: "<2.17.0"）
    
    Returns:
        マッチしたエントリと影響システム・担当者のリスト
    """
    sbom = _load_sbom()
    
    if not sbom:
        return {
            "matched_entries": [],
            "affected_systems": [],
            "owners": [],
            "total_count": 0,
            "message": _build_sbom_missing_message()
        }
    
    matched = []
    for entry in sbom:
        if _matches_criteria(entry, product_type, product_name, version_range):
            # 担当者情報を付加
            owner_info = _find_owner_for_purl(entry.get("purl", ""))
            enriched_entry = {**entry, **owner_info}
            matched.append(enriched_entry)
    
    # 結果を集計
    affected_systems = list(set(e["system_name"] for e in matched if e.get("system_name")))
    owners = list(set(e["owner_email"] for e in matched if e.get("owner_email")))
    
    return {
        "matched_entries": matched,
        "affected_systems": affected_systems,
        "owners": owners,
        "total_count": len(matched),
        "search_criteria": {
            "product_type": product_type,
            "product_name": product_name,
            "version_range": version_range
        }
    }


def get_affected_systems(
    cve_id: str,
    purls: list[str] = None,
    products: list[str] = None
) -> dict[str, Any]:
    """
    CVEの影響を受けるシステムと担当者を総合的に検索します。
    
    Args:
        cve_id: CVE番号（記録用）
        purls: 検索するPURLのリスト
        products: 検索する製品名のリスト
    
    Returns:
        影響を受けるシステムと担当者の情報
    """
    all_matched = []
    
    if purls:
        for purl in purls:
            result = search_sbom_by_purl(purl)
            all_matched.extend(result.get("matched_entries", []))
    
    if products:
        for product in products:
            result = search_sbom_by_product(product_name=product)
            all_matched.extend(result.get("matched_entries", []))
    
    # 重複除去
    # purl/version だけだと purl 未設定エントリが衝突しやすいため、
    # type/name/release もキーに含めて誤って統合されるのを防ぐ
    unique = {
        f"{e.get('purl', '')}:{e.get('version', '')}:{e.get('type', '')}:{e.get('name', '')}:{e.get('release', '')}": e
        for e in all_matched
    }
    matched = list(unique.values())
    
    # 結果を集計
    affected_systems = list(set(e["system_name"] for e in matched if e.get("system_name")))
    owners = list(set(e["owner_email"] for e in matched if e.get("owner_email")))
    
    # 担当者の詳細情報も含める
    owner_details = {}
    for entry in matched:
        email = entry.get("owner_email")
        if email and email not in owner_details:
            owner_details[email] = {
                "email": email,
                "name": entry.get("owner_name", ""),
                "systems": []
            }
        if email:
            system = entry.get("system_name")
            if system and system not in owner_details[email]["systems"]:
                owner_details[email]["systems"].append(system)
    
    return {
        "cve_id": cve_id,
        "affected_systems": affected_systems,
        "owners": owners,
        "owner_details": list(owner_details.values()),
        "total_count": len(matched),
        "details": matched
    }


def get_owner_mapping() -> dict[str, Any]:
    """
    現在の担当者マッピング設定を取得します。
    デバッグや確認用のツール。
    
    Returns:
        担当者マッピングの一覧
    """
    mappings = _load_owner_mapping()
    
    result = {
        "mappings": mappings,
        "total_count": len(mappings),
        "backend": _get_sbom_data_backend(),
    }
    if not mappings and _get_sbom_data_backend() == "bigquery" and _owner_mapping_last_error:
        result["message"] = _owner_mapping_last_error
    return result


def get_sbom_contents(max_results: int = 50) -> dict[str, Any]:
    """
    SBOMデータの内容を一覧で返す（先頭N件）。

    「SBOMの内容を教えて」という問い合わせ向けの読み取り専用ツール。
    未依頼の追加処理を避けるため、検索・集計・通知は行わない。
    """
    limit = _normalize_result_limit(max_results, default=50, max_value=200)
    backend = _get_sbom_data_backend()
    sbom = _load_sbom()

    if not sbom:
        return {
            "status": "error",
            "backend": backend,
            "entries": [],
            "returned_count": 0,
            "total_count": 0,
            "message": _build_sbom_missing_message(),
        }

    entries = sbom[:limit]
    type_counts: dict[str, int] = {}
    for entry in sbom:
        pkg_type = (entry.get("type") or "").strip() or "(unknown)"
        type_counts[pkg_type] = type_counts.get(pkg_type, 0) + 1

    return {
        "status": "success",
        "backend": backend,
        "columns": ["type", "name", "version", "release", "purl"],
        "entries": entries,
        "returned_count": len(entries),
        "total_count": len(sbom),
        "type_counts": dict(sorted(type_counts.items(), key=lambda x: x[0])),
        "message": (
            "SBOM内容の一覧です。追加の集計・検索・脆弱性スキャンは未実行です。"
        ),
    }


def list_sbom_package_types() -> dict[str, Any]:
    """
    SBOMに含まれるパッケージ type 一覧を返す。
    """
    backend = _get_sbom_data_backend()
    sbom = _load_sbom()
    if not sbom:
        return {
            "status": "error",
            "backend": backend,
            "types": [],
            "total_count": 0,
            "message": _build_sbom_missing_message(),
        }

    types = sorted({(entry.get("type") or "").strip() or "(unknown)" for entry in sbom})
    return {
        "status": "success",
        "backend": backend,
        "types": types,
        "total_count": len(types),
    }


def count_sbom_packages_by_type() -> dict[str, Any]:
    """
    SBOMを type ごとに件数集計して返す。
    """
    backend = _get_sbom_data_backend()
    sbom = _load_sbom()
    if not sbom:
        return {
            "status": "error",
            "backend": backend,
            "counts": {},
            "total_count": 0,
            "message": _build_sbom_missing_message(),
        }

    counts: dict[str, int] = {}
    for entry in sbom:
        pkg_type = (entry.get("type") or "").strip() or "(unknown)"
        counts[pkg_type] = counts.get(pkg_type, 0) + 1

    return {
        "status": "success",
        "backend": backend,
        "counts": dict(sorted(counts.items(), key=lambda x: x[0])),
        "total_count": len(sbom),
    }


def list_sbom_packages_by_type(package_type: str, max_results: int = 50) -> dict[str, Any]:
    """
    指定 type のSBOMエントリ一覧を返す。
    """
    pkg_type = (package_type or "").strip()
    if not pkg_type:
        return {"status": "error", "message": "package_type は必須です。"}

    limit = _normalize_result_limit(max_results, default=50, max_value=300)
    backend = _get_sbom_data_backend()
    sbom = _load_sbom()
    if not sbom:
        return {
            "status": "error",
            "backend": backend,
            "package_type": pkg_type,
            "entries": [],
            "returned_count": 0,
            "total_count": 0,
            "message": _build_sbom_missing_message(),
        }

    matched = [e for e in sbom if (e.get("type") or "").strip().lower() == pkg_type.lower()]
    return {
        "status": "success",
        "backend": backend,
        "package_type": pkg_type,
        "entries": matched[:limit],
        "returned_count": min(limit, len(matched)),
        "total_count": len(matched),
    }


def list_sbom_package_versions(
    package_name: str,
    package_type: str | None = None,
    max_results: int = 50,
) -> dict[str, Any]:
    """
    指定パッケージ名のバージョン一覧を返す（必要なら type で絞り込み）。
    """
    name_query = (package_name or "").strip()
    type_query = (package_type or "").strip()
    if not name_query:
        return {"status": "error", "message": "package_name は必須です。"}

    limit = _normalize_result_limit(max_results, default=50, max_value=300)
    backend = _get_sbom_data_backend()
    sbom = _load_sbom()
    if not sbom:
        return {
            "status": "error",
            "backend": backend,
            "package_name": name_query,
            "package_type": type_query,
            "entries": [],
            "returned_count": 0,
            "total_count": 0,
            "message": _build_sbom_missing_message(),
        }

    matched = []
    for entry in sbom:
        entry_name = (entry.get("name") or "").strip()
        if name_query.lower() not in entry_name.lower():
            continue
        if type_query and (entry.get("type") or "").strip().lower() != type_query.lower():
            continue
        matched.append(entry)

    versions = sorted({(e.get("version") or "").strip() or "(unknown)" for e in matched})
    return {
        "status": "success",
        "backend": backend,
        "package_name": name_query,
        "package_type": type_query,
        "versions": versions,
        "entries": matched[:limit],
        "returned_count": min(limit, len(matched)),
        "total_count": len(matched),
    }


def get_sbom_entry_by_purl(purl: str) -> dict[str, Any]:
    """
    指定PURLのSBOMエントリを1件返す（完全一致）。
    """
    normalized = (purl or "").strip()
    if not normalized:
        return {"status": "error", "message": "purl は必須です。"}

    backend = _get_sbom_data_backend()
    sbom = _load_sbom()
    if not sbom:
        return {
            "status": "error",
            "backend": backend,
            "purl": normalized,
            "found": False,
            "entry": None,
            "message": _build_sbom_missing_message(),
        }

    for entry in sbom:
        if (entry.get("purl") or "").strip() == normalized:
            owner_info = _find_owner_for_purl(normalized)
            return {
                "status": "success",
                "backend": backend,
                "purl": normalized,
                "found": True,
                "entry": {**entry, **owner_info},
            }

    return {
        "status": "success",
        "backend": backend,
        "purl": normalized,
        "found": False,
        "entry": None,
        "message": "指定したPURLのエントリは見つかりませんでした。",
    }


def _matches_criteria(entry: dict, product_type: str, product_name: str, version_range: str) -> bool:
    """エントリが検索条件にマッチするかチェック"""
    entry_type = (entry.get("type") or "").strip()
    if product_type and entry_type.lower() != product_type.lower():
        return False
    
    if product_name:
        # name フィールドまたは purl で検索
        name = entry.get("name", "").lower()
        purl = entry.get("purl", "").lower()
        product_lower = product_name.lower()
        
        if product_lower not in name and product_lower not in purl:
            return False
    
    if version_range:
        entry_version = (entry.get("version") or "").strip()
        # バージョン条件がある場合、バージョン不明のエントリは一致させない
        if not entry_version:
            return False
        if not _version_matches_range(entry_version, version_range):
            return False
    
    return True


def _normalize_result_limit(value: Any, default: int, max_value: int) -> int:
    try:
        num = int(value)
    except (TypeError, ValueError):
        return default
    if num < 1:
        return 1
    if num > max_value:
        return max_value
    return num


def _normalize_bigquery_table_id(raw_table_id: str, env_name: str) -> str:
    """BigQueryテーブルIDを検証して返す。許容: project.dataset.table / dataset.table"""
    table_id = (raw_table_id or "").strip().strip("`")
    if not table_id:
        return ""
    if _BQ_FULL_TABLE_ID_PATTERN.match(table_id):
        return table_id
    if _BQ_SHORT_TABLE_ID_PATTERN.match(table_id):
        return table_id
    logger.error("%s format is invalid: %s", env_name, table_id)
    return ""


def _build_sbom_missing_message() -> str:
    backend = _get_sbom_data_backend()
    if backend == "bigquery" and _sbom_last_error:
        return _sbom_last_error
    return "SBOMデータが見つかりません"


def _version_matches_range(version_str: str, range_spec: str) -> bool:
    """バージョンが指定範囲に含まれるかチェック"""
    try:
        # 数値を含まないバージョン文字列は比較不能として非一致
        if not re.search(r"\d", version_str or ""):
            return False

        # 正規化
        ver = re.sub(r"^v", "", version_str)
        ver = re.sub(r"[-_](alpha|beta|rc|snapshot).*$", "", ver, flags=re.IGNORECASE)
        ver = re.sub(r"^[^\d]+", "", ver) or "0"
        v = pkg_version.parse(ver)
        
        # 条件チェック
        for condition in range_spec.split(","):
            condition = condition.strip()
            if not condition:
                continue

            if condition.endswith((".x", ".*")):
                prefix = condition[:-2]
                ver_str = str(v)
                if ver_str != prefix and not ver_str.startswith(prefix + "."):
                    return False
                continue
            matched = False

            for op, func in [(">=", lambda a, b: a >= b), ("<=", lambda a, b: a <= b),
                            (">", lambda a, b: a > b), ("<", lambda a, b: a < b)]:
                if condition.startswith(op):
                    target = pkg_version.parse(re.sub(r"^[^\d]+", "", condition[len(op):]) or "0")
                    if not func(v, target):
                        return False
                    matched = True
                    break
            if not matched:
                target = pkg_version.parse(re.sub(r"^[^\d]+", "", condition) or "0")
                if v != target:
                    return False
        
        return True
    except Exception:
        # パース失敗時は誤検知を避けるため非一致として扱う
        return False
