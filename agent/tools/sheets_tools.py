"""
Google Sheets Tools - SBOM検索

Vertex AI Agent Engine版

シート構成:
  - SBOMシート: type | name | version | release | purl
  - 担当者マッピングシート: pattern | system_name | owner_email | owner_name | notes
"""

import os
import re
import fnmatch
import logging
from typing import Any

from google.cloud import bigquery
from google.oauth2 import service_account
from googleapiclient.discovery import build
from packaging import version as pkg_version

logger = logging.getLogger(__name__)

# キャッシュ
_sbom_cache = None
_owner_mapping_cache = None
_sbom_cache_timestamp = None
_owner_mapping_cache_timestamp = None
_sbom_cache_backend = None
_owner_mapping_cache_backend = None


def _get_sbom_data_backend() -> str:
    """
    SBOMデータ取得バックエンドを返す。

    環境変数:
      - SBOM_DATA_BACKEND: sheets | bigquery | auto (default: sheets)

    auto の場合は BigQuery テーブル設定があれば bigquery、なければ sheets を利用。
    """
    configured = os.environ.get("SBOM_DATA_BACKEND", "sheets").strip().lower()
    if configured not in {"sheets", "bigquery", "auto"}:
        logger.warning("Invalid SBOM_DATA_BACKEND=%s, fallback to sheets", configured)
        return "sheets"

    if configured == "auto":
        sbom_table_id = os.environ.get("BQ_SBOM_TABLE_ID", "").strip()
        owner_table_id = os.environ.get("BQ_OWNER_MAPPING_TABLE_ID", "").strip()
        if sbom_table_id and owner_table_id:
            return "bigquery"
        return "sheets"

    return configured


def _get_bigquery_client() -> bigquery.Client:
    """BigQueryクライアントを構築"""
    project = os.environ.get("GCP_PROJECT_ID") or None
    return bigquery.Client(project=project)


_sheets_service = None
_sheets_service_timestamp = None
_SERVICE_CACHE_TTL = 1800  # 30分


def _get_sheets_service():
    """Sheets APIサービスを構築"""
    global _sheets_service, _sheets_service_timestamp

    import time
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
    
    import time
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
    spreadsheet_id = os.environ.get("SBOM_SPREADSHEET_ID", "")
    sheet_name = os.environ.get("SBOM_SHEET_NAME", "SBOM")

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
    table_id = os.environ.get("BQ_SBOM_TABLE_ID", "").strip()
    if not table_id:
        logger.warning("BQ_SBOM_TABLE_ID not set")
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
        return sbom_entries
    except Exception as e:
        logger.error("Error loading SBOM from BigQuery: %s", e)
        return []


def _load_owner_mapping(force_refresh: bool = False) -> list[dict]:
    """
    担当者マッピングをロード（キャッシュ対応）
    
    シート構成: pattern | system_name | owner_email | owner_name | notes
    """
    global _owner_mapping_cache, _owner_mapping_cache_timestamp, _owner_mapping_cache_backend
    
    import time
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
    spreadsheet_id = os.environ.get("SBOM_SPREADSHEET_ID", "")
    owner_sheet_name = os.environ.get("OWNER_SHEET_NAME", "担当者マッピング")

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
    table_id = os.environ.get("BQ_OWNER_MAPPING_TABLE_ID", "").strip()
    if not table_id:
        logger.warning("BQ_OWNER_MAPPING_TABLE_ID not set")
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
        return mappings
    except Exception as e:
        logger.error("Error loading owner mapping from BigQuery: %s", e)
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
    sbom = _load_sbom()
    
    if not sbom:
        return {
            "matched_entries": [],
            "affected_systems": [],
            "owners": [],
            "total_count": 0,
            "message": "SBOMデータが見つかりません"
        }
    
    matched = []
    for entry in sbom:
        if entry["purl"] and purl_pattern.lower() in entry["purl"].lower():
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
        "search_criteria": {"purl_pattern": purl_pattern}
    }


def search_sbom_by_product(
    product_type: str = None,
    product_name: str = None,
    version_range: str = None
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
            "message": "SBOMデータが見つかりません"
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
    
    return {
        "mappings": mappings,
        "total_count": len(mappings)
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
