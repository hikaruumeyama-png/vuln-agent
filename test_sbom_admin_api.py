"""
sbom_admin_api.py のユニットテスト

BigQuery クライアントはスタブで差し替え、外部接続なしで実行する。
各 test class が setUpClass でスタブを sys.modules にインストールし、
テスト実行中も維持することで、関数内 `from google.cloud import bigquery`
の遅延インポートもスタブに当たるようにする。
"""

import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent / "live_gateway" / "sbom_admin_api.py"


# ── ヘルパー: Row / QueryJob スタブ ─────────────────────────


class _Row:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class _QueryJob:
    def __init__(self, rows):
        self._rows = rows

    def result(self):
        return iter(self._rows)


# ── 設定可能なBQクライアント ──────────────────────────────


class _ConfigurableBQClient:
    """テスト間でクラス変数を差し替えることで挙動を制御できるスタブ"""

    # テスト側から書き換える
    count_result: int = 0
    select_rows: list = []
    raise_on_query: bool = False
    raise_on_insert: bool = False
    recorded_sql: list = []

    def __init__(self, project=None):
        self.project = project

    def query(self, sql: str, job_config=None):
        type(self).recorded_sql.append(sql.strip())
        if type(self).raise_on_query:
            raise RuntimeError("bigquery stub error")
        if type(self).raise_on_insert and "INSERT" in sql:
            raise RuntimeError("insert stub error")
        if "COUNT(*)" in sql:
            return _QueryJob([_Row(cnt=type(self).count_result)])
        return _QueryJob(type(self).select_rows)

    @classmethod
    def reset(cls):
        cls.count_result = 0
        cls.select_rows = []
        cls.raise_on_query = False
        cls.raise_on_insert = False
        cls.recorded_sql = []


# ── スタブインストール ─────────────────────────────────────


def _install_google_stubs():
    """google.cloud.bigquery / secretmanager を永続的にスタブで差し替える"""

    bq_module = types.ModuleType("google.cloud.bigquery")

    class ScalarQueryParameter:
        def __init__(self, name, type_, value):
            self.name = name
            self.type_ = type_
            self.value = value

    class QueryJobConfig:
        def __init__(self, query_parameters=None):
            self.query_parameters = query_parameters or []

    bq_module.ScalarQueryParameter = ScalarQueryParameter
    bq_module.QueryJobConfig = QueryJobConfig
    bq_module.Client = _ConfigurableBQClient

    sm_module = types.ModuleType("google.cloud.secretmanager")
    sm_module.SecretManagerServiceClient = lambda: None

    cloud_module = types.ModuleType("google.cloud")
    cloud_module.bigquery = bq_module
    cloud_module.secretmanager = sm_module

    google_module = types.ModuleType("google")
    google_module.cloud = cloud_module

    auth_module = types.ModuleType("google.auth")
    auth_module.default = lambda: (object(), "test-project")
    google_module.auth = auth_module

    sys.modules["google"] = google_module
    sys.modules["google.cloud"] = cloud_module
    sys.modules["google.cloud.bigquery"] = bq_module
    sys.modules["google.cloud.secretmanager"] = sm_module
    sys.modules["google.auth"] = auth_module


def _load_admin_api():
    spec = importlib.util.spec_from_file_location("sbom_admin_api_test", MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── NormalizeTableId ──────────────────────────────────────


class NormalizeTableIdTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _install_google_stubs()
        cls.mod = _load_admin_api()

    def test_full_table_id_accepted(self):
        self.assertEqual(
            self.mod._normalize_table_id("myproject.mydataset.mytable"),
            "myproject.mydataset.mytable",
        )

    def test_short_table_id_accepted(self):
        self.assertEqual(
            self.mod._normalize_table_id("mydataset.mytable"),
            "mydataset.mytable",
        )

    def test_backtick_stripped(self):
        self.assertEqual(
            self.mod._normalize_table_id("`myproject.mydataset.mytable`"),
            "myproject.mydataset.mytable",
        )

    def test_invalid_format_returns_empty(self):
        self.assertEqual(self.mod._normalize_table_id("bad table id"), "")
        self.assertEqual(self.mod._normalize_table_id(""), "")
        self.assertEqual(self.mod._normalize_table_id("   "), "")
        self.assertEqual(self.mod._normalize_table_id("only-one-part"), "")

    def test_project_with_hyphen_accepted(self):
        """project-id.dataset.table 形式は受け入れられる"""
        self.assertEqual(
            self.mod._normalize_table_id("my-project.mydataset.mytable"),
            "my-project.mydataset.mytable",
        )


# ── list_sbom ─────────────────────────────────────────────


class SbomListTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _install_google_stubs()
        cls.mod = _load_admin_api()

    def setUp(self):
        self._orig_env = dict(os.environ)
        _ConfigurableBQClient.reset()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._orig_env)

    def test_missing_table_id_returns_error(self):
        os.environ.pop("BQ_SBOM_TABLE_ID", None)
        result = self.mod.list_sbom()
        self.assertEqual(result["status"], "error")
        self.assertIn("BQ_SBOM_TABLE_ID", result["message"])

    def test_bq_exception_returns_error(self):
        os.environ["BQ_SBOM_TABLE_ID"] = "proj.ds.tbl"
        _ConfigurableBQClient.raise_on_query = True
        result = self.mod.list_sbom()
        self.assertEqual(result["status"], "error")
        self.assertIn("bigquery stub error", result["message"])

    def test_returns_success_with_empty_rows(self):
        os.environ["BQ_SBOM_TABLE_ID"] = "proj.ds.tbl"
        _ConfigurableBQClient.count_result = 0
        _ConfigurableBQClient.select_rows = []
        result = self.mod.list_sbom()
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["entries"], [])
        self.assertEqual(result["total"], 0)

    def test_returns_success_with_rows(self):
        os.environ["BQ_SBOM_TABLE_ID"] = "proj.ds.tbl"
        _ConfigurableBQClient.count_result = 1
        _ConfigurableBQClient.select_rows = [
            _Row(type="maven", name="log4j-core", version="2.14.1",
                 release="", purl="pkg:maven/log4j-core@2.14.1",
                 os_name="", os_version="", arch="")
        ]
        result = self.mod.list_sbom()
        self.assertEqual(result["status"], "success")
        self.assertEqual(len(result["entries"]), 1)
        self.assertEqual(result["entries"][0]["purl"], "pkg:maven/log4j-core@2.14.1")

    def test_per_page_capped_at_200(self):
        os.environ["BQ_SBOM_TABLE_ID"] = "proj.ds.tbl"
        _ConfigurableBQClient.count_result = 0
        _ConfigurableBQClient.select_rows = []
        result = self.mod.list_sbom(per_page=9999)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["per_page"], 200)

    def test_page_below_1_normalized(self):
        os.environ["BQ_SBOM_TABLE_ID"] = "proj.ds.tbl"
        result = self.mod.list_sbom(page=0)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["page"], 1)

    def test_search_query_appended_to_sql(self):
        os.environ["BQ_SBOM_TABLE_ID"] = "proj.ds.tbl"
        _ConfigurableBQClient.select_rows = []
        self.mod.list_sbom(q="log4j")
        sqls = " ".join(_ConfigurableBQClient.recorded_sql)
        self.assertIn("LIKE @q", sqls)


# ── insert_sbom_entry ────────────────────────────────────


class SbomInsertTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _install_google_stubs()
        cls.mod = _load_admin_api()

    def setUp(self):
        self._orig_env = dict(os.environ)
        _ConfigurableBQClient.reset()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._orig_env)

    def test_missing_table_returns_error(self):
        os.environ.pop("BQ_SBOM_TABLE_ID", None)
        result = self.mod.insert_sbom_entry({"purl": "pkg:maven/a@1.0"})
        self.assertEqual(result["status"], "error")

    def test_empty_purl_returns_error(self):
        os.environ["BQ_SBOM_TABLE_ID"] = "proj.ds.tbl"
        result = self.mod.insert_sbom_entry({"purl": ""})
        self.assertEqual(result["status"], "error")
        self.assertIn("purl", result["message"])

    def test_whitespace_purl_returns_error(self):
        os.environ["BQ_SBOM_TABLE_ID"] = "proj.ds.tbl"
        result = self.mod.insert_sbom_entry({"purl": "   "})
        self.assertEqual(result["status"], "error")

    def test_duplicate_purl_returns_error(self):
        os.environ["BQ_SBOM_TABLE_ID"] = "proj.ds.tbl"
        _ConfigurableBQClient.count_result = 1  # 既存
        result = self.mod.insert_sbom_entry({"purl": "pkg:maven/log4j@2.14.1"})
        self.assertEqual(result["status"], "error")
        self.assertIn("既に存在します", result["message"])

    def test_new_purl_succeeds(self):
        os.environ["BQ_SBOM_TABLE_ID"] = "proj.ds.tbl"
        _ConfigurableBQClient.count_result = 0
        result = self.mod.insert_sbom_entry({
            "purl": "pkg:maven/log4j@2.14.1",
            "name": "log4j", "version": "2.14.1", "type": "maven",
        })
        self.assertEqual(result["status"], "success")

    def test_bq_error_on_insert_returns_error(self):
        os.environ["BQ_SBOM_TABLE_ID"] = "proj.ds.tbl"
        _ConfigurableBQClient.count_result = 0
        _ConfigurableBQClient.raise_on_insert = True
        result = self.mod.insert_sbom_entry({"purl": "pkg:npm/express@4.0.0"})
        self.assertEqual(result["status"], "error")


# ── update_sbom_entry / delete_sbom_entry ───────────────


class SbomUpdateDeleteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _install_google_stubs()
        cls.mod = _load_admin_api()

    def setUp(self):
        self._orig_env = dict(os.environ)
        _ConfigurableBQClient.reset()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._orig_env)

    def test_update_missing_table_returns_error(self):
        os.environ.pop("BQ_SBOM_TABLE_ID", None)
        result = self.mod.update_sbom_entry("old", {"purl": "new"})
        self.assertEqual(result["status"], "error")

    def test_update_empty_old_purl_returns_error(self):
        os.environ["BQ_SBOM_TABLE_ID"] = "proj.ds.tbl"
        result = self.mod.update_sbom_entry("", {"purl": "pkg:maven/a@1.0"})
        self.assertEqual(result["status"], "error")
        self.assertIn("必須", result["message"])

    def test_update_empty_new_purl_returns_error(self):
        os.environ["BQ_SBOM_TABLE_ID"] = "proj.ds.tbl"
        result = self.mod.update_sbom_entry("pkg:maven/a@1.0", {"purl": ""})
        self.assertEqual(result["status"], "error")

    def test_update_succeeds(self):
        os.environ["BQ_SBOM_TABLE_ID"] = "proj.ds.tbl"
        result = self.mod.update_sbom_entry(
            "pkg:maven/a@1.0",
            {"purl": "pkg:maven/a@2.0", "name": "a", "version": "2.0",
             "type": "maven", "release": "", "os_name": "", "os_version": "", "arch": ""},
        )
        self.assertEqual(result["status"], "success")
        sqls = " ".join(_ConfigurableBQClient.recorded_sql)
        self.assertIn("UPDATE", sqls)

    def test_delete_missing_table_returns_error(self):
        os.environ.pop("BQ_SBOM_TABLE_ID", None)
        result = self.mod.delete_sbom_entry("pkg:maven/a@1.0")
        self.assertEqual(result["status"], "error")

    def test_delete_empty_purl_no_fallback_fields_returns_error(self):
        """PURLも name/type も全て空の場合はエラー"""
        os.environ["BQ_SBOM_TABLE_ID"] = "proj.ds.tbl"
        result = self.mod.delete_sbom_entry(purl="")
        self.assertEqual(result["status"], "error")

    def test_delete_by_name_type_when_purl_empty(self):
        """PURLが空でも name+type があれば削除できる"""
        os.environ["BQ_SBOM_TABLE_ID"] = "proj.ds.tbl"
        result = self.mod.delete_sbom_entry(purl="", name="Firefox", type="application")
        self.assertEqual(result["status"], "success")
        sqls = " ".join(_ConfigurableBQClient.recorded_sql)
        self.assertIn("DELETE", sqls)
        self.assertIn("COALESCE(purl,'') = ''", sqls)  # PURLなしのみを対象

    def test_delete_succeeds(self):
        os.environ["BQ_SBOM_TABLE_ID"] = "proj.ds.tbl"
        result = self.mod.delete_sbom_entry("pkg:maven/a@1.0")
        self.assertEqual(result["status"], "success")
        sqls = " ".join(_ConfigurableBQClient.recorded_sql)
        self.assertIn("DELETE", sqls)


# ── list_owner_mappings ──────────────────────────────────


class OwnerMappingListTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _install_google_stubs()
        cls.mod = _load_admin_api()

    def setUp(self):
        self._orig_env = dict(os.environ)
        _ConfigurableBQClient.reset()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._orig_env)

    def test_missing_table_returns_error(self):
        os.environ.pop("BQ_OWNER_MAPPING_TABLE_ID", None)
        result = self.mod.list_owner_mappings()
        self.assertEqual(result["status"], "error")
        self.assertIn("BQ_OWNER_MAPPING_TABLE_ID", result["message"])

    def test_bq_error_returns_error(self):
        os.environ["BQ_OWNER_MAPPING_TABLE_ID"] = "proj.ds.owners"
        _ConfigurableBQClient.raise_on_query = True
        result = self.mod.list_owner_mappings()
        self.assertEqual(result["status"], "error")

    def test_returns_success_with_empty_rows(self):
        os.environ["BQ_OWNER_MAPPING_TABLE_ID"] = "proj.ds.owners"
        _ConfigurableBQClient.select_rows = []
        result = self.mod.list_owner_mappings()
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["mappings"], [])
        self.assertEqual(result["total"], 0)

    def test_returns_rows(self):
        os.environ["BQ_OWNER_MAPPING_TABLE_ID"] = "proj.ds.owners"
        _ConfigurableBQClient.select_rows = [
            _Row(pattern="pkg:maven/*", system_name="基幹システム",
                 owner_email="owner@example.com", owner_name="Owner",
                 notes="", priority=1)
        ]
        result = self.mod.list_owner_mappings()
        self.assertEqual(result["status"], "success")
        self.assertEqual(len(result["mappings"]), 1)
        self.assertEqual(result["mappings"][0]["owner_email"], "owner@example.com")

    def test_search_query_included_in_sql(self):
        os.environ["BQ_OWNER_MAPPING_TABLE_ID"] = "proj.ds.owners"
        _ConfigurableBQClient.select_rows = []
        self.mod.list_owner_mappings(q="admin")
        sqls = " ".join(_ConfigurableBQClient.recorded_sql)
        self.assertIn("LIKE @q", sqls)


# ── insert_owner_mapping ─────────────────────────────────


class OwnerMappingInsertTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _install_google_stubs()
        cls.mod = _load_admin_api()

    def setUp(self):
        self._orig_env = dict(os.environ)
        _ConfigurableBQClient.reset()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._orig_env)

    def test_missing_table_returns_error(self):
        os.environ.pop("BQ_OWNER_MAPPING_TABLE_ID", None)
        result = self.mod.insert_owner_mapping({"pattern": "pkg:*"})
        self.assertEqual(result["status"], "error")

    def test_empty_pattern_returns_error(self):
        os.environ["BQ_OWNER_MAPPING_TABLE_ID"] = "proj.ds.owners"
        result = self.mod.insert_owner_mapping({"pattern": ""})
        self.assertEqual(result["status"], "error")
        self.assertIn("pattern", result["message"])

    def test_duplicate_pattern_system_returns_error(self):
        os.environ["BQ_OWNER_MAPPING_TABLE_ID"] = "proj.ds.owners"
        _ConfigurableBQClient.count_result = 1
        result = self.mod.insert_owner_mapping({"pattern": "pkg:*", "system_name": "SysA"})
        self.assertEqual(result["status"], "error")
        self.assertIn("既に存在します", result["message"])

    def test_new_mapping_succeeds(self):
        os.environ["BQ_OWNER_MAPPING_TABLE_ID"] = "proj.ds.owners"
        _ConfigurableBQClient.count_result = 0
        result = self.mod.insert_owner_mapping({
            "pattern": "pkg:maven/*", "system_name": "基幹システム",
            "owner_email": "owner@example.com", "owner_name": "Owner",
            "notes": "", "priority": 1,
        })
        self.assertEqual(result["status"], "success")

    def test_invalid_priority_defaults_to_9999(self):
        """priority が int に変換できない場合は 9999 になりエラーにならない"""
        os.environ["BQ_OWNER_MAPPING_TABLE_ID"] = "proj.ds.owners"
        _ConfigurableBQClient.count_result = 0
        result = self.mod.insert_owner_mapping({
            "pattern": "pkg:npm/*",
            "priority": "not-a-number",
        })
        self.assertEqual(result["status"], "success")

    def test_none_priority_defaults_to_9999(self):
        os.environ["BQ_OWNER_MAPPING_TABLE_ID"] = "proj.ds.owners"
        _ConfigurableBQClient.count_result = 0
        result = self.mod.insert_owner_mapping({"pattern": "pkg:npm/*"})
        self.assertEqual(result["status"], "success")


# ── update_owner_mapping / delete_owner_mapping ──────────


class OwnerMappingUpdateDeleteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _install_google_stubs()
        cls.mod = _load_admin_api()

    def setUp(self):
        self._orig_env = dict(os.environ)
        _ConfigurableBQClient.reset()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._orig_env)

    def test_update_missing_table_returns_error(self):
        os.environ.pop("BQ_OWNER_MAPPING_TABLE_ID", None)
        result = self.mod.update_owner_mapping("pkg:*", "SysA", {"pattern": "pkg:*"})
        self.assertEqual(result["status"], "error")

    def test_update_empty_old_pattern_returns_error(self):
        os.environ["BQ_OWNER_MAPPING_TABLE_ID"] = "proj.ds.owners"
        result = self.mod.update_owner_mapping("", "SysA", {"pattern": "pkg:*"})
        self.assertEqual(result["status"], "error")
        self.assertIn("必須", result["message"])

    def test_update_empty_new_pattern_returns_error(self):
        os.environ["BQ_OWNER_MAPPING_TABLE_ID"] = "proj.ds.owners"
        result = self.mod.update_owner_mapping("pkg:*", "SysA", {"pattern": ""})
        self.assertEqual(result["status"], "error")

    def test_update_succeeds(self):
        os.environ["BQ_OWNER_MAPPING_TABLE_ID"] = "proj.ds.owners"
        result = self.mod.update_owner_mapping(
            "pkg:*", "SysA",
            {"pattern": "pkg:maven/*", "system_name": "SysA",
             "owner_email": "x@x.com", "owner_name": "X", "notes": "", "priority": 1},
        )
        self.assertEqual(result["status"], "success")
        sqls = " ".join(_ConfigurableBQClient.recorded_sql)
        self.assertIn("UPDATE", sqls)

    def test_delete_missing_table_returns_error(self):
        os.environ.pop("BQ_OWNER_MAPPING_TABLE_ID", None)
        result = self.mod.delete_owner_mapping("pkg:*", "SysA")
        self.assertEqual(result["status"], "error")

    def test_delete_empty_pattern_returns_error(self):
        os.environ["BQ_OWNER_MAPPING_TABLE_ID"] = "proj.ds.owners"
        result = self.mod.delete_owner_mapping("", "SysA")
        self.assertEqual(result["status"], "error")
        self.assertIn("pattern", result["message"])

    def test_delete_succeeds(self):
        os.environ["BQ_OWNER_MAPPING_TABLE_ID"] = "proj.ds.owners"
        result = self.mod.delete_owner_mapping("pkg:maven/*", "基幹システム")
        self.assertEqual(result["status"], "success")
        sqls = " ".join(_ConfigurableBQClient.recorded_sql)
        self.assertIn("DELETE", sqls)


# ── app.py の admin ルート宣言チェック（AST）────────────────


class AdminApiRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import ast
        app_path = Path(__file__).resolve().parent / "live_gateway" / "app.py"
        cls._source = app_path.read_text(encoding="utf-8")
        cls._tree = ast.parse(cls._source)
        cls._declared = cls._extract_route_paths(cls._tree)

    @staticmethod
    def _extract_route_paths(tree) -> set[str]:
        import ast
        paths: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call) or not dec.args:
                    continue
                arg0 = dec.args[0]
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                    paths.add(arg0.value)
        return paths

    def test_admin_sbom_get_route_declared(self):
        self.assertTrue(
            {"/api/admin/sbom", "/api/admin/sbom/"} & self._declared,
            "GET /api/admin/sbom が宣言されていません",
        )

    def test_admin_owners_get_route_declared(self):
        self.assertTrue(
            {"/api/admin/owners", "/api/admin/owners/"} & self._declared,
            "GET /api/admin/owners が宣言されていません",
        )

    def test_admin_static_html_route(self):
        self.assertIn("/admin", self._source)

    def test_admin_js_and_css_routes(self):
        self.assertIn("/admin.js", self._source)
        self.assertIn("/admin.css", self._source)

    def test_require_admin_auth_helper_exists(self):
        self.assertIn("_require_admin_auth", self._source)

    def test_admin_api_available_flag_exists(self):
        self.assertIn("_admin_api_available", self._source)

    def test_import_fallback_pattern_exists(self):
        """相対インポート失敗時に絶対インポートへフォールバックする"""
        self.assertIn("from .sbom_admin_api import", self._source)
        self.assertIn("from sbom_admin_api import", self._source)

    def test_503_when_admin_api_unavailable(self):
        """_admin_api_available=False の場合に 503 を返す処理が存在する"""
        self.assertIn("503", self._source)
        self.assertIn("Admin API unavailable", self._source)


if __name__ == "__main__":
    unittest.main()
