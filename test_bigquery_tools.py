import importlib.util
import os
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parent
SHEETS_TOOLS_PATH = ROOT / "agent" / "tools" / "sheets_tools.py"
HISTORY_TOOLS_PATH = ROOT / "agent" / "tools" / "history_tools.py"


class _StubQueryClient:
    should_raise = False

    def __init__(self, project=None):
        self.project = project

    def query(self, query):
        if self.should_raise:
            raise RuntimeError("query failed")
        return types.SimpleNamespace(result=lambda: [])

    def insert_rows_json(self, table_id, rows):
        return []


class _StubHistoryClient:
    should_raise = False
    return_errors = None

    def __init__(self, project=None):
        self.project = project

    def insert_rows_json(self, table_id, rows):
        if self.should_raise:
            raise RuntimeError("insert failed")
        return self.return_errors or []


def _stub_google_modules_for_sheets() -> None:
    google = types.ModuleType("google")
    cloud = types.ModuleType("google.cloud")
    bigquery = types.ModuleType("google.cloud.bigquery")
    bigquery.Client = _StubQueryClient
    cloud.bigquery = bigquery
    google.cloud = cloud

    oauth2 = types.ModuleType("google.oauth2")
    service_account = types.ModuleType("google.oauth2.service_account")

    class _Creds:
        @staticmethod
        def from_service_account_file(*args, **kwargs):
            return object()

    service_account.Credentials = _Creds
    oauth2.service_account = service_account
    google.oauth2 = oauth2

    googleapiclient = types.ModuleType("googleapiclient")
    discovery = types.ModuleType("googleapiclient.discovery")
    discovery.build = lambda *args, **kwargs: object()
    googleapiclient.discovery = discovery

    sys.modules["google"] = google
    sys.modules["google.cloud"] = cloud
    sys.modules["google.cloud.bigquery"] = bigquery
    sys.modules["google.oauth2"] = oauth2
    sys.modules["google.oauth2.service_account"] = service_account
    sys.modules["googleapiclient"] = googleapiclient
    sys.modules["googleapiclient.discovery"] = discovery

    packaging = types.ModuleType("packaging")
    packaging_version = types.ModuleType("packaging.version")
    packaging_version.parse = lambda value: value
    packaging.version = packaging_version
    sys.modules["packaging"] = packaging
    sys.modules["packaging.version"] = packaging_version

    secret_config = types.ModuleType("secret_config")

    def get_config_value(env_names, secret_name=None, default=""):
        for env_name in env_names:
            value = (os.environ.get(env_name) or "").strip()
            if value:
                return value
        if secret_name:
            secret_env_key = f"TEST_SECRET_{secret_name.upper().replace('-', '_')}"
            secret_value = (os.environ.get(secret_env_key) or "").strip()
            if secret_value:
                return secret_value
        return default

    secret_config.get_config_value = get_config_value
    sys.modules["secret_config"] = secret_config


def _stub_google_modules_for_history() -> None:
    google = types.ModuleType("google")
    cloud = types.ModuleType("google.cloud")
    bigquery = types.ModuleType("google.cloud.bigquery")
    bigquery.Client = _StubHistoryClient
    cloud.bigquery = bigquery
    google.cloud = cloud
    sys.modules["google"] = google
    sys.modules["google.cloud"] = cloud
    sys.modules["google.cloud.bigquery"] = bigquery


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class BigQuerySheetsToolsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _stub_google_modules_for_sheets()
        cls.sheets_tools = _load_module("sheets_tools_bq_test", SHEETS_TOOLS_PATH)

    def setUp(self):
        self._orig_env = dict(os.environ)
        self._orig_load_sbom = self.sheets_tools._load_sbom
        os.environ["SBOM_DATA_BACKEND"] = "bigquery"
        self.sheets_tools._sbom_cache = None
        self.sheets_tools._sbom_cache_timestamp = None
        self.sheets_tools._sbom_cache_backend = None
        self.sheets_tools._sbom_last_error = ""
        _StubQueryClient.should_raise = False

    def tearDown(self):
        self.sheets_tools._load_sbom = self._orig_load_sbom
        os.environ.clear()
        os.environ.update(self._orig_env)

    def test_normalize_bigquery_table_id(self):
        self.assertEqual(
            self.sheets_tools._normalize_bigquery_table_id("proj.ds.tbl", "BQ_SBOM_TABLE_ID"),
            "proj.ds.tbl",
        )
        self.assertEqual(
            self.sheets_tools._normalize_bigquery_table_id("ds.tbl", "BQ_SBOM_TABLE_ID"),
            "ds.tbl",
        )
        self.assertEqual(
            self.sheets_tools._normalize_bigquery_table_id("bad table id", "BQ_SBOM_TABLE_ID"),
            "",
        )

    def test_search_sbom_by_purl_requires_pattern(self):
        result = self.sheets_tools.search_sbom_by_purl(" ")
        self.assertEqual(result["status"], "error")

    def test_search_sbom_by_purl_surfaces_missing_table_config(self):
        os.environ.pop("BQ_SBOM_TABLE_ID", None)
        result = self.sheets_tools.search_sbom_by_purl("pkg:maven")
        self.assertIn("BQ_SBOM_TABLE_ID", result["message"])

    def test_search_sbom_by_purl_surfaces_bigquery_error(self):
        os.environ["BQ_SBOM_TABLE_ID"] = "proj.ds.tbl"
        _StubQueryClient.should_raise = True
        result = self.sheets_tools.search_sbom_by_purl("pkg:maven")
        self.assertIn("BigQueryからSBOM取得に失敗", result["message"])

    def test_search_sbom_uses_secret_when_env_missing(self):
        os.environ.pop("BQ_SBOM_TABLE_ID", None)
        os.environ["TEST_SECRET_VULN_AGENT_BQ_SBOM_TABLE_ID"] = "proj.ds.tbl"
        _StubQueryClient.should_raise = True
        result = self.sheets_tools.search_sbom_by_purl("pkg:maven")
        self.assertIn("BigQueryからSBOM取得に失敗", result["message"])

    def test_get_sbom_contents_returns_preview_and_summary(self):
        self.sheets_tools._load_sbom = lambda force_refresh=False: [
            {"type": "maven", "name": "a", "version": "1.0.0", "release": "", "purl": "pkg:maven/a@1.0.0"},
            {"type": "npm", "name": "b", "version": "2.0.0", "release": "", "purl": "pkg:npm/b@2.0.0"},
            {"type": "maven", "name": "c", "version": "3.0.0", "release": "", "purl": "pkg:maven/c@3.0.0"},
        ]
        result = self.sheets_tools.get_sbom_contents(max_results=2)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["returned_count"], 2)
        self.assertEqual(result["total_count"], 3)
        self.assertEqual(result["type_counts"]["maven"], 2)
        self.assertEqual(result["type_counts"]["npm"], 1)

    def test_get_sbom_contents_returns_error_when_empty(self):
        self.sheets_tools._load_sbom = lambda force_refresh=False: []
        result = self.sheets_tools.get_sbom_contents(max_results=10)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["returned_count"], 0)


class BigQueryHistoryToolsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _stub_google_modules_for_history()
        cls.history_tools = _load_module("history_tools_bq_test", HISTORY_TOOLS_PATH)

    def setUp(self):
        self._orig_env = dict(os.environ)
        _StubHistoryClient.should_raise = False
        _StubHistoryClient.return_errors = None

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._orig_env)

    def test_history_requires_required_fields(self):
        os.environ["BQ_HISTORY_TABLE_ID"] = "proj.ds.tbl"
        result = self.history_tools.log_vulnerability_history(
            vulnerability_id="",
            title="title",
            severity="高",
            affected_systems=["sys-a"],
        )
        self.assertEqual(result["status"], "error")

    def test_history_rejects_invalid_occurred_at(self):
        os.environ["BQ_HISTORY_TABLE_ID"] = "proj.ds.tbl"
        result = self.history_tools.log_vulnerability_history(
            vulnerability_id="CVE-2026-0001",
            title="title",
            severity="高",
            affected_systems=["sys-a"],
            occurred_at="not-a-date",
        )
        self.assertEqual(result["status"], "error")

    def test_history_returns_error_on_insert_exception(self):
        os.environ["BQ_HISTORY_TABLE_ID"] = "proj.ds.tbl"
        _StubHistoryClient.should_raise = True
        result = self.history_tools.log_vulnerability_history(
            vulnerability_id="CVE-2026-0002",
            title="title",
            severity="高",
            affected_systems=["sys-a"],
        )
        self.assertEqual(result["status"], "error")
        self.assertIn("BigQuery insert failed", result["message"])


if __name__ == "__main__":
    unittest.main()
