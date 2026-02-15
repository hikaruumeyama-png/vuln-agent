import importlib.util
import os
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parent
CAPABILITY_TOOLS_PATH = ROOT / "agent" / "tools" / "capability_tools.py"


class _StubRow(dict):
    def keys(self):
        return super().keys()

    def get(self, key, default=None):
        return super().get(key, default)


class _StubQueryResult:
    def __init__(self, rows):
        self._rows = rows

    def result(self):
        return self._rows


class _StubTableItem:
    def __init__(self, table_id):
        self.table_id = table_id
        self.full_table_id = f"proj:ds.{table_id}"
        self.table_type = "TABLE"


class _StubBQClient:
    fail_list_datasets = False
    fail_list_tables = False
    fail_query = False

    def __init__(self, project=None):
        self.project = project or "proj"

    def list_datasets(self):
        if self.fail_list_datasets:
            raise RuntimeError("list_datasets denied")
        return [types.SimpleNamespace(dataset_id="vuln_agent")]

    def list_tables(self, dataset_ref, max_results=100):
        _ = max_results
        if self.fail_list_tables:
            raise RuntimeError(f"list_tables denied: {dataset_ref}")
        return [_StubTableItem("sbom_packages"), _StubTableItem("owner_mapping")]

    def query(self, sql):
        if self.fail_query:
            raise RuntimeError("query denied")
        if "SELECT * FROM (" in sql:
            return _StubQueryResult([_StubRow({"name": "log4j", "version": "2.17.0"})])
        return _StubQueryResult([])


def _stub_modules():
    google = types.ModuleType("google")
    cloud = types.ModuleType("google.cloud")
    bigquery = types.ModuleType("google.cloud.bigquery")
    bigquery.Client = _StubBQClient
    cloud.bigquery = bigquery
    google.cloud = cloud
    sys.modules["google"] = google
    sys.modules["google.cloud"] = cloud
    sys.modules["google.cloud.bigquery"] = bigquery

    secret_config = types.ModuleType("secret_config")

    def get_config_value(env_names, secret_name=None, default=""):
        _ = secret_name
        for env_name in env_names:
            value = (os.environ.get(env_name) or "").strip()
            if value:
                return value
        return default

    secret_config.get_config_value = get_config_value
    sys.modules["secret_config"] = secret_config

    gmail_tools = types.ModuleType("gmail_tools")
    gmail_tools.check_gmail_connection = lambda: {"status": "connected"}
    sys.modules["gmail_tools"] = gmail_tools

    chat_tools = types.ModuleType("chat_tools")
    chat_tools.check_chat_connection = lambda: {"status": "connected"}
    sys.modules["chat_tools"] = chat_tools

    sheets_tools = types.ModuleType("sheets_tools")
    sheets_tools.get_owner_mapping = lambda: {"total_count": 1}
    sys.modules["sheets_tools"] = sheets_tools

    a2a_tools = types.ModuleType("a2a_tools")
    a2a_tools.list_registered_agents = lambda: {"count": 0}
    sys.modules["a2a_tools"] = a2a_tools


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class CapabilityToolsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _stub_modules()
        cls.mod = _load_module("capability_tools_test_module", CAPABILITY_TOOLS_PATH)

    def test_is_readonly_sql(self):
        self.assertTrue(self.mod._is_readonly_sql("SELECT 1"))
        self.assertTrue(self.mod._is_readonly_sql("WITH t AS (SELECT 1) SELECT * FROM t"))
        self.assertTrue(self.mod._is_readonly_sql("SELECT 1;"))
        self.assertFalse(self.mod._is_readonly_sql("DELETE FROM x"))
        self.assertFalse(self.mod._is_readonly_sql("SELECT 1; DROP TABLE t"))
        self.assertFalse(self.mod._is_readonly_sql("SELECT 1; SELECT 2"))

    def test_list_bigquery_tables_requires_dataset(self):
        result = self.mod.list_bigquery_tables("")
        self.assertEqual(result["status"], "error")

    def test_run_bigquery_readonly_query_success(self):
        result = self.mod.run_bigquery_readonly_query("SELECT name, version FROM `proj.ds.tbl`")
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["row_count"], 1)

    def test_run_bigquery_readonly_query_allows_trailing_semicolon(self):
        result = self.mod.run_bigquery_readonly_query("SELECT 1;")
        self.assertEqual(result["status"], "success")

    def test_get_runtime_capabilities_live_check_error_is_wrapped(self):
        original = self.mod.check_chat_connection
        self.mod.check_chat_connection = lambda: (_ for _ in ()).throw(RuntimeError("chat down"))
        try:
            result = self.mod.get_runtime_capabilities(include_live_checks=True)
            self.assertEqual(result["live_checks"]["chat"]["status"], "error")
            self.assertIn("chat down", result["live_checks"]["chat"]["message"])
        finally:
            self.mod.check_chat_connection = original

    def test_inspect_bigquery_capabilities(self):
        os.environ["BQ_SBOM_TABLE_ID"] = "proj.vuln_agent.sbom_packages"
        os.environ["BQ_OWNER_MAPPING_TABLE_ID"] = "proj.vuln_agent.owner_mapping"
        result = self.mod.inspect_bigquery_capabilities()
        self.assertEqual(result["status"], "success")
        self.assertIn("table_read_checks", result)
        self.assertIn("dataset_listing", result)


if __name__ == "__main__":
    unittest.main()
