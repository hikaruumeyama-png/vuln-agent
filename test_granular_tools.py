import importlib.util
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parent
TOOLS_PATH = ROOT / "agent" / "tools" / "granular_tools.py"


def _stub_dependency_modules() -> None:
    gmail_tools = types.ModuleType("gmail_tools")
    gmail_tools.get_sidfm_emails = lambda max_results=10: {
        "status": "success",
        "emails": [{"id": "m1", "subject": "s1"}, {"id": "m2", "subject": "s2"}],
    }
    gmail_tools.get_unread_emails = lambda query="is:unread", max_results=10: {
        "status": "success",
        "emails": [{"id": "m1", "subject": "s1", "body_preview": "p1"}],
    }
    sys.modules["gmail_tools"] = gmail_tools

    chat_tools = types.ModuleType("chat_tools")
    chat_tools.check_chat_connection = lambda space_id=None: {
        "status": "connected",
        "space_id": "spaces/AAA",
        "space_name": "team",
        "space_type": "SPACE",
        "member_count": 2,
    }
    chat_tools.list_space_members = lambda space_id=None: {
        "status": "success",
        "members": [{"email": "a@example.com"}, {"email": "b@example.com"}],
    }
    sys.modules["chat_tools"] = chat_tools

    history_tools = types.ModuleType("history_tools")
    history_tools.log_vulnerability_history = lambda **kwargs: {"status": "saved", "incident_id": "x"}
    sys.modules["history_tools"] = history_tools

    a2a_tools = types.ModuleType("a2a_tools")
    a2a_tools.list_registered_agents = lambda: {
        "status": "success",
        "agents": [{"agent_id": "jira_agent"}, {"agent_id": "report_agent"}],
    }
    sys.modules["a2a_tools"] = a2a_tools

    capability_tools = types.ModuleType("capability_tools")
    capability_tools.get_runtime_capabilities = lambda include_live_checks=True: {
        "configuration": {"project_id": "proj", "bigquery_tables": {"sbom": "proj.ds.tbl"}}
    }
    capability_tools.inspect_bigquery_capabilities = lambda: {
        "status": "success",
        "project_id": "proj",
        "table_read_checks": [{"name": "sbom", "readable": True}, {"name": "history", "readable": False}],
    }
    sys.modules["capability_tools"] = capability_tools

    web_tools = types.ModuleType("web_tools")
    web_tools.web_search = lambda query, max_results=5: {
        "status": "success",
        "results": [{"url": "https://a.example"}, {"url": "https://b.example"}],
    }
    web_tools.fetch_web_content = lambda url, max_chars=1200: {
        "status": "success",
        "url": url,
        "content": "example content",
        "content_type": "text/html",
    }
    sys.modules["web_tools"] = web_tools

    vuln_intel_tools = types.ModuleType("vuln_intel_tools")
    vuln_intel_tools.get_nvd_cve_details = lambda cve_id: {
        "status": "success",
        "cve_id": cve_id,
        "found": True,
        "cvss": {"base_score": 9.8},
        "published": "2026-01-01",
        "last_modified": "2026-01-02",
    }
    vuln_intel_tools.search_osv_vulnerabilities = lambda ecosystem, package_name, version="", max_results=10: {
        "status": "success",
        "query": {"ecosystem": ecosystem, "package_name": package_name, "version": version},
        "vulnerabilities": [{"id": "OSV-1"}, {"id": "OSV-2"}],
    }
    sys.modules["vuln_intel_tools"] = vuln_intel_tools


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class GranularToolsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _stub_dependency_modules()
        cls.mod = _load_module("granular_tools_test_module", TOOLS_PATH)

    def test_list_sidfm_email_subjects(self):
        result = self.mod.list_sidfm_email_subjects()
        self.assertEqual(result["count"], 2)

    def test_get_chat_space_info(self):
        result = self.mod.get_chat_space_info()
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["space_id"], "spaces/AAA")

    def test_get_nvd_cvss_summary(self):
        result = self.mod.get_nvd_cvss_summary("CVE-2026-0001")
        self.assertEqual(result["status"], "success")
        self.assertTrue(result["found"])

    def test_list_osv_vulnerability_ids(self):
        result = self.mod.list_osv_vulnerability_ids("PyPI", "requests")
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["vulnerability_ids"], ["OSV-1", "OSV-2"])


if __name__ == "__main__":
    unittest.main()
