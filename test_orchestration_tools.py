import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent
TOOLS_PATH = ROOT / "agent" / "tools" / "orchestration_tools.py"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class OrchestrationToolsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module("orchestration_tools_test_module", TOOLS_PATH)

    def test_list_predefined_operations(self):
        result = self.mod.list_predefined_operations()
        self.assertEqual(result["status"], "success")
        self.assertGreater(result["count"], 10)
        self.assertIn("operations", result)
        self.assertIn("domains", result)

    def test_decide_execution_mode_direct(self):
        result = self.mod.decide_execution_mode("CVE-2026-1234のCVSSを確認して")
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["mode"], "direct_tool")

    def test_decide_execution_mode_codegen(self):
        result = self.mod.decide_execution_mode(
            "通知本文を全件抽出してSBOMを横断突合して担当者ごとに集計してから通知して",
            requested_operations=["search_sbom_by_product", "get_owner_mapping", "send_vulnerability_alert", "log_vulnerability_history"],
        )
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["mode"], "codegen_with_tools")
        self.assertGreaterEqual(result["complexity_score"], 3)

    def test_generate_tool_workflow_code(self):
        result = self.mod.generate_tool_workflow_code(
            "CVE-2026-1234の確認",
            tool_sequence=["get_nvd_cve_details", "get_nvd_cvss_summary"],
        )
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["language"], "python")
        self.assertIn("def run_workflow", result["code"])
        self.assertIn("get_nvd_cve_details", result["code"])

    def test_list_operation_catalog_health(self):
        result = self.mod.list_operation_catalog_health()
        self.assertEqual(result["status"], "success")
        self.assertIn("is_synced", result)
        self.assertIsInstance(result["missing_in_catalog"], list)

    def test_execute_tool_workflow_plan_rejects_unknown_tool(self):
        result = self.mod.execute_tool_workflow_plan(
            [{"tool": "tool_not_found", "kwargs": {}}],
            fail_fast=True,
        )
        self.assertEqual(result["status"], "error")
        self.assertIn("step_results", result)


if __name__ == "__main__":
    unittest.main()
