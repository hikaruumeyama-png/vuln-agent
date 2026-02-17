from pathlib import Path
import unittest


AGENT_FILE = Path(__file__).resolve().parent / "agent" / "agent.py"
TOOLS_INIT_FILE = Path(__file__).resolve().parent / "agent" / "tools" / "__init__.py"


class AgentOrchestrationPolicyTests(unittest.TestCase):
    def test_agent_instruction_contains_execution_mode_policy(self):
        source = AGENT_FILE.read_text(encoding="utf-8")
        self.assertIn("実行方式選択ポリシー（必須）", source)
        self.assertIn("decide_execution_mode", source)
        self.assertIn("codegen_with_tools", source)

    def test_agent_registers_orchestration_tools(self):
        source = AGENT_FILE.read_text(encoding="utf-8")
        self.assertIn("FunctionTool(list_predefined_operations)", source)
        self.assertIn("FunctionTool(list_operation_catalog_health)", source)
        self.assertIn("FunctionTool(get_authorized_operations_overview)", source)
        self.assertIn("FunctionTool(decide_execution_mode)", source)
        self.assertIn("FunctionTool(generate_tool_workflow_code)", source)
        self.assertIn("FunctionTool(execute_tool_workflow_plan)", source)
        self.assertIn("FunctionTool(list_known_config_keys)", source)
        self.assertIn("FunctionTool(get_runtime_config_snapshot)", source)

    def test_tools_package_exports_orchestration_tools(self):
        source = TOOLS_INIT_FILE.read_text(encoding="utf-8")
        self.assertIn('"orchestration_tools"', source)
        self.assertIn('"list_predefined_operations"', source)
        self.assertIn('"list_operation_catalog_health"', source)
        self.assertIn('"get_authorized_operations_overview"', source)
        self.assertIn('"decide_execution_mode"', source)
        self.assertIn('"generate_tool_workflow_code"', source)
        self.assertIn('"execute_tool_workflow_plan"', source)
        self.assertIn('"config_tools"', source)
        self.assertIn('"list_known_config_keys"', source)
        self.assertIn('"get_runtime_config_snapshot"', source)


if __name__ == "__main__":
    unittest.main()
