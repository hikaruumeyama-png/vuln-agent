import importlib.util
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parent
A2A_TOOLS_PATH = ROOT / "agent" / "tools" / "a2a_tools.py"


class _FakeReasoningEngine:
    def __init__(self, resource_name: str):
        self.resource_name = resource_name

    def query(self, user_id: str, message: str):
        return {
            "content": {
                "parts": [
                    {"text": f"processed: {message}"},
                ],
            },
            "user_id": user_id,
        }


class _FakeReasoningEngineNoQuery:
    def __init__(self, resource_name: str):
        self.resource_name = resource_name


def _stub_vertexai_modules() -> None:
    vertexai = types.ModuleType("vertexai")
    vertexai.init = lambda *args, **kwargs: None

    preview = types.ModuleType("vertexai.preview")
    reasoning_engines = types.ModuleType("vertexai.preview.reasoning_engines")
    reasoning_engines.ReasoningEngine = _FakeReasoningEngine
    preview.reasoning_engines = reasoning_engines

    sys.modules["vertexai"] = vertexai
    sys.modules["vertexai.preview"] = preview
    sys.modules["vertexai.preview.reasoning_engines"] = reasoning_engines


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class A2AToolsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _stub_vertexai_modules()
        cls.a2a_tools = _load_module("a2a_tools_test", A2A_TOOLS_PATH)

    def setUp(self):
        self.a2a_tools._agent_registry.clear()

    def test_register_remote_agent_requires_valid_resource_name(self):
        result = self.a2a_tools.register_remote_agent("jira_agent", "bad-resource")
        self.assertEqual(result["status"], "error")
        self.assertIn("resource_name format is invalid", result["message"])

    def test_register_and_list_remote_agent(self):
        result = self.a2a_tools.register_remote_agent(
            "jira_agent",
            "projects/p1/locations/asia-northeast1/reasoningEngines/123",
            "Jira",
        )
        self.assertEqual(result["status"], "registered")
        listed = self.a2a_tools.list_registered_agents()
        self.assertEqual(listed["count"], 1)
        self.assertEqual(listed["agents"][0]["agent_id"], "jira_agent")

    def test_call_remote_agent_validates_inputs(self):
        missing = self.a2a_tools.call_remote_agent("", "hello")
        self.assertEqual(missing["status"], "error")
        self.assertIn("agent_id is required", missing["message"])

        unregistered = self.a2a_tools.call_remote_agent("jira_agent", "hello")
        self.assertEqual(unregistered["status"], "error")
        self.assertIn("not registered", unregistered["message"])

    def test_call_remote_agent_returns_response_text(self):
        self.a2a_tools.register_remote_agent(
            "jira_agent",
            "projects/p1/locations/asia-northeast1/reasoningEngines/123",
            "Jira",
        )
        result = self.a2a_tools.call_remote_agent("jira_agent", "create ticket")
        self.assertEqual(result["status"], "success")
        self.assertIn("processed: create ticket", result["response_text"])

    def test_call_remote_agent_falls_back_when_query_missing(self):
        self.a2a_tools.register_remote_agent(
            "master_agent",
            "projects/p1/locations/asia-northeast1/reasoningEngines/123",
            "Master",
        )
        original_engine = self.a2a_tools.reasoning_engines.ReasoningEngine
        original_rest_query = self.a2a_tools._query_remote_agent_rest
        try:
            self.a2a_tools.reasoning_engines.ReasoningEngine = _FakeReasoningEngineNoQuery

            def _fake_rest_query(**kwargs):
                return {"text": f"rest:{kwargs['message']}"}

            self.a2a_tools._query_remote_agent_rest = _fake_rest_query
            result = self.a2a_tools.call_remote_agent("master_agent", "ping")
            self.assertEqual(result["status"], "success")
            self.assertEqual(result["response_text"], "rest:ping")
        finally:
            self.a2a_tools.reasoning_engines.ReasoningEngine = original_engine
            self.a2a_tools._query_remote_agent_rest = original_rest_query

    def test_create_jira_ticket_request_validates_required_fields(self):
        result = self.a2a_tools.create_jira_ticket_request(
            vulnerability_id="",
            title="t",
            severity="高",
            affected_systems=["s1"],
            assignee="a@example.com",
        )
        self.assertEqual(result["status"], "error")
        self.assertIn("vulnerability_id", result["message"])

    def test_create_approval_request_validates_required_fields(self):
        result = self.a2a_tools.create_approval_request(
            vulnerability_id="CVE-1",
            action="",
            approvers=["x@example.com"],
        )
        self.assertEqual(result["status"], "error")
        self.assertIn("action", result["message"])

    def test_register_master_agent_uses_env_when_missing_argument(self):
        import os

        os.environ["REMOTE_AGENT_MASTER"] = "projects/p1/locations/asia-northeast1/reasoningEngines/999"
        try:
            result = self.a2a_tools.register_master_agent()
            self.assertEqual(result["status"], "registered")
            self.assertEqual(result["agent_id"], "master_agent")
        finally:
            os.environ.pop("REMOTE_AGENT_MASTER", None)

    def test_create_master_agent_handoff_request_requires_fields(self):
        result = self.a2a_tools.create_master_agent_handoff_request(
            task_type="",
            objective="調整",
        )
        self.assertEqual(result["status"], "error")
        self.assertIn("task_type", result["message"])

    def test_call_master_agent_success(self):
        self.a2a_tools.register_remote_agent(
            "master_agent",
            "projects/p1/locations/asia-northeast1/reasoningEngines/321",
            "Master",
        )
        result = self.a2a_tools.call_master_agent(
            task_type="方針確認",
            objective="優先順位を確定したい",
            facts=["CVSS 9.8", "公開資産が影響"],
            requested_actions=["対応順序を提示してください"],
        )
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["agent_id"], "master_agent")
        self.assertIn("processed:", result["response_text"])


if __name__ == "__main__":
    unittest.main()
