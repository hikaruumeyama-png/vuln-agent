import importlib.util
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parent
AGENT_PATH = ROOT / "test_dialog_agent" / "agent.py"


def _stub_adk_modules() -> None:
    google = types.ModuleType("google")
    adk = types.ModuleType("google.adk")
    tools = types.ModuleType("google.adk.tools")

    class _Agent:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class _FunctionTool:
        def __init__(self, fn):
            self.fn = fn

    adk.Agent = _Agent
    tools.FunctionTool = _FunctionTool
    google.adk = adk

    sys.modules["google"] = google
    sys.modules["google.adk"] = adk
    sys.modules["google.adk.tools"] = tools


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class TestDialogAgentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _stub_adk_modules()
        cls.mod = _load_module("test_dialog_agent_module", AGENT_PATH)

    def test_ping(self):
        result = self.mod.ping()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["agent"], "test_dialog_agent")

    def test_echo_message(self):
        result = self.mod.echo_message(" hello ", source="a2a")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["received_message"], "hello")
        self.assertEqual(result["source"], "a2a")

    def test_parse_handoff_sections(self):
        text = "【連携種別】\n方針確認\n\n【目的】\n優先順位を決める"
        result = self.mod.parse_handoff_sections(text)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["sections"]["連携種別"], "方針確認")
        self.assertEqual(result["sections"]["目的"], "優先順位を決める")


if __name__ == "__main__":
    unittest.main()

