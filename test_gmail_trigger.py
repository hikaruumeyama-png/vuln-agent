import base64
import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parent
GMAIL_TRIGGER_PATH = ROOT / "gmail_trigger" / "main.py"


def _stub_dependencies() -> None:
    ff = types.ModuleType("functions_framework")
    ff.cloud_event = lambda fn: fn
    ff.http = lambda fn: fn
    sys.modules["functions_framework"] = ff

    vertexai = types.ModuleType("vertexai")
    vertexai.init = lambda **kwargs: None
    vertexai.Client = object
    sys.modules["vertexai"] = vertexai

    googleapiclient = types.ModuleType("googleapiclient")
    discovery = types.ModuleType("googleapiclient.discovery")
    discovery.build = lambda *args, **kwargs: object()
    googleapiclient.discovery = discovery
    sys.modules["googleapiclient"] = googleapiclient
    sys.modules["googleapiclient.discovery"] = discovery


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class GmailTriggerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _stub_dependencies()
        cls.gmail_trigger = _load_module("gmail_trigger_test_module", GMAIL_TRIGGER_PATH)

    def test_build_sidfm_query_uses_or_with_sender_and_subject(self):
        query = self.gmail_trigger._build_sidfm_query("noreply@sidfm.com", "[SIDfm]", "7d")
        self.assertEqual(
            query,
            '(from:noreply@sidfm.com OR subject:"[SIDfm]") is:unread newer_than:7d',
        )

    def test_parse_pubsub_payload_decodes_message_data(self):
        payload = {"emailAddress": "user@example.com", "historyId": "12345"}
        encoded = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
        cloud_event = {"data": {"message": {"data": encoded}}}
        parsed = self.gmail_trigger._parse_pubsub_payload(cloud_event)
        self.assertEqual(parsed, payload)


if __name__ == "__main__":
    unittest.main()
