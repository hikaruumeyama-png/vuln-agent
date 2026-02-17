import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parent
CHAT_WEBHOOK_PATH = ROOT / "chat_webhook" / "main.py"


def _stub_dependencies() -> None:
    ff = types.ModuleType("functions_framework")
    ff.http = lambda fn: fn
    sys.modules["functions_framework"] = ff

    vertexai = types.ModuleType("vertexai")
    vertexai.init = lambda **kwargs: None
    vertexai.Client = object
    sys.modules["vertexai"] = vertexai


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class _FakeRequest:
    def __init__(self, payload):
        self._payload = payload

    def get_json(self, silent=True):
        _ = silent
        return self._payload


class ChatWebhookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _stub_dependencies()
        cls.chat_webhook = _load_module("chat_webhook_test_module", CHAT_WEBHOOK_PATH)

    def setUp(self):
        if hasattr(self.chat_webhook, "_RECENT_TURNS"):
            self.chat_webhook._RECENT_TURNS.clear()

    def test_clean_chat_text_prefers_argument_text(self):
        text = self.chat_webhook._clean_chat_text(
            {"message": {"argumentText": "  CVEを調べて  ", "text": "@bot 無視される"}}
        )
        self.assertEqual(text, "CVEを調べて")

    def test_clean_chat_text_removes_mentions(self):
        text = self.chat_webhook._clean_chat_text({"message": {"text": "<users/12345> こんにちは"}})
        self.assertEqual(text, "こんにちは")

    def test_handle_chat_event_returns_threaded_response(self):
        self.chat_webhook._is_valid_token = lambda event: True
        self.chat_webhook._run_agent_query = lambda prompt, user_id: f"echo:{prompt}:{user_id}"
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {"text": "<users/999> CVE-2026-1234 の影響を確認して", "thread": {"name": "spaces/AAA/threads/BBB"}},
        }
        raw_body, status, _headers = self.chat_webhook.handle_chat_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertEqual(body["thread"]["name"], "spaces/AAA/threads/BBB")
        self.assertIn("echo:CVE-2026-1234 の影響を確認して:111", body["text"])

    def test_handle_chat_event_returns_clarification_for_ambiguous_prompt(self):
        self.chat_webhook._is_valid_token = lambda event: True
        self.chat_webhook._run_agent_query = lambda prompt, user_id: (_ for _ in ()).throw(
            AssertionError("Agent should not be called for ambiguous prompts")
        )
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {"text": "<users/999> これお願い", "thread": {"name": "spaces/AAA/threads/BBB"}},
        }
        raw_body, status, _headers = self.chat_webhook.handle_chat_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertEqual(body["thread"]["name"], "spaces/AAA/threads/BBB")
        self.assertIn("もう少し具体化してください", body["text"])

    def test_ambiguous_prompt_uses_recent_context(self):
        self.chat_webhook._is_valid_token = lambda event: True
        captured: list[str] = []

        def _fake_run(prompt, user_id):
            captured.append(prompt)
            return f"echo:{user_id}"

        self.chat_webhook._run_agent_query = _fake_run

        first_payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {"text": "<users/999> CVE-2026-1234 の影響を確認して", "thread": {"name": "spaces/AAA/threads/BBB"}},
        }
        second_payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {"text": "<users/999> 先ほどの件で優先度は？", "thread": {"name": "spaces/AAA/threads/BBB"}},
        }

        _raw_body1, status1, _headers1 = self.chat_webhook.handle_chat_event(_FakeRequest(first_payload))
        raw_body2, status2, _headers2 = self.chat_webhook.handle_chat_event(_FakeRequest(second_payload))

        self.assertEqual(status1, 200)
        self.assertEqual(status2, 200)
        self.assertEqual(len(captured), 2)
        self.assertIn("直近の会話文脈", captured[1])
        self.assertIn("CVE-2026-1234 の影響を確認して", captured[1])
        body2 = json.loads(raw_body2)
        self.assertIn("echo:111", body2["text"])

    def test_handle_chat_event_rejects_invalid_token(self):
        self.chat_webhook._is_valid_token = lambda event: False
        payload = {"type": "MESSAGE", "message": {"text": "test"}}
        _raw_body, status, _headers = self.chat_webhook.handle_chat_event(_FakeRequest(payload))
        self.assertEqual(status, 403)


if __name__ == "__main__":
    unittest.main()
