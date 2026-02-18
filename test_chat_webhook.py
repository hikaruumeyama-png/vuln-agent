import importlib.util
import json
import os
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
        for key in ("AGENT_RESOURCE_NAME", "AGENT_RESOURCE_NAME_FLASH", "AGENT_RESOURCE_NAME_PRO"):
            os.environ.pop(key, None)

    def test_clean_chat_text_prefers_argument_text(self):
        text = self.chat_webhook._clean_chat_text(
            {"message": {"argumentText": "  CVEを調べて  ", "text": "@bot 無視される"}}
        )
        self.assertEqual(text, "CVEを調べて")

    def test_clean_chat_text_removes_mentions(self):
        text = self.chat_webhook._clean_chat_text({"message": {"text": "<users/12345> こんにちは"}})
        self.assertEqual(text, "こんにちは")

    def test_is_gmail_app_message_detects_card_style_digest(self):
        payload = {
            "message": {
                "sender": {"displayName": "Notifier", "type": "BOT", "name": "users/abc"},
                "text": (
                    "[悪用された脆弱性] Apple複数のバッファオーバーフロー脆弱性\n"
                    "From: yoshihisa.kamimura@rakus.co.jp\n"
                    "CVE-2026-20700\n"
                    "View message\n"
                    "To view the full email in Google Groups..."
                ),
            }
        }
        self.assertTrue(self.chat_webhook._is_gmail_app_message(payload))

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
        self.assertIn("echo:CVE-2026-1234 の影響を確認して:thread:spaces/AAA/threads/BBB", body["text"])

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
        self.assertIn("echo:thread:spaces/AAA/threads/BBB", body2["text"])

    def test_handle_chat_event_processes_card_style_notification(self):
        self.chat_webhook._is_valid_token = lambda event: True
        captured: list[str] = []

        def _fake_run(prompt, user_id):
            captured.append(prompt)
            return "ok"

        self.chat_webhook._run_agent_query = _fake_run
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "sender": {"displayName": "Notifier", "type": "BOT", "name": "users/abc"},
                "text": (
                    "[悪用された脆弱性] Apple複数のバッファオーバーフロー脆弱性\n"
                    "From: sidfm-notification@rakus.co.jp\n"
                    "CVE-2026-20700\n"
                    "View message"
                ),
                "thread": {"name": "spaces/AAA/threads/BBB"},
            },
        }
        raw_body, status, _headers = self.chat_webhook.handle_chat_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        self.assertEqual(len(captured), 1)
        self.assertIn("GmailアプリがChatに投稿したメール内容", captured[0])
        self.assertIn("【希望納期】", captured[0])
        self.assertIn("【脆弱性情報（リンク貼り付け）】", captured[0])
        body = json.loads(raw_body)
        self.assertIn("【起票用（コピペ）】", body["text"])
        self.assertIn("【判断理由】", body["text"])

    def test_analysis_trigger_uses_thread_root_message(self):
        self.chat_webhook._is_valid_token = lambda event: True
        self.chat_webhook._fetch_thread_root_message_text = lambda event: (
            "From: sidfm-notification@rakus.co.jp\nCVE-2026-30001\nView message"
        )
        captured: list[str] = []

        def _fake_run(prompt, user_id):
            captured.append(prompt)
            return "ok"

        self.chat_webhook._run_agent_query = _fake_run
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "text": "<users/999> 確認して",
                "thread": {"name": "spaces/AAA/threads/BBB"},
            },
        }
        raw_body, status, _headers = self.chat_webhook.handle_chat_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        self.assertEqual(len(captured), 1)
        self.assertIn("【希望納期】", captured[0])
        self.assertIn("sidfm-notification@rakus.co.jp", captured[0])
        body = json.loads(raw_body)
        self.assertIn("【起票用（コピペ）】", body["text"])
        self.assertIn("【判断理由】", body["text"])

    def test_analysis_trigger_without_thread_source_uses_thread_followup_prompt(self):
        self.chat_webhook._is_valid_token = lambda event: True
        self.chat_webhook._fetch_thread_root_message_text = lambda event: ""
        self.chat_webhook._fetch_latest_ticket_record_from_history = lambda event: {}
        self.chat_webhook._run_agent_query = lambda prompt, user_id: (_ for _ in ()).throw(
            AssertionError("Agent should not be called when no backfill context is available")
        )
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {"text": "<users/999> 確認して", "thread": {"name": "spaces/AAA/threads/BBB"}},
        }
        raw_body, status, _headers = self.chat_webhook.handle_chat_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertIn("初回取り込みが未完了", body["text"])
        self.assertIn("この内容で起票用を作成して", body["text"])

    def test_analysis_trigger_without_thread_source_uses_history_ticket_record(self):
        self.chat_webhook._is_valid_token = lambda event: True
        self.chat_webhook._fetch_thread_root_message_text = lambda event: ""
        self.chat_webhook._fetch_latest_ticket_record_from_history = lambda event: {
            "incident_id": "123e4567-e89b-12d3-a456-426614174000",
            "copy_paste_text": "【起票用（コピペ）】\n大分類: 017.脆弱性対応（情シス専用）",
            "reasoning_text": "【判断理由】\n- 履歴から再利用",
            "title": "AlmaLinux の脆弱性確認",
            "vulnerability_id": "CVE-2026-9999",
        }
        self.chat_webhook._run_agent_query = lambda prompt, user_id: (_ for _ in ()).throw(
            AssertionError("Agent should not be called when history fallback is available")
        )
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {"text": "<users/999> 確認して", "thread": {"name": "spaces/AAA/threads/BBB"}},
        }
        raw_body, status, _headers = self.chat_webhook.handle_chat_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertIn("【起票用（コピペ）】", body["text"])
        self.assertIn("【判断理由】", body["text"])
        self.assertIn("【管理ID】", body["text"])

    def test_manual_ticket_generation_prompt_builds_ticket_and_saves_history(self):
        self.chat_webhook._is_valid_token = lambda event: True
        self.chat_webhook._is_gmail_app_message = lambda event: False
        captured: list[str] = []
        saved: list[str] = []

        def _fake_run(prompt, user_id):
            captured.append(prompt)
            return "【起票用（コピペ）】\n大分類: 017.脆弱性対応（情シス専用）\n\n【判断理由】\n- test"

        self.chat_webhook._run_agent_query = _fake_run
        self.chat_webhook._save_ticket_record_to_history = lambda event, response_text, source="": saved.append(source)
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "text": "<users/999> CVE-2026-1234 の通知本文です。\nhttps://sid.softek.jp/filter/sinfo/62989\nこの内容で起票用を作成して",
                "thread": {"name": "spaces/AAA/threads/BBB"},
            },
        }
        raw_body, status, _headers = self.chat_webhook.handle_chat_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        self.assertEqual(len(captured), 1)
        self.assertIn("【希望納期】", captured[0])
        self.assertEqual(saved, ["chat_webhook_manual"])
        body = json.loads(raw_body)
        self.assertIn("【起票用（コピペ）】", body["text"])

    def test_manual_ticket_generation_prompt_returns_guidance_when_source_missing(self):
        self.chat_webhook._is_valid_token = lambda event: True
        self.chat_webhook._is_gmail_app_message = lambda event: False
        self.chat_webhook._fetch_quoted_message_text = lambda event: ""
        self.chat_webhook._run_agent_query = lambda prompt, user_id: (_ for _ in ()).throw(
            AssertionError("Agent should not be called when source body is missing")
        )
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "text": "<users/999> この内容で起票用を作成して",
                "thread": {"name": "spaces/AAA/threads/BBB"},
            },
        }
        raw_body, status, _headers = self.chat_webhook.handle_chat_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertIn("初回取り込みが未完了", body["text"])

    def test_manual_ticket_generation_prompt_returns_guidance_for_low_quality_output(self):
        self.chat_webhook._is_valid_token = lambda event: True
        self.chat_webhook._is_gmail_app_message = lambda event: False
        self.chat_webhook._save_ticket_record_to_history = lambda event, response_text, source="": None
        self.chat_webhook._run_agent_query = lambda prompt, user_id: "はい、承知いたしました。テンプレートを作成します。"
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "text": "<users/999> CVE-2026-1234\nhttps://sid.softek.jp/filter/sinfo/62989\nこの内容で起票用を作成して",
                "thread": {"name": "spaces/AAA/threads/BBB"},
            },
        }
        raw_body, status, _headers = self.chat_webhook.handle_chat_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertIn("この内容で起票用を作成して", body["text"])

    def test_correction_prompt_auto_resolves_incident_id_from_thread(self):
        self.chat_webhook._is_valid_token = lambda event: True
        self.chat_webhook._fetch_thread_root_message_text = lambda event: (
            "【管理ID】\nincident_id: 123e4567-e89b-12d3-a456-426614174000\n"
        )
        captured: list[str] = []

        def _fake_run(prompt, user_id):
            captured.append(prompt)
            return "修正保存しました"

        self.chat_webhook._run_agent_query = _fake_run
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "text": "<users/999> 詳細を 002.IT基盤チーム に変更して",
                "thread": {"name": "spaces/AAA/threads/BBB"},
            },
        }
        raw_body, status, _headers = self.chat_webhook.handle_chat_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        self.assertEqual(len(captured), 1)
        self.assertIn("save_ticket_review_result", captured[0])
        self.assertIn("incident_id: 123e4567-e89b-12d3-a456-426614174000", captured[0])
        body = json.loads(raw_body)
        self.assertEqual(body["text"], "修正保存しました")

    def test_format_ticket_like_response_converts_table_style_output(self):
        raw = (
            "### 起票用項目案\n"
            "|項目|内容|\n"
            "|:--|:--|\n"
            "|大分類|017.脆弱性対応（情シス専用）|\n"
        )
        formatted = self.chat_webhook._format_ticket_like_response(raw)
        self.assertIn("【起票用（コピペ）】", formatted)
        self.assertIn("【判断理由】", formatted)

    def test_correction_prompt_without_incident_id_returns_guidance(self):
        self.chat_webhook._is_valid_token = lambda event: True
        self.chat_webhook._fetch_thread_root_message_text = lambda event: ""
        self.chat_webhook._run_agent_query = lambda prompt, user_id: (_ for _ in ()).throw(
            AssertionError("Agent should not be called when incident_id is missing")
        )
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "text": "<users/999> 詳細を 002.IT基盤チーム に変更して",
                "thread": {"name": "spaces/AAA/threads/BBB"},
            },
        }
        raw_body, status, _headers = self.chat_webhook.handle_chat_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertIn("incident_id を特定できませんでした", body["text"])

    def test_handle_chat_event_rejects_invalid_token(self):
        self.chat_webhook._is_valid_token = lambda event: False
        payload = {"type": "MESSAGE", "message": {"text": "test"}}
        _raw_body, status, _headers = self.chat_webhook.handle_chat_event(_FakeRequest(payload))
        self.assertEqual(status, 403)

    def test_model_routing_prefers_flash_for_simple_request(self):
        os.environ["AGENT_RESOURCE_NAME_FLASH"] = "flash-agent"
        os.environ["AGENT_RESOURCE_NAME_PRO"] = "pro-agent"
        selected, route = self.chat_webhook._resolve_agent_resource_name("CVE-2026-1234 の影響は？")
        self.assertEqual(selected, "flash-agent")
        self.assertEqual(route["tier"], "flash")

    def test_model_routing_prefers_pro_for_complex_request(self):
        os.environ["AGENT_RESOURCE_NAME_FLASH"] = "flash-agent"
        os.environ["AGENT_RESOURCE_NAME_PRO"] = "pro-agent"
        prompt = (
            "CVE-2026-1111 と CVE-2026-2222 を比較し、影響範囲と対策の優先順位を整理して、"
            "段階的な実装計画を表形式で示してください。"
        )
        selected, route = self.chat_webhook._resolve_agent_resource_name(prompt)
        self.assertEqual(selected, "pro-agent")
        self.assertEqual(route["tier"], "pro")


if __name__ == "__main__":
    unittest.main()
