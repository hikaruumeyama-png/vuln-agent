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
    def __init__(self, payload, headers=None):
        self._payload = payload
        self.headers = headers or {}

    def get_json(self, silent=True):
        _ = silent
        return self._payload


class ChatWebhookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _stub_dependencies()
        cls.chat_webhook = _load_module("chat_webhook_test_module", CHAT_WEBHOOK_PATH)
        cls._orig_process_message_event = cls.chat_webhook._process_message_event
        cls._orig_send_message_to_thread = cls.chat_webhook._send_message_to_thread
        cls._orig_run_agent_query = cls.chat_webhook._run_agent_query
        cls._orig_run_ai_intent_planner = getattr(cls.chat_webhook, "_run_ai_intent_planner", None)
        cls._orig_fetch_latest_ticket_record_from_history = cls.chat_webhook._fetch_latest_ticket_record_from_history
        cls._orig_fetch_thread_root_message_text = cls.chat_webhook._fetch_thread_root_message_text
        cls._orig_fetch_quoted_message_text = cls.chat_webhook._fetch_quoted_message_text
        cls._orig_is_gmail_app_message = cls.chat_webhook._is_gmail_app_message
        cls._orig_save_ticket_record_to_history = cls.chat_webhook._save_ticket_record_to_history

    def setUp(self):
        if hasattr(self.chat_webhook, "_RECENT_TURNS"):
            self.chat_webhook._RECENT_TURNS.clear()
        if hasattr(self.chat_webhook, "_THREAD_ROOT_CACHE"):
            self.chat_webhook._THREAD_ROOT_CACHE.clear()
        if hasattr(self.chat_webhook, "_ASYNC_EVENT_SEEN"):
            self.chat_webhook._ASYNC_EVENT_SEEN.clear()
        for key in ("AGENT_RESOURCE_NAME", "AGENT_RESOURCE_NAME_FLASH", "AGENT_RESOURCE_NAME_PRO"):
            os.environ.pop(key, None)
        os.environ["CHAT_ASYNC_RESPONSE_ENABLED"] = "false"
        self.chat_webhook._process_message_event = type(self)._orig_process_message_event
        self.chat_webhook._send_message_to_thread = type(self)._orig_send_message_to_thread
        self.chat_webhook._run_agent_query = type(self)._orig_run_agent_query
        self.chat_webhook._fetch_latest_ticket_record_from_history = type(self)._orig_fetch_latest_ticket_record_from_history
        self.chat_webhook._fetch_thread_root_message_text = type(self)._orig_fetch_thread_root_message_text
        self.chat_webhook._fetch_quoted_message_text = type(self)._orig_fetch_quoted_message_text
        self.chat_webhook._is_gmail_app_message = type(self)._orig_is_gmail_app_message
        self.chat_webhook._save_ticket_record_to_history = type(self)._orig_save_ticket_record_to_history
        if hasattr(self.chat_webhook, "_run_ai_intent_planner"):
            self.chat_webhook._run_ai_intent_planner = lambda **kwargs: {
                "intent": "general_analysis",
                "needs_ticket_format": False,
                "prefer_thread_root": False,
                "prefer_history": False,
                "reason": "test_default",
                "confidence": "high",
            }

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
        self.chat_webhook._run_ai_intent_planner = lambda **kwargs: {
            "intent": "clarification",
            "needs_ticket_format": False,
            "prefer_thread_root": False,
            "prefer_history": False,
            "reason": "ambiguous",
            "confidence": "high",
        }
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
        self.chat_webhook._run_ai_intent_planner = lambda **kwargs: {
            "intent": "ticket_generate",
            "needs_ticket_format": True,
            "prefer_thread_root": True,
            "prefer_history": False,
            "reason": "gmail",
            "confidence": "high",
        }
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
        self.assertGreaterEqual(len(captured), 1)
        self.assertIn("仮説JSON", captured[0])
        self.assertIn("CVE-2026-20700", captured[0])
        body = json.loads(raw_body)
        self.assertIn("【起票用（コピペ）】", body["text"])
        self.assertIn("【判断理由】", body["text"])

    def test_gmail_post_with_low_quality_output_returns_guidance(self):
        self.chat_webhook._is_valid_token = lambda event: True
        self.chat_webhook._run_agent_query = lambda prompt, user_id: "はい、承知いたしました。テンプレートを作成します。"
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "sender": {"displayName": "Notifier", "type": "BOT", "name": "users/abc"},
                "text": (
                    "To view the full email in Google Groups, including links and attachments, select View message."
                ),
                "thread": {"name": "spaces/AAA/threads/BBB"},
            },
        }
        raw_body, status, _headers = self.chat_webhook.handle_chat_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertIn("根拠情報が不足", body["text"])

    def test_analysis_trigger_uses_thread_root_message(self):
        self.chat_webhook._is_valid_token = lambda event: True
        self.chat_webhook._fetch_thread_root_message_text = lambda event: (
            "From: sidfm-notification@rakus.co.jp\nCVE-2026-30001\nView message"
        )
        self.chat_webhook._run_ai_intent_planner = lambda **kwargs: {
            "intent": "ticket_generate",
            "needs_ticket_format": True,
            "prefer_thread_root": True,
            "prefer_history": False,
            "reason": "thread_root_digest",
            "confidence": "high",
        }
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
        self.assertGreaterEqual(len(captured), 1)
        self.assertIn("仮説JSON", captured[0])
        self.assertIn("sidfm-notification@rakus.co.jp", captured[0])
        body = json.loads(raw_body)
        self.assertIn("【起票用（コピペ）】", body["text"])
        self.assertIn("【判断理由】", body["text"])

    def test_analysis_trigger_without_thread_source_uses_thread_followup_prompt(self):
        self.chat_webhook._is_valid_token = lambda event: True
        self.chat_webhook._fetch_thread_root_message_text = lambda event: ""
        self.chat_webhook._fetch_latest_ticket_record_from_history = lambda event: {}
        self.chat_webhook._run_ai_intent_planner = lambda **kwargs: {
            "intent": "ticket_generate",
            "needs_ticket_format": True,
            "prefer_thread_root": True,
            "prefer_history": True,
            "reason": "need_backfill",
            "confidence": "high",
        }
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
        self.chat_webhook._run_ai_intent_planner = lambda **kwargs: {
            "intent": "ticket_generate",
            "needs_ticket_format": True,
            "prefer_thread_root": False,
            "prefer_history": True,
            "reason": "history_fallback",
            "confidence": "high",
        }
        self.chat_webhook._run_agent_query = lambda prompt, user_id: "invalid-json"
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
        self.assertIn("【判断理由】", body["text"])

    def test_manual_ticket_generation_prompt_builds_ticket_and_saves_history(self):
        self.chat_webhook._is_valid_token = lambda event: True
        self.chat_webhook._is_gmail_app_message = lambda event: False
        self.chat_webhook._run_ai_intent_planner = lambda **kwargs: {
            "intent": "ticket_generate",
            "needs_ticket_format": True,
            "prefer_thread_root": True,
            "prefer_history": True,
            "reason": "manual_ticket",
            "confidence": "high",
        }
        captured: list[str] = []
        saved: list[str] = []

        def _fake_run(prompt, user_id):
            captured.append(prompt)
            return (
                "【起票用（コピペ）】\n"
                "大分類: 017.脆弱性対応（情シス専用）\n"
                "小分類: 002.IT基盤チーム\n"
                "依頼概要: AlmaLinux の脆弱性確認及び該当バージョンの対応願い\n"
                "詳細: 002.IT基盤チーム\n\n"
                "【判断理由】\n"
                "- CVEとURLを検知"
            )

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
        self.assertGreaterEqual(len(captured), 1)
        self.assertIn("仮説JSON", captured[0])
        self.assertEqual(saved, ["chat_webhook_manual"])
        body = json.loads(raw_body)
        self.assertIn("【起票用（コピペ）】", body["text"])

    def test_manual_ticket_generation_prompt_returns_guidance_when_source_missing(self):
        self.chat_webhook._is_valid_token = lambda event: True
        self.chat_webhook._is_gmail_app_message = lambda event: False
        self.chat_webhook._fetch_quoted_message_text = lambda event: ""
        self.chat_webhook._run_ai_intent_planner = lambda **kwargs: {
            "intent": "ticket_generate",
            "needs_ticket_format": True,
            "prefer_thread_root": True,
            "prefer_history": False,
            "reason": "manual_missing_source",
            "confidence": "high",
        }
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
        self.chat_webhook._run_ai_intent_planner = lambda **kwargs: {
            "intent": "ticket_generate",
            "needs_ticket_format": True,
            "prefer_thread_root": True,
            "prefer_history": True,
            "reason": "manual_ticket",
            "confidence": "high",
        }
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
        self.assertIn("【起票用（コピペ）】", body["text"])

    def test_correction_prompt_auto_resolves_incident_id_from_thread(self):
        self.chat_webhook._is_valid_token = lambda event: True
        self.chat_webhook._fetch_thread_root_message_text = lambda event: (
            "【管理ID】\nincident_id: 123e4567-e89b-12d3-a456-426614174000\n"
        )
        self.chat_webhook._run_ai_intent_planner = lambda **kwargs: {
            "intent": "ticket_revise",
            "needs_ticket_format": True,
            "prefer_thread_root": True,
            "prefer_history": True,
            "reason": "revise",
            "confidence": "high",
        }
        self.chat_webhook._fetch_latest_ticket_record_from_history = lambda event: {
            "incident_id": "123e4567-e89b-12d3-a456-426614174000",
            "copy_paste_text": (
                "【起票用（コピペ）】\n"
                "大分類: 017.脆弱性対応（情シス専用）\n"
                "小分類: 002.IT基盤チーム\n"
                "依頼概要: AlmaLinux の脆弱性確認及び該当バージョンの対応願い\n"
                "詳細:\n"
                "【脆弱性情報】\nhttps://sid.softek.jp/filter/sinfo/62989\n"
                "【CVSSスコア】\n8.8"
            ),
            "reasoning_text": "【判断理由】\n- 履歴再利用",
        }
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
        self.assertGreaterEqual(len(captured), 1)
        body = json.loads(raw_body)
        self.assertIn("【起票用（コピペ）】", body["text"])

    def test_polite_correction_prompt_auto_resolves_incident_id(self):
        self.chat_webhook._is_valid_token = lambda event: True
        self.chat_webhook._fetch_thread_root_message_text = lambda event: (
            "【管理ID】\nincident_id: 123e4567-e89b-12d3-a456-426614174000\n"
        )
        self.chat_webhook._run_ai_intent_planner = lambda **kwargs: {
            "intent": "ticket_revise",
            "needs_ticket_format": True,
            "prefer_thread_root": True,
            "prefer_history": True,
            "reason": "revise",
            "confidence": "high",
        }
        self.chat_webhook._fetch_latest_ticket_record_from_history = lambda event: {
            "incident_id": "123e4567-e89b-12d3-a456-426614174000",
            "copy_paste_text": (
                "【起票用（コピペ）】\n"
                "大分類: 017.脆弱性対応（情シス専用）\n"
                "小分類: 002.IT基盤チーム\n"
                "依頼概要: AlmaLinux の脆弱性確認及び該当バージョンの対応願い\n"
                "詳細:\n"
                "【脆弱性情報】\nhttps://sid.softek.jp/filter/sinfo/62989\n"
                "【CVSSスコア】\n8.8"
            ),
            "reasoning_text": "【判断理由】\n- 履歴再利用",
        }
        captured: list[str] = []

        def _fake_run(prompt, user_id):
            captured.append(prompt)
            return "修正保存しました"

        self.chat_webhook._run_agent_query = _fake_run
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "text": "<users/999> 【対象の機器/アプリ】について、AlmaLinux8/9 だけ追加してもらえますか？",
                "thread": {"name": "spaces/AAA/threads/BBB"},
            },
        }
        raw_body, status, _headers = self.chat_webhook.handle_chat_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        self.assertGreaterEqual(len(captured), 1)
        body = json.loads(raw_body)
        self.assertIn("【起票用（コピペ）】", body["text"])

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

    def test_format_ticket_like_response_rejects_internal_artifact_noise(self):
        raw = "gemini-2.5-pro / <ctrl42> / tool_code"
        formatted = self.chat_webhook._format_ticket_like_response(raw)
        self.assertIn("根拠情報が不足", formatted)

    def test_format_ticket_like_response_repairs_conversational_summary(self):
        raw = (
            "【起票用（コピペ）】\n"
            "大分類: 017.脆弱性対応（情シス専用）\n"
            "小分類: 002.IT基盤チーム\n"
            "依頼概要: はい、承知いたしました。 / ご依頼のメール内容は脆弱性関連の通知と判断しました。\n"
            "詳細: 要確認\n\n"
            "【判断理由】\n"
            "- スレッド文脈が不足していたため、不足項目を「要確認」で補完\n"
        )
        source = "AlmaLinux9\nhttps://sid.softek.jp/filter/sinfo/62989\nCVSS 8.8"
        formatted = self.chat_webhook._format_ticket_like_response(raw, source)
        self.assertIn("依頼概要: AlmaLinux の脆弱性確認及び該当バージョンの対応願い", formatted)
        self.assertNotIn("承知いたしました", formatted)
        self.assertIn("【対象の機器/アプリ】", formatted)
        self.assertIn("https://sid.softek.jp/filter/sinfo/62989", formatted)
        self.assertIn("【判断理由】", formatted)
        self.assertIn("通知本文から対象製品を抽出", formatted)

    def test_build_ticket_text_from_sidfm_sample_filters_alma10_and_formats_detail(self):
        self.chat_webhook._get_sbom_almalinux_versions = lambda: {"8", "9"}
        source = (
            "[SIDfm] AWSサーバー_001 (2025/12/24)\n"
            "No ID    CVSS TITLE\n"
            "1 61832  8.8 AlmaLinux 9 の webkit2gtk3 に任意のコード実行など複数の問題\n"
            "2 61814  8.8 AlmaLinux 8 の webkit2gtk3 に任意のコードを実行されるなど複数の問題\n"
            "3 61841  8.2 AlmaLinux 10 の keylime にセキュリティコントロールを迂回される問題\n"
            "4 61851  8.1 AlmaLinux 10 の git-lfs に任意のファイルを上書きされる問題\n"
            "5 61836  8.1 AlmaLinux 9 の git-lfs に任意のファイルを上書きされる問題\n"
            "6 61816  8.1 AlmaLinux 8 の git-lfs に任意のファイルを上書きされる問題\n"
            "https://sid.softek.jp/filter/sinfo/61832\n"
            "https://sid.softek.jp/filter/sinfo/61814\n"
            "https://sid.softek.jp/filter/sinfo/61841\n"
            "https://sid.softek.jp/filter/sinfo/61851\n"
            "https://sid.softek.jp/filter/sinfo/61836\n"
            "https://sid.softek.jp/filter/sinfo/61816\n"
        )
        out = self.chat_webhook._build_ticket_text_from_source(source)
        self.assertIn("依頼概要: AlmaLinux の脆弱性確認及び該当バージョンの対応願い", out)
        self.assertIn("【対象の機器/アプリ】", out)
        self.assertIn("AlmaLinux9", out)
        self.assertIn("AlmaLinux8", out)
        self.assertNotIn("AlmaLinux10", out)
        self.assertIn("【脆弱性情報】（リンク貼り付け）", out)
        self.assertIn("https://sid.softek.jp/filter/sinfo/61832", out)
        self.assertIn("https://sid.softek.jp/filter/sinfo/61836", out)
        self.assertIn("https://sid.softek.jp/filter/sinfo/61814", out)
        self.assertIn("https://sid.softek.jp/filter/sinfo/61816", out)
        self.assertNotIn("https://sid.softek.jp/filter/sinfo/61841", out)
        self.assertNotIn("https://sid.softek.jp/filter/sinfo/61851", out)
        self.assertIn("【CVSSスコア】\n8.8", out)
        self.assertIn("SBOM照合で対象AlmaLinuxバージョンを適用: 8, 9", out)

    def test_build_ticket_text_from_sidfm_mixed_versions_keeps_only_sbom_versions(self):
        self.chat_webhook._get_sbom_almalinux_versions = lambda: {"8", "9"}
        source = (
            "[SIDfm] AWSサーバー_001 (2026/02/12)\n"
            "No ID    CVSS TITLE\n"
            "1 62977  9.4 AlmaLinux 10 の keylime にクライアント証明書による認証を迂回される問題\n"
            "2 62986  8.8 AlmaLinux 9 の fontforge に情報漏洩・情報改竄・サービス妨害など複数の問題\n"
            "3 62990  8.6 AlmaLinux 10 の libsoup3 に任意のコード実行など複数の問題\n"
            "4 62989  8.6 AlmaLinux 8 の libsoup に任意のコード実行など複数の問題\n"
            "https://sid.softek.jp/filter/sinfo/62977\n"
            "https://sid.softek.jp/filter/sinfo/62986\n"
            "https://sid.softek.jp/filter/sinfo/62990\n"
            "https://sid.softek.jp/filter/sinfo/62989\n"
        )
        out = self.chat_webhook._build_ticket_text_from_source(source)
        self.assertIn("AlmaLinux9", out)
        self.assertIn("AlmaLinux8", out)
        self.assertNotIn("AlmaLinux10", out)
        self.assertIn("https://sid.softek.jp/filter/sinfo/62986", out)
        self.assertIn("https://sid.softek.jp/filter/sinfo/62989", out)
        self.assertNotIn("https://sid.softek.jp/filter/sinfo/62977", out)
        self.assertNotIn("https://sid.softek.jp/filter/sinfo/62990", out)
        self.assertIn("起票対象: 2件", out)

    def test_correction_prompt_without_incident_id_returns_guidance(self):
        self.chat_webhook._is_valid_token = lambda event: True
        self.chat_webhook._fetch_thread_root_message_text = lambda event: ""
        self.chat_webhook._run_ai_intent_planner = lambda **kwargs: {
            "intent": "ticket_revise",
            "needs_ticket_format": True,
            "prefer_thread_root": True,
            "prefer_history": False,
            "reason": "revise_missing_context",
            "confidence": "high",
        }
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
        self.assertIn("初回取り込みが未完了", body["text"])

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

    def test_async_mode_sends_thinking_and_final_messages(self):
        os.environ["CHAT_ASYNC_RESPONSE_ENABLED"] = "true"
        self.chat_webhook._is_valid_token = lambda event: True
        sent: list[str] = []
        self.chat_webhook._send_message_to_thread = lambda event, text: sent.append(text)
        submitted: list[tuple[dict, str]] = []
        self.chat_webhook._submit_async_job = lambda event, user_name: submitted.append((event, user_name))
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {"text": "<users/999> 確認して", "thread": {"name": "spaces/AAA/threads/BBB"}},
        }
        raw_body, status, _headers = self.chat_webhook.handle_chat_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw_body), {})
        self.assertEqual(len(sent), 1)
        self.assertIn("思考中です", sent[0])
        self.assertEqual(len(submitted), 1)
        self.assertEqual(submitted[0][1], "111")

    def test_async_mode_skips_non_actionable_bot_messages(self):
        os.environ["CHAT_ASYNC_RESPONSE_ENABLED"] = "true"
        self.chat_webhook._is_valid_token = lambda event: True
        self.chat_webhook._ASYNC_WORKER_POOL = type("P", (), {"submit": lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("submit should not be called")
        )})()
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "sender": {"displayName": "脆弱性管理エージェント", "type": "BOT", "name": "users/app"},
                "text": "",
                "thread": {"name": "spaces/AAA/threads/BBB"},
            },
        }
        raw_body, status, _headers = self.chat_webhook.handle_chat_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw_body), {})

    def test_manual_ticket_generation_uses_thread_root_fallback_when_inline_body_missing(self):
        self.chat_webhook._is_valid_token = lambda event: True
        self.chat_webhook._is_gmail_app_message = lambda event: False
        self.chat_webhook._fetch_quoted_message_text = lambda event: ""
        self.chat_webhook._run_ai_intent_planner = lambda **kwargs: {
            "intent": "ticket_generate",
            "needs_ticket_format": True,
            "prefer_thread_root": True,
            "prefer_history": False,
            "reason": "manual_root_fallback",
            "confidence": "high",
        }
        self.chat_webhook._fetch_thread_root_message_text = (
            lambda event: "【脆弱性情報】\nCVE-2026-1234\nhttps://sid.softek.jp/filter/sinfo/62989"
        )
        self.chat_webhook._save_ticket_record_to_history = lambda event, response_text, source="": None
        captured: list[str] = []

        def _fake_run(prompt, user_id):
            captured.append(prompt)
            return (
                "【起票用（コピペ）】\n"
                "大分類: 017.脆弱性対応（情シス専用）\n"
                "小分類: 002.IT基盤チーム\n"
                "依頼概要: AlmaLinux の脆弱性確認及び該当バージョンの対応願い\n"
                "詳細: 002.IT基盤チーム\n\n"
                "【判断理由】\n"
                "- スレッド本文を参照"
            )

        self.chat_webhook._run_agent_query = _fake_run
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
        self.assertGreaterEqual(len(captured), 1)
        self.assertIn("CVE-2026-1234", captured[0])
        body = json.loads(raw_body)
        self.assertIn("【起票用（コピペ）】", body["text"])

    def test_contains_specific_vuln_signal_does_not_accept_generic_url_only(self):
        text = "To view the full email in Google Groups, select View message. https://groups.google.com/"
        self.assertFalse(self.chat_webhook._contains_specific_vuln_signal(text))

    def test_send_message_to_thread_retries_without_thread_on_invalid_thread(self):
        class _Exec:
            def __init__(self, should_fail):
                self._should_fail = should_fail

            def execute(self):
                if self._should_fail:
                    raise Exception("The request contains an invalid thread resource name")
                return {"name": "spaces/AAA/messages/1"}

        class _Messages:
            def __init__(self):
                self.calls = []

            def create(self, parent=None, body=None, messageReplyOption=None):
                self.calls.append({"parent": parent, "body": body, "messageReplyOption": messageReplyOption})
                should_fail = len(self.calls) == 1
                return _Exec(should_fail)

        class _Spaces:
            def __init__(self, messages):
                self._messages = messages

            def messages(self):
                return self._messages

        class _Service:
            def __init__(self, messages):
                self._spaces = _Spaces(messages)

            def spaces(self):
                return self._spaces

        messages = _Messages()
        self.chat_webhook._get_chat_service = lambda mode="post": _Service(messages)
        event = {
            "space": {"name": "spaces/AAA"},
            "message": {"thread": {"name": "spaces/AAA/threads/bad-thread"}},
        }
        self.chat_webhook._send_message_to_thread(event, "hello")
        self.assertEqual(len(messages.calls), 2)
        self.assertIn("thread", messages.calls[0]["body"])
        self.assertNotIn("thread", messages.calls[1]["body"])
        self.assertEqual(messages.calls[0]["messageReplyOption"], "REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD")
        self.assertIsNone(messages.calls[1]["messageReplyOption"])

    def test_strip_manual_command_lines_keeps_inline_source_text(self):
        text = "@脆弱性管理エージェント CVE-2026-1234 https://sid.softek.jp/filter/sinfo/62989 この内容で起票用を作成して"
        out = self.chat_webhook._strip_manual_command_lines(text)
        self.assertIn("CVE-2026-1234", out)
        self.assertIn("https://sid.softek.jp/filter/sinfo/62989", out)

    def test_cloud_tasks_internal_request_processes_and_posts_final_message(self):
        self.chat_webhook._is_valid_token = lambda event: (_ for _ in ()).throw(
            AssertionError("token validation should be bypassed for Cloud Tasks internal request")
        )
        sent: list[str] = []
        self.chat_webhook._process_message_event = lambda event, user_name: "FINAL_FROM_TASK"
        self.chat_webhook._send_message_to_thread = lambda event, text: sent.append(text)
        payload = {
            "_internal_async_task": True,
            "user_name": "111",
            "chat_event": {
                "type": "MESSAGE",
                "user": {"name": "users/111"},
                "message": {"text": "<users/999> 確認して", "thread": {"name": "spaces/AAA/threads/BBB"}},
            },
        }
        headers = {"X-CloudTasks-TaskName": "projects/p/locations/l/queues/q/tasks/t1"}
        raw_body, status, _headers = self.chat_webhook.handle_chat_event(_FakeRequest(payload, headers=headers))
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw_body)["status"], "ok")
        self.assertEqual(sent, ["FINAL_FROM_TASK"])

    def test_non_preferred_path_still_normalizes_ticket_template_style_output(self):
        self.chat_webhook._is_valid_token = lambda event: True
        self.chat_webhook._is_gmail_app_message = lambda event: False
        self.chat_webhook._run_agent_query = lambda prompt, user_id: (
            "ご依頼いただいたGmailの内容はSIDfmからの脆弱性通知と判断しました。\n"
            "【大分類】\n017.脆弱性対応（情シス専用）\n"
            "【小分類】\n002.IT基盤チーム\n"
            "【依頼概要】\nAlmaLinuxで検知された複数の脆弱性に関する対応依頼\n"
            "【対象の機器/アプリ】\nAlmaLinux9\n"
            "【脆弱性情報（リンク貼り付け）】\nhttps://sid.softek.jp/filter/sinfo/62989\n"
            "【CVSSスコア】\n8.6\n"
            "【依頼内容】\n対応願います。\n"
            "【対応完了目標】\n要確認"
        )
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "text": "<users/999> CVE-2026-1234 の要点を教えて",
                "thread": {"name": "spaces/AAA/threads/BBB"},
            },
        }
        raw_body, status, _headers = self.chat_webhook.handle_chat_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertIn("【起票用（コピペ）】", body["text"])
        self.assertIn("【判断理由】", body["text"])


if __name__ == "__main__":
    unittest.main()
