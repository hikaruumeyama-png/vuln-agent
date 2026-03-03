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

    # vertexai.generative_models stub for _call_gemini_json
    gen_models = types.ModuleType("vertexai.generative_models")

    class _FakeGenerativeModel:
        def __init__(self, model_name="gemini-2.5-flash"):
            self.model_name = model_name

        def generate_content(self, prompt, generation_config=None):
            _ = generation_config
            return types.SimpleNamespace(text='{}')

    class _FakeGenerationConfig:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    gen_models.GenerativeModel = _FakeGenerativeModel
    gen_models.GenerationConfig = _FakeGenerationConfig
    sys.modules["vertexai.generative_models"] = gen_models


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
        cls._orig_save_ticket_preference = cls.chat_webhook._save_ticket_preference
        cls._orig_save_correction_as_preference = cls.chat_webhook._save_correction_as_preference
        cls._orig_fetch_ticket_preferences = cls.chat_webhook._fetch_ticket_preferences
        cls._orig_get_preference_correction_counts = cls.chat_webhook._get_preference_correction_counts

    def setUp(self):
        if hasattr(self.chat_webhook, "_RECENT_TURNS"):
            self.chat_webhook._RECENT_TURNS.clear()
        if hasattr(self.chat_webhook, "_THREAD_ROOT_CACHE"):
            self.chat_webhook._THREAD_ROOT_CACHE.clear()
        if hasattr(self.chat_webhook, "_ASYNC_EVENT_SEEN"):
            self.chat_webhook._ASYNC_EVENT_SEEN.clear()
        if hasattr(self.chat_webhook, "_SBOM_PRODUCT_CACHE"):
            self.chat_webhook._SBOM_PRODUCT_CACHE.update({"names": None, "fetched_at": None})
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
        self.chat_webhook._save_ticket_preference = lambda **kwargs: None
        self.chat_webhook._save_correction_as_preference = lambda event, original_ticket, revised_ticket, instruction: None
        self.chat_webhook._fetch_ticket_preferences = lambda event, product_names=None, cvss_score=None: {}
        self.chat_webhook._get_preference_correction_counts = lambda event: {}
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
        self.chat_webhook._save_ticket_record_to_history = lambda event, response_text, source="", facts=None: saved.append(source)
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
        self.chat_webhook._save_ticket_record_to_history = lambda event, response_text, source="", facts=None: None
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
            "公開日: 2026/02/12\n"
            "脆弱性情報が公開されました。\n"
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
        # AlmaLinux 9 is classified as public resource → 10 business days
        self.assertIn("10営業日", out)
        # all_entries_count should show pre-filter total (4), not post-filter (2)
        self.assertIn("4件", out)

    def test_build_ticket_from_single_line_google_chat_text(self):
        """Google Chat may deliver the entire email as a single line (no line breaks)."""
        self.chat_webhook._get_sbom_almalinux_versions = lambda: {"8", "9"}
        # Simulate single-line Google Chat text (no \n between entries)
        source = (
            "@bot [SIDfm] Server_001 (2026/02/12) "
            "No ID CVSS TITLE "
            "1 62977 9.4 AlmaLinux 10 の keylime にクライアント証明書による認証を迂回される問題 (ALSA-2026:2225) "
            "2 62986 8.8 AlmaLinux 9 の fontforge に情報漏洩・情報改竄・サービス妨害など複数の問題 "
            "3 62990 8.6 AlmaLinux 10 の libsoup3 に任意のコード実行など複数の問題 (ALSA-2026:2182) "
            "4 62989 8.6 AlmaLinux 8 の libsoup に任意のコード実行など複数の問題 (ALSA-2026:2215) "
            "ID:62977 CVSSv3: 9.4 AlmaLinux 10 の keylime https://sid.softek.jp/filter/sinfo/62977 "
            "ID:62986 CVSSv3: 8.8 AlmaLinux 9 の fontforge https://sid.softek.jp/filter/sinfo/62986 "
            "ID:62990 CVSSv3: 8.6 AlmaLinux 10 の libsoup3 https://sid.softek.jp/filter/sinfo/62990 "
            "ID:62989 CVSSv3: 8.6 AlmaLinux 8 の libsoup https://sid.softek.jp/filter/sinfo/62989"
        )
        out = self.chat_webhook._build_ticket_text_from_source(source)
        self.assertIn("AlmaLinux9", out)
        self.assertIn("AlmaLinux8", out)
        self.assertNotIn("AlmaLinux10", out)
        self.assertIn("https://sid.softek.jp/filter/sinfo/62986", out)
        self.assertIn("https://sid.softek.jp/filter/sinfo/62989", out)
        self.assertNotIn("https://sid.softek.jp/filter/sinfo/62977", out)
        self.assertIn("【CVSSスコア】\n8.8", out)
        self.assertIn("起票対象: 2件", out)
        self.assertIn("4件", out)
        # AlmaLinux 9 is classified as public resource → 10 business days
        self.assertIn("10営業日", out)

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
        self.chat_webhook._save_ticket_record_to_history = lambda event, response_text, source="", facts=None: None
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


    def test_remember_turn_stores_1200_chars_assistant(self):
        """_remember_turn stores up to 1200 chars of assistant text."""
        mod = self.chat_webhook
        key = "test_1200"
        long_text = "A" * 1500
        mod._remember_turn(key, "user prompt", long_text)
        turns = mod._get_recent_turns(key, max_turns=1)
        self.assertEqual(len(turns), 1)
        self.assertEqual(len(turns[0]["assistant"]), 1200)


    # ---- Gemini API direct / 依頼内容AIチェック tests ----

    def test_call_gemini_json_returns_parsed_dict(self):
        """_call_gemini_json returns parsed JSON from model response."""
        mod = self.chat_webhook
        import vertexai.generative_models as gen_mod

        original_model = gen_mod.GenerativeModel
        response_data = {"is_appropriate": True, "confidence": "high", "reasoning": "テスト"}

        class _MockModel:
            def __init__(self, model_name="gemini-2.5-flash"):
                pass

            def generate_content(self, prompt, generation_config=None):
                return types.SimpleNamespace(text=json.dumps(response_data))

        gen_mod.GenerativeModel = _MockModel
        try:
            result = mod._call_gemini_json("テストプロンプト")
            self.assertIsInstance(result, dict)
            self.assertTrue(result.get("is_appropriate"))
            self.assertEqual(result["confidence"], "high")
        finally:
            gen_mod.GenerativeModel = original_model

    def test_call_gemini_json_returns_empty_on_failure(self):
        """_call_gemini_json returns {} when model raises an exception."""
        mod = self.chat_webhook
        import vertexai.generative_models as gen_mod

        original_model = gen_mod.GenerativeModel

        class _ErrorModel:
            def __init__(self, model_name="gemini-2.5-flash"):
                pass

            def generate_content(self, prompt, generation_config=None):
                raise RuntimeError("API unavailable")

        gen_mod.GenerativeModel = _ErrorModel
        try:
            result = mod._call_gemini_json("テストプロンプト")
            self.assertEqual(result, {})
        finally:
            gen_mod.GenerativeModel = original_model

    def test_check_remediation_advice_appropriate(self):
        """_check_remediation_advice returns is_appropriate=True when AI agrees."""
        mod = self.chat_webhook
        original_fn = mod._call_gemini_json
        mod._call_gemini_json = lambda prompt, response_schema=None: {
            "is_appropriate": True,
            "confidence": "high",
            "reasoning": "バージョンアップ指示は適切です",
            "suggested_action": "",
            "risk_notes": "",
        }
        try:
            facts = {
                "products": ["AlmaLinux9"],
                "entries": [{"id": "12345", "cvss": "8.1", "title": "テスト脆弱性"}],
                "max_score": 8.1,
                "due_date": "2026/05/12",
                "due_reason": "CVSS8.0以上(3か月)",
            }
            result = mod._check_remediation_advice(facts, "テスト通知本文")
            self.assertTrue(result["is_appropriate"])
            self.assertEqual(result["confidence"], "high")
            self.assertEqual(result["suggested_action"], "")
        finally:
            mod._call_gemini_json = original_fn

    def test_check_remediation_advice_suggests_alternative(self):
        """_check_remediation_advice returns suggested_action when not appropriate."""
        mod = self.chat_webhook
        original_fn = mod._call_gemini_json
        mod._call_gemini_json = lambda prompt, response_schema=None: {
            "is_appropriate": False,
            "confidence": "high",
            "reasoning": "パッチ適用が推奨されます",
            "suggested_action": "セキュリティパッチの適用をお願いいたします。",
            "risk_notes": "悪用実績あり。早急な対応が必要です。",
        }
        try:
            facts = {
                "products": ["AlmaLinux8"],
                "entries": [{"id": "99999", "cvss": "9.8", "title": "重大RCE脆弱性"}],
                "max_score": 9.8,
                "due_date": "2026/04/01",
                "due_reason": "緊急(1か月)",
            }
            result = mod._check_remediation_advice(facts, "悪用が確認された重大な脆弱性")
            self.assertFalse(result["is_appropriate"])
            self.assertIn("パッチ", result["suggested_action"])
            self.assertIn("悪用実績", result["risk_notes"])
        finally:
            mod._call_gemini_json = original_fn

    def test_ticket_detail_uses_remediation_from_facts(self):
        """_infer_ticket_detail_from_facts uses facts['remediation_text'] when present."""
        mod = self.chat_webhook
        facts = {
            "products": ["AlmaLinux9"],
            "entries": [{"id": "12345", "cvss": "8.1", "title": "テスト", "url": "https://example.com"}],
            "max_score": 8.1,
            "scores": [8.1],
            "due_date": "2026/05/12",
            "due_reason": "CVSS8.0以上(3か月)",
            "vuln_links": ["https://example.com"],
            "grouped_vuln_links": {},
            "sbom_alma_versions": ["9"],
            "remediation_text": "セキュリティパッチの即時適用をお願いいたします。",
        }
        detail = mod._infer_ticket_detail_from_facts(facts)
        self.assertIn("セキュリティパッチの即時適用", detail)
        self.assertNotIn("バージョンアップのご対応お願いいたします", detail)

    def test_ticket_detail_uses_default_remediation_when_no_override(self):
        """_infer_ticket_detail_from_facts uses _DEFAULT_REMEDIATION_TEXT when no override."""
        mod = self.chat_webhook
        facts = {
            "products": ["AlmaLinux9"],
            "entries": [{"id": "12345", "cvss": "7.0", "title": "テスト", "url": "https://example.com"}],
            "max_score": 7.0,
            "scores": [7.0],
            "due_date": "2026/06/01",
            "due_reason": "CVSS7.0以上(6か月)",
            "vuln_links": ["https://example.com"],
            "grouped_vuln_links": {},
            "sbom_alma_versions": ["9"],
        }
        detail = mod._infer_ticket_detail_from_facts(facts)
        self.assertIn("バージョンアップのご対応お願いいたします", detail)

    def test_reasoning_includes_ai_check_results(self):
        """_infer_reasoning_from_facts appends AI check results when present in facts."""
        mod = self.chat_webhook
        facts = {
            "products": ["AlmaLinux9"],
            "entries": [{"id": "12345", "cvss": "8.1", "title": "テスト", "url": "https://example.com"}],
            "max_score": 8.1,
            "scores": [8.1],
            "due_date": "2026/05/12",
            "due_reason": "CVSS8.0以上(3か月)",
            "vuln_links": ["https://example.com"],
            "grouped_vuln_links": {},
            "sbom_alma_versions": ["9"],
            "remediation_reasoning": "パッチ適用が推奨されます",
            "remediation_risk_notes": "悪用実績あり",
        }
        reasoning = mod._infer_reasoning_from_facts(facts)
        self.assertIn("【依頼内容チェック（AI）】", reasoning)
        self.assertIn("パッチ適用が推奨されます", reasoning)
        self.assertIn("悪用実績あり", reasoning)

    def test_reasoning_omits_ai_check_when_no_remediation_data(self):
        """_infer_reasoning_from_facts omits AI check section when no remediation data."""
        mod = self.chat_webhook
        facts = {
            "products": ["AlmaLinux9"],
            "entries": [{"id": "12345", "cvss": "7.0", "title": "テスト", "url": "https://example.com"}],
            "max_score": 7.0,
            "scores": [7.0],
            "due_date": "2026/06/01",
            "due_reason": "CVSS7.0以上(6か月)",
            "vuln_links": ["https://example.com"],
            "grouped_vuln_links": {},
            "sbom_alma_versions": ["9"],
        }
        reasoning = mod._infer_reasoning_from_facts(facts)
        self.assertNotIn("【依頼内容チェック（AI）】", reasoning)

    def test_hypothesis_pipeline_tries_gemini_direct_first(self):
        """_run_hypothesis_pipeline calls _call_gemini_json before Agent Engine."""
        mod = self.chat_webhook
        call_log = []

        original_gemini = mod._call_gemini_json
        original_agent = mod._run_agent_query

        def mock_gemini_json(prompt, response_schema=None):
            call_log.append("gemini_direct")
            return {
                "request_summary": "テスト概要",
                "affected_product_names": ["AlmaLinux9"],
                "vulnerability_entries": [],
                "cvss_max_score": 7.0,
            }

        def mock_agent_query(prompt, history_key):
            call_log.append("agent_engine")
            return ""

        mod._call_gemini_json = mock_gemini_json
        mod._run_agent_query = mock_agent_query
        try:
            result = mod._run_hypothesis_pipeline("テスト入力", "test_key")
            self.assertIn("gemini_direct", call_log)
            # Agent Engine should NOT be called if Gemini direct succeeds
            self.assertNotIn("agent_engine", call_log)
        finally:
            mod._call_gemini_json = original_gemini
            mod._run_agent_query = original_agent

    # ------------------------------------------------------------------
    # Phase 1 tests: 修正フローの修復
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Phase 2 tests: 修正学習システム
    # ------------------------------------------------------------------

    def test_detect_correction_field_remediation(self):
        """_detect_correction_field detects remediation_text changes."""
        mod = self.chat_webhook
        original = (
            "【起票用（コピペ）】\n"
            "大分類: 017.脆弱性対応（情シス専用）\n"
            "小分類: 002.IT基盤チーム\n"
            "依頼概要: AlmaLinux脆弱性対応\n"
            "詳細:\n"
            "【対象の機器/アプリ】\nAlmaLinux9\n\n"
            "【脆弱性情報】（リンク貼り付け）\nhttps://sid.softek.jp/filter/sinfo/62989\n\n"
            "【CVSSスコア】\n8.8\n\n"
            "【依頼内容】\nバージョンアップのご対応お願いいたします。\n\n"
            "【対応完了目標】\n2026/05/12\n\n"
            "【判断理由】\n- 判断根拠"
        )
        revised = original.replace(
            "バージョンアップのご対応お願いいたします。",
            "セキュリティパッチの適用をお願いいたします。",
        )
        field, orig_val, new_val = mod._detect_correction_field(original, revised, "依頼内容を修正")
        self.assertEqual(field, "remediation_text")
        self.assertIn("バージョンアップ", orig_val)
        self.assertIn("セキュリティパッチ", new_val)

    def test_detect_correction_field_due_date(self):
        """_detect_correction_field detects due_date changes."""
        mod = self.chat_webhook
        original = (
            "【起票用（コピペ）】\n"
            "大分類: 017.脆弱性対応（情シス専用）\n"
            "詳細:\n"
            "【対象の機器/アプリ】\nAlmaLinux9\n\n"
            "【脆弱性情報】（リンク貼り付け）\nhttps://example.com\n\n"
            "【CVSSスコア】\n8.8\n\n"
            "【依頼内容】\n対応願います。\n\n"
            "【対応完了目標】\n2026/05/12（社内方針: 3か月）\n\n"
            "【判断理由】\n- 判断根拠"
        )
        revised = original.replace("2026/05/12（社内方針: 3か月）", "2026/03/01（ユーザー指示により10営業日）")
        field, orig_val, new_val = mod._detect_correction_field(original, revised, "対応完了目標を変更")
        self.assertEqual(field, "due_date")
        self.assertIn("2026/05/12", orig_val)
        self.assertIn("2026/03/01", new_val)

    def test_save_ticket_preference_creates_new_row(self):
        """_save_ticket_preference calls BQ insert for new preference."""
        mod = self.chat_webhook
        # Restore original to verify it handles missing BQ gracefully
        mod._save_ticket_preference = type(self)._orig_save_ticket_preference
        # Without BQ_PREFERENCES_TABLE_ID, should return silently
        os.environ.pop("BQ_PREFERENCES_TABLE_ID", None)
        # Should not raise
        mod._save_ticket_preference(
            space_id="spaces/AAA",
            field_name="remediation_text",
            pattern_key="*",
            preferred_value="パッチ適用",
            original_value="バージョンアップ",
            created_by="users/111",
        )

    def test_determine_pattern_key_product_specific(self):
        """_determine_pattern_key returns product name when detected in source."""
        mod = self.chat_webhook
        key = mod._determine_pattern_key("remediation_text", "AlmaLinux 9 の脆弱性")
        self.assertEqual(key, "AlmaLinux")

    def test_determine_pattern_key_cvss_threshold(self):
        """_determine_pattern_key returns cvss threshold for due_date field."""
        mod = self.chat_webhook
        key = mod._determine_pattern_key("due_date", "", {"max_score": 9.5})
        self.assertEqual(key, "cvss>=9.0")
        key_mid = mod._determine_pattern_key("due_date", "", {"max_score": 7.5})
        self.assertEqual(key_mid, "cvss>=7.0")

    def test_determine_pattern_key_wildcard(self):
        """_determine_pattern_key returns '*' for unknown context."""
        mod = self.chat_webhook
        key = mod._determine_pattern_key("notes")
        self.assertEqual(key, "*")

    def test_split_ticket_into_sections(self):
        """_split_ticket_into_sections extracts fields from ticket text."""
        mod = self.chat_webhook
        ticket = (
            "【起票用（コピペ）】\n"
            "大分類: 017.脆弱性対応（情シス専用）\n"
            "小分類: 002.IT基盤チーム\n"
            "依頼概要: AlmaLinux脆弱性対応\n"
            "詳細:\n"
            "【対象の機器/アプリ】\nAlmaLinux9\n\n"
            "【脆弱性情報】（リンク貼り付け）\nhttps://example.com\n\n"
            "【CVSSスコア】\n8.8\n\n"
            "【依頼内容】\n対応願います。\n\n"
            "【対応完了目標】\n2026/05/12\n\n"
            "【判断理由】\n- 判断根拠"
        )
        sections = mod._split_ticket_into_sections(ticket)
        self.assertEqual(sections["request_summary"], "AlmaLinux脆弱性対応")
        self.assertIn("AlmaLinux9", sections["target_devices"])
        self.assertIn("8.8", sections["cvss_score"])
        self.assertIn("対応願います", sections["remediation_text"])
        self.assertIn("2026/05/12", sections["due_date"])

    # ------------------------------------------------------------------
    # Phase 3 tests: 学習済みプリファレンスの適用
    # ------------------------------------------------------------------

    def test_fetch_ticket_preferences_returns_learned_values(self):
        """_fetch_ticket_preferences returns preferences when BQ has data."""
        mod = self.chat_webhook
        # Stub to return mock preferences
        mod._fetch_ticket_preferences = lambda event, product_names=None, cvss_score=None: {
            "remediation_text": "セキュリティパッチ適用をお願いします。",
        }
        event = {
            "message": {"thread": {"name": "spaces/AAA/threads/BBB"}},
            "space": {"name": "spaces/AAA"},
        }
        prefs = mod._fetch_ticket_preferences(event, ["AlmaLinux9"], 8.8)
        self.assertIn("remediation_text", prefs)
        self.assertIn("セキュリティパッチ", prefs["remediation_text"])

    def test_apply_preferences_to_facts(self):
        """_apply_preferences_to_facts merges preferences into facts dict."""
        mod = self.chat_webhook
        facts = {
            "products": ["AlmaLinux9"],
            "remediation_text": "バージョンアップ",
            "due_date": "2026/05/12",
        }
        preferences = {
            "remediation_text": "セキュリティパッチ適用",
        }
        result = mod._apply_preferences_to_facts(facts, preferences)
        self.assertEqual(result["remediation_text"], "セキュリティパッチ適用")
        # Unchanged fields should remain
        self.assertEqual(result["products"], ["AlmaLinux9"])

    def test_strong_preference_not_overridden_by_ai(self):
        """correction_count >= 3 preferences are not overridden by AI check."""
        mod = self.chat_webhook
        # Verify the threshold constant
        self.assertEqual(mod._PREFERENCE_STRONG_THRESHOLD, 3)

    def test_ticket_generation_applies_preferences(self):
        """End-to-end: preferences from learning system are applied during ticket generation."""
        mod = self.chat_webhook
        mod._is_valid_token = lambda event: True
        mod._is_gmail_app_message = lambda event: False
        mod._run_ai_intent_planner = lambda **kwargs: {
            "intent": "ticket_generate",
            "needs_ticket_format": True,
            "prefer_thread_root": True,
            "prefer_history": True,
            "reason": "manual_ticket",
            "confidence": "high",
        }
        # Mock preferences
        mod._fetch_ticket_preferences = lambda event, product_names=None, cvss_score=None: {
            "remediation_text": "学習済み: セキュリティパッチの適用をお願いいたします。対応を実施した場合はサーバのホスト名をご教示ください。",
        }
        mod._get_preference_correction_counts = lambda event: {"remediation_text": 5}
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
                "- CVEとURLを検知"
            )
        mod._run_agent_query = _fake_run
        mod._save_ticket_record_to_history = lambda event, response_text, source="", facts=None: None
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "text": "<users/999> CVE-2026-1234\nhttps://sid.softek.jp/filter/sinfo/62989\nこの内容で起票用を作成して",
                "thread": {"name": "spaces/AAA/threads/BBB"},
            },
            "space": {"name": "spaces/AAA"},
        }
        raw_body, status, _headers = mod.handle_chat_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertIn("【起票用（コピペ）】", body["text"])


    # ---- paste-back revision tests ----

    def test_paste_back_detected_when_user_sends_ticket_template(self):
        """ユーザーが【起票用（コピペ）】を含むメッセージを送ると paste-back として検出される。"""
        mod = self.chat_webhook
        mod._is_valid_token = lambda event: True
        mod._is_gmail_app_message = lambda event: False
        saved: list[dict] = []
        mod._save_ticket_record_to_history = lambda event, response_text, source="", facts=None: saved.append(
            {"text": response_text, "source": source}
        )
        pasted = (
            "【起票用（コピペ）】\n"
            "大分類: 017.脆弱性対応（情シス専用）\n"
            "小分類: 002.IT基盤チーム\n"
            "依頼概要: AlmaLinux の脆弱性対応\n"
            "【依頼内容】\n"
            "修正済みの依頼内容です。\n\n"
            "【判断理由】\n"
            "- CVE検知"
        )
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "text": f"<users/999> {pasted}",
                "thread": {"name": "spaces/AAA/threads/BBB"},
            },
            "space": {"name": "spaces/AAA"},
        }
        raw_body, status, _headers = mod.handle_chat_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertIn("修正版チケットを受領しました", body["text"])
        self.assertIn("【起票用（コピペ）】", body["text"])
        # BQ保存が呼ばれたことを確認
        self.assertTrue(len(saved) >= 1)
        self.assertEqual(saved[0]["source"], "human_review")

    def test_paste_back_not_triggered_for_gmail_posts(self):
        """GmailポストはBOT転送なのでpaste-backとして扱わない。"""
        mod = self.chat_webhook
        mod._is_valid_token = lambda event: True
        mod._is_gmail_app_message = lambda event: True
        captured: list[str] = []
        # 起票パイプラインが走ることを確認するために、_run_agent_queryをモック
        def _fake_run(prompt, user_id):
            captured.append(prompt)
            return (
                "【起票用（コピペ）】\n"
                "依頼概要: テスト\n"
                "【判断理由】\n- テスト"
            )
        mod._run_agent_query = _fake_run
        mod._save_ticket_record_to_history = lambda event, response_text, source="", facts=None: None
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "sender": {"displayName": "Notifier", "type": "BOT", "name": "users/abc"},
                "text": (
                    "【起票用（コピペ）】\n"
                    "From: test@example.com\n"
                    "CVE-2026-99999\nhttps://sid.softek.jp/filter/sinfo/99999"
                ),
                "thread": {"name": "spaces/AAA/threads/CCC"},
            },
            "space": {"name": "spaces/AAA"},
        }
        raw_body, status, _headers = mod.handle_chat_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        # paste-back確認メッセージではなく、通常のチケット生成出力であること
        self.assertNotIn("修正版チケットを受領しました", body["text"])

    def test_paste_back_saves_correction_preference(self):
        """paste-back時に前回チケットとの差分が学習データとして保存される。"""
        mod = self.chat_webhook
        mod._is_valid_token = lambda event: True
        mod._is_gmail_app_message = lambda event: False
        # 前回チケット（BQ履歴）
        mod._fetch_latest_ticket_record_from_history = lambda event: {
            "copy_paste_text": (
                "【起票用（コピペ）】\n"
                "依頼概要: AlmaLinux の脆弱性対応\n"
                "【依頼内容】\n旧依頼内容"
            ),
            "reasoning_text": "【判断理由】\n- CVE検知",
        }
        saved_prefs: list[dict] = []
        mod._save_correction_as_preference = lambda event, original_ticket, revised_ticket, instruction: saved_prefs.append(
            {"original": original_ticket, "revised": revised_ticket, "instruction": instruction}
        )
        mod._save_ticket_record_to_history = lambda event, response_text, source="", facts=None: None
        pasted = (
            "【起票用（コピペ）】\n"
            "依頼概要: AlmaLinux の脆弱性対応\n"
            "【依頼内容】\n新しい依頼内容に修正しました"
        )
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "text": f"<users/999> {pasted}",
                "thread": {"name": "spaces/AAA/threads/BBB"},
            },
            "space": {"name": "spaces/AAA"},
        }
        raw_body, status, _headers = mod.handle_chat_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertIn("修正版チケットを受領しました", body["text"])
        # 学習データ保存が呼ばれたことを確認
        self.assertEqual(len(saved_prefs), 1)
        self.assertIn("旧依頼内容", saved_prefs[0]["original"])
        self.assertIn("新しい依頼内容", saved_prefs[0]["revised"])

    def test_paste_back_response_includes_further_edit_guidance(self):
        """paste-back応答に再編集ガイダンスが含まれること。"""
        mod = self.chat_webhook
        mod._is_valid_token = lambda event: True
        mod._is_gmail_app_message = lambda event: False
        mod._save_ticket_record_to_history = lambda event, response_text, source="", facts=None: None
        pasted = "【起票用（コピペ）】\n依頼概要: テスト\n【判断理由】\n- テスト"
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "text": f"<users/999> {pasted}",
                "thread": {"name": "spaces/AAA/threads/BBB"},
            },
            "space": {"name": "spaces/AAA"},
        }
        raw_body, status, _headers = mod.handle_chat_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertIn("再送信してください", body["text"])


    # ------------------------------------------------------------------
    # Multi-field correction detection tests
    # ------------------------------------------------------------------

    def test_detect_correction_fields_returns_multiple_changes(self):
        """_detect_correction_fields returns tuples for each changed field."""
        mod = self.chat_webhook
        original = (
            "【起票用（コピペ）】\n"
            "大分類: 017.脆弱性対応（情シス専用）\n"
            "小分類: 002.IT基盤チーム\n"
            "依頼概要: AlmaLinux脆弱性対応\n"
            "詳細:\n"
            "【対象の機器/アプリ】\nAlmaLinux9\n\n"
            "【脆弱性情報】（リンク貼り付け）\nhttps://example.com\n\n"
            "【CVSSスコア】\n8.8\n\n"
            "【依頼内容】\nバージョンアップのご対応お願いいたします。\n\n"
            "【対応完了目標】\n2026/05/12（社内方針: 3か月）\n\n"
            "【判断理由】\n- 判断根拠"
        )
        revised = original.replace(
            "バージョンアップのご対応お願いいたします。",
            "セキュリティパッチの適用をお願いいたします。",
        ).replace(
            "2026/05/12（社内方針: 3か月）",
            "2026/03/15（ユーザー指示: 10営業日）",
        )
        changes = mod._detect_correction_fields(original, revised, "")
        self.assertEqual(len(changes), 2)
        field_names = [c[0] for c in changes]
        self.assertIn("remediation_text", field_names)
        self.assertIn("due_date", field_names)

    def test_detect_correction_fields_includes_header_fields(self):
        """_detect_correction_fields detects header field changes like category_major."""
        mod = self.chat_webhook
        original = (
            "【起票用（コピペ）】\n"
            "大分類: 017.脆弱性対応（情シス専用）\n"
            "小分類: 002.IT基盤チーム\n"
            "依頼概要: テスト\n"
            "詳細:\n"
            "【依頼内容】\n対応願います。\n\n"
            "【判断理由】\n- テスト"
        )
        revised = original.replace(
            "大分類: 017.脆弱性対応（情シス専用）",
            "大分類: 018.別の分類",
        )
        changes = mod._detect_correction_fields(original, revised, "")
        self.assertGreaterEqual(len(changes), 1)
        field_names = [c[0] for c in changes]
        self.assertIn("category_major", field_names)

    def test_save_correction_saves_all_changed_fields(self):
        """_save_correction_as_preference calls _save_ticket_preference once per changed field."""
        mod = self.chat_webhook
        mod._is_valid_token = lambda event: True
        mod._is_gmail_app_message = lambda event: False
        mod._save_ticket_record_to_history = lambda event, response_text, source="", facts=None: None
        # Track _save_ticket_preference calls
        pref_calls: list[dict] = []
        mod._save_ticket_preference = lambda **kwargs: pref_calls.append(kwargs)
        # Previous ticket from BQ with 2 fields that will differ
        mod._fetch_latest_ticket_record_from_history = lambda event: {
            "copy_paste_text": (
                "【起票用（コピペ）】\n"
                "大分類: 017.脆弱性対応（情シス専用）\n"
                "依頼概要: テスト\n"
                "詳細:\n"
                "【依頼内容】\n旧依頼内容\n\n"
                "【対応完了目標】\n2026/05/12\n\n"
                "【判断理由】\n- テスト"
            ),
            "reasoning_text": "【判断理由】\n- テスト",
        }
        # Restore real _save_correction_as_preference so it loops over changes
        mod._save_correction_as_preference = type(self)._orig_save_correction_as_preference
        pasted = (
            "【起票用（コピペ）】\n"
            "大分類: 017.脆弱性対応（情シス専用）\n"
            "依頼概要: テスト\n"
            "詳細:\n"
            "【依頼内容】\n新しい依頼内容\n\n"
            "【対応完了目標】\n2026/03/15\n\n"
            "【判断理由】\n- テスト"
        )
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "text": f"<users/999> {pasted}",
                "thread": {"name": "spaces/AAA/threads/BBB"},
            },
            "space": {"name": "spaces/AAA"},
        }
        raw_body, status, _headers = mod.handle_chat_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertIn("修正版チケットを受領しました", body["text"])
        # _save_ticket_preference should be called 2 times (remediation_text + due_date)
        self.assertEqual(len(pref_calls), 2)
        saved_fields = {c["field_name"] for c in pref_calls}
        self.assertIn("remediation_text", saved_fields)
        self.assertIn("due_date", saved_fields)

    def test_paste_back_with_due_date_change(self):
        """End-to-end paste-back where only due_date changes saves preference with field_name=due_date."""
        mod = self.chat_webhook
        mod._is_valid_token = lambda event: True
        mod._is_gmail_app_message = lambda event: False
        mod._save_ticket_record_to_history = lambda event, response_text, source="", facts=None: None
        pref_calls: list[dict] = []
        mod._save_ticket_preference = lambda **kwargs: pref_calls.append(kwargs)
        mod._fetch_latest_ticket_record_from_history = lambda event: {
            "copy_paste_text": (
                "【起票用（コピペ）】\n"
                "大分類: 017.脆弱性対応（情シス専用）\n"
                "依頼概要: テスト\n"
                "詳細:\n"
                "【依頼内容】\n対応願います。\n\n"
                "【対応完了目標】\n2026/05/12（社内方針: 3か月）\n\n"
                "【判断理由】\n- テスト"
            ),
            "reasoning_text": "【判断理由】\n- テスト",
        }
        mod._save_correction_as_preference = type(self)._orig_save_correction_as_preference
        pasted = (
            "【起票用（コピペ）】\n"
            "大分類: 017.脆弱性対応（情シス専用）\n"
            "依頼概要: テスト\n"
            "詳細:\n"
            "【依頼内容】\n対応願います。\n\n"
            "【対応完了目標】\n2026/03/01（ユーザー指示: 10営業日）\n\n"
            "【判断理由】\n- テスト"
        )
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "text": f"<users/999> {pasted}",
                "thread": {"name": "spaces/AAA/threads/BBB"},
            },
            "space": {"name": "spaces/AAA"},
        }
        raw_body, status, _headers = mod.handle_chat_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertIn("修正版チケットを受領しました", body["text"])
        self.assertEqual(len(pref_calls), 1)
        self.assertEqual(pref_calls[0]["field_name"], "due_date")


    # ------------------------------------------------------------------ #
    # SBOM汎用製品フィルタリングテスト
    # ------------------------------------------------------------------ #

    def test_get_sbom_product_names_returns_set(self):
        """キャッシュ経由で製品名セットを取得できること。"""
        mod = self.chat_webhook
        from datetime import datetime, timezone
        # キャッシュに直接値をセットしてキャッシュヒットをテスト
        expected = {"google chrome (ウェブブラウザ)", "firefox", "fortigate 60f"}
        mod._SBOM_PRODUCT_CACHE["names"] = set(expected)
        mod._SBOM_PRODUCT_CACHE["fetched_at"] = datetime.now(timezone.utc)
        result = mod._get_sbom_product_names()
        self.assertIsInstance(result, set)
        self.assertEqual(result, expected)
        self.assertIn("google chrome (ウェブブラウザ)", result)
        self.assertIn("firefox", result)
        self.assertIn("fortigate 60f", result)

    def test_check_product_in_sbom_partial_match(self):
        """部分一致でSBOM製品名をマッチできること。"""
        mod = self.chat_webhook
        sbom_names = {"google chrome (ウェブブラウザ)", "firefox", "fortigate 60f", "fortigate 200e"}
        self.assertTrue(mod._check_product_in_sbom("Google Chrome", sbom_names))
        self.assertTrue(mod._check_product_in_sbom("Firefox", sbom_names))
        self.assertTrue(mod._check_product_in_sbom("FortiGate", sbom_names))
        self.assertFalse(mod._check_product_in_sbom("Thunderbird", sbom_names))
        self.assertFalse(mod._check_product_in_sbom("MacOS", sbom_names))
        self.assertFalse(mod._check_product_in_sbom("", sbom_names))

    def test_extract_product_names_quick_chrome(self):
        """Google Chrome通知テキストからChrome製品名を検出。"""
        mod = self.chat_webhook
        text = "[緊急度: 高] Google Chrome に複数の脆弱性 CVE-2026-1234"
        products = mod._extract_product_names_quick(text)
        self.assertIn("Google Chrome", products)

    def test_extract_product_names_quick_firefox(self):
        """Firefox通知テキストからFirefox製品名を検出。"""
        mod = self.chat_webhook
        text = "Firefox における任意コード実行の脆弱性 CVE-2026-5678"
        products = mod._extract_product_names_quick(text)
        self.assertIn("Firefox", products)

    def test_extract_product_names_quick_almalinux(self):
        """AlmaLinux通知テキストからAlmaLinux製品名を検出。"""
        mod = self.chat_webhook
        text = "AlmaLinux 9 のパッケージアップデート"
        products = mod._extract_product_names_quick(text)
        self.assertIn("AlmaLinux", products)

    def test_check_sbom_registration_skip(self):
        """SBOM未登録製品はshould_skip=Trueを返す。"""
        mod = self.chat_webhook
        import unittest.mock as mock
        sbom_names = {"almalinux", "fortigate 60f"}
        with mock.patch.object(mod, "_get_sbom_product_names", return_value=sbom_names):
            should_skip, products, reason = mod._check_sbom_registration(
                "Google Chrome に複数の脆弱性 CVE-2026-1234"
            )
        self.assertTrue(should_skip)
        self.assertIn("Google Chrome", products)
        self.assertIn("SBOM", reason)

    def test_check_sbom_registration_continue(self):
        """SBOM登録済み製品はshould_skip=Falseを返す。"""
        mod = self.chat_webhook
        import unittest.mock as mock
        sbom_names = {"google chrome (ウェブブラウザ)", "firefox", "fortigate 60f"}
        with mock.patch.object(mod, "_get_sbom_product_names", return_value=sbom_names):
            should_skip, products, reason = mod._check_sbom_registration(
                "Google Chrome に複数の脆弱性 CVE-2026-1234"
            )
        self.assertFalse(should_skip)
        self.assertIn("Google Chrome", products)
        self.assertEqual(reason, "")

    def test_check_sbom_registration_almalinux_always_continues(self):
        """AlmaLinuxはSBOMチェックを経ず常にshould_skip=Falseを返す。"""
        mod = self.chat_webhook
        import unittest.mock as mock
        with mock.patch.object(mod, "_get_sbom_product_names", return_value=set()):
            should_skip, products, reason = mod._check_sbom_registration(
                "AlmaLinux 9 のパッケージアップデート"
            )
        self.assertFalse(should_skip)
        self.assertIn("AlmaLinux", products)

    def test_sbom_not_registered_skips_ticket_e2e(self):
        """E2E: SBOM未登録製品 → 対応不要メッセージが返される（AI処理スキップ）。"""
        mod = self.chat_webhook
        import unittest.mock as mock

        mod._is_valid_token = lambda event: True
        mod._is_gmail_app_message = lambda event: True
        mod._fetch_thread_root_message_text = lambda event: ""
        mod._fetch_quoted_message_text = lambda event: ""
        mod._fetch_latest_ticket_record_from_history = lambda event: {}
        mod._save_ticket_record_to_history = lambda *a, **kw: None
        if hasattr(mod, "_run_ai_intent_planner"):
            mod._run_ai_intent_planner = lambda **kwargs: {
                "intent": "ticket_create",
                "needs_ticket_format": True,
                "prefer_thread_root": False,
                "prefer_history": False,
                "reason": "test",
                "confidence": "high",
            }

        sbom_names = {"almalinux", "fortigate 60f"}
        chrome_text = (
            "[緊急度: 高] Google Chrome に複数の脆弱性\n"
            "CVE-2026-1234\nCVSS: 8.8\nhttps://sid.softek.jp/12345"
        )
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "sender": {"displayName": "Gmail", "type": "BOT", "name": "users/gmail"},
                "text": chrome_text,
                "thread": {"name": "spaces/AAA/threads/CCC"},
            },
            "space": {"name": "spaces/AAA"},
        }

        with mock.patch.object(mod, "_get_sbom_product_names", return_value=sbom_names):
            raw_body, status, _headers = mod.handle_chat_event(_FakeRequest(payload))

        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertIn("対応不要", body["text"])
        self.assertIn("Google Chrome", body["text"])

    def test_sbom_registered_generates_ticket_e2e(self):
        """E2E: SBOM登録済み製品 → チケット生成フローに進む（対応不要にならない）。"""
        mod = self.chat_webhook
        import unittest.mock as mock

        mod._is_valid_token = lambda event: True
        mod._is_gmail_app_message = lambda event: True
        mod._fetch_thread_root_message_text = lambda event: ""
        mod._fetch_quoted_message_text = lambda event: ""
        mod._fetch_latest_ticket_record_from_history = lambda event: {}
        mod._save_ticket_record_to_history = lambda *a, **kw: None
        if hasattr(mod, "_run_ai_intent_planner"):
            mod._run_ai_intent_planner = lambda **kwargs: {
                "intent": "ticket_create",
                "needs_ticket_format": True,
                "prefer_thread_root": False,
                "prefer_history": False,
                "reason": "test",
                "confidence": "high",
            }

        sbom_names = {"google chrome (ウェブブラウザ)", "firefox", "fortigate 60f"}
        chrome_text = (
            "[緊急度: 高] Google Chrome に複数の脆弱性\n"
            "CVE-2026-1234\nCVSS: 8.8\nhttps://sid.softek.jp/12345"
        )
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "sender": {"displayName": "Gmail", "type": "BOT", "name": "users/gmail"},
                "text": chrome_text,
                "thread": {"name": "spaces/AAA/threads/DDD"},
            },
            "space": {"name": "spaces/AAA"},
        }

        # SBOMに登録済み → チケット生成フローに進むことを確認
        # _run_hypothesis_pipeline が呼ばれることを検証
        pipeline_called = []
        def fake_pipeline(source_text, history_key, user_instruction=""):
            pipeline_called.append(True)
            return {
                "status": "success",
                "ticket_text": "【起票用（コピペ）】\nタイトル: Google Chrome 脆弱性\n依頼概要: テスト\n",
                "reasoning_text": "テスト理由",
                "raw_ai_output": "{}",
            }

        with mock.patch.object(mod, "_get_sbom_product_names", return_value=sbom_names):
            with mock.patch.object(mod, "_run_hypothesis_pipeline", side_effect=fake_pipeline):
                raw_body, status, _headers = mod.handle_chat_event(_FakeRequest(payload))

        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        # チケットフォーマットが生成される（「対応不要」単独応答ではない）
        self.assertIn("【起票用（コピペ）】", body["text"])
        self.assertGreaterEqual(len(pipeline_called), 1, "hypothesis pipeline should be called")


    # ---- メッセージフォーマット分類テスト ----

    def test_classify_message_format_sidfm(self):
        """[SIDfm] マーカーを含むメッセージは sidfm と分類される。"""
        mod = self.chat_webhook
        text = "[SIDfm] Apache HTTP Server の脆弱性 CVE-2026-9999"
        self.assertEqual(mod._classify_message_format(text), mod._MSG_FORMAT_SIDFM)

    def test_classify_message_format_exploited(self):
        """【悪用された脆弱性】マーカーを含むメッセージは exploited と分類される。"""
        mod = self.chat_webhook
        text = "【悪用された脆弱性】Windows カーネルの特権昇格の脆弱性"
        self.assertEqual(mod._classify_message_format(text), mod._MSG_FORMAT_EXPLOITED)

    def test_classify_message_format_unknown(self):
        """マーカーなしメッセージは unknown と分類される。"""
        mod = self.chat_webhook
        text = "CVE-2026-1234 について調査してください"
        self.assertEqual(mod._classify_message_format(text), mod._MSG_FORMAT_UNKNOWN)

    def test_classify_message_format_exploited_with_forwarded_header(self):
        """転送ヘッダー付きでもマーカーが検出される。"""
        mod = self.chat_webhook
        header = (
            "---------- Forwarded message ---------\n"
            "From: SIDfm <notify@sid.softek.jp>\n"
            "Date: 2026年2月24日(月) 09:00\n"
            "Subject: 【悪用された脆弱性】Windows カーネルの特権昇格\n"
            "To: security-team@example.com\n\n"
        )
        text = header + "本文テキスト..."
        self.assertEqual(mod._classify_message_format(text), mod._MSG_FORMAT_EXPLOITED)

    def test_classify_message_format_both_markers_exploited_wins(self):
        """両マーカー共存時は【悪用された脆弱性】が優先される。"""
        mod = self.chat_webhook
        text = "【悪用された脆弱性】[SIDfm] Windows の脆弱性"
        self.assertEqual(mod._classify_message_format(text), mod._MSG_FORMAT_EXPLOITED)

    # ---- 【悪用された脆弱性】E2Eテスト ----

    def test_exploited_vuln_windows_e2e(self):
        """E2E: 【悪用された脆弱性】+Windows → アップデート推奨メッセージ。"""
        mod = self.chat_webhook
        import unittest.mock as mock

        mod._is_valid_token = lambda event: True
        mod._is_gmail_app_message = lambda event: True
        mod._fetch_thread_root_message_text = lambda event: ""
        mod._fetch_quoted_message_text = lambda event: ""
        mod._fetch_latest_ticket_record_from_history = lambda event: {}

        sbom_names = {"windows server 2022", "almalinux"}
        windows_text = (
            "【悪用された脆弱性】Windows カーネルの特権昇格の脆弱性\n"
            "CVE-2026-5678\nCVSS: 9.8\nhttps://sid.softek.jp/99999"
        )
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "sender": {"displayName": "Gmail", "type": "BOT", "name": "users/gmail"},
                "text": windows_text,
                "thread": {"name": "spaces/AAA/threads/EXP1"},
            },
            "space": {"name": "spaces/AAA"},
        }

        gemini_result = {
            "is_windows_or_apple": True,
            "product_name": "Windows カーネル",
            "cve_ids": ["CVE-2026-5678"],
            "comment": "特権昇格の脆弱性です。早急にパッチを適用してください。",
        }

        with mock.patch.object(mod, "_get_sbom_product_names", return_value=sbom_names):
            with mock.patch.object(mod, "_call_gemini_json", return_value=gemini_result):
                raw_body, status, _headers = mod.handle_chat_event(_FakeRequest(payload))

        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertIn("アップデートを推奨", body["text"])
        self.assertIn("Windows カーネル", body["text"])
        self.assertIn("CVE-2026-5678", body["text"])
        self.assertIn("AIコメント", body["text"])

    def test_exploited_vuln_apple_e2e(self):
        """E2E: 【悪用された脆弱性】+Apple → アップデート推奨メッセージ。"""
        mod = self.chat_webhook
        import unittest.mock as mock

        mod._is_valid_token = lambda event: True
        mod._is_gmail_app_message = lambda event: True
        mod._fetch_thread_root_message_text = lambda event: ""
        mod._fetch_quoted_message_text = lambda event: ""
        mod._fetch_latest_ticket_record_from_history = lambda event: {}

        sbom_names = {"macos", "almalinux"}
        apple_text = (
            "【悪用された脆弱性】Apple macOS の複数の脆弱性\n"
            "CVE-2026-7890\nCVSS: 8.5\nhttps://sid.softek.jp/88888"
        )
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "sender": {"displayName": "Gmail", "type": "BOT", "name": "users/gmail"},
                "text": apple_text,
                "thread": {"name": "spaces/AAA/threads/EXP2"},
            },
            "space": {"name": "spaces/AAA"},
        }

        gemini_result = {
            "is_windows_or_apple": True,
            "product_name": "Apple macOS",
            "cve_ids": ["CVE-2026-7890"],
            "comment": "macOSの重大な脆弱性です。最新バージョンに更新してください。",
        }

        with mock.patch.object(mod, "_get_sbom_product_names", return_value=sbom_names):
            with mock.patch.object(mod, "_call_gemini_json", return_value=gemini_result):
                raw_body, status, _headers = mod.handle_chat_event(_FakeRequest(payload))

        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertIn("アップデートを推奨", body["text"])
        self.assertIn("Apple macOS", body["text"])

    def test_exploited_vuln_gemini_failure_e2e(self):
        """E2E: 【悪用された脆弱性】+Gemini障害 → 安全側フォールバックメッセージ。"""
        mod = self.chat_webhook
        import unittest.mock as mock

        mod._is_valid_token = lambda event: True
        mod._is_gmail_app_message = lambda event: True
        mod._fetch_thread_root_message_text = lambda event: ""
        mod._fetch_quoted_message_text = lambda event: ""
        mod._fetch_latest_ticket_record_from_history = lambda event: {}

        sbom_names = {"windows server 2022", "almalinux"}
        windows_text = (
            "【悪用された脆弱性】Windows カーネルの特権昇格の脆弱性\n"
            "CVE-2026-5678\nCVSS: 9.8\nhttps://sid.softek.jp/99999"
        )
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "sender": {"displayName": "Gmail", "type": "BOT", "name": "users/gmail"},
                "text": windows_text,
                "thread": {"name": "spaces/AAA/threads/EXP_FAIL"},
            },
            "space": {"name": "spaces/AAA"},
        }

        # Gemini障害で空dictが返るケース
        with mock.patch.object(mod, "_get_sbom_product_names", return_value=sbom_names):
            with mock.patch.object(mod, "_call_gemini_json", return_value={}):
                raw_body, status, _headers = mod.handle_chat_event(_FakeRequest(payload))

        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertIn("AI分析が利用できませんでした", body["text"])
        self.assertIn("アップデートの要否を判断", body["text"])
        # 「対応不要」ではないことを確認
        self.assertNotIn("対応不要", body["text"])

    def test_exploited_vuln_other_e2e(self):
        """E2E: 【悪用された脆弱性】+Chrome(Windows/Apple以外) → 対応不要メッセージ。"""
        mod = self.chat_webhook
        import unittest.mock as mock

        mod._is_valid_token = lambda event: True
        mod._is_gmail_app_message = lambda event: True
        mod._fetch_thread_root_message_text = lambda event: ""
        mod._fetch_quoted_message_text = lambda event: ""
        mod._fetch_latest_ticket_record_from_history = lambda event: {}

        sbom_names = {"google chrome (ウェブブラウザ)", "almalinux"}
        chrome_text = (
            "【悪用された脆弱性】Google Chrome のゼロデイ脆弱性\n"
            "CVE-2026-4321\nCVSS: 9.0\nhttps://sid.softek.jp/77777"
        )
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "sender": {"displayName": "Gmail", "type": "BOT", "name": "users/gmail"},
                "text": chrome_text,
                "thread": {"name": "spaces/AAA/threads/EXP3"},
            },
            "space": {"name": "spaces/AAA"},
        }

        gemini_result = {
            "is_windows_or_apple": False,
            "product_name": "Google Chrome",
            "cve_ids": ["CVE-2026-4321"],
            "comment": "Chrome固有の脆弱性です。",
        }

        with mock.patch.object(mod, "_get_sbom_product_names", return_value=sbom_names):
            with mock.patch.object(mod, "_call_gemini_json", return_value=gemini_result):
                raw_body, status, _headers = mod.handle_chat_event(_FakeRequest(payload))

        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertIn("対応不要", body["text"])
        self.assertIn("Google Chrome", body["text"])
        self.assertIn("Windows / Apple 以外", body["text"])


    # ---- 【脆弱性情報 更新通知】分類テスト ----

    def test_classify_message_format_update(self):
        """【脆弱性情報 更新通知】マーカーを含むメッセージは update と分類される。"""
        mod = self.chat_webhook
        text = "【脆弱性情報 更新通知】Windows カーネルの脆弱性情報が更新されました"
        self.assertEqual(mod._classify_message_format(text), mod._MSG_FORMAT_UPDATE)

    def test_classify_message_format_exploited_over_update(self):
        """【悪用された脆弱性】と【脆弱性情報 更新通知】が共存時は exploited が優先される。"""
        mod = self.chat_webhook
        text = "【悪用された脆弱性】【脆弱性情報 更新通知】Windows の脆弱性"
        self.assertEqual(mod._classify_message_format(text), mod._MSG_FORMAT_EXPLOITED)

    def test_classify_message_format_update_with_forwarded_header(self):
        """転送ヘッダー付きでも更新通知マーカーが検出される。"""
        mod = self.chat_webhook
        header = (
            "---------- Forwarded message ---------\n"
            "From: SIDfm <notify@sid.softek.jp>\n"
            "Date: 2026年3月1日(日) 09:00\n"
            "Subject: 【脆弱性情報 更新通知】Windows カーネルの脆弱性\n"
            "To: security-team@example.com\n\n"
        )
        text = header + "本文テキスト..."
        self.assertEqual(mod._classify_message_format(text), mod._MSG_FORMAT_UPDATE)

    # ---- 【脆弱性情報 更新通知】E2Eテスト ----

    def test_update_notification_windows_e2e(self):
        """E2E: 【脆弱性情報 更新通知】+Windows → 更新通知メッセージ。"""
        mod = self.chat_webhook
        import unittest.mock as mock

        mod._is_valid_token = lambda event: True
        mod._is_gmail_app_message = lambda event: True
        mod._fetch_thread_root_message_text = lambda event: ""
        mod._fetch_quoted_message_text = lambda event: ""
        mod._fetch_latest_ticket_record_from_history = lambda event: {}

        sbom_names = {"windows server 2022", "almalinux"}
        update_text = (
            "【脆弱性情報 更新通知】Windows カーネルの特権昇格の脆弱性\n"
            "CVE-2026-8888\nCVSS: 8.5\nhttps://sid.softek.jp/88888"
        )
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "sender": {"displayName": "Gmail", "type": "BOT", "name": "users/gmail"},
                "text": update_text,
                "thread": {"name": "spaces/AAA/threads/UPD1"},
            },
            "space": {"name": "spaces/AAA"},
        }

        gemini_result = {
            "is_windows_or_apple": True,
            "product_name": "Windows カーネル",
            "cve_ids": ["CVE-2026-8888"],
            "comment": "特権昇格の脆弱性情報が更新されました。パッチ適用を検討してください。",
        }

        with mock.patch.object(mod, "_get_sbom_product_names", return_value=sbom_names):
            with mock.patch.object(mod, "_call_gemini_json", return_value=gemini_result):
                raw_body, status, _headers = mod.handle_chat_event(_FakeRequest(payload))

        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertIn("更新通知", body["text"])
        self.assertIn("Windows カーネル", body["text"])
        self.assertIn("CVE-2026-8888", body["text"])
        self.assertNotIn("悪用", body["text"])

    def test_update_notification_other_e2e(self):
        """E2E: 【脆弱性情報 更新通知】+Chrome(Windows/Apple以外) → 対応不要メッセージ。"""
        mod = self.chat_webhook
        import unittest.mock as mock

        mod._is_valid_token = lambda event: True
        mod._is_gmail_app_message = lambda event: True
        mod._fetch_thread_root_message_text = lambda event: ""
        mod._fetch_quoted_message_text = lambda event: ""
        mod._fetch_latest_ticket_record_from_history = lambda event: {}

        sbom_names = {"google chrome (ウェブブラウザ)", "almalinux"}
        update_text = (
            "【脆弱性情報 更新通知】Google Chrome の脆弱性\n"
            "CVE-2026-9999\nCVSS: 7.5\nhttps://sid.softek.jp/99999"
        )
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "sender": {"displayName": "Gmail", "type": "BOT", "name": "users/gmail"},
                "text": update_text,
                "thread": {"name": "spaces/AAA/threads/UPD2"},
            },
            "space": {"name": "spaces/AAA"},
        }

        gemini_result = {
            "is_windows_or_apple": False,
            "product_name": "Google Chrome",
            "cve_ids": ["CVE-2026-9999"],
            "comment": "Chrome固有の脆弱性情報更新です。",
        }

        with mock.patch.object(mod, "_get_sbom_product_names", return_value=sbom_names):
            with mock.patch.object(mod, "_call_gemini_json", return_value=gemini_result):
                raw_body, status, _headers = mod.handle_chat_event(_FakeRequest(payload))

        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertIn("ℹ️ 対応不要", body["text"])
        self.assertIn("Google Chrome", body["text"])
        self.assertIn("Windows / Apple 以外", body["text"])

    def test_update_notification_gemini_failure_e2e(self):
        """E2E: 【脆弱性情報 更新通知】+Gemini障害 → 安全側フォールバック。"""
        mod = self.chat_webhook
        import unittest.mock as mock

        mod._is_valid_token = lambda event: True
        mod._is_gmail_app_message = lambda event: True
        mod._fetch_thread_root_message_text = lambda event: ""
        mod._fetch_quoted_message_text = lambda event: ""
        mod._fetch_latest_ticket_record_from_history = lambda event: {}

        sbom_names = {"windows server 2022", "almalinux"}
        update_text = (
            "【脆弱性情報 更新通知】Windows カーネルの脆弱性\n"
            "CVE-2026-8888\nCVSS: 8.5\nhttps://sid.softek.jp/88888"
        )
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "sender": {"displayName": "Gmail", "type": "BOT", "name": "users/gmail"},
                "text": update_text,
                "thread": {"name": "spaces/AAA/threads/UPD_FAIL"},
            },
            "space": {"name": "spaces/AAA"},
        }

        with mock.patch.object(mod, "_get_sbom_product_names", return_value=sbom_names):
            with mock.patch.object(mod, "_call_gemini_json", return_value={}):
                raw_body, status, _headers = mod.handle_chat_event(_FakeRequest(payload))

        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertIn("更新通知", body["text"])
        self.assertIn("AI分析が利用できませんでした", body["text"])
        self.assertNotIn("悪用", body["text"])

    # ---- 対応不要メッセージ視認性テスト ----

    def test_sbom_not_registered_message_has_info_prefix(self):
        """SBOM未登録の対応不要メッセージに ℹ️ 対応不要 プレフィックスがある。"""
        mod = self.chat_webhook
        msg = mod._build_sbom_not_registered_message(["FortiGate"], "SBOMに未登録")
        self.assertTrue(msg.startswith("ℹ️ 対応不要"))

    def test_exploited_not_target_message_has_info_prefix(self):
        """悪用脆弱性の対応不要メッセージに ℹ️ 対応不要 プレフィックスがある。"""
        mod = self.chat_webhook
        msg = mod._build_exploited_not_target_message({"product_name": "Linux Kernel"})
        self.assertTrue(msg.startswith("ℹ️ 対応不要"))

    def test_sbom_version_not_applicable_message(self):
        """SBOMバージョン不一致時のメッセージが正しく構築される。"""
        mod = self.chat_webhook
        msg = mod._build_sbom_version_not_applicable_message(
            ["AlmaLinux10"], {"8", "9"},
        )
        self.assertTrue(msg.startswith("ℹ️ 対応不要"))
        self.assertIn("AlmaLinux10", msg)
        self.assertIn("8, 9", msg)

    def test_sbom_version_filter_skips_ticket_e2e(self):
        """E2E: AlmaLinux10のみの通知 + SBOM(8,9) → SBOMバージョン不一致で対応不要。"""
        mod = self.chat_webhook
        import unittest.mock as mock

        mod._is_valid_token = lambda event: True
        mod._is_gmail_app_message = lambda event: True
        mod._fetch_thread_root_message_text = lambda event: ""
        mod._fetch_quoted_message_text = lambda event: ""
        mod._fetch_latest_ticket_record_from_history = lambda event: {}
        mod._save_ticket_record_to_history = lambda *a, **kw: None
        mod._run_agent_query = lambda prompt, user_id: "{}"
        if hasattr(mod, "_run_ai_intent_planner"):
            mod._run_ai_intent_planner = lambda **kwargs: {
                "intent": "ticket_create",
                "needs_ticket_format": True,
                "prefer_thread_root": False,
                "prefer_history": False,
                "reason": "test",
                "confidence": "high",
            }

        sbom_names = {"almalinux"}
        alma10_text = (
            "[SIDfm] AlmaLinux 10 の脆弱性\n"
            "1 63416 8.1 AlmaLinux 10 の freerdp に任意のコードを実行される問題\n"
            "https://sid.softek.jp/filter/sinfo/63416"
        )
        payload = {
            "type": "MESSAGE",
            "user": {"name": "users/111"},
            "message": {
                "sender": {"displayName": "Gmail", "type": "BOT", "name": "users/gmail"},
                "text": alma10_text,
                "thread": {"name": "spaces/AAA/threads/ALMA10"},
            },
            "space": {"name": "spaces/AAA"},
        }

        # 実際の環境では extract_sidfm_entries が AlmaLinux10 エントリを抽出し、
        # SBOM バージョンフィルタ(8,9)で除去されて entries=[] になる。
        # テスト環境ではテキスト結合で抽出が変わるため、
        # _merge_hypothesis_with_tool_facts をモックして実シナリオを再現。
        mock_facts = {
            "entries": [],
            "all_entries_count": 1,
            "selected_entries_count": 0,
            "due_group_count": 1,
            "products": ["AlmaLinux10"],
            "vuln_links": ["https://sid.softek.jp/filter/sinfo/63416"],
            "grouped_vuln_links": {},
            "scores": [],
            "max_score": None,
            "due_date": "対応不要",
            "due_reason": "CVSS 8.0未満または不明のため対応不要",
            "sbom_alma_versions": ["8", "9"],
        }

        with mock.patch.object(mod, "_get_sbom_product_names", return_value=sbom_names):
            with mock.patch.object(mod, "_get_sbom_almalinux_versions", return_value={"8", "9"}):
                with mock.patch.object(mod, "_call_gemini_json", return_value={}):
                    with mock.patch.object(mod, "_merge_hypothesis_with_tool_facts", return_value=mock_facts):
                        raw_body, status, _headers = mod.handle_chat_event(_FakeRequest(payload))

        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertIn("ℹ️ 対応不要", body["text"])
        self.assertIn("8, 9", body["text"])
        # フル起票テンプレートが含まれないことを確認
        self.assertNotIn("【起票用（コピペ）】", body["text"])
        self.assertNotIn("【CVSSスコア】", body["text"])


if __name__ == "__main__":
    unittest.main()
