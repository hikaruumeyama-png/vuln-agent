"""workspace_events_webhook/main.py のユニットテスト。

shared.ticket_pipeline.generate_ticket をモックして、
webhook ハンドラのルーティング・重複排除・Chat API 呼び出しを検証する。
"""

import base64
import dataclasses
import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parent
MODULE_PATH = ROOT / "workspace_events_webhook" / "main.py"


# ---------------------------------------------------------------------------
# generate_ticket のモック用 TicketResult
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class _MockTicketResult:
    status: str = "ticket"
    text: str = "【起票用（コピペ）】\nテスト起票テンプレート"
    facts: dict | None = None
    audit_ok: bool = True
    audit_errors: list = dataclasses.field(default_factory=list)


_generate_ticket_calls: list[dict] = []


def _mock_generate_ticket(source_text: str, **kwargs) -> _MockTicketResult:
    _generate_ticket_calls.append({"source_text": source_text, **kwargs})
    return _MockTicketResult()


def _mock_run_agent_query(prompt: str, user_id: str) -> str:
    return "mocked agent response"


# ---------------------------------------------------------------------------
# 依存スタブ
# ---------------------------------------------------------------------------
def _stub_dependencies():
    # functions_framework
    ff = types.ModuleType("functions_framework")
    ff.http = lambda fn: fn
    sys.modules["functions_framework"] = ff

    # google.auth
    google_mod = types.ModuleType("google")
    auth_mod = types.ModuleType("google.auth")
    transport_mod = types.ModuleType("google.auth.transport")
    requests_mod = types.ModuleType("google.auth.transport.requests")
    requests_mod.Request = object
    transport_mod.requests = requests_mod
    auth_mod.default = lambda scopes=None: (object(), "test-project")
    auth_mod.transport = transport_mod
    google_mod.auth = auth_mod
    sys.modules["google"] = google_mod
    sys.modules["google.auth"] = auth_mod
    sys.modules["google.auth.transport"] = transport_mod
    sys.modules["google.auth.transport.requests"] = requests_mod

    # googleapiclient
    ga = types.ModuleType("googleapiclient")
    discovery = types.ModuleType("googleapiclient.discovery")
    discovery.build = lambda *args, **kwargs: object()
    ga.discovery = discovery
    sys.modules["googleapiclient"] = ga
    sys.modules["googleapiclient.discovery"] = discovery

    # shared (全モジュールをモック)
    shared_mod = types.ModuleType("shared")
    shared_mod.__path__ = []
    sys.modules["shared"] = shared_mod

    # shared.agent_query
    aq_mod = types.ModuleType("shared.agent_query")
    aq_mod.run_agent_query = _mock_run_agent_query
    shared_mod.agent_query = aq_mod
    sys.modules["shared.agent_query"] = aq_mod

    # shared.ticket_pipeline
    tp_mod = types.ModuleType("shared.ticket_pipeline")
    tp_mod.generate_ticket = _mock_generate_ticket
    tp_mod.TicketResult = _MockTicketResult
    shared_mod.ticket_pipeline = tp_mod
    sys.modules["shared.ticket_pipeline"] = tp_mod

    # shared.ticket_renderers
    # build_toplevel_summary の簡易スタブ（実装と同じロジック）
    _SKIP = frozenset({"sbom_skip", "exploited_not_target", "update_not_target", "low_quality", "error"})
    def _stub_build_toplevel_summary(status, facts):
        if status in _SKIP:
            return None
        if status == "ticket" and facts:
            products = facts.get("products") or ["要確認"]
            product_text = " / ".join(products[:3])
            max_score = facts.get("max_score")
            cvss_text = f"CVSS {max_score:.1f}" if max_score is not None else "CVSS 要確認"
            due_date = facts.get("due_date") or "要確認"
            return f"🔴 起票対象: {product_text} | {cvss_text} | 期限 {due_date} ← 詳細はスレッドを確認"
        if status == "exploited_update":
            return "🔴 悪用確認: 脆弱性のアップデート要否を確認してください ← 詳細はスレッドを確認"
        if status == "update_notification":
            return "🟠 更新通知: 脆弱性情報が更新されました ← 詳細はスレッドを確認"
        if status == "ticket":
            return "🟠 起票対象: 脆弱性が検出されました ← 詳細はスレッドを確認"
        return None
    tr_mod = types.ModuleType("shared.ticket_renderers")
    tr_mod.build_toplevel_summary = _stub_build_toplevel_summary
    shared_mod.ticket_renderers = tr_mod
    sys.modules["shared.ticket_renderers"] = tr_mod


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# テスト用フェイク
# ---------------------------------------------------------------------------
class _FakeRequest:
    def __init__(self, payload, path="/"):
        self._payload = payload
        self.path = path

    def get_json(self, silent=True):
        _ = silent
        return self._payload


class _MessagesResource:
    def __init__(self):
        self.created_calls = []
        self.source_message = {
            "name": "spaces/AAA/messages/BBB",
            "text": "From: sidfm-notification@rakus.co.jp\nSubject: CVE-2026-1234\nCVE-2026-1234 脆弱性通知",
            "thread": {"name": "spaces/AAA/threads/TTT"},
        }

    def get(self, name):
        _ = name
        return types.SimpleNamespace(execute=lambda: self.source_message)

    def create(self, parent, body, messageReplyOption=None):
        self.created_calls.append(
            {"parent": parent, "body": body, "messageReplyOption": messageReplyOption}
        )
        return types.SimpleNamespace(execute=lambda: {"name": "spaces/AAA/messages/CCC"})


class _SpacesResource:
    def __init__(self):
        self.messages_resource = _MessagesResource()

    def messages(self):
        return self.messages_resource


class _ChatService:
    def __init__(self):
        self.spaces_resource = _SpacesResource()

    def spaces(self):
        return self.spaces_resource


# ---------------------------------------------------------------------------
# テストケース
# ---------------------------------------------------------------------------
class WorkspaceEventsWebhookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _stub_dependencies()
        cls.mod = _load_module("workspace_events_webhook_test_module", MODULE_PATH)

    def setUp(self):
        self.mod._EVENT_CACHE.clear()
        _generate_ticket_calls.clear()
        # generate_ticket モックをデフォルトに復元
        self.mod.generate_ticket = _mock_generate_ticket

    # --- イベント抽出 ---
    def test_extract_event_from_pubsub_push(self):
        data = {"reaction": {"name": "spaces/AAA/messages/BBB/reactions/R1"}}
        encoded = base64.b64encode(json.dumps(data).encode("utf-8")).decode("utf-8")
        payload = {
            "message": {
                "data": encoded,
                "attributes": {
                    "ce-type": "google.workspace.chat.reaction.v1.created",
                    "ce-id": "evt-1",
                },
            }
        }
        event_type, event_id, event_data = self.mod._extract_event(payload)
        self.assertEqual(event_type, "google.workspace.chat.reaction.v1.created")
        self.assertEqual(event_id, "evt-1")
        self.assertEqual(event_data["reaction"]["name"], "spaces/AAA/messages/BBB/reactions/R1")

    # --- ？リアクション → generate_ticket ---
    def test_question_reaction_calls_generate_ticket(self):
        service = _ChatService()
        reader_service = _ChatService()
        self.mod._build_chat_service = lambda: service
        self.mod._build_chat_reader_service = lambda: reader_service

        event_data = {
            "reaction": {
                "name": "spaces/AAA/messages/BBB/reactions/R1",
                "emoji": {"unicode": "❓"},
                "user": {"name": "users/999"},
            }
        }
        encoded = base64.b64encode(json.dumps(event_data).encode("utf-8")).decode("utf-8")
        payload = {
            "message": {
                "data": encoded,
                "attributes": {
                    "ce-type": "google.workspace.chat.reaction.v1.created",
                    "ce-id": "evt-2",
                },
            }
        }

        raw_body, status, _headers = self.mod.handle_workspace_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertEqual(body["processed"], 1)

        # generate_ticket が呼ばれたか
        self.assertEqual(len(_generate_ticket_calls), 1)
        call = _generate_ticket_calls[0]
        self.assertIn("CVE-2026-1234", call["source_text"])
        # agent_query_fn が渡されているか
        self.assertIsNotNone(call.get("agent_query_fn"))
        # space_id と thread_name が渡されているか
        self.assertEqual(call.get("space_id"), "spaces/AAA")
        self.assertEqual(call.get("thread_name"), "spaces/AAA/threads/TTT")
        self.assertEqual(call.get("history_key"), "workspace_reaction")

        # Chat API にメッセージが送信されたか（スレッド返信 + トップレベルサマリ）
        created = service.spaces().messages().created_calls
        self.assertGreaterEqual(len(created), 1)
        self.assertEqual(created[0]["parent"], "spaces/AAA")
        self.assertEqual(created[0]["body"]["thread"]["name"], "spaces/AAA/threads/TTT")
        self.assertIn("【起票用（コピペ）】", created[0]["body"]["text"])

    # --- 非？リアクション → スキップ ---
    def test_non_question_reaction_is_ignored(self):
        service = _ChatService()
        self.mod._build_chat_service = lambda: service

        event_data = {
            "reaction": {
                "name": "spaces/AAA/messages/BBB/reactions/R2",
                "emoji": {"unicode": "👍"},
                "user": {"name": "users/999"},
            }
        }
        encoded = base64.b64encode(json.dumps(event_data).encode("utf-8")).decode("utf-8")
        payload = {
            "message": {
                "data": encoded,
                "attributes": {
                    "ce-type": "google.workspace.chat.reaction.v1.created",
                    "ce-id": "evt-3",
                },
            }
        }
        raw_body, status, _headers = self.mod.handle_workspace_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertEqual(body["processed"], 0)
        self.assertEqual(len(_generate_ticket_calls), 0)

    # --- 重複イベント排除 ---
    def test_duplicate_event_is_skipped(self):
        service = _ChatService()
        reader_service = _ChatService()
        self.mod._build_chat_service = lambda: service
        self.mod._build_chat_reader_service = lambda: reader_service

        event_data = {
            "reaction": {
                "name": "spaces/AAA/messages/BBB/reactions/R1",
                "emoji": {"unicode": "❓"},
                "user": {"name": "users/999"},
            }
        }
        encoded = base64.b64encode(json.dumps(event_data).encode("utf-8")).decode("utf-8")
        payload = {
            "message": {
                "data": encoded,
                "attributes": {
                    "ce-type": "google.workspace.chat.reaction.v1.created",
                    "ce-id": "evt-dup",
                },
            }
        }

        # 1回目: 処理される
        raw1, s1, _ = self.mod.handle_workspace_event(_FakeRequest(payload))
        self.assertEqual(json.loads(raw1)["processed"], 1)

        # 2回目: event_id レベルで重複排除
        raw2, s2, _ = self.mod.handle_workspace_event(_FakeRequest(payload))
        self.assertEqual(json.loads(raw2)["status"], "duplicate")

    # --- Gmail メッセージイベント ---
    def test_gmail_message_event_calls_generate_ticket(self):
        service = _ChatService()
        self.mod._build_chat_service = lambda: service

        msg = {
            "name": "spaces/AAA/messages/GGG",
            "text": "From: sidfm-notification@example.com\nSubject: CVE-2026-9999\nView message",
            "sender": {"displayName": "Gmail", "type": "BOT"},
            "thread": {"name": "spaces/AAA/threads/TTT2"},
        }
        event_data = {"message": msg}
        encoded = base64.b64encode(json.dumps(event_data).encode("utf-8")).decode("utf-8")
        payload = {
            "message": {
                "data": encoded,
                "attributes": {
                    "ce-type": "google.workspace.chat.message.v1.created",
                    "ce-id": "evt-gmail-1",
                },
            }
        }

        raw_body, status, _ = self.mod.handle_workspace_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertEqual(body["processed"], 1)
        self.assertEqual(len(_generate_ticket_calls), 1)

        # Gmail メッセージでも agent_query_fn, space_id, thread_name が渡されるか
        call = _generate_ticket_calls[0]
        self.assertIsNotNone(call.get("agent_query_fn"))
        self.assertEqual(call.get("space_id"), "spaces/AAA")
        self.assertEqual(call.get("thread_name"), "spaces/AAA/threads/TTT2")
        self.assertEqual(call.get("history_key"), "workspace_gmail")

    # --- サポートされていないイベントタイプ ---
    def test_unsupported_event_type_is_ignored(self):
        event_data = {"space": {"name": "spaces/AAA"}}
        encoded = base64.b64encode(json.dumps(event_data).encode("utf-8")).decode("utf-8")
        payload = {
            "message": {
                "data": encoded,
                "attributes": {
                    "ce-type": "google.workspace.chat.space.v1.updated",
                    "ce-id": "evt-unsupported",
                },
            }
        }
        raw_body, status, _ = self.mod.handle_workspace_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertEqual(body["status"], "ignored")

    # --- /renew パス ---
    def test_renew_path_calls_renew_subscription(self):
        renew_called = []
        self.mod._renew_subscription = lambda: (
            renew_called.append(True) or {"status": "renewed", "result": {}}
        )
        raw_body, status, _ = self.mod.handle_workspace_event(
            _FakeRequest({}, path="/renew")
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(renew_called), 1)

    # --- _looks_like_gmail_message ---
    def test_looks_like_gmail_message_by_sender(self):
        msg = {"sender": {"displayName": "Gmail", "type": "BOT"}, "text": "hello"}
        self.assertTrue(self.mod._looks_like_gmail_message(msg))

    def test_looks_like_gmail_message_by_signals(self):
        msg = {
            "sender": {"displayName": "SomeBot"},
            "text": "From: test@example.com\nSubject: Alert\nView message",
        }
        self.assertTrue(self.mod._looks_like_gmail_message(msg))

    def test_not_gmail_message(self):
        msg = {"sender": {"displayName": "User"}, "text": "こんにちは"}
        self.assertFalse(self.mod._looks_like_gmail_message(msg))

    # --- cardsV2 テキスト抽出 ---
    def test_extract_text_from_cards_v2(self):
        """Gmail App の cardsV2 メッセージからテキストが正しく抽出される。"""
        msg = {
            "name": "spaces/AAA/messages/CCC",
            "text": "",
            "cardsV2": [{
                "cardId": "forward_email_message",
                "card": {
                    "sections": [
                        {
                            "widgets": [{
                                "decoratedText": {
                                    "text": "[SIDfm] 脆弱性通知テスト",
                                    "bottomLabel": "From: sidfm@example.com",
                                }
                            }]
                        },
                        {
                            "widgets": [
                                {
                                    "textParagraph": {
                                        "text": "━━━ SIDfm通知本文 ━━━\\r\\n1 63416  8.1 AlmaLinux 10 CVE-2026-1234"
                                    }
                                },
                                {
                                    "decoratedText": {
                                        "bottomLabel": "To view the full email, go to Gmail"
                                    }
                                },
                            ]
                        },
                    ]
                }
            }],
            "sender": {"displayName": "Gmail", "type": "BOT"},
            "thread": {"name": "spaces/AAA/threads/TTT3"},
        }

        result = self.mod._extract_source_text(msg)
        # cardsV2 から件名・From 行・本文が抽出されること
        self.assertIn("[SIDfm] 脆弱性通知テスト", result)
        self.assertIn("From: sidfm@example.com", result)
        self.assertIn("CVE-2026-1234", result)
        self.assertIn("AlmaLinux 10", result)
        # リテラル \r\n が実改行に変換されること
        self.assertNotIn("\\r\\n", result)
        # フッター行が除外されること
        self.assertNotIn("To view the full email", result)
        # json.dumps フォールバックが使われていないこと
        self.assertNotIn('"cardsV2"', result)

    def test_extract_text_from_cards_v2_with_html_entities(self):
        """HTML エンティティが正しく復元される。"""
        msg = {
            "text": "",
            "cardsV2": [{
                "cardId": "test",
                "card": {
                    "sections": [{
                        "widgets": [{
                            "textParagraph": {
                                "text": "脆弱性 &amp; セキュリティ &lt;重要&gt;"
                            }
                        }]
                    }]
                }
            }],
        }
        result = self.mod._extract_source_text(msg)
        self.assertIn("脆弱性 & セキュリティ <重要>", result)

    def test_extract_source_text_prefers_longer(self):
        """cardsV2 と text の両方がある場合、長い方が採用される。"""
        long_body = "━━━ 本文 ━━━\n" + "A" * 200
        msg = {
            "text": "短いテキスト",
            "cardsV2": [{
                "cardId": "test",
                "card": {
                    "sections": [{
                        "widgets": [{
                            "textParagraph": {"text": long_body}
                        }]
                    }]
                }
            }],
        }
        result = self.mod._extract_source_text(msg)
        self.assertIn("━━━ 本文 ━━━", result)

    def test_gmail_cards_v2_message_event_extracts_body(self):
        """Gmail App cardsV2 メッセージイベントで generate_ticket に正しいテキストが渡される。"""
        service = _ChatService()
        self.mod._build_chat_service = lambda: service

        msg = {
            "name": "spaces/AAA/messages/CARD1",
            "text": "",
            "cardsV2": [{
                "cardId": "forward_email_message",
                "card": {
                    "sections": [
                        {"widgets": [{"decoratedText": {"text": "[SIDfm] CVE通知"}}]},
                        {"widgets": [{"textParagraph": {"text": "1 99999  9.8 AlmaLinux 10 CVE-2026-5678"}}]},
                    ]
                }
            }],
            "sender": {"displayName": "Gmail", "type": "BOT"},
            "thread": {"name": "spaces/AAA/threads/TTT4"},
        }
        event_data = {"message": msg}
        encoded = base64.b64encode(json.dumps(event_data).encode("utf-8")).decode("utf-8")
        payload = {
            "message": {
                "data": encoded,
                "attributes": {
                    "ce-type": "google.workspace.chat.message.v1.created",
                    "ce-id": "evt-gmail-card-1",
                },
            }
        }

        raw_body, status, _ = self.mod.handle_workspace_event(_FakeRequest(payload))
        self.assertEqual(status, 200)
        body = json.loads(raw_body)
        self.assertEqual(body["processed"], 1)

        # generate_ticket に cardsV2 から抽出したテキストが渡されるか
        self.assertEqual(len(_generate_ticket_calls), 1)
        call = _generate_ticket_calls[0]
        self.assertIn("CVE-2026-5678", call["source_text"])
        self.assertIn("[SIDfm] CVE通知", call["source_text"])
        # json.dumps フォールバックが使われていないこと
        self.assertNotIn('"cardsV2"', call["source_text"])


    # --- トップレベルサマリ投稿 ---
    def test_toplevel_summary_posted_for_ticket_status(self):
        """status=ticket のとき、スレッド返信+トップレベルサマリの2メッセージが投稿される。"""
        # facts 付きの TicketResult を返すモックに差し替え
        def _mock_with_facts(source_text, **kwargs):
            _generate_ticket_calls.append({"source_text": source_text, **kwargs})
            return _MockTicketResult(
                status="ticket",
                text="【起票用（コピペ）】\nテスト",
                facts={"products": ["AlmaLinux9"], "max_score": 9.8, "due_date": "2026/03/28"},
            )
        self.mod.generate_ticket = _mock_with_facts

        service = _ChatService()
        self.mod._build_chat_service = lambda: service

        msg = {
            "name": "spaces/AAA/messages/SUM1",
            "text": "From: sidfm@example.com\nSubject: CVE\nView message",
            "sender": {"displayName": "Gmail", "type": "BOT"},
            "thread": {"name": "spaces/AAA/threads/TTT5"},
        }
        event_data = {"message": msg}
        encoded = base64.b64encode(json.dumps(event_data).encode("utf-8")).decode("utf-8")
        payload = {
            "message": {
                "data": encoded,
                "attributes": {
                    "ce-type": "google.workspace.chat.message.v1.created",
                    "ce-id": "evt-summary-1",
                },
            }
        }

        raw_body, status, _ = self.mod.handle_workspace_event(_FakeRequest(payload))
        self.assertEqual(status, 200)

        created = service.spaces().messages().created_calls
        # スレッド返信 + トップレベルサマリ = 2件
        self.assertEqual(len(created), 2)
        # 1件目: スレッド返信（thread あり）
        self.assertIn("thread", created[0]["body"])
        self.assertEqual(created[0]["messageReplyOption"], "REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD")
        # 2件目: トップレベルサマリ（thread なし）
        self.assertNotIn("thread", created[1]["body"])
        self.assertIsNone(created[1]["messageReplyOption"])
        self.assertIn("起票対象", created[1]["body"]["text"])
        self.assertIn("CVSS 9.8", created[1]["body"]["text"])

    def test_no_toplevel_summary_for_sbom_skip(self):
        """status=sbom_skip のとき、トップレベルサマリは投稿されない。"""
        def _mock_skip(source_text, **kwargs):
            _generate_ticket_calls.append({"source_text": source_text, **kwargs})
            return _MockTicketResult(status="sbom_skip", text="SBOM未登録です")
        self.mod.generate_ticket = _mock_skip

        service = _ChatService()
        self.mod._build_chat_service = lambda: service

        msg = {
            "name": "spaces/AAA/messages/SUM2",
            "text": "From: sidfm@example.com\nSubject: CVE\nView message",
            "sender": {"displayName": "Gmail", "type": "BOT"},
            "thread": {"name": "spaces/AAA/threads/TTT6"},
        }
        event_data = {"message": msg}
        encoded = base64.b64encode(json.dumps(event_data).encode("utf-8")).decode("utf-8")
        payload = {
            "message": {
                "data": encoded,
                "attributes": {
                    "ce-type": "google.workspace.chat.message.v1.created",
                    "ce-id": "evt-summary-2",
                },
            }
        }

        self.mod.handle_workspace_event(_FakeRequest(payload))

        created = service.spaces().messages().created_calls
        # スレッド返信のみ = 1件
        self.assertEqual(len(created), 1)
        self.assertIn("thread", created[0]["body"])


class BuildToplevelSummaryTests(unittest.TestCase):
    """build_toplevel_summary の単体テスト。"""

    def _build(self, status, facts):
        return sys.modules["shared.ticket_renderers"].build_toplevel_summary(status, facts)

    def test_ticket_with_facts(self):
        facts = {"products": ["FortiOS"], "max_score": 8.2, "due_date": "2026/04/07"}
        result = self._build("ticket", facts)
        self.assertIsNotNone(result)
        self.assertIn("起票対象", result)
        self.assertIn("FortiOS", result)
        self.assertIn("CVSS 8.2", result)
        self.assertIn("2026/04/07", result)

    def test_ticket_without_facts(self):
        result = self._build("ticket", None)
        self.assertIsNotNone(result)
        self.assertIn("起票対象", result)

    def test_sbom_skip_returns_none(self):
        self.assertIsNone(self._build("sbom_skip", None))

    def test_exploited_not_target_returns_none(self):
        self.assertIsNone(self._build("exploited_not_target", None))

    def test_low_quality_returns_none(self):
        self.assertIsNone(self._build("low_quality", None))

    def test_exploited_update(self):
        result = self._build("exploited_update", None)
        self.assertIsNotNone(result)
        self.assertIn("悪用確認", result)

    def test_update_notification(self):
        result = self._build("update_notification", None)
        self.assertIsNotNone(result)
        self.assertIn("更新通知", result)

    def test_error_returns_none(self):
        self.assertIsNone(self._build("error", None))


if __name__ == "__main__":
    unittest.main()
