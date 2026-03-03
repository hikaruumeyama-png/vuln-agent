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

    def create(self, parent, body, messageReplyOption):
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

        # Chat API にメッセージが送信されたか
        created = service.spaces().messages().created_calls
        self.assertEqual(len(created), 1)
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


if __name__ == "__main__":
    unittest.main()
