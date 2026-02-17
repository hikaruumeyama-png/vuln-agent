import base64
import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parent
MODULE_PATH = ROOT / "workspace_events_webhook" / "main.py"


def _stub_dependencies():
    ff = types.ModuleType("functions_framework")
    ff.http = lambda fn: fn
    sys.modules["functions_framework"] = ff

    google = types.ModuleType("google")
    auth = types.ModuleType("google.auth")
    auth.default = lambda scopes=None: (object(), "test-project")
    google.auth = auth
    sys.modules["google"] = google
    sys.modules["google.auth"] = auth

    ga = types.ModuleType("googleapiclient")
    discovery = types.ModuleType("googleapiclient.discovery")
    discovery.build = lambda *args, **kwargs: object()
    ga.discovery = discovery
    sys.modules["googleapiclient"] = ga
    sys.modules["googleapiclient.discovery"] = discovery

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


class _MessagesResource:
    def __init__(self):
        self.created_calls = []
        self.source_message = {
            "name": "spaces/AAA/messages/BBB",
            "text": "From: sidfm-notification@rakus.co.jp\nCVE-2026-1234",
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


class WorkspaceEventsWebhookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _stub_dependencies()
        cls.mod = _load_module("workspace_events_webhook_test_module", MODULE_PATH)

    def setUp(self):
        self.mod._EVENT_CACHE.clear()

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

    def test_handle_workspace_event_processes_question_reaction(self):
        service = _ChatService()
        self.mod._build_chat_service = lambda: service
        self.mod._run_agent_query = lambda prompt, user_id: f"ok:{user_id}:{'【希望納期】' in prompt}"

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
        self.assertEqual(len(service.spaces().messages().created_calls), 1)
        created = service.spaces().messages().created_calls[0]
        self.assertEqual(created["parent"], "spaces/AAA")
        self.assertEqual(created["body"]["thread"]["name"], "spaces/AAA/threads/TTT")
        self.assertIn("ok:999:True", created["body"]["text"])

    def test_handle_workspace_event_ignores_non_question_reaction(self):
        service = _ChatService()
        self.mod._build_chat_service = lambda: service
        self.mod._run_agent_query = lambda prompt, user_id: "ok"

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
        self.assertEqual(len(service.spaces().messages().created_calls), 0)


if __name__ == "__main__":
    unittest.main()

