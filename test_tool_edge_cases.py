import importlib.util
import os
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parent
CHAT_TOOLS_PATH = ROOT / "agent" / "tools" / "chat_tools.py"
GMAIL_TOOLS_PATH = ROOT / "agent" / "tools" / "gmail_tools.py"


def _stub_google_modules() -> None:
    google = types.ModuleType("google")
    oauth2 = types.ModuleType("google.oauth2")
    service_account = types.ModuleType("google.oauth2.service_account")

    class _Creds:
        @staticmethod
        def from_service_account_file(*args, **kwargs):
            return object()

        @staticmethod
        def from_service_account_info(*args, **kwargs):
            return object()

    service_account.Credentials = _Creds
    oauth2.service_account = service_account
    google.oauth2 = oauth2

    googleapiclient = types.ModuleType("googleapiclient")
    discovery = types.ModuleType("googleapiclient.discovery")
    discovery.build = lambda *args, **kwargs: object()
    googleapiclient.discovery = discovery
    errors = types.ModuleType("googleapiclient.errors")
    errors.HttpError = type("HttpError", (Exception,), {"resp": None})
    googleapiclient.errors = errors

    sys.modules["google"] = google
    sys.modules["google.oauth2"] = oauth2
    sys.modules["google.oauth2.service_account"] = service_account
    sys.modules["googleapiclient"] = googleapiclient
    sys.modules["googleapiclient.discovery"] = discovery
    sys.modules["googleapiclient.errors"] = errors


def _stub_secret_config_module() -> None:
    mod = types.ModuleType("secret_config")

    def get_config_value(env_names, secret_name=None, default=""):
        for env_name in env_names:
            value = (os.environ.get(env_name) or "").strip()
            if value:
                return value
        return default

    mod.get_config_value = get_config_value
    sys.modules["secret_config"] = mod


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class _FakeMessageListCall:
    def __init__(self, max_results: int):
        self.max_results = max_results

    def execute(self):
        return {"messages": []}


class _FakeMessagesResource:
    def __init__(self):
        self.last_max_results = None
        self.last_query = None

    def list(self, userId, q, maxResults):
        self.last_max_results = maxResults
        self.last_query = q
        return _FakeMessageListCall(maxResults)


class _FakeUsersResource:
    def __init__(self):
        self.messages_resource = _FakeMessagesResource()

    def messages(self):
        return self.messages_resource


class _FakeGmailService:
    def __init__(self):
        self.users_resource = _FakeUsersResource()

    def users(self):
        return self.users_resource


class ToolEdgeCaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _stub_google_modules()
        _stub_secret_config_module()
        cls.chat_tools = _load_module("chat_tools_edge_test", CHAT_TOOLS_PATH)
        cls.gmail_tools = _load_module("gmail_tools_edge_test", GMAIL_TOOLS_PATH)

    def setUp(self):
        for key in ("DEFAULT_CHAT_SPACE_ID", "CHAT_SPACE_ID", "GOOGLE_CHAT_SPACE_ID"):
            os.environ.pop(key, None)

    def tearDown(self):
        for key in ("DEFAULT_CHAT_SPACE_ID", "CHAT_SPACE_ID", "GOOGLE_CHAT_SPACE_ID"):
            os.environ.pop(key, None)

    def test_gmail_decode_body_invalid_data_returns_empty(self):
        self.assertEqual(self.gmail_tools._decode_body("%%%"), "")
        self.assertEqual(self.gmail_tools._decode_body(""), "")

    def test_gmail_mark_email_as_read_requires_email_id(self):
        result = self.gmail_tools.mark_email_as_read("  ")
        self.assertEqual(result["status"], "error")
        self.assertIn("email_id", result["message"])

    def test_gmail_get_unread_emails_normalizes_max_results(self):
        fake_service = _FakeGmailService()
        self.gmail_tools._get_gmail_service = lambda: fake_service
        self.gmail_tools._get_email_detail = lambda service, message_id: {"id": message_id}

        self.gmail_tools.get_unread_emails(max_results=0)
        self.assertEqual(fake_service.users().messages().last_max_results, 1)

        self.gmail_tools.get_unread_emails(max_results=9999)
        self.assertEqual(fake_service.users().messages().last_max_results, 100)

        self.gmail_tools.get_unread_emails(max_results="abc")
        self.assertEqual(fake_service.users().messages().last_max_results, 10)

    def test_gmail_get_sidfm_emails_uses_or_between_sender_and_subject(self):
        fake_service = _FakeGmailService()
        self.gmail_tools._get_gmail_service = lambda: fake_service
        os.environ.pop("SIDFM_SENDER_EMAIL", None)

        self.gmail_tools.get_sidfm_emails()

        query = fake_service.users().messages().last_query
        self.assertIn("from:noreply@sidfm.com", query)
        self.assertIn('subject:"[SIDfm]"', query)
        self.assertIn(" OR ", query)
        self.assertIn("is:unread", query)

    def test_chat_resolve_space_id_uses_env_when_argument_is_blank(self):
        os.environ["DEFAULT_CHAT_SPACE_ID"] = "spaces/AAAA"
        self.assertEqual(self.chat_tools._resolve_space_id("   "), "spaces/AAAA")

    def test_chat_resolve_space_id_accepts_non_string_input(self):
        self.assertEqual(self.chat_tools._resolve_space_id(12345), "spaces/12345")


if __name__ == "__main__":
    unittest.main()
