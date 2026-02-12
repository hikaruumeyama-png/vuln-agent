import importlib.util
import os
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parent
CHAT_TOOLS_PATH = ROOT / "agent" / "tools" / "chat_tools.py"
GMAIL_TOOLS_PATH = ROOT / "agent" / "tools" / "gmail_tools.py"
SETUP_CLOUD_PATH = ROOT / "setup_cloud.sh"


def _stub_google_modules() -> None:
    google = types.ModuleType("google")
    oauth2 = types.ModuleType("google.oauth2")
    service_account = types.ModuleType("google.oauth2.service_account")

    class _Creds:
        @staticmethod
        def from_service_account_file(*args, **kwargs):
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


class ConnectionEnvWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _stub_google_modules()
        _stub_secret_config_module()
        cls.chat_tools = _load_module("chat_tools_test", CHAT_TOOLS_PATH)
        cls.gmail_tools_source = GMAIL_TOOLS_PATH.read_text(encoding="utf-8")
        cls.setup_cloud_source = SETUP_CLOUD_PATH.read_text(encoding="utf-8")

    def setUp(self):
        for key in ("DEFAULT_CHAT_SPACE_ID", "CHAT_SPACE_ID", "GOOGLE_CHAT_SPACE_ID"):
            os.environ.pop(key, None)

    def test_resolve_space_id_uses_default_env(self):
        os.environ["DEFAULT_CHAT_SPACE_ID"] = "spaces/AAAA"
        self.assertEqual(self.chat_tools._resolve_space_id(), "spaces/AAAA")

    def test_resolve_space_id_supports_fallback_and_normalizes(self):
        os.environ["CHAT_SPACE_ID"] = " BBBB "
        self.assertEqual(self.chat_tools._resolve_space_id(), "spaces/BBBB")
        os.environ.pop("CHAT_SPACE_ID", None)
        os.environ["GOOGLE_CHAT_SPACE_ID"] = " spaces/CCCC "
        self.assertEqual(self.chat_tools._resolve_space_id(), "spaces/CCCC")

    def test_gmail_tools_supports_workspace_env_alias(self):
        self.assertIn('["GMAIL_USER_EMAIL", "GOOGLE_WORKSPACE_USER_EMAIL"]', self.gmail_tools_source)
        self.assertIn('secret_name="vuln-agent-gmail-oauth-token"', self.gmail_tools_source)
        self.assertIn('secret_name="vuln-agent-gmail-user-email"', self.gmail_tools_source)

    def test_chat_tools_uses_chat_secret_fallback(self):
        chat_source = CHAT_TOOLS_PATH.read_text(encoding="utf-8")
        self.assertIn('secret_name="vuln-agent-chat-space-id"', chat_source)

    def test_setup_cloud_has_gmail_user_secret(self):
        self.assertIn("vuln-agent-gmail-user-email", self.setup_cloud_source)
        self.assertIn("GMAIL_USER_EMAIL=$(_sm_get vuln-agent-gmail-user-email)", self.setup_cloud_source)


if __name__ == "__main__":
    unittest.main()
