import importlib.util
import os
from pathlib import Path
import sys
import types
import unittest


SECRET_CONFIG_PATH = Path("agent/tools/secret_config.py")


def _load_secret_config_module():
    spec = importlib.util.spec_from_file_location("secret_config_test", SECRET_CONFIG_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class SecretConfigTests(unittest.TestCase):
    def setUp(self):
        self._tracked_keys = [
            "google",
            "google.auth",
            "google.cloud",
            "google.cloud.secretmanager",
            "secret_config_test",
        ]
        self._orig_modules = {k: sys.modules.get(k) for k in self._tracked_keys}
        self._orig_env = dict(os.environ)

    def tearDown(self):
        for key in self._tracked_keys:
            if self._orig_modules[key] is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = self._orig_modules[key]
        os.environ.clear()
        os.environ.update(self._orig_env)

    def test_prefers_env_value(self):
        google = types.ModuleType("google")
        auth = types.ModuleType("google.auth")
        auth.default = lambda: (object(), "dummy-project")
        cloud = types.ModuleType("google.cloud")
        secretmanager = types.ModuleType("google.cloud.secretmanager")
        secretmanager.SecretManagerServiceClient = object
        cloud.secretmanager = secretmanager
        google.auth = auth
        google.cloud = cloud
        sys.modules["google"] = google
        sys.modules["google.auth"] = auth
        sys.modules["google.cloud"] = cloud
        sys.modules["google.cloud.secretmanager"] = secretmanager

        mod = _load_secret_config_module()
        os.environ["TEST_ENV"] = " env-value "
        value = mod.get_config_value(["TEST_ENV"], secret_name="dummy-secret", default="x")
        self.assertEqual(value, "env-value")

    def test_uses_secret_when_env_missing(self):
        google = types.ModuleType("google")
        auth = types.ModuleType("google.auth")
        auth.default = lambda: (object(), "dummy-project")

        class _Client:
            def access_secret_version(self, request):
                self.last_name = request["name"]
                payload = types.SimpleNamespace(data=b" secret-value ")
                return types.SimpleNamespace(payload=payload)

        cloud = types.ModuleType("google.cloud")
        secretmanager = types.ModuleType("google.cloud.secretmanager")
        secretmanager.SecretManagerServiceClient = _Client
        cloud.secretmanager = secretmanager
        google.auth = auth
        google.cloud = cloud

        sys.modules["google"] = google
        sys.modules["google.auth"] = auth
        sys.modules["google.cloud"] = cloud
        sys.modules["google.cloud.secretmanager"] = secretmanager

        mod = _load_secret_config_module()
        value = mod.get_config_value(["MISSING_ENV"], secret_name="my-secret", default="x")
        self.assertEqual(value, "secret-value")


if __name__ == "__main__":
    unittest.main()
