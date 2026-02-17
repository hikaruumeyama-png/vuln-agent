import importlib.util
import os
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent
TOOLS_PATH = ROOT / "agent" / "tools" / "config_tools.py"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class ConfigToolsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module("config_tools_test_module", TOOLS_PATH)

    def test_list_known_config_keys(self):
        result = self.mod.list_known_config_keys()
        self.assertEqual(result["status"], "success")
        self.assertGreater(result["count"], 0)
        self.assertIn("project_id", result["keys"])

    def test_get_runtime_config_snapshot_masks_values(self):
        os.environ["GCP_PROJECT_ID"] = "test-project-1234"
        result = self.mod.get_runtime_config_snapshot(keys=["project_id"], mask_values=True)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["count"], 1)
        value = result["configs"]["project_id"]["value"]
        self.assertNotEqual(value, "test-project-1234")
        self.assertTrue(value.startswith("te"))


if __name__ == "__main__":
    unittest.main()

