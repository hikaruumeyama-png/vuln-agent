import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent
WEB_TOOLS_PATH = ROOT / "agent" / "tools" / "web_tools.py"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class _FakeResponse:
    def __init__(self, body: str, content_type: str = "application/json"):
        self._body = body.encode("utf-8")
        self.headers = {"Content-Type": content_type}

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        _ = (exc_type, exc, tb)
        return False


class WebToolsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module("web_tools_test_module", WEB_TOOLS_PATH)

    def test_is_safe_public_url(self):
        self.assertTrue(self.mod._is_safe_public_url("https://example.com/a"))
        self.assertFalse(self.mod._is_safe_public_url("file:///etc/passwd"))
        self.assertFalse(self.mod._is_safe_public_url("http://localhost:8080"))
        self.assertFalse(self.mod._is_safe_public_url("http://127.0.0.1:8080"))

    @patch("urllib.request.urlopen")
    def test_web_search_success(self, mock_urlopen):
        body = json.dumps(
            {
                "Heading": "Test Heading",
                "AbstractText": "Test summary",
                "AbstractURL": "https://example.com/overview",
                "RelatedTopics": [
                    {"Text": "Result A", "FirstURL": "https://example.com/a"},
                    {"Text": "Result B", "FirstURL": "https://example.com/b"},
                ],
            }
        )
        mock_urlopen.return_value = _FakeResponse(body, "application/json")

        result = self.mod.web_search("test")
        self.assertEqual(result["status"], "success")
        self.assertGreaterEqual(result["count"], 1)
        self.assertIn("results", result)

    @patch("urllib.request.urlopen")
    def test_fetch_web_content_html(self, mock_urlopen):
        html = "<html><head><title>x</title></head><body><h1>Hello</h1><p>World</p></body></html>"
        mock_urlopen.return_value = _FakeResponse(html, "text/html; charset=utf-8")

        result = self.mod.fetch_web_content("https://example.com/doc")
        self.assertEqual(result["status"], "success")
        self.assertIn("Hello", result["content"])
        self.assertIn("World", result["content"])


if __name__ == "__main__":
    unittest.main()
