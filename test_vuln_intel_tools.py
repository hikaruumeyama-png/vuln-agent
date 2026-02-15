import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent
TOOLS_PATH = ROOT / "agent" / "tools" / "vuln_intel_tools.py"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class _FakeResponse:
    def __init__(self, body: str):
        self._body = body.encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        _ = (exc_type, exc, tb)
        return False


class VulnIntelToolsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module("vuln_intel_tools_test_module", TOOLS_PATH)

    @patch("urllib.request.urlopen")
    def test_get_nvd_cve_details_success(self, mock_urlopen):
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "published": "2025-01-01T00:00:00.000",
                        "lastModified": "2025-01-02T00:00:00.000",
                        "sourceIdentifier": "nvd@nist.gov",
                        "descriptions": [{"lang": "en", "value": "test vuln"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "version": "3.1",
                                        "baseScore": 9.8,
                                        "baseSeverity": "CRITICAL",
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    }
                                }
                            ]
                        },
                        "references": [{"url": "https://example.com/ref1"}],
                    }
                }
            ]
        }
        mock_urlopen.return_value = _FakeResponse(json.dumps(payload))

        result = self.mod.get_nvd_cve_details("CVE-2025-1234")
        self.assertEqual(result["status"], "success")
        self.assertTrue(result["found"])
        self.assertEqual(result["cve_id"], "CVE-2025-1234")
        self.assertEqual(result["cvss"]["base_score"], 9.8)

    @patch("urllib.request.urlopen")
    def test_search_osv_vulnerabilities_success(self, mock_urlopen):
        payload = {
            "vulns": [
                {
                    "id": "OSV-2025-1",
                    "summary": "sample vuln",
                    "aliases": ["CVE-2025-1234"],
                    "references": [{"url": "https://osv.dev/vulnerability/OSV-2025-1"}],
                }
            ]
        }
        mock_urlopen.return_value = _FakeResponse(json.dumps(payload))

        result = self.mod.search_osv_vulnerabilities("PyPI", "requests", "2.31.0")
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["vulnerabilities"][0]["id"], "OSV-2025-1")

    def test_search_osv_vulnerabilities_requires_fields(self):
        result = self.mod.search_osv_vulnerabilities("", "")
        self.assertEqual(result["status"], "error")


if __name__ == "__main__":
    unittest.main()
