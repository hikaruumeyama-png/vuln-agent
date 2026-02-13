import ast
from pathlib import Path
import unittest


APP_FILE = Path(__file__).with_name("app.py")


def _load_app_tree() -> ast.Module:
    return ast.parse(APP_FILE.read_text(encoding="utf-8"))


class HealthEndpointTests(unittest.TestCase):
    def test_health_routes_are_declared(self):
        tree = _load_app_tree()
        expected_paths = {"/healthz", "/healthz/", "/health", "/health/"}
        declared_paths: set[str] = set()

        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call):
                    continue
                if not isinstance(dec.func, ast.Attribute):
                    continue
                if dec.func.attr != "get":
                    continue
                if not dec.args:
                    continue
                arg0 = dec.args[0]
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                    declared_paths.add(arg0.value)

        self.assertTrue(
            expected_paths.issubset(declared_paths),
            f"missing endpoints: {sorted(expected_paths - declared_paths)}",
        )

    def test_healthz_header_filter_uses_allowlist(self):
        tree = _load_app_tree()
        target = None

        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name == "_safe_healthz_headers":
                target = node
                break

        self.assertIsNotNone(target, "_safe_healthz_headers function not found")

        source = ast.get_source_segment(APP_FILE.read_text(encoding="utf-8"), target) or ""
        self.assertIn("HEALTHZ_HEADER_ALLOWLIST", source)
        self.assertIn("request.headers.items()", source)
        self.assertIn("key.lower()", source)

    def test_query_agent_emits_request_id_and_progress(self):
        source = APP_FILE.read_text(encoding="utf-8")
        self.assertIn('"request_id": request_id', source)
        self.assertIn('"progress": {', source)
        self.assertIn('"total_tool_calls": total_tool_calls', source)
        self.assertIn('"completed_tool_calls": completed_tool_calls', source)

    def test_error_detail_helper_exists(self):
        source = APP_FILE.read_text(encoding="utf-8")
        self.assertIn("def _extract_error_detail", source)
        self.assertIn('for field in direct_fields', source)
        self.assertIn('for container_key in ("error", "result", "response")', source)


if __name__ == "__main__":
    unittest.main()
