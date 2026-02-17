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

    def test_cors_configuration_supports_cookie_auth(self):
        source = APP_FILE.read_text(encoding="utf-8")
        self.assertIn("def _resolve_cors_origins", source)
        self.assertIn("CORS_ALLOW_ORIGINS", source)
        self.assertIn('if OIDC_ENABLED and "*" in origins', source)
        self.assertIn("allow_origins=_resolve_cors_origins()", source)
        self.assertIn("allow_credentials=OIDC_ENABLED", source)

    def test_cookie_samesite_is_dynamic(self):
        source = APP_FILE.read_text(encoding="utf-8")
        self.assertIn("def _cookie_samesite_value", source)
        self.assertIn('return "none" if _cookie_secure_flag(request) else "lax"', source)
        self.assertIn("samesite=_cookie_samesite_value(request)", source)

    def test_gateway_emits_a2a_trace_events(self):
        source = APP_FILE.read_text(encoding="utf-8")
        self.assertIn('"type": "a2a_trace"', source)
        self.assertIn('if tool_name in {"call_remote_agent", "call_master_agent"}', source)
        self.assertIn('"phase": "call"', source)
        self.assertIn('"phase": "result"', source)

    def test_ambiguous_prompt_guard_exists(self):
        source = APP_FILE.read_text(encoding="utf-8")
        self.assertIn("def _is_ambiguous_prompt", source)
        self.assertIn("def _build_clarification_message", source)
        self.assertIn("def _get_recent_turns", source)
        self.assertIn("def _remember_turn", source)
        self.assertIn("def _build_contextual_prompt", source)
        self.assertIn("if _is_ambiguous_prompt(message):", source)
        self.assertIn("recent_turns = _get_recent_turns(user_id, max_turns=2)", source)
        self.assertIn("message = _build_contextual_prompt(message, recent_turns)", source)
        self.assertIn('"message": "追加情報待ち"', source)
        self.assertIn('AMBIGUITY_PRESET_NAME = (os.environ.get("AMBIGUITY_PRESET") or "standard")', source)

    def test_ui_auth_gate_routes_exist(self):
        source = APP_FILE.read_text(encoding="utf-8")
        self.assertIn('@app.get("/login")', source)
        self.assertIn('@app.get("/app.js")', source)
        self.assertIn('@app.get("/style.css")', source)
        self.assertIn("RedirectResponse(url=\"/login\", status_code=302)", source)
        self.assertIn("def _resolve_ui_file", source)

    def test_chat_audit_logging_exists(self):
        source = APP_FILE.read_text(encoding="utf-8")
        self.assertIn("def _audit_chat_event", source)
        self.assertIn('event="text_request"', source)
        self.assertIn('event="text_response"', source)
        self.assertIn('event="voice_request"', source)
        self.assertIn('event="voice_response"', source)

    def test_model_routing_for_flash_pro_exists(self):
        source = APP_FILE.read_text(encoding="utf-8")
        self.assertIn("AGENT_RESOURCE_NAME_FLASH", source)
        self.assertIn("AGENT_RESOURCE_NAME_PRO", source)
        self.assertIn("MODEL_ROUTING_SCORE_THRESHOLD", source)
        self.assertIn("def _estimate_prompt_complexity", source)
        self.assertIn("def _resolve_agent_resource_name", source)
        self.assertIn("agent_resource_name, route = _resolve_agent_resource_name(original_message)", source)


if __name__ == "__main__":
    unittest.main()
