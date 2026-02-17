import asyncio
import base64
import binascii
from collections import deque
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
import urllib.parse
import urllib.request
import uuid
from typing import Any

import jwt
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import vertexai
from vertexai import Client

try:
    from .live_api import GeminiLiveClient
except ImportError:
    from live_api import GeminiLiveClient

GCP_PROJECT_ID = os.environ.get("GCP_PROJECT_ID")
GCP_LOCATION = os.environ.get("GCP_LOCATION", "asia-northeast1")
AGENT_RESOURCE_NAME = os.environ.get("AGENT_RESOURCE_NAME")
AGENT_RESOURCE_NAME_FLASH = os.environ.get("AGENT_RESOURCE_NAME_FLASH")
AGENT_RESOURCE_NAME_PRO = os.environ.get("AGENT_RESOURCE_NAME_PRO")
LIVE_GREETING_TEXT = os.environ.get(
    "LIVE_GREETING_TEXT",
    "こんにちは。脆弱性管理AIエージェントです。ご要望をどうぞ。",
)
OIDC_ENABLED = os.environ.get("OIDC_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
OIDC_TENANT_ID = os.environ.get("OIDC_TENANT_ID", "").strip()
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "").strip()
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "").strip()
OIDC_ISSUER = os.environ.get("OIDC_ISSUER", "").strip() or (
    f"https://login.microsoftonline.com/{OIDC_TENANT_ID}/v2.0" if OIDC_TENANT_ID else ""
)
OIDC_SCOPES = os.environ.get("OIDC_SCOPES", "openid profile email").strip()
OIDC_REDIRECT_URI = os.environ.get("OIDC_REDIRECT_URI", "").strip()
OIDC_SESSION_SECRET = os.environ.get("OIDC_SESSION_SECRET", "").strip()
OIDC_SESSION_COOKIE_NAME = os.environ.get("OIDC_SESSION_COOKIE_NAME", "vuln_agent_session").strip()
OIDC_STATE_COOKIE_NAME = os.environ.get("OIDC_STATE_COOKIE_NAME", "vuln_agent_oidc_state").strip()
OIDC_SESSION_TTL_SEC = 8 * 60 * 60
OIDC_STATE_TTL_SEC = 10 * 60
CORS_ALLOW_ORIGINS_RAW = os.environ.get("CORS_ALLOW_ORIGINS", "").strip()
_oidc_metadata_cache: dict[str, Any] | None = None
_oidc_metadata_cache_at = 0.0

TOOL_DISPLAY_MAP: dict[str, dict[str, str]] = {
    "get_sidfm_emails":         {"label": "SIDfm脆弱性メールを取得中",     "icon": "mail"},
    "get_unread_emails":        {"label": "未読メールを確認中",           "icon": "mail"},
    "mark_email_as_read":       {"label": "メールを既読にマーク中",       "icon": "mail-check"},
    "check_gmail_connection":   {"label": "Gmail接続を確認中",           "icon": "mail"},
    "search_sbom_by_purl":      {"label": "SBOMをパッケージURLで検索中",   "icon": "search"},
    "search_sbom_by_product":   {"label": "SBOMを製品名で検索中",         "icon": "search"},
    "get_sbom_contents":        {"label": "SBOM一覧を取得中",             "icon": "list"},
    "list_sbom_package_types":  {"label": "SBOM type一覧を取得中",        "icon": "list"},
    "count_sbom_packages_by_type": {"label": "SBOM type別件数を集計中",   "icon": "bar-chart-3"},
    "list_sbom_packages_by_type": {"label": "SBOMをtype指定で取得中",     "icon": "filter"},
    "list_sbom_package_versions": {"label": "パッケージの版一覧を取得中",  "icon": "history"},
    "get_sbom_entry_by_purl":   {"label": "PURLでSBOMを1件取得中",       "icon": "target"},
    "get_affected_systems":     {"label": "影響を受けるシステムを特定中",   "icon": "server"},
    "get_owner_mapping":        {"label": "システムオーナーを検索中",      "icon": "users"},
    "send_vulnerability_alert": {"label": "脆弱性アラートを送信中",       "icon": "alert-triangle"},
    "send_simple_message":      {"label": "通知を送信中",               "icon": "message-square"},
    "check_chat_connection":    {"label": "Chat接続を確認中",            "icon": "message-square"},
    "list_space_members":       {"label": "スペースメンバーを取得中",     "icon": "users"},
    "log_vulnerability_history": {"label": "脆弱性履歴を記録中",         "icon": "database"},
    "register_remote_agent":    {"label": "リモートエージェントを登録中",  "icon": "link"},
    "call_remote_agent":        {"label": "リモートエージェントを呼出中",  "icon": "link"},
    "list_registered_agents":   {"label": "登録済エージェントを取得中",    "icon": "link"},
    "create_jira_ticket_request": {"label": "Jiraチケットを作成中",      "icon": "clipboard"},
    "create_approval_request":  {"label": "承認リクエストを作成中",       "icon": "check-circle"},
    "list_sidfm_email_subjects": {"label": "SIDfm件名一覧を取得中",        "icon": "list"},
    "list_unread_email_ids":    {"label": "未読メールID一覧を取得中",      "icon": "list"},
    "get_email_preview_by_id":  {"label": "メールプレビューを取得中",      "icon": "mail-open"},
    "get_chat_space_info":      {"label": "Chatスペース情報を取得中",      "icon": "message-square"},
    "list_chat_member_emails":  {"label": "Chatメンバー一覧を取得中",      "icon": "users"},
    "build_history_record_preview": {"label": "履歴レコードを組立中",      "icon": "clipboard"},
    "list_registered_agent_ids": {"label": "連携エージェントIDを取得中",    "icon": "list"},
    "get_registered_agent_details": {"label": "連携エージェント詳細を取得中","icon": "info"},
    "get_configured_bigquery_tables": {"label": "BQ設定テーブルを確認中",   "icon": "database"},
    "check_bigquery_readability_summary": {"label": "BQ読取可否を確認中",   "icon": "shield-check"},
    "list_web_search_urls":     {"label": "検索URL一覧を取得中",           "icon": "globe"},
    "get_web_content_excerpt":  {"label": "Web本文抜粋を取得中",           "icon": "file-text"},
    "get_nvd_cvss_summary":     {"label": "NVD CVSS要約を取得中",          "icon": "activity"},
    "list_osv_vulnerability_ids": {"label": "OSV脆弱性ID一覧を取得中",      "icon": "list"},
    "save_vulnerability_history_minimal": {"label": "最小履歴を保存中",      "icon": "database"},
}
AMBIGUOUS_PROMPT_EXACT = {
    "?",
    "？",
    "help",
    "ヘルプ",
    "お願い",
    "お願いします",
    "教えて",
    "調べて",
    "確認して",
    "これ",
    "それ",
    "あれ",
    "この件",
    "その件",
    "上記",
}
AMBIGUITY_PRESETS = {
    "strict": {"min_chars_without_context": 6},
    "standard": {"min_chars_without_context": 4},
    "relaxed": {"min_chars_without_context": 2},
}
AMBIGUITY_PRESET_NAME = (os.environ.get("AMBIGUITY_PRESET") or "standard").strip().lower()
if AMBIGUITY_PRESET_NAME not in AMBIGUITY_PRESETS:
    AMBIGUITY_PRESET_NAME = "standard"
AMBIGUITY_PRESET = AMBIGUITY_PRESETS[AMBIGUITY_PRESET_NAME]
AMBIGUOUS_REFERENCE_TOKENS = ("これ", "それ", "あれ", "この件", "その件", "上記", "さっき", "先ほど")
CLEAR_CONTEXT_KEYWORDS = (
    "cve-",
    "cwe-",
    "cvss",
    "osv",
    "nvd",
    "sbom",
    "sidfm",
    "purl",
    "bigquery",
    "gmail",
    "chat",
    "jira",
    "脆弱性",
    "パッケージ",
    "システム",
    "通知",
    "担当者",
    "メール",
    "製品",
)
COMPLEXITY_KEYWORDS = (
    "比較",
    "違い",
    "優先順位",
    "トレードオフ",
    "設計",
    "アーキテクチャ",
    "戦略",
    "根拠",
    "検証",
    "段階",
    "手順",
    "実装",
    "移行",
    "分析",
    "影響範囲",
    "原因",
    "対策",
    "why",
    "compare",
    "trade-off",
    "architecture",
    "design",
    "plan",
)
STRUCTURED_OUTPUT_HINTS = (
    "表で",
    "表形式",
    "箇条書き",
    "json",
    "yaml",
    "手順書",
    "チェックリスト",
    "テンプレート",
    "章立て",
)
MULTI_INTENT_HINTS = (
    "かつ",
    "また",
    "さらに",
    "加えて",
    "その上で",
    "うえで",
    "and",
    "also",
    "then",
)
MODEL_ROUTING_ENABLED = (os.environ.get("MODEL_ROUTING_ENABLED", "true") or "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
try:
    MODEL_ROUTING_SCORE_THRESHOLD = int((os.environ.get("MODEL_ROUTING_SCORE_THRESHOLD") or "4").strip())
except Exception:
    MODEL_ROUTING_SCORE_THRESHOLD = 4
if MODEL_ROUTING_SCORE_THRESHOLD < 1:
    MODEL_ROUTING_SCORE_THRESHOLD = 1

logger = logging.getLogger(__name__)
RECENT_TURNS: dict[str, deque[dict[str, str]]] = {}
MAX_RECENT_TURNS = 4

HEALTHZ_HEADER_ALLOWLIST = {
    "host",
    "user-agent",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-cloud-trace-context",
}


def _tool_display_message(tool_name: str) -> str:
    return TOOL_DISPLAY_MAP.get(tool_name, {}).get("label", f"{tool_name} を実行中")


def _tool_display_icon(tool_name: str) -> str:
    return TOOL_DISPLAY_MAP.get(tool_name, {}).get("icon", "wrench")


def _is_ambiguous_prompt(prompt: str) -> bool:
    normalized = " ".join((prompt or "").strip().split()).lower()
    if not normalized:
        return True
    if normalized in AMBIGUOUS_PROMPT_EXACT:
        return True
    if re.fullmatch(r"[?？!！。,.、\s]+", normalized):
        return True
    has_context = any(keyword in normalized for keyword in CLEAR_CONTEXT_KEYWORDS)
    min_chars = int(AMBIGUITY_PRESET.get("min_chars_without_context", 4))
    if len(normalized) < min_chars and not has_context:
        return True
    if any(token in normalized for token in AMBIGUOUS_REFERENCE_TOKENS) and not has_context:
        return True
    return False


def _build_clarification_message() -> str:
    return (
        "ぶれた回答を防ぐため、意図を正確に把握したいです。もう少し具体化してください。\n"
        "1) 対象（例: CVE番号 / 製品名 / システム名）\n"
        "2) 知りたい内容（影響範囲 / 優先度 / 対応方法 など）"
    )


def _estimate_prompt_complexity(prompt: str) -> dict[str, Any]:
    text = (prompt or "").strip()
    normalized = " ".join(text.split()).lower()
    score = 0
    reasons: list[str] = []

    if len(normalized) >= 180:
        score += 2
        reasons.append("long_input")
    elif len(normalized) >= 80:
        score += 1
        reasons.append("mid_length_input")

    if text.count("\n") >= 3:
        score += 1
        reasons.append("multi_line_request")

    cve_count = len(re.findall(r"\bcve-\d{4}-\d{4,7}\b", normalized))
    if cve_count >= 2:
        score += 2
        reasons.append("multiple_cves")

    if sum(1 for token in MULTI_INTENT_HINTS if token in normalized) >= 2:
        score += 2
        reasons.append("multi_intent")

    if any(token in normalized for token in COMPLEXITY_KEYWORDS):
        score += 2
        reasons.append("analysis_or_planning")

    if any(token in normalized for token in STRUCTURED_OUTPUT_HINTS):
        score += 1
        reasons.append("structured_output")

    if normalized.count("?") + normalized.count("？") >= 2:
        score += 1
        reasons.append("multi_questions")

    return {
        "score": score,
        "tier": "pro" if score >= MODEL_ROUTING_SCORE_THRESHOLD else "flash",
        "reasons": reasons,
        "threshold": MODEL_ROUTING_SCORE_THRESHOLD,
    }


def _resolve_agent_resource_name(prompt: str) -> tuple[str, dict[str, Any]]:
    base_resource = (AGENT_RESOURCE_NAME or "").strip()
    flash_resource = (AGENT_RESOURCE_NAME_FLASH or "").strip() or base_resource
    pro_resource = (AGENT_RESOURCE_NAME_PRO or "").strip() or base_resource

    if not MODEL_ROUTING_ENABLED:
        selected = base_resource or pro_resource or flash_resource
        return selected, {"routing_enabled": False, "tier": "single", "score": 0, "reasons": ["routing_disabled"]}

    if not flash_resource or not pro_resource:
        selected = base_resource or pro_resource or flash_resource
        return selected, {
            "routing_enabled": False,
            "tier": "single",
            "score": 0,
            "reasons": ["missing_flash_or_pro_resource"],
        }

    complexity = _estimate_prompt_complexity(prompt)
    selected = pro_resource if complexity["tier"] == "pro" else flash_resource
    return selected, {"routing_enabled": True, **complexity}


def _get_recent_turns(user_id: str, max_turns: int = 2) -> list[dict[str, str]]:
    turns = list(RECENT_TURNS.get(user_id) or [])
    if not turns:
        return []
    return turns[-max_turns:]


def _remember_turn(user_id: str, user_prompt: str, assistant_text: str) -> None:
    if not user_id or not user_prompt.strip():
        return
    if user_id not in RECENT_TURNS:
        RECENT_TURNS[user_id] = deque(maxlen=MAX_RECENT_TURNS)
    RECENT_TURNS[user_id].append(
        {
            "user": user_prompt.strip(),
            "assistant": (assistant_text or "").strip()[:300],
        }
    )


def _build_contextual_prompt(original_prompt: str, recent_turns: list[dict[str, str]]) -> str:
    if not recent_turns:
        return original_prompt
    lines: list[str] = ["以下は直近の会話文脈です。必要な範囲で参照してください。"]
    for idx, turn in enumerate(recent_turns, start=1):
        user_text = (turn.get("user") or "").strip()
        assistant_text = (turn.get("assistant") or "").strip()
        if user_text:
            lines.append(f"- 直近{idx}件前のユーザー発話: {user_text}")
        if assistant_text:
            lines.append(f"- 直近{idx}件前のあなたの回答要約: {assistant_text}")
    lines.append("")
    lines.append(f"現在のユーザー発話: {original_prompt}")
    return "\n".join(lines).strip()


def _safe_healthz_headers(request: Request) -> dict[str, str]:
    return {
        key: value
        for key, value in request.headers.items()
        if key.lower() in HEALTHZ_HEADER_ALLOWLIST
    }


def _base64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _base64url_decode(raw: str) -> bytes:
    padded = raw + ("=" * (-len(raw) % 4))
    return base64.urlsafe_b64decode(padded.encode("utf-8"))


def _sign_value(payload: dict[str, Any], ttl_sec: int) -> str:
    if not OIDC_SESSION_SECRET:
        raise RuntimeError("OIDC_SESSION_SECRET is required when OIDC is enabled.")
    body = dict(payload)
    body["exp"] = int(time.time()) + int(ttl_sec)
    body_json = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    body_b64 = _base64url_encode(body_json)
    sig = hmac.new(
        OIDC_SESSION_SECRET.encode("utf-8"),
        body_b64.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return f"{body_b64}.{_base64url_encode(sig)}"


def _verify_signed_value(value: str | None) -> dict[str, Any] | None:
    if not value or "." not in value or not OIDC_SESSION_SECRET:
        return None
    try:
        body_b64, sig_b64 = value.split(".", 1)
        expected_sig = hmac.new(
            OIDC_SESSION_SECRET.encode("utf-8"),
            body_b64.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        provided_sig = _base64url_decode(sig_b64)
        if not hmac.compare_digest(expected_sig, provided_sig):
            return None
        payload = json.loads(_base64url_decode(body_b64).decode("utf-8"))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload
    except Exception:
        # 壊れたCookieは未認証として扱う（500を避ける）。
        return None


def _is_oidc_ready() -> bool:
    return bool(
        OIDC_ENABLED
        and OIDC_ISSUER
        and OIDC_CLIENT_ID
        and OIDC_CLIENT_SECRET
        and OIDC_SESSION_SECRET
    )


def _resolve_base_url_from_request(request: Request) -> str:
    forwarded_proto = (request.headers.get("x-forwarded-proto") or "").strip()
    scheme = forwarded_proto or request.url.scheme
    host = request.headers.get("host") or request.url.netloc
    return f"{scheme}://{host}"


def _cookie_secure_flag(request: Request) -> bool:
    base = _resolve_base_url_from_request(request)
    return base.lower().startswith("https://")


def _cookie_samesite_value(request: Request) -> str:
    # SameSite=None は Secure 必須。http 開発環境では Lax にフォールバックする。
    return "none" if _cookie_secure_flag(request) else "lax"


def _resolve_redirect_uri(request: Request) -> str:
    if OIDC_REDIRECT_URI:
        return OIDC_REDIRECT_URI
    return f"{_resolve_base_url_from_request(request)}/auth/callback"


def _get_oidc_metadata() -> dict[str, Any]:
    global _oidc_metadata_cache, _oidc_metadata_cache_at
    if _oidc_metadata_cache and (time.time() - _oidc_metadata_cache_at < 3600):
        return _oidc_metadata_cache
    if not OIDC_ISSUER:
        raise RuntimeError("OIDC_ISSUER is not configured.")
    url = f"{OIDC_ISSUER.rstrip('/')}/.well-known/openid-configuration"
    with urllib.request.urlopen(url, timeout=15) as resp:
        metadata = json.loads(resp.read().decode("utf-8", errors="replace"))
    _oidc_metadata_cache = metadata
    _oidc_metadata_cache_at = time.time()
    return metadata


def _exchange_code_for_token(code: str, redirect_uri: str) -> dict[str, Any]:
    metadata = _get_oidc_metadata()
    token_endpoint = metadata.get("token_endpoint")
    if not token_endpoint:
        raise RuntimeError("OIDC token_endpoint not found.")
    body = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "client_id": OIDC_CLIENT_ID,
            "client_secret": OIDC_CLIENT_SECRET,
            "code": code,
            "redirect_uri": redirect_uri,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        token_endpoint,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def _validate_id_token(id_token: str, expected_nonce: str) -> dict[str, Any]:
    metadata = _get_oidc_metadata()
    jwks_uri = metadata.get("jwks_uri")
    issuer = metadata.get("issuer") or OIDC_ISSUER
    if not jwks_uri:
        raise RuntimeError("OIDC jwks_uri not found.")
    jwk_client = jwt.PyJWKClient(jwks_uri)
    signing_key = jwk_client.get_signing_key_from_jwt(id_token)
    claims = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256", "RS384", "RS512"],
        audience=OIDC_CLIENT_ID,
        issuer=issuer,
    )
    if expected_nonce and claims.get("nonce") != expected_nonce:
        raise RuntimeError("OIDC nonce mismatch.")
    return claims


def _build_post_login_redirect(next_url: str) -> str:
    safe_next = (next_url or "").strip()
    if not safe_next:
        return "/"
    parsed = urllib.parse.urlparse(safe_next)
    if parsed.scheme or parsed.netloc:
        return "/"
    if not safe_next.startswith("/"):
        return "/"
    return safe_next


def _get_session_user_from_cookie(cookies: dict[str, str]) -> dict[str, Any] | None:
    payload = _verify_signed_value(cookies.get(OIDC_SESSION_COOKIE_NAME))
    if not payload:
        return None
    return {
        "sub": payload.get("sub", ""),
        "name": payload.get("name", ""),
        "email": payload.get("email", ""),
    }


def _is_error_response(response_data: Any) -> bool:
    return isinstance(response_data, dict) and (
        response_data.get("status") == "error" or "error" in response_data
    )


def _extract_error_detail(response_data: Any) -> str | None:
    if not isinstance(response_data, dict):
        return None

    direct_fields = ("message", "error", "detail", "reason")
    for field in direct_fields:
        value = response_data.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip()

    for container_key in ("error", "result", "response"):
        container = response_data.get(container_key)
        if not isinstance(container, dict):
            continue
        for field in direct_fields:
            value = container.get(field)
            if isinstance(value, str) and value.strip():
                return value.strip()

    return None


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return {}
    return {}


def _preview_text(value: Any, limit: int = 280) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[:limit] + "..."


def _extract_a2a_call_text(tool_name: str, args: dict[str, Any]) -> str:
    if tool_name == "call_remote_agent":
        return str(args.get("message") or "").strip()
    if tool_name == "call_master_agent":
        explicit = str(args.get("message") or "").strip()
        if explicit:
            return explicit
        objective = str(args.get("objective") or "").strip()
        task_type = str(args.get("task_type") or "").strip()
        actions = args.get("requested_actions") or []
        action_text = ""
        if isinstance(actions, list):
            values = [str(x).strip() for x in actions if str(x).strip()]
            if values:
                action_text = " / ".join(values[:2])
        if objective and action_text:
            return f"{objective} ({action_text})"
        if objective:
            return objective
        if task_type:
            return task_type
    return ""


def _extract_a2a_request_text_from_result(payload: dict[str, Any]) -> str:
    handoff = payload.get("handoff")
    if isinstance(handoff, dict):
        objective = str(handoff.get("objective") or "").strip()
        task_type = str(handoff.get("task_type") or "").strip()
        actions = handoff.get("requested_actions") or []
        action_text = ""
        if isinstance(actions, list):
            values = [str(x).strip() for x in actions if str(x).strip()]
            if values:
                action_text = "\n".join(f"- {v}" for v in values[:4])
        lines: list[str] = []
        if task_type:
            lines.append(f"種別: {task_type}")
        if objective:
            lines.append(f"目的: {objective}")
        if action_text:
            lines.append(f"依頼アクション:\n{action_text}")
        if lines:
            return "\n".join(lines).strip()

    candidate = str(payload.get("message") or "").strip()
    if candidate:
        return candidate
    return ""


async def _safe_send(websocket: WebSocket, data: dict[str, Any]) -> None:
    """Send JSON via WebSocket, silently ignoring disconnection errors."""
    try:
        await websocket.send_text(json.dumps(data, ensure_ascii=False))
    except Exception:
        pass


app = FastAPI()


def _resolve_cors_origins() -> list[str]:
    if CORS_ALLOW_ORIGINS_RAW:
        origins = [o.strip() for o in CORS_ALLOW_ORIGINS_RAW.split(",") if o.strip()]
        if OIDC_ENABLED and "*" in origins:
            origins = [o for o in origins if o != "*"]
        if origins:
            return origins
    if OIDC_ENABLED:
        # Cookie 認証が必要なデフォルト開発オリジンを明示許可する。
        return [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ]
    return ["*"]


app.add_middleware(
    CORSMiddleware,
    allow_origins=_resolve_cors_origins(),
    allow_credentials=OIDC_ENABLED,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _init_vertex() -> Client:
    has_any_resource = bool(
        (AGENT_RESOURCE_NAME or "").strip()
        or (AGENT_RESOURCE_NAME_FLASH or "").strip()
        or (AGENT_RESOURCE_NAME_PRO or "").strip()
    )
    if not GCP_PROJECT_ID or not has_any_resource:
        raise RuntimeError("GCP_PROJECT_ID と AGENT_RESOURCE_NAME(系) が未設定です。")
    vertexai.init(project=GCP_PROJECT_ID, location=GCP_LOCATION)
    return Client(project=GCP_PROJECT_ID, location=GCP_LOCATION)


async def _query_agent(
    client: Client, message: str, websocket: WebSocket, user_id: str,
) -> dict[str, Any]:
    request_id = f"req-{uuid.uuid4().hex[:10]}"
    original_message = message
    if _is_ambiguous_prompt(message):
        recent_turns = _get_recent_turns(user_id, max_turns=2)
        if recent_turns:
            message = _build_contextual_prompt(message, recent_turns)
        else:
            clarification = _build_clarification_message()
            await _safe_send(websocket, {
                "type": "agent_activity",
                "request_id": request_id,
                "activity": "thinking",
                "tool": None,
                "icon": "help-circle",
                "message": "入力内容を確認中...",
                "progress": {
                    "total_tool_calls": 0,
                    "completed_tool_calls": 0,
                },
            })
            await _safe_send(websocket, {
                "type": "agent_activity",
                "request_id": request_id,
                "activity": "done",
                "tool": None,
                "icon": "check-circle-2",
                "message": "追加情報待ち",
                "progress": {
                    "total_tool_calls": 0,
                    "completed_tool_calls": 0,
                },
            })
            return {
                "type": "agent_response",
                "request_id": request_id,
                "text": clarification,
            }

    agent_resource_name, route = _resolve_agent_resource_name(original_message)
    logger.info(
        "model routing: enabled=%s tier=%s score=%s threshold=%s reasons=%s",
        route.get("routing_enabled"),
        route.get("tier"),
        route.get("score"),
        route.get("threshold"),
        ",".join(route.get("reasons", [])),
    )
    app_client = client.agent_engines.get(name=agent_resource_name)
    chunks: list[str] = []
    total_tool_calls = 0
    completed_tool_calls = 0

    await _safe_send(websocket, {
        "type": "agent_activity",
        "request_id": request_id,
        "activity": "thinking",
        "tool": None,
        "icon": "brain",
        "message": "リクエストを分析中...",
        "progress": {
            "total_tool_calls": total_tool_calls,
            "completed_tool_calls": completed_tool_calls,
        },
    })

    async for event in app_client.async_stream_query(user_id=user_id, message=message):
        logger.debug("Agent event type: %s", type(event))

        if isinstance(event, dict):
            content = event.get("content")
        else:
            content = getattr(event, "content", None)

        if not content:
            continue

        if isinstance(content, dict):
            parts = content.get("parts", [])
        else:
            parts = getattr(content, "parts", None)

        if not parts:
            continue

        for part in parts:
            if isinstance(part, dict):
                if "text" in part:
                    chunks.append(part["text"])
                    continue

                if "function_call" in part:
                    fc = part["function_call"]
                    tool_name = fc.get("name", "unknown")
                    fc_args = _as_dict(fc.get("args"))
                    total_tool_calls += 1
                    await _safe_send(websocket, {
                        "type": "agent_activity",
                        "request_id": request_id,
                        "activity": "tool_call",
                        "tool": tool_name,
                        "icon": _tool_display_icon(tool_name),
                        "message": _tool_display_message(tool_name),
                        "progress": {
                            "total_tool_calls": total_tool_calls,
                            "completed_tool_calls": completed_tool_calls,
                        },
                    })
                    if tool_name in {"call_remote_agent", "call_master_agent"}:
                        agent_id = str(
                            fc_args.get("agent_id")
                            or fc_args.get("target_agent_id")
                            or ("master_agent" if tool_name == "call_master_agent" else "")
                        ).strip()
                        request_text = _extract_a2a_call_text(tool_name, fc_args)
                        await _safe_send(websocket, {
                            "type": "a2a_trace",
                            "request_id": request_id,
                            "phase": "call",
                            "tool": tool_name,
                            "agent_id": agent_id,
                            "message_preview": _preview_text(request_text),
                            "request_text": request_text,
                            "timestamp": int(time.time()),
                        })
                    continue

                if "function_response" in part:
                    fr = part["function_response"]
                    tool_name = fr.get("name", "unknown")
                    response_data = fr.get("response", {})
                    status = "error" if _is_error_response(response_data) else "success"
                    completed_tool_calls += 1
                    label = _tool_display_message(tool_name)
                    suffix = "完了" if status == "success" else "失敗"
                    detail = _extract_error_detail(response_data) if status == "error" else None
                    await _safe_send(websocket, {
                        "type": "agent_activity",
                        "request_id": request_id,
                        "activity": "tool_result",
                        "tool": tool_name,
                        "status": status,
                        "message": f"{label} - {suffix}",
                        "detail": detail,
                        "progress": {
                            "total_tool_calls": total_tool_calls,
                            "completed_tool_calls": completed_tool_calls,
                        },
                    })
                    if tool_name in {"call_remote_agent", "call_master_agent"}:
                        payload = _as_dict(response_data)
                        agent_id = str(payload.get("agent_id") or "").strip()
                        request_text = _extract_a2a_request_text_from_result(payload)
                        response_text = (
                            payload.get("response_text")
                            or payload.get("message")
                            or _extract_error_detail(payload)
                            or ""
                        )
                        await _safe_send(websocket, {
                            "type": "a2a_trace",
                            "request_id": request_id,
                            "phase": "result",
                            "tool": tool_name,
                            "agent_id": agent_id,
                            "status": status,
                            "request_text": request_text,
                            "response_text": str(response_text).strip(),
                            "response_preview": _preview_text(response_text),
                            "timestamp": int(time.time()),
                        })
                    continue

            txt = getattr(part, "text", None)
            if txt:
                chunks.append(txt)

    await _safe_send(websocket, {
        "type": "agent_activity",
        "request_id": request_id,
        "activity": "done",
        "tool": None,
        "icon": "check-circle-2",
        "message": "分析完了",
        "progress": {
            "total_tool_calls": total_tool_calls,
            "completed_tool_calls": completed_tool_calls,
        },
    })

    response_text = "".join(chunks).strip()
    _remember_turn(user_id, original_message, response_text)
    return {
        "type": "agent_response",
        "request_id": request_id,
        "text": response_text,
    }


@app.get("/healthz")
def healthz(request: Request):
    logger.info("healthz called headers=%s", _safe_healthz_headers(request))
    return {"status": "ok"}


@app.get("/healthz/")
def healthz_slash(request: Request):
    logger.info("healthz called headers=%s", _safe_healthz_headers(request))
    return {"status": "ok"}


@app.get("/health")
def health(request: Request):
    logger.info("health called headers=%s", _safe_healthz_headers(request))
    return {"status": "ok"}


@app.get("/health/")
def health_slash(request: Request):
    logger.info("health called headers=%s", _safe_healthz_headers(request))
    return {"status": "ok"}


@app.get("/ping")
def ping():
    return {"status": "ok"}


@app.get("/auth/me")
def auth_me(request: Request):
    if not OIDC_ENABLED:
        return {"enabled": False, "authenticated": True, "user": {"sub": "anonymous"}}
    user = _get_session_user_from_cookie(request.cookies)
    return {"enabled": True, "authenticated": bool(user), "user": user}


@app.get("/auth/login")
def auth_login(request: Request, next: str = "/"):
    if not _is_oidc_ready():
        return {"status": "error", "message": "OIDC is not fully configured."}
    metadata = _get_oidc_metadata()
    authorization_endpoint = metadata.get("authorization_endpoint")
    if not authorization_endpoint:
        return {"status": "error", "message": "OIDC authorization_endpoint not found."}

    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    redirect_uri = _resolve_redirect_uri(request)
    params = {
        "client_id": OIDC_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "response_mode": "query",
        "scope": OIDC_SCOPES,
        "state": state,
        "nonce": nonce,
    }
    auth_url = f"{authorization_endpoint}?{urllib.parse.urlencode(params)}"

    response = RedirectResponse(url=auth_url, status_code=302)
    response.set_cookie(
        key=OIDC_STATE_COOKIE_NAME,
        value=_sign_value(
            {"state": state, "nonce": nonce, "next": _build_post_login_redirect(next)},
            ttl_sec=OIDC_STATE_TTL_SEC,
        ),
        httponly=True,
        secure=_cookie_secure_flag(request),
        samesite=_cookie_samesite_value(request),
        max_age=OIDC_STATE_TTL_SEC,
        path="/",
    )
    return response


@app.get("/auth/callback")
def auth_callback(request: Request, code: str = "", state: str = ""):
    if not _is_oidc_ready():
        return {"status": "error", "message": "OIDC is not fully configured."}

    state_cookie = _verify_signed_value(request.cookies.get(OIDC_STATE_COOKIE_NAME))
    if not code or not state or not state_cookie:
        return {"status": "error", "message": "Missing OIDC callback parameters."}
    if state_cookie.get("state") != state:
        return {"status": "error", "message": "OIDC state mismatch."}

    token_payload = _exchange_code_for_token(code, _resolve_redirect_uri(request))
    id_token = (token_payload.get("id_token") or "").strip()
    if not id_token:
        return {"status": "error", "message": "id_token was not returned."}
    claims = _validate_id_token(id_token, expected_nonce=str(state_cookie.get("nonce", "")))

    session_payload = {
        "sub": claims.get("sub", ""),
        "name": claims.get("name", claims.get("preferred_username", "")),
        "email": claims.get("preferred_username", claims.get("email", "")),
    }
    next_url = _build_post_login_redirect(str(state_cookie.get("next", "/")))

    response = RedirectResponse(url=next_url, status_code=302)
    response.delete_cookie(OIDC_STATE_COOKIE_NAME, path="/")
    response.set_cookie(
        key=OIDC_SESSION_COOKIE_NAME,
        value=_sign_value(session_payload, ttl_sec=OIDC_SESSION_TTL_SEC),
        httponly=True,
        secure=_cookie_secure_flag(request),
        samesite=_cookie_samesite_value(request),
        max_age=OIDC_SESSION_TTL_SEC,
        path="/",
    )
    return response


@app.post("/auth/logout")
def auth_logout():
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie(OIDC_SESSION_COOKIE_NAME, path="/")
    response.delete_cookie(OIDC_STATE_COOKIE_NAME, path="/")
    return response


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    ws_user = _get_session_user_from_cookie(websocket.cookies) if OIDC_ENABLED else {"sub": "anonymous"}
    if OIDC_ENABLED and not ws_user:
        await websocket.close(code=4401, reason="Unauthorized")
        return
    await websocket.accept()
    client = _init_vertex()
    ws_conversation_id = uuid.uuid4().hex[:10]
    ws_user_id = f"live_gateway:{ws_user.get('sub', 'anonymous')}:{ws_conversation_id}"
    audio_queue: asyncio.Queue[tuple[bytes | None, int]] = asyncio.Queue()
    live_client: GeminiLiveClient | None = None
    live_task: asyncio.Task | None = None
    greeting_task: asyncio.Task | None = None
    response_task: asyncio.Task | None = None
    tts_task: asyncio.Task | None = None
    transcript_parts: list[str] = []
    last_response_index = 0
    last_response_at = 0.0

    async def _start_live_session():
        nonlocal audio_queue, live_client, live_task, greeting_task, response_task, tts_task, last_response_at, last_response_index
        if live_task is not None and not live_task.done():
            return

        if live_task is not None and live_task.done():
            live_task = None

        audio_queue = asyncio.Queue()
        live_client = GeminiLiveClient()
        last_response_at = 0.0
        last_response_index = 0
        tts_task = None
        transcript_parts.clear()

        async def _stream():
            nonlocal response_task
            async for response in live_client.stream_transcription(audio_queue):
                if response.text:
                    transcript_parts.append(response.text)
                    await _safe_send(websocket, {
                        "type": "live_user_text",
                        "text": " ".join(transcript_parts).strip(),
                    })
                    now = time.monotonic()
                    if response_task is None and now - last_response_at > 2.0:
                        response_task = asyncio.create_task(_trigger_agent_response())

        live_task = asyncio.create_task(_stream())

        async def _speak_text(text: str) -> bool:
            nonlocal tts_task
            has_audio = False

            async def _run():
                nonlocal has_audio
                tts_client = GeminiLiveClient()
                async for response in tts_client.stream_text(text):
                    if response.audio_bytes:
                        has_audio = True
                        await _safe_send(websocket, {
                            "type": "live_audio",
                            "audio": base64.b64encode(response.audio_bytes).decode("utf-8"),
                            "mime_type": response.mime_type or "audio/pcm",
                        })

            current_task = asyncio.create_task(_run())
            tts_task = current_task
            try:
                await current_task
            finally:
                if tts_task is current_task:
                    tts_task = None
            return has_audio

        async def _greeting():
            greeting_text = LIVE_GREETING_TEXT.strip() or "こんにちは。要件を教えてください。"

            sent_audio = False
            await _safe_send(websocket, {"type": "live_text", "text": greeting_text})
            try:
                sent_audio = await _speak_text(greeting_text)
                if not sent_audio:
                    await _safe_send(websocket, {
                        "type": "live_status",
                        "status": "greeting_no_audio",
                        "text": greeting_text,
                    })
            except Exception as exc:
                logger.exception("Greeting TTS failed: %s", exc)
                await _safe_send(websocket, {"type": "live_text", "text": greeting_text})
                await _safe_send(websocket, {
                    "type": "live_status",
                    "status": "greeting_error",
                    "text": greeting_text,
                })

        greeting_task = asyncio.create_task(_greeting())

    async def _stop_live_session():
        nonlocal live_task, live_client, greeting_task, response_task, tts_task
        if live_task is not None:
            await audio_queue.put((None, 0))

        tasks_to_cancel = [
            t for t in (live_task, greeting_task, response_task, tts_task) if t is not None
        ]
        for task in tasks_to_cancel:
            task.cancel()
        if tasks_to_cancel:
            await asyncio.gather(*tasks_to_cancel, return_exceptions=True)

        live_task = None
        greeting_task = None
        response_task = None
        tts_task = None
        live_client = None

    async def _trigger_agent_response():
        nonlocal response_task, tts_task, last_response_at, last_response_index
        try:
            transcript = " ".join(transcript_parts[last_response_index:]).strip()
            if not transcript:
                return
            last_response_index = len(transcript_parts)
            agent_response = await _query_agent(client, transcript, websocket, ws_user_id)
            await _safe_send(websocket, agent_response)
            response_text = agent_response.get("text", "")
            if response_text:
                await _safe_send(websocket, {"type": "live_text", "text": response_text})
            if response_text:
                async def _run_tts():
                    tts_client = GeminiLiveClient()
                    async for response in tts_client.stream_text(response_text):
                        if response.audio_bytes:
                            await _safe_send(websocket, {
                                "type": "live_audio",
                                "audio": base64.b64encode(response.audio_bytes).decode("utf-8"),
                                "mime_type": response.mime_type or "audio/pcm",
                            })

                current_task = asyncio.create_task(_run_tts())
                tts_task = current_task
                try:
                    await current_task
                finally:
                    if tts_task is current_task:
                        tts_task = None
            last_response_at = time.monotonic()
        finally:
            response_task = None

    try:
        while True:
            data = await websocket.receive_text()
            try:
                payload = json.loads(data)
            except json.JSONDecodeError:
                await websocket.send_text(
                    json.dumps({"type": "error", "message": "Invalid JSON payload"})
                )
                continue

            if not isinstance(payload, dict):
                await websocket.send_text(
                    json.dumps({"type": "error", "message": "Payload must be a JSON object"})
                )
                continue

            if payload.get("type") == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
                continue

            if payload.get("type") == "user_text":
                raw_message = payload.get("text", "")
                if not isinstance(raw_message, str):
                    await websocket.send_text(
                        json.dumps({"type": "error", "message": "Invalid text payload"})
                    )
                    continue

                message = raw_message.strip()
                if not message:
                    await websocket.send_text(
                        json.dumps({"type": "error", "message": "Empty message"})
                    )
                    continue

                response = await _query_agent(client, message, websocket, ws_user_id)
                await websocket.send_text(json.dumps(response, ensure_ascii=False))
                continue

            if payload.get("type") == "live_start":
                try:
                    await _start_live_session()
                    await websocket.send_text(
                        json.dumps({"type": "live_status", "status": "started"})
                    )
                except Exception as exc:
                    await websocket.send_text(
                        json.dumps({"type": "error", "message": str(exc)}, ensure_ascii=False)
                    )
                continue

            if payload.get("type") == "live_stop":
                try:
                    await _stop_live_session()
                    await websocket.send_text(
                        json.dumps({"type": "live_status", "status": "stopped"})
                    )
                except Exception as exc:
                    await websocket.send_text(
                        json.dumps({"type": "error", "message": str(exc)}, ensure_ascii=False)
                    )
                continue

            if payload.get("type") == "audio_chunk":
                if not live_client:
                    await websocket.send_text(
                        json.dumps({"type": "error", "message": "Live session not started"})
                    )
                    continue
                audio_b64 = payload.get("audio")
                if not isinstance(audio_b64, str):
                    await websocket.send_text(
                        json.dumps({"type": "error", "message": "Invalid audio payload"})
                    )
                    continue

                try:
                    sample_rate = int(payload.get("sample_rate", 16000))
                    if sample_rate <= 0:
                        raise ValueError("sample_rate must be positive")
                except (TypeError, ValueError):
                    await websocket.send_text(
                        json.dumps({"type": "error", "message": "Invalid sample_rate"})
                    )
                    continue

                if not audio_b64:
                    await websocket.send_text(
                        json.dumps({"type": "error", "message": "Missing audio payload"})
                    )
                    continue
                try:
                    audio_bytes = GeminiLiveClient.decode_audio_base64(audio_b64)
                except (binascii.Error, ValueError, TypeError):
                    await websocket.send_text(
                        json.dumps({"type": "error", "message": "Invalid audio payload"})
                    )
                    continue

                await audio_queue.put((audio_bytes, sample_rate))
                continue

            if payload.get("type") == "speech_pause":
                if response_task is None and live_client is not None:
                    response_task = asyncio.create_task(_trigger_agent_response())
                await websocket.send_text(
                    json.dumps({"type": "live_status", "status": "speech_pause"})
                )
                continue

            if payload.get("type") == "barge_in":
                if greeting_task:
                    greeting_task.cancel()
                if response_task:
                    response_task.cancel()
                if tts_task:
                    tts_task.cancel()
                await websocket.send_text(
                    json.dumps({"type": "live_status", "status": "barge_in"})
                )
                continue

            await websocket.send_text(
                json.dumps({"type": "error", "message": "Unsupported payload type"})
            )

    except WebSocketDisconnect:
        await _stop_live_session()
        return
    except Exception as exc:
        try:
            await websocket.send_text(
                json.dumps({"type": "error", "message": str(exc)}, ensure_ascii=False)
            )
        except Exception:
            pass
        await _stop_live_session()
