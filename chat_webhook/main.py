"""Google Chat webhook handler for message-triggered vulnerability analysis."""

from __future__ import annotations

import asyncio
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
import os
import re
import threading
import uuid
from typing import Any

import functions_framework
import vertexai

logger = logging.getLogger(__name__)

_secret_client = None
_chat_service_read_client = None
_chat_service_post_client = None
_RECENT_TURNS: dict[str, deque[dict[str, str]]] = {}
_THREAD_ROOT_CACHE: dict[str, str] = {}
_ASYNC_WORKER_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="chat-webhook-worker")
_ASYNC_EVENT_LOCK = threading.Lock()
_ASYNC_EVENT_SEEN: dict[str, float] = {}
_MAX_RECENT_TURNS = 4
_AMBIGUITY_PRESETS = {
    "strict": {"min_chars_without_context": 6},
    "standard": {"min_chars_without_context": 4},
    "relaxed": {"min_chars_without_context": 2},
}
_AMBIGUITY_PRESET_NAME = (os.environ.get("AMBIGUITY_PRESET") or "standard").strip().lower()
if _AMBIGUITY_PRESET_NAME not in _AMBIGUITY_PRESETS:
    _AMBIGUITY_PRESET_NAME = "standard"
_AMBIGUITY_PRESET = _AMBIGUITY_PRESETS[_AMBIGUITY_PRESET_NAME]
_AMBIGUOUS_PROMPT_EXACT = {
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
_AMBIGUOUS_REFERENCE_TOKENS = ("これ", "それ", "あれ", "この件", "その件", "上記", "さっき", "先ほど")
_CLEAR_CONTEXT_KEYWORDS = (
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
_ANALYSIS_TRIGGER_WORDS = (
    "確認して",
    "解析して",
    "解析",
    "確認",
    "見て",
    "チェックして",
    "analyze",
    "analyse",
    "check",
)
_MANUAL_TICKET_TRIGGER_WORDS = (
    "この内容で",
    "この本文で",
    "起票用",
    "起票",
    "作成して",
    "作って",
    "貼り付け",
    "コピペ",
)
_THREAD_ROOT_REFERENCE_WORDS = (
    "スレッド元",
    "元メッセージ",
    "このスレッド",
    "上のメッセージ",
    "前のメッセージ",
)
_CORRECTION_TRIGGER_WORDS = (
    "変更して",
    "修正して",
    "直して",
    "更新して",
)
_INCIDENT_ID_PATTERN = re.compile(r"\bincident_id[:=\s]*([0-9a-fA-F\-]{8,})\b", re.IGNORECASE)
_COMPLEXITY_KEYWORDS = (
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
_STRUCTURED_OUTPUT_HINTS = (
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
_MULTI_INTENT_HINTS = (
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
_MODEL_ROUTING_ENABLED = (os.environ.get("MODEL_ROUTING_ENABLED", "true") or "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
try:
    _MODEL_ROUTING_SCORE_THRESHOLD = int((os.environ.get("MODEL_ROUTING_SCORE_THRESHOLD") or "4").strip())
except Exception:
    _MODEL_ROUTING_SCORE_THRESHOLD = 4
if _MODEL_ROUTING_SCORE_THRESHOLD < 1:
    _MODEL_ROUTING_SCORE_THRESHOLD = 1


def _get_secret_client():
    global _secret_client
    if _secret_client is None:
        from google.cloud import secretmanager

        _secret_client = secretmanager.SecretManagerServiceClient()
    return _secret_client


def _get_chat_service(mode: str = "read"):
    global _chat_service_read_client, _chat_service_post_client
    normalized_mode = (mode or "read").strip().lower()
    if normalized_mode not in {"read", "post"}:
        normalized_mode = "read"

    if normalized_mode == "read" and _chat_service_read_client is not None:
        return _chat_service_read_client
    if normalized_mode == "post" and _chat_service_post_client is not None:
        return _chat_service_post_client

    from googleapiclient.discovery import build

    scopes = ["https://www.googleapis.com/auth/chat.bot"]
    if normalized_mode == "read":
        scopes.append("https://www.googleapis.com/auth/chat.messages.readonly")
    sa_json = _get_config("CHAT_SA_CREDENTIALS_JSON", "vuln-agent-chat-sa-key", "")
    delegated_user = _get_config("CHAT_DELEGATED_USER", "vuln-agent-chat-delegated-user", "")
    if sa_json:
        try:
            from google.oauth2 import service_account

            sa_info = json.loads(sa_json)
            credentials = service_account.Credentials.from_service_account_info(sa_info, scopes=scopes)
            if normalized_mode == "read" and delegated_user:
                # Chat message read is user-data scope; use domain-wide delegation when configured.
                credentials = credentials.with_subject(delegated_user)
                logger.info("Thread fetch uses delegated user auth: %s", delegated_user)
            elif normalized_mode == "read":
                logger.warning(
                    "CHAT_DELEGATED_USER is not configured. "
                    "ListMessages may fail with insufficient scopes in app auth mode."
                )
            service = build("chat", "v1", credentials=credentials, cache_discovery=False)
            if normalized_mode == "read":
                _chat_service_read_client = service
                logger.info("Thread fetch uses Chat SA credentials from secret")
            else:
                _chat_service_post_client = service
                logger.info("Chat post uses Chat SA bot credentials from secret")
            return service
        except Exception as exc:
            logger.warning("Failed to init Chat service from SA secret: %s", exc)

    import google.auth

    credentials, _ = google.auth.default(scopes=scopes)
    service = build("chat", "v1", credentials=credentials, cache_discovery=False)
    if normalized_mode == "read":
        _chat_service_read_client = service
        logger.warning("Thread fetch uses ADC fallback credentials")
    else:
        _chat_service_post_client = service
        logger.warning("Chat post uses ADC fallback credentials")
    return service


def _get_project_id() -> str:
    return (
        os.environ.get("GCP_PROJECT_ID")
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
        or os.environ.get("GCLOUD_PROJECT")
        or ""
    )


def _get_config(env_name: str, secret_name: str, default: str = "") -> str:
    value = (os.environ.get(env_name) or "").strip()
    if value:
        return value

    project_id = _get_project_id()
    if not project_id:
        return default

    try:
        client = _get_secret_client()
        name = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
        response = client.access_secret_version(request={"name": name})
        secret_value = response.payload.data.decode("utf-8").strip()
        return secret_value or default
    except Exception:
        return default


def _clean_chat_text(event: dict[str, Any]) -> str:
    message = event.get("message") or {}
    arg_text = (message.get("argumentText") or "").strip()
    if arg_text:
        return arg_text

    raw_text = (message.get("text") or "").strip()
    if not raw_text:
        return ""

    text = re.sub(r"<users/[^>]+>", "", raw_text)
    return re.sub(r"\s+", " ", text).strip()


def _strip_mentions_preserve_lines(raw_text: str) -> str:
    if not raw_text:
        return ""
    text = re.sub(r"<users/[^>]+>", "", raw_text)
    lines = [line.strip() for line in text.splitlines()]
    return "\n".join(lines).strip()


def _sender_info(event: dict[str, Any]) -> dict[str, str]:
    sender = ((event.get("message") or {}).get("sender") or {})
    return {
        "name": str(sender.get("name") or ""),
        "display_name": str(sender.get("displayName") or ""),
        "type": str(sender.get("type") or ""),
    }


def _looks_like_gmail_digest(text: str) -> bool:
    t = text.lower()
    signals = 0

    if "from:" in t or "差出人:" in t:
        signals += 1
    if "subject:" in t or "件名:" in t:
        signals += 1
    if re.search(r"^\[[^\]]+\]", text.strip()):
        signals += 1
    if "view message" in t:
        signals += 1
    if "to view the full email" in t or "google groups" in t:
        signals += 1
    if re.search(r"\bcve-\d{4}-\d{4,7}\b", t):
        signals += 1
    if "gmail" in t and "new email" in t:
        signals += 2

    return signals >= 2


def _is_gmail_app_message(event: dict[str, Any]) -> bool:
    sender = _sender_info(event)
    text = str(((event.get("message") or {}).get("text") or ""))
    if "gmail" in sender["display_name"].lower():
        return True
    if sender["type"].upper() == "BOT" and "gmail" in sender["name"].lower():
        return True
    return _looks_like_gmail_digest(text)


def _is_valid_token(event: dict[str, Any]) -> bool:
    expected = _get_config(
        "CHAT_WEBHOOK_VERIFICATION_TOKEN",
        "vuln-agent-chat-verification-token",
        "",
    )
    if not expected:
        return True
    actual = (event.get("token") or "").strip()
    return actual == expected


def _is_ambiguous_prompt(prompt: str) -> bool:
    normalized = re.sub(r"\s+", " ", (prompt or "").strip()).lower()
    if not normalized:
        return True
    if normalized in _AMBIGUOUS_PROMPT_EXACT:
        return True
    if re.fullmatch(r"[?？!！。,.、\s]+", normalized):
        return True
    has_context = any(keyword in normalized for keyword in _CLEAR_CONTEXT_KEYWORDS)
    min_chars = int(_AMBIGUITY_PRESET.get("min_chars_without_context", 4))
    if len(normalized) < min_chars and not has_context:
        return True
    if any(token in normalized for token in _AMBIGUOUS_REFERENCE_TOKENS) and not has_context:
        return True
    return False


def _build_clarification_message() -> str:
    return (
        "ぶれた回答を防ぐため、意図を正確に把握したいです。もう少し具体化してください。\n"
        "1) 対象（例: CVE番号 / 製品名 / システム名）\n"
        "2) 知りたい内容（影響範囲 / 優先度 / 対応方法 など）"
    )


def _is_analysis_trigger_prompt(prompt: str) -> bool:
    normalized = re.sub(r"\s+", " ", (prompt or "").strip()).lower()
    if not normalized:
        return False
    return any(word in normalized for word in _ANALYSIS_TRIGGER_WORDS)


def _contains_vulnerability_signal(text: str) -> bool:
    t = (text or "").lower()
    if not t:
        return False
    if "cve-" in t or "cvss" in t:
        return True
    if "sid.softek.jp" in t or "nvd.nist.gov" in t:
        return True
    if "脆弱性" in text or "対象の機器/アプリ" in text:
        return True
    return False


def _contains_specific_vuln_signal(text: str) -> bool:
    t = (text or "").lower()
    if not t:
        return False
    if re.search(r"\bcve-\d{4}-\d{4,7}\b", t):
        return True
    if "cvss" in t:
        return True
    if "sid.softek.jp" in t or "nvd.nist.gov" in t:
        return True
    vuln_domains = (
        "cve.mitre.org",
        "security-next.com",
        "fortiguard.com",
        "sec.cloudapps.cisco.com",
        "motex.co.jp",
        "jvn.jp",
        "jpcert.or.jp",
        "redhat.com",
        "ubuntu.com",
        "debian.org",
    )
    if any(domain in t for domain in vuln_domains):
        return True
    if "脆弱性" in text and ("http://" in t or "https://" in t):
        return True
    return False


def _contains_manual_ticket_trigger(text: str) -> bool:
    normalized = re.sub(r"\s+", " ", (text or "").strip()).lower()
    if not normalized:
        return False
    return any(token in normalized for token in _MANUAL_TICKET_TRIGGER_WORDS)


def _is_manual_ticket_generation_prompt(prompt: str) -> bool:
    normalized = re.sub(r"\s+", " ", (prompt or "").strip()).lower()
    if not normalized:
        return False
    if not _contains_manual_ticket_trigger(normalized):
        return False
    return _contains_specific_vuln_signal(prompt) or len(prompt) >= 120


def _requests_thread_root_context(prompt: str) -> bool:
    normalized = re.sub(r"\s+", " ", (prompt or "").strip()).lower()
    if not normalized:
        return False
    return any(token in normalized for token in _THREAD_ROOT_REFERENCE_WORDS)


def _build_vulnerability_ticket_prompt(raw_text: str) -> str:
    return (
        "以下はGmailアプリがChatに投稿したメール内容です。"
        "SIDfm以外のフォーマットを含む可能性があるため、まず脆弱性関連通知かを判定してください。"
        "脆弱性関連なら、以下の依頼票テンプレートを埋めた形式で出力してください。"
        "必ずプレーンテキストで、コピペしやすい改行を維持してください。"
        "不明な値は「要確認」と記載してください。\n\n"
        "【希望納期】\n"
        "【大分類】017.脆弱性対応（情シス専用）\n"
        "【小分類】002.IT基盤チーム\n"
        "【依頼概要】\n"
        "【対象の機器/アプリ】\n"
        "【脆弱性情報（リンク貼り付け）】\n"
        "【CVSSスコア】\n"
        "【依頼内容】\n"
        "【対応完了目標】\n\n"
        "必要なら上記の後ろに補足として「備考」を1段落だけ追加してください。\n\n"
        f"{raw_text}"
    )


def _build_thread_root_analysis_prompt(user_prompt: str, root_text: str) -> str:
    return (
        "以下はスレッド元メッセージです。"
        "ユーザー指示に従い、根拠を示して解析してください。"
        "不明点は推測せず「要確認」と明記してください。\n\n"
        f"ユーザー指示:\n{user_prompt}\n\n"
        f"スレッド元メッセージ:\n{root_text}"
    )


def _is_correction_prompt(prompt: str) -> bool:
    normalized = re.sub(r"\s+", " ", (prompt or "").strip()).lower()
    if not normalized:
        return False
    return any(token in normalized for token in _CORRECTION_TRIGGER_WORDS)


def _extract_incident_id(text: str) -> str:
    raw = (text or "").strip()
    if not raw:
        return ""
    match = _INCIDENT_ID_PATTERN.search(raw)
    if not match:
        return ""
    return str(match.group(1) or "").strip()


def _build_review_prompt_with_incident_id(user_prompt: str, incident_id: str) -> str:
    return (
        "以下は起票内容の修正依頼です。"
        "同一スレッドで解決した incident_id を必ず使用して更新してください。\n"
        "保存には save_ticket_review_result を使ってください。"
        "ユーザーが指定した変更点だけ反映し、未指定項目は現在値を維持してください。"
        "最後に更新後の【起票用（コピペ）】を返してください。\n\n"
        f"incident_id: {incident_id}\n"
        f"ユーザー依頼: {user_prompt}"
    )


def _extract_space_name(event: dict[str, Any], thread_name: str) -> str:
    space_name = str((event.get("space") or {}).get("name") or "").strip()
    if space_name:
        return space_name
    if thread_name.startswith("spaces/"):
        parts = thread_name.split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
    return ""


def _extract_message_text_payload(message: dict[str, Any]) -> str:
    def _walk(value: Any, out: list[str]) -> None:
        if value is None:
            return
        if isinstance(value, str):
            text = re.sub(r"\s+", " ", value).strip()
            if text:
                out.append(text)
            return
        if isinstance(value, list):
            for item in value:
                _walk(item, out)
            return
        if isinstance(value, dict):
            for key in (
                "text",
                "formattedText",
                "argumentText",
                "fallbackText",
                "title",
                "subtitle",
                "name",
            ):
                if key in value:
                    _walk(value.get(key), out)
            for child_key in ("cardsV2", "cards", "sections", "widgets", "textParagraph"):
                if child_key in value:
                    _walk(value.get(child_key), out)

    chunks: list[str] = []
    _walk(message, chunks)
    if not chunks:
        return ""
    merged = " ".join(chunks)
    merged = re.sub(r"\s+", " ", merged).strip()
    return merged[:12000]


def _fetch_quoted_message_text(event: dict[str, Any]) -> str:
    quoted_name = str((((event.get("message") or {}).get("quotedMessageMetadata") or {}).get("name") or "")).strip()
    if not quoted_name:
        return ""
    try:
        service = _get_chat_service(mode="read")
        quoted_message = service.spaces().messages().get(name=quoted_name).execute()
        return _extract_message_text_payload(quoted_message if isinstance(quoted_message, dict) else {})
    except Exception as exc:
        logger.warning("Failed to fetch quoted message text: %s", exc)
        return ""


def _fetch_thread_root_message_text(event: dict[str, Any]) -> str:
    message = event.get("message") or {}
    thread_name = str(((message.get("thread") or {}).get("name") or "")).strip()
    if not thread_name:
        return ""
    current_message_name = str(message.get("name") or "").strip()
    space_name = _extract_space_name(event, thread_name)
    if not space_name:
        return ""

    try:
        service = _get_chat_service(mode="read")

        quoted_name = str((((event.get("message") or {}).get("quotedMessageMetadata") or {}).get("name") or "")).strip()
        if quoted_name:
            try:
                quoted_message = service.spaces().messages().get(name=quoted_name).execute()
                quoted_text = _extract_message_text_payload(quoted_message if isinstance(quoted_message, dict) else {})
                if quoted_text:
                    return quoted_text
            except Exception:
                pass

        def _list_messages(with_filter: bool) -> list[dict[str, Any]]:
            kwargs: dict[str, Any] = {"parent": space_name, "pageSize": 100}
            if with_filter:
                kwargs["filter"] = f'thread.name="{thread_name}"'
            all_messages: list[dict[str, Any]] = []
            page_token = ""
            page_limit = 5
            for _ in range(page_limit):
                req = dict(kwargs)
                if page_token:
                    req["pageToken"] = page_token
                response = service.spaces().messages().list(**req).execute()
                messages = response.get("messages") or []
                all_messages.extend([m for m in messages if isinstance(m, dict)])
                page_token = str(response.get("nextPageToken") or "").strip()
                if not page_token:
                    break
            return all_messages

        try:
            messages = _list_messages(with_filter=True)
        except Exception:
            messages = [
                m
                for m in _list_messages(with_filter=False)
                if str(((m.get("thread") or {}).get("name") or "")).strip() == thread_name
            ]

        candidates = [m for m in messages if (m.get("name") or "") != current_message_name]
        if not candidates:
            return ""

        def _sort_key(msg: dict[str, Any]) -> tuple[str, str]:
            return (str(msg.get("createTime") or ""), str(msg.get("name") or ""))

        sorted_candidates = sorted(candidates, key=_sort_key)
        extracted: list[str] = []
        for msg in sorted_candidates:
            if not isinstance(msg, dict):
                continue
            text = _extract_message_text_payload(msg)
            if not text:
                continue
            extracted.append(text)

        if not extracted:
            return ""

        def _looks_like_vuln_context(text: str) -> bool:
            t = (text or "").lower()
            if _looks_like_gmail_digest(text):
                return True
            if "cve-" in t or "cvss" in t:
                return True
            if "sid.softek.jp" in t or "nvd.nist.gov" in t:
                return True
            if "【起票用（コピペ）】" in text:
                return True
            return False

        vuln_like = [t for t in extracted if _looks_like_vuln_context(t)]
        if vuln_like:
            return vuln_like[0]

        # Prefer substantial root-like text.
        substantial = [t for t in extracted if len(t) >= 30 and not _is_ambiguous_prompt(t)]
        if substantial:
            return substantial[0]
        return extracted[0]
    except Exception as exc:
        logger.warning("Failed to fetch thread root message: %s", exc)
        return ""


def _estimate_prompt_complexity(prompt: str) -> dict[str, Any]:
    text = (prompt or "").strip()
    normalized = re.sub(r"\s+", " ", text).lower()
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

    if sum(1 for token in _MULTI_INTENT_HINTS if token in normalized) >= 2:
        score += 2
        reasons.append("multi_intent")

    if any(token in normalized for token in _COMPLEXITY_KEYWORDS):
        score += 2
        reasons.append("analysis_or_planning")

    if any(token in normalized for token in _STRUCTURED_OUTPUT_HINTS):
        score += 1
        reasons.append("structured_output")

    if normalized.count("?") + normalized.count("？") >= 2:
        score += 1
        reasons.append("multi_questions")

    return {
        "score": score,
        "tier": "pro" if score >= _MODEL_ROUTING_SCORE_THRESHOLD else "flash",
        "reasons": reasons,
        "threshold": _MODEL_ROUTING_SCORE_THRESHOLD,
    }


def _resolve_agent_resource_name(prompt: str) -> tuple[str, dict[str, Any]]:
    base_resource = (
        (os.environ.get("AGENT_RESOURCE_NAME") or "").strip()
        or _get_config("AGENT_RESOURCE_NAME", "vuln-agent-resource-name", "")
    )
    flash_resource = (
        (os.environ.get("AGENT_RESOURCE_NAME_FLASH") or "").strip()
        or _get_config("AGENT_RESOURCE_NAME_FLASH", "vuln-agent-resource-name-flash", "")
        or base_resource
    )
    pro_resource = (
        (os.environ.get("AGENT_RESOURCE_NAME_PRO") or "").strip()
        or _get_config("AGENT_RESOURCE_NAME_PRO", "vuln-agent-resource-name-pro", "")
        or base_resource
    )

    if not _MODEL_ROUTING_ENABLED:
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


def _looks_like_internal_artifact(text: str) -> bool:
    t = (text or "").strip()
    if not t:
        return False
    lowered = t.lower()
    bad_tokens = (
        "gemini-",
        "tool_code",
        "tool code",
        "tool_name",
        "on_demand",
        "<ctrl",
        "function_call",
        "assistant_response",
    )
    if any(token in lowered for token in bad_tokens):
        return True
    if re.search(r"<[^>]{2,32}>", t):
        return True
    return False


def _run_agent_query(prompt: str, user_id: str) -> str:
    project_id = _get_project_id()
    location = os.environ.get("GCP_LOCATION", "asia-northeast1")
    agent_name, route = _resolve_agent_resource_name(prompt)
    if not project_id or not agent_name:
        raise RuntimeError("GCP_PROJECT_ID and AGENT_RESOURCE_NAME are required")
    logger.info(
        "model routing: enabled=%s tier=%s score=%s threshold=%s reasons=%s",
        route.get("routing_enabled"),
        route.get("tier"),
        route.get("score"),
        route.get("threshold"),
        ",".join(route.get("reasons", [])),
    )

    vertexai.init(project=project_id, location=location)
    from vertexai import Client

    client = Client(project=project_id, location=location)
    app = client.agent_engines.get(name=agent_name)

    chunks: list[str] = []

    def _harvest_text(obj: Any) -> None:
        if obj is None:
            return
        if isinstance(obj, str):
            if obj.strip():
                chunks.append(obj.strip())
            return
        if isinstance(obj, dict):
            text = obj.get("text")
            if isinstance(text, str) and text.strip():
                chunks.append(text.strip())
            for value in obj.values():
                _harvest_text(value)
            return
        if isinstance(obj, (list, tuple, set)):
            for item in obj:
                _harvest_text(item)
            return
        if hasattr(obj, "text"):
            value = getattr(obj, "text", "")
            if isinstance(value, str) and value.strip():
                chunks.append(value.strip())
        if hasattr(obj, "model_dump"):
            try:
                _harvest_text(obj.model_dump())
            except Exception:
                pass
        elif hasattr(obj, "__dict__"):
            _harvest_text(vars(obj))

    def _collect_text_from_event(stream_event: Any) -> None:
        direct_text = getattr(stream_event, "text", "")
        if isinstance(direct_text, str) and direct_text.strip():
            chunks.append(direct_text.strip())

        content = getattr(stream_event, "content", None)
        parts = []
        if isinstance(content, dict):
            parts = content.get("parts", []) or []
        elif content is not None:
            parts = getattr(content, "parts", []) or []

        for part in parts:
            if isinstance(part, dict):
                text = part.get("text", "")
            else:
                text = getattr(part, "text", "")
            if isinstance(text, str) and text.strip():
                chunks.append(text.strip())
            else:
                _harvest_text(part)

        _harvest_text(stream_event)

    async def execute_query():
        async for event in app.async_stream_query(
            user_id=user_id or "google-chat-user",
            message=prompt,
        ):
            _collect_text_from_event(event)

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(execute_query())
    finally:
        loop.close()

    def _is_noise_line(line: str) -> bool:
        if not line:
            return True
        if _looks_like_internal_artifact(line):
            return True
        if line in {"model", "TEXT", "STOP", "ON_DEMAND", "sent", "user"}:
            return True
        if line.startswith("spaces/"):
            return True
        if re.fullmatch(r"[A-Za-z0-9._:/=\-]{24,}", line):
            return True
        if re.fullmatch(r"[A-Za-z0-9._\-]{16,}", line):
            return True
        return False

    def _normalize_chunks(raw_chunks: list[str]) -> str:
        seen = set()
        candidates: list[str] = []
        for raw in raw_chunks:
            for line in raw.splitlines():
                text = line.strip()
                if not text or text in seen or _is_noise_line(text):
                    continue
                seen.add(text)
                candidates.append(text)
        if not candidates:
            return ""
        preferred = [x for x in candidates if re.search(r"[^\x00-\x7F]", x) or " " in x or "。" in x]
        selected = preferred if preferred else candidates
        # 以前は6行に制限しており回答が途中で欠けやすかったため、上限を拡大する。
        return "\n".join(selected[:60]).strip()

    def _trim_response_text(text: str, max_chars: int = 12000) -> str:
        if len(text) <= max_chars:
            return text
        # 文中カットを避けるため、できる限り境界で切る。
        head = text[:max_chars]
        cut_points = [
            head.rfind("\n"),
            head.rfind("。"),
            head.rfind(". "),
            head.rfind("! "),
            head.rfind("? "),
        ]
        cut = max(cut_points)
        if cut < int(max_chars * 0.6):
            cut = max_chars
        return head[:cut].rstrip() + "\n\n(長文のため一部を省略しました)"

    result = _normalize_chunks(chunks)
    if not result:
        return "回答を生成できませんでした。もう一度お試しください。"
    return _trim_response_text(result)


def _thread_payload(event: dict[str, Any], text: str) -> dict[str, Any]:
    message = event.get("message") or {}
    thread_name = ((message.get("thread") or {}).get("name") or "").strip()
    payload: dict[str, Any] = {"text": text}
    if thread_name:
        payload["thread"] = {"name": thread_name}
    return payload


def _is_async_response_enabled() -> bool:
    return (os.environ.get("CHAT_ASYNC_RESPONSE_ENABLED", "false") or "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _is_message_actionable(event: dict[str, Any]) -> bool:
    message = event.get("message") or {}
    sender = (message.get("sender") or {})
    sender_type = str(sender.get("type") or "").upper()
    if sender_type == "BOT" and not _is_gmail_app_message(event):
        return False

    raw_text = str(message.get("text") or "").strip()
    prompt = _clean_chat_text(event)
    if _is_gmail_app_message(event):
        return True
    if raw_text and prompt:
        return True
    return False


def _register_async_event_once(event: dict[str, Any]) -> bool:
    message_name = str(((event.get("message") or {}).get("name") or "")).strip()
    if not message_name:
        return True
    now = datetime.now(timezone.utc).timestamp()
    ttl_sec = 900
    with _ASYNC_EVENT_LOCK:
        stale = [k for k, ts in _ASYNC_EVENT_SEEN.items() if now - ts > ttl_sec]
        for key in stale:
            _ASYNC_EVENT_SEEN.pop(key, None)
        if message_name in _ASYNC_EVENT_SEEN:
            return False
        _ASYNC_EVENT_SEEN[message_name] = now
    return True


def _submit_async_job(event: dict[str, Any], user_name: str) -> None:
    if _enqueue_async_task(event, user_name):
        return
    global _ASYNC_WORKER_POOL
    try:
        _ASYNC_WORKER_POOL.submit(_run_async_message_processing, event, user_name)
        return
    except RuntimeError:
        # Worker pool can be in shutdown state during instance lifecycle transitions.
        _ASYNC_WORKER_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="chat-webhook-worker")
        _ASYNC_WORKER_POOL.submit(_run_async_message_processing, event, user_name)


def _get_async_task_target_url() -> str:
    explicit = (os.environ.get("CHAT_ASYNC_TASK_TARGET_URL") or "").strip()
    if explicit:
        return explicit
    project_id = _get_project_id()
    region = (os.environ.get("CHAT_ASYNC_TASKS_LOCATION") or os.environ.get("GCP_LOCATION") or "asia-northeast1").strip()
    service = (os.environ.get("K_SERVICE") or "vuln-agent-chat-webhook").strip()
    if not project_id or not region or not service:
        return ""
    return f"https://{region}-{project_id}.cloudfunctions.net/{service}"


def _enqueue_async_task(event: dict[str, Any], user_name: str) -> bool:
    if not _is_async_response_enabled():
        return False
    try:
        from google.cloud import tasks_v2
        from google.api_core.exceptions import AlreadyExists
    except Exception as exc:
        logger.warning("Cloud Tasks libraries unavailable; fallback to in-process async: %s", exc)
        return False

    project_id = _get_project_id()
    location = (os.environ.get("CHAT_ASYNC_TASKS_LOCATION") or os.environ.get("GCP_LOCATION") or "asia-northeast1").strip()
    queue_id = (os.environ.get("CHAT_ASYNC_TASKS_QUEUE") or "vuln-agent-chat-async").strip()
    target_url = _get_async_task_target_url()
    if not project_id or not location or not queue_id or not target_url:
        logger.warning("Async task enqueue skipped: missing project/location/queue/target_url")
        return False

    try:
        client = tasks_v2.CloudTasksClient()

        parent = client.queue_path(project_id, location, queue_id)
        payload = {
            "_internal_async_task": True,
            "chat_event": event,
            "user_name": user_name,
        }
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        task: dict[str, Any] = {
            "http_request": {
                "http_method": tasks_v2.HttpMethod.POST,
                "url": target_url,
                "headers": {"Content-Type": "application/json"},
                "body": body,
            }
        }

        message_name = str(((event.get("message") or {}).get("name") or "")).strip()
        if message_name:
            digest = hashlib.sha1(message_name.encode("utf-8")).hexdigest()[:24]
            task_id = f"msg-{digest}"
            task["name"] = client.task_path(project_id, location, queue_id, task_id)

        client.create_task(parent=parent, task=task)
        logger.info("Enqueued async processing task to Cloud Tasks queue=%s", queue_id)
        return True
    except AlreadyExists:
        logger.info("Skipped duplicate async task enqueue for same message")
        return True
    except Exception as exc:
        logger.warning("Failed to enqueue async task; fallback to in-process async: %s", exc)
        return False


def _is_cloud_tasks_request(request: Any, event: dict[str, Any]) -> bool:
    if not isinstance(event, dict):
        return False
    if not bool(event.get("_internal_async_task")):
        return False
    headers = getattr(request, "headers", None)
    if headers is None:
        return False
    task_name = str(headers.get("X-CloudTasks-TaskName") or "").strip()
    return bool(task_name)


def _send_message_to_thread(event: dict[str, Any], text: str) -> None:
    payload = _thread_payload(event, text)
    thread_name = str(((payload.get("thread") or {}).get("name") or "")).strip()
    space_name = _extract_space_name(event, thread_name)
    if not space_name:
        return
    service = _get_chat_service(mode="post")
    body: dict[str, Any] = {"text": str(payload.get("text") or "")}
    if thread_name:
        body["thread"] = {"name": thread_name}
    service.spaces().messages().create(
        parent=space_name,
        body=body,
        messageReplyOption="REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD",
    ).execute()


def _context_key(event: dict[str, Any], user_name: str) -> str:
    message = event.get("message") or {}
    thread_name = ((message.get("thread") or {}).get("name") or "").strip()
    if thread_name:
        return f"thread:{thread_name}"
    return f"user:{user_name or 'google-chat-user'}"


def _remember_thread_root_text(event: dict[str, Any], text: str) -> None:
    message = event.get("message") or {}
    thread_name = ((message.get("thread") or {}).get("name") or "").strip()
    if not thread_name:
        return
    normalized = re.sub(r"\s+", " ", (text or "").strip())
    if not normalized:
        return
    _THREAD_ROOT_CACHE[thread_name] = normalized[:12000]


def _get_cached_thread_root_text(event: dict[str, Any]) -> str:
    message = event.get("message") or {}
    thread_name = ((message.get("thread") or {}).get("name") or "").strip()
    if not thread_name:
        return ""
    return _THREAD_ROOT_CACHE.get(thread_name, "")


def _fetch_latest_ticket_record_from_history(event: dict[str, Any]) -> dict[str, str]:
    table_id = _get_config("BQ_HISTORY_TABLE_ID", "vuln-agent-bq-table-id", "").strip()
    if not table_id:
        return {}

    message = event.get("message") or {}
    thread_name = str(((message.get("thread") or {}).get("name") or "")).strip()
    space_name = _extract_space_name(event, thread_name)

    try:
        from google.cloud import bigquery

        project_id = _get_project_id() or None
        client = bigquery.Client(project=project_id)
        query = f"""
            SELECT incident_id, vulnerability_id, title, severity, occurred_at, extra, source
            FROM `{table_id}`
            WHERE source IN ('chat_alert', 'chat_webhook_manual', 'human_review')
              AND (@thread_name = '' OR JSON_VALUE(extra, '$.thread_name') = @thread_name)
            ORDER BY occurred_at DESC
            LIMIT 50
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("thread_name", "STRING", thread_name),
            ]
        )
        rows = client.query(query, job_config=job_config).result()
        for row in rows:
            extra_raw = str(getattr(row, "extra", "") or "").strip()
            if not extra_raw:
                continue
            try:
                extra = json.loads(extra_raw)
            except Exception:
                continue
            if not isinstance(extra, dict):
                continue
            row_thread = str(extra.get("thread_name") or "").strip()
            row_space = str(extra.get("space_id") or "").strip()
            if thread_name and row_thread and row_thread != thread_name:
                continue
            if space_name and row_space and row_space != space_name:
                continue
            ticket_record = extra.get("ticket_record") or {}
            if not ticket_record and isinstance(extra.get("review"), dict):
                ticket_record = (extra.get("review") or {}).get("final_ticket_record") or {}
            if not isinstance(ticket_record, dict):
                continue
            copy_text = str(ticket_record.get("copy_paste_text") or "").strip()
            reasoning_text = str(ticket_record.get("reasoning_text") or "").strip()
            if not copy_text and not reasoning_text:
                continue
            return {
                "incident_id": str(getattr(row, "incident_id", "") or "").strip(),
                "copy_paste_text": copy_text,
                "reasoning_text": reasoning_text,
                "title": str(getattr(row, "title", "") or "").strip(),
                "vulnerability_id": str(getattr(row, "vulnerability_id", "") or "").strip(),
            }

        # Backward-compatible fallback: old records without thread_name.
        if not thread_name:
            return {}
        query_space = f"""
            SELECT incident_id, vulnerability_id, title, severity, occurred_at, extra, source
            FROM `{table_id}`
            WHERE source = 'chat_alert'
            ORDER BY occurred_at DESC
            LIMIT 50
        """
        rows = client.query(query_space).result()
        for row in rows:
            extra_raw = str(getattr(row, "extra", "") or "").strip()
            if not extra_raw:
                continue
            try:
                extra = json.loads(extra_raw)
            except Exception:
                continue
            if not isinstance(extra, dict):
                continue
            row_space = str(extra.get("space_id") or "").strip()
            if space_name and row_space and row_space != space_name:
                continue
            ticket_record = extra.get("ticket_record") or {}
            if not isinstance(ticket_record, dict):
                continue
            copy_text = str(ticket_record.get("copy_paste_text") or "").strip()
            reasoning_text = str(ticket_record.get("reasoning_text") or "").strip()
            if not copy_text and not reasoning_text:
                continue
            return {
                "incident_id": str(getattr(row, "incident_id", "") or "").strip(),
                "copy_paste_text": copy_text,
                "reasoning_text": reasoning_text,
                "title": str(getattr(row, "title", "") or "").strip(),
                "vulnerability_id": str(getattr(row, "vulnerability_id", "") or "").strip(),
            }
    except Exception as exc:
        logger.warning("Failed to fetch latest ticket record from history: %s", exc)
    return {}


def _build_history_ticket_message(record: dict[str, str]) -> str:
    copy_text = str(record.get("copy_paste_text") or "").strip()
    reasoning_text = str(record.get("reasoning_text") or "").strip()
    incident_id = str(record.get("incident_id") or "").strip()
    title = str(record.get("title") or "").strip()
    vuln_id = str(record.get("vulnerability_id") or "").strip()

    sections: list[str] = []
    if copy_text:
        sections.append(copy_text)
    if reasoning_text:
        sections.append(reasoning_text)

    if not sections:
        return ""
    if incident_id:
        sections.append(f"【管理ID】\n{incident_id}")
    if title or vuln_id:
        lines = ["【参照元】", "スレッド読取に失敗したため履歴から補完しました。"]
        if vuln_id:
            lines.append(f"- 脆弱性ID: {vuln_id}")
        if title:
            lines.append(f"- 件名: {title}")
        sections.append("\n".join(lines))
    return "\n\n".join(sections).strip()


def _extract_ticket_sections(text: str) -> tuple[str, str]:
    body = (text or "").strip()
    if not body:
        return "", ""
    copy_marker = "【起票用（コピペ）】"
    reason_marker = "【判断理由】"
    incident_marker = "【管理ID】"

    copy_text = ""
    reasoning_text = ""
    copy_idx = body.find(copy_marker)
    reason_idx = body.find(reason_marker)
    incident_idx = body.find(incident_marker)

    if copy_idx >= 0:
        copy_end = len(body)
        if reason_idx > copy_idx:
            copy_end = reason_idx
        elif incident_idx > copy_idx:
            copy_end = incident_idx
        copy_text = body[copy_idx:copy_end].strip()
    if reason_idx >= 0:
        reason_end = len(body)
        if incident_idx > reason_idx:
            reason_end = incident_idx
        reasoning_text = body[reason_idx:reason_end].strip()
    return copy_text, reasoning_text


def _save_ticket_record_to_history(event: dict[str, Any], response_text: str, source: str = "chat_webhook_manual") -> None:
    table_id = _get_config("BQ_HISTORY_TABLE_ID", "vuln-agent-bq-table-id", "").strip()
    if not table_id:
        return
    copy_text, reasoning_text = _extract_ticket_sections(response_text)
    if not copy_text and not reasoning_text:
        return
    try:
        from google.cloud import bigquery
    except Exception:
        return

    message = event.get("message") or {}
    thread_name = str(((message.get("thread") or {}).get("name") or "")).strip()
    space_name = _extract_space_name(event, thread_name)
    incident_id = _extract_incident_id(response_text) or str(uuid.uuid4())
    vuln_match = re.search(r"\bCVE-\d{4}-\d{4,7}\b", response_text, flags=re.IGNORECASE)
    vulnerability_id = (vuln_match.group(0).upper() if vuln_match else "").strip()
    if not vulnerability_id:
        seed = re.sub(r"[^A-Za-z0-9]", "", thread_name)[-16:] or "UNKNOWN"
        vulnerability_id = f"THREAD-{seed}"

    summary = "Chat follow-up ticket"
    for line in copy_text.splitlines():
        if "依頼概要" in line and ":" in line:
            summary = line.split(":", 1)[1].strip() or summary
            break

    extra = {
        "space_id": space_name,
        "thread_name": thread_name,
        "ticket_record": {
            "copy_paste_text": copy_text,
            "reasoning_text": reasoning_text,
        },
    }
    row = {
        "incident_id": incident_id,
        "vulnerability_id": vulnerability_id,
        "title": summary[:500],
        "severity": "要確認",
        "affected_systems": "[]",
        "cvss_score": None,
        "description": None,
        "remediation": None,
        "owners": "[]",
        "status": "notified",
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "extra": json.dumps(extra, ensure_ascii=False),
    }
    try:
        client = bigquery.Client(project=_get_project_id() or None)
        errors = client.insert_rows_json(table_id, [row])
        if errors:
            logger.warning("Failed to save ticket record to history: %s", errors)
    except Exception as exc:
        logger.warning("Failed to save ticket record to history: %s", exc)


def _get_recent_turns(key: str, max_turns: int = 2) -> list[dict[str, str]]:
    turns = list(_RECENT_TURNS.get(key) or [])
    if not turns:
        return []
    return turns[-max_turns:]


def _remember_turn(key: str, user_prompt: str, assistant_text: str) -> None:
    if not key or not user_prompt.strip():
        return
    if key not in _RECENT_TURNS:
        _RECENT_TURNS[key] = deque(maxlen=_MAX_RECENT_TURNS)
    _RECENT_TURNS[key].append(
        {
            "user": user_prompt.strip()[:1200],
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


def _build_thread_followup_prompt(user_prompt: str) -> str:
    return (
        "以下は同一スレッド内のフォローアップ依頼です。"
        "対象は『このスレッドで直前に扱った脆弱性通知』に固定してください。"
        "確認質問は返さず、分析結果を出力してください。"
        "情報不足の項目は必ず「要確認」と明記してください。\n\n"
        "出力要件:\n"
        "- Markdown表は使わない\n"
        "- 見出しは必ず次の2つだけを使う\n"
        "  1) 【起票用（コピペ）】\n"
        "  2) 【判断理由】\n"
        "- 【起票用（コピペ）】は次の4項目を固定順で出力\n"
        "  大分類 / 小分類 / 依頼概要 / 詳細\n"
        "- 値が特定できない項目は「要確認」\n\n"
        f"ユーザー依頼: {user_prompt}"
    )


def _build_backfill_guidance_message() -> str:
    return (
        "このスレッドは初回取り込みが未完了のため、過去通知を復元できませんでした。\n"
        "次の形式で同一スレッドに貼り付けてください。\n\n"
        "1) 元の脆弱性通知本文（CVE/URLを含む）を貼り付け\n"
        "2) 最後に「この内容で起票用を作成して」と送信\n\n"
        "取り込み後は「確認して」だけで再表示できます。"
    )


def _build_low_quality_ticket_message() -> str:
    return (
        "起票データの根拠情報が不足しているため、このままでは誤起票の可能性があります。\n"
        "次の形式で同一スレッドに貼り付けてください。\n\n"
        "1) 脆弱性通知本文（CVE / CVSS / 対象製品 / 参照URL を含む）\n"
        "2) 最後に「この内容で起票用を作成して」と送信\n\n"
        "十分な情報が確認でき次第、起票用データを再生成します。"
    )


def _strip_manual_command_lines(text: str) -> str:
    if not text:
        return ""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    kept: list[str] = []
    for line in lines:
        lowered = line.lower()
        if any(token in lowered for token in _MANUAL_TICKET_TRIGGER_WORDS):
            continue
        if line in {"確認して", "確認", "解析して"}:
            continue
        kept.append(line)
    return "\n".join(kept).strip()


def _resolve_manual_backfill_source_text(event: dict[str, Any], raw_body_text: str) -> str:
    candidate = _strip_manual_command_lines(raw_body_text)
    if _contains_specific_vuln_signal(candidate):
        return candidate
    if _contains_vulnerability_signal(candidate) and len(candidate) >= 80:
        return candidate
    quoted = _fetch_quoted_message_text(event)
    if _contains_specific_vuln_signal(quoted):
        return quoted
    if _contains_vulnerability_signal(quoted) and len(quoted) >= 80:
        return quoted
    root_text = _fetch_thread_root_message_text(event)
    if _contains_specific_vuln_signal(root_text):
        return root_text
    if _contains_vulnerability_signal(root_text) and len(root_text) >= 80:
        return root_text
    cached_root = _get_cached_thread_root_text(event)
    if _contains_specific_vuln_signal(cached_root):
        return cached_root
    if _contains_vulnerability_signal(cached_root) and len(cached_root) >= 80:
        return cached_root
    history_ticket = _fetch_latest_ticket_record_from_history(event)
    history_copy = str(history_ticket.get("copy_paste_text") or "").strip()
    if _contains_specific_vuln_signal(history_copy):
        return history_copy
    return ""


def _is_low_quality_ticket_output(text: str) -> bool:
    body = (text or "").strip()
    if not body:
        return True
    if "【起票用（コピペ）】" not in body:
        return True
    if "詳細: 要確認" not in body:
        return False
    weak_phrases = ("承知", "了解", "テンプレート", "以下に", "作成します")
    if any(phrase in body for phrase in weak_phrases) and not _contains_specific_vuln_signal(body):
        return True
    return False


def _has_ticket_sections(text: str) -> bool:
    body = (text or "").strip()
    return "【起票用（コピペ）】" in body and "【判断理由】" in body


def _is_manual_ticket_output_usable(text: str) -> bool:
    body = (text or "").strip()
    if not body:
        return False
    if not _has_ticket_sections(body):
        return False
    if _is_low_quality_ticket_output(body):
        return False
    required_lines = ("大分類:", "小分類:", "依頼概要:", "詳細:")
    if not all(token in body for token in required_lines):
        return False
    if "小分類: 要確認" in body and "依頼概要: 要確認" in body and "詳細: 要確認" in body:
        return False
    return True


def _is_auto_ticket_output_usable(text: str) -> bool:
    body = (text or "").strip()
    if not body:
        return False
    if _looks_like_internal_artifact(body):
        return False
    if not _has_ticket_sections(body):
        return False
    if _is_low_quality_ticket_output(body):
        return False
    if "依頼概要:" not in body or "詳細:" not in body:
        return False
    weak_summary = (
        "はい、承知",
        "承知いたしました",
        "ご依頼のメール内容",
        "判断しました",
        "以下に",
        "テンプレート",
        "作成します",
    )
    for line in body.splitlines():
        if not line.strip().startswith("依頼概要:"):
            continue
        summary = line.split(":", 1)[1].strip()
        if any(w in summary for w in weak_summary):
            return False
        if len(summary) < 10:
            return False
        if "脆弱性" not in summary and "ペネトレ" not in summary and "アップグレード" not in summary:
            return False
    return True


def _infer_request_summary_from_source(source_text: str) -> str:
    text = (source_text or "").strip()
    if not text:
        return "脆弱性確認及び該当バージョンの対応願い"
    lower = text.lower()
    product_patterns = [
        (r"almalinux", "AlmaLinux"),
        (r"fortios|fortigate", "FortiOS"),
        (r"cisco\s*asa", "Cisco ASA"),
        (r"amazon\s*linux", "Amazon Linux"),
        (r"lanscope", "LANSCOPE"),
        (r"\bios\b|iphone", "Apple iOS"),
        (r"windows", "Windows"),
    ]
    for pattern, name in product_patterns:
        if re.search(pattern, lower):
            if name == "Apple iOS":
                return "Apple iOS のアップグレード"
            return f"{name} の脆弱性確認及び該当バージョンの対応願い"
    return "脆弱性確認及び該当バージョンの対応願い"


def _extract_sidfm_entries(source_text: str) -> list[dict[str, Any]]:
    text = (source_text or "").strip()
    if not text:
        return []

    entries: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    lines = text.splitlines()

    # 1) SIDfm一覧テーブル: "1 62977  9.4 AlmaLinux ..."
    row_pat = re.compile(r"^\s*\d+\s+(\d{4,8})\s+([0-9](?:\.[0-9])?)\s+(.+?)\s*$")
    for raw in lines:
        m = row_pat.match(raw)
        if not m:
            continue
        vuln_id, cvss_s, title = m.group(1), m.group(2), m.group(3).strip()
        if vuln_id in seen_ids:
            continue
        seen_ids.add(vuln_id)
        try:
            cvss = float(cvss_s)
        except Exception:
            cvss = None
        entries.append({"id": vuln_id, "cvss": cvss, "title": title, "url": f"https://sid.softek.jp/filter/sinfo/{vuln_id}"})

    # 2) 本文ブロック: "ID:62977 ... CVSSv3: 9.4"
    block_pat = re.compile(r"ID:(\d{4,8}).*?CVSSv3:\s*([0-9](?:\.[0-9])?)", re.IGNORECASE)
    for i, raw in enumerate(lines):
        m = block_pat.search(raw)
        if not m:
            continue
        vuln_id, cvss_s = m.group(1), m.group(2)
        if vuln_id in seen_ids:
            continue
        try:
            cvss = float(cvss_s)
        except Exception:
            cvss = None
        title = ""
        url = ""
        for j in range(i + 1, min(i + 12, len(lines))):
            candidate = lines[j].strip()
            if not candidate:
                continue
            if not title and "http" not in candidate and "AlmaLinux" in candidate:
                title = re.sub(r"\s+", " ", candidate).strip()
            if "https://sid.softek.jp/filter/sinfo/" in candidate:
                url = re.search(r"https://sid\.softek\.jp/filter/sinfo/\d+", candidate).group(0)  # type: ignore[union-attr]
                break
        if not url:
            url = f"https://sid.softek.jp/filter/sinfo/{vuln_id}"
        seen_ids.add(vuln_id)
        entries.append({"id": vuln_id, "cvss": cvss, "title": title or "要確認", "url": url})

    def _key(item: dict[str, Any]) -> tuple[float, str]:
        score = item.get("cvss")
        return (float(score) if isinstance(score, (int, float)) else -1.0, str(item.get("id") or ""))

    return sorted(entries, key=_key, reverse=True)


def _extract_base_date_from_source(source_text: str) -> datetime:
    text = (source_text or "").strip()
    m = re.search(r"SIDfm\s*\((\d{4})/(\d{2})/(\d{2})\)", text)
    if m:
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
        try:
            return datetime(y, mo, d, tzinfo=timezone.utc)
        except Exception:
            pass
    return datetime.now(timezone.utc)


def _add_business_days(base: datetime, days: int) -> datetime:
    current = base
    added = 0
    while added < max(0, days):
        current = current + timedelta(days=1)
        if current.weekday() < 5:
            added += 1
    return current


def _infer_due_date_from_policy(source_text: str, max_cvss: float | None) -> tuple[str, str]:
    base = _extract_base_date_from_source(source_text)
    text = (source_text or "").lower()
    exploit_signal = ("悪用実績" in source_text) or ("エクスプロイトコード" in source_text) or ("exploit" in text)
    is_public_resource = any(token in text for token in ("fortigate", "cisco asa", "zeem", "mail", "公開"))

    if max_cvss is None or max_cvss < 8.0:
        return "要確認", "CVSS 8.0未満または不明"
    if is_public_resource and max_cvss >= 9.0 and exploit_signal:
        due = _add_business_days(base, 5)
        return due.strftime("%Y/%m/%d"), "社内方針: 公開リソース×CVSS9.0以上×悪用実績あり(5営業日)"
    if is_public_resource and max_cvss >= 8.0:
        due = _add_business_days(base, 10)
        return due.strftime("%Y/%m/%d"), "社内方針: 公開リソース×CVSS8.0以上(10営業日)"
    # デフォルトは内部リソース扱い: 3か月
    month = base.month + 3
    year = base.year + (month - 1) // 12
    month = ((month - 1) % 12) + 1
    day = min(base.day, 28)
    due = datetime(year, month, day, tzinfo=timezone.utc)
    return due.strftime("%Y/%m/%d"), "社内方針: 内部リソース×CVSS8.0以上(3か月)"


def _extract_source_facts(source_text: str) -> dict[str, Any]:
    text = (source_text or "").strip()
    lowered = text.lower()
    entries = _extract_sidfm_entries(text)
    links = re.findall(r"https?://[^\s)>\]]+", text)
    sid_links = [u for u in links if "sid.softek.jp" in u]
    # 同一納期で同一起票とするため、エントリごとに納期を算出してグルーピングする。
    due_groups: dict[str, list[dict[str, Any]]] = {}
    for e in entries:
        entry_score = e.get("cvss")
        score = float(entry_score) if isinstance(entry_score, (int, float)) else None
        due_date, due_reason = _infer_due_date_from_policy(text, score)
        entry = dict(e)
        entry["due_date"] = due_date
        entry["due_reason"] = due_reason
        due_groups.setdefault(due_date, []).append(entry)

    selected_due_date = ""
    selected_entries: list[dict[str, Any]] = []
    if due_groups:
        # 件数優先、同数なら日付昇順で選択。
        def _due_sort_key(item: tuple[str, list[dict[str, Any]]]) -> tuple[int, str]:
            due, group = item
            due_key = due if re.fullmatch(r"\d{4}/\d{2}/\d{2}", due or "") else "9999/12/31"
            return (-len(group), due_key)

        selected_due_date, selected_entries = sorted(due_groups.items(), key=_due_sort_key)[0]
    else:
        selected_entries = []

    entry_links = [str(e.get("url") or "").strip() for e in selected_entries if str(e.get("url") or "").strip()]
    vuln_links = entry_links or sid_links or links

    products: list[str] = []
    if "almalinux" in lowered:
        versions = sorted({m.group(1) for m in re.finditer(r"almalinux\s*([0-9]{1,2})", lowered)})
        if versions:
            products.extend([f"AlmaLinux{v}" for v in versions])
        else:
            products.append("AlmaLinux")
    if re.search(r"fortios|fortigate", lowered):
        products.append("FortiOS")
    if re.search(r"cisco\s*asa", lowered):
        products.append("Cisco ASA")
    if re.search(r"amazon\s*linux", lowered):
        products.append("Amazon Linux")
    if re.search(r"\bios\b|iphone", lowered):
        products.append("Apple iOS")
    if not products:
        products.append("要確認")
    products = list(dict.fromkeys(products))

    scores: list[float] = []
    entry_scores = [float(e.get("cvss")) for e in selected_entries if isinstance(e.get("cvss"), (int, float))]
    if entry_scores:
        scores.extend(entry_scores)
    else:
        for m in re.finditer(r"(?:cvss(?:v3)?[:\s]*)\s*(10(?:\.0)?|[0-9](?:\.[0-9])?)", lowered):
            try:
                scores.append(float(m.group(1)))
            except Exception:
                pass
        if not scores:
            # SIDfm一覧の "8.8 AlmaLinux ..." のような記法を拾う。
            for m in re.finditer(r"\b(10(?:\.0)?|[0-9]\.[0-9])\b", text):
                try:
                    value = float(m.group(1))
                    if 0.0 <= value <= 10.0:
                        scores.append(value)
                except Exception:
                    pass
    unique_scores = sorted(set(scores), reverse=True)
    max_score = unique_scores[0] if unique_scores else None

    if selected_due_date:
        due_date = selected_due_date
        first_reason = str((selected_entries[0] or {}).get("due_reason") or "").strip() if selected_entries else ""
        due_reason = first_reason or "社内方針に基づき算出"
    else:
        due_date, due_reason = _infer_due_date_from_policy(text, max_score)
    return {
        "entries": selected_entries or entries,
        "all_entries_count": len(entries),
        "selected_entries_count": len(selected_entries) if selected_entries else len(entries),
        "due_group_count": len(due_groups) if due_groups else 1,
        "products": products,
        "vuln_links": vuln_links[:20],
        "scores": unique_scores[:10],
        "max_score": max_score,
        "due_date": due_date,
        "due_reason": due_reason,
    }


def _infer_ticket_detail_from_source(source_text: str) -> str:
    facts = _extract_source_facts(source_text)
    product_line = "\n".join(facts["products"]) if facts["products"] else "要確認"
    links = facts["vuln_links"] or ["要確認"]
    links_line = "\n".join(links)
    if facts["scores"]:
        max_score = facts["max_score"]
        scores_text = ", ".join(f"{s:.1f}" for s in facts["scores"])
        cvss_line = f"最大 {max_score:.1f}（通知内: {scores_text}）"
    else:
        cvss_line = "要確認"

    entry_lines: list[str] = []
    for e in facts.get("entries", []):
        vuln_id = str(e.get("id") or "").strip()
        score = e.get("cvss")
        title = str(e.get("title") or "").strip()
        url = str(e.get("url") or "").strip()
        score_text = f"{float(score):.1f}" if isinstance(score, (int, float)) else "要確認"
        parts = [f"ID:{vuln_id}" if vuln_id else "ID:要確認", f"CVSS:{score_text}"]
        if title and title != "要確認":
            parts.append(title)
        if url:
            parts.append(url)
        entry_lines.append(" - " + " / ".join(parts))
    entry_text = "\n".join(entry_lines[:12]) if entry_lines else " - 要確認"
    split_note = ""
    if int(facts.get("due_group_count") or 1) > 1:
        split_note = (
            "\n\n【備考】\n"
            "通知内で納期が異なる脆弱性が含まれるため、本起票は同一納期グループでまとめています。"
        )

    return (
        "【対象の機器/アプリ】\n"
        f"{product_line}\n\n"
        "【通知内の脆弱性一覧】\n"
        f"{entry_text}\n\n"
        "【脆弱性情報】\n"
        f"{links_line}\n\n"
        "【CVSSスコア】\n"
        f"{cvss_line}\n\n"
        "【依頼内容】\n"
        "上記脆弱性情報をご確認いただき、該当バージョンの場合はアップデート対応をお願いします。\n"
        "対応を実施した場合は対象ホスト名（または対象端末）をご共有ください。\n\n"
        "【対応完了目標】\n"
        f"{facts.get('due_date') or '要確認'}"
        f"{split_note}"
    )


def _infer_reasoning_from_source(source_text: str) -> str:
    facts = _extract_source_facts(source_text)
    product_text = " / ".join(facts["products"]) if facts["products"] else "要確認"
    links_count = len(facts["vuln_links"])
    entries_count = len(facts.get("entries", []))
    all_entries_count = int(facts.get("all_entries_count") or entries_count)
    if facts["scores"]:
        scores_text = ", ".join(f"{s:.1f}" for s in facts["scores"])
    else:
        scores_text = "要確認"
    return (
        "【判断理由】\n"
        f"- 通知本文から対象製品を抽出: {product_text}\n"
        f"- 通知本文から脆弱性エントリを抽出: {all_entries_count}件（起票対象: {entries_count}件）\n"
        f"- 参照URLを抽出: {links_count}件\n"
        f"- CVSSを抽出: {scores_text}\n"
        f"- 対応完了目標を算出: {facts.get('due_date') or '要確認'}（{facts.get('due_reason') or '根拠不足'}）"
    )


def _is_summary_low_quality(summary: str) -> bool:
    weak_summary_tokens = (
        "はい、承知",
        "承知いたしました",
        "ご依頼のメール内容",
        "判断しました",
        "以下に",
        "テンプレート",
        "作成します",
    )
    return (
        (not summary)
        or len(summary) < 10
        or any(token in summary for token in weak_summary_tokens)
        or ("脆弱性" not in summary and "ペネトレ" not in summary and "アップグレード" not in summary)
    )


def _repair_ticket_summary_if_needed(text: str, source_text: str = "") -> str:
    body = (text or "").strip()
    if not body:
        return body
    lines = body.splitlines()
    summary_idx = -1
    summary = ""
    for i, raw in enumerate(lines):
        line = raw.strip()
        if not line.startswith("依頼概要:"):
            continue
        summary_idx = i
        summary = line.split(":", 1)[1].strip()
        break
    if summary_idx < 0:
        return body

    needs_repair = _is_summary_low_quality(summary)
    if not needs_repair:
        return body

    repaired = _infer_request_summary_from_source(source_text)
    lines[summary_idx] = f"依頼概要: {repaired}"
    return "\n".join(lines).strip()


def _should_rebuild_ticket_text(body: str) -> bool:
    if "詳細: 要確認" in body:
        return True
    if "スレッド文脈が不足" in body and "要確認" in body:
        return True
    summary = ""
    for raw in body.splitlines():
        line = raw.strip()
        if line.startswith("依頼概要:"):
            summary = line.split(":", 1)[1].strip()
            break
    return _is_summary_low_quality(summary)


def _build_ticket_text_from_source(source_text: str) -> str:
    summary = _infer_request_summary_from_source(source_text)
    detail = _infer_ticket_detail_from_source(source_text)
    reasoning = _infer_reasoning_from_source(source_text)
    return (
        "【起票用（コピペ）】\n"
        "大分類: 017.脆弱性対応（情シス専用）\n"
        "小分類: 002.IT基盤チーム\n"
        f"依頼概要: {summary}\n"
        f"詳細:\n{detail}\n\n"
        f"{reasoning}"
    ).strip()


def _format_ticket_like_response(text: str, source_text: str = "") -> str:
    body = (text or "").strip()
    if not body:
        return body
    if _looks_like_internal_artifact(body):
        return _build_low_quality_ticket_message()
    has_copy = "【起票用（コピペ）】" in body
    has_reason = "【判断理由】" in body
    if has_copy and has_reason:
        repaired = _repair_ticket_summary_if_needed(body, source_text)
        if _should_rebuild_ticket_text(repaired):
            return _build_ticket_text_from_source(source_text)
        return repaired

    lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
    noise_prefixes = ("```", "###", "|", ":---", "---")
    summary_candidates = [
        ln for ln in lines if not ln.startswith(noise_prefixes) and not _looks_like_internal_artifact(ln)
    ]
    summary = " / ".join(summary_candidates[:3]) if summary_candidates else ""
    summary = re.sub(r"\s+", " ", summary).strip()[:220]
    if _is_summary_low_quality(summary):
        return _build_ticket_text_from_source(source_text)

    detail = _infer_ticket_detail_from_source(source_text)
    reasoning = _infer_reasoning_from_source(source_text)
    return (
        "【起票用（コピペ）】\n"
        "大分類: 017.脆弱性対応（情シス専用）\n"
        "小分類: 002.IT基盤チーム\n"
        f"依頼概要: {summary}\n"
        f"詳細:\n{detail}\n\n"
        f"{reasoning}"
    ).strip()


def _process_message_event(event: dict[str, Any], user_name: str) -> str | None:
    raw_text = str(((event.get("message") or {}).get("text") or "")).strip()
    prompt = _clean_chat_text(event)
    is_gmail_post = _is_gmail_app_message(event)
    history_key = _context_key(event, user_name)
    prefer_ticket_format = False
    save_ticket_history = False
    manual_backfill_mode = False
    raw_body_text = _strip_mentions_preserve_lines(raw_text)
    source_text_for_quality = ""
    if is_gmail_post:
        message_payload_text = _extract_message_text_payload((event.get("message") or {}))
        source_text_for_quality = message_payload_text or raw_text
        _remember_thread_root_text(event, source_text_for_quality)
        prompt = _build_vulnerability_ticket_prompt(source_text_for_quality)
        prefer_ticket_format = True
        save_ticket_history = True
    elif _contains_manual_ticket_trigger(raw_body_text):
        manual_source = _resolve_manual_backfill_source_text(event, raw_body_text)
        if not manual_source:
            return _build_backfill_guidance_message()
        source_text_for_quality = manual_source
        _remember_thread_root_text(event, manual_source)
        prompt = _build_vulnerability_ticket_prompt(manual_source)
        prefer_ticket_format = True
        save_ticket_history = True
        manual_backfill_mode = True
    elif _is_correction_prompt(prompt):
        if _extract_incident_id(prompt):
            pass
        else:
            root_text = _fetch_thread_root_message_text(event)
            resolved_incident = _extract_incident_id(root_text)
            if not resolved_incident:
                recent_turns = _get_recent_turns(history_key, max_turns=2)
                for turn in reversed(recent_turns):
                    candidate = _extract_incident_id(turn.get("assistant", ""))
                    if candidate:
                        resolved_incident = candidate
                        break
            if not resolved_incident:
                history_ticket = _fetch_latest_ticket_record_from_history(event)
                resolved_incident = str(history_ticket.get("incident_id") or "").strip()
            if not resolved_incident:
                return (
                    "このスレッドから incident_id を特定できませんでした。"
                    " 直近の通知に含まれる【管理ID】を指定して再度「修正して」と依頼してください。"
                )
            prompt = _build_review_prompt_with_incident_id(prompt, resolved_incident)
    elif not prompt:
        return None
    elif _is_analysis_trigger_prompt(prompt) and _requests_thread_root_context(prompt):
        root_text = _fetch_thread_root_message_text(event)
        if not root_text:
            root_text = _get_cached_thread_root_text(event)
        if root_text:
            if _looks_like_gmail_digest(root_text):
                prompt = _build_vulnerability_ticket_prompt(root_text)
                prefer_ticket_format = True
            else:
                prompt = _build_thread_root_analysis_prompt(prompt, root_text)
        else:
            return _build_clarification_message()
    elif _is_analysis_trigger_prompt(prompt) and _is_ambiguous_prompt(prompt):
        root_text = _fetch_thread_root_message_text(event)
        if not root_text:
            root_text = _get_cached_thread_root_text(event)
        if root_text:
            prompt = _build_vulnerability_ticket_prompt(root_text)
            prefer_ticket_format = True
        else:
            message = event.get("message") or {}
            thread_name = ((message.get("thread") or {}).get("name") or "").strip()
            if thread_name:
                history_ticket = _fetch_latest_ticket_record_from_history(event)
                history_message = _build_history_ticket_message(history_ticket)
                if history_message:
                    _remember_turn(history_key, _clean_chat_text(event), history_message)
                    return history_message
                recent_turns = _get_recent_turns(history_key, max_turns=2)
                if recent_turns:
                    contextual = _build_contextual_prompt(prompt, recent_turns)
                    prompt = _build_thread_followup_prompt(contextual)
                else:
                    return _build_backfill_guidance_message()
                prefer_ticket_format = True
            else:
                return _build_clarification_message()
    elif _is_ambiguous_prompt(prompt):
        recent_turns = _get_recent_turns(history_key, max_turns=2)
        if not recent_turns:
            return _build_clarification_message()
        prompt = _build_contextual_prompt(prompt, recent_turns)

    response_text = _run_agent_query(prompt, history_key)
    if manual_backfill_mode:
        if not _is_manual_ticket_output_usable(response_text):
            return _build_backfill_guidance_message()
        if save_ticket_history:
            _save_ticket_record_to_history(event, response_text, source="chat_webhook_manual")
    elif prefer_ticket_format:
        if not _is_auto_ticket_output_usable(response_text):
            if is_gmail_post and not _contains_specific_vuln_signal(source_text_for_quality):
                return _build_low_quality_ticket_message()
            response_text = _format_ticket_like_response(response_text, source_text_for_quality)
    _remember_turn(history_key, _clean_chat_text(event), response_text)
    return response_text


def _run_async_message_processing(event: dict[str, Any], user_name: str) -> None:
    try:
        text = _process_message_event(event, user_name)
        if not text:
            return
        _send_message_to_thread(event, text)
    except Exception as exc:
        logger.exception("Failed async chat processing: %s", exc)
        try:
            _send_message_to_thread(event, f"処理中にエラーが発生しました: {exc}")
        except Exception:
            pass


@functions_framework.http
def handle_chat_event(request):
    try:
        event = request.get_json(silent=True) or {}
    except Exception:
        event = {}

    if not event:
        return json.dumps({"text": "Invalid request"}), 400, {"Content-Type": "application/json"}

    if _is_cloud_tasks_request(request, event):
        chat_event = event.get("chat_event") if isinstance(event.get("chat_event"), dict) else {}
        user_name = str(event.get("user_name") or "google-chat-user")
        if not chat_event:
            return json.dumps({"status": "ignored", "reason": "missing chat_event"}, ensure_ascii=False), 200, {
                "Content-Type": "application/json"
            }
        try:
            response_text = _process_message_event(chat_event, user_name)
            if response_text:
                _send_message_to_thread(chat_event, response_text)
            return json.dumps({"status": "ok"}, ensure_ascii=False), 200, {"Content-Type": "application/json"}
        except Exception as exc:
            logger.exception("Failed to process Cloud Tasks async request: %s", exc)
            try:
                _send_message_to_thread(chat_event, f"処理中にエラーが発生しました: {exc}")
            except Exception:
                pass
            return json.dumps({"status": "error"}, ensure_ascii=False), 200, {"Content-Type": "application/json"}

    if not _is_valid_token(event):
        return json.dumps({"text": "Unauthorized"}), 403, {"Content-Type": "application/json"}

    event_type = event.get("type", "")
    user = event.get("user") or {}
    user_name = (user.get("name") or "").replace("users/", "") or "google-chat-user"

    if event_type == "ADDED_TO_SPACE":
        text = "追加ありがとうございます。Gmail通知投稿を検知して自動分析し、このスレッドに返信します。"
        return json.dumps({"text": text}, ensure_ascii=False), 200, {"Content-Type": "application/json"}

    if event_type != "MESSAGE":
        return json.dumps({"text": "Unsupported event type"}), 200, {"Content-Type": "application/json"}

    if _is_async_response_enabled():
        if not _is_message_actionable(event):
            return json.dumps({}, ensure_ascii=False), 200, {"Content-Type": "application/json"}
        if not _register_async_event_once(event):
            return json.dumps({}, ensure_ascii=False), 200, {"Content-Type": "application/json"}
        try:
            _send_message_to_thread(event, "思考中です。分析が完了したらこのスレッドに結果を送信します。")
        except Exception as exc:
            logger.warning("Failed to send thinking message: %s", exc)
        _submit_async_job(event, user_name)
        return json.dumps({}, ensure_ascii=False), 200, {"Content-Type": "application/json"}

    try:
        response_text = _process_message_event(event, user_name)
        if response_text is None:
            return json.dumps({}, ensure_ascii=False), 200, {"Content-Type": "application/json"}
        return json.dumps(_thread_payload(event, response_text), ensure_ascii=False), 200, {
            "Content-Type": "application/json"
        }
    except Exception as exc:
        logger.exception("Failed to handle chat event: %s", exc)
        return json.dumps(
            _thread_payload(event, f"処理中にエラーが発生しました: {exc}"),
            ensure_ascii=False,
        ), 200, {"Content-Type": "application/json"}
