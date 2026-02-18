"""Google Chat webhook handler for message-triggered vulnerability analysis."""

from __future__ import annotations

import asyncio
from collections import deque
import json
import logging
import os
import re
from typing import Any

import functions_framework
import vertexai

logger = logging.getLogger(__name__)

_secret_client = None
_chat_service_client = None
_RECENT_TURNS: dict[str, deque[dict[str, str]]] = {}
_THREAD_ROOT_CACHE: dict[str, str] = {}
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


def _get_chat_service():
    global _chat_service_client
    if _chat_service_client is not None:
        return _chat_service_client

    from googleapiclient.discovery import build

    scopes = [
        "https://www.googleapis.com/auth/chat.bot",
        "https://www.googleapis.com/auth/chat.messages.readonly",
    ]
    sa_json = _get_config("CHAT_SA_CREDENTIALS_JSON", "vuln-agent-chat-sa-key", "")
    if sa_json:
        try:
            from google.oauth2 import service_account

            sa_info = json.loads(sa_json)
            credentials = service_account.Credentials.from_service_account_info(sa_info, scopes=scopes)
            _chat_service_client = build("chat", "v1", credentials=credentials, cache_discovery=False)
            logger.info("Thread fetch uses Chat app SA credentials from secret")
            return _chat_service_client
        except Exception as exc:
            logger.warning("Failed to init Chat service from SA secret: %s", exc)

    import google.auth

    credentials, _ = google.auth.default(scopes=scopes)
    _chat_service_client = build("chat", "v1", credentials=credentials, cache_discovery=False)
    logger.warning("Thread fetch uses ADC fallback credentials")
    return _chat_service_client


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
        service = _get_chat_service()

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
            response = service.spaces().messages().list(**kwargs).execute()
            messages = response.get("messages") or []
            return [m for m in messages if isinstance(m, dict)]

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

        # Prefer substantial root-like text (e.g., Gmail digest/card content).
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


@functions_framework.http
def handle_chat_event(request):
    try:
        event = request.get_json(silent=True) or {}
    except Exception:
        event = {}

    if not event:
        return json.dumps({"text": "Invalid request"}), 400, {"Content-Type": "application/json"}

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

    raw_text = str(((event.get("message") or {}).get("text") or "")).strip()
    prompt = _clean_chat_text(event)
    is_gmail_post = _is_gmail_app_message(event)
    history_key = _context_key(event, user_name)
    if is_gmail_post:
        _remember_thread_root_text(event, raw_text)
        prompt = _build_vulnerability_ticket_prompt(raw_text)
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
                return json.dumps(
                    _thread_payload(
                        event,
                        "このスレッドから incident_id を特定できませんでした。"
                        " 直近の通知に含まれる【管理ID】を指定して再度「修正して」と依頼してください。",
                    ),
                    ensure_ascii=False,
                ), 200, {"Content-Type": "application/json"}
            prompt = _build_review_prompt_with_incident_id(prompt, resolved_incident)
    elif not prompt:
        # メンションでもGmail投稿でもない通常メッセージは何もしない。
        return json.dumps({}, ensure_ascii=False), 200, {"Content-Type": "application/json"}
    elif _is_analysis_trigger_prompt(prompt) and _requests_thread_root_context(prompt):
        root_text = _fetch_thread_root_message_text(event)
        if not root_text:
            root_text = _get_cached_thread_root_text(event)
        if root_text:
            if _looks_like_gmail_digest(root_text):
                prompt = _build_vulnerability_ticket_prompt(root_text)
            else:
                prompt = _build_thread_root_analysis_prompt(prompt, root_text)
        else:
            return json.dumps(_thread_payload(event, _build_clarification_message()), ensure_ascii=False), 200, {
                "Content-Type": "application/json"
            }
    elif _is_analysis_trigger_prompt(prompt) and _is_ambiguous_prompt(prompt):
        root_text = _fetch_thread_root_message_text(event)
        if not root_text:
            root_text = _get_cached_thread_root_text(event)
        if root_text:
            prompt = _build_vulnerability_ticket_prompt(root_text)
        else:
            return json.dumps(_thread_payload(event, _build_clarification_message()), ensure_ascii=False), 200, {
                "Content-Type": "application/json"
            }
    elif _is_ambiguous_prompt(prompt):
        recent_turns = _get_recent_turns(history_key, max_turns=2)
        if not recent_turns:
            return json.dumps(_thread_payload(event, _build_clarification_message()), ensure_ascii=False), 200, {
                "Content-Type": "application/json"
            }
        prompt = _build_contextual_prompt(prompt, recent_turns)

    try:
        response_text = _run_agent_query(prompt, user_name)
        if not is_gmail_post:
            _remember_turn(history_key, _clean_chat_text(event), response_text)
        return json.dumps(_thread_payload(event, response_text), ensure_ascii=False), 200, {
            "Content-Type": "application/json"
        }
    except Exception as exc:
        logger.exception("Failed to handle chat event: %s", exc)
        return json.dumps(
            _thread_payload(event, f"処理中にエラーが発生しました: {exc}"),
            ensure_ascii=False,
        ), 200, {"Content-Type": "application/json"}
