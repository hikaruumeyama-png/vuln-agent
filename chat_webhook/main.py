"""Google Chat webhook handler for message-triggered vulnerability analysis."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from typing import Any

import functions_framework
import vertexai

logger = logging.getLogger(__name__)

_secret_client = None


def _get_secret_client():
    global _secret_client
    if _secret_client is None:
        from google.cloud import secretmanager

        _secret_client = secretmanager.SecretManagerServiceClient()
    return _secret_client


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
    return (
        ("subject:" in t and "from:" in t)
        or ("差出人:" in t and "件名:" in t)
        or ("gmail" in t and "new email" in t)
    )


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


def _run_agent_query(prompt: str, user_id: str) -> str:
    project_id = _get_project_id()
    location = os.environ.get("GCP_LOCATION", "asia-northeast1")
    agent_name = (
        (os.environ.get("AGENT_RESOURCE_NAME") or "").strip()
        or _get_config("AGENT_RESOURCE_NAME", "vuln-agent-resource-name", "")
    )
    if not project_id or not agent_name:
        raise RuntimeError("GCP_PROJECT_ID and AGENT_RESOURCE_NAME are required")

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
        return "\n".join(selected[:6]).strip()

    result = _normalize_chunks(chunks)
    if not result:
        return "回答を生成できませんでした。もう一度お試しください。"
    return result[:3500]


def _thread_payload(event: dict[str, Any], text: str) -> dict[str, Any]:
    message = event.get("message") or {}
    thread_name = ((message.get("thread") or {}).get("name") or "").strip()
    payload: dict[str, Any] = {"text": text}
    if thread_name:
        payload["thread"] = {"name": thread_name}
    return payload


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
    if is_gmail_post:
        prompt = (
            "以下はGmailアプリがChatに投稿したメール内容です。"
            "脆弱性通知として解析し、重要なポイントを簡潔に要約してください。"
            "CVE/CVSS/影響システム/推奨対応を優先して示し、必要なら担当者通知アクションを実行してください。\n\n"
            f"{raw_text}"
        )
    elif not prompt:
        # メンションでもGmail投稿でもない通常メッセージは何もしない。
        return json.dumps({}, ensure_ascii=False), 200, {"Content-Type": "application/json"}

    try:
        response_text = _run_agent_query(prompt, user_name)
        return json.dumps(_thread_payload(event, response_text), ensure_ascii=False), 200, {
            "Content-Type": "application/json"
        }
    except Exception as exc:
        logger.exception("Failed to handle chat event: %s", exc)
        return json.dumps(
            _thread_payload(event, f"処理中にエラーが発生しました: {exc}"),
            ensure_ascii=False,
        ), 200, {"Content-Type": "application/json"}
