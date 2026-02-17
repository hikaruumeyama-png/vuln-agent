"""
Google Workspace Events webhook for Chat reaction-triggered analysis.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
from typing import Any

import functions_framework
import google.auth
from googleapiclient.discovery import build
import vertexai

logger = logging.getLogger(__name__)

_EVENT_CACHE: dict[str, bool] = {}
_EVENT_CACHE_LIMIT = 1000
_QUESTION_EMOJIS = {"?", "？", "❓", "⁉️", "❔"}
_WORKSPACE_REACTION_TYPES = {
    "google.workspace.chat.reaction.v1.created",
    "google.workspace.chat.reaction.v1.batchCreated",
}


def _get_project_id() -> str:
    return (
        os.environ.get("GCP_PROJECT_ID")
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
        or os.environ.get("GCLOUD_PROJECT")
        or ""
    )


def _run_agent_query(prompt: str, user_id: str) -> str:
    project_id = _get_project_id()
    location = os.environ.get("GCP_LOCATION", "asia-northeast1")
    agent_name = (os.environ.get("AGENT_RESOURCE_NAME") or "").strip()
    if not project_id or not agent_name:
        raise RuntimeError("GCP_PROJECT_ID and AGENT_RESOURCE_NAME are required")

    vertexai.init(project=project_id, location=location)
    from vertexai import Client

    client = Client(project=project_id, location=location)
    app = client.agent_engines.get(name=agent_name)
    chunks: list[str] = []

    async def execute_query() -> None:
        async for event in app.async_stream_query(
            user_id=user_id or "workspace-events-user",
            message=prompt,
        ):
            content = getattr(event, "content", None)
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

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(execute_query())
    finally:
        loop.close()

    text = "\n".join([line.strip() for line in chunks if line and line.strip()]).strip()
    if not text:
        return "回答を生成できませんでした。もう一度お試しください。"
    return text[:3500]


def _build_chat_service():
    credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/chat.bot"])
    return build("chat", "v1", credentials=credentials, cache_discovery=False)


def _extract_event(payload: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    # Pub/Sub push format from Workspace Events API.
    message = payload.get("message") or {}
    attributes = message.get("attributes") or {}
    event_type = str(attributes.get("ce-type") or "")
    event_id = str(attributes.get("ce-id") or "")

    encoded = str(message.get("data") or "")
    event_data: dict[str, Any] = {}
    if encoded:
        try:
            decoded = base64.b64decode(encoded).decode("utf-8")
            parsed = json.loads(decoded)
            if isinstance(parsed, dict):
                event_data = parsed
        except Exception:
            event_data = {}

    # Fallback for direct JSON tests.
    if not event_type:
        event_type = str(payload.get("ce-type") or payload.get("eventType") or "")
    if not event_id:
        event_id = str(payload.get("ce-id") or payload.get("eventId") or "")
    if not event_data and isinstance(payload.get("data"), dict):
        event_data = payload.get("data") or {}
    return event_type, event_id, event_data


def _message_name_from_reaction_name(reaction_name: str) -> str:
    reaction_name = (reaction_name or "").strip()
    marker = "/reactions/"
    if marker in reaction_name:
        return reaction_name.split(marker, 1)[0]
    return ""


def _extract_reactions(event_data: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(event_data.get("reaction"), dict):
        return [event_data["reaction"]]
    items = event_data.get("reactions") or []
    reactions: list[dict[str, Any]] = []
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("reaction"), dict):
                reactions.append(item["reaction"])
            elif isinstance(item, dict):
                reactions.append(item)
    return reactions


def _is_question_reaction(reaction: dict[str, Any]) -> bool:
    emoji = (reaction.get("emoji") or {})
    unicode_emoji = str(emoji.get("unicode") or "").strip()
    custom_emoji = str((emoji.get("customEmoji") or {}).get("uid") or "").strip()
    return unicode_emoji in _QUESTION_EMOJIS or custom_emoji in _QUESTION_EMOJIS


def _user_id_from_reaction(reaction: dict[str, Any]) -> str:
    user_name = str((reaction.get("user") or {}).get("name") or "").strip()
    if user_name.startswith("users/"):
        return user_name.replace("users/", "", 1)
    return user_name or "workspace-events-user"


def _space_from_message_name(message_name: str) -> str:
    if not message_name.startswith("spaces/"):
        return ""
    parts = message_name.split("/")
    if len(parts) < 2:
        return ""
    return f"{parts[0]}/{parts[1]}"


def _analysis_prompt_from_source_message(source_message: dict[str, Any]) -> str:
    raw_text = str(source_message.get("text") or source_message.get("formattedText") or "").strip()
    if not raw_text:
        raw_text = json.dumps(source_message, ensure_ascii=False)
    return (
        "以下はGoogle Chatのスレッド元メッセージです。"
        "脆弱性関連通知かを判定し、該当する場合は依頼票テンプレートを埋めて出力してください。"
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
        f"{raw_text}"
    )


def _is_duplicate_event(event_key: str) -> bool:
    if not event_key:
        return False
    if event_key in _EVENT_CACHE:
        return True
    _EVENT_CACHE[event_key] = True
    if len(_EVENT_CACHE) > _EVENT_CACHE_LIMIT:
        # FIFO behavior is not required; drop oldest inserted key.
        first_key = next(iter(_EVENT_CACHE.keys()))
        _EVENT_CACHE.pop(first_key, None)
    return False


@functions_framework.http
def handle_workspace_event(request):
    try:
        payload = request.get_json(silent=True) or {}
    except Exception:
        payload = {}

    event_type, event_id, event_data = _extract_event(payload)
    if event_type not in _WORKSPACE_REACTION_TYPES:
        return json.dumps({"status": "ignored", "reason": "unsupported_event"}), 200, {
            "Content-Type": "application/json"
        }

    reactions = _extract_reactions(event_data)
    if not reactions:
        return json.dumps({"status": "ignored", "reason": "no_reaction"}), 200, {"Content-Type": "application/json"}

    service = _build_chat_service()
    processed = 0
    for reaction in reactions:
        if not _is_question_reaction(reaction):
            continue

        reaction_name = str(reaction.get("name") or "").strip()
        message_name = _message_name_from_reaction_name(reaction_name)
        if not message_name:
            continue

        event_key = f"{event_id}:{reaction_name}"
        if _is_duplicate_event(event_key):
            continue

        try:
            source_message = service.spaces().messages().get(name=message_name).execute()
            thread_name = str(((source_message.get("thread") or {}).get("name") or "")).strip()
            space_name = _space_from_message_name(message_name)
            if not space_name:
                continue

            prompt = _analysis_prompt_from_source_message(source_message)
            response_text = _run_agent_query(prompt, _user_id_from_reaction(reaction))

            body: dict[str, Any] = {"text": response_text}
            if thread_name:
                body["thread"] = {"name": thread_name}
            service.spaces().messages().create(
                parent=space_name,
                body=body,
                messageReplyOption="REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD",
            ).execute()
            processed += 1
        except Exception as exc:
            logger.exception("Failed to process reaction event: %s", exc)

    return json.dumps({"status": "ok", "processed": processed}, ensure_ascii=False), 200, {
        "Content-Type": "application/json"
    }

