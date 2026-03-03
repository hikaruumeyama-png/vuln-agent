"""
Google Workspace Events webhook for Chat event-triggered analysis.

対応イベント:
  - reaction.created / batchCreated: ？リアクションで元メッセージを解析
  - message.created / batchCreated: Gmail アプリ投稿（SIDfm通知等）を自動解析

サブスクリプション自動更新:
  Cloud Scheduler から /renew パスで呼び出すとサブスクリプションを再作成する。
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
from typing import Any

import functions_framework
import google.auth
import google.auth.transport.requests
from googleapiclient.discovery import build

from shared.agent_query import run_agent_query
from shared.ticket_pipeline import generate_ticket

logger = logging.getLogger(__name__)

_EVENT_CACHE: dict[str, bool] = {}
_EVENT_CACHE_LIMIT = 1000
_QUESTION_EMOJIS = {"?", "？", "❓", "⁉️", "❔"}
_WORKSPACE_REACTION_TYPES = {
    "google.workspace.chat.reaction.v1.created",
    "google.workspace.chat.reaction.v1.batchCreated",
}
_WORKSPACE_MESSAGE_TYPES = {
    "google.workspace.chat.message.v1.created",
    "google.workspace.chat.message.v1.batchCreated",
}
_SUPPORTED_EVENT_TYPES = _WORKSPACE_REACTION_TYPES | _WORKSPACE_MESSAGE_TYPES

_WORKSPACE_EVENTS_API = "https://workspaceevents.googleapis.com/v1/subscriptions"
_DEFAULT_SUBSCRIPTION_EVENT_TYPES = [
    "google.workspace.chat.message.v1.created",
    "google.workspace.chat.reaction.v1.created",
]


def _get_project_id() -> str:
    return (
        os.environ.get("GCP_PROJECT_ID")
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
        or os.environ.get("GCLOUD_PROJECT")
        or ""
    )


def _extract_source_text(source_message: dict[str, Any]) -> str:
    """Chat メッセージからソーステキストを抽出する。"""
    raw_text = str(source_message.get("text") or source_message.get("formattedText") or "").strip()
    if not raw_text:
        raw_text = json.dumps(source_message, ensure_ascii=False)
    return raw_text


def _build_chat_service():
    """Bot 認証の Chat サービス（メッセージ送信用）。"""
    credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/chat.bot"])
    return build("chat", "v1", credentials=credentials, cache_discovery=False)


def _build_chat_reader_service():
    """OAuth ユーザー認証の Chat サービス（メッセージ読み取り用）。

    chat.bot スコープではBot自身のメッセージしか読めないため、
    他ユーザーのメッセージ取得には OAuth ユーザー認証が必要。
    """
    creds = _get_oauth_credentials()
    return build("chat", "v1", credentials=creds, cache_discovery=False)


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


def _looks_like_gmail_message(chat_message: dict[str, Any]) -> bool:
    """Workspace Events API 経由のメッセージが Gmail アプリ投稿かを判定する。"""
    sender = chat_message.get("sender") or {}
    sender_name = str(sender.get("displayName") or "").lower()
    sender_type = str(sender.get("type") or "").upper()

    if "gmail" in sender_name:
        return True
    if sender_type == "BOT" and "gmail" in str(sender.get("name") or "").lower():
        return True

    text = str(chat_message.get("text") or "").lower()
    signals = 0
    if "from:" in text or "差出人:" in text:
        signals += 1
    if "subject:" in text or "件名:" in text:
        signals += 1
    if re.search(r"^\[[^\]]+\]", str(chat_message.get("text") or "").strip()):
        signals += 1
    if "view message" in text:
        signals += 1
    if "to view the full email" in text or "google groups" in text:
        signals += 1
    if re.search(r"\bcve-\d{4}-\d{4,9}\b", text):
        signals += 1
    return signals >= 2


def _extract_messages(event_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Workspace Events API のメッセージイベントからメッセージを抽出する。"""
    if isinstance(event_data.get("message"), dict):
        return [event_data["message"]]
    items = event_data.get("messages") or []
    messages: list[dict[str, Any]] = []
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("message"), dict):
                messages.append(item["message"])
            elif isinstance(item, dict):
                messages.append(item)
    return messages


def _handle_message_events(
    event_id: str, event_data: dict[str, Any], service: Any,
) -> int:
    """Gmail アプリ投稿のメッセージイベントを処理する。"""
    messages = _extract_messages(event_data)
    if not messages:
        return 0

    processed = 0
    for msg in messages:
        if not _looks_like_gmail_message(msg):
            continue

        message_name = str(msg.get("name") or "").strip()
        if not message_name:
            continue

        event_key = f"{event_id}:{message_name}"
        if _is_duplicate_event(event_key):
            continue

        space_name = _space_from_message_name(message_name)
        thread_name = str((msg.get("thread") or {}).get("name") or "").strip()
        if not space_name:
            continue

        try:
            logger.info("Gmail message detected: %s in %s", message_name, space_name)
            source_text = _extract_source_text(msg)
            result = generate_ticket(
                source_text=source_text,
                agent_query_fn=run_agent_query,
                history_key="workspace_gmail",
                space_id=space_name,
                thread_name=thread_name,
            )
            response_text = result.text

            body: dict[str, Any] = {"text": response_text}
            if thread_name:
                body["thread"] = {"name": thread_name}
            service.spaces().messages().create(
                parent=space_name,
                body=body,
                messageReplyOption="REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD",
            ).execute()
            processed += 1
            logger.info("Replied to Gmail message: %s (status=%s)", message_name, result.status)
        except Exception as exc:
            logger.exception("Failed to process Gmail message event: %s", exc)

    return processed


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


def _get_oauth_credentials():
    """Secret Manager からユーザー OAuth 認証情報を取得する。"""
    from google.cloud import secretmanager
    from google.oauth2.credentials import Credentials as OAuthCredentials

    project_id = _get_project_id()
    secret_name = os.environ.get(
        "WORKSPACE_EVENTS_OAUTH_SECRET",
        "vuln-agent-workspace-events-oauth-token",
    )
    client = secretmanager.SecretManagerServiceClient()
    resource = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
    response = client.access_secret_version(request={"name": resource})
    token_data = json.loads(response.payload.data.decode("utf-8"))

    creds = OAuthCredentials.from_authorized_user_info(token_data)
    if not creds.valid:
        creds.refresh(google.auth.transport.requests.Request())
    return creds


def _renew_subscription() -> dict[str, Any]:
    """Workspace Events API サブスクリプションを再作成する。

    Workspace Events API はユーザー OAuth 認証が必須のため、
    Secret Manager に保存された OAuth トークンを使用する。

    環境変数:
      WORKSPACE_EVENTS_SPACE_ID: 対象スペース (デフォルト: spaces/AAAA--pjkDQ)
      WORKSPACE_EVENTS_PUBSUB_TOPIC: Pub/Sub トピック
      WORKSPACE_EVENTS_OAUTH_SECRET: OAuth トークンのシークレット名
    """
    import urllib.request
    import urllib.error

    project_id = _get_project_id()
    space_id = os.environ.get("WORKSPACE_EVENTS_SPACE_ID", "spaces/AAAA--pjkDQ")
    topic = os.environ.get(
        "WORKSPACE_EVENTS_PUBSUB_TOPIC",
        f"projects/{project_id}/topics/vuln-agent-workspace-events",
    )

    creds = _get_oauth_credentials()

    body = {
        "targetResource": f"//chat.googleapis.com/{space_id}",
        "eventTypes": _DEFAULT_SUBSCRIPTION_EVENT_TYPES,
        "notificationEndpoint": {"pubsubTopic": topic},
        "payloadOptions": {"includeResource": True},
    }

    headers = {
        "Authorization": f"Bearer {creds.token}",
        "Content-Type": "application/json",
    }

    def _create() -> dict[str, Any]:
        req = urllib.request.Request(
            _WORKSPACE_EVENTS_API,
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _delete_subscription(sub_name: str) -> None:
        del_url = f"https://workspaceevents.googleapis.com/v1/{sub_name}"
        del_req = urllib.request.Request(del_url, headers=headers, method="DELETE")
        with urllib.request.urlopen(del_req, timeout=30) as resp:
            resp.read()
        logger.info("Deleted existing subscription: %s", sub_name)

    # 作成を試み、409 なら既存を削除してリトライ
    try:
        result = _create()
        logger.info("Subscription renewed: %s", result.get("name", ""))
        return {"status": "renewed", "result": result}
    except urllib.error.HTTPError as e:
        if e.code != 409:
            error_body = e.read().decode("utf-8", errors="replace")
            logger.error("Subscription renewal failed (%s): %s", e.code, error_body)
            return {"status": "error", "code": e.code, "message": error_body}

        # 409: 既存サブスクリプション名をエラーレスポンスから取得して削除
        error_body = e.read().decode("utf-8", errors="replace")
        try:
            error_data = json.loads(error_body)
            details = error_data.get("error", {}).get("details", [])
            existing_sub = ""
            for detail in details:
                metadata = detail.get("metadata", {})
                if metadata.get("current_subscription"):
                    existing_sub = metadata["current_subscription"]
                    break
            if existing_sub:
                _delete_subscription(existing_sub)
        except Exception as del_exc:
            logger.warning("Failed to delete existing subscription: %s", del_exc)

    # リトライ
    try:
        result = _create()
        logger.info("Subscription renewed (retry): %s", result.get("name", ""))
        return {"status": "renewed", "result": result}
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        logger.error("Subscription renewal failed on retry (%s): %s", e.code, error_body)
        return {"status": "error", "code": e.code, "message": error_body}


@functions_framework.http
def handle_workspace_event(request):
    # --- サブスクリプション自動更新 (Cloud Scheduler から呼び出し) ---
    if request.path.rstrip("/").endswith("/renew"):
        result = _renew_subscription()
        status_code = 200 if result.get("status") != "error" else 500
        return json.dumps(result, ensure_ascii=False), status_code, {
            "Content-Type": "application/json"
        }

    try:
        payload = request.get_json(silent=True) or {}
    except Exception:
        payload = {}

    event_type, event_id, event_data = _extract_event(payload)
    if event_type not in _SUPPORTED_EVENT_TYPES:
        return json.dumps({"status": "ignored", "reason": "unsupported_event"}), 200, {
            "Content-Type": "application/json"
        }

    # --- event_id レベルの早期重複排除 ---
    # Pub/Sub リトライで同一イベントが複数回配信される場合の防御。
    if event_id and _is_duplicate_event(f"top:{event_id}"):
        logger.info("Duplicate event_id detected at entry, skipping: %s", event_id)
        return json.dumps({"status": "duplicate", "event_id": event_id}), 200, {
            "Content-Type": "application/json"
        }

    service = _build_chat_service()

    # --- メッセージイベント: Gmail アプリ投稿を処理 ---
    if event_type in _WORKSPACE_MESSAGE_TYPES:
        processed = _handle_message_events(event_id, event_data, service)
        return json.dumps({"status": "ok", "processed": processed}, ensure_ascii=False), 200, {
            "Content-Type": "application/json"
        }

    # --- リアクションイベント: ？リアクションを処理 ---
    reactions = _extract_reactions(event_data)
    if not reactions:
        return json.dumps({"status": "ignored", "reason": "no_reaction"}), 200, {"Content-Type": "application/json"}

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
            reader = _build_chat_reader_service()
            source_message = reader.spaces().messages().get(name=message_name).execute()
            thread_name = str(((source_message.get("thread") or {}).get("name") or "")).strip()
            space_name = _space_from_message_name(message_name)
            if not space_name:
                continue

            source_text = _extract_source_text(source_message)
            result = generate_ticket(
                source_text=source_text,
                agent_query_fn=run_agent_query,
                history_key="workspace_reaction",
                space_id=space_name,
                thread_name=thread_name,
            )
            response_text = result.text

            body: dict[str, Any] = {"text": response_text}
            if thread_name:
                body["thread"] = {"name": thread_name}
            service.spaces().messages().create(
                parent=space_name,
                body=body,
                messageReplyOption="REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD",
            ).execute()
            processed += 1
            logger.info("Replied to reaction: %s (status=%s)", message_name, result.status)
        except Exception as exc:
            logger.exception("Failed to process reaction event: %s", exc)

    return json.dumps({"status": "ok", "processed": processed}, ensure_ascii=False), 200, {
        "Content-Type": "application/json"
    }
