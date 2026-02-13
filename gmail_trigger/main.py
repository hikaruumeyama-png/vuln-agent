"""
Gmail Push Trigger for vulnerability scan execution.

Flow:
  Pub/Sub (Gmail push) -> Cloud Function -> Gmail lightweight filter -> Agent Engine
"""

from __future__ import annotations

import asyncio
import base64
import datetime as dt
import json
import logging
import os
from typing import Any

import functions_framework
import vertexai
from googleapiclient.discovery import build

logger = logging.getLogger(__name__)

GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.modify"
DEFAULT_SIDFM_SENDER = "noreply@sidfm.com"
DEFAULT_SUBJECT_TAG = "[SIDfm]"
DEFAULT_NEWER_THAN = "7d"
DEFAULT_TOPIC = "vuln-agent-gmail-events"

_secret_client = None
_gmail_service = None


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


def _get_gmail_service():
    global _gmail_service
    if _gmail_service is not None:
        return _gmail_service

    oauth_token = _get_config("GMAIL_OAUTH_TOKEN", "vuln-agent-gmail-oauth-token", "")
    gmail_user = _get_config("GMAIL_USER_EMAIL", "vuln-agent-gmail-user-email", "")

    credentials = None

    if oauth_token:
        try:
            from google.auth.transport.requests import Request
            from google.oauth2.credentials import Credentials

            token_json = base64.b64decode(oauth_token).decode("utf-8")
            token_data = json.loads(token_json)

            credentials = Credentials(
                token=token_data.get("token"),
                refresh_token=token_data.get("refresh_token"),
                token_uri=token_data.get("token_uri", "https://oauth2.googleapis.com/token"),
                client_id=token_data.get("client_id"),
                client_secret=token_data.get("client_secret"),
                scopes=token_data.get("scopes", [GMAIL_SCOPE]),
            )
            if credentials.refresh_token:
                credentials.refresh(Request())
                logger.info("OAuth token refreshed for Gmail trigger")
        except Exception as exc:
            logger.error("OAuth token error: %s", exc)
            credentials = None

    if not credentials and gmail_user:
        try:
            from google.oauth2 import service_account

            sa_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
            if sa_path and os.path.exists(sa_path):
                credentials = service_account.Credentials.from_service_account_file(
                    sa_path,
                    scopes=[GMAIL_SCOPE],
                    subject=gmail_user,
                )
        except Exception as exc:
            logger.error("Domain delegation auth error: %s", exc)
            credentials = None

    if not credentials:
        from google.auth import default

        credentials, _ = default(scopes=[GMAIL_SCOPE])

    _gmail_service = build("gmail", "v1", credentials=credentials)
    return _gmail_service


def _build_sidfm_query(sender: str, subject_tag: str, newer_than: str) -> str:
    safe_subject = (subject_tag or DEFAULT_SUBJECT_TAG).replace('"', "")
    safe_sender = sender or DEFAULT_SIDFM_SENDER
    safe_newer_than = newer_than or DEFAULT_NEWER_THAN
    return f'(from:{safe_sender} OR subject:"{safe_subject}") is:unread newer_than:{safe_newer_than}'


def _parse_pubsub_payload(cloud_event: Any) -> dict[str, Any]:
    raw = ""
    try:
        data = cloud_event.get("data") if isinstance(cloud_event, dict) else getattr(cloud_event, "data", {})
        if isinstance(data, dict):
            raw = ((data.get("message") or {}).get("data") or "").strip()
        if not raw:
            return {}
        decoded = base64.b64decode(raw).decode("utf-8")
        return json.loads(decoded)
    except Exception:
        return {}


def _has_matching_unread_email(service, query: str, max_results: int = 5) -> bool:
    result = service.users().messages().list(
        userId="me",
        q=query,
        maxResults=max_results,
    ).execute()
    return bool(result.get("messages", []))


def _run_agent_scan(reason: str) -> dict[str, Any]:
    project_id = _get_project_id()
    location = os.environ.get("GCP_LOCATION", "asia-northeast1")
    agent_name = (
        (os.environ.get("AGENT_RESOURCE_NAME") or "").strip()
        or _get_config("AGENT_RESOURCE_NAME", "vuln-agent-resource-name", "")
    )
    if not agent_name:
        raise RuntimeError("AGENT_RESOURCE_NAME is required")

    vertexai.init(project=project_id, location=location)
    from vertexai import Client

    client = Client(project=project_id, location=location)
    app = client.agent_engines.get(name=agent_name)

    prompt = f"""
    Gmail Push 通知を受信しました（理由: {reason}）。
    新しい SIDfm 脆弱性通知メールを確認し、未処理があれば処理してください:
    1. SBOMと照合して影響システムを特定
    2. 優先度を判定
    3. 担当者へ通知
    4. 対象メールを既読化
    """

    results: list[str] = []

    async def execute_scan():
        async for event in app.async_stream_query(
            user_id="gmail-push-trigger",
            message=prompt,
        ):
            if hasattr(event, "content"):
                for part in event.content.get("parts", []):
                    text = part.get("text")
                    if text:
                        results.append(text)

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(execute_scan())
    finally:
        loop.close()

    summary = "\n".join(results)
    return {"status": "success", "summary": summary}


@functions_framework.cloud_event
def handle_gmail_push(cloud_event):
    payload = _parse_pubsub_payload(cloud_event)
    history_id = payload.get("historyId", "")
    email = payload.get("emailAddress", "")
    logger.info("Received Gmail push event: email=%s historyId=%s", email, history_id)

    sender = _get_config("SIDFM_SENDER_EMAIL", "vuln-agent-sidfm-sender", DEFAULT_SIDFM_SENDER)
    subject_tag = (os.environ.get("SIDFM_SUBJECT_TAG") or DEFAULT_SUBJECT_TAG).strip()
    newer_than = (os.environ.get("SIDFM_QUERY_NEWER_THAN") or DEFAULT_NEWER_THAN).strip()
    query = _build_sidfm_query(sender, subject_tag, newer_than)

    try:
        service = _get_gmail_service()
        if not _has_matching_unread_email(service, query):
            logger.info("No SIDfm unread email matched query, skipping agent execution. query=%s", query)
            return {"status": "skipped", "reason": "no_matching_email"}

        result = _run_agent_scan(reason=f"historyId={history_id}")
        logger.info("Agent execution completed: %s", result.get("status"))
        return result
    except Exception as exc:
        logger.exception("Failed to handle Gmail push: %s", exc)
        return {"status": "error", "message": str(exc)}


@functions_framework.http
def refresh_gmail_watch(request):
    _ = request
    service = _get_gmail_service()
    project_id = _get_project_id()
    topic = (
        os.environ.get("GMAIL_WATCH_TOPIC")
        or f"projects/{project_id}/topics/{DEFAULT_TOPIC}"
    )
    label_ids = [item.strip() for item in (os.environ.get("GMAIL_WATCH_LABEL_IDS") or "INBOX").split(",") if item.strip()]
    body = {
        "topicName": topic,
        "labelFilterAction": "include",
        "labelIds": label_ids,
    }

    response = service.users().watch(userId="me", body=body).execute()
    expiration = response.get("expiration")
    expiration_iso = ""
    if expiration:
        expiration_dt = dt.datetime.fromtimestamp(int(expiration) / 1000, tz=dt.timezone.utc)
        expiration_iso = expiration_dt.isoformat()

    payload = {
        "status": "success",
        "topic": topic,
        "historyId": response.get("historyId"),
        "expiration": expiration,
        "expiration_iso": expiration_iso,
    }
    return json.dumps(payload, ensure_ascii=False), 200, {"Content-Type": "application/json"}
