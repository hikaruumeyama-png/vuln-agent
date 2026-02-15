import asyncio
import base64
import binascii
import json
import logging
import os
import time
import uuid
from typing import Any

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
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
LIVE_GREETING_TEXT = os.environ.get(
    "LIVE_GREETING_TEXT",
    "こんにちは。脆弱性管理AIエージェントです。ご要望をどうぞ。",
)

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
}

logger = logging.getLogger(__name__)

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


def _safe_healthz_headers(request: Request) -> dict[str, str]:
    return {
        key: value
        for key, value in request.headers.items()
        if key.lower() in HEALTHZ_HEADER_ALLOWLIST
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


async def _safe_send(websocket: WebSocket, data: dict[str, Any]) -> None:
    """Send JSON via WebSocket, silently ignoring disconnection errors."""
    try:
        await websocket.send_text(json.dumps(data, ensure_ascii=False))
    except Exception:
        pass


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _init_vertex() -> Client:
    if not GCP_PROJECT_ID or not AGENT_RESOURCE_NAME:
        raise RuntimeError("GCP_PROJECT_ID または AGENT_RESOURCE_NAME が未設定です。")
    vertexai.init(project=GCP_PROJECT_ID, location=GCP_LOCATION)
    return Client(project=GCP_PROJECT_ID, location=GCP_LOCATION)


async def _query_agent(
    client: Client, message: str, websocket: WebSocket,
) -> dict[str, Any]:
    app_client = client.agent_engines.get(name=AGENT_RESOURCE_NAME)
    chunks: list[str] = []
    request_id = f"req-{uuid.uuid4().hex[:10]}"
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

    async for event in app_client.async_stream_query(
        user_id="live_gateway",
        message=message,
    ):
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

    return {
        "type": "agent_response",
        "request_id": request_id,
        "text": "".join(chunks).strip(),
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


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    client = _init_vertex()
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
            agent_response = await _query_agent(client, transcript, websocket)
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

                response = await _query_agent(client, message, websocket)
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
