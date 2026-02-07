import asyncio
import base64
import json
import os
import time
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import vertexai
from vertexai import Client

from .live_api import GeminiLiveClient

GCP_PROJECT_ID = os.environ.get("GCP_PROJECT_ID")
GCP_LOCATION = os.environ.get("GCP_LOCATION", "asia-northeast1")
AGENT_RESOURCE_NAME = os.environ.get("AGENT_RESOURCE_NAME")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _init_vertex() -> Client:
    if not GCP_PROJECT_ID or not AGENT_RESOURCE_NAME:
        raise RuntimeError("GCP_PROJECT_ID または AGENT_RESOURCE_NAME が未設定です。")
    vertexai.init(project=GCP_PROJECT_ID, location=GCP_LOCATION)
    return Client(project=GCP_PROJECT_ID, location=GCP_LOCATION)


async def _query_agent(client: Client, message: str) -> dict[str, Any]:
    app_client = client.agent_engines.get(name=AGENT_RESOURCE_NAME)
    chunks: list[str] = []

    async for event in app_client.async_stream_query(
        user_id="live_gateway",
        message=message,
    ):
        if hasattr(event, "content"):
            for part in event.content.get("parts", []):
                if "text" in part:
                    chunks.append(part["text"])

    return {
        "type": "agent_response",
        "text": "".join(chunks).strip(),
    }


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    client = _init_vertex()
    audio_queue: asyncio.Queue[tuple[bytes, int] | tuple[None, int]] = asyncio.Queue()
    live_client: GeminiLiveClient | None = None
    live_task: asyncio.Task | None = None
    greeting_task: asyncio.Task | None = None
    response_task: asyncio.Task | None = None
    transcript_parts: list[str] = []
    last_response_index = 0
    last_response_at = 0.0

    async def _start_live_session():
        nonlocal live_client, live_task, greeting_task, response_task, last_response_at, last_response_index
        live_client = GeminiLiveClient()
        last_response_at = 0.0
        last_response_index = 0
        transcript_parts.clear()

        async def _stream():
            nonlocal response_task
            async for response in live_client.stream_transcription(audio_queue):
                if response.text:
                    transcript_parts.append(response.text)
                    await websocket.send_text(
                        json.dumps({"type": "live_text", "text": response.text}, ensure_ascii=False)
                    )
                    now = time.monotonic()
                    if response_task is None and now - last_response_at > 2.0:
                        response_task = asyncio.create_task(_trigger_agent_response())

        live_task = asyncio.create_task(_stream())

        async def _greeting():
            tts_client = GeminiLiveClient()
            async for response in tts_client.stream_text("こんにちは。要件を教えてください。"):
                if response.text:
                    await websocket.send_text(
                        json.dumps({"type": "live_text", "text": response.text}, ensure_ascii=False)
                    )
                if response.audio_bytes:
                    await websocket.send_text(
                        json.dumps(
                            {
                                "type": "live_audio",
                                "audio": base64.b64encode(response.audio_bytes).decode("utf-8"),
                                "mime_type": response.mime_type or "audio/pcm",
                            },
                            ensure_ascii=False,
                        )
                    )

        greeting_task = asyncio.create_task(_greeting())

    async def _stop_live_session():
        nonlocal live_task, live_client, greeting_task, response_task
        await audio_queue.put((None, 0))
        if live_task:
            live_task.cancel()
        if greeting_task:
            greeting_task.cancel()
        if response_task:
            response_task.cancel()
        live_task = None
        greeting_task = None
        response_task = None
        live_client = None

    async def _trigger_agent_response():
        nonlocal response_task, last_response_at, last_response_index
        try:
            transcript = " ".join(transcript_parts[last_response_index:]).strip()
            if not transcript:
                return
            last_response_index = len(transcript_parts)
            agent_response = await _query_agent(client, transcript)
            await websocket.send_text(json.dumps(agent_response, ensure_ascii=False))
            tts_client = GeminiLiveClient()
            async for response in tts_client.stream_text(agent_response.get("text", "")):
                if response.text:
                    await websocket.send_text(
                        json.dumps(
                            {"type": "live_text", "text": response.text},
                            ensure_ascii=False,
                        )
                    )
                if response.audio_bytes:
                    await websocket.send_text(
                        json.dumps(
                            {
                                "type": "live_audio",
                                "audio": base64.b64encode(response.audio_bytes).decode("utf-8"),
                                "mime_type": response.mime_type or "audio/pcm",
                            },
                            ensure_ascii=False,
                        )
                    )
            last_response_at = time.monotonic()
        finally:
            response_task = None

    try:
        while True:
            data = await websocket.receive_text()
            payload = json.loads(data)

            if payload.get("type") == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
                continue

            if payload.get("type") == "user_text":
                message = payload.get("text", "").strip()
                if not message:
                    await websocket.send_text(
                        json.dumps({"type": "error", "message": "Empty message"})
                    )
                    continue

                response = await _query_agent(client, message)
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
                sample_rate = int(payload.get("sample_rate", 16000))
                if not audio_b64:
                    await websocket.send_text(
                        json.dumps({"type": "error", "message": "Missing audio payload"})
                    )
                    continue
                await audio_queue.put((GeminiLiveClient.decode_audio_base64(audio_b64), sample_rate))
                continue

            if payload.get("type") == "speech_pause":
                if response_task is None and live_client is not None:
                    response_task = asyncio.create_task(_trigger_agent_response())
                await websocket.send_text(
                    json.dumps({"type": "live_status", "status": "speech_pause"})
                )
                continue

            if payload.get("type") == "barge_in":
                if response_task:
                    response_task.cancel()
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
