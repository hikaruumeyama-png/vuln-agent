import asyncio
import base64
import contextlib
import os
from dataclasses import dataclass
from typing import AsyncGenerator

from google import genai
from google.genai import types


DEFAULT_MODEL = "gemini-2.5-flash-native-audio-preview-12-2025"


@dataclass
class LiveResponse:
    text: str | None = None
    audio_bytes: bytes | None = None
    mime_type: str | None = None


class GeminiLiveClient:
    def __init__(self, api_key: str | None = None, model: str | None = None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        if not self.api_key:
            raise RuntimeError("GEMINI_API_KEY が未設定です。")
        self.model = model or os.environ.get("GEMINI_LIVE_MODEL", DEFAULT_MODEL)
        self._client = genai.Client(api_key=self.api_key)

    async def stream_text(self, message: str) -> AsyncGenerator[LiveResponse, None]:
        config = types.LiveConnectConfig(response_modalities=["AUDIO"])
        async with self._client.aio.live.connect(model=self.model, config=config) as session:
            await session.send_client_content(
                turns={"role": "user", "parts": [{"text": message}]},
                turn_complete=True,
            )
            async for response in session.receive():
                for part in _iter_response_parts(response):
                    if part.text:
                        yield LiveResponse(text=part.text)
                    if part.inline_data and part.inline_data.data:
                        yield LiveResponse(
                            audio_bytes=part.inline_data.data,
                            mime_type=part.inline_data.mime_type,
                        )

    async def stream_transcription(
        self, audio_queue: "asyncio.Queue[tuple[bytes, int]]"
    ) -> AsyncGenerator[LiveResponse, None]:
        config = types.LiveConnectConfig(
            response_modalities=["TEXT"],
            system_instruction=types.Content(
                role="system",
                parts=[
                    types.Part.from_text(
                        text=(
                        "あなたは日本語音声の書き起こし専用です。話者の発話を日本語で簡潔に文字起こししてください。"
                        )
                    )
                ],
            ),
        )
        async with self._client.aio.live.connect(model=self.model, config=config) as session:

            async def _sender():
                while True:
                    chunk, sample_rate = await audio_queue.get()
                    if chunk is None:
                        break
                    await session.send_realtime_input(
                        audio=types.Blob(
                            data=chunk,
                            mime_type=f"audio/pcm;rate={sample_rate}",
                        )
                    )

            sender_task = asyncio.create_task(_sender())
            try:
                async for response in session.receive():
                    for part in _iter_response_parts(response):
                        if part.text:
                            yield LiveResponse(text=part.text)
            finally:
                sender_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await sender_task

    @staticmethod
    def decode_audio_base64(payload: str) -> bytes:
        return base64.b64decode(payload, validate=True)


def _iter_response_parts(response: object):
    parts = getattr(response, "parts", None)
    if parts:
        for part in parts:
            yield part
        return
    server_content = getattr(response, "server_content", None)
    if not server_content:
        return
    model_turn = getattr(server_content, "model_turn", None)
    if not model_turn:
        return
    turn_parts = getattr(model_turn, "parts", None)
    if not turn_parts:
        return
    for part in turn_parts:
        yield part
