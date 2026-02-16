"""
Minimal Test Dialog Agent for A2A integration checks.

This agent is intentionally simple and deterministic:
- echoes received requests
- exposes basic health/ping tools
- helps confirm A2A handoff payload reachability
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from google.adk import Agent
from google.adk.tools import FunctionTool


def ping() -> dict[str, Any]:
    """A2A疎通確認用の最小レスポンスを返す。"""
    return {
        "status": "ok",
        "agent": "test_dialog_agent",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


def echo_message(message: str, source: str = "unknown") -> dict[str, Any]:
    """受信メッセージをそのまま返す。"""
    normalized = str(message or "").strip()
    return {
        "status": "ok",
        "agent": "test_dialog_agent",
        "source": str(source or "unknown").strip() or "unknown",
        "received_message": normalized,
        "message_length": len(normalized),
    }


def parse_handoff_sections(message: str) -> dict[str, Any]:
    """
    handoff文面（【セクション名】形式）を簡易パースして返す。
    マスターエージェント向けフォーマット確認に使う。
    """
    text = str(message or "").strip()
    if not text:
        return {"status": "error", "message": "message is required."}

    sections: dict[str, str] = {}
    current = ""
    lines = [line.rstrip() for line in text.splitlines()]
    for raw_line in lines:
        line = raw_line.strip()
        if line.startswith("【") and line.endswith("】") and len(line) >= 3:
            current = line[1:-1].strip()
            sections[current] = ""
            continue
        if not current:
            continue
        existing = sections.get(current, "")
        sections[current] = f"{existing}\n{line}".strip() if line else existing

    return {
        "status": "ok",
        "agent": "test_dialog_agent",
        "sections": sections,
        "section_count": len(sections),
    }


AGENT_INSTRUCTION = """あなたはA2A接続確認用のテスト対話エージェントです。
主目的は、呼び出し元から渡されたメッセージを明確に返し、疎通確認を行うことです。

方針:
1. 事実のみ返す
2. 不要な推測・外部アクセスをしない
3. 受信した内容の確認を優先する

レスポンスは簡潔に、確認しやすい形式で返答してください。
"""


def create_test_dialog_agent() -> Agent:
    model_name = (os.environ.get("TEST_DIALOG_AGENT_MODEL") or "gemini-2.5-flash").strip()
    return Agent(
        name="test_dialog_agent",
        model=model_name,
        instruction=AGENT_INSTRUCTION,
        tools=[
            FunctionTool(ping),
            FunctionTool(echo_message),
            FunctionTool(parse_handoff_sections),
        ],
    )


root_agent = create_test_dialog_agent()

