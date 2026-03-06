"""Gemini API 直接呼び出しモジュール。"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import vertexai

from shared.constants import DEFAULT_REMEDIATION_TEXT
from shared.infra import get_project_id

logger = logging.getLogger(__name__)


def call_gemini_json(prompt: str, response_schema: dict[str, Any] | None = None) -> dict[str, Any]:
    """Agent Engineを経由せず、Gemini APIで直接JSON出力を得る。"""
    from vertexai.generative_models import GenerativeModel, GenerationConfig

    project_id = get_project_id()
    location = os.environ.get("GCP_LOCATION", "asia-northeast1")
    vertexai.init(project=project_id, location=location)

    model = GenerativeModel("gemini-2.5-flash")
    config_kwargs: dict[str, Any] = {"response_mime_type": "application/json"}
    if response_schema:
        config_kwargs["response_schema"] = response_schema
    config = GenerationConfig(**config_kwargs)
    _MAX_RETRIES = 3
    for _attempt in range(_MAX_RETRIES):
        try:
            response = model.generate_content(prompt, generation_config=config)
            return json.loads(response.text)
        except Exception as exc:
            _exc_str = str(exc).lower()
            if ("429" in _exc_str or "resource_exhausted" in _exc_str or "resource exhausted" in _exc_str) and _attempt < _MAX_RETRIES - 1:
                import time
                _backoff = (2 ** _attempt) + 1
                logger.warning("Gemini direct 429 (attempt %d/%d), retrying in %ds: %s", _attempt + 1, _MAX_RETRIES, _backoff, exc)
                time.sleep(_backoff)
                continue
            logger.warning("Gemini direct JSON call failed: %s", exc)
            return {}


def check_remediation_advice(facts: dict[str, Any], source_text: str) -> dict[str, Any]:
    """通知内容とSBOM情報をもとに、【依頼内容】の妥当性をGemini APIで検証する。"""
    products = facts.get("products") or ["要確認"]
    entries = facts.get("entries") or []
    max_score = facts.get("max_score")
    due_date = facts.get("due_date") or "要確認"
    due_reason = facts.get("due_reason") or ""

    entry_summary = []
    for e in entries[:10]:
        entry_summary.append(
            f"- ID:{e.get('id', '?')} CVSS:{e.get('cvss', '?')} {e.get('title', '')}"
        )
    entries_text = "\n".join(entry_summary) if entry_summary else "エントリなし"
    source_excerpt = (source_text or "")[:2000]

    prompt = (
        "あなたは脆弱性対応の専門家です。以下の脆弱性情報をもとに、"
        "提案されている【依頼内容】が対応策として適切かを判定してください。\n\n"
        f"対象製品: {', '.join(products)}\n"
        f"脆弱性エントリ:\n{entries_text}\n"
        f"最大CVSSスコア: {max_score}\n"
        f"対応完了目標: {due_date}（{due_reason}）\n\n"
        f"通知本文の要点:\n{source_excerpt}\n\n"
        f"現在の【依頼内容】:\n{DEFAULT_REMEDIATION_TEXT}\n\n"
        "## 回答ルール\n"
        "- suggested_action は2〜3文以内の簡潔な依頼文にしてください。\n"
        "- 現在の【依頼内容】と同じスタイル・トーン（丁寧語、〜お願いいたします）を維持してください。\n"
        "- テスト実施・影響調査・報告手順などの詳細な作業指示は含めないでください。\n"
        "- 「対応を実施した場合はサーバのホスト名をご教示ください。」は必ず末尾に残してください。\n"
        "JSONで回答してください。"
    )
    schema = {
        "type": "OBJECT",
        "properties": {
            "is_appropriate": {"type": "BOOLEAN"},
            "confidence": {"type": "STRING", "enum": ["high", "medium", "low"]},
            "reasoning": {"type": "STRING"},
            "suggested_action": {"type": "STRING"},
            "risk_notes": {"type": "STRING"},
        },
        "required": ["is_appropriate", "confidence", "reasoning"],
    }
    try:
        result = call_gemini_json(prompt, response_schema=schema)
        if not isinstance(result, dict):
            return {}
        return result
    except Exception as exc:
        logger.warning("Remediation advice check failed: %s", exc)
        return {}


def analyze_exploited_vuln(source_text: str, notification_type: str = "exploited") -> dict[str, Any]:
    """【悪用された脆弱性】/【脆弱性情報 更新通知】をGeminiで軽量分析。"""
    if notification_type == "update":
        intro = "以下は「脆弱性情報の更新通知」のテキストです。\n"
    else:
        intro = "以下は「悪用が確認された脆弱性」の通知テキストです。\n"
    prompt = (
        intro +
        "次の情報をJSON形式で返してください。\n\n"
        "1. is_windows_or_apple: 対象製品がWindows製品またはApple製品"
        "（macOS, iOS, iPadOS, Safari, watchOS, tvOS, visionOS等）"
        "であればtrue、それ以外はfalse\n"
        "2. product_name: 対象製品名（日本語）\n"
        "3. cve_ids: 検出されたCVE番号のリスト\n"
        "4. comment: セキュリティ担当者向けの対応コメント（3〜4文）。以下を必ず含めること:\n"
        "   - CVE番号に含まれる発行年（例: CVE-2023-XXXXなら「2023年発行」）と、"
        "     現在からの経過年数（例: 「約2年前」）\n"
        "   - その脆弱性が古い場合は通常の定期アップデートで対応済みである可能性が高い旨\n"
        "   - 新しい脆弱性の場合は速やかな対応が必要な旨\n"
        "5. action_required: 社内端末への即時確認・対応が必要かどうか。\n"
        "   - CVE発行から概ね1年以上経過しており、通常の定期アップデートで"
        "     対応済みの可能性が高い場合: false\n"
        "   - 発行から1年未満、または深刻度が特に高い(CVSS 9.0+)場合: true\n"
        "6. max_cvss: 通知テキストに含まれる最大CVSSスコア（文字列、例: '9.8'）。"
        "見つからない場合は空文字\n\n"
        f"通知テキスト:\n{source_text[:3000]}"
    )
    schema = {
        "type": "object",
        "properties": {
            "is_windows_or_apple": {"type": "boolean"},
            "product_name": {"type": "string"},
            "cve_ids": {"type": "array", "items": {"type": "string"}},
            "comment": {"type": "string"},
            "action_required": {"type": "boolean"},
            "max_cvss": {"type": "string"},
        },
        "required": ["is_windows_or_apple", "product_name", "cve_ids", "comment", "action_required"],
    }
    try:
        return call_gemini_json(prompt, response_schema=schema)
    except Exception as exc:
        logger.warning("[exploited_vuln] Gemini analysis failed: %s", exc)
        return {}
