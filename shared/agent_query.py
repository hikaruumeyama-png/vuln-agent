"""Agent Engine クエリ + リフレクションループ。

chat_webhook/main.py から抽出したAgent Engineストリーミングクエリ機能。
モデルルーティング（flash/pro）対応。
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from typing import Any

import vertexai

from shared.infra import get_config, get_project_id
from shared.ticket_parsers import looks_like_internal_artifact

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# モデルルーティング定数
# ---------------------------------------------------------------------------

_COMPLEXITY_KEYWORDS = (
    "比較", "違い", "優先順位", "トレードオフ", "設計",
    "アーキテクチャ", "戦略", "根拠", "検証", "段階",
    "手順", "実装", "移行", "分析", "影響範囲",
    "原因", "対策", "why", "compare", "trade-off",
    "architecture", "design", "plan",
)
_STRUCTURED_OUTPUT_HINTS = (
    "表で", "表形式", "箇条書き", "json", "yaml",
    "手順書", "チェックリスト", "テンプレート", "章立て",
)
_MULTI_INTENT_HINTS = (
    "かつ", "また", "さらに", "加えて", "その上で",
    "うえで", "and", "also", "then",
)

_MODEL_ROUTING_ENABLED = (
    os.environ.get("MODEL_ROUTING_ENABLED", "true") or "true"
).strip().lower() in {"1", "true", "yes", "on"}
try:
    _MODEL_ROUTING_SCORE_THRESHOLD = int(
        (os.environ.get("MODEL_ROUTING_SCORE_THRESHOLD") or "4").strip()
    )
except Exception:
    _MODEL_ROUTING_SCORE_THRESHOLD = 4
if _MODEL_ROUTING_SCORE_THRESHOLD < 1:
    _MODEL_ROUTING_SCORE_THRESHOLD = 1


# ---------------------------------------------------------------------------
# リフレクション定数
# ---------------------------------------------------------------------------

_REQUIRED_OUTPUT_SECTIONS = ("結論", "根拠", "不確実性", "次アクション")
_VULN_KEYWORDS = ("cve", "脆弱性", "cvss", "vulnerability", "脆弱", "パッチ")
_REFLECTION_ENABLED_KEY = "REFLECTION_ENABLED"


# ---------------------------------------------------------------------------
# モデルルーティング
# ---------------------------------------------------------------------------


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

    cve_count = len(re.findall(r"\bcve-\d{4}-\d{4,9}\b", normalized))
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
        or get_config("AGENT_RESOURCE_NAME", "vuln-agent-resource-name", "")
    )
    flash_resource = (
        (os.environ.get("AGENT_RESOURCE_NAME_FLASH") or "").strip()
        or get_config("AGENT_RESOURCE_NAME_FLASH", "vuln-agent-resource-name-flash", "")
        or base_resource
    )
    pro_resource = (
        (os.environ.get("AGENT_RESOURCE_NAME_PRO") or "").strip()
        or get_config("AGENT_RESOURCE_NAME_PRO", "vuln-agent-resource-name-pro", "")
        or base_resource
    )

    if not _MODEL_ROUTING_ENABLED:
        selected = base_resource or pro_resource or flash_resource
        return selected, {
            "routing_enabled": False, "tier": "single",
            "score": 0, "reasons": ["routing_disabled"],
        }

    if not flash_resource or not pro_resource:
        selected = base_resource or pro_resource or flash_resource
        return selected, {
            "routing_enabled": False, "tier": "single",
            "score": 0, "reasons": ["missing_flash_or_pro_resource"],
        }

    complexity = _estimate_prompt_complexity(prompt)
    selected = pro_resource if complexity["tier"] == "pro" else flash_resource
    return selected, {"routing_enabled": True, **complexity}


# ---------------------------------------------------------------------------
# Agent Engine クエリ
# ---------------------------------------------------------------------------


def run_agent_query(prompt: str, user_id: str) -> str:
    """Agent Engine にストリーミングクエリを送り、テキスト結果を返す。"""
    project_id = get_project_id()
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
            user_id=user_id or "workspace-events-user",
            message=prompt,
        ):
            _collect_text_from_event(event)

    _MAX_AGENT_RETRIES = 3
    for _retry_attempt in range(_MAX_AGENT_RETRIES):
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(execute_query())
            break
        except Exception as _agent_exc:
            loop.close()
            _exc_str = str(_agent_exc).lower()
            if (
                "429" in _exc_str
                or "resource_exhausted" in _exc_str
                or "resource exhausted" in _exc_str
            ):
                if _retry_attempt < _MAX_AGENT_RETRIES - 1:
                    _backoff = (2 ** _retry_attempt) + 1
                    logger.warning(
                        "Agent Engine 429 (attempt %d/%d), retrying in %ds: %s",
                        _retry_attempt + 1, _MAX_AGENT_RETRIES, _backoff, _agent_exc,
                    )
                    time.sleep(_backoff)
                    chunks.clear()
                    continue
            raise
        finally:
            if not loop.is_closed():
                loop.close()

    def _is_noise_line(line: str) -> bool:
        if not line:
            return True
        if looks_like_internal_artifact(line):
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
        seen: set[str] = set()
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
        preferred = [
            x for x in candidates
            if re.search(r"[^\x00-\x7F]", x) or " " in x or "。" in x
        ]
        selected = preferred if preferred else candidates
        return "\n".join(selected[:60]).strip()

    def _trim_response_text(text: str, max_chars: int = 12000) -> str:
        if len(text) <= max_chars:
            return text
        head = text[:max_chars]
        cut_points = [
            head.rfind("\n"), head.rfind("。"),
            head.rfind(". "), head.rfind("! "), head.rfind("? "),
        ]
        cut = max(cut_points)
        if cut < int(max_chars * 0.6):
            cut = max_chars
        return head[:cut].rstrip() + "\n\n(長文のため一部を省略しました)"

    result = _normalize_chunks(chunks)
    if not result:
        return "回答を生成できませんでした。もう一度お試しください。"
    return _trim_response_text(result)


# ---------------------------------------------------------------------------
# リフレクションループ
# ---------------------------------------------------------------------------


def _validate_agent_response(response_text: str, original_prompt: str) -> list[str]:
    """エージェント回答の品質を検証する。問題のリストを返す（空=合格）。"""
    issues: list[str] = []
    is_vuln_response = any(kw in original_prompt.lower() for kw in _VULN_KEYWORDS)

    if not is_vuln_response or len(response_text) < 100:
        return issues

    missing = [s for s in _REQUIRED_OUTPUT_SECTIONS if s not in response_text]
    if len(missing) >= 2:
        issues.append(f"必須セクション不足: {', '.join(missing)}")

    if "根拠" in response_text and "確認中" not in response_text:
        evidence_keywords = (
            "NVD", "SBOM", "BigQuery", "OSV",
            "search_sbom", "get_nvd", "web_search",
        )
        parts = response_text.split("根拠")
        evidence_part = parts[1][:500] if len(parts) > 1 else ""
        if not any(kw in evidence_part for kw in evidence_keywords):
            issues.append("根拠セクションにデータソース記載なし")

    return issues


def run_agent_query_with_reflection(prompt: str, user_id: str) -> str:
    """エージェントクエリを実行し、品質不足時にリトライする。"""
    response = run_agent_query(prompt, user_id)

    if os.environ.get(_REFLECTION_ENABLED_KEY, "true").lower() != "true":
        return response

    issues = _validate_agent_response(response, prompt)
    if not issues:
        return response

    logger.info("Reflection: issues found: %s, retrying", issues)

    reflection_prompt = (
        "前回の回答に以下の品質問題があります。修正して再回答してください。\n"
        + "\n".join(f"- {issue}" for issue in issues)
        + f"\n\n元の質問:\n{prompt}\n\n"
        "修正ルール:\n"
        "- 必須4セクション（結論/根拠/不確実性/次アクション）を必ず含める\n"
        "- 根拠にはツール名・データソースを明記する\n"
        "- 不確実性には最低1つの前提条件を記載する"
    )

    corrected = run_agent_query(reflection_prompt, user_id)
    corrected_issues = _validate_agent_response(corrected, prompt)

    if len(corrected_issues) < len(issues):
        return corrected
    return response
