"""Google Chat webhook handler for message-triggered vulnerability analysis."""

from __future__ import annotations

import asyncio
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
import os
import re
import threading
import uuid
from typing import Any

import functions_framework
import vertexai

logger = logging.getLogger(__name__)

_secret_client = None
_chat_service_read_client = None
_chat_service_post_client = None
_RECENT_TURNS: dict[str, deque[dict[str, str]]] = {}
_THREAD_ROOT_CACHE: dict[str, str] = {}
_SBOM_ALMA_VERSION_CACHE: dict[str, Any] = {"versions": None, "fetched_at": None}
_SBOM_PRODUCT_CACHE: dict[str, Any] = {"names": None, "fetched_at": None}
_ASYNC_WORKER_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="chat-webhook-worker")
_ASYNC_EVENT_LOCK = threading.Lock()
_ASYNC_EVENT_SEEN: dict[str, float] = {}
_MAX_RECENT_TURNS = 4
_AMBIGUITY_PRESETS = {
    "strict": {"min_chars_without_context": 6},
    "standard": {"min_chars_without_context": 4},
    "relaxed": {"min_chars_without_context": 2},
}
_AMBIGUITY_PRESET_NAME = (os.environ.get("AMBIGUITY_PRESET") or "standard").strip().lower()
if _AMBIGUITY_PRESET_NAME not in _AMBIGUITY_PRESETS:
    _AMBIGUITY_PRESET_NAME = "standard"
_AMBIGUITY_PRESET = _AMBIGUITY_PRESETS[_AMBIGUITY_PRESET_NAME]
_AMBIGUOUS_PROMPT_EXACT = {
    "?",
    "？",
    "help",
    "ヘルプ",
    "お願い",
    "お願いします",
    "教えて",
    "調べて",
    "確認して",
    "これ",
    "それ",
    "あれ",
    "この件",
    "その件",
    "上記",
}
_AMBIGUOUS_REFERENCE_TOKENS = ("これ", "それ", "あれ", "この件", "その件", "上記", "さっき", "先ほど")
_CLEAR_CONTEXT_KEYWORDS = (
    "cve-",
    "cwe-",
    "cvss",
    "osv",
    "nvd",
    "sbom",
    "sidfm",
    "purl",
    "bigquery",
    "gmail",
    "chat",
    "jira",
    "脆弱性",
    "パッケージ",
    "システム",
    "通知",
    "担当者",
    "メール",
    "製品",
)
_MANUAL_TICKET_TRIGGER_WORDS = (
    "この内容で",
    "この本文で",
    "起票用",
    "起票",
    "作成して",
    "作って",
    "貼り付け",
    "コピペ",
)
try:
    _HYPOTHESIS_RETRY_LIMIT = int((os.environ.get("HYPOTHESIS_RETRY_LIMIT") or "2").strip())
except Exception:
    _HYPOTHESIS_RETRY_LIMIT = 2
if _HYPOTHESIS_RETRY_LIMIT < 0:
    _HYPOTHESIS_RETRY_LIMIT = 0
_DEFAULT_REMEDIATION_TEXT = (
    "上記脆弱性情報をご確認いただき、バージョンアップが低い場合は"
    "バージョンアップのご対応お願いいたします。\n"
    "対応を実施した場合はサーバのホスト名をご教示ください。"
)
_TICKET_FORBIDDEN_PHRASES = (
    "はい、承知いたしました",
    "ご依頼のメール内容は",
    "テンプレートを作成します",
)
_INCIDENT_ID_PATTERN = re.compile(r"\bincident_id[:=\s]*([0-9a-fA-F\-]{8,})\b", re.IGNORECASE)
_INTENT_JSON_MAX_CHARS = 1200
_COMPLEXITY_KEYWORDS = (
    "比較",
    "違い",
    "優先順位",
    "トレードオフ",
    "設計",
    "アーキテクチャ",
    "戦略",
    "根拠",
    "検証",
    "段階",
    "手順",
    "実装",
    "移行",
    "分析",
    "影響範囲",
    "原因",
    "対策",
    "why",
    "compare",
    "trade-off",
    "architecture",
    "design",
    "plan",
)
_STRUCTURED_OUTPUT_HINTS = (
    "表で",
    "表形式",
    "箇条書き",
    "json",
    "yaml",
    "手順書",
    "チェックリスト",
    "テンプレート",
    "章立て",
)
_MULTI_INTENT_HINTS = (
    "かつ",
    "また",
    "さらに",
    "加えて",
    "その上で",
    "うえで",
    "and",
    "also",
    "then",
)
_MODEL_ROUTING_ENABLED = (os.environ.get("MODEL_ROUTING_ENABLED", "true") or "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
try:
    _MODEL_ROUTING_SCORE_THRESHOLD = int((os.environ.get("MODEL_ROUTING_SCORE_THRESHOLD") or "4").strip())
except Exception:
    _MODEL_ROUTING_SCORE_THRESHOLD = 4
if _MODEL_ROUTING_SCORE_THRESHOLD < 1:
    _MODEL_ROUTING_SCORE_THRESHOLD = 1


def _get_secret_client():
    global _secret_client
    if _secret_client is None:
        from google.cloud import secretmanager

        _secret_client = secretmanager.SecretManagerServiceClient()
    return _secret_client


def _get_chat_service(mode: str = "read"):
    global _chat_service_read_client, _chat_service_post_client
    normalized_mode = (mode or "read").strip().lower()
    if normalized_mode not in {"read", "post"}:
        normalized_mode = "read"

    if normalized_mode == "read" and _chat_service_read_client is not None:
        return _chat_service_read_client
    if normalized_mode == "post" and _chat_service_post_client is not None:
        return _chat_service_post_client

    from googleapiclient.discovery import build

    scopes = ["https://www.googleapis.com/auth/chat.bot"]
    if normalized_mode == "read":
        scopes.append("https://www.googleapis.com/auth/chat.messages.readonly")
    sa_json = _get_config("CHAT_SA_CREDENTIALS_JSON", "vuln-agent-chat-sa-key", "")
    delegated_user = _get_config("CHAT_DELEGATED_USER", "vuln-agent-chat-delegated-user", "")
    if sa_json:
        try:
            from google.oauth2 import service_account

            sa_info = json.loads(sa_json)
            credentials = service_account.Credentials.from_service_account_info(sa_info, scopes=scopes)
            if normalized_mode == "read" and delegated_user:
                # Chat message read is user-data scope; use domain-wide delegation when configured.
                credentials = credentials.with_subject(delegated_user)
                logger.info("Thread fetch uses delegated user auth: %s", delegated_user)
            elif normalized_mode == "read":
                logger.warning(
                    "CHAT_DELEGATED_USER is not configured. "
                    "ListMessages may fail with insufficient scopes in app auth mode."
                )
            service = build("chat", "v1", credentials=credentials, cache_discovery=False)
            if normalized_mode == "read":
                _chat_service_read_client = service
                logger.info("Thread fetch uses Chat SA credentials from secret")
            else:
                _chat_service_post_client = service
                logger.info("Chat post uses Chat SA bot credentials from secret")
            return service
        except Exception as exc:
            logger.warning("Failed to init Chat service from SA secret: %s", exc)

    import google.auth

    credentials, _ = google.auth.default(scopes=scopes)
    service = build("chat", "v1", credentials=credentials, cache_discovery=False)
    if normalized_mode == "read":
        _chat_service_read_client = service
        logger.warning("Thread fetch uses ADC fallback credentials")
    else:
        _chat_service_post_client = service
        logger.warning("Chat post uses ADC fallback credentials")
    return service


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


def _strip_mentions_preserve_lines(raw_text: str) -> str:
    if not raw_text:
        return ""
    text = re.sub(r"<users/[^>]+>", "", raw_text)
    lines = [line.strip() for line in text.splitlines()]
    return "\n".join(lines).strip()


def _sender_info(event: dict[str, Any]) -> dict[str, str]:
    sender = ((event.get("message") or {}).get("sender") or {})
    return {
        "name": str(sender.get("name") or ""),
        "display_name": str(sender.get("displayName") or ""),
        "type": str(sender.get("type") or ""),
    }


def _looks_like_gmail_digest(text: str) -> bool:
    t = text.lower()
    signals = 0

    if "from:" in t or "差出人:" in t:
        signals += 1
    if "subject:" in t or "件名:" in t:
        signals += 1
    if re.search(r"^\[[^\]]+\]", text.strip()):
        signals += 1
    if "view message" in t:
        signals += 1
    if "to view the full email" in t or "google groups" in t:
        signals += 1
    if re.search(r"\bcve-\d{4}-\d{4,9}\b", t):
        signals += 1
    if "gmail" in t and "new email" in t:
        signals += 2

    return signals >= 2


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


def _is_ambiguous_prompt(prompt: str) -> bool:
    normalized = re.sub(r"\s+", " ", (prompt or "").strip()).lower()
    if not normalized:
        return True
    if _contains_specific_vuln_signal(normalized):
        return False
    if normalized in _AMBIGUOUS_PROMPT_EXACT:
        return True
    if re.fullmatch(r"[?？!！。,.、\s]+", normalized):
        return True
    has_context = any(keyword in normalized for keyword in _CLEAR_CONTEXT_KEYWORDS)
    min_chars = int(_AMBIGUITY_PRESET.get("min_chars_without_context", 4))
    if len(normalized) < min_chars and not has_context:
        return True
    if any(token in normalized for token in _AMBIGUOUS_REFERENCE_TOKENS) and not has_context:
        return True
    return False


def _build_clarification_message() -> str:
    return (
        "ぶれた回答を防ぐため、意図を正確に把握したいです。もう少し具体化してください。\n"
        "1) 対象（例: CVE番号 / 製品名 / システム名）\n"
        "2) 知りたい内容（影響範囲 / 優先度 / 対応方法 など）"
    )


def _contains_vulnerability_signal(text: str) -> bool:
    t = (text or "").lower()
    if not t:
        return False
    if "cve-" in t or "cvss" in t:
        return True
    if re.search(r"\bghsa-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}\b", t):
        return True
    if "sid.softek.jp" in t or "nvd.nist.gov" in t:
        return True
    if "脆弱性" in text or "対象の機器/アプリ" in text:
        return True
    return False


def _contains_specific_vuln_signal(text: str) -> bool:
    t = (text or "").lower()
    if not t:
        return False
    if re.search(r"\bcve-\d{4}-\d{4,9}\b", t):
        return True
    if re.search(r"\bghsa-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}\b", t):
        return True
    if "cvss" in t:
        return True
    if "sid.softek.jp" in t or "nvd.nist.gov" in t:
        return True
    vuln_domains = (
        "cve.mitre.org",
        "security-next.com",
        "fortiguard.com",
        "sec.cloudapps.cisco.com",
        "motex.co.jp",
        "jvn.jp",
        "jpcert.or.jp",
        "redhat.com",
        "ubuntu.com",
        "debian.org",
        "github.com/advisories",
        "osv.dev",
        "nvd.nist.gov",
    )
    if any(domain in t for domain in vuln_domains):
        return True
    if "脆弱性" in text and ("http://" in t or "https://" in t):
        return True
    return False


def _contains_manual_ticket_trigger(text: str) -> bool:
    normalized = re.sub(r"\s+", " ", (text or "").strip()).lower()
    if not normalized:
        return False
    return any(token in normalized for token in _MANUAL_TICKET_TRIGGER_WORDS)


def _is_manual_ticket_generation_prompt(prompt: str) -> bool:
    normalized = re.sub(r"\s+", " ", (prompt or "").strip()).lower()
    if not normalized:
        return False
    if not _contains_manual_ticket_trigger(normalized):
        return False
    return _contains_specific_vuln_signal(prompt) or len(prompt) >= 120


def _call_gemini_json(prompt: str, response_schema: dict[str, Any] | None = None) -> dict[str, Any]:
    """Agent Engineを経由せず、Gemini APIで直接JSON出力を得る。"""
    from vertexai.generative_models import GenerativeModel, GenerationConfig

    project_id = _get_project_id()
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


def _check_remediation_advice(facts: dict[str, Any], source_text: str) -> dict[str, Any]:
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
        f"現在の【依頼内容】:\n{_DEFAULT_REMEDIATION_TEXT}\n\n"
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
        result = _call_gemini_json(prompt, response_schema=schema)
        if not isinstance(result, dict):
            return {}
        return result
    except Exception as exc:
        logger.warning("Remediation advice check failed: %s", exc)
        return {}


def _build_ticket_hypothesis_prompt(raw_text: str, user_instruction: str = "") -> str:
    instruction_block = ""
    if (user_instruction or "").strip():
        instruction_block = (
            "\n\n【ユーザー追加指示】\n"
            f"{str(user_instruction).strip()}\n"
            "上記指示を優先し、起票フォーマットを壊さず補正してください。"
        )
    return (
        "以下の脆弱性通知本文を解析し、まず仮説JSONのみを出力してください。"
        "説明文は禁止です。JSONオブジェクト以外を出力しないでください。\n"
        "必須スキーマ:\n"
        "{\n"
        '  "is_vulnerability_notification": true/false,\n'
        '  "request_summary": "string",\n'
        '  "target_products": ["string", ...],\n'
        '  "entries": [\n'
        "    {\n"
        '      "id": "string",\n'
        '      "cvss": number,\n'
        '      "title": "string",\n'
        '      "url": "string",\n'
        '      "os_version": "string (optional)",\n'
        '      "package": "string",\n'
        '      "confidence": number,\n'
        '      "evidence": "string"\n'
        "    }\n"
        "  ],\n"
        '  "grouping_plan": "single|split",\n'
        '  "assumptions": ["string", ...]\n'
        "}\n"
        "os_version はオプションです。特定OS/バージョン依存の脆弱性のみ記載してください。\n"
        "OS非依存（Webライブラリ等）の場合は `要確認` または省略可能です。\n"
        "不明値は空文字ではなく `要確認` を使ってください。\n\n"
        f"{raw_text}{instruction_block}"
    )


def _build_ai_intent_prompt(
    user_prompt: str,
    raw_body_text: str,
    root_text: str,
    recent_turns: list[dict[str, str]],
    is_gmail_post: bool,
) -> str:
    turns_preview: list[str] = []
    for turn in recent_turns[-2:]:
        u = str(turn.get("user", "")).strip()
        a = str(turn.get("assistant", "")).strip()
        if u or a:
            turns_preview.append(f"- user: {u[:200]}\n  assistant: {a[:200]}")
    recent = "\n".join(turns_preview) if turns_preview else "(none)"
    root_preview = (root_text or "").strip()
    if len(root_preview) > 1200:
        root_preview = root_preview[:1200] + "\n...(truncated)"
    return (
        "あなたはGoogle Chat運用の意図判定器です。"
        "次の入力に対して、JSONのみを返してください。説明文は禁止です。\n\n"
        "返却JSON schema:\n"
        '{'
        '"intent":"ticket_generate|general_analysis|clarification",'
        '"needs_ticket_format":true|false,'
        '"prefer_thread_root":true|false,'
        '"prefer_history":true|false,'
        '"reason":"short reason",'
        '"confidence":"high|medium|low"'
        '}\n\n'
        "intent判定ルール:\n"
        "- ticket_generate: 脆弱性通知メール本文を含み、新規起票テンプレート作成が必要\n"
        "- general_analysis: 脆弱性や技術情報に関する一般的な質問・分析\n"
        "- clarification: 入力があいまいで判定不能\n\n"
        f"is_gmail_post: {str(bool(is_gmail_post)).lower()}\n"
        f"user_prompt:\n{(user_prompt or '').strip()}\n\n"
        f"raw_body_text:\n{(raw_body_text or '').strip()}\n\n"
        f"thread_root_preview:\n{root_preview or '(none)'}\n\n"
        f"recent_turns:\n{recent}\n"
    )


def _parse_ai_intent_json(text: str) -> dict[str, Any]:
    blob = _extract_first_json_object(text)
    if not blob:
        return {}
    try:
        parsed = json.loads(blob)
    except Exception:
        return {}
    if not isinstance(parsed, dict):
        return {}
    intent = str(parsed.get("intent") or "").strip()
    if intent not in {"ticket_generate", "general_analysis", "clarification"}:
        return {}
    return {
        "intent": intent,
        "needs_ticket_format": bool(parsed.get("needs_ticket_format")),
        "prefer_thread_root": bool(parsed.get("prefer_thread_root")),
        "prefer_history": bool(parsed.get("prefer_history")),
        "reason": str(parsed.get("reason") or "").strip()[:_INTENT_JSON_MAX_CHARS],
        "confidence": str(parsed.get("confidence") or "").strip().lower() or "low",
    }


def _run_ai_intent_planner(
    user_prompt: str,
    raw_body_text: str,
    root_text: str,
    recent_turns: list[dict[str, str]],
    is_gmail_post: bool,
    history_key: str,
) -> dict[str, Any]:
    if is_gmail_post:
        return {
            "intent": "ticket_generate",
            "needs_ticket_format": True,
            "prefer_thread_root": True,
            "prefer_history": False,
            "reason": "gmail_notification",
            "confidence": "high",
        }
    prompt = _build_ai_intent_prompt(
        user_prompt=user_prompt,
        raw_body_text=raw_body_text,
        root_text=root_text,
        recent_turns=recent_turns,
        is_gmail_post=is_gmail_post,
    )
    raw = _run_agent_query(prompt, history_key)
    parsed = _parse_ai_intent_json(raw)
    if parsed:
        return parsed

    # Fallback for malformed planner output: preserve existing behavior as safety net.
    if _is_ambiguous_prompt(user_prompt) and not root_text and not recent_turns:
        return {
            "intent": "clarification",
            "needs_ticket_format": False,
            "prefer_thread_root": False,
            "prefer_history": False,
            "reason": "fallback_ambiguous_without_context",
            "confidence": "medium",
        }
    if _contains_manual_ticket_trigger(raw_body_text):
        return {
            "intent": "ticket_generate",
            "needs_ticket_format": True,
            "prefer_thread_root": True,
            "prefer_history": True,
            "reason": "fallback_ticket_pattern",
            "confidence": "low",
        }
    return {
        "intent": "general_analysis",
        "needs_ticket_format": False,
        "prefer_thread_root": False,
        "prefer_history": False,
        "reason": "fallback_general",
        "confidence": "low",
    }


def _extract_first_json_object(text: str) -> str:
    body = (text or "").strip()
    if not body:
        return ""
    start = body.find("{")
    if start < 0:
        return ""
    depth = 0
    for i in range(start, len(body)):
        ch = body[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return body[start : i + 1]
    return ""


def _parse_ticket_hypothesis_json(text: str) -> dict[str, Any]:
    raw = _extract_first_json_object(text)
    if not raw:
        return {}
    try:
        obj = json.loads(raw)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def _validate_ticket_hypothesis_schema(hypothesis: dict[str, Any]) -> tuple[bool, list[str]]:
    errs: list[str] = []
    if not isinstance(hypothesis, dict):
        return False, ["hypothesis is not object"]
    for key in ("is_vulnerability_notification", "request_summary", "target_products", "entries", "grouping_plan", "assumptions"):
        if key not in hypothesis:
            errs.append(f"missing:{key}")
    if "target_products" in hypothesis and not isinstance(hypothesis.get("target_products"), list):
        errs.append("target_products must be list")
    if "entries" in hypothesis and not isinstance(hypothesis.get("entries"), list):
        errs.append("entries must be list")
    if isinstance(hypothesis.get("entries"), list):
        for idx, e in enumerate(hypothesis.get("entries") or []):
            if not isinstance(e, dict):
                errs.append(f"entries[{idx}] not object")
                continue
            for k in ("id", "cvss", "title", "url", "package", "confidence", "evidence"):
                if k not in e:
                    errs.append(f"entries[{idx}] missing:{k}")
    return (len(errs) == 0), errs


def _run_hypothesis_pipeline(source_text: str, history_key: str, user_instruction: str = "") -> dict[str, Any]:
    attempts = max(1, _HYPOTHESIS_RETRY_LIMIT + 1)
    last_errs: list[str] = []
    for attempt_num in range(attempts):
        prompt = _build_ticket_hypothesis_prompt(source_text, user_instruction=user_instruction)
        if attempt_num > 0 and last_errs:
            prompt = (
                prompt
                + "\n\n【前回の検証エラー】前回の出力が以下の理由で不正でした。修正して再出力してください。\n"
                + "\n".join(f"- {e}" for e in last_errs[:10])
                + "\n\nJSONのみ出力。説明文・マークダウン禁止。"
            )
        # Gemini API direct call (JSON mode) instead of Agent Engine
        parsed = _call_gemini_json(prompt)
        if not parsed:
            # Fallback: try Agent Engine if Gemini direct fails
            raw = _run_agent_query(prompt, history_key)
            parsed = _parse_ticket_hypothesis_json(raw)
        ok, errs = _validate_ticket_hypothesis_schema(parsed)
        if ok:
            return parsed
        last_errs = errs
    logger.warning("Hypothesis schema validation failed after retries: %s", ", ".join(last_errs))
    return {}


def _extract_incident_id(text: str) -> str:
    raw = (text or "").strip()
    if not raw:
        return ""
    match = _INCIDENT_ID_PATTERN.search(raw)
    if not match:
        return ""
    return str(match.group(1) or "").strip()


def _extract_space_name(event: dict[str, Any], thread_name: str) -> str:
    space_name = str((event.get("space") or {}).get("name") or "").strip()
    if space_name:
        return space_name
    if thread_name.startswith("spaces/"):
        parts = thread_name.split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
    return ""


def _extract_message_text_payload(message: dict[str, Any]) -> str:
    def _walk(value: Any, out: list[str]) -> None:
        if value is None:
            return
        if isinstance(value, str):
            text = re.sub(r"\s+", " ", value).strip()
            if text:
                out.append(text)
            return
        if isinstance(value, list):
            for item in value:
                _walk(item, out)
            return
        if isinstance(value, dict):
            for key in (
                "text",
                "formattedText",
                "argumentText",
                "fallbackText",
                "title",
                "subtitle",
                "name",
            ):
                if key in value:
                    _walk(value.get(key), out)
            for child_key in ("cardsV2", "cards", "sections", "widgets", "textParagraph"):
                if child_key in value:
                    _walk(value.get(child_key), out)

    chunks: list[str] = []
    _walk(message, chunks)
    if not chunks:
        return ""
    merged = " ".join(chunks)
    merged = re.sub(r"\s+", " ", merged).strip()
    return merged[:12000]


def _fetch_quoted_message_text(event: dict[str, Any]) -> str:
    quoted_name = str((((event.get("message") or {}).get("quotedMessageMetadata") or {}).get("name") or "")).strip()
    if not quoted_name:
        return ""
    try:
        service = _get_chat_service(mode="read")
        quoted_message = service.spaces().messages().get(name=quoted_name).execute()
        return _extract_message_text_payload(quoted_message if isinstance(quoted_message, dict) else {})
    except Exception as exc:
        logger.warning("Failed to fetch quoted message text: %s", exc)
        return ""


def _fetch_thread_root_message_text(event: dict[str, Any]) -> str:
    message = event.get("message") or {}
    thread_name = str(((message.get("thread") or {}).get("name") or "")).strip()
    if not thread_name:
        return ""
    delegated_user = _get_config("CHAT_DELEGATED_USER", "vuln-agent-chat-delegated-user", "").strip()
    if not delegated_user:
        # DWD未設定環境ではChat read scope取得が失敗しやすいため、読み取りAPI呼び出しを抑止。
        return ""
    current_message_name = str(message.get("name") or "").strip()
    space_name = _extract_space_name(event, thread_name)
    if not space_name:
        return ""

    try:
        service = _get_chat_service(mode="read")

        quoted_name = str((((event.get("message") or {}).get("quotedMessageMetadata") or {}).get("name") or "")).strip()
        if quoted_name:
            try:
                quoted_message = service.spaces().messages().get(name=quoted_name).execute()
                quoted_text = _extract_message_text_payload(quoted_message if isinstance(quoted_message, dict) else {})
                if quoted_text:
                    return quoted_text
            except Exception:
                pass

        def _list_messages(with_filter: bool) -> list[dict[str, Any]]:
            kwargs: dict[str, Any] = {"parent": space_name, "pageSize": 100}
            if with_filter:
                kwargs["filter"] = f'thread.name="{thread_name}"'
            all_messages: list[dict[str, Any]] = []
            page_token = ""
            page_limit = 5
            for _ in range(page_limit):
                req = dict(kwargs)
                if page_token:
                    req["pageToken"] = page_token
                response = service.spaces().messages().list(**req).execute()
                messages = response.get("messages") or []
                all_messages.extend([m for m in messages if isinstance(m, dict)])
                page_token = str(response.get("nextPageToken") or "").strip()
                if not page_token:
                    break
            return all_messages

        try:
            messages = _list_messages(with_filter=True)
        except Exception:
            messages = [
                m
                for m in _list_messages(with_filter=False)
                if str(((m.get("thread") or {}).get("name") or "")).strip() == thread_name
            ]

        candidates = [m for m in messages if (m.get("name") or "") != current_message_name]
        if not candidates:
            return ""

        def _sort_key(msg: dict[str, Any]) -> tuple[str, str]:
            return (str(msg.get("createTime") or ""), str(msg.get("name") or ""))

        sorted_candidates = sorted(candidates, key=_sort_key)
        extracted: list[str] = []
        for msg in sorted_candidates:
            if not isinstance(msg, dict):
                continue
            text = _extract_message_text_payload(msg)
            if not text:
                continue
            extracted.append(text)

        if not extracted:
            return ""

        def _looks_like_vuln_context(text: str) -> bool:
            t = (text or "").lower()
            if _looks_like_gmail_digest(text):
                return True
            if "cve-" in t or "cvss" in t:
                return True
            if "sid.softek.jp" in t or "nvd.nist.gov" in t:
                return True
            if "【起票用（コピペ）】" in text:
                return True
            return False

        vuln_like = [t for t in extracted if _looks_like_vuln_context(t)]
        if vuln_like:
            return vuln_like[0]

        # Prefer substantial root-like text.
        substantial = [t for t in extracted if len(t) >= 30 and not _is_ambiguous_prompt(t)]
        if substantial:
            return substantial[0]
        return extracted[0]
    except Exception as exc:
        logger.warning("Failed to fetch thread root message: %s", exc)
        return ""


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
        or _get_config("AGENT_RESOURCE_NAME", "vuln-agent-resource-name", "")
    )
    flash_resource = (
        (os.environ.get("AGENT_RESOURCE_NAME_FLASH") or "").strip()
        or _get_config("AGENT_RESOURCE_NAME_FLASH", "vuln-agent-resource-name-flash", "")
        or base_resource
    )
    pro_resource = (
        (os.environ.get("AGENT_RESOURCE_NAME_PRO") or "").strip()
        or _get_config("AGENT_RESOURCE_NAME_PRO", "vuln-agent-resource-name-pro", "")
        or base_resource
    )

    if not _MODEL_ROUTING_ENABLED:
        selected = base_resource or pro_resource or flash_resource
        return selected, {"routing_enabled": False, "tier": "single", "score": 0, "reasons": ["routing_disabled"]}

    if not flash_resource or not pro_resource:
        selected = base_resource or pro_resource or flash_resource
        return selected, {
            "routing_enabled": False,
            "tier": "single",
            "score": 0,
            "reasons": ["missing_flash_or_pro_resource"],
        }

    complexity = _estimate_prompt_complexity(prompt)
    selected = pro_resource if complexity["tier"] == "pro" else flash_resource
    return selected, {"routing_enabled": True, **complexity}


def _looks_like_internal_artifact(text: str) -> bool:
    t = (text or "").strip()
    if not t:
        return False
    lowered = t.lower()
    bad_tokens = (
        "gemini-",
        "tool_code",
        "tool code",
        "tool_name",
        "on_demand",
        "<ctrl",
        "function_call",
        "assistant_response",
    )
    if any(token in lowered for token in bad_tokens):
        return True
    if re.search(r"<[^>]{2,32}>", t):
        return True
    return False


def _run_agent_query(prompt: str, user_id: str) -> str:
    project_id = _get_project_id()
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
            user_id=user_id or "google-chat-user",
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
            if "429" in _exc_str or "resource_exhausted" in _exc_str or "resource exhausted" in _exc_str:
                if _retry_attempt < _MAX_AGENT_RETRIES - 1:
                    _backoff = (2 ** _retry_attempt) + 1
                    logger.warning(
                        "Agent Engine 429 (attempt %d/%d), retrying in %ds: %s",
                        _retry_attempt + 1, _MAX_AGENT_RETRIES, _backoff, _agent_exc,
                    )
                    import time
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
        if _looks_like_internal_artifact(line):
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
        # 以前は6行に制限しており回答が途中で欠けやすかったため、上限を拡大する。
        return "\n".join(selected[:60]).strip()

    def _trim_response_text(text: str, max_chars: int = 12000) -> str:
        if len(text) <= max_chars:
            return text
        # 文中カットを避けるため、できる限り境界で切る。
        head = text[:max_chars]
        cut_points = [
            head.rfind("\n"),
            head.rfind("。"),
            head.rfind(". "),
            head.rfind("! "),
            head.rfind("? "),
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
# Reflection loop – general_analysis 回答の品質検証 & リトライ
# ---------------------------------------------------------------------------
_REQUIRED_OUTPUT_SECTIONS = ("結論", "根拠", "不確実性", "次アクション")
_VULN_KEYWORDS = ("cve", "脆弱性", "cvss", "vulnerability", "脆弱", "パッチ")
_REFLECTION_ENABLED_KEY = "REFLECTION_ENABLED"


def _validate_agent_response(response_text: str, original_prompt: str) -> list[str]:
    """エージェント回答の品質を検証する。問題のリストを返す（空=合格）。"""
    issues: list[str] = []
    is_vuln_response = any(kw in original_prompt.lower() for kw in _VULN_KEYWORDS)

    if not is_vuln_response or len(response_text) < 100:
        return issues  # 脆弱性以外 or 短すぎる回答は検証スキップ

    # 必須セクション検査（1 件欠損までは許容）
    missing = [s for s in _REQUIRED_OUTPUT_SECTIONS if s not in response_text]
    if len(missing) >= 2:
        issues.append(f"必須セクション不足: {', '.join(missing)}")

    # 根拠セクションのデータソース記載チェック
    if "根拠" in response_text and "確認中" not in response_text:
        evidence_keywords = ("NVD", "SBOM", "BigQuery", "OSV", "search_sbom", "get_nvd", "web_search")
        parts = response_text.split("根拠")
        evidence_part = parts[1][:500] if len(parts) > 1 else ""
        if not any(kw in evidence_part for kw in evidence_keywords):
            issues.append("根拠セクションにデータソース記載なし")

    return issues


def _run_agent_query_with_reflection(prompt: str, user_id: str) -> str:
    """エージェントクエリを実行し、品質不足時にリトライする。"""
    response = _run_agent_query(prompt, user_id)

    # 環境変数で無効化可能（デフォルト有効）
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

    corrected = _run_agent_query(reflection_prompt, user_id)
    corrected_issues = _validate_agent_response(corrected, prompt)

    if len(corrected_issues) < len(issues):
        return corrected
    return response  # フォールバック: 元の回答を返す


def _thread_payload(event: dict[str, Any], text: str) -> dict[str, Any]:
    message = event.get("message") or {}
    thread_name = ((message.get("thread") or {}).get("name") or "").strip()
    payload: dict[str, Any] = {"text": text}
    if thread_name:
        payload["thread"] = {"name": thread_name}
    return payload


def _is_async_response_enabled() -> bool:
    return (os.environ.get("CHAT_ASYNC_RESPONSE_ENABLED", "true") or "true").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _is_message_actionable(event: dict[str, Any]) -> bool:
    message = event.get("message") or {}
    sender = (message.get("sender") or {})
    sender_type = str(sender.get("type") or "").upper()
    if sender_type == "BOT" and not _is_gmail_app_message(event):
        return False

    raw_text = str(message.get("text") or "").strip()
    prompt = _clean_chat_text(event)
    if _is_gmail_app_message(event):
        return True
    if raw_text and prompt:
        return True
    return False


def _register_async_event_once(event: dict[str, Any]) -> bool:
    message_name = str(((event.get("message") or {}).get("name") or "")).strip()
    if not message_name:
        return True
    now = datetime.now(timezone.utc).timestamp()
    ttl_sec = 900
    with _ASYNC_EVENT_LOCK:
        stale = [k for k, ts in _ASYNC_EVENT_SEEN.items() if now - ts > ttl_sec]
        for key in stale:
            _ASYNC_EVENT_SEEN.pop(key, None)
        if message_name in _ASYNC_EVENT_SEEN:
            return False
        _ASYNC_EVENT_SEEN[message_name] = now
    return True


def _submit_async_job(event: dict[str, Any], user_name: str) -> None:
    if _enqueue_async_task(event, user_name):
        return
    global _ASYNC_WORKER_POOL
    try:
        _ASYNC_WORKER_POOL.submit(_run_async_message_processing, event, user_name)
        return
    except RuntimeError:
        # Worker pool can be in shutdown state during instance lifecycle transitions.
        _ASYNC_WORKER_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="chat-webhook-worker")
        _ASYNC_WORKER_POOL.submit(_run_async_message_processing, event, user_name)


def _get_async_task_target_url() -> str:
    explicit = (os.environ.get("CHAT_ASYNC_TASK_TARGET_URL") or "").strip()
    if explicit:
        return explicit
    project_id = _get_project_id()
    region = (os.environ.get("CHAT_ASYNC_TASKS_LOCATION") or os.environ.get("GCP_LOCATION") or "asia-northeast1").strip()
    service = (os.environ.get("K_SERVICE") or "vuln-agent-chat-webhook").strip()
    if not project_id or not region or not service:
        return ""
    return f"https://{region}-{project_id}.cloudfunctions.net/{service}"


def _enqueue_async_task(event: dict[str, Any], user_name: str) -> bool:
    if not _is_async_response_enabled():
        return False
    try:
        from google.cloud import tasks_v2
        from google.api_core.exceptions import AlreadyExists
    except Exception as exc:
        logger.warning("Cloud Tasks libraries unavailable; fallback to in-process async: %s", exc)
        return False

    project_id = _get_project_id()
    location = (os.environ.get("CHAT_ASYNC_TASKS_LOCATION") or os.environ.get("GCP_LOCATION") or "asia-northeast1").strip()
    queue_id = (os.environ.get("CHAT_ASYNC_TASKS_QUEUE") or "vuln-agent-chat-async").strip()
    target_url = _get_async_task_target_url()
    if not project_id or not location or not queue_id or not target_url:
        logger.warning("Async task enqueue skipped: missing project/location/queue/target_url")
        return False

    try:
        client = tasks_v2.CloudTasksClient()

        parent = client.queue_path(project_id, location, queue_id)
        payload = {
            "_internal_async_task": True,
            "chat_event": event,
            "user_name": user_name,
        }
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        task: dict[str, Any] = {
            "http_request": {
                "http_method": tasks_v2.HttpMethod.POST,
                "url": target_url,
                "headers": {"Content-Type": "application/json"},
                "body": body,
            }
        }

        message_name = str(((event.get("message") or {}).get("name") or "")).strip()
        if message_name:
            digest = hashlib.sha1(message_name.encode("utf-8")).hexdigest()[:24]
            task_id = f"msg-{digest}"
            task["name"] = client.task_path(project_id, location, queue_id, task_id)

        client.create_task(parent=parent, task=task)
        logger.info("Enqueued async processing task to Cloud Tasks queue=%s", queue_id)
        return True
    except AlreadyExists:
        logger.info("Skipped duplicate async task enqueue for same message")
        return True
    except Exception as exc:
        logger.warning("Failed to enqueue async task; fallback to in-process async: %s", exc)
        return False


def _is_cloud_tasks_request(request: Any, event: dict[str, Any]) -> bool:
    if not isinstance(event, dict):
        return False
    if not bool(event.get("_internal_async_task")):
        return False
    headers = getattr(request, "headers", None)
    if headers is None:
        return False
    task_name = str(headers.get("X-CloudTasks-TaskName") or "").strip()
    return bool(task_name)


def _send_message_to_thread(event: dict[str, Any], text: str) -> None:
    payload = _thread_payload(event, text)
    thread_name = str(((payload.get("thread") or {}).get("name") or "")).strip()
    space_name = _extract_space_name(event, thread_name)
    if not space_name:
        return
    service = _get_chat_service(mode="post")
    body: dict[str, Any] = {"text": str(payload.get("text") or "")}
    if thread_name:
        body["thread"] = {"name": thread_name}
    try:
        req: dict[str, Any] = {
            "parent": space_name,
            "body": body,
        }
        if thread_name:
            req["messageReplyOption"] = "REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD"
        service.spaces().messages().create(**req).execute()
    except Exception as exc:
        msg = str(exc)
        if "malformed space resource name" in msg.lower() or "missing or malformed space resource name" in msg.lower():
            logger.warning("Skip Chat post due to malformed space name: %s", space_name)
            return
        if thread_name and ("invalid thread resource name" in msg.lower() or "malformed thread" in msg.lower()):
            logger.warning("Retrying Chat post without thread due to invalid thread name: %s", thread_name)
            service.spaces().messages().create(
                parent=space_name,
                body={"text": str(payload.get("text") or "")},
            ).execute()
            return
        raise


def _context_key(event: dict[str, Any], user_name: str) -> str:
    message = event.get("message") or {}
    thread_name = ((message.get("thread") or {}).get("name") or "").strip()
    if thread_name:
        return f"thread:{thread_name}"
    return f"user:{user_name or 'google-chat-user'}"


def _remember_thread_root_text(event: dict[str, Any], text: str) -> None:
    message = event.get("message") or {}
    thread_name = ((message.get("thread") or {}).get("name") or "").strip()
    if not thread_name:
        return
    normalized = re.sub(r"\s+", " ", (text or "").strip())
    if not normalized:
        return
    _THREAD_ROOT_CACHE[thread_name] = normalized[:12000]


def _get_cached_thread_root_text(event: dict[str, Any]) -> str:
    message = event.get("message") or {}
    thread_name = ((message.get("thread") or {}).get("name") or "").strip()
    if not thread_name:
        return ""
    return _THREAD_ROOT_CACHE.get(thread_name, "")


def _fetch_latest_ticket_record_from_history(event: dict[str, Any]) -> dict[str, str]:
    table_id = _get_config("BQ_HISTORY_TABLE_ID", "vuln-agent-bq-table-id", "").strip()
    if not table_id:
        return {}

    message = event.get("message") or {}
    thread_name = str(((message.get("thread") or {}).get("name") or "")).strip()
    space_name = _extract_space_name(event, thread_name)

    try:
        from google.cloud import bigquery

        project_id = _get_project_id() or None
        client = bigquery.Client(project=project_id)
        query = f"""
            SELECT incident_id, vulnerability_id, title, severity, occurred_at, extra, source
            FROM `{table_id}`
            WHERE source IN ('chat_alert', 'chat_webhook_manual', 'human_review')
              AND (@thread_name = '' OR JSON_VALUE(extra, '$.thread_name') = @thread_name)
            ORDER BY occurred_at DESC
            LIMIT 50
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("thread_name", "STRING", thread_name),
            ]
        )
        rows = client.query(query, job_config=job_config).result()
        for row in rows:
            extra_raw = str(getattr(row, "extra", "") or "").strip()
            if not extra_raw:
                continue
            try:
                extra = json.loads(extra_raw)
            except Exception:
                continue
            if not isinstance(extra, dict):
                continue
            row_thread = str(extra.get("thread_name") or "").strip()
            row_space = str(extra.get("space_id") or "").strip()
            if thread_name and row_thread and row_thread != thread_name:
                continue
            if space_name and row_space and row_space != space_name:
                continue
            ticket_record = extra.get("ticket_record") or {}
            if not ticket_record and isinstance(extra.get("review"), dict):
                ticket_record = (extra.get("review") or {}).get("final_ticket_record") or {}
            if not isinstance(ticket_record, dict):
                continue
            copy_text = str(ticket_record.get("copy_paste_text") or "").strip()
            reasoning_text = str(ticket_record.get("reasoning_text") or "").strip()
            if not copy_text and not reasoning_text:
                continue
            return {
                "incident_id": str(getattr(row, "incident_id", "") or "").strip(),
                "copy_paste_text": copy_text,
                "reasoning_text": reasoning_text,
                "title": str(getattr(row, "title", "") or "").strip(),
                "vulnerability_id": str(getattr(row, "vulnerability_id", "") or "").strip(),
            }

        # Backward-compatible fallback: old records without thread_name.
        if not thread_name:
            return {}
        query_space = f"""
            SELECT incident_id, vulnerability_id, title, severity, occurred_at, extra, source
            FROM `{table_id}`
            WHERE source = 'chat_alert'
            ORDER BY occurred_at DESC
            LIMIT 50
        """
        rows = client.query(query_space).result()
        for row in rows:
            extra_raw = str(getattr(row, "extra", "") or "").strip()
            if not extra_raw:
                continue
            try:
                extra = json.loads(extra_raw)
            except Exception:
                continue
            if not isinstance(extra, dict):
                continue
            row_space = str(extra.get("space_id") or "").strip()
            if space_name and row_space and row_space != space_name:
                continue
            ticket_record = extra.get("ticket_record") or {}
            if not isinstance(ticket_record, dict):
                continue
            copy_text = str(ticket_record.get("copy_paste_text") or "").strip()
            reasoning_text = str(ticket_record.get("reasoning_text") or "").strip()
            if not copy_text and not reasoning_text:
                continue
            return {
                "incident_id": str(getattr(row, "incident_id", "") or "").strip(),
                "copy_paste_text": copy_text,
                "reasoning_text": reasoning_text,
                "title": str(getattr(row, "title", "") or "").strip(),
                "vulnerability_id": str(getattr(row, "vulnerability_id", "") or "").strip(),
            }
    except Exception as exc:
        logger.warning("Failed to fetch latest ticket record from history: %s", exc)
    return {}


def _build_history_ticket_message(record: dict[str, str]) -> str:
    copy_text = str(record.get("copy_paste_text") or "").strip()
    reasoning_text = str(record.get("reasoning_text") or "").strip()
    incident_id = str(record.get("incident_id") or "").strip()
    title = str(record.get("title") or "").strip()
    vuln_id = str(record.get("vulnerability_id") or "").strip()

    sections: list[str] = []
    if copy_text:
        sections.append(copy_text)
    if reasoning_text:
        sections.append(reasoning_text)

    if not sections:
        return ""
    if incident_id:
        sections.append(f"【管理ID】\n{incident_id}")
    if title or vuln_id:
        lines = ["【参照元】", "スレッド読取に失敗したため履歴から補完しました。"]
        if vuln_id:
            lines.append(f"- 脆弱性ID: {vuln_id}")
        if title:
            lines.append(f"- 件名: {title}")
        sections.append("\n".join(lines))
    return "\n\n".join(sections).strip()



def _extract_ticket_sections(text: str) -> tuple[str, str]:
    body = (text or "").strip()
    if not body:
        return "", ""
    copy_marker = "【起票用（コピペ）】"
    reason_marker = "【判断理由】"
    incident_marker = "【管理ID】"

    copy_text = ""
    reasoning_text = ""
    copy_idx = body.find(copy_marker)
    reason_idx = body.find(reason_marker)
    incident_idx = body.find(incident_marker)

    if copy_idx >= 0:
        copy_end = len(body)
        if reason_idx > copy_idx:
            copy_end = reason_idx
        elif incident_idx > copy_idx:
            copy_end = incident_idx
        copy_text = body[copy_idx:copy_end].strip()
    if reason_idx >= 0:
        reason_end = len(body)
        if incident_idx > reason_idx:
            reason_end = incident_idx
        reasoning_text = body[reason_idx:reason_end].strip()
    return copy_text, reasoning_text


def _save_ticket_record_to_history(event: dict[str, Any], response_text: str, source: str = "chat_webhook_manual") -> None:
    table_id = _get_config("BQ_HISTORY_TABLE_ID", "vuln-agent-bq-table-id", "").strip()
    if not table_id:
        return
    copy_text, reasoning_text = _extract_ticket_sections(response_text)
    if not copy_text and not reasoning_text:
        return
    try:
        from google.cloud import bigquery
    except Exception:
        return

    message = event.get("message") or {}
    thread_name = str(((message.get("thread") or {}).get("name") or "")).strip()
    space_name = _extract_space_name(event, thread_name)
    incident_id = _extract_incident_id(response_text) or str(uuid.uuid4())
    vuln_match = re.search(r"\bCVE-\d{4}-\d{4,7}\b", response_text, flags=re.IGNORECASE)
    vulnerability_id = (vuln_match.group(0).upper() if vuln_match else "").strip()
    if not vulnerability_id:
        seed = re.sub(r"[^A-Za-z0-9]", "", thread_name)[-16:] or "UNKNOWN"
        vulnerability_id = f"THREAD-{seed}"

    summary = "Chat follow-up ticket"
    for line in copy_text.splitlines():
        if "依頼概要" in line and ":" in line:
            summary = line.split(":", 1)[1].strip() or summary
            break

    extra = {
        "space_id": space_name,
        "thread_name": thread_name,
        "ticket_record": {
            "copy_paste_text": copy_text,
            "reasoning_text": reasoning_text,
        },
    }
    row = {
        "incident_id": incident_id,
        "vulnerability_id": vulnerability_id,
        "title": summary[:500],
        "severity": "要確認",
        "affected_systems": "[]",
        "cvss_score": None,
        "description": None,
        "remediation": None,
        "owners": "[]",
        "status": "notified",
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "extra": json.dumps(extra, ensure_ascii=False),
    }
    try:
        client = bigquery.Client(project=_get_project_id() or None)
        errors = client.insert_rows_json(table_id, [row])
        if errors:
            logger.warning("Failed to save ticket record to history: %s", errors)
    except Exception as exc:
        logger.warning("Failed to save ticket record to history: %s", exc)


def _get_recent_turns(key: str, max_turns: int = 2) -> list[dict[str, str]]:
    turns = list(_RECENT_TURNS.get(key) or [])
    if not turns:
        return []
    return turns[-max_turns:]


def _remember_turn(key: str, user_prompt: str, assistant_text: str) -> None:
    if not key or not user_prompt.strip():
        return
    if key not in _RECENT_TURNS:
        _RECENT_TURNS[key] = deque(maxlen=_MAX_RECENT_TURNS)
    _RECENT_TURNS[key].append(
        {
            "user": user_prompt.strip()[:1200],
            "assistant": (assistant_text or "").strip()[:1200],
        }
    )


def _build_contextual_prompt(original_prompt: str, recent_turns: list[dict[str, str]]) -> str:
    if not recent_turns:
        return original_prompt
    lines: list[str] = ["以下は直近の会話文脈です。必要な範囲で参照してください。"]
    for idx, turn in enumerate(recent_turns, start=1):
        user_text = (turn.get("user") or "").strip()
        assistant_text = (turn.get("assistant") or "").strip()
        if user_text:
            lines.append(f"- 直近{idx}件前のユーザー発話: {user_text}")
        if assistant_text:
            lines.append(f"- 直近{idx}件前のあなたの回答要約: {assistant_text}")
    lines.append("")
    lines.append(f"現在のユーザー発話: {original_prompt}")
    return "\n".join(lines).strip()


def _build_thread_followup_prompt(user_prompt: str) -> str:
    return (
        "以下は同一スレッド内のフォローアップ依頼です。"
        "対象は『このスレッドで直前に扱った脆弱性通知』に固定してください。"
        "確認質問は返さず、分析結果を出力してください。"
        "情報不足の項目は必ず「要確認」と明記してください。\n\n"
        "出力要件:\n"
        "- Markdown表は使わない\n"
        "- 見出しは必ず次の2つだけを使う\n"
        "  1) 【起票用（コピペ）】\n"
        "  2) 【判断理由】\n"
        "- 【起票用（コピペ）】は次の4項目を固定順で出力\n"
        "  大分類 / 小分類 / 依頼概要 / 詳細\n"
        "- 値が特定できない項目は「要確認」\n\n"
        f"ユーザー依頼: {user_prompt}"
    )


def _build_backfill_guidance_message() -> str:
    return (
        "このスレッドは初回取り込みが未完了のため、過去通知を復元できませんでした。\n"
        "次の形式で同一スレッドに貼り付けてください。\n\n"
        "1) 元の脆弱性通知本文（CVE/URLを含む）を貼り付け\n"
        "2) 最後に「この内容で起票用を作成して」と送信\n\n"
        "取り込み後は「確認して」だけで再表示できます。"
    )


def _build_low_quality_ticket_message() -> str:
    return (
        "起票データの根拠情報が不足しているため、このままでは誤起票の可能性があります。\n"
        "次の形式で同一スレッドに貼り付けてください。\n\n"
        "1) 脆弱性通知本文（CVE / CVSS / 対象製品 / 参照URL を含む）\n"
        "2) 最後に「この内容で起票用を作成して」と送信\n\n"
        "十分な情報が確認でき次第、起票用データを再生成します。"
    )


def _strip_manual_command_lines(text: str) -> str:
    if not text:
        return ""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    kept: list[str] = []
    for line in lines:
        lowered = line.lower()
        if any(token in lowered for token in _MANUAL_TICKET_TRIGGER_WORDS):
            cleaned = line
            for token in _MANUAL_TICKET_TRIGGER_WORDS:
                cleaned = re.sub(re.escape(token), "", cleaned, flags=re.IGNORECASE)
            cleaned = re.sub(r"\s+", " ", cleaned).strip()
            if cleaned:
                kept.append(cleaned)
            continue
        if line in {"確認して", "確認", "解析して"}:
            continue
        kept.append(line)
    return "\n".join(kept).strip()


def _resolve_manual_backfill_source_text(event: dict[str, Any], raw_body_text: str) -> str:
    candidate = _strip_manual_command_lines(raw_body_text)
    if _contains_specific_vuln_signal(candidate):
        return candidate
    if _contains_vulnerability_signal(candidate) and len(candidate) >= 80:
        return candidate
    quoted = _fetch_quoted_message_text(event)
    if _contains_specific_vuln_signal(quoted):
        return quoted
    if _contains_vulnerability_signal(quoted) and len(quoted) >= 80:
        return quoted
    root_text = _fetch_thread_root_message_text(event)
    if _contains_specific_vuln_signal(root_text):
        return root_text
    if _contains_vulnerability_signal(root_text) and len(root_text) >= 80:
        return root_text
    cached_root = _get_cached_thread_root_text(event)
    if _contains_specific_vuln_signal(cached_root):
        return cached_root
    if _contains_vulnerability_signal(cached_root) and len(cached_root) >= 80:
        return cached_root
    history_ticket = _fetch_latest_ticket_record_from_history(event)
    history_copy = str(history_ticket.get("copy_paste_text") or "").strip()
    if _contains_specific_vuln_signal(history_copy):
        return history_copy
    return ""


def _is_low_quality_ticket_output(text: str) -> bool:
    body = (text or "").strip()
    if not body:
        return True
    if "【起票用（コピペ）】" not in body:
        return True
    if "詳細: 要確認" not in body:
        return False
    weak_phrases = ("承知", "了解", "テンプレート", "以下に", "作成します")
    if any(phrase in body for phrase in weak_phrases) and not _contains_specific_vuln_signal(body):
        return True
    return False


def _has_ticket_sections(text: str) -> bool:
    body = (text or "").strip()
    return "【起票用（コピペ）】" in body and "【判断理由】" in body


def _looks_like_ticket_template_output(text: str) -> bool:
    body = (text or "").strip()
    if not body:
        return False
    markers = (
        "【大分類】",
        "【小分類】",
        "【依頼概要】",
        "【対象の機器/アプリ】",
        "【脆弱性情報",
        "【CVSSスコア】",
        "【依頼内容】",
        "【対応完了目標】",
    )
    return sum(1 for m in markers if m in body) >= 3


def _is_manual_ticket_output_usable(text: str) -> bool:
    body = (text or "").strip()
    if not body:
        return False
    if not _has_ticket_sections(body):
        return False
    if _is_low_quality_ticket_output(body):
        return False
    required_lines = ("大分類:", "小分類:", "依頼概要:", "詳細:")
    if not all(token in body for token in required_lines):
        return False
    if "小分類: 要確認" in body and "依頼概要: 要確認" in body and "詳細: 要確認" in body:
        return False
    return True


def _is_auto_ticket_output_usable(text: str) -> bool:
    body = (text or "").strip()
    if not body:
        return False
    if _looks_like_internal_artifact(body):
        return False
    if not _has_ticket_sections(body):
        return False
    if _is_low_quality_ticket_output(body):
        return False
    if "依頼概要:" not in body or "詳細:" not in body:
        return False
    weak_summary = (
        "はい、承知",
        "承知いたしました",
        "ご依頼のメール内容",
        "判断しました",
        "以下に",
        "テンプレート",
        "作成します",
    )
    for line in body.splitlines():
        if not line.strip().startswith("依頼概要:"):
            continue
        summary = line.split(":", 1)[1].strip()
        if any(w in summary for w in weak_summary):
            return False
        if len(summary) < 10:
            return False
        if "脆弱性" not in summary and "ペネトレ" not in summary and "アップグレード" not in summary:
            return False
    return True


def _infer_request_summary_from_source(source_text: str) -> str:
    text = (source_text or "").strip()
    if not text:
        return "脆弱性確認及び該当バージョンの対応願い"
    lower = text.lower()
    product_patterns = [
        (r"almalinux", "AlmaLinux"),
        (r"fortios|fortigate", "FortiOS"),
        (r"cisco\s*asa", "Cisco ASA"),
        (r"amazon\s*linux", "Amazon Linux"),
        (r"lanscope", "LANSCOPE"),
        (r"\bios\b|iphone", "Apple iOS"),
        (r"windows", "Windows"),
    ]
    for pattern, name in product_patterns:
        if re.search(pattern, lower):
            if name == "Apple iOS":
                return "Apple iOS のアップグレード"
            return f"{name} の脆弱性確認及び該当バージョンの対応願い"
    return "脆弱性確認及び該当バージョンの対応願い"


def _extract_sidfm_entries(source_text: str) -> list[dict[str, Any]]:
    text = (source_text or "").strip()
    if not text:
        return []

    # Normalize invisible Unicode characters that Google Chat may insert
    text = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff]", "", text)
    # Normalize various Unicode whitespace to regular spaces (within lines)
    text = re.sub(r"[\u00a0\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u205f\u3000]", " ", text)

    # Google Chat may deliver the entire email as a single line (no line breaks).
    # Restore line breaks by inserting \n before known SIDfm structural markers.
    if text.count("\n") < 5 and len(text) > 300:
        # Before SIDfm table rows: "1 62977 9.4 AlmaLinux ..."
        text = re.sub(r"(?<=\s)(\d{1,2}\s+\d{5,8}\s+(?:10(?:\.\d{1,2})?|[0-9](?:\.\d{1,2})?)\s+)", r"\n\1", text)
        # Before detail block entries: "○No.1 ID:62977 ..."
        text = re.sub(r"(?=○No\.\d)", "\n", text)
        # Before ID: references in block format
        text = re.sub(r"(?=ID:\d{4,8})", "\n", text)
        # Before SIDfm URLs
        text = re.sub(r"(?=https://sid\.softek\.jp/filter/sinfo/\d)", "\n", text)
        # Before section dividers
        text = re.sub(r"(?=◆――)", "\n", text)
        text = re.sub(r"(?=―――――)", "\n", text)
        logger.warning("[diag:sidfm] single-line text detected, restored line breaks: lines_after=%d", text.count("\n") + 1)

    entries: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    lines = text.splitlines()
    logger.warning("[diag:sidfm] total_lines=%d first_200_chars=%r", len(lines), text[:200])

    # 1) SIDfm一覧テーブル: "1 62977  9.4 AlmaLinux ..."
    # CVSS supports: 9.4, 9.40, 10, 10.0 formats
    row_pat = re.compile(r"^\s*\d+\s+(\d{4,8})\s+(10(?:\.\d{1,2})?|[0-9](?:\.\d{1,2})?)\s+(.+?)\s*$")
    candidate_lines = [raw for raw in lines if re.search(r"\d{4,8}", raw) and re.search(r"[0-9]\.[0-9]", raw)]
    logger.warning("[diag:sidfm] candidate_lines_with_id_and_cvss=%d samples=%r", len(candidate_lines), candidate_lines[:5])
    for raw in lines:
        m = row_pat.match(raw)
        if not m:
            continue
        vuln_id, cvss_s, title = m.group(1), m.group(2), m.group(3).strip()
        if vuln_id in seen_ids:
            continue
        seen_ids.add(vuln_id)
        try:
            cvss = float(cvss_s)
        except Exception:
            cvss = None
        entries.append({"id": vuln_id, "cvss": cvss, "title": title, "url": f"https://sid.softek.jp/filter/sinfo/{vuln_id}"})

    # 2) 本文ブロック: "ID:62977 ... CVSSv3: 9.4"
    block_pat = re.compile(r"ID:(\d{4,8}).*?CVSSv3:\s*(10(?:\.\d{1,2})?|[0-9](?:\.\d{1,2})?)", re.IGNORECASE)
    for i, raw in enumerate(lines):
        m = block_pat.search(raw)
        if not m:
            continue
        vuln_id, cvss_s = m.group(1), m.group(2)
        if vuln_id in seen_ids:
            continue
        try:
            cvss = float(cvss_s)
        except Exception:
            cvss = None
        title = ""
        url = ""
        for j in range(i + 1, min(i + 12, len(lines))):
            candidate = lines[j].strip()
            if not candidate:
                continue
            if not title and "http" not in candidate and "AlmaLinux" in candidate:
                title = re.sub(r"\s+", " ", candidate).strip()
            if "https://sid.softek.jp/filter/sinfo/" in candidate:
                url = re.search(r"https://sid\.softek\.jp/filter/sinfo/\d+", candidate).group(0)  # type: ignore[union-attr]
                break
        if not url:
            url = f"https://sid.softek.jp/filter/sinfo/{vuln_id}"
        seen_ids.add(vuln_id)
        entries.append({"id": vuln_id, "cvss": cvss, "title": title or "要確認", "url": url})

    # 3) SIDfm ID without index: "62977  9.4 AlmaLinux ..." (no leading row number)
    noindex_pat = re.compile(r"^\s*(\d{5,8})\s+(10(?:\.\d{1,2})?|[0-9](?:\.\d{1,2})?)\s+(.+?)\s*$")
    for raw in lines:
        m = noindex_pat.match(raw)
        if not m:
            continue
        vuln_id, cvss_s, title = m.group(1), m.group(2), m.group(3).strip()
        if vuln_id in seen_ids:
            continue
        seen_ids.add(vuln_id)
        try:
            cvss = float(cvss_s)
        except Exception:
            cvss = None
        entries.append({"id": vuln_id, "cvss": cvss, "title": title, "url": f"https://sid.softek.jp/filter/sinfo/{vuln_id}"})

    logger.warning("[diag:sidfm] extracted_entries=%d entries=%r", len(entries), [(e.get("id"), e.get("cvss"), e.get("title", "")[:40]) for e in entries])

    def _key(item: dict[str, Any]) -> tuple[float, str]:
        score = item.get("cvss")
        return (float(score) if isinstance(score, (int, float)) else -1.0, str(item.get("id") or ""))

    return sorted(entries, key=_key, reverse=True)


def _extract_almalinux_versions_from_text(text: str) -> list[str]:
    versions = sorted(
        {m.group(1) for m in re.finditer(r"almalinux\s*([0-9]{1,2})", text or "", re.IGNORECASE)},
        key=lambda x: int(x),
        reverse=True,
    )
    return versions


def _build_entries_from_sid_links_fallback(source_text: str, sid_links: list[str]) -> list[dict[str, Any]]:
    if not sid_links:
        return []
    text = source_text or ""
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for link in sid_links:
        m = re.search(r"/sinfo/(\d+)", link)
        if not m:
            continue
        vuln_id = m.group(1)
        if vuln_id in seen:
            continue
        seen.add(vuln_id)
        # ID と CVSS/バージョンの近傍を可能な範囲で復元
        cvss = None
        ver = ""
        title = "要確認"
        block_pat = re.compile(
            rf"(?:ID[:：]\s*{re.escape(vuln_id)}.*?CVSSv3[:：]?\s*([0-9](?:\.[0-9])?).*?AlmaLinux\s*([0-9]{{1,2}}).*?{re.escape(link)})",
            re.IGNORECASE | re.DOTALL,
        )
        bm = block_pat.search(text)
        if bm:
            try:
                cvss = float(bm.group(1))
            except Exception:
                cvss = None
            ver = str(bm.group(2) or "").strip()
            title = f"AlmaLinux {ver} の脆弱性" if ver else "AlmaLinux の脆弱性"
        entries.append(
            {
                "id": vuln_id,
                "cvss": cvss,
                "title": title,
                "url": link,
                "os_version": ver or "要確認",
            }
        )
    return entries


def _group_sid_links_by_almalinux_version(source_text: str, sid_links: list[str]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    text = source_text or ""
    for link in sid_links:
        link = str(link or "").strip()
        if not link:
            continue
        escaped = re.escape(link)
        # 直前近傍にある AlmaLinux バージョンを拾う
        mm = re.search(
            rf"(AlmaLinux\s*([0-9]{{1,2}}).{{0,260}}?{escaped}|{escaped}.{{0,260}}?AlmaLinux\s*([0-9]{{1,2}}))",
            text,
            re.IGNORECASE | re.DOTALL,
        )
        version = ""
        if mm:
            version = str(mm.group(2) or mm.group(3) or "").strip()
        if not version:
            # URLのIDに対応する本文ブロックから推定
            id_match = re.search(r"/sinfo/(\d+)", link)
            vuln_id = id_match.group(1) if id_match else ""
            if vuln_id:
                vm = re.search(
                    rf"ID[:：]\s*{re.escape(vuln_id)}.*?AlmaLinux\s*([0-9]{{1,2}})",
                    text,
                    re.IGNORECASE | re.DOTALL,
                )
                if vm:
                    version = str(vm.group(1) or "").strip()
        if version:
            key = f"AlmaLinux{version}"
            grouped.setdefault(key, [])
            if link not in grouped[key]:
                grouped[key].append(link)
    return grouped


def _get_sbom_almalinux_versions() -> set[str]:
    cached_versions = _SBOM_ALMA_VERSION_CACHE.get("versions")
    fetched_at = _SBOM_ALMA_VERSION_CACHE.get("fetched_at")
    now = datetime.now(timezone.utc)
    if isinstance(cached_versions, set) and isinstance(fetched_at, datetime):
        if (now - fetched_at).total_seconds() < 600:
            return set(cached_versions)

    table_id = _get_config("BQ_SBOM_TABLE_ID", "vuln-agent-bq-sbom-table-id", "").strip()
    if not table_id:
        return set()
    try:
        from google.cloud import bigquery

        client = bigquery.Client(project=_get_project_id() or None)
        query = f"""
            SELECT DISTINCT REGEXP_EXTRACT(LOWER(release), r'almalinux([0-9]{{1,2}})') AS alma_ver
            FROM `{table_id}`
            WHERE REGEXP_CONTAINS(LOWER(release), r'almalinux[0-9]{{1,2}}')
        """
        rows = list(client.query(query).result())
        versions = {str((r.get("alma_ver") if isinstance(r, dict) else getattr(r, "alma_ver", "")) or "").strip() for r in rows}
        versions = {v for v in versions if v}
        _SBOM_ALMA_VERSION_CACHE["versions"] = set(versions)
        _SBOM_ALMA_VERSION_CACHE["fetched_at"] = now
        return versions
    except Exception as exc:
        logger.warning("[diag:sbom] Failed to load AlmaLinux versions from SBOM table: %s", exc)
        return set()


def _get_sbom_product_names() -> set[str]:
    """BQ SBOMテーブルから製品名(name列)をDISTINCTで取得。10分キャッシュ。"""
    cached_names = _SBOM_PRODUCT_CACHE.get("names")
    fetched_at = _SBOM_PRODUCT_CACHE.get("fetched_at")
    now = datetime.now(timezone.utc)
    if isinstance(cached_names, set) and isinstance(fetched_at, datetime):
        if (now - fetched_at).total_seconds() < 600:
            return set(cached_names)

    table_id = _get_config("BQ_SBOM_TABLE_ID", "vuln-agent-bq-sbom-table-id", "").strip()
    if not table_id:
        return set()
    try:
        from google.cloud import bigquery

        client = bigquery.Client(project=_get_project_id() or None)
        query = f"""
            SELECT DISTINCT LOWER(name) AS product_name
            FROM `{table_id}`
            WHERE type IN ('application', 'os', 'network')
        """
        rows = list(client.query(query).result())
        names = {
            str((r.get("product_name") if isinstance(r, dict) else getattr(r, "product_name", "")) or "").strip()
            for r in rows
        }
        names = {n for n in names if n}
        _SBOM_PRODUCT_CACHE["names"] = set(names)
        _SBOM_PRODUCT_CACHE["fetched_at"] = now
        return names
    except Exception as exc:
        logger.warning("[diag:sbom] Failed to load product names from SBOM table: %s", exc)
        return set()


_PRODUCT_EXTRACT_PATTERNS: list[tuple[str, str]] = [
    (r"google\s*chrome", "Google Chrome"),
    (r"\bfirefox\b", "Firefox"),
    (r"\bthunderbird\b", "Thunderbird"),
    (r"\bedge\b.*(?:chromium|ブラウザ)", "Microsoft Edge"),
    (r"\bmacos\b|\bmac\s*os\b", "MacOS"),
    (r"\bwindows\s*server", "Windows Server"),
    (r"\bwindows\s*1[01]\b", "Windows"),
    (r"\besxi\b|\bvmware\b|\bvsphere\b", "ESXi"),
    (r"\bpostfix\b", "Postfix"),
    (r"\bsql\s*server\b", "SQL Server"),
    (r"\bapache\b", "Apache"),
    (r"\bnginx\b", "nginx"),
    (r"\bopenssl\b", "openssl"),
]


def _extract_product_names_quick(text: str) -> list[str]:
    """通知テキストから製品名を軽量抽出（SBOM照合用）。"""
    lowered = (text or "").lower()
    products: list[str] = []
    if "almalinux" in lowered:
        products.append("AlmaLinux")
    if re.search(r"fortios|fortigate", lowered):
        products.append("FortiGate")
    if re.search(r"cisco\s*asa", lowered):
        products.append("Cisco")
    for pattern, name in _PRODUCT_EXTRACT_PATTERNS:
        if re.search(pattern, lowered):
            if name not in products:
                products.append(name)
    return products


def _check_product_in_sbom(product_name: str, sbom_names: set[str]) -> bool:
    """SIDfmの製品名がSBOMに登録されているか柔軟にマッチング（部分一致・小文字比較）。"""
    lowered = product_name.lower().strip()
    if not lowered:
        return False
    for sbom_name in sbom_names:
        if lowered in sbom_name or sbom_name in lowered:
            return True
    return False


def _check_sbom_registration(source_text: str) -> tuple[bool, list[str], str]:
    """SBOMに製品が登録されているかチェック。

    Returns:
        (should_skip, detected_products, reason)
        - should_skip=True → 対応不要
        - should_skip=False → チケット生成続行
    """
    products = _extract_product_names_quick(source_text)
    if not products:
        return False, [], ""  # 製品を特定できない場合は安全のため既存フローに任せる
    # AlmaLinuxは既存フィルタに任せる（バージョン単位のフィルタがある）
    if any("almalinux" in p.lower() for p in products):
        return False, products, ""
    sbom_names = _get_sbom_product_names()
    if not sbom_names:
        return False, products, ""  # SBOMデータ取得失敗 → 安全のため続行
    matched = any(_check_product_in_sbom(p, sbom_names) for p in products)
    if matched:
        return False, products, ""  # SBOM登録あり → チケット生成
    return True, products, "SBOMに登録されていない製品のため、自社環境に該当なしと判断"


def _build_sbom_not_registered_message(products: list[str], reason: str) -> str:
    """SBOM未登録製品に対する対応不要メッセージを構築。"""
    products_str = ", ".join(products) if products else "（製品を特定できませんでした）"
    return (
        "対応不要と判断しました。\n\n"
        f"【検出された製品】\n{products_str}\n\n"
        f"【判断理由】\n{reason}\n\n"
        "もし対象環境に該当製品がある場合はお知らせください。"
    )


_MSG_FORMAT_SIDFM = "sidfm"
_MSG_FORMAT_EXPLOITED = "exploited"
_MSG_FORMAT_UNKNOWN = "unknown"


def _classify_message_format(text: str) -> str:
    """通知メッセージのフォーマットを分類する。"""
    t = (text or "").strip()
    # 先頭500文字以内にマーカーがあるか（メール転送ヘッダー考慮）
    head = t[:500]
    # 優先順位: exploited > sidfm（悪用済み通知が最優先）
    if "【悪用された脆弱性】" in head:
        return _MSG_FORMAT_EXPLOITED
    if "[SIDfm]" in head:
        return _MSG_FORMAT_SIDFM
    return _MSG_FORMAT_UNKNOWN


def _analyze_exploited_vuln(source_text: str) -> dict[str, Any]:
    """【悪用された脆弱性】通知をGeminiで軽量分析。"""
    prompt = (
        "以下は「悪用が確認された脆弱性」の通知テキストです。\n"
        "次の情報をJSON形式で返してください。\n\n"
        "1. is_windows_or_apple: 対象製品がWindows製品またはApple製品"
        "（macOS, iOS, iPadOS, Safari, watchOS, tvOS, visionOS等）"
        "であればtrue、それ以外はfalse\n"
        "2. product_name: 対象製品名（日本語）\n"
        "3. cve_ids: 検出されたCVE番号のリスト\n"
        "4. comment: セキュリティ担当者向けの簡潔な対応コメント（2-3文）\n\n"
        f"通知テキスト:\n{source_text[:3000]}"
    )
    schema = {
        "type": "object",
        "properties": {
            "is_windows_or_apple": {"type": "boolean"},
            "product_name": {"type": "string"},
            "cve_ids": {"type": "array", "items": {"type": "string"}},
            "comment": {"type": "string"},
        },
        "required": ["is_windows_or_apple", "product_name", "cve_ids", "comment"],
    }
    try:
        return _call_gemini_json(prompt, response_schema=schema)
    except Exception as exc:
        logger.warning("[exploited_vuln] Gemini analysis failed: %s", exc)
        return {}


def _build_exploited_update_message(analysis: dict[str, Any]) -> str:
    """悪用された脆弱性に対するアップデート推奨メッセージ。"""
    product = analysis.get("product_name") or "（不明）"
    cves = analysis.get("cve_ids") or []
    cve_str = ", ".join(cves) if cves else "（CVE番号なし）"
    comment = analysis.get("comment") or ""
    lines = [
        "⚠ 悪用が確認された脆弱性です。速やかなアップデートを推奨します。",
        "",
        f"【対象製品】\n{product}",
        "",
        f"【CVE】\n{cve_str}",
    ]
    if comment:
        lines.append("")
        lines.append(f"【AIコメント】\n{comment}")
    lines.append("")
    lines.append("速やかに最新バージョンへのアップデートをお願いします。")
    return "\n".join(lines)


def _build_exploited_not_target_message(analysis: dict[str, Any]) -> str:
    """悪用された脆弱性だがWindows/Apple以外 → 対応不要メッセージ。"""
    product = analysis.get("product_name") or "（不明）"
    return (
        "対応不要と判断しました。\n\n"
        f"【検出された製品】\n{product}\n\n"
        "【判断理由】\nWindows / Apple 以外の製品のため、対応対象外です。"
    )


def _extract_base_date_from_source(source_text: str) -> datetime:
    text = (source_text or "").strip()
    m = re.search(r"SIDfm\s*\((\d{4})/(\d{2})/(\d{2})\)", text)
    if m:
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
        try:
            return datetime(y, mo, d, tzinfo=timezone.utc)
        except Exception:
            pass
    return datetime.now(timezone.utc)


def _add_business_days(base: datetime, days: int) -> datetime:
    current = base
    added = 0
    while added < max(0, days):
        current = current + timedelta(days=1)
        if current.weekday() < 5:
            added += 1
    return current


def _infer_due_date_from_policy(source_text: str, max_cvss: float | None) -> tuple[str, str]:
    base = _extract_base_date_from_source(source_text)
    text = (source_text or "").lower()
    exploit_signal = ("悪用実績" in source_text) or ("エクスプロイトコード" in source_text) or ("exploit" in text)
    is_public_resource = any(token in text for token in ("fortigate", "cisco asa", "zeem", "メールサーバ", "mail server", "公開サーバ", "公開リソース", "インターネット公開", "dmz", "almalinux 9", "almalinux9"))

    if max_cvss is None or max_cvss < 8.0:
        return "対応不要", "CVSS 8.0未満または不明のため対応不要"
    if is_public_resource and max_cvss >= 9.0 and exploit_signal:
        due = _add_business_days(base, 5)
        return due.strftime("%Y/%m/%d"), "社内方針: 公開リソース×CVSS9.0以上×悪用実績あり(5営業日)"
    if is_public_resource and max_cvss >= 8.0:
        due = _add_business_days(base, 10)
        return due.strftime("%Y/%m/%d"), "社内方針: 公開リソース×CVSS8.0以上(10営業日)"
    # デフォルトは内部リソース扱い: 3か月
    month = base.month + 3
    year = base.year + (month - 1) // 12
    month = ((month - 1) % 12) + 1
    day = min(base.day, 28)
    due = datetime(year, month, day, tzinfo=timezone.utc)
    return due.strftime("%Y/%m/%d"), "社内方針: 内部リソース×CVSS8.0以上(3か月)"


def _extract_source_facts(source_text: str) -> dict[str, Any]:
    text = (source_text or "").strip()
    lowered = text.lower()
    entries = _extract_sidfm_entries(text)
    pre_filter_count = len(entries)
    links = re.findall(r"https?://[^\s)>\]|]+", text)
    sid_links = [u for u in links if "sid.softek.jp/filter/sinfo/" in u]
    sid_links = list(dict.fromkeys(sid_links))
    if not entries and sid_links:
        entries = _build_entries_from_sid_links_fallback(text, sid_links)
        logger.warning("[diag:facts] used sid_links_fallback, entries=%d", len(entries))
    sbom_alma_versions = _get_sbom_almalinux_versions()
    logger.warning("[diag:facts] pre_filter_entries=%d sbom_versions=%r", pre_filter_count, sbom_alma_versions)
    if sbom_alma_versions:
        filtered_entries: list[dict[str, Any]] = []
        for e in entries:
            title = str(e.get("title") or "")
            m = re.search(r"almalinux\s*([0-9]{1,2})", title, re.IGNORECASE)
            if m:
                if m.group(1) in sbom_alma_versions:
                    filtered_entries.append(e)
                else:
                    logger.warning("[diag:facts] SBOM-filtered out: id=%s ver=%s title=%s", e.get("id"), m.group(1), title[:50])
            else:
                filtered_entries.append(e)
                logger.warning("[diag:facts] no AlmaLinux version in title, keeping: id=%s title=%s", e.get("id"), title[:50])
        entries = filtered_entries
    logger.warning("[diag:facts] post_filter_entries=%d", len(entries))

    # 同一納期で同一起票とするため、エントリごとに納期を算出してグルーピングする。
    due_groups: dict[str, list[dict[str, Any]]] = {}

    def _try_cvss_float(v: Any) -> float | None:
        try:
            return float(v)
        except (TypeError, ValueError):
            return None

    all_scores = [s for e in entries if (s := _try_cvss_float(e.get("cvss"))) is not None]
    max_score = max(all_scores) if all_scores else None

    for e in entries:
        score = _try_cvss_float(e.get("cvss"))
        if score is None:
            score = max_score
        due_date, due_reason = _infer_due_date_from_policy(text, score)
        entry = dict(e)
        entry["due_date"] = due_date
        entry["due_reason"] = due_reason
        due_groups.setdefault(due_date, []).append(entry)

    selected_due_date = ""
    selected_entries: list[dict[str, Any]] = []
    if due_groups:
        # 件数優先、同数なら日付昇順で選択。
        def _due_sort_key(item: tuple[str, list[dict[str, Any]]]) -> tuple[int, str]:
            due, group = item
            due_key = due if re.fullmatch(r"\d{4}/\d{2}/\d{2}", due or "") else "9999/12/31"
            return (-len(group), due_key)

        selected_due_date, selected_entries = sorted(due_groups.items(), key=_due_sort_key)[0]
    else:
        selected_entries = []

    entry_links = [str(e.get("url") or "").strip() for e in selected_entries if str(e.get("url") or "").strip()]
    vuln_links = entry_links or sid_links or links

    grouped_links_by_version: dict[str, list[str]] = {}
    for e in (selected_entries or entries):
        title = str(e.get("title") or "")
        url = str(e.get("url") or "").strip()
        if not url:
            continue
        vm = re.search(r"AlmaLinux\s*([0-9]{1,2})", title, re.IGNORECASE)
        if not vm:
            continue
        key = f"AlmaLinux{vm.group(1)}"
        grouped_links_by_version.setdefault(key, [])
        if url not in grouped_links_by_version[key]:
            grouped_links_by_version[key].append(url)
    if not grouped_links_by_version:
        grouped_links_by_version = _group_sid_links_by_almalinux_version(text, sid_links)
    if sbom_alma_versions and grouped_links_by_version:
        allowed = {f"AlmaLinux{v}" for v in sbom_alma_versions}
        grouped_links_by_version = {
            k: v for k, v in grouped_links_by_version.items() if k in allowed and v
        }

    products: list[str] = []
    entry_text_for_products = "\n".join(str(e.get("title") or "") for e in (selected_entries or entries))
    if "almalinux" in lowered or "almalinux" in entry_text_for_products.lower():
        versions = _extract_almalinux_versions_from_text(entry_text_for_products or lowered)
        if not versions and sbom_alma_versions:
            versions = sorted(set(sbom_alma_versions), key=lambda x: int(x), reverse=True)
        if versions:
            products.extend([f"AlmaLinux{v}" for v in versions])
        else:
            products.append("AlmaLinux")
    if re.search(r"fortios|fortigate", lowered):
        products.append("FortiOS")
    if re.search(r"cisco\s*asa", lowered):
        products.append("Cisco ASA")
    if re.search(r"amazon\s*linux", lowered):
        products.append("Amazon Linux")
    if re.search(r"\bios\b|iphone", lowered):
        products.append("Apple iOS")
    # 汎用パターンで追加検出
    for _pat, _pname in _PRODUCT_EXTRACT_PATTERNS:
        if re.search(_pat, lowered) or re.search(_pat, entry_text_for_products.lower()):
            if _pname not in products:
                products.append(_pname)
    if not products:
        products.append("要確認")
    products = list(dict.fromkeys(products))

    scores: list[float] = []
    entry_scores = [s for e in selected_entries if (s := _try_cvss_float(e.get("cvss"))) is not None]
    if entry_scores:
        scores.extend(entry_scores)
    elif not sbom_alma_versions:
        # Regex fallback only when SBOM filtering is not active.
        # When SBOM is configured but all entries were filtered, regex would pick up
        # CVSS values from SBOM-unregistered entries in the raw text.
        for m in re.finditer(r"(?:cvss(?:v3)?[:\s]*)\s*(10(?:\.0)?|[0-9](?:\.[0-9])?)", lowered):
            try:
                scores.append(float(m.group(1)))
            except Exception:
                pass
        if not scores:
            # SIDfm一覧の "8.8 AlmaLinux ..." のような記法を拾う。
            for m in re.finditer(r"\b(10(?:\.0)?|[0-9]\.[0-9])\b", text):
                try:
                    value = float(m.group(1))
                    if 0.0 <= value <= 10.0:
                        scores.append(value)
                except Exception:
                    pass
    unique_scores = sorted(set(scores), reverse=True)
    max_score = unique_scores[0] if unique_scores else None
    logger.warning("[diag:facts] entry_scores=%r regex_fallback_used=%r max_score=%r selected_entries=%d",
                entry_scores, not entry_scores and not sbom_alma_versions, max_score, len(selected_entries))

    # Check is_public_resource tokens for diagnostic
    _pub_tokens = ("fortigate", "cisco asa", "zeem", "メールサーバ", "mail server", "公開サーバ", "公開リソース", "インターネット公開", "dmz", "almalinux 9", "almalinux9")
    _matched_pub = [t for t in _pub_tokens if t in lowered]
    logger.warning("[diag:facts] is_public_matched_tokens=%r", _matched_pub)

    if selected_due_date:
        due_date = selected_due_date
        first_reason = str((selected_entries[0] or {}).get("due_reason") or "").strip() if selected_entries else ""
        due_reason = first_reason or "社内方針に基づき算出"
    else:
        due_date, due_reason = _infer_due_date_from_policy(text, max_score)
    logger.warning("[diag:facts] final due_date=%r due_reason=%r", due_date, due_reason)
    return {
        "entries": selected_entries or entries,
        "all_entries_count": pre_filter_count,
        "selected_entries_count": len(selected_entries) if selected_entries else len(entries),
        "due_group_count": len(due_groups) if due_groups else 1,
        "products": products,
        "vuln_links": vuln_links[:20],
        "grouped_vuln_links": grouped_links_by_version,
        "scores": unique_scores[:10],
        "max_score": max_score,
        "due_date": due_date,
        "due_reason": due_reason,
        "sbom_alma_versions": sorted(sbom_alma_versions),
    }


def _merge_hypothesis_with_tool_facts(hypothesis: dict[str, Any], source_text: str) -> dict[str, Any]:
    facts = _extract_source_facts(source_text)
    if not hypothesis:
        return facts

    # Use AI interpretation as tentative signal, then keep tool-verified facts as source of truth.
    products = [str(p).strip() for p in (hypothesis.get("target_products") or []) if str(p).strip()]
    if products:
        normalized = []
        for p in products:
            if re.search(r"almalinux\s*[0-9]{1,2}", p, re.IGNORECASE):
                m = re.search(r"([0-9]{1,2})", p)
                if m:
                    normalized.append(f"AlmaLinux{m.group(1)}")
                    continue
            normalized.append(p)
        facts["products"] = list(dict.fromkeys(normalized))

    h_entries = hypothesis.get("entries") if isinstance(hypothesis.get("entries"), list) else []
    if h_entries:
        by_id = {str(e.get("id") or "").strip(): e for e in facts.get("entries", []) if str(e.get("id") or "").strip()}
        for he in h_entries:
            if not isinstance(he, dict):
                continue
            hid = str(he.get("id") or "").strip()
            if not hid or hid not in by_id:
                continue
            if str(by_id[hid].get("title") or "").strip() in ("", "要確認"):
                by_id[hid]["title"] = str(he.get("title") or "").strip() or by_id[hid]["title"]
        facts["entries"] = list(by_id.values())

    req_summary = str(hypothesis.get("request_summary") or "").strip()
    if req_summary and not _is_summary_low_quality(req_summary):
        facts["request_summary_ai"] = req_summary

    assumptions = hypothesis.get("assumptions")
    if isinstance(assumptions, list):
        facts["assumptions"] = [str(a).strip() for a in assumptions if str(a).strip()]
    return facts


def _audit_ticket_candidate(
    summary: str,
    detail: str,
    reasoning: str,
    facts: dict[str, Any] | None = None,
) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if not summary or _is_summary_low_quality(summary):
        errors.append("summary_low_quality")
    for line in ("【対象の機器/アプリ】", "【脆弱性情報】", "【CVSSスコア】", "【依頼内容】", "【対応完了目標】"):
        if line not in detail:
            errors.append(f"missing_section:{line}")
    urls = re.findall(r"https?://[^\s)>\]|]+", detail)
    if not urls:
        errors.append("missing_url")
    if any(not (u.startswith("https://sid.softek.jp/filter/sinfo/") or "nvd.nist.gov" in u) for u in urls):
        # permissive warning-style hardening
        errors.append("unexpected_url_domain")
    score_match = re.search(r"【CVSSスコア】\s*[\r\n]+([0-9](?:\.[0-9])?)", detail)
    if not score_match:
        errors.append("missing_cvss_numeric")
    else:
        try:
            v = float(score_match.group(1))
            if not (0.0 <= v <= 10.0):
                errors.append("cvss_out_of_range")
        except Exception:
            errors.append("cvss_parse_error")
    lowered = (summary + "\n" + detail + "\n" + reasoning).lower()
    for phrase in _TICKET_FORBIDDEN_PHRASES:
        if phrase.lower() in lowered:
            errors.append(f"forbidden_phrase:{phrase}")
    if isinstance(facts, dict):
        sbom_versions = [str(v).strip() for v in (facts.get("sbom_alma_versions") or []) if str(v).strip()]
        if len(sbom_versions) >= 2:
            alma_lines = re.findall(r"^AlmaLinux[0-9]{1,2}\s*$", detail, flags=re.MULTILINE)
            if len(set(alma_lines)) < 2:
                errors.append("missing_multiversion_target_lines")
            sid_urls = [u for u in urls if u.startswith("https://sid.softek.jp/filter/sinfo/")]
            if len(set(sid_urls)) < 2:
                errors.append("missing_multiversion_urls")
        all_entries_count = int(facts.get("all_entries_count") or 0)
        sid_links_count = len([u for u in (facts.get("vuln_links") or []) if str(u).startswith("https://sid.softek.jp/filter/sinfo/")])
        if all_entries_count == 0 and sid_links_count >= 2:
            errors.append("entry_extraction_inconsistent_with_links")
    return len(errors) == 0, errors


def _infer_ticket_detail_from_source(source_text: str) -> str:
    facts = _extract_source_facts(source_text)
    try:
        remediation_check = _check_remediation_advice(facts, source_text)
        if remediation_check.get("suggested_action"):
            facts["remediation_text"] = remediation_check["suggested_action"]
        if remediation_check.get("risk_notes"):
            facts["remediation_risk_notes"] = remediation_check["risk_notes"]
        if remediation_check.get("reasoning"):
            facts["remediation_reasoning"] = remediation_check["reasoning"]
    except Exception as exc:
        logger.warning("Remediation check in detail-from-source failed: %s", exc)
    return _infer_ticket_detail_from_facts(facts)


def _infer_ticket_detail_from_facts(facts: dict[str, Any]) -> str:
    product_line = "\n".join(facts["products"]) if facts["products"] else "要確認"
    links = facts["vuln_links"] or ["要確認"]
    grouped_links: dict[str, list[str]] = {}
    pre_grouped = facts.get("grouped_vuln_links")
    if isinstance(pre_grouped, dict):
        for k, vals in pre_grouped.items():
            key = str(k or "").strip()
            if not key:
                continue
            urls = [str(v).strip() for v in (vals or []) if str(v).strip()]
            if urls:
                grouped_links[key] = list(dict.fromkeys(urls))
    for e in facts.get("entries", []):
        title = str(e.get("title") or "")
        url = str(e.get("url") or "").strip()
        if not url:
            continue
        m = re.search(r"(AlmaLinux\s*[0-9]{1,2})", title, re.IGNORECASE)
        key = m.group(1).replace(" ", "") if m else ""
        if key:
            grouped_links.setdefault(key, [])
            if url not in grouped_links[key]:
                grouped_links[key].append(url)
    # SBOM適用版が複数ある場合でも、通知本文で言及されたバージョンのみを対象にする。
    # facts["products"] は通知本文のエントリから抽出されたもの。SBOMで全上書きしない。
    if grouped_links:
        def _sort_key(k: str) -> tuple[int, str]:
            m = re.search(r"([0-9]{1,2})$", k)
            return (-(int(m.group(1)) if m else -1), k.lower())

        parts: list[str] = []
        for key in sorted(grouped_links.keys(), key=_sort_key):
            parts.append(key)
            parts.extend(grouped_links[key])
            parts.append("")
        links_line = "\n".join(parts).strip()
    else:
        links_line = "\n".join(links)
    if facts["scores"]:
        max_score = facts["max_score"]
        cvss_line = f"{max_score:.1f}"
    else:
        cvss_line = "要確認"
    split_note = ""
    if int(facts.get("due_group_count") or 1) > 1:
        split_note = (
            "\n\n【備考】\n"
            "通知内で納期が異なる脆弱性が含まれるため、本起票は同一納期グループでまとめています。"
        )

    return (
        "【対象の機器/アプリ】\n"
        f"{product_line}\n\n"
        "【脆弱性情報】（リンク貼り付け）\n"
        f"{links_line}\n\n"
        "【CVSSスコア】\n"
        f"{cvss_line}\n\n"
        "【依頼内容】\n"
        f"{facts.get('remediation_text') or _DEFAULT_REMEDIATION_TEXT}\n\n"
        "【対応完了目標】\n"
        f"{facts.get('due_date') or '要確認'}"
        f"{split_note}"
    )


def _infer_reasoning_from_source(source_text: str) -> str:
    facts = _extract_source_facts(source_text)
    return _infer_reasoning_from_facts(facts)


def _infer_reasoning_from_facts(facts: dict[str, Any]) -> str:
    product_text = " / ".join(facts["products"]) if facts["products"] else "要確認"
    links_count = len(facts["vuln_links"])
    entries_count = len(facts.get("entries", []))
    all_entries_count = int(facts.get("all_entries_count") or entries_count)
    if facts["scores"]:
        scores_text = ", ".join(f"{s:.1f}" for s in facts["scores"])
    else:
        scores_text = "要確認"
    base = (
        "【判断理由】\n"
        f"- 通知本文から対象製品を抽出: {product_text}\n"
        f"- 通知本文から脆弱性エントリを抽出: {all_entries_count}件（起票対象: {entries_count}件）\n"
        f"- 参照URLを抽出: {links_count}件\n"
        f"- CVSSを抽出: {scores_text}\n"
        f"- SBOM照合で対象AlmaLinuxバージョンを適用: {', '.join(facts.get('sbom_alma_versions') or ['未適用'])}\n"
        f"- 対応完了目標を算出: {facts.get('due_date') or '要確認'}（{facts.get('due_reason') or '根拠不足'}）"
    )
    remediation_reasoning = str(facts.get("remediation_reasoning") or "").strip()
    remediation_risk = str(facts.get("remediation_risk_notes") or "").strip()
    if remediation_reasoning or remediation_risk:
        base += "\n\n【依頼内容チェック（AI）】"
        if remediation_reasoning:
            base += f"\n判定理由: {remediation_reasoning}"
        if remediation_risk:
            base += f"\n注意点: {remediation_risk}"
    return base


def _is_summary_low_quality(summary: str) -> bool:
    weak_summary_tokens = (
        "はい、承知",
        "承知いたしました",
        "ご依頼のメール内容",
        "判断しました",
        "以下に",
        "テンプレート",
        "作成します",
    )
    return (
        (not summary)
        or len(summary) < 10
        or any(token in summary for token in weak_summary_tokens)
        or ("脆弱性" not in summary and "ペネトレ" not in summary and "アップグレード" not in summary)
    )


def _repair_ticket_summary_if_needed(text: str, source_text: str = "") -> str:
    body = (text or "").strip()
    if not body:
        return body
    lines = body.splitlines()
    summary_idx = -1
    summary = ""
    for i, raw in enumerate(lines):
        line = raw.strip()
        if not line.startswith("依頼概要:"):
            continue
        summary_idx = i
        summary = line.split(":", 1)[1].strip()
        break
    if summary_idx < 0:
        return body

    needs_repair = _is_summary_low_quality(summary)
    if not needs_repair:
        return body

    repaired = _infer_request_summary_from_source(source_text)
    lines[summary_idx] = f"依頼概要: {repaired}"
    return "\n".join(lines).strip()


def _should_rebuild_ticket_text(body: str) -> bool:
    if "詳細: 要確認" in body:
        return True
    if "スレッド文脈が不足" in body and "要確認" in body:
        return True
    summary = ""
    for raw in body.splitlines():
        line = raw.strip()
        if line.startswith("依頼概要:"):
            summary = line.split(":", 1)[1].strip()
            break
    return _is_summary_low_quality(summary)


def _build_ticket_text_from_source(source_text: str) -> str:
    summary = _infer_request_summary_from_source(source_text)
    facts = _extract_source_facts(source_text)
    # AI check: validate remediation advice
    remediation_check = _check_remediation_advice(facts, source_text)
    if remediation_check.get("suggested_action"):
        facts["remediation_text"] = remediation_check["suggested_action"]
    if remediation_check.get("risk_notes"):
        facts["remediation_risk_notes"] = remediation_check["risk_notes"]
    if remediation_check.get("reasoning"):
        facts["remediation_reasoning"] = remediation_check["reasoning"]
    detail = _infer_ticket_detail_from_facts(facts)
    reasoning = _infer_reasoning_from_facts(facts)
    return _build_ticket_text_from_parts(summary, detail, reasoning)



# ====================================================
# Phase 2: 修正学習システム
# ====================================================

_TICKET_SECTION_MARKERS = (
    "【対象の機器/アプリ】",
    "【脆弱性情報】",
    "【CVSSスコア】",
    "【依頼内容】",
    "【対応完了目標】",
    "【備考】",
)
_TICKET_FIELD_MAP = {
    "【対象の機器/アプリ】": "target_devices",
    "【脆弱性情報】": "vuln_links",
    "【CVSSスコア】": "cvss_score",
    "【依頼内容】": "remediation_text",
    "【対応完了目標】": "due_date",
    "【備考】": "notes",
}


def _split_ticket_into_sections(ticket_text: str) -> dict[str, str]:
    """起票テンプレートをセクションマーカーで分割し、{field_name: value} のdictを返す。"""
    result: dict[str, str] = {}
    body = (ticket_text or "").strip()
    if not body:
        return result
    # 主要セクション以外（大分類、小分類、依頼概要）
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("依頼概要:"):
            result["request_summary"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("大分類:"):
            result["category_major"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("小分類:"):
            result["category_minor"] = stripped.split(":", 1)[1].strip()
    # セクションマーカーで分割
    all_markers = list(_TICKET_SECTION_MARKERS)
    all_markers.extend(["【判断理由】", "【管理ID】"])
    positions: list[tuple[int, str]] = []
    for marker in all_markers:
        idx = body.find(marker)
        if idx >= 0:
            positions.append((idx, marker))
    positions.sort(key=lambda x: x[0])
    for i, (pos, marker) in enumerate(positions):
        end = positions[i + 1][0] if i + 1 < len(positions) else len(body)
        content = body[pos + len(marker):end].strip()
        # マーカーの括弧注釈を除去（例:「（リンク貼り付け）」）
        content = re.sub(r"^（[^）]*）\s*", "", content).strip()
        field = _TICKET_FIELD_MAP.get(marker, marker)
        result[field] = content
    return result


_CORRECTION_DETECT_FIELDS = (
    "remediation_text", "due_date", "target_devices", "cvss_score",
    "request_summary", "vuln_links", "notes",
    "category_major", "category_minor",
)


def _detect_correction_fields(original: str, revised: str, instruction: str) -> list[tuple[str, str, str]]:
    """修正前後のチケットを比較し、変更があった全フィールドを [(field_name, original_value, new_value), ...] で返す。"""
    orig_sections = _split_ticket_into_sections(original)
    rev_sections = _split_ticket_into_sections(revised)
    changes: list[tuple[str, str, str]] = []
    for field in _CORRECTION_DETECT_FIELDS:
        orig_val = orig_sections.get(field, "")
        rev_val = rev_sections.get(field, "")
        if orig_val != rev_val and rev_val:
            changes.append((field, orig_val, rev_val))
    return changes


def _detect_correction_field(original: str, revised: str, instruction: str) -> tuple[str, str, str]:
    """修正前後のチケットを比較し、最初に検出された (field_name, original_value, new_value) を返す。"""
    changes = _detect_correction_fields(original, revised, instruction)
    if changes:
        return changes[0]
    return "", "", ""


def _determine_pattern_key(field_name: str, source_text: str = "", facts: dict[str, Any] | None = None) -> str:
    """修正フィールドに応じたパターンキーを決定する。"""
    if not field_name:
        return "*"
    if field_name == "due_date" and facts:
        max_score = facts.get("max_score")
        if isinstance(max_score, (int, float)):
            if max_score >= 9.0:
                return "cvss>=9.0"
            if max_score >= 7.0:
                return "cvss>=7.0"
    if field_name in ("remediation_text", "target_devices"):
        # 製品名を検出
        source = source_text or ""
        for product in ("AlmaLinux", "CentOS", "Ubuntu", "Windows", "Apache", "nginx"):
            if product.lower() in source.lower():
                return product
    return "*"


def _save_ticket_preference(
    space_id: str, field_name: str, pattern_key: str,
    preferred_value: str, original_value: str, created_by: str,
) -> None:
    """修正内容をBQのticket_preferencesテーブルに保存。同一レコードがあればcorrection_countをインクリメント。"""
    table_id = _get_config("BQ_PREFERENCES_TABLE_ID", "vuln-agent-bq-preferences-table-id", "").strip()
    if not table_id or not space_id or not field_name:
        return
    try:
        from google.cloud import bigquery

        project_id = _get_project_id() or None
        client = bigquery.Client(project=project_id)
        # 既存レコードを検索
        query = f"""
            SELECT preference_id, correction_count
            FROM `{table_id}`
            WHERE space_id = @space_id
              AND field_name = @field_name
              AND pattern_key = @pattern_key
            ORDER BY updated_at DESC
            LIMIT 1
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("space_id", "STRING", space_id),
                bigquery.ScalarQueryParameter("field_name", "STRING", field_name),
                bigquery.ScalarQueryParameter("pattern_key", "STRING", pattern_key),
            ]
        )
        rows = list(client.query(query, job_config=job_config).result())
        now = datetime.now(timezone.utc).isoformat()
        if rows:
            # 既存レコードをUPDATE（correction_countインクリメント）
            existing = rows[0]
            pref_id = str(getattr(existing, "preference_id", ""))
            count = int(getattr(existing, "correction_count", 0) or 0) + 1
            update_query = f"""
                UPDATE `{table_id}`
                SET preferred_value = @preferred_value,
                    original_value = @original_value,
                    correction_count = @correction_count,
                    updated_at = @updated_at
                WHERE preference_id = @preference_id
            """
            update_config = bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ScalarQueryParameter("preferred_value", "STRING", preferred_value),
                    bigquery.ScalarQueryParameter("original_value", "STRING", original_value),
                    bigquery.ScalarQueryParameter("correction_count", "INT64", count),
                    bigquery.ScalarQueryParameter("updated_at", "TIMESTAMP", now),
                    bigquery.ScalarQueryParameter("preference_id", "STRING", pref_id),
                ]
            )
            client.query(update_query, job_config=update_config).result()
        else:
            # 新規レコードをINSERT
            row = {
                "preference_id": str(uuid.uuid4()),
                "space_id": space_id,
                "field_name": field_name,
                "pattern_key": pattern_key,
                "preferred_value": preferred_value,
                "original_value": original_value,
                "correction_count": 1,
                "created_at": now,
                "updated_at": now,
                "created_by": created_by or "",
                "extra": "{}",
            }
            errors = client.insert_rows_json(table_id, [row])
            if errors:
                logger.warning("Failed to insert ticket preference: %s", errors)
    except Exception as exc:
        logger.warning("_save_ticket_preference failed: %s", exc)


def _save_correction_as_preference(
    event: dict[str, Any], original_ticket: str, revised_ticket: str, instruction: str,
) -> None:
    """修正成功時に自動的に学習データとしてBQに保存する。全変更フィールドを保存。"""
    changes = _detect_correction_fields(original_ticket, revised_ticket, instruction)
    if not changes:
        return
    message = event.get("message") or {}
    thread_name = str(((message.get("thread") or {}).get("name") or "")).strip()
    space_id = _extract_space_name(event, thread_name)
    if not space_id:
        return
    user_name = str((event.get("user") or {}).get("name") or "")
    for field_name, original_value, new_value in changes:
        pattern_key = _determine_pattern_key(field_name)
        _save_ticket_preference(
            space_id=space_id,
            field_name=field_name,
            pattern_key=pattern_key,
            preferred_value=new_value,
            original_value=original_value,
            created_by=user_name,
        )


# ====================================================
# Phase 3: 学習済みプリファレンスの適用
# ====================================================

_PREFERENCE_STRONG_THRESHOLD = 3  # correction_count >= 3 でAI上書きしない


def _fetch_ticket_preferences(
    event: dict[str, Any], product_names: list[str] | None = None, cvss_score: float | None = None,
) -> dict[str, str]:
    """空間ごとの学習済みプリファレンスをBQから取得し、{field_name: preferred_value} を返す。"""
    table_id = _get_config("BQ_PREFERENCES_TABLE_ID", "vuln-agent-bq-preferences-table-id", "").strip()
    if not table_id:
        return {}
    message = event.get("message") or {}
    thread_name = str(((message.get("thread") or {}).get("name") or "")).strip()
    space_id = _extract_space_name(event, thread_name)
    if not space_id:
        return {}
    try:
        from google.cloud import bigquery

        project_id = _get_project_id() or None
        client = bigquery.Client(project=project_id)
        query = f"""
            SELECT field_name, pattern_key, preferred_value, correction_count
            FROM `{table_id}`
            WHERE space_id = @space_id
            ORDER BY correction_count DESC, updated_at DESC
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("space_id", "STRING", space_id),
            ]
        )
        rows = list(client.query(query, job_config=job_config).result())
        if not rows:
            return {}

        # パターンキーのマッチング: 具体的なもの優先、次に "*"
        candidate_patterns: list[str] = ["*"]
        for p in (product_names or []):
            candidate_patterns.append(p)
        if isinstance(cvss_score, (int, float)):
            if cvss_score >= 9.0:
                candidate_patterns.append("cvss>=9.0")
            if cvss_score >= 7.0:
                candidate_patterns.append("cvss>=7.0")

        result: dict[str, str] = {}
        result_counts: dict[str, int] = {}
        for row in rows:
            field = str(getattr(row, "field_name", "") or "").strip()
            pattern = str(getattr(row, "pattern_key", "") or "").strip()
            value = str(getattr(row, "preferred_value", "") or "").strip()
            count = int(getattr(row, "correction_count", 0) or 0)
            if not field or not value:
                continue
            if pattern not in candidate_patterns:
                continue
            # 具体的なパターンを優先（"*" より製品名等を優先）
            existing_count = result_counts.get(field, -1)
            is_more_specific = pattern != "*" and result.get(field) and result_counts.get(field, 0) <= count
            is_first = field not in result
            is_higher_count = count > existing_count
            if is_first or is_more_specific or (pattern != "*" and is_higher_count):
                result[field] = value
                result_counts[field] = count
        return result
    except Exception as exc:
        logger.warning("_fetch_ticket_preferences failed: %s", exc)
        return {}


def _apply_preferences_to_facts(
    facts: dict[str, Any], preferences: dict[str, str],
) -> dict[str, Any]:
    """学習済みプリファレンスをmerged_factsに適用する。"""
    if not preferences:
        return facts
    field_to_fact_key = {
        "remediation_text": "remediation_text",
        "due_date": "due_date",
        "target_devices": "products",
    }
    for field, value in preferences.items():
        fact_key = field_to_fact_key.get(field)
        if not fact_key:
            continue
        if fact_key == "products" and value:
            # products はリスト型
            facts[fact_key] = [v.strip() for v in value.split("\n") if v.strip()]
        else:
            facts[fact_key] = value
    return facts


def _get_preference_correction_counts(
    event: dict[str, Any],
) -> dict[str, int]:
    """各フィールドのcorrection_countを返す。"""
    table_id = _get_config("BQ_PREFERENCES_TABLE_ID", "vuln-agent-bq-preferences-table-id", "").strip()
    if not table_id:
        return {}
    message = event.get("message") or {}
    thread_name = str(((message.get("thread") or {}).get("name") or "")).strip()
    space_id = _extract_space_name(event, thread_name)
    if not space_id:
        return {}
    try:
        from google.cloud import bigquery

        project_id = _get_project_id() or None
        client = bigquery.Client(project=project_id)
        query = f"""
            SELECT field_name, MAX(correction_count) AS max_count
            FROM `{table_id}`
            WHERE space_id = @space_id
            GROUP BY field_name
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("space_id", "STRING", space_id),
            ]
        )
        rows = list(client.query(query, job_config=job_config).result())
        return {
            str(getattr(r, "field_name", "")): int(getattr(r, "max_count", 0) or 0)
            for r in rows
        }
    except Exception as exc:
        logger.warning("_get_preference_correction_counts failed: %s", exc)
        return {}


def _build_ticket_text_from_parts(summary: str, detail: str, reasoning: str) -> str:
    return (
        "【起票用（コピペ）】\n"
        "大分類: 017.脆弱性対応（情シス専用）\n"
        "小分類: 002.IT基盤チーム\n"
        f"依頼概要: {summary}\n"
        f"詳細:\n{detail}\n\n"
        f"{reasoning}"
    ).strip()


def _ai_final_review_with_value_lock(summary: str, detail: str, reasoning: str, history_key: str) -> str:
    base_text = _build_ticket_text_from_parts(summary, detail, reasoning)
    prompt = (
        "以下の起票文を、値を変えずに可読性だけ改善してください。"
        "禁止: 値改変・項目追加削除。許可: 改行や句読点の軽微調整のみ。\n\n"
        f"{base_text}"
    )
    reviewed = _run_agent_query(prompt, history_key)
    normalized = _format_ticket_like_response(reviewed, detail)
    if "【起票用（コピペ）】" not in normalized or "【判断理由】" not in normalized:
        return base_text
    # value-lock check
    required_tokens = [f"依頼概要: {summary}", "大分類: 017.脆弱性対応（情シス専用）", "小分類: 002.IT基盤チーム"]
    if any(tok not in normalized for tok in required_tokens):
        return base_text
    # Verify key numeric/date values are preserved by AI review
    base_cvss = re.search(r"【CVSSスコア】\s*[\r\n]+([0-9](?:\.[0-9])?)", base_text)
    norm_cvss = re.search(r"【CVSSスコア】\s*[\r\n]+([0-9](?:\.[0-9])?)", normalized)
    if base_cvss and (not norm_cvss or norm_cvss.group(1) != base_cvss.group(1)):
        return base_text
    base_due = re.search(r"【対応完了目標】\s*[\r\n]*(.+)", base_text)
    norm_due = re.search(r"【対応完了目標】\s*[\r\n]*(.+)", normalized)
    if base_due and (not norm_due or norm_due.group(1).strip() != base_due.group(1).strip()):
        return base_text
    base_urls = set(re.findall(r"https://sid\.softek\.jp/filter/sinfo/\d+", base_text))
    norm_urls = set(re.findall(r"https://sid\.softek\.jp/filter/sinfo/\d+", normalized))
    if base_urls and base_urls != norm_urls:
        return base_text
    # Lock the reasoning section — AI review must not change structured facts
    base_reason_match = re.search(r"【判断理由】[\s\S]*$", base_text)
    norm_reason_match = re.search(r"【判断理由】[\s\S]*$", normalized)
    if base_reason_match:
        if not norm_reason_match or norm_reason_match.group(0).strip() != base_reason_match.group(0).strip():
            return base_text
    return normalized


def _format_ticket_like_response(text: str, source_text: str = "") -> str:
    body = (text or "").strip()
    if not body:
        return body
    if _looks_like_internal_artifact(body):
        return _build_low_quality_ticket_message()
    has_copy = "【起票用（コピペ）】" in body
    has_reason = "【判断理由】" in body
    if has_copy and has_reason:
        repaired = _repair_ticket_summary_if_needed(body, source_text)
        if _should_rebuild_ticket_text(repaired):
            return _build_ticket_text_from_source(source_text)
        return repaired

    lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
    noise_prefixes = ("```", "###", "|", ":---", "---")
    summary_candidates = [
        ln for ln in lines if not ln.startswith(noise_prefixes) and not _looks_like_internal_artifact(ln)
    ]
    summary = " / ".join(summary_candidates[:3]) if summary_candidates else ""
    summary = re.sub(r"\s+", " ", summary).strip()[:220]
    if _is_summary_low_quality(summary):
        return _build_ticket_text_from_source(source_text)

    detail = _infer_ticket_detail_from_source(source_text)
    reasoning = _infer_reasoning_from_source(source_text)
    return (
        "【起票用（コピペ）】\n"
        "大分類: 017.脆弱性対応（情シス専用）\n"
        "小分類: 002.IT基盤チーム\n"
        f"依頼概要: {summary}\n"
        f"詳細:\n{detail}\n\n"
        f"{reasoning}"
    ).strip()


def _handle_paste_back_revision(
    event: dict[str, Any], pasted_text: str, history_key: str,
) -> str:
    """ユーザーがコピペ修正したチケットテンプレートを受け取り、新版として保存する。

    ユーザーの修正フロー:
    1. ボットが出力したチケットテンプレートをコピー
    2. チャット入力欄に貼り付けて直接テキストを編集
    3. 送信 → この関数で受け取る

    Returns:
        確認メッセージ文字列。
    """
    # BQ履歴から直前のチケットを取得（差分検出用）
    previous_ticket = ""
    try:
        bq_record = _fetch_latest_ticket_record_from_history(event)
        bq_copy = str(bq_record.get("copy_paste_text") or "")
        bq_reason = str(bq_record.get("reasoning_text") or "")
        if bq_copy:
            previous_ticket = bq_copy
            if bq_reason:
                previous_ticket += "\n\n" + bq_reason
    except Exception as exc:
        logger.warning("paste_back: failed to fetch previous ticket: %s", exc)

    # 修正後チケットをBQ履歴に保存
    try:
        _save_ticket_record_to_history(event, pasted_text, source="human_review")
    except Exception as exc:
        logger.warning("paste_back: failed to save revised ticket: %s", exc)

    # 修正差分を学習データとして保存
    if previous_ticket:
        try:
            _save_correction_as_preference(event, previous_ticket, pasted_text, "ユーザー直接編集")
        except Exception as exc:
            logger.warning("paste_back: failed to save correction preference: %s", exc)

    _remember_turn(history_key, pasted_text, "（修正版チケットを受領しました）")

    return (
        "修正版チケットを受領しました。以下の内容で更新済みです。\n\n"
        "━━━━━━━━━━━━━━━\n"
        f"{pasted_text}\n"
        "━━━━━━━━━━━━━━━\n\n"
        "さらに修正が必要な場合は、上記をコピーして編集のうえ再送信してください。"
    )


def _process_message_event(event: dict[str, Any], user_name: str) -> str | None:
    raw_text = str(((event.get("message") or {}).get("text") or "")).strip()
    prompt = _clean_chat_text(event)
    is_gmail_post = _is_gmail_app_message(event)
    history_key = _context_key(event, user_name)
    prefer_ticket_format = False
    save_ticket_history = False
    manual_backfill_mode = False
    intent = ""
    raw_body_text = _strip_mentions_preserve_lines(raw_text)
    source_text_for_quality = ""
    root_text = _fetch_thread_root_message_text(event)
    if not root_text:
        root_text = _get_cached_thread_root_text(event)
    recent_turns = _get_recent_turns(history_key, max_turns=3)

    # ---- paste-back検出: ユーザーがチケットテンプレートをコピペ編集して再送信 ----
    if not is_gmail_post and "【起票用（コピペ）】" in raw_body_text:
        logger.info("paste_back: detected user-edited ticket template in message")
        return _handle_paste_back_revision(event, raw_body_text, history_key)

    if is_gmail_post:
        message_payload_text = _extract_message_text_payload((event.get("message") or {}))
        source_text_for_quality = message_payload_text or raw_text
        _remember_thread_root_text(event, source_text_for_quality)
        prefer_ticket_format = True
        save_ticket_history = True
    elif not prompt:
        return None
    else:
        intent_plan = _run_ai_intent_planner(
            user_prompt=prompt,
            raw_body_text=raw_body_text,
            root_text=root_text,
            recent_turns=recent_turns,
            is_gmail_post=is_gmail_post,
            history_key=history_key,
        )
        intent = str(intent_plan.get("intent") or "").strip()
        logger.info(
            "ai_intent_plan intent=%s ticket=%s root=%s history=%s confidence=%s reason=%s",
            intent,
            bool(intent_plan.get("needs_ticket_format")),
            bool(intent_plan.get("prefer_thread_root")),
            bool(intent_plan.get("prefer_history")),
            str(intent_plan.get("confidence") or ""),
            str(intent_plan.get("reason") or ""),
        )
        if intent == "clarification":
            return _build_clarification_message()
        if bool(intent_plan.get("needs_ticket_format")) or intent == "ticket_generate":
            prefer_ticket_format = True
            save_ticket_history = True
            if _contains_manual_ticket_trigger(raw_body_text):
                manual_backfill_mode = True
            # 1) user provided body
            candidate_source = _resolve_manual_backfill_source_text(event, raw_body_text)
            # 2) thread root
            if not candidate_source and bool(intent_plan.get("prefer_thread_root")):
                candidate_source = root_text
            # 3) history fallback
            if not candidate_source and bool(intent_plan.get("prefer_history")):
                history_ticket = _fetch_latest_ticket_record_from_history(event)
                history_message = _build_history_ticket_message(history_ticket)
                if history_message:
                    candidate_source = history_message
            source_text_for_quality = candidate_source
            if source_text_for_quality:
                _remember_thread_root_text(event, source_text_for_quality)
            else:
                return _build_backfill_guidance_message()
        else:
            if _is_ambiguous_prompt(prompt) and recent_turns:
                prompt = _build_contextual_prompt(prompt, recent_turns)
            elif _is_ambiguous_prompt(prompt) and not recent_turns:
                return _build_clarification_message()

    if prefer_ticket_format:
        # SBOMフィルタリング: 最初に製品をチェックし、未登録なら即スキップ
        sbom_should_skip, sbom_detected_products, sbom_reason = _check_sbom_registration(source_text_for_quality)
        if sbom_should_skip:
            response_text = _build_sbom_not_registered_message(sbom_detected_products, sbom_reason)
            _remember_turn(history_key, _clean_chat_text(event), response_text)
            return response_text

        # メッセージフォーマット分類: 【悪用された脆弱性】は専用フローへ
        msg_format = _classify_message_format(source_text_for_quality)
        if msg_format == _MSG_FORMAT_EXPLOITED:
            analysis = _analyze_exploited_vuln(source_text_for_quality)
            if not analysis:
                # Gemini障害時は安全側（確認依頼）にフォールバック
                response_text = (
                    "⚠ 悪用が確認された脆弱性の通知です（AI分析が利用できませんでした）。\n"
                    "内容を確認の上、速やかにアップデートの要否を判断してください。"
                )
            elif analysis.get("is_windows_or_apple"):
                response_text = _build_exploited_update_message(analysis)
            else:
                response_text = _build_exploited_not_target_message(analysis)
            _remember_turn(history_key, _clean_chat_text(event), response_text)
            return response_text

        if is_gmail_post and not _contains_specific_vuln_signal(source_text_for_quality):
            return _build_low_quality_ticket_message()

        hypothesis_instruction = ""
        if manual_backfill_mode and prompt:
            hypothesis_instruction = prompt

        hypothesis = _run_hypothesis_pipeline(source_text_for_quality, history_key, user_instruction=hypothesis_instruction)
        merged_facts = _merge_hypothesis_with_tool_facts(hypothesis, source_text_for_quality)

        # --- 学習済みプリファレンスの適用 ---
        preference_counts: dict[str, int] = {}
        try:
            product_names = merged_facts.get("products") or []
            max_score = merged_facts.get("max_score")
            preferences = _fetch_ticket_preferences(event, product_names, max_score)
            if preferences:
                merged_facts = _apply_preferences_to_facts(merged_facts, preferences)
                preference_counts = _get_preference_correction_counts(event)
                logger.info("Applied %d ticket preferences from learning system", len(preferences))
        except Exception as exc:
            logger.warning("Preference application failed: %s", exc)

        # --- 【依頼内容】AIチェック ---
        try:
            remediation_check = _check_remediation_advice(merged_facts, source_text_for_quality)
            # correction_count >= 3 のプリファレンスはAI上書きしない
            remediation_locked = preference_counts.get("remediation_text", 0) >= _PREFERENCE_STRONG_THRESHOLD
            if not remediation_locked:
                if remediation_check.get("suggested_action"):
                    merged_facts["remediation_text"] = remediation_check["suggested_action"]
            if remediation_check.get("risk_notes"):
                merged_facts["remediation_risk_notes"] = remediation_check["risk_notes"]
            if remediation_check.get("reasoning"):
                merged_facts["remediation_reasoning"] = remediation_check["reasoning"]
        except Exception as exc:
            logger.warning("Remediation check in main flow failed: %s", exc)

        if manual_backfill_mode and not merged_facts.get("entries") and not _contains_specific_vuln_signal(source_text_for_quality):
            return _build_backfill_guidance_message()

        summary = str(merged_facts.get("request_summary_ai") or _infer_request_summary_from_source(source_text_for_quality)).strip()
        detail = _infer_ticket_detail_from_facts(merged_facts)
        reasoning = _infer_reasoning_from_facts(merged_facts)
        ok, audit_errors = _audit_ticket_candidate(summary, detail, reasoning, facts=merged_facts)
        if not ok:
            logger.warning("Ticket audit failed, fallback to source-derived fixed output: %s", ", ".join(audit_errors))
            response_text = _build_ticket_text_from_source(source_text_for_quality)
        else:
            response_text = _ai_final_review_with_value_lock(summary, detail, reasoning, history_key)

        if manual_backfill_mode and not _is_manual_ticket_output_usable(response_text):
            response_text = _build_ticket_text_from_source(source_text_for_quality)
        if save_ticket_history:
            _save_ticket_record_to_history(
                event,
                response_text,
                source="chat_webhook_manual" if manual_backfill_mode else "chat_alert",
            )
    else:
        response_text = _run_agent_query_with_reflection(prompt, history_key)
        if _looks_like_ticket_template_output(response_text):
            # どの経路でも、起票テンプレート風の回答は固定フォーマットへ正規化する。
            source_for_format = source_text_for_quality or _get_cached_thread_root_text(event)
            response_text = _format_ticket_like_response(response_text, source_for_format)
    _remember_turn(history_key, _clean_chat_text(event), response_text)
    return response_text


def _run_async_message_processing(event: dict[str, Any], user_name: str) -> None:
    try:
        text = _process_message_event(event, user_name)
        if not text:
            return
        _send_message_to_thread(event, text)
    except Exception as exc:
        logger.exception("Failed async chat processing: %s", exc)
        try:
            _send_message_to_thread(event, f"処理中にエラーが発生しました: {exc}")
        except Exception:
            pass


@functions_framework.http
def handle_chat_event(request):
    try:
        event = request.get_json(silent=True) or {}
    except Exception:
        event = {}

    if not event:
        return json.dumps({"text": "Invalid request"}), 400, {"Content-Type": "application/json"}

    if _is_cloud_tasks_request(request, event):
        chat_event = event.get("chat_event") if isinstance(event.get("chat_event"), dict) else {}
        user_name = str(event.get("user_name") or "google-chat-user")
        if not chat_event:
            return json.dumps({"status": "ignored", "reason": "missing chat_event"}, ensure_ascii=False), 200, {
                "Content-Type": "application/json"
            }
        try:
            response_text = _process_message_event(chat_event, user_name)
            if response_text:
                _send_message_to_thread(chat_event, response_text)
            return json.dumps({"status": "ok"}, ensure_ascii=False), 200, {"Content-Type": "application/json"}
        except Exception as exc:
            logger.exception("Failed to process Cloud Tasks async request: %s", exc)
            try:
                _send_message_to_thread(chat_event, f"処理中にエラーが発生しました: {exc}")
            except Exception:
                pass
            return json.dumps({"status": "error"}, ensure_ascii=False), 200, {"Content-Type": "application/json"}

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

    if _is_async_response_enabled():
        if not _is_message_actionable(event):
            return json.dumps({}, ensure_ascii=False), 200, {"Content-Type": "application/json"}
        if not _register_async_event_once(event):
            return json.dumps({}, ensure_ascii=False), 200, {"Content-Type": "application/json"}
        try:
            _send_message_to_thread(event, "思考中です。分析が完了したらこのスレッドに結果を送信します。")
        except Exception as exc:
            logger.warning("Failed to send thinking message: %s", exc)
        _submit_async_job(event, user_name)
        return json.dumps({}, ensure_ascii=False), 200, {"Content-Type": "application/json"}

    try:
        response_text = _process_message_event(event, user_name)
        if response_text is None:
            return json.dumps({}, ensure_ascii=False), 200, {"Content-Type": "application/json"}
        return json.dumps(_thread_payload(event, response_text), ensure_ascii=False), 200, {
            "Content-Type": "application/json"
        }
    except Exception as exc:
        logger.exception("Failed to handle chat event: %s", exc)
        return json.dumps(
            _thread_payload(event, f"処理中にエラーが発生しました: {exc}"),
            ensure_ascii=False,
        ), 200, {"Content-Type": "application/json"}
