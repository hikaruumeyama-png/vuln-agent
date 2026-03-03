"""
ガードレールコールバック - ADKエージェント用バリデーション

ツール実行の前後で入力・出力を検証し、警告やブロックを行うコールバック群。
ADK Agent の before_tool_callback / after_tool_callback として登録する。
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 型ヒント用（ADK の実型はランタイムで解決）
# ---------------------------------------------------------------------------
# google.adk.tools.BaseTool / google.adk.tools.ToolContext を直接 import すると
# Agent Engine 以外の環境で ImportError になる場合があるため、TYPE_CHECKING で保護する。
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from google.adk.tools import BaseTool, ToolContext


# ===========================================================================
# Callback 1: validate_alert_after_send (after_tool)
# ===========================================================================

def validate_alert_after_send(
    tool: "BaseTool",
    args: dict[str, Any],
    tool_context: "ToolContext",
    tool_response: dict,
) -> Optional[dict]:
    """send_vulnerability_alert の実行後にレスポンスを検証する。

    検証項目:
      - owners 引数が空でないか
      - cvss_score と severity の整合性
      - affected_systems が空または「不明」のみでないか

    警告がある場合は tool_response["guardrail_warnings"] に追加して返す。
    警告がなければ None を返し、元のレスポンスを維持する。
    """
    if tool.name != "send_vulnerability_alert":
        return None

    warnings: list[str] = []

    # --- owners が未指定 ---
    owners = args.get("owners")
    if not owners:
        warnings.append("WARN: No owners specified")
        logger.warning("ガードレール: send_vulnerability_alert で owners が未指定です")

    # --- CVSS と severity の整合性チェック ---
    cvss_score = args.get("cvss_score")
    severity = args.get("severity", "")
    if cvss_score is not None:
        try:
            score = float(cvss_score)
            if score >= 9.0 and severity != "緊急":
                warnings.append(
                    f"WARN: CVSS {score} は緊急相当ですが severity='{severity}' です"
                )
                logger.warning(
                    "ガードレール: CVSS %.1f >= 9.0 だが severity='%s' (期待: 緊急)",
                    score, severity,
                )
            if score >= 7.0 and severity in ("低", "中"):
                warnings.append(
                    f"WARN: CVSS {score} に対して severity='{severity}' は低すぎます"
                )
                logger.warning(
                    "ガードレール: CVSS %.1f >= 7.0 だが severity='%s' (低/中は不整合)",
                    score, severity,
                )
        except (TypeError, ValueError):
            pass

    # --- affected_systems が空 or 「不明」のみ ---
    affected_systems = args.get("affected_systems") or []
    if not affected_systems or affected_systems == ["不明"]:
        warnings.append("WARN: affected_systems が空または不明のみです")
        logger.warning("ガードレール: affected_systems が空または不明のみ")

    if not warnings:
        return None

    tool_response["guardrail_warnings"] = warnings
    return tool_response


# ===========================================================================
# Callback 2: validate_sbom_search_result (after_tool)
# ===========================================================================

_SBOM_ERROR_INDICATORS = ("未設定", "失敗", "エラー")

def validate_sbom_search_result(
    tool: "BaseTool",
    args: dict[str, Any],
    tool_context: "ToolContext",
    tool_response: dict,
) -> Optional[dict]:
    """search_sbom_by_product / search_sbom_by_purl の実行後にレスポンスを検証する。

    検証項目:
      - total_count == 0 かつ message にエラー指標がある → データソース障害の可能性
      - total_count == 0 でエラーなし → マッチなし情報
      - 全 matched_entries の owner_email が空 → 担当者マッピング欠落の警告

    警告がある場合は tool_response["guardrail_warnings"] に追加して返す。
    """
    if tool.name not in ("search_sbom_by_product", "search_sbom_by_purl"):
        return None

    warnings: list[str] = []
    total_count = tool_response.get("total_count", 0)
    message = str(tool_response.get("message", ""))

    if total_count == 0:
        # エラー指標がメッセージに含まれるか確認
        if any(indicator in message for indicator in _SBOM_ERROR_INDICATORS):
            warnings.append(
                f"WARN: データソース障害の可能性があります (message: {message})"
            )
            logger.warning(
                "ガードレール: SBOM検索結果0件 + エラー指標検出: %s", message,
            )
        else:
            warnings.append("INFO: 検索条件に一致するSBOMエントリはありませんでした")
            logger.info("ガードレール: SBOM検索結果0件 (正常)")

    # --- 全エントリの owner_email が空 ---
    matched_entries = tool_response.get("matched_entries") or []
    if matched_entries and all(
        not entry.get("owner_email") for entry in matched_entries
    ):
        warnings.append(
            "WARN: 全マッチエントリの owner_email が空です。担当者マッピングを確認してください"
        )
        logger.warning(
            "ガードレール: %d件のマッチエントリ全てで owner_email が未設定",
            len(matched_entries),
        )

    if not warnings:
        return None

    tool_response["guardrail_warnings"] = warnings
    return tool_response


# ===========================================================================
# Callback 3: validate_a2a_request (before_tool)
# ===========================================================================

_A2A_TOOL_NAMES = frozenset({
    "call_remote_agent",
    "call_remote_agent_conversation_loop",
    "call_master_agent",
})

def validate_a2a_request(
    tool: "BaseTool",
    args: dict[str, Any],
    tool_context: "ToolContext",
) -> Optional[dict]:
    """A2A連携ツール呼び出し前に入力を検証する。

    検証項目:
      - message / initial_message / objective が空でないか
      - message / initial_message / objective が10文字未満でないか
      - call_remote_agent の場合、agent_id が空でないか

    問題がある場合はエラー dict を返してツール実行をブロックする。
    問題がなければ None を返して実行を許可する。
    """
    if tool.name not in _A2A_TOOL_NAMES:
        return None

    # --- メッセージフィールドの特定 ---
    # call_remote_agent: message
    # call_remote_agent_conversation_loop: initial_message
    # call_master_agent: objective
    if tool.name == "call_master_agent":
        message_key = "objective"
    elif tool.name == "call_remote_agent_conversation_loop":
        message_key = "initial_message"
    else:
        message_key = "message"

    message_value = str(args.get(message_key) or "").strip()

    # --- メッセージが空 ---
    if not message_value:
        logger.error(
            "ガードレール: %s の %s が空のためブロックしました", tool.name, message_key,
        )
        return {
            "status": "error",
            "message": f"{message_key} は必須です。空のメッセージでA2A呼び出しはできません。",
        }

    # --- メッセージが短すぎる ---
    if len(message_value) < 10:
        logger.error(
            "ガードレール: %s の %s が短すぎます (%d文字)",
            tool.name, message_key, len(message_value),
        )
        return {
            "status": "error",
            "message": (
                f"{message_key} が短すぎます ({len(message_value)}文字)。"
                "A2A連携には具体的な指示が必要です（10文字以上）。"
            ),
        }

    # --- call_remote_agent / call_remote_agent_conversation_loop: agent_id チェック ---
    if tool.name in ("call_remote_agent", "call_remote_agent_conversation_loop"):
        agent_id = str(args.get("agent_id") or "").strip()
        if not agent_id:
            logger.error(
                "ガードレール: %s の agent_id が空のためブロックしました", tool.name,
            )
            return {
                "status": "error",
                "message": "agent_id は必須です。呼び出し先エージェントを指定してください。",
            }

    return None


# ===========================================================================
# Callback 4: validate_bigquery_query (before_tool)
# ===========================================================================

# BigQuery Scripting / DDL構文の追加禁止パターン
_BQ_DANGEROUS_PATTERNS = re.compile(
    r"\b(BEGIN|DECLARE|EXECUTE\s+IMMEDIATE|CALL|CREATE\s+TEMP|CREATE\s+OR\s+REPLACE|ASSERT)\b",
    re.IGNORECASE,
)

def validate_bigquery_query(
    tool: "BaseTool",
    args: dict[str, Any],
    tool_context: "ToolContext",
) -> Optional[dict]:
    """run_bigquery_readonly_query の実行前にSQLを追加検証する。

    検証項目:
      - BigQuery Scripting 構文 (BEGIN, DECLARE等) の禁止
      - SQLの監査ログ出力
    """
    if tool.name != "run_bigquery_readonly_query":
        return None

    query = str(args.get("query") or "").strip()

    # 監査ログ
    logger.info("ガードレール: BigQuery SQL実行要求: %s", query[:200])

    # Scripting構文チェック
    if _BQ_DANGEROUS_PATTERNS.search(query):
        logger.error(
            "ガードレール: BigQuery SQLに危険な構文を検出しブロック: %s", query[:200],
        )
        return {
            "status": "error",
            "message": "BigQuery Scripting構文 (BEGIN/DECLARE/EXECUTE IMMEDIATE等) は禁止されています。",
        }

    return None


# ===========================================================================
# Callback 5: validate_chat_message (before_tool)
# ===========================================================================

_MAX_SIMPLE_MESSAGE_LENGTH = 4000

def validate_chat_message(
    tool: "BaseTool",
    args: dict[str, Any],
    tool_context: "ToolContext",
) -> Optional[dict]:
    """send_simple_message の実行前にメッセージを検証する。

    検証項目:
      - メッセージが空でないか
      - メッセージ長の上限チェック
    """
    if tool.name != "send_simple_message":
        return None

    message = str(args.get("message") or "").strip()

    if not message:
        logger.error("ガードレール: send_simple_message のメッセージが空です")
        return {
            "status": "error",
            "message": "送信メッセージは必須です。空のメッセージは送信できません。",
        }

    if len(message) > _MAX_SIMPLE_MESSAGE_LENGTH:
        logger.warning(
            "ガードレール: send_simple_message のメッセージが長すぎます (%d文字)",
            len(message),
        )
        return {
            "status": "error",
            "message": f"メッセージが長すぎます ({len(message)}文字)。{_MAX_SIMPLE_MESSAGE_LENGTH}文字以内にしてください。",
        }

    return None
