"""
A2A Tools - Agent-to-Agent 連携

Vertex AI Agent Engine の A2A プロトコルを使用して
他のエージェントと連携します。

連携例:
  - Jiraチケット作成エージェント
  - 承認ワークフローエージェント
  - パッチ管理エージェント
  - 報告書作成エージェント
"""

import logging
import json
import os
import urllib.error
import urllib.request
from typing import Any

import vertexai
from vertexai.preview import reasoning_engines

logger = logging.getLogger(__name__)

# エージェントレジストリ（キャッシュ）
_agent_registry: dict[str, Any] = {}


def _get_config_value_fallback(
    env_names: list[str],
    *,
    secret_name: str | None = None,
    default: str = "",
) -> str:
    """Resolve config by env first, then optional Secret Manager fallback."""
    try:
        from .secret_config import get_config_value  # type: ignore
    except Exception:
        try:
            from agent.tools.secret_config import get_config_value  # type: ignore
        except Exception:
            get_config_value = None

    if get_config_value:
        try:
            return str(get_config_value(env_names, secret_name=secret_name, default=default) or "").strip()
        except Exception:
            pass

    for env_name in env_names:
        value = str(os.environ.get(env_name) or "").strip()
        if value:
            return value
    return str(default or "").strip()


def _is_valid_resource_name(resource_name: str) -> bool:
    text = str(resource_name or "").strip()
    if not text:
        return False
    # Expected:
    # projects/<project>/locations/<location>/reasoningEngines/<id>
    parts = text.split("/")
    if len(parts) != 6:
        return False
    return (
        parts[0] == "projects"
        and bool(parts[1])
        and parts[2] == "locations"
        and bool(parts[3])
        and parts[4] == "reasoningEngines"
        and bool(parts[5])
    )


def _extract_remote_response_text(response: Any) -> str:
    """Best-effort extraction of text from remote agent response payload."""
    if isinstance(response, str):
        return response.strip()
    if isinstance(response, dict):
        # Common direct keys
        for key in ("text", "message", "output", "result"):
            value = response.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        # Agent style nested content
        content = response.get("content")
        if isinstance(content, dict):
            parts = content.get("parts", [])
            if isinstance(parts, list):
                texts: list[str] = []
                for part in parts:
                    if isinstance(part, dict):
                        text = part.get("text")
                        if isinstance(text, str) and text.strip():
                            texts.append(text.strip())
                if texts:
                    return "\n".join(texts)
    if isinstance(response, list):
        texts = [_extract_remote_response_text(item) for item in response]
        texts = [t for t in texts if t]
        if texts:
            return "\n".join(texts)
    return ""


def _extract_project_location_from_resource(resource_name: str) -> tuple[str, str]:
    parts = resource_name.split("/")
    if len(parts) == 6 and parts[0] == "projects" and parts[2] == "locations":
        return parts[1], parts[3]
    return "", ""


def _get_access_token() -> str:
    """Fetch OAuth2 access token for calling Vertex AI REST APIs."""
    # Preferred path: google-auth (available in Cloud Run image).
    try:
        import google.auth  # type: ignore
        from google.auth.transport.requests import Request  # type: ignore

        credentials, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        credentials.refresh(Request())
        token = getattr(credentials, "token", None)
        if token:
            return str(token)
    except Exception:
        pass

    # Fallback path for Cloud Run/GCE metadata server.
    metadata_url = (
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
    )
    req = urllib.request.Request(
        metadata_url,
        headers={"Metadata-Flavor": "Google"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
        token = payload.get("access_token")
        if not token:
            raise RuntimeError("metadata server returned no access_token")
        return str(token)


def _query_remote_agent_rest(
    *,
    resource_name: str,
    message: str,
    user_id: str,
    project_id: str,
    location: str,
) -> Any:
    """Call Reasoning Engine REST endpoint directly (streamQuery first)."""
    if not project_id or not location:
        parsed_project, parsed_location = _extract_project_location_from_resource(resource_name)
        project_id = project_id or parsed_project
        location = location or parsed_location
    if not project_id or not location:
        raise RuntimeError("Unable to resolve project/location for remote agent query.")

    token = _get_access_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json; charset=utf-8",
    }

    # 1) Try streamQuery first. This works for ADK agents that expose stream_query.
    stream_endpoint = f"https://{location}-aiplatform.googleapis.com/v1/{resource_name}:streamQuery"
    stream_payload = {
        "class_method": "stream_query",
        "input": {
            "user_id": user_id,
            "message": message,
        },
    }
    try:
        req = urllib.request.Request(
            stream_endpoint,
            data=json.dumps(stream_payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode("utf-8")
            if not raw.strip():
                return {}

            # streamQuery often returns newline-delimited JSON events.
            lines = [line.strip() for line in raw.splitlines() if line.strip()]
            events: list[Any] = []
            if len(lines) == 1:
                decoded = json.loads(lines[0])
                if isinstance(decoded, list):
                    events = decoded
                else:
                    events = [decoded]
            else:
                for line in lines:
                    events.append(json.loads(line))

            text = ""
            for event in events:
                candidate = _extract_remote_response_text(event)
                if candidate:
                    text = candidate

            return {
                "events": events,
                "text": text,
            }
    except urllib.error.HTTPError as stream_err:
        stream_body = ""
        try:
            stream_body = stream_err.read().decode("utf-8")
        except Exception:
            stream_body = ""
        logger.warning(
            "streamQuery failed for %s: HTTP %s %s; fallback to :query",
            resource_name,
            stream_err.code,
            stream_body[:300],
        )

    # 2) Fallback to query endpoint for engines that expose query method.
    query_endpoint = f"https://{location}-aiplatform.googleapis.com/v1/{resource_name}:query"
    query_payload = {
        "classMethod": "query",
        "input": {
            "user_id": user_id,
            "message": message,
        },
    }
    query_req = urllib.request.Request(
        query_endpoint,
        data=json.dumps(query_payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(query_req, timeout=60) as resp:
            raw = resp.read().decode("utf-8")
            decoded = json.loads(raw) if raw else {}
            if isinstance(decoded, dict) and "output" in decoded:
                return decoded.get("output")
            return decoded
    except urllib.error.HTTPError as query_err:
        query_body = ""
        try:
            query_body = query_err.read().decode("utf-8")
        except Exception:
            query_body = ""
        raise RuntimeError(
            f"ReasoningEngine REST query failed: HTTP {query_err.code} {query_body}"
        ) from query_err


def register_remote_agent(
    agent_id: str,
    resource_name: str,
    description: str = "",
) -> dict[str, Any]:
    """
    連携するリモートエージェントを登録します。

    Args:
        agent_id: エージェントの識別子（呼び出し時に使用）
        resource_name: Agent Engine のリソース名
        description: エージェントの説明

    Returns:
        登録結果

    Example:
        >>> register_remote_agent(
        ...     agent_id="jira_agent",
        ...     resource_name="projects/my-project/locations/us-central1/reasoningEngines/12345",
        ...     description="Jiraチケット作成エージェント"
        ... )
    """
    try:
        normalized_agent_id = str(agent_id or "").strip()
        normalized_resource = str(resource_name or "").strip()
        if not normalized_agent_id:
            return {"status": "error", "message": "agent_id is required."}
        if not _is_valid_resource_name(normalized_resource):
            return {
                "status": "error",
                "message": (
                    "resource_name format is invalid. Expected: "
                    "projects/<project>/locations/<location>/reasoningEngines/<id>"
                ),
            }

        _agent_registry[normalized_agent_id] = {
            "resource_name": normalized_resource,
            "description": str(description or "").strip(),
        }

        logger.info(f"Registered agent: {normalized_agent_id} -> {normalized_resource}")

        return {
            "status": "registered",
            "agent_id": normalized_agent_id,
            "resource_name": normalized_resource,
        }

    except Exception as e:
        logger.error(f"Failed to register agent: {e}")
        return {"status": "error", "message": str(e)}


def register_master_agent(
    resource_name: str | None = None,
    description: str = "課のマスターエージェント",
) -> dict[str, Any]:
    """
    マスターエージェントを `master_agent` として登録する。

    resource_name 未指定時は以下の順で自動解決する。
    1) REMOTE_AGENT_MASTER / Secret(vuln-agent-master-agent-resource-name)
    2) REMOTE_AGENT_TEST / REMOTE_AGENT_TEST_DIALOG / Secret(vuln-agent-test-dialog-resource-name)
    """
    resolved_resource = str(resource_name or "").strip()
    resolution_source = "argument"
    if not resolved_resource:
        resolved_resource = _get_config_value_fallback(
            ["REMOTE_AGENT_MASTER"],
            secret_name="vuln-agent-master-agent-resource-name",
            default="",
        )
        if resolved_resource:
            resolution_source = "master_config"
    if not resolved_resource:
        resolved_resource = _get_config_value_fallback(
            ["REMOTE_AGENT_TEST", "REMOTE_AGENT_TEST_DIALOG"],
            secret_name="vuln-agent-test-dialog-resource-name",
            default="",
        )
        if resolved_resource:
            resolution_source = "test_dialog_config"
    if not resolved_resource:
        return {
            "status": "error",
            "message": (
                "resource_name is required. Set argument, REMOTE_AGENT_MASTER, "
                "or configure vuln-agent-test-dialog-resource-name."
            ),
        }
    result = register_remote_agent(
        agent_id="master_agent",
        resource_name=resolved_resource,
        description=description,
    )
    if result.get("status") == "registered":
        result["agent_role"] = "master_agent"
        result["resolved_from"] = resolution_source
    return result


def _auto_register_default_agents() -> None:
    """
    Register default A2A agents from runtime config when possible.

    This function is best-effort and never raises.
    """
    try:
        test_dialog_resource = _get_config_value_fallback(
            ["REMOTE_AGENT_TEST", "REMOTE_AGENT_TEST_DIALOG"],
            secret_name="vuln-agent-test-dialog-resource-name",
            default="",
        )
        if _is_valid_resource_name(test_dialog_resource):
            if "test_agent" not in _agent_registry:
                register_remote_agent(
                    agent_id="test_agent",
                    resource_name=test_dialog_resource,
                    description="A2A test dialog agent",
                )
            if "master_agent" not in _agent_registry:
                register_remote_agent(
                    agent_id="master_agent",
                    resource_name=test_dialog_resource,
                    description="課のマスターエージェント",
                )
    except Exception:
        # Best-effort only; explicit registration path still exists.
        pass


def call_remote_agent(
    agent_id: str,
    message: str,
    user_id: str = "vuln_agent",
) -> dict[str, Any]:
    """
    登録済みのリモートエージェントを呼び出します。

    Args:
        agent_id: 登録済みエージェントの識別子
        message: エージェントに送るメッセージ
        user_id: ユーザー識別子（セッション管理用）

    Returns:
        エージェントからの応答

    Example:
        >>> # Jiraチケット作成を依頼
        >>> call_remote_agent(
        ...     agent_id="jira_agent",
        ...     message="CVE-2024-12345の対応チケットを作成してください。優先度: 高、担当者: tanaka@example.com"
        ... )
    """
    try:
        normalized_agent_id = str(agent_id or "").strip()
        normalized_message = str(message or "").strip()
        normalized_user_id = str(user_id or "vuln_agent").strip() or "vuln_agent"
        if not normalized_agent_id:
            return {"status": "error", "message": "agent_id is required."}
        if not normalized_message:
            return {"status": "error", "agent_id": normalized_agent_id, "message": "message is required."}

        if normalized_agent_id not in _agent_registry:
            _auto_register_default_agents()
        if normalized_agent_id not in _agent_registry:
            return {
                "status": "error",
                "message": f"Agent '{normalized_agent_id}' is not registered. Use register_remote_agent first."
            }

        agent_info = _agent_registry[normalized_agent_id]
        resource_name = agent_info["resource_name"]

        # Vertex AI 初期化
        project_id = os.environ.get("GCP_PROJECT_ID")
        location = os.environ.get("GCP_LOCATION", "asia-northeast1")

        if project_id:
            vertexai.init(project=project_id, location=location)

        # リモートエージェントを取得
        remote_agent = reasoning_engines.ReasoningEngine(resource_name)

        # Prefer SDK query when available; fallback to REST query.
        if hasattr(remote_agent, "query"):
            response = remote_agent.query(
                user_id=normalized_user_id,
                message=normalized_message,
            )
        else:
            logger.warning(
                "ReasoningEngine object has no query(); using REST fallback for %s",
                normalized_agent_id,
            )
            response = _query_remote_agent_rest(
                resource_name=resource_name,
                message=normalized_message,
                user_id=normalized_user_id,
                project_id=project_id or "",
                location=location or "",
            )

        response_text = _extract_remote_response_text(response)

        logger.info(f"Called agent {normalized_agent_id}: {normalized_message[:50]}...")

        return {
            "status": "success",
            "agent_id": normalized_agent_id,
            "response": response,
            "response_text": response_text,
        }

    except Exception as e:
        logger.error(f"Failed to call agent {agent_id}: {e}")
        return {
            "status": "error",
            "agent_id": agent_id,
            "message": str(e)
        }


def call_remote_agent_conversation_loop(
    agent_id: str,
    initial_message: str,
    user_id: str = "vuln_agent",
    max_turns: int = 5,
    goal: str = "",
    continue_instruction: str = "",
    max_response_chars: int = 4000,
) -> dict[str, Any]:
    """
    登録済みリモートエージェントと複数ターンで継続対話する。

    単発 `call_remote_agent` を内部で繰り返し呼び出し、以下の条件で停止する:
    - エラーが返る
    - 最終回答マーカーを検出する
    - 同一回答の繰り返しを検出する
    - `max_turns` に到達する
    """
    normalized_agent_id = str(agent_id or "").strip()
    normalized_initial = str(initial_message or "").strip()
    normalized_user_id = str(user_id or "vuln_agent").strip() or "vuln_agent"
    normalized_goal = str(goal or "").strip()
    normalized_continue = str(continue_instruction or "").strip()

    if not normalized_agent_id:
        return {"status": "error", "message": "agent_id is required."}
    if not normalized_initial:
        return {"status": "error", "message": "initial_message is required."}
    if max_turns < 1 or max_turns > 20:
        return {"status": "error", "message": "max_turns must be between 1 and 20."}
    if max_response_chars < 200 or max_response_chars > 20000:
        return {"status": "error", "message": "max_response_chars must be between 200 and 20000."}

    conversation_goal = normalized_goal or normalized_initial
    followup_instruction = normalized_continue or (
        "目的に対して次の最善ステップを1つ進めてください。"
        "完了した場合は必ず '最終回答:' で始めて結論を示してください。"
    )

    transcript: list[dict[str, Any]] = []
    seen_normalized_responses: set[str] = set()
    final_markers = ("最終回答:", "final answer:", "完了です", "以上です")
    current_message = normalized_initial
    stop_reason = "max_turns_reached"

    for turn in range(1, max_turns + 1):
        result = call_remote_agent(
            agent_id=normalized_agent_id,
            message=current_message,
            user_id=normalized_user_id,
        )
        response_text = str(result.get("response_text") or "").strip()
        transcript.append(
            {
                "turn": turn,
                "sent_message": current_message,
                "status": result.get("status", "error"),
                "response_text": response_text,
                "message": result.get("message", ""),
            }
        )

        if result.get("status") != "success":
            stop_reason = "remote_error"
            return {
                "status": "error",
                "agent_id": normalized_agent_id,
                "stop_reason": stop_reason,
                "turns_executed": turn,
                "final_response_text": response_text,
                "transcript": transcript,
                "message": str(result.get("message") or "remote agent call failed"),
            }

        normalized_response = " ".join(response_text.lower().split())
        if any(marker in response_text.lower() for marker in final_markers):
            stop_reason = "final_marker_detected"
            break
        if normalized_response and normalized_response in seen_normalized_responses:
            stop_reason = "duplicate_response_detected"
            break
        if normalized_response:
            seen_normalized_responses.add(normalized_response)
        if turn >= max_turns:
            stop_reason = "max_turns_reached"
            break

        excerpt = response_text[:max_response_chars]
        current_message = (
            "継続対話です。以下を踏まえて次へ進めてください。\n"
            f"目的: {conversation_goal}\n"
            f"直前の回答:\n{excerpt}\n\n"
            f"追加指示: {followup_instruction}"
        )

    return {
        "status": "success",
        "agent_id": normalized_agent_id,
        "stop_reason": stop_reason,
        "turns_executed": len(transcript),
        "final_response_text": transcript[-1]["response_text"] if transcript else "",
        "transcript": transcript,
    }


def create_master_agent_handoff_request(
    task_type: str,
    objective: str,
    facts: list[str] | None = None,
    constraints: list[str] | None = None,
    requested_actions: list[str] | None = None,
    context: dict[str, Any] | None = None,
    urgency: str = "中",
) -> dict[str, Any]:
    """
    マスターエージェントへの引き継ぎ依頼文を標準フォーマットで構築する。
    """
    normalized_task_type = str(task_type or "").strip()
    normalized_objective = str(objective or "").strip()
    normalized_urgency = str(urgency or "中").strip() or "中"

    if not normalized_task_type:
        return {"status": "error", "message": "task_type is required."}
    if not normalized_objective:
        return {"status": "error", "message": "objective is required."}

    fact_lines = [f"- {str(x).strip()}" for x in (facts or []) if str(x).strip()]
    constraint_lines = [f"- {str(x).strip()}" for x in (constraints or []) if str(x).strip()]
    action_lines = [f"- {str(x).strip()}" for x in (requested_actions or []) if str(x).strip()]

    context_pairs = []
    for k, v in (context or {}).items():
        key = str(k).strip()
        value = str(v).strip()
        if key and value:
            context_pairs.append(f"- {key}: {value}")

    sections = [
        "【連携種別】",
        normalized_task_type,
        "",
        "【目的】",
        normalized_objective,
        "",
        "【緊急度】",
        normalized_urgency,
    ]

    if fact_lines:
        sections.extend(["", "【確定事項】", *fact_lines])
    if constraint_lines:
        sections.extend(["", "【制約条件】", *constraint_lines])
    if action_lines:
        sections.extend(["", "【依頼アクション】", *action_lines])
    if context_pairs:
        sections.extend(["", "【追加コンテキスト】", *context_pairs])

    message = "\n".join(sections).strip()
    return {
        "status": "ready",
        "target_agent_id": "master_agent",
        "message": message,
        "handoff": {
            "task_type": normalized_task_type,
            "objective": normalized_objective,
            "urgency": normalized_urgency,
            "facts": [str(x).strip() for x in (facts or []) if str(x).strip()],
            "constraints": [str(x).strip() for x in (constraints or []) if str(x).strip()],
            "requested_actions": [str(x).strip() for x in (requested_actions or []) if str(x).strip()],
            "context": context or {},
        },
    }


def call_master_agent(
    task_type: str,
    objective: str,
    facts: list[str] | None = None,
    constraints: list[str] | None = None,
    requested_actions: list[str] | None = None,
    context: dict[str, Any] | None = None,
    urgency: str = "中",
    user_id: str = "vuln_agent",
) -> dict[str, Any]:
    """
    標準フォーマットでマスターエージェントを呼び出す。
    """
    handoff = create_master_agent_handoff_request(
        task_type=task_type,
        objective=objective,
        facts=facts,
        constraints=constraints,
        requested_actions=requested_actions,
        context=context,
        urgency=urgency,
    )
    if handoff.get("status") != "ready":
        return handoff

    result = call_remote_agent(
        agent_id="master_agent",
        message=handoff["message"],
        user_id=user_id,
    )
    return {
        "status": result.get("status", "error"),
        "agent_id": "master_agent",
        "handoff": handoff.get("handoff", {}),
        "response": result.get("response"),
        "response_text": result.get("response_text", ""),
        "message": result.get("message", ""),
    }


def list_registered_agents() -> dict[str, Any]:
    """
    登録済みのリモートエージェント一覧を取得します。

    Returns:
        登録済みエージェントの一覧
    """
    _auto_register_default_agents()

    agents = []
    for agent_id, info in _agent_registry.items():
        agents.append({
            "agent_id": agent_id,
            "resource_name": info["resource_name"],
            "description": info.get("description", ""),
        })

    return {
        "status": "success",
        "agents": agents,
        "count": len(agents),
    }


def create_jira_ticket_request(
    vulnerability_id: str,
    title: str,
    severity: str,
    affected_systems: list[str],
    assignee: str,
    description: str | None = None,
) -> dict[str, Any]:
    """
    Jiraチケット作成リクエストを構築します。

    この関数はJiraエージェントに渡すメッセージを構築するヘルパーです。
    実際のチケット作成はcall_remote_agent()でJiraエージェントを呼び出します。

    Args:
        vulnerability_id: CVE番号等
        title: チケットタイトル
        severity: 重大度（緊急/高/中/低）
        affected_systems: 影響システムリスト
        assignee: 担当者メールアドレス
        description: 詳細説明

    Returns:
        Jiraエージェント用のリクエストメッセージ

    Example:
        >>> request = create_jira_ticket_request(
        ...     vulnerability_id="CVE-2024-12345",
        ...     title="Log4j脆弱性対応",
        ...     severity="緊急",
        ...     affected_systems=["基幹システム", "顧客管理"],
        ...     assignee="tanaka@example.com"
        ... )
        >>> call_remote_agent("jira_agent", request["message"])
    """
    if not str(vulnerability_id or "").strip():
        return {"status": "error", "message": "vulnerability_id is required."}
    if not str(title or "").strip():
        return {"status": "error", "message": "title is required."}
    if not str(assignee or "").strip():
        return {"status": "error", "message": "assignee is required."}
    if not affected_systems:
        return {"status": "error", "message": "affected_systems is required."}

    priority_map = {
        "緊急": "Highest",
        "高": "High",
        "中": "Medium",
        "低": "Low",
    }

    systems_text = ", ".join(affected_systems)
    priority = priority_map.get(severity, "Medium")

    message = f"""以下の内容でJiraチケットを作成してください:

タイトル: [{vulnerability_id}] {title}
優先度: {priority}
担当者: {assignee}
ラベル: vulnerability, security, {severity}

説明:
## 脆弱性情報
- CVE番号: {vulnerability_id}
- 重大度: {severity}

## 影響範囲
影響を受けるシステム: {systems_text}

## 対応内容
{description or "脆弱性の調査と対応を行ってください。"}
"""

    return {
        "status": "ready",
        "message": message,
        "vulnerability_id": vulnerability_id,
        "priority": priority,
    }


def create_approval_request(
    vulnerability_id: str,
    action: str,
    approvers: list[str],
    details: str | None = None,
) -> dict[str, Any]:
    """
    承認リクエストを構築します。

    承認ワークフローエージェントに渡すメッセージを構築するヘルパーです。

    Args:
        vulnerability_id: CVE番号等
        action: 承認を求めるアクション（例: "緊急パッチ適用"）
        approvers: 承認者リスト
        details: 詳細説明

    Returns:
        承認エージェント用のリクエストメッセージ

    Example:
        >>> request = create_approval_request(
        ...     vulnerability_id="CVE-2024-12345",
        ...     action="緊急パッチ適用",
        ...     approvers=["manager@example.com"],
        ...     details="本番環境へのパッチ適用を承認してください"
        ... )
        >>> call_remote_agent("approval_agent", request["message"])
    """
    if not str(vulnerability_id or "").strip():
        return {"status": "error", "message": "vulnerability_id is required."}
    if not str(action or "").strip():
        return {"status": "error", "message": "action is required."}
    if not approvers:
        return {"status": "error", "message": "approvers is required."}

    approvers_text = ", ".join(approvers)

    message = f"""以下の内容で承認リクエストを作成してください:

件名: [{vulnerability_id}] {action}の承認依頼
承認者: {approvers_text}

詳細:
{details or f"{vulnerability_id}に対する{action}の承認をお願いします。"}

承認後のアクション:
- 承認: 対応を開始
- 却下: 代替案を検討
"""

    return {
        "status": "ready",
        "message": message,
        "vulnerability_id": vulnerability_id,
        "action": action,
    }


# 環境変数から事前登録するエージェント
def _load_preconfigured_agents():
    """環境変数から事前設定されたエージェントを読み込む"""
    # REMOTE_AGENT_JIRA=projects/xxx/locations/xxx/reasoningEngines/xxx
    # REMOTE_AGENT_APPROVAL=projects/xxx/locations/xxx/reasoningEngines/xxx

    agent_configs = {
        "jira_agent": ("REMOTE_AGENT_JIRA", "Jiraチケット作成エージェント"),
        "approval_agent": ("REMOTE_AGENT_APPROVAL", "承認ワークフローエージェント"),
        "patch_agent": ("REMOTE_AGENT_PATCH", "パッチ管理エージェント"),
        "report_agent": ("REMOTE_AGENT_REPORT", "報告書作成エージェント"),
        "master_agent": ("REMOTE_AGENT_MASTER", "課のマスターエージェント"),
    }

    for agent_id, (env_var, description) in agent_configs.items():
        resource_name = os.environ.get(env_var)
        if resource_name:
            register_remote_agent(agent_id, resource_name, description)
            logger.info(f"Pre-configured agent loaded: {agent_id}")


# モジュール読み込み時に事前設定エージェントを読み込む
_load_preconfigured_agents()
