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

import os
import logging
from typing import Any

import vertexai
from vertexai.preview import reasoning_engines

logger = logging.getLogger(__name__)

# エージェントレジストリ（キャッシュ）
_agent_registry: dict[str, Any] = {}


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
        _agent_registry[agent_id] = {
            "resource_name": resource_name,
            "description": description,
        }

        logger.info(f"Registered agent: {agent_id} -> {resource_name}")

        return {
            "status": "registered",
            "agent_id": agent_id,
            "resource_name": resource_name,
        }

    except Exception as e:
        logger.error(f"Failed to register agent: {e}")
        return {"status": "error", "message": str(e)}


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
        if agent_id not in _agent_registry:
            return {
                "status": "error",
                "message": f"Agent '{agent_id}' is not registered. Use register_remote_agent first."
            }

        agent_info = _agent_registry[agent_id]
        resource_name = agent_info["resource_name"]

        # Vertex AI 初期化
        project_id = os.environ.get("GCP_PROJECT_ID")
        location = os.environ.get("GCP_LOCATION", "asia-northeast1")

        if project_id:
            vertexai.init(project=project_id, location=location)

        # リモートエージェントを取得
        remote_agent = reasoning_engines.ReasoningEngine(resource_name)

        # クエリを実行
        response = remote_agent.query(
            user_id=user_id,
            message=message,
        )

        logger.info(f"Called agent {agent_id}: {message[:50]}...")

        return {
            "status": "success",
            "agent_id": agent_id,
            "response": response,
        }

    except Exception as e:
        logger.error(f"Failed to call agent {agent_id}: {e}")
        return {
            "status": "error",
            "agent_id": agent_id,
            "message": str(e)
        }


def list_registered_agents() -> dict[str, Any]:
    """
    登録済みのリモートエージェント一覧を取得します。

    Returns:
        登録済みエージェントの一覧
    """
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
    }

    for agent_id, (env_var, description) in agent_configs.items():
        resource_name = os.environ.get(env_var)
        if resource_name:
            register_remote_agent(agent_id, resource_name, description)
            logger.info(f"Pre-configured agent loaded: {agent_id}")


# モジュール読み込み時に事前設定エージェントを読み込む
_load_preconfigured_agents()
