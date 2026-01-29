# A2A連携（Agent-to-Agent）セットアップガイド

脆弱性管理エージェントと他のエージェントを連携させる設定手順です。

---

## 概要

```
┌─────────────────────────────────────────────────────────────────┐
│                     A2A連携アーキテクチャ                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│                    ┌─────────────────────┐                      │
│                    │  脆弱性管理Agent     │                      │
│                    │  (このエージェント)   │                      │
│                    └──────────┬──────────┘                      │
│                               │                                  │
│           ┌───────────────────┼───────────────────┐              │
│           │                   │                   │              │
│           ▼                   ▼                   ▼              │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐    │
│  │  Jira Agent     │ │ Approval Agent  │ │  Report Agent   │    │
│  │  チケット作成    │ │  承認ワークフロー │ │  報告書作成     │    │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Step 1: 連携エージェントのデプロイ

### 1.1 Jira連携エージェントの例

```python
# jira_agent/agent.py
from google.adk import Agent
from google.adk.tools import FunctionTool

def create_jira_ticket(
    project_key: str,
    summary: str,
    description: str,
    issue_type: str = "Task",
    priority: str = "Medium",
    assignee: str = None,
    labels: list[str] = None,
) -> dict:
    """Jiraチケットを作成"""
    # Jira API呼び出し
    # ...
    return {"status": "created", "ticket_id": "VULN-123"}

agent = Agent(
    name="jira_agent",
    model="gemini-2.5-flash",
    instruction="Jiraチケットを作成するエージェント",
    tools=[FunctionTool(create_jira_ticket)],
)
```

### 1.2 デプロイ

```bash
cd jira_agent
adk deploy --project=YOUR_PROJECT --location=us-central1
```

デプロイ後のリソース名をメモ:
```
projects/YOUR_PROJECT/locations/us-central1/reasoningEngines/AGENT_ID
```

---

## Step 2: 環境変数の設定

### 2.1 `.env` ファイルを編集

```bash
# A2A連携エージェント
REMOTE_AGENT_JIRA=projects/your-project/locations/us-central1/reasoningEngines/jira-agent-id
REMOTE_AGENT_APPROVAL=projects/your-project/locations/us-central1/reasoningEngines/approval-agent-id
REMOTE_AGENT_PATCH=projects/your-project/locations/us-central1/reasoningEngines/patch-agent-id
REMOTE_AGENT_REPORT=projects/your-project/locations/us-central1/reasoningEngines/report-agent-id
```

### 2.2 再デプロイ

```bash
./deploy.sh
```

---

## Step 3: 動作確認

### 3.1 登録済みエージェントの確認

```bash
./test_agent.sh "登録されているエージェントを教えて"
```

期待される応答:
```
登録済みエージェント:
- jira_agent: Jiraチケット作成エージェント
- approval_agent: 承認ワークフローエージェント
```

### 3.2 Jiraチケット作成テスト

```bash
./test_agent.sh "CVE-2024-12345のJiraチケットを作成して。担当者はtanaka@example.com、優先度は高"
```

---

## 使用例

### 例1: 脆弱性検出からJiraチケット作成まで

```
ユーザー: 「脆弱性スキャンを実行して、緊急度が高い場合はJiraチケットも作成して」

エージェントの処理:
1. get_sidfm_emails() で未読メール取得
2. search_sbom_by_purl() で影響分析
3. 優先度が「緊急」または「高」の場合:
   - create_jira_ticket_request() でリクエスト構築
   - call_remote_agent("jira_agent", ...) でチケット作成
4. send_vulnerability_alert() で担当者に通知
```

### 例2: 承認ワークフロー

```
ユーザー: 「CVE-2024-12345の緊急パッチ適用について、manager@example.comに承認を依頼して」

エージェントの処理:
1. create_approval_request() でリクエスト構築
2. call_remote_agent("approval_agent", ...) で承認依頼
3. 承認結果を待機（非同期）
```

### 例3: 動的なエージェント登録

```
ユーザー: 「新しいエージェントを登録して: slack_agent, projects/xxx/locations/xxx/reasoningEngines/123」

エージェントの処理:
1. register_remote_agent("slack_agent", "projects/xxx/...", "Slack通知エージェント")
2. 以降、call_remote_agent("slack_agent", ...) で呼び出し可能
```

---

## A2Aプロトコルの詳細

### Agent Card

各エージェントは「Agent Card」で能力を公開します:

```json
{
  "name": "vulnerability_management_agent",
  "capabilities": [
    {
      "name": "vulnerability_detection",
      "description": "脆弱性を検出"
    },
    {
      "name": "impact_analysis",
      "description": "影響分析を実行"
    }
  ]
}
```

### 認証

Agent Engine間の通信は自動的にサービスアカウント認証が行われます。

---

## サンプルエージェント

### Jira連携エージェント（簡易版）

```python
# jira_agent/agent.py
"""Jira連携エージェント"""

from google.adk import Agent
from google.adk.tools import FunctionTool
import os
from jira import JIRA

def _get_jira_client():
    return JIRA(
        server=os.environ.get("JIRA_SERVER"),
        basic_auth=(
            os.environ.get("JIRA_USER"),
            os.environ.get("JIRA_TOKEN")
        )
    )

def create_ticket(
    project: str,
    summary: str,
    description: str,
    issue_type: str = "Task",
    priority: str = "Medium",
    assignee: str = None,
) -> dict:
    """Jiraチケットを作成"""
    jira = _get_jira_client()

    fields = {
        "project": {"key": project},
        "summary": summary,
        "description": description,
        "issuetype": {"name": issue_type},
        "priority": {"name": priority},
    }

    if assignee:
        fields["assignee"] = {"name": assignee}

    issue = jira.create_issue(fields=fields)

    return {
        "status": "created",
        "ticket_id": issue.key,
        "url": f"{os.environ.get('JIRA_SERVER')}/browse/{issue.key}"
    }

agent = Agent(
    name="jira_agent",
    model="gemini-2.5-flash",
    instruction="Jiraチケットを作成・管理するエージェント",
    tools=[FunctionTool(create_ticket)],
)
```

### 承認ワークフローエージェント（簡易版）

```python
# approval_agent/agent.py
"""承認ワークフローエージェント"""

from google.adk import Agent
from google.adk.tools import FunctionTool

# 簡易的な承認状態管理（実際はDBを使用）
pending_approvals = {}

def request_approval(
    request_id: str,
    title: str,
    description: str,
    approvers: list[str],
) -> dict:
    """承認リクエストを作成"""
    pending_approvals[request_id] = {
        "title": title,
        "description": description,
        "approvers": approvers,
        "status": "pending",
    }

    # 実際はメール/Chat/Slackで通知
    return {
        "status": "pending",
        "request_id": request_id,
        "message": f"承認リクエストを {', '.join(approvers)} に送信しました"
    }

def check_approval_status(request_id: str) -> dict:
    """承認状態を確認"""
    if request_id not in pending_approvals:
        return {"status": "not_found"}

    return pending_approvals[request_id]

agent = Agent(
    name="approval_agent",
    model="gemini-2.5-flash",
    instruction="承認ワークフローを管理するエージェント",
    tools=[
        FunctionTool(request_approval),
        FunctionTool(check_approval_status),
    ],
)
```

---

## トラブルシューティング

### エラー: "Agent not registered"

**原因**: 環境変数が設定されていないか、エージェントがデプロイされていない

**解決**:
1. 環境変数を確認: `echo $REMOTE_AGENT_JIRA`
2. エージェントのデプロイ状態を確認

---

### エラー: "Permission denied"

**原因**: サービスアカウント間の権限がない

**解決**:
1. 呼び出し元のサービスアカウントに `aiplatform.reasoningEngines.query` 権限を付与
2. または、同じプロジェクト内にエージェントをデプロイ

---

### エラー: "Agent timeout"

**原因**: リモートエージェントの応答が遅い

**解決**:
1. リモートエージェントのログを確認
2. 複雑なタスクは分割して実行
