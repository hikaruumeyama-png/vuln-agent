# Workspace Events セットアップ

この機能は Workspace Events API 経由で Google Chat イベントを受信し、
Bot への @メンションなしで以下を自動処理します。

- **Gmail 通知（SIDfm等）**: メッセージイベントでメール内容を自動解析し、同スレッドに返信
- **？リアクション**: リアクションが付いた元メッセージを解析し、同スレッドに返信

## デプロイ対象

- Cloud Functions: `vuln-agent-workspace-events-webhook`
- Entry point: `handle_workspace_event`
- Source: `workspace_events_webhook/`

## 事前準備

1. `setup_cloud.sh` または `cloudbuild.yaml` で上記 Function をデプロイ
2. Workspace Events API でサブスクリプションを作成（後述）
3. Pub/Sub Push の通知先を Function URL に設定

## 購読イベント

### メッセージイベント（Gmail通知自動処理用）
- `google.workspace.chat.message.v1.created`
- `google.workspace.chat.message.v1.batchCreated`

### リアクションイベント（？リアクション解析用）
- `google.workspace.chat.reaction.v1.created`
- `google.workspace.chat.reaction.v1.batchCreated`

## サブスクリプション作成

Workspace Events API のサブスクリプションは **ユーザー認証（OAuth）** が必要です。
以下のスクリプトで作成できます。

```bash
python scripts/create_workspace_subscription.py \
  --space-id "spaces/AAAA--pjkDQ" \
  --topic "projects/info-sec-ai-platform/topics/vuln-agent-workspace-events"
```

### 手動作成（REST API）

```bash
# OAuth アクセストークンを取得（chat.messages.readonly スコープが必要）
TOKEN=$(gcloud auth print-access-token \
  --scopes=https://www.googleapis.com/auth/chat.messages.readonly)

curl -X POST "https://workspaceevents.googleapis.com/v1/subscriptions" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "targetResource": "//chat.googleapis.com/spaces/AAAA--pjkDQ",
    "eventTypes": [
      "google.workspace.chat.message.v1.created",
      "google.workspace.chat.reaction.v1.created"
    ],
    "notificationEndpoint": {
      "pubsubTopic": "projects/info-sec-ai-platform/topics/vuln-agent-workspace-events"
    },
    "payloadOptions": {
      "includeResource": true
    }
  }'
```

> サブスクリプションは **7日間** で自動失効します。
> 本番運用では Cloud Scheduler 等で定期更新してください。

## 動作仕様

### Gmail 通知処理フロー
1. Gmail アプリがスペースにメール通知を投稿
2. Workspace Events API → Pub/Sub → Cloud Functions にメッセージイベント到達
3. `_looks_like_gmail_message()` で Gmail 投稿か判定（人間の雑談は無視）
4. エージェントで脆弱性解析
5. 同じスレッドに結果を返信

### リアクション処理フロー
1. ユーザーがメッセージに `？` / `❓` リアクションを付与
2. Workspace Events API → Pub/Sub → Cloud Functions にリアクションイベント到達
3. 元メッセージを取得 → エージェントで解析 → 同スレッドに返信

## 注意

- Function は重複イベントをメモリ内で簡易除外します（短期）。
- 再デプロイやスケールアウト時の重複完全排除には外部ストアの冪等管理を追加してください。
