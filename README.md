# 脆弱性管理AIエージェント

SIDfm の脆弱性通知メールを取り込み、SBOM と突合して担当者へ Google Chat 通知する Vertex AI Agent Engine 向けエージェントです。

## 何ができるか
- Gmail から SIDfm 通知メール取得
- SBOM（BigQuery または Sheets）で影響システム検索
- 担当者マッピングで通知先特定
- Google Chat へカード通知
- BigQuery へ対応履歴保存
- 定期スキャン（Cloud Scheduler + Cloud Functions）

## 構成
- `agent/`: Agent Engine 本体（ツール実装含む）
- `scheduler/`: 定期実行エントリーポイント
- `live_gateway/`: リアルタイム対話ゲートウェイ（任意）
- `web/`: Web UI（任意）
- `setup_cloud.sh`: 初期セットアップ
- `cloudbuild.yaml`: 再デプロイ/CI

## 最短セットアップ（推奨）
前提:
- GCP プロジェクト（課金有効）
- `gcloud` 利用可能
- Gmail OAuth 用 `credentials.json`

### 1. リポジトリ取得
```bash
gcloud config set project YOUR_PROJECT_ID
git clone https://github.com/YOUR_ORG/vuln-agent.git
cd vuln-agent
```

### 2. Gmail OAuth トークン作成
```bash
pip install -q google-auth-oauthlib google-api-python-client
python setup_gmail_oauth.py
```

### 3. Gmail トークンを Secret Manager に保存
```bash
OAUTH_TOKEN=$(grep '^GMAIL_OAUTH_TOKEN=' agent/.env | cut -d'=' -f2-)
echo -n "$OAUTH_TOKEN" | gcloud secrets create vuln-agent-gmail-oauth-token \
  --data-file=- --replication-policy=automatic 2>/dev/null \
  || echo -n "$OAUTH_TOKEN" | gcloud secrets versions add vuln-agent-gmail-oauth-token --data-file=-
```

### 4. 初期セットアップ実行
```bash
bash setup_cloud.sh
```

このスクリプトで API 有効化、必要 Secret 作成、BigQuery テーブル作成、Agent/Scheduler などのデプロイまで実行します。

## BigQuery 利用時の必須設定
`SBOM_DATA_BACKEND=bigquery` の場合、以下 Secret が必要です。
- `vuln-agent-sbom-data-backend` = `bigquery`
- `vuln-agent-bq-sbom-table-id` = `PROJECT.DATASET.sbom_packages`
- `vuln-agent-bq-owner-table-id` = `PROJECT.DATASET.owner_mapping`
- `vuln-agent-bq-table-id` = `PROJECT.DATASET.incident_response_history`（履歴記録用）

設定例:
```bash
echo -n "bigquery" | gcloud secrets versions add vuln-agent-sbom-data-backend --data-file=-
echo -n "${PROJECT_ID}.vuln_agent.sbom_packages" | gcloud secrets versions add vuln-agent-bq-sbom-table-id --data-file=-
echo -n "${PROJECT_ID}.vuln_agent.owner_mapping" | gcloud secrets versions add vuln-agent-bq-owner-table-id --data-file=-
```

## BigQuery 権限（重要）
Agent Engine 実行 ID（`service-<PROJECT_NUMBER>@gcp-sa-aiplatform-re.iam.gserviceaccount.com`）に、少なくとも次を付与してください。
- `roles/bigquery.jobUser`
- `roles/bigquery.dataViewer`

付与例:
```bash
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:service-<PROJECT_NUMBER>@gcp-sa-aiplatform-re.iam.gserviceaccount.com" \
  --role="roles/bigquery.jobUser"

gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:service-<PROJECT_NUMBER>@gcp-sa-aiplatform-re.iam.gserviceaccount.com" \
  --role="roles/bigquery.dataViewer"
```

## 動作確認
```bash
bash test_agent.sh "Gmailへの接続を確認して"
bash test_agent.sh "Chatへの接続を確認して"
bash test_agent.sh "SBOMでlog4jを検索して結果を教えて"
```

## よく使う運用コマンド
再デプロイ:
```bash
gcloud builds submit --config cloudbuild.yaml
```

Secret 更新（例: Chat Space ID）:
```bash
echo -n "spaces/XXXX" | gcloud secrets versions add vuln-agent-chat-space-id --data-file=-
gcloud builds submit --config cloudbuild.yaml
```

ログ確認:
```bash
gcloud logging read 'resource.type="aiplatform.googleapis.com/ReasoningEngine"' --limit=20
gcloud run services logs read vuln-agent-live-gateway --region=asia-northeast1 --limit=20
gcloud functions logs read vuln-agent-scheduler --region=asia-northeast1 --limit=20
```

## ツール一覧（Agent）
- Gmail: `get_sidfm_emails`, `get_unread_emails`, `mark_email_as_read`, `check_gmail_connection`
- SBOM/担当者: `search_sbom_by_purl`, `search_sbom_by_product`, `get_affected_systems`, `get_owner_mapping`
- Chat: `send_vulnerability_alert`, `send_simple_message`, `check_chat_connection`, `list_space_members`
- 履歴: `log_vulnerability_history`
- A2A: `register_remote_agent`, `call_remote_agent`, `list_registered_agents`, `create_jira_ticket_request`, `create_approval_request`

## トラブルシュート（最小）
- `SBOMデータが見つかりません`
  - `vuln-agent-sbom-data-backend` と `vuln-agent-bq-*-table-id` を確認
  - Agent Engine 実行 ID に BigQuery 権限（`jobUser`, `dataViewer`）があるか確認
- Gmail 接続失敗
  - `vuln-agent-gmail-oauth-token` の最新値を確認し、必要なら再発行
- Chat 接続失敗
  - `vuln-agent-chat-space-id` と Chat アプリのスペース参加状態を確認

## 補足ドキュメント
詳細手順は `docs/` を参照してください。
- `docs/SETUP_GMAIL.md`
- `docs/SETUP_CHAT.md`
- `docs/SETUP_A2A.md`
- `docs/SETUP_SCHEDULER.md`
