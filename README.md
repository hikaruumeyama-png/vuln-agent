# 脆弱性管理AIエージェント

SIDfm の脆弱性通知メールを取り込み、SBOM と突合して担当者へ Google Chat 通知する Vertex AI Agent Engine 向けエージェントです。

## 何ができるか
- Gmail から SIDfm 通知メール取得
- SBOM（BigQuery または Sheets）で影響システム検索
- 担当者マッピングで通知先特定
- Google Chat へカード通知
- Google Chat メンション対話（Chatアプリ経由）
- Google Chat の Gmail 投稿メッセージを自動解析して同一スレッド返信
- BigQuery へ対応履歴保存

## 構成
- `agent/`: Agent Engine 本体（ツール実装含む）
- `chat_webhook/`: Google Chat メンション受信Webhook
- `workspace_events_webhook/`: Google Workspace Events (Chatリアクション) 受信Webhook
- `live_gateway/`: リアルタイム対話ゲートウェイ（任意）
- `web/`: Web UI（任意）
- `test_dialog_agent/`: A2A疎通確認用の最小テスト対話エージェント
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

このスクリプトで API 有効化、必要 Secret 作成、BigQuery テーブル作成、Agent/Live Gateway/Chat Webhook などのデプロイまで実行します。
また、`vuln-agent-workspace-events-webhook` もデプロイされ、Workspace Events API の Pub/Sub Push 先に利用できます。

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

A2A統合テスト（任意）:
```bash
export RUN_A2A_INTEGRATION_TEST=1
export REMOTE_AGENT_TEST="projects/<PROJECT>/locations/<LOCATION>/reasoningEngines/<AGENT_ID>"
python -m unittest -v test_a2a_integration.py
```

## Entra ID SSO (OIDC)
Live Gateway は OIDC 認証を有効化できます（Entra ID 対応）。

必要環境変数（`live_gateway`）:
- `OIDC_ENABLED=true`
- `OIDC_TENANT_ID=<entra-tenant-id>`
- `OIDC_CLIENT_ID=<app-registration-client-id>`
- `OIDC_CLIENT_SECRET=<client-secret>`
- `OIDC_REDIRECT_URI=https://<live-gateway-domain>/auth/callback`
- `OIDC_SESSION_SECRET=<32bytes以上のランダム文字列>`

任意:
- `OIDC_SCOPES`（デフォルト: `openid profile email`）
- `OIDC_ISSUER`（未指定時は tenant から自動生成）

動作:
- `/auth/login` で Entra ID へリダイレクト
- `/auth/callback` でログイン完了し、セッションCookieを発行
- `/`（UI本体）, `/app.js`, `/style.css` は未認証時 `/login` にリダイレクト
- `/ws` は認証済みセッションがないと接続拒否

段階導入:
- `OIDC_ENABLED=false`（デフォルト）なら従来どおり未認証でもUIにアクセス可能
- `OIDC_ENABLED=true` に切り替えた時点でUIとWebSocket保護が有効化

監査ログ（ユーザー別チャット追跡）:
- Live Gateway は `chat_audit` ログをCloud Loggingへ出力
- 主要フィールド: `user_sub`, `user_email`, `request_id`, `event`, `message`, `response_text`
- 例:
```bash
gcloud run services logs read vuln-agent-live-gateway \
  --region=asia-northeast1 \
  --limit=200 \
  --filter='textPayload:"chat_audit"'
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
gcloud functions logs read vuln-agent-chat-webhook --region=asia-northeast1 --limit=20
gcloud functions logs read vuln-agent-workspace-events-webhook --region=asia-northeast1 --limit=20
```

## ツール一覧（Agent）
- Gmail: `get_sidfm_emails`, `get_unread_emails`, `mark_email_as_read`, `check_gmail_connection`
- SBOM/担当者: `search_sbom_by_purl`, `search_sbom_by_product`, `get_affected_systems`, `get_owner_mapping`
- SBOM一覧: `get_sbom_contents`（SBOM内容の先頭N件を返す）
- SBOM細粒度:
  - `list_sbom_package_types`
  - `count_sbom_packages_by_type`
  - `list_sbom_packages_by_type`
  - `list_sbom_package_versions`
  - `get_sbom_entry_by_purl`
- Chat: `send_vulnerability_alert`, `send_simple_message`, `check_chat_connection`, `list_space_members`
  - `send_vulnerability_alert` は定型フォーマット通知（対象機器/脆弱性リンク/CVSS/依頼内容/対応完了目標）に対応
  - 対応期限は CVSS・公開/内部リソース・悪用実績/Exploit 公開有無ルールを優先
- 履歴: `log_vulnerability_history`
- A2A: `register_remote_agent`, `register_master_agent`, `call_remote_agent`, `call_master_agent`, `list_registered_agents`, `create_jira_ticket_request`, `create_approval_request`, `create_master_agent_handoff_request`
- 権限可視化/柔軟参照: `get_runtime_capabilities`, `inspect_bigquery_capabilities`, `list_bigquery_tables`, `run_bigquery_readonly_query`
- Web参照: `web_search`, `fetch_web_content`
- 脆弱性インテリジェンス: `get_nvd_cve_details`, `search_osv_vulnerabilities`
- 細粒度ツール（横断）:
  - Gmail: `list_sidfm_email_subjects`, `list_unread_email_ids`, `get_email_preview_by_id`
  - Chat: `get_chat_space_info`, `list_chat_member_emails`
  - 履歴/A2A: `build_history_record_preview`, `list_registered_agent_ids`, `get_registered_agent_details`, `save_vulnerability_history_minimal`
  - Capability/Web/Intel: `get_configured_bigquery_tables`, `check_bigquery_readability_summary`, `list_web_search_urls`, `get_web_content_excerpt`, `get_nvd_cvss_summary`, `list_osv_vulnerability_ids`

## 回答品質を上げる設定
- モデルは `AGENT_MODEL`（または Secret `vuln-agent-model-name`）で上書き可能  
  例: `gemini-2.5-pro`
- Chat Webhook / Live Gateway でリクエスト単位にモデルを使い分ける場合:
  - `AGENT_RESOURCE_NAME_FLASH`（Secret: `vuln-agent-resource-name-flash`）
  - `AGENT_RESOURCE_NAME_PRO`（Secret: `vuln-agent-resource-name-pro`）
  - `MODEL_ROUTING_ENABLED=true`（既定）
  - `MODEL_ROUTING_SCORE_THRESHOLD=4`（推奨）
- 推奨運用: Flash 側 Agent は `Gemini 3 Flash`、Pro 側 Agent は `Gemini 3 Pro` で別々にデプロイし、上記2つの Resource Name を設定
- 最新情報が必要な質問は、エージェントが `web_search` / `fetch_web_content` を使って根拠確認して回答します。
- 通常回答は `結論 / 根拠 / 不確実性 / 次アクション` の固定フォーマットで返すように指示済みです。
- 大きい依頼に対しては、細粒度ツールを段階的に組み合わせて回答するよう指示済みです。

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
- `docs/SETUP_CHAT_INTERACTIVE.md`
- `docs/SETUP_WORKSPACE_EVENTS.md`
- `docs/SETUP_A2A.md`
- `docs/EXTENSION_SIDEPANEL_BACKLOG.md`（ブラウザ拡張の開発予定）
