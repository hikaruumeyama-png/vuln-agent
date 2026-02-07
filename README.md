# 脆弱性管理AIエージェント

SIDfmの脆弱性通知メールを自動で解析し、SBOMと突合して担当者へ通知する **Vertex AI Agent Engine** 向けのAIエージェントです。Gmail / Google Sheets / Google Chat を使った運用を前提に、定期実行のスキャンや音声/チャットUI連携にも対応しています。

**ローカル環境は不要**です。Cloud Shell と Cloud Build だけでセットアップ・運用できます。

## 主な機能

- **脆弱性検知**: SIDfmメールを監視して未読の通知を取得
- **影響分析**: SBOMと照合して影響システムを特定
- **担当者特定**: 担当者マッピングのパターンから自動選定
- **優先度判定**: CVSSスコアと条件で期限を決定
- **担当者通知**: Google Chatにカード形式でアラート送信
- **A2A連携**: Jira / 承認 / パッチ / レポートなど別エージェント連携
- **音声/チャットUI**: Gemini Live API を使ったリアルタイム対話
- **対応履歴**: BigQueryへの自動記録

## アーキテクチャ

すべてのコンポーネントが Google Cloud 上で動作します。

```
┌─────────────────────────────────────────────────────────────────┐
│                     Google Cloud Platform                       │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │          Vertex AI Agent Engine                         │    │
│  │  ┌─────────────────────────────────────────────────┐    │    │
│  │  │  Vulnerability Management Agent (gemini-2.5)    │    │    │
│  │  │                                                 │    │    │
│  │  │  Gmail Tools │ Sheets Tools │ Chat Tools        │    │    │
│  │  │  A2A Tools   │ History Tools                    │    │    │
│  │  └─────────────────────────────────────────────────┘    │    │
│  └────────────┬───────────────┬───────────────┬────────────┘    │
│               │               │               │                 │
│          Gmail API      Google Sheets    Google Chat             │
│         (SIDfm監視)     (SBOM/担当者)     (通知送信)             │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │  Cloud Run   │  │Cloud Functions│  │Cloud Storage │          │
│  │ Live Gateway │  │  Scheduler   │  │   Web UI     │          │
│  │ (WebSocket)  │  │  (定期実行)  │  │  (静的配信)  │          │
│  └──────┬───────┘  └──────┬───────┘  └──────────────┘          │
│         │                 │                                     │
│  ┌──────┴─────┐  ┌───────┴──────┐  ┌──────────────┐           │
│  │Gemini Live │  │Cloud Scheduler│  │  BigQuery    │           │
│  │   API      │  │  (cron)      │  │  (対応履歴)  │           │
│  └────────────┘  └──────────────┘  └──────────────┘           │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Secret Manager (認証情報・設定値)                      │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Cloud Build (CI/CD パイプライン)                       │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## ディレクトリ構成

```
.
├── agent/                 # Vertex AI Agent Engine 向けエージェント
│   ├── agent.py             # エージェント定義 (システムプロンプト + ツール登録)
│   ├── .env.example         # 環境変数テンプレート
│   └── tools/               # Gmail / Sheets / Chat / A2A / History ツール群
├── scheduler/               # Cloud Functions 定期実行エントリーポイント
├── live_gateway/            # Cloud Run WebSocket + Gemini Live API ゲートウェイ
│   ├── Dockerfile
│   ├── app.py
│   └── live_api.py
├── web/                     # ブラウザ用チャット / 音声UI
├── docs/                    # 個別セットアップガイド
├── setup_cloud.sh           # Cloud Shell 用 初回セットアップスクリプト
├── cloudbuild.yaml          # Cloud Build CI/CD パイプライン定義
├── deploy.sh                # (レガシー) ローカル ADK CLI デプロイ
├── deploy_python.py         # (レガシー) Python SDK デプロイ
└── setup_gmail_oauth.py     # Gmail OAuth トークン生成
```

## クイックスタート (Cloud Shell)

### 前提条件

- Google Cloud プロジェクト (課金有効)
- Google Workspace の管理者権限 (Gmail ドメイン委任を使う場合)
- SIDfm のメール通知が有効

### Step 1: Cloud Shell でリポジトリをクローン

```bash
gcloud config set project YOUR_PROJECT_ID
git clone https://github.com/YOUR_ORG/vuln-agent.git
cd vuln-agent
```

### Step 2: セットアップスクリプトを実行

```bash
bash setup_cloud.sh
```

対話形式で以下の情報を入力します:

| 項目 | 説明 | 例 |
|------|------|----|
| Gmail ユーザーメール | Workspace 委任対象のメール | `security@example.com` |
| SIDfm 送信元メール | SIDfm の送信元アドレス | `noreply@sidfm.com` |
| SBOM スプレッドシート ID | Google Sheets の ID | `1BxiMVs0XRA5...` |
| Chat スペース ID | 通知先スペース | `spaces/AAAA_BBBBB` |
| Gemini API Key | Live Gateway 用 (任意) | `AIza...` |

スクリプトが以下をすべて自動で実行します:

1. API の有効化 (Vertex AI, Gmail, Sheets, Chat, BigQuery 等)
2. サービスアカウントの作成と IAM ロール付与
3. Secret Manager へのシークレット登録
4. Cloud Storage バケットの作成
5. BigQuery データセット / テーブルの作成
6. Agent Engine のデプロイ
7. Live Gateway (Cloud Run) のデプロイ
8. Scheduler (Cloud Functions + Cloud Scheduler) のデプロイ
9. Web UI (Cloud Storage) のデプロイ

### Step 3: Google Workspace のドメイン委任を設定

1. [Google Workspace 管理コンソール](https://admin.google.com) を開く
2. **セキュリティ** → **API Controls** → **ドメイン全体の委任**
3. Vertex AI のサービスエージェントを追加し、以下のスコープを付与:
   - `https://www.googleapis.com/auth/gmail.modify`
   - `https://www.googleapis.com/auth/spreadsheets.readonly`
   - `https://www.googleapis.com/auth/chat.bot`

### Step 4: SBOM スプレッドシートの共有

スプレッドシートの共有設定で、サービスアカウントに**閲覧者**権限を付与します:

```
vuln-agent-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com
```

### Step 5: 動作確認

Cloud Console からテスト:

```
https://console.cloud.google.com/vertex-ai/agents?project=YOUR_PROJECT_ID
```

## CI/CD (Cloud Build)

初回セットアップ後、コードを変更したら Cloud Build で再デプロイできます。

### 手動実行

```bash
gcloud builds submit --config cloudbuild.yaml
```

### Git push 連動 (トリガー登録)

```bash
gcloud builds triggers create github \
  --repo-name=vuln-agent \
  --repo-owner=YOUR_ORG \
  --branch-pattern="^main$" \
  --build-config=cloudbuild.yaml
```

Cloud Build は以下を自動で実行します:

1. Secret Manager から `.env` を生成
2. Agent Engine を再デプロイ
3. Live Gateway (Cloud Run) を再デプロイ
4. Scheduler (Cloud Functions) を再デプロイ
5. Web UI (Cloud Storage) を更新

## Secret Manager に登録されるシークレット一覧

| シークレット名 | 用途 | 必須 |
|---------------|------|------|
| `vuln-agent-gmail-user` | Gmail ドメイン委任ユーザー | はい |
| `vuln-agent-sidfm-sender` | SIDfm 送信元メール | はい |
| `vuln-agent-sbom-spreadsheet-id` | SBOM スプレッドシート ID | はい |
| `vuln-agent-sbom-sheet-name` | SBOM シート名 | いいえ (デフォルト: SBOM) |
| `vuln-agent-owner-sheet-name` | 担当者マッピングシート名 | いいえ (デフォルト: 担当者マッピング) |
| `vuln-agent-chat-space-id` | Google Chat スペース ID | はい |
| `vuln-agent-gemini-api-key` | Gemini API Key (Live Gateway 用) | Live Gateway を使う場合 |
| `vuln-agent-bq-table-id` | BigQuery テーブル ID | いいえ (自動生成) |
| `vuln-agent-resource-name` | Agent Engine リソース名 (自動保存) | 自動 |

シークレットの値を更新するには:

```bash
echo -n "NEW_VALUE" | gcloud secrets versions add SECRET_NAME --data-file=-
```

## コンポーネント詳細

### Agent Engine (`agent/`)

`agent.py` がシステムプロンプトとツール定義をまとめ、`gemini-2.5-flash` モデルで動作します。

ツール一覧:

| ツール | 説明 |
|-------|------|
| `get_sidfm_emails` | SIDfm 未読メール取得 |
| `get_unread_emails` | 任意クエリでメール検索 |
| `mark_email_as_read` | メールを既読に |
| `check_gmail_connection` | Gmail 接続確認 |
| `search_sbom_by_purl` | PURL で SBOM 検索 |
| `search_sbom_by_product` | 製品名でSBOM検索 |
| `get_affected_systems` | CVE 影響システム特定 |
| `get_owner_mapping` | 担当者マッピング確認 |
| `send_vulnerability_alert` | Chat アラート送信 |
| `send_simple_message` | Chat テキスト送信 |
| `log_vulnerability_history` | BigQuery 履歴記録 |
| `register_remote_agent` | A2A エージェント登録 |
| `call_remote_agent` | A2A エージェント呼出 |
| `create_jira_ticket_request` | Jira チケットリクエスト構築 |
| `create_approval_request` | 承認リクエスト構築 |

### Scheduler (`scheduler/`)

Cloud Scheduler → Cloud Functions → Agent Engine の構成で定期スキャンを実行します。

- エントリーポイント: `run_vulnerability_scan`
- デフォルトスケジュール: 毎時 (変更は Cloud Console から可能)

### Live Gateway (`live_gateway/`)

Cloud Run 上で WebSocket サーバーを動作させ、以下を処理します:

- テキストメッセージ → Agent Engine へ転送
- 音声ストリーム → Gemini Live API で書き起こし → Agent Engine
- Agent 応答 → Gemini Live API でTTS → クライアントへ

### Web UI (`web/`)

Cloud Storage から配信される静的 HTML/JS/CSS です。
ブラウザから WebSocket で Live Gateway に接続し、テキスト / 音声対話が可能です。

## SBOM スプレッドシートの構成

### SBOM シート

| type | name | version | release | purl |
|------|------|---------|---------|------|
| maven | log4j-core | 2.14.1 | | pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1 |
| npm | express | 4.17.1 | | pkg:npm/express@4.17.1 |

### 担当者マッピングシート

| pattern | system_name | owner_email | owner_name | notes |
|---------|------------|-------------|------------|-------|
| pkg:maven/org.apache.logging.* | ログ基盤 | tanaka@example.com | 田中太郎 | Log4j 関連 |
| pkg:npm/* | フロントエンド | suzuki@example.com | 鈴木花子 | |
| * | インフラ | admin@example.com | 管理者 | デフォルト |

パターンマッチングは具体的なパターンが優先されます。`*` はデフォルトの担当者です。

## 優先度判定基準

| 優先度 | 条件 | 対応期限 |
|--------|------|----------|
| 緊急 | CVSS 9.0 以上、または既に悪用確認 | 24 時間以内 |
| 高 | CVSS 7.0-8.9、リモート攻撃可能 | 3 日以内 |
| 中 | CVSS 4.0-6.9 | 1 週間以内 |
| 低 | CVSS 4.0 未満 | 1 ヶ月以内 |

## Gmail 認証方式

### 方式 A: Google Workspace ドメイン委任 (推奨)

サービスアカウントに Gmail へのアクセスを委任します。`setup_cloud.sh` で `GMAIL_USER_EMAIL` を設定すれば自動で構成されます。

### 方式 B: 個人 Gmail (OAuth)

個人 Gmail の場合は OAuth トークンが必要です。

```bash
python setup_gmail_oauth.py
```

生成されたトークンを Secret Manager に登録し、Agent Engine の環境変数 `GMAIL_OAUTH_TOKEN` に設定します。

## A2A 連携 (Agent-to-Agent)

環境変数でリモートエージェントのリソース名を設定すると、モジュール読み込み時に自動登録されます。

```bash
# Secret Manager に登録
echo -n "projects/xxx/locations/xxx/reasoningEngines/xxx" | \
  gcloud secrets create vuln-agent-remote-jira --data-file=-
```

## トラブルシューティング

### Agent Engine のデプロイに失敗する

```bash
# API が有効か確認
gcloud services list --enabled --filter="aiplatform"

# サービスアカウントの権限を確認
gcloud projects get-iam-policy YOUR_PROJECT_ID \
  --flatten="bindings[].members" \
  --filter="bindings.members:vuln-agent-sa"
```

### Gmail 接続エラー

```bash
# ドメイン委任が正しく設定されているか確認
# → Google Workspace 管理コンソール → セキュリティ → API Controls
```

### Live Gateway が起動しない

```bash
# Cloud Run のログを確認
gcloud run services logs read vuln-agent-live-gateway --region=asia-northeast1

# Gemini API Key が設定されているか確認
gcloud secrets versions access latest --secret=vuln-agent-gemini-api-key
```

### シークレットの値を変更したい

```bash
# 値を更新
echo -n "NEW_VALUE" | gcloud secrets versions add vuln-agent-xxx --data-file=-

# Agent Engine に反映するには再デプロイ
gcloud builds submit --config cloudbuild.yaml
```

## ライセンス

このリポジトリのライセンスは現時点で明示されていません。必要に応じて追加してください。
