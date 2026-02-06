# 🛡️ 脆弱性管理AIエージェント

SIDfmの脆弱性通知メールを自動で解析し、SBOMと突合して担当者へ通知する **Vertex AI Agent Engine** 向けのAIエージェントです。Gmail / Google Sheets / Google Chat を使った運用を前提に、定期実行のスキャンや音声/チャットUI連携にも対応しています。

## 主な機能

- **脆弱性検知**: SIDfmメールを監視して未読の通知を取得
- **影響分析**: SBOMと照合して影響システムを特定
- **担当者特定**: 担当者マッピングのパターンから自動選定
- **優先度判定**: CVSSスコアと条件で期限を決定
- **担当者通知**: Google Chatにカード形式でアラート送信
- **A2A連携**: Jira / 承認 / パッチ / レポートなど別エージェント連携
- **音声/チャットUI**: Gemini Live API を使ったリアルタイム対話

## アーキテクチャ概要

```
┌─────────────────────────────────────────────────────────────┐
│              Vertex AI Agent Engine                         │
│  ┌───────────────────────────────────────────────────────┐  │
│  │     Vulnerability Management Agent (gemini-2.5-flash) │  │
│  │                                                       │  │
│  │   ┌───────────┐  ┌───────────┐  ┌───────────┐        │  │
│  │   │Gmail Tools│  │Sheets Tool│  │Chat Tools │        │  │
│  │   └─────┬─────┘  └─────┬─────┘  └─────┬─────┘        │  │
│  └─────────┼──────────────┼──────────────┼──────────────┘  │
└────────────┼──────────────┼──────────────┼──────────────────┘
             ▼              ▼              ▼
        Gmail API     Google Sheets    Google Chat
        (SIDfm監視)   (SBOM/担当者)    (通知送信)
```

### 音声/チャットUIの追加構成

```
┌─────────────────────────────────────────────────────────────┐
│                       Web Client                             │
│   - text chat UI / mic capture (Barge-in対応)                │
└───────────────▲─────────────────────────────────────────────┘
                │ WebSocket
┌───────────────┴─────────────────────────────────────────────┐
│                Live Gateway (Cloud Run)                      │
│   - Gemini Live API セッション管理                           │
│   - Agent Engine へのテキスト問い合わせ                      │
└───────────────▲─────────────────────────────────────────────┘
                │ Vertex AI SDK
┌───────────────┴─────────────────────────────────────────────┐
│              Vertex AI Agent Engine                          │
└─────────────────────────────────────────────────────────────┘
```

## ディレクトリ構成

```
.
├── agent/                # Vertex AI Agent Engine向けエージェント
│   ├── agent.py           # エージェント定義とプロンプト
│   └── tools/             # Gmail / Sheets / Chat / A2A ツール群
├── scheduler/             # Cloud Scheduler からの定期実行
├── live_gateway/          # WebSocket + Gemini Live API ゲートウェイ
├── web/                   # ブラウザ用チャットUI
├── docs/                  # セットアップガイド
├── deploy.sh              # ADK CLIによるデプロイスクリプト
├── deploy_python.py       # Pythonによるデプロイスクリプト
└── setup_gmail_oauth.py   # Gmail OAuthトークン生成
```

## 主要コンポーネント

### 1) エージェント本体 (`agent/`)
- `agent.py` がシステムプロンプト、ツール定義、A2A連携をまとめています。
- Gmail / Sheets / Chat / A2A 用ツールをFunctionToolとして登録。

### 2) Gmail連携 (`agent/tools/gmail_tools.py`)
- OAuthトークン / ドメイン委任 / デフォルト認証の自動判定。
- SIDfm未読メールを取得して解析します。

### 3) Sheets連携 (`agent/tools/sheets_tools.py`)
- SBOMと担当者マッピングを読み込み、PURLマッチで担当者を特定。
- 5分のキャッシュを持つため、頻繁な呼び出しでも高速です。

### 4) Chat連携 (`agent/tools/chat_tools.py`)
- Google Chatへのアラート送信とカード描画。
- 重大度に応じた対応期限を自動計算します。

### 5) A2A連携 (`agent/tools/a2a_tools.py`)
- 他エージェントの登録・呼び出しのためのヘルパー。
- Jiraチケット作成や承認申請のリクエスト構築にも対応。

### 6) 定期実行 (`scheduler/`)
- Cloud Scheduler → Cloud Functions → Agent Engine の構成で定期スキャン。
- `run_vulnerability_scan` がエントリーポイントです。

### 7) Live Gateway (`live_gateway/`)
- WebSocket経由でテキスト/音声を受け、Agent Engineに転送。
- Gemini Live APIを使った音声書き起こし・音声応答を管理。

### 8) Web UI (`web/`)
- ブラウザからWebSocketで接続し、テキスト/音声対話が可能。
- 音声のバージイン（割り込み）にも対応。

## セットアップ & デプロイ前チェックリスト

以下のチェックリストを満たしていれば、Google Cloud へのデプロイ後も問題なく動作します。

### 1) 必須の環境変数

`agent/.env` に設定します（`deploy.sh` がテンプレートを生成します）。

```bash
# 共通
GCP_PROJECT_ID=your-project-id
GCP_LOCATION=asia-northeast1
AGENT_RESOURCE_NAME=projects/your-project/locations/asia-northeast1/reasoningEngines/AGENT_ID

# Gmail（OAuth or Workspace）
GMAIL_OAUTH_TOKEN=...               # 個人Gmailのときのみ
GMAIL_USER_EMAIL=security@domain    # Workspace委任のときのみ
SIDFM_SENDER_EMAIL=noreply@sidfm.com

# Sheets
SBOM_SPREADSHEET_ID=your-spreadsheet-id
SBOM_SHEET_NAME=SBOM
OWNER_SHEET_NAME=担当者マッピング

# Chat
DEFAULT_CHAT_SPACE_ID=spaces/AAAA_BBBBB

# BigQuery（対応履歴の保存）
BQ_HISTORY_TABLE_ID=your-project.your_dataset.incident_response_history

# Live API
GEMINI_API_KEY=your-gemini-api-key
GEMINI_LIVE_MODEL=gemini-2.0-flash-live-001

# A2A（任意）
REMOTE_AGENT_JIRA=projects/your-project/locations/us-central1/reasoningEngines/jira-agent-id
REMOTE_AGENT_APPROVAL=projects/your-project/locations/us-central1/reasoningEngines/approval-agent-id
REMOTE_AGENT_PATCH=projects/your-project/locations/us-central1/reasoningEngines/patch-agent-id
REMOTE_AGENT_REPORT=projects/your-project/locations/us-central1/reasoningEngines/report-agent-id
```

### 2) 必要なAPI/権限

最小構成で必要なAPI:

- Gmail API
- Google Sheets API
- Google Chat API
- Vertex AI / Agent Engine
- (Live Gateway を使う場合) Gemini Live API

サービスアカウントに必要な権限例:

- `roles/aiplatform.user`（Agent Engine 呼び出し）
- `roles/iam.serviceAccountUser`（Cloud Functions/Runなどでの実行）
- Gmail/Chat/Sheets APIに必要なアクセス権

### 3) 疎通確認（デプロイ後）

```bash
./test_agent.sh "Gmailへの接続を確認して"
./test_agent.sh "Chat接続を確認して"
./test_agent.sh "未読メールを3件取得して"
```

---

## RAG / ファインチューニングの追加アイデア

既存のフロー（Gmail → SBOM/担当者 → Chat通知）にプラスアルファで、RAGやファインチューニングを活用する場合の方向性です。

### 1) RAG（検索拡張生成）

**目的**: 脆弱性通知に対して、より根拠のある説明や判断材料を添える。

- **追加するデータ源の例**
  - 製品ごとの運用手順・SOP（Docs/Confluence）
  - 過去インシデントの対応履歴（チケット/レポート/DB）
  - 社内の例外ポリシー（例: 週末は対応方針が異なる など）
- **具体的な使い方**
  - エージェントが「対象PURL / 影響システム」を特定した後に、
    **RAGで「対応手順」「例外ルール」「過去の類似対応」を取得**
  - Chat通知カードに「参考リンク」や「推奨手順」を自動追記
- **最低限の実装パターン**
  - 既存のSheets/SBOM参照に加えて、社内ドキュメントや対応履歴を
    **ベクタDB（Vertex AI Matching Engine など）に格納**し検索
  - エージェントのツールとして `search_knowledge_base()` を追加し、
    返却結果をプロンプトに差し込む
- **対応履歴をBigQueryで蓄積する場合の考え方**
  - **方向性は妥当**。対応履歴をデータベースに集約することで、
    人間の検索・集計にも使え、RAGの検索元にもできる
  - 典型的には「BigQueryに格納 →（必要に応じて）ベクトル化して検索」
    の2段構成にするのが扱いやすい
  - BigQuery自体は分析・集計に強いので、**人間向けのナレッジベース**
    としても有効。RAG向けには、説明文や要約を別カラムとして持つと便利
  - まずは **BigQueryを単一の情報源（SSOT）** にし、
    RAG用のインデックスは必要に応じて派生させるのが運用しやすい
- **本リポジトリでの実装内容（対応履歴の保存）**
  - `log_vulnerability_history()` ツールで、対応履歴をBigQueryに行追加
  - `send_vulnerability_alert()` の送信成功時に履歴保存を自動実行
  - `BQ_HISTORY_TABLE_ID` が未設定の場合は保存をスキップ

### 2) ファインチューニング

**目的**: 文章のトーンや判断基準を社内ルールに合わせて安定化する。

- **向いている用途**
  - Chat通知の文面（緊急度ごとの言い回し）
  - 期限や優先度の判定における「組織の暗黙知」の反映
- **実施ステップの例**
  - 過去の通知文・対応結果から
    **「入力（脆弱性 + 影響情報）」→「出力（推奨アクション）」**の
    形式で学習データを作成
  - 低頻度で良いので、組織のレビュー済みデータに限定して学習
- **運用のヒント**
  - まずは RAG で根拠（ポリシー・手順）を参照し、
    「表現の一貫性」はファインチューニングで補う、という併用が安定

---

## セットアップ詳細ガイド（統合版）

以下は `docs/` 内のセットアップガイドを README に統合したものです。

### 必須の環境変数（例）

`agent/.env` に設定します（`deploy.sh` がテンプレートを生成します）。

```
GMAIL_USER_EMAIL=security-team@your-domain.com
SIDFM_SENDER_EMAIL=noreply@sidfm.com
SBOM_SPREADSHEET_ID=your-spreadsheet-id
SBOM_SHEET_NAME=SBOM
OWNER_SHEET_NAME=担当者マッピング
DEFAULT_CHAT_SPACE_ID=spaces/your-space-id
```

## Gmail連携（個人Gmail）セットアップ

### Step 1: OAuth クライアントIDの作成

1. https://console.cloud.google.com/apis/credentials
2. 「認証情報を作成」→「OAuth クライアントID」
3. アプリケーションの種類: **デスクトップアプリ**
4. 名前: `vuln-agent-gmail`
5. JSON をダウンロードして `credentials.json` にリネーム

```bash
mv ~/Downloads/client_secret_xxx.json /path/to/vuln-agent/credentials.json
```

### Step 2: Gmail API 有効化

https://console.cloud.google.com/apis/library/gmail.googleapis.com を有効化

### Step 3: OAuth 同意画面の設定

1. https://console.cloud.google.com/apis/credentials/consent
2. ユーザータイプ: **外部**（個人Gmailの場合）
3. スコープに `https://www.googleapis.com/auth/gmail.modify` を追加
4. テストユーザーに利用するGmailを追加（必須）

### Step 4: セットアップスクリプトの実行

```bash
python setup_gmail_oauth.py
```

### Step 5: 再デプロイ

```bash
./deploy.sh
```

---

## Google Chat 通知セットアップ

### Step 1: Chat API 有効化

https://console.cloud.google.com/apis/library/chat.googleapis.com を有効化

### Step 2: Chat Bot 設定

https://console.cloud.google.com/apis/api/chat.googleapis.com/hangouts-chat

| 項目 | 値 |
|------|-----|
| アプリ名 | 脆弱性管理Bot |
| 説明 | 脆弱性通知を送信するBot |
| スペースとグループの会話でアプリを有効化 | ✅ |
| 1:1 でのメッセージの受信 | ✅（任意） |
| 公開設定 | 特定ユーザーのみ |

### Step 3: スペースに Bot を追加

Google Chat上でスペースを作成し、Botを追加してください。

### Step 4: スペースIDを取得

URLの `room/` 以降がIDです。環境変数には `spaces/XXXX` 形式で設定します。

### Step 5: 環境変数追加 & 再デプロイ

```bash
DEFAULT_CHAT_SPACE_ID=spaces/AAAA_BBBBB
./deploy.sh
```

---

## 定期実行（Cloud Scheduler + Cloud Functions）

### 簡単セットアップ（推奨）

```bash
gcloud ai reasoning-engines list --location=asia-northeast1
./setup_scheduler.sh
```

### 手動セットアップ

1) API有効化

```bash
gcloud services enable cloudfunctions.googleapis.com
gcloud services enable cloudscheduler.googleapis.com
gcloud services enable cloudbuild.googleapis.com
gcloud services enable run.googleapis.com
```

2) サービスアカウント作成と権限付与

```bash
PROJECT_ID=$(gcloud config get-value project)
gcloud iam service-accounts create vuln-agent-scheduler-sa \
  --display-name="Vulnerability Agent Scheduler"
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:vuln-agent-scheduler-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/aiplatform.user"
```

3) Cloud Functions デプロイ

```bash
cd scheduler
gcloud functions deploy vuln-agent-scheduler \
  --gen2 \
  --runtime=python312 \
  --region=asia-northeast1 \
  --source=. \
  --entry-point=run_vulnerability_scan \
  --trigger-http \
  --allow-unauthenticated=false \
  --service-account="vuln-agent-scheduler-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --set-env-vars="GCP_PROJECT_ID=${PROJECT_ID},GCP_LOCATION=asia-northeast1,AGENT_RESOURCE_NAME=projects/${PROJECT_ID}/locations/asia-northeast1/reasoningEngines/YOUR_AGENT_ID" \
  --memory=512MB \
  --timeout=540s
cd ..
```

4) Cloud Scheduler ジョブ作成

```bash
FUNCTION_URL=$(gcloud functions describe vuln-agent-scheduler \
  --region=asia-northeast1 \
  --format='value(serviceConfig.uri)')
gcloud scheduler jobs create http vuln-agent-scan \
  --location=asia-northeast1 \
  --schedule="0 * * * *" \
  --time-zone="Asia/Tokyo" \
  --uri="$FUNCTION_URL" \
  --http-method=POST \
  --oidc-service-account-email="vuln-agent-scheduler-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --oidc-token-audience="$FUNCTION_URL"
```

---

## A2A連携（Agent-to-Agent）

### 1) 連携エージェントのデプロイ

例: Jira連携エージェント

```python
from google.adk import Agent
from google.adk.tools import FunctionTool

def create_jira_ticket(...):
    ...

agent = Agent(
    name="jira_agent",
    model="gemini-2.5-flash",
    instruction="Jiraチケットを作成するエージェント",
    tools=[FunctionTool(create_jira_ticket)],
)
```

```bash
adk deploy --project=YOUR_PROJECT --location=us-central1
```

### 2) 環境変数の設定

```bash
REMOTE_AGENT_JIRA=projects/your-project/locations/us-central1/reasoningEngines/jira-agent-id
REMOTE_AGENT_APPROVAL=projects/your-project/locations/us-central1/reasoningEngines/approval-agent-id
REMOTE_AGENT_PATCH=projects/your-project/locations/us-central1/reasoningEngines/patch-agent-id
REMOTE_AGENT_REPORT=projects/your-project/locations/us-central1/reasoningEngines/report-agent-id
```

### 3) 動作確認

```bash
./test_agent.sh "登録されているエージェントを教えて"
```

---

## Live API + Web UI（音声対話）

### 1) Live Gateway をローカル起動

```bash
cd live_gateway
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export GCP_PROJECT_ID=YOUR_PROJECT_ID
export GCP_LOCATION=asia-northeast1
export AGENT_RESOURCE_NAME=projects/PROJECT/locations/asia-northeast1/reasoningEngines/AGENT_ID
export GEMINI_API_KEY=YOUR_API_KEY
export GEMINI_LIVE_MODEL=gemini-2.0-flash-live-001

python app.py
```

### 2) Web UI を起動

```bash
cd web
python -m http.server 8081
```

ブラウザで `http://localhost:8081` を開き、Gateway URL に
`ws://localhost:8000/ws` を指定して接続します。

### 3) Cloud Run へデプロイ

```bash
cd live_gateway
gcloud run deploy vuln-agent-live-gateway \
  --source=. \
  --region=asia-northeast1 \
  --set-env-vars=GCP_PROJECT_ID=YOUR_PROJECT_ID,GCP_LOCATION=asia-northeast1,AGENT_RESOURCE_NAME=projects/PROJECT/locations/asia-northeast1/reasoningEngines/AGENT_ID,GEMINI_API_KEY=YOUR_API_KEY \
  --allow-unauthenticated
```

### 4) Web UI のホスティング（GCS例）

```bash
gsutil mb gs://YOUR_PROJECT_ID-live-ui
gsutil web set -m index.html -e index.html gs://YOUR_PROJECT_ID-live-ui
gsutil rsync -R web gs://YOUR_PROJECT_ID-live-ui
```

公開URLにアクセスし、Cloud Run の `wss://.../ws` を入力します。

---

## デプロイ

### ADK CLIでデプロイ

```bash
GCP_PROJECT_ID=your-project-id \
STAGING_BUCKET=gs://your-staging-bucket \
./deploy.sh
```

### Pythonでデプロイ

```bash
python deploy_python.py \
  --project your-project-id \
  --location asia-northeast1 \
  --staging-bucket gs://your-staging-bucket
```

## 動作確認

```bash
./test_agent.sh "Gmailへの接続を確認して"
```

## ライセンス

このリポジトリのライセンスは現時点で明示されていません。必要に応じて追加してください。
