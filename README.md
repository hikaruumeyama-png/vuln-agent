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

## セットアップ概要

詳しい手順は `docs/` 内のガイドを参照してください。

- Gmail OAuth設定: `docs/SETUP_GMAIL.md`
- Google Chat設定: `docs/SETUP_CHAT.md`
- Cloud Scheduler設定: `docs/SETUP_SCHEDULER.md`
- A2A連携設定: `docs/SETUP_A2A.md`
- Live Gateway + Web UI: `docs/LIVE_VOICE_SETUP.md`

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
