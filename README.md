# 脆弱性管理AIエージェント

SIDfmの脆弱性通知メールを自動で解析し、SBOMと突合して担当者へ通知する **Vertex AI Agent Engine** 向けのAIエージェントです。Gmail / Google Sheets / Google Chat を使った運用を前提に、定期実行のスキャンや音声/チャットUI連携にも対応しています。

**ローカル環境は不要**です。以下の手順はすべて Google Cloud Shell 上でコマンドを入力するだけで完了します。

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
│   ├── requirements.txt     # Agent Engine 上でのランタイム依存パッケージ
│   ├── .env.example         # 環境変数テンプレート
│   └── tools/               # Gmail / Sheets / Chat / A2A / History ツール群
├── scheduler/               # Cloud Functions 定期実行エントリーポイント
├── live_gateway/            # Cloud Run WebSocket + Gemini Live API ゲートウェイ
│   ├── Dockerfile
│   ├── app.py
│   └── live_api.py
├── web/                     # ブラウザ用チャット / 音声UI
├── docs/                    # 個別セットアップガイド
├── setup_cloud.sh           # Cloud Shell 用 初回セットアップスクリプト (自動化)
├── cloudbuild.yaml          # Cloud Build CI/CD パイプライン定義
├── deploy_python.py         # (レガシー) Python SDK デプロイ
└── setup_gmail_oauth.py     # Gmail OAuth トークン生成 (個人Gmail用)
```

---

## デプロイ手順

以降の手順はすべて **Google Cloud Shell** で実行します。
ブラウザで [Cloud Shell](https://shell.cloud.google.com) を開き、コマンドを上から順に貼り付けていくだけで完了します。

### 事前に用意するもの

デプロイ作業中に以下の情報を入力します。あらかじめ控えておいてください。

| 項目 | 説明 | 例 |
|------|------|----|
| Google Cloud プロジェクト ID | 課金が有効なプロジェクト | `my-project-123` |
| Gmail ユーザーメール | SIDfm メールを受信する Workspace メール | `security@example.com` |
| SIDfm 送信元メール | SIDfm の From アドレス | `noreply@sidfm.com` |
| SBOM スプレッドシート ID | Google Sheets の URL 中の ID 部分 | `1BxiMVs0XRA5nFMdK...` |
| Google Chat スペース ID | 通知を送信するスペース | `spaces/AAAA_BBBBB` |
| Gemini API Key *(任意)* | 音声UI (Live Gateway) を使う場合のみ | `AIza...` |

---

### Step 1: プロジェクトを設定してリポジトリを取得する

Cloud Shell が使用する GCP プロジェクトを指定し、このリポジトリをクローンします。
`YOUR_PROJECT_ID` は自分のプロジェクト ID に置き換えてください。

```bash
gcloud config set project YOUR_PROJECT_ID
git clone https://github.com/YOUR_ORG/vuln-agent.git
cd vuln-agent
```

---

### Step 2: セットアップスクリプトを実行する

以下の 1 コマンドで、Google Cloud 上の全コンポーネントをまとめてセットアップします。
途中で設定値の入力を求められるので、事前に用意した値を入力してください (デフォルト値がある項目はそのまま Enter で OK)。

```bash
bash setup_cloud.sh
```

> **このスクリプトが自動で実行する内容:**
>
> 1. **API の有効化** --- Vertex AI, Gmail, Sheets, Chat, BigQuery, Cloud Build, Cloud Functions, Cloud Scheduler, Cloud Run, Secret Manager, Artifact Registry の計 11 API を有効にします
> 2. **サービスアカウントの作成** --- `vuln-agent-sa` を作成し、Vertex AI / BigQuery / Secret Manager / Cloud Storage のロールを付与します。Cloud Build 用サービスアカウントにも必要な権限を追加します
> 3. **Secret Manager への設定値登録** --- 対話形式で入力した Gmail メール・スプレッドシート ID・Chat スペース ID などを Secret Manager に安全に保存します
> 4. **Cloud Storage バケットの作成** --- Web UI 配信用とステージング用の 2 つのバケットを作成します
> 5. **BigQuery テーブルの作成** --- 脆弱性対応履歴を記録する `vuln_agent.incident_response_history` テーブルを作成します
> 6. **Agent Engine のデプロイ** --- Secret Manager の値から `.env` を生成し、ADK CLI でエージェントを Vertex AI Agent Engine にデプロイします。デプロイ後のリソース名は自動的に Secret Manager に保存されます
> 7. **Live Gateway のデプロイ** --- WebSocket ゲートウェイを Cloud Run にデプロイします (Gemini API Key が登録済みの場合のみ)
> 8. **Scheduler のデプロイ** --- 定期スキャン用の Cloud Functions と、毎時実行の Cloud Scheduler ジョブを作成します
> 9. **Web UI のデプロイ** --- チャット/音声 UI を Cloud Storage に配信します

完了すると、デプロイされた各コンポーネントの URL が表示されます。

---

### Step 3: Google Workspace のドメイン委任を設定する

エージェントがサービスアカウント経由で Gmail / Sheets / Chat にアクセスするため、Google Workspace 管理者がドメイン全体の委任を設定します。

まず、Vertex AI サービスエージェントのクライアント ID を確認します。

```bash
gcloud iam service-accounts describe \
  service-$(gcloud projects describe $(gcloud config get-value project) --format='value(projectNumber)')@gcp-sa-aiplatform-re.iam.gserviceaccount.com \
  --format='value(uniqueId)'
```

表示された数値 ID を控えたら、以下の手順でドメイン委任を追加します。

1. ブラウザで [Google Workspace 管理コンソール](https://admin.google.com) を開く
2. **セキュリティ** → **アクセスとデータ管理** → **API の制御** → **ドメイン全体の委任** に移動
3. **「新しく追加」** をクリックし、上で控えたクライアント ID と以下のスコープを入力:

```
https://www.googleapis.com/auth/gmail.modify,https://www.googleapis.com/auth/spreadsheets.readonly,https://www.googleapis.com/auth/chat.bot
```

4. **「承認」** をクリック

---

### Step 4: SBOM スプレッドシートをサービスアカウントに共有する

エージェントが SBOM と担当者マッピングを読み取れるよう、スプレッドシートの共有設定を変更します。

まず、共有先のサービスアカウントのメールアドレスを確認します。

```bash
echo "vuln-agent-sa@$(gcloud config get-value project).iam.gserviceaccount.com"
```

1. ブラウザで SBOM スプレッドシートを開く
2. 右上の **「共有」** をクリック
3. 上で表示されたサービスアカウントのメールアドレスを入力し、**「閲覧者」** 権限で共有

> **スプレッドシートの構成:**
>
> SBOM シートには `type`, `name`, `version`, `release`, `purl` の列が必要です。
> 担当者マッピングシートには `pattern`, `system_name`, `owner_email`, `owner_name`, `notes` の列が必要です。
> 詳細は本 README 末尾の「SBOM スプレッドシートの構成」を参照してください。

---

### Step 5: デプロイ結果を確認する

各コンポーネントが正常にデプロイされたことを確認します。

```bash
# Agent Engine の一覧を表示
gcloud ai reasoning-engines list \
  --region=asia-northeast1 \
  --project=$(gcloud config get-value project)
```

```bash
# Live Gateway の URL を確認 (音声UIを使う場合)
gcloud run services describe vuln-agent-live-gateway \
  --region=asia-northeast1 \
  --format='value(status.url)' 2>/dev/null \
  && echo "" || echo "(Live Gateway はデプロイされていません)"
```

```bash
# Scheduler の URL を確認
gcloud functions describe vuln-agent-scheduler \
  --region=asia-northeast1 \
  --format='value(serviceConfig.uri)' 2>/dev/null \
  && echo "" || echo "(Scheduler はデプロイされていません)"
```

```bash
# Web UI の URL を表示
echo "https://storage.googleapis.com/$(gcloud config get-value project)-vuln-agent-ui/index.html"
```

Cloud Console の Agent 画面からもテストできます。

```bash
echo "https://console.cloud.google.com/vertex-ai/agents?project=$(gcloud config get-value project)"
```

---

### Step 6 (任意): Cloud Build で CI/CD を設定する

コードを変更した際に自動で全コンポーネントを再デプロイする CI/CD パイプラインを設定します。

Cloud Build パイプラインは以下を自動で実行します:

1. Secret Manager から `.env` を再生成
2. Agent Engine を再デプロイ
3. Live Gateway (Cloud Run) を再デプロイ
4. Scheduler (Cloud Functions) を再デプロイ
5. Web UI (Cloud Storage) を更新

**手動で Cloud Build を実行する場合:**

```bash
gcloud builds submit --config cloudbuild.yaml
```

**Git push 時に自動実行させたい場合 (トリガー登録):**

`YOUR_ORG` はリポジトリのオーナー名に置き換えてください。

```bash
gcloud builds triggers create github \
  --repo-name=vuln-agent \
  --repo-owner=YOUR_ORG \
  --branch-pattern="^main$" \
  --build-config=cloudbuild.yaml
```

---

### Step 7 (任意): 個人 Gmail で使う場合 (OAuth 認証)

Google Workspace ではなく個人 Gmail を使う場合は、ドメイン委任の代わりに OAuth トークンで認証します。

```bash
pip install google-auth-oauthlib
python setup_gmail_oauth.py
```

画面の指示に従って認証を完了すると、Base64 エンコードされたトークンが出力されます。
それを Secret Manager に登録してください。

```bash
echo -n "BASE64_ENCODED_TOKEN" | \
  gcloud secrets create vuln-agent-gmail-oauth-token --data-file=-
```

---

## 運用コマンド集

デプロイ後の日常運用で使うコマンドです。すべて Cloud Shell で実行できます。

### シークレットの値を変更する

```bash
# 例: Chat スペース ID を変更
echo -n "spaces/NEW_SPACE_ID" | \
  gcloud secrets versions add vuln-agent-chat-space-id --data-file=-

# Agent Engine に反映するには再デプロイ
gcloud builds submit --config cloudbuild.yaml
```

### 脆弱性スキャンを手動で実行する

```bash
# Scheduler の Cloud Function を直接呼び出す
FUNCTION_URL=$(gcloud functions describe vuln-agent-scheduler \
  --region=asia-northeast1 --format='value(serviceConfig.uri)')

curl -X POST "$FUNCTION_URL" \
  -H "Authorization: bearer $(gcloud auth print-identity-token)" \
  -H "Content-Type: application/json"
```

### ログを確認する

```bash
# Agent Engine のログ
gcloud logging read 'resource.type="aiplatform.googleapis.com/ReasoningEngine"' \
  --limit=20 --format='table(timestamp,textPayload)'

# Live Gateway のログ
gcloud run services logs read vuln-agent-live-gateway --region=asia-northeast1 --limit=20

# Scheduler のログ
gcloud functions logs read vuln-agent-scheduler --region=asia-northeast1 --limit=20
```

### A2A 連携エージェントを登録する

```bash
# 例: Jira エージェントのリソース名を登録
echo -n "projects/xxx/locations/xxx/reasoningEngines/xxx" | \
  gcloud secrets create vuln-agent-remote-jira --data-file=-
```

---

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
| `vuln-agent-resource-name` | Agent Engine リソース名 | 自動保存 |

---

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

---

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

---

## 優先度判定基準

| 優先度 | 条件 | 対応期限 |
|--------|------|----------|
| 緊急 | CVSS 9.0 以上、または既に悪用確認 | 24 時間以内 |
| 高 | CVSS 7.0-8.9、リモート攻撃可能 | 3 日以内 |
| 中 | CVSS 4.0-6.9 | 1 週間以内 |
| 低 | CVSS 4.0 未満 | 1 ヶ月以内 |

---

## トラブルシューティング

### Agent Engine のデプロイに失敗する

```bash
# Vertex AI API が有効か確認
gcloud services list --enabled --filter="aiplatform"

# サービスアカウントの権限を確認
gcloud projects get-iam-policy $(gcloud config get-value project) \
  --flatten="bindings[].members" \
  --filter="bindings.members:vuln-agent-sa" \
  --format='table(bindings.role)'
```

### Gmail 接続エラー

```bash
# ドメイン委任が正しく設定されているか確認
# → Google Workspace 管理コンソール → セキュリティ → API Controls → ドメイン全体の委任
# Vertex AI サービスエージェントのクライアント ID が登録されているか確認:
gcloud iam service-accounts describe \
  service-$(gcloud projects describe $(gcloud config get-value project) --format='value(projectNumber)')@gcp-sa-aiplatform-re.iam.gserviceaccount.com \
  --format='value(uniqueId)'
```

### Live Gateway が起動しない

```bash
# Cloud Run のログを確認
gcloud run services logs read vuln-agent-live-gateway --region=asia-northeast1 --limit=30

# Gemini API Key が設定されているか確認
gcloud secrets versions access latest --secret=vuln-agent-gemini-api-key 2>/dev/null \
  && echo "(設定済み)" || echo "(未設定)"
```

### Scheduler が実行されない

```bash
# Cloud Scheduler ジョブの状態を確認
gcloud scheduler jobs describe vuln-agent-scan \
  --location=asia-northeast1 \
  --format='table(state,schedule,lastAttemptTime,status.code)'

# Cloud Functions のログを確認
gcloud functions logs read vuln-agent-scheduler --region=asia-northeast1 --limit=30
```

### シークレットの値を変更したい

```bash
# 値を更新 (例: Chat スペース ID)
echo -n "NEW_VALUE" | gcloud secrets versions add vuln-agent-chat-space-id --data-file=-

# Agent Engine に反映するには再デプロイが必要
gcloud builds submit --config cloudbuild.yaml
```

---

## ライセンス

このリポジトリのライセンスは現時点で明示されていません。必要に応じて追加してください。
