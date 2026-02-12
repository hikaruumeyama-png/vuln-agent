# 脆弱性管理AIエージェント

SIDfmの脆弱性通知メールを自動で解析し、SBOMと突合して担当者へ通知する **Vertex AI Agent Engine** 向けのAIエージェントです。Gmail / Google Sheets / Google Chat を使った運用を前提に、定期実行のスキャンや音声/チャットUI連携にも対応しています。

**ローカル環境は不要**です。以下の手順はすべて Google Cloud Shell 上でコマンドを入力するだけで完了します。
Google Workspace の管理者権限も不要で、個人アカウントまたは GCP プロジェクトの管理者権限があれば構築できます。

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
│  │  │  Vulnerability Management Agent (gemini-2.5-flash)│   │    │
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
│   ├── SETUP_GMAIL.md         # Gmail OAuth 設定
│   ├── SETUP_CHAT.md          # Google Chat Bot 設定
│   ├── SETUP_SCHEDULER.md     # Cloud Scheduler 設定
│   ├── SETUP_A2A.md           # Agent-to-Agent 連携設定
│   └── LIVE_VOICE_SETUP.md    # Gemini Live 音声設定
├── setup_cloud.sh           # Cloud Shell 用 初回セットアップスクリプト (自動化)
├── setup_git_auto_deploy.sh # git pull 後の自動デプロイhook設定
├── cloudbuild.yaml          # Cloud Build CI/CD パイプライン定義
├── deploy_python.py         # (レガシー) Python SDK デプロイ
├── setup_gmail_oauth.py     # Gmail OAuth トークン生成
├── deploy.sh                # (レガシー) Shell デプロイスクリプト
├── setup_scheduler.sh       # (レガシー) Scheduler 個別セットアップ
└── test_agent.sh            # Agent Engine 動作テスト
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
| Gmail アカウント | SIDfm メールを受信するアカウント | `user@gmail.com` |
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

### Step 2: OAuth 同意画面とクライアント ID を作成する

エージェントが Gmail にアクセスするために、OAuth 2.0 の認証情報を作成します。
この手順は GCP プロジェクトの管理者権限で完了でき、Google Workspace 管理者は不要です。

**まず OAuth 同意画面を設定します。** 初めてのプロジェクトでは同意画面の構成が必要です。

```bash
# OAuth 同意画面の設定ページを開く
echo "https://console.cloud.google.com/apis/credentials/consent?project=$(gcloud config get-value project)"
```

表示された URL をブラウザで開き、以下を設定します:

1. User Type: **「外部」** を選択 (テスト用途であれば外部で OK)
2. アプリ名: `vuln-agent` (任意)
3. ユーザーサポートメール: 自分のメールアドレス
4. デベロッパーの連絡先: 自分のメールアドレス
5. スコープは追加不要 (後で自動設定されます)
6. テストユーザーに **Gmail で使用するメールアドレスを追加**
7. **「保存」** をクリック

**次に OAuth クライアント ID を作成します。**

```bash
# 認証情報ページを開く
echo "https://console.cloud.google.com/apis/credentials?project=$(gcloud config get-value project)"
```

1. **「+ 認証情報を作成」** → **「OAuth クライアント ID」**
2. アプリケーションの種類: **「デスクトップ アプリ」**
3. 名前: `vuln-agent` (任意)
4. **「作成」** をクリック
5. 表示されたダイアログで **「JSON をダウンロード」** をクリック

ダウンロードした JSON ファイルを Cloud Shell にアップロードし、`credentials.json` にリネームします。

```bash
# Cloud Shell のアップロード機能 (右上の「︙」→「アップロード」) で JSON をアップロードした後:
mv ~/client_secret_*.json credentials.json
```

---

### Step 3: Gmail OAuth トークンを取得する

作成したクライアント ID を使って Gmail アクセス用の OAuth トークンを取得します。
対話形式で認証 URL が表示されるので、ブラウザでログインして認証コードを貼り付けてください。

```bash
pip install -q google-auth-oauthlib google-api-python-client
python setup_gmail_oauth.py
```

スクリプトの実行手順:

1. 認証用 URL が表示される → ブラウザの新しいタブで開く
2. Google アカウントでログインし、アクセスを許可
3. リダイレクト先の URL (または認証コード) をコピーして Cloud Shell に貼り付け
4. `認証成功: user@gmail.com` と表示されれば OK

トークンを Secret Manager に保存します。

```bash
# setup_gmail_oauth.py が agent/.env に書き込んだトークンを取得して Secret Manager に登録
OAUTH_TOKEN=$(grep '^GMAIL_OAUTH_TOKEN=' agent/.env | cut -d'=' -f2-)
echo -n "$OAUTH_TOKEN" | gcloud secrets create vuln-agent-gmail-oauth-token \
  --data-file=- --replication-policy=automatic 2>/dev/null \
  || echo -n "$OAUTH_TOKEN" | gcloud secrets versions add vuln-agent-gmail-oauth-token --data-file=-
echo "Gmail OAuth トークンを Secret Manager に保存しました"
```

---

### Step 4: セットアップスクリプトを実行する

以下の 1 コマンドで、残りの Google Cloud コンポーネントをまとめてセットアップします。
途中で設定値の入力を求められるので、事前に用意した値を入力してください (デフォルト値がある項目はそのまま Enter で OK)。

```bash
bash setup_cloud.sh
```

> **このスクリプトが自動で実行する内容:**
>
> 1. **API の有効化** --- Vertex AI, Gmail, Sheets, Chat, BigQuery, Cloud Build, Cloud Functions, Cloud Scheduler, Cloud Run, Secret Manager, Artifact Registry の計 11 API を有効にします
> 2. **サービスアカウントの作成** --- `vuln-agent-sa` を作成し、Vertex AI / BigQuery / Secret Manager / Cloud Storage のロールを付与します。Cloud Build 用サービスアカウントにも必要な権限を追加します
> 3. **Secret Manager への設定値登録** --- 対話形式で入力した SIDfm 送信元・スプレッドシート ID・Chat スペース ID などを Secret Manager に保存します (Gmail OAuth トークンは Step 3 で登録済み)
> 4. **Cloud Storage バケットの作成** --- Web UI 配信用とステージング用の 2 つのバケットを作成します
> 5. **BigQuery テーブルの作成** --- `vuln_agent.incident_response_history` (対応履歴)、`vuln_agent.sbom_packages` (SBOM)、`vuln_agent.owner_mapping` (担当者マッピング) の 3 テーブルを作成します
> 6. **Agent Engine のデプロイ** --- Secret Manager の値から `.env` を生成し、ADK CLI でエージェントを Vertex AI Agent Engine にデプロイします。デプロイ後のリソース名は自動的に Secret Manager に保存されます
> 7. **Live Gateway のデプロイ** --- WebSocket ゲートウェイを Cloud Run にデプロイします (Gemini API Key が登録済みの場合のみ)
> 8. **Scheduler のデプロイ** --- 定期スキャン用の Cloud Functions と、毎時実行の Cloud Scheduler ジョブを作成します
> 9. **Web UI のデプロイ** --- チャット/音声 UI を Cloud Storage に配信します

完了すると、デプロイされた各コンポーネントの URL が表示されます。

---

### Step 5: SBOM データソースを設定する（推奨: BigQuery）

SBOM と担当者マッピングの参照先は `Sheets` / `BigQuery` を選べます。  
組織ポリシーでサービスアカウントに Sheets 共有できない場合は、BigQuery を使用してください。

- `SBOM_DATA_BACKEND=sheets`: 従来どおり Google Sheets を参照
- `SBOM_DATA_BACKEND=bigquery`: BigQuery テーブルを参照
- `SBOM_DATA_BACKEND=auto`: `BQ_SBOM_TABLE_ID` と `BQ_OWNER_MAPPING_TABLE_ID` があれば BigQuery、なければ Sheets

#### 5-A. BigQuery を使う場合（推奨）

`setup_cloud.sh` を使う場合は以下テーブルが自動作成されます。

- `${PROJECT_ID}.vuln_agent.sbom_packages`
- `${PROJECT_ID}.vuln_agent.owner_mapping`

手動で作る場合の例:

```bash
bq mk --table ${PROJECT_ID}:vuln_agent.sbom_packages   type:STRING,name:STRING,version:STRING,release:STRING,purl:STRING

bq mk --table ${PROJECT_ID}:vuln_agent.owner_mapping   pattern:STRING,system_name:STRING,owner_email:STRING,owner_name:STRING,notes:STRING
```

サンプル投入（質問で共有いただいたテストシート相当）:

```bash
bq query --use_legacy_sql=false "
INSERT INTO `${PROJECT_ID}.vuln_agent.sbom_packages` (type,name,version,release,purl) VALUES
('maven','log4j-core','2.14.1','','pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1'),
('maven','spring-web','5.3.13','','pkg:maven/org.springframework/spring-web@5.3.13'),
('npm','express','4.17.1','','pkg:npm/express@4.17.1'),
('pypi','requests','2.26.0','','pkg:pypi/requests@2.26.0'),
('maven','commons-text','1.9','','pkg:maven/org.apache.commons/commons-text@1.9')
"

bq query --use_legacy_sql=false "
INSERT INTO `${PROJECT_ID}.vuln_agent.owner_mapping` (pattern,system_name,owner_email,owner_name,notes) VALUES
('*','共通基盤','your-email@gmail.com','管理者','デフォルトの担当者（ワイルドカード）'),
('pkg:maven/org.springframework/*','決済システム','your-email@gmail.com','田中 太郎','Spring Framework関連'),
('pkg:npm/*','フロントエンド','your-email@gmail.com','佐藤 花子','フロントエンド全般'),
('pkg:maven/org.apache.logging.log4j/*','基幹システム','your-email@gmail.com','鈴木 一郎','ログ基盤担当'),
('pkg:maven/org.apache.commons/*','共通ライブラリ','your-email@gmail.com','高橋 次郎','commons系ライブラリ担当')
"
```

シークレット更新:

```bash
echo -n "bigquery" | gcloud secrets versions add vuln-agent-sbom-data-backend --data-file=-
echo -n "${PROJECT_ID}.vuln_agent.sbom_packages" | gcloud secrets versions add vuln-agent-bq-sbom-table-id --data-file=-
echo -n "${PROJECT_ID}.vuln_agent.owner_mapping" | gcloud secrets versions add vuln-agent-bq-owner-table-id --data-file=-
```

#### 5-B. Sheets を使う場合（従来運用）

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

### Step 6: Google Chat アプリを設定する

エージェントが Google Chat スペースにメッセージを送信できるよう、GCP Console で Chat アプリ (Bot) を設定します。

```bash
# Chat API の設定ページを開く
echo "https://console.cloud.google.com/apis/api/chat.googleapis.com/hangouts-chat?project=$(gcloud config get-value project)"
```

表示された URL をブラウザで開き、以下を設定します:

1. **アプリ名**: `脆弱性管理エージェント` (任意)
2. **アバター URL**: 空欄で OK
3. **説明**: `脆弱性アラートを通知するBot` (任意)
4. **機能**: 「1:1 のメッセージを受信する」にチェック
5. **接続設定**: **「Apps Script」** を選択し、適当なスクリプト ID を入力 (実際には REST API で送信するため、この設定は形式上必要なだけです)
6. **公開設定**: **「このアプリをドメイン内の特定のユーザーとグループが利用できるようにする」** を選択
7. **「保存」** をクリック

保存後、対象の Google Chat スペースで **「+ アプリと統合機能を追加」** から作成したアプリを追加してください。

---

### Step 7: デプロイ結果を確認する

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

### Step 8 (任意): Cloud Build で CI/CD を設定する

コードを変更した際に自動で再デプロイする CI/CD パイプラインを設定します。

Cloud Build パイプラインは以下を自動で実行します:

1. 変更ファイルからデプロイ対象 (`agent` / `live_gateway` / `scheduler` / `web`) を判定
2. `agent/` が対象のときのみ `.env` を再生成して Agent Engine を再デプロイ
3. `live_gateway/` が対象のときのみ Live Gateway (Cloud Run) を再デプロイ
4. `scheduler/` が対象のときのみ Scheduler (Cloud Functions) を再デプロイ
5. `web/` が対象のときのみ Web UI (Cloud Storage) を更新

`cloudbuild.yaml` の追加 substitution:

- `_ADK_BUILDER_IMAGE`: ADK 同梱済みのカスタムビルダーイメージに差し替え可能（既定: `gcr.io/google.com/cloudsdktool/cloud-sdk`）
- `_FORCE_FULL_DEPLOY`: `true` にすると変更判定を無視して全コンポーネントを再デプロイ
- `_CHANGED_FILES`: `agent/a.py,web/index.html` のように変更ファイル一覧を明示指定可能

**手動で Cloud Build を実行する場合:**

```bash
gcloud builds submit --config cloudbuild.yaml
```

```bash
# 例: ADK 同梱ビルダーを使い、agent と web だけをデプロイ対象にする
gcloud builds submit --config cloudbuild.yaml \
  --substitutions=_ADK_BUILDER_IMAGE=asia-northeast1-docker.pkg.dev/YOUR_PROJECT/builders/adk-cloud-sdk:latest,_CHANGED_FILES=agent/agent.py,web/index.html
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

## 運用コマンド集

デプロイ後の日常運用で使うコマンドです。すべて Cloud Shell で実行できます。

### git pull 後に自動デプロイする（Cloud Shell 推奨）

Cloud Shell で `git pull` したタイミングで、対象ファイル変更があれば
`gcloud builds submit --config cloudbuild.yaml` を自動実行する Git Hook を設定できます。

```bash
./setup_git_auto_deploy.sh
```

- 一時無効化して pull: `SKIP_AUTO_DEPLOY=1 git pull`
- 状態確認: `./setup_git_auto_deploy.sh --status`
- 解除: `./setup_git_auto_deploy.sh --remove`
- 既存hookを上書き: `./setup_git_auto_deploy.sh --force`

### シークレットの値を変更する

```bash
# 例: Chat スペース ID を変更
echo -n "spaces/NEW_SPACE_ID" | \
  gcloud secrets versions add vuln-agent-chat-space-id --data-file=-

# Agent Engine に反映するには再デプロイ
gcloud builds submit --config cloudbuild.yaml
```

### Gmail OAuth トークンを更新する

OAuth トークンは自動更新されますが、refresh_token が無効になった場合は再取得してください。

```bash
python setup_gmail_oauth.py

# 新しいトークンを Secret Manager に保存
OAUTH_TOKEN=$(grep '^GMAIL_OAUTH_TOKEN=' agent/.env | cut -d'=' -f2-)
echo -n "$OAUTH_TOKEN" | gcloud secrets versions add vuln-agent-gmail-oauth-token --data-file=-

# Agent Engine に反映
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

### Agent Engine の動作をテストする

```bash
# デフォルトのテストメッセージで実行
bash test_agent.sh

# カスタムメッセージで実行
bash test_agent.sh "CVE-2024-12345の影響を教えてください"
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
| `vuln-agent-gmail-oauth-token` | Gmail OAuth トークン (Base64) | はい |
| `vuln-agent-gmail-user-email` | Gmail ユーザーEmail（Workspace/ドメイン委任時） | いいえ |
| `vuln-agent-sidfm-sender` | SIDfm 送信元メール | はい |
| `vuln-agent-sbom-data-backend` | SBOM データソース (`sheets` / `bigquery` / `auto`) | いいえ (デフォルト: sheets) |
| `vuln-agent-sbom-spreadsheet-id` | SBOM スプレッドシート ID | Sheets 利用時は必須 |
| `vuln-agent-sbom-sheet-name` | SBOM シート名 | いいえ (デフォルト: SBOM) |
| `vuln-agent-owner-sheet-name` | 担当者マッピングシート名 | いいえ (デフォルト: 担当者マッピング) |
| `vuln-agent-bq-sbom-table-id` | BigQuery SBOM テーブル ID | BigQuery 利用時は必須 |
| `vuln-agent-bq-owner-table-id` | BigQuery 担当者マッピングテーブル ID | BigQuery 利用時は必須 |
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
| `check_chat_connection` | Chat 接続確認 |
| `list_space_members` | スペースメンバー取得 |
| `log_vulnerability_history` | BigQuery 履歴記録 |
| `register_remote_agent` | A2A エージェント登録 |
| `call_remote_agent` | A2A エージェント呼出 |
| `create_jira_ticket_request` | Jira チケットリクエスト構築 |
| `create_approval_request` | 承認リクエスト構築 |
| `list_registered_agents` | 登録済エージェント一覧 |

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
# OAuth トークンが Secret Manager に登録されているか確認
gcloud secrets versions access latest --secret=vuln-agent-gmail-oauth-token 2>/dev/null | head -c 20
echo "..."

# トークンを再取得する場合
python setup_gmail_oauth.py
OAUTH_TOKEN=$(grep '^GMAIL_OAUTH_TOKEN=' agent/.env | cut -d'=' -f2-)
echo -n "$OAUTH_TOKEN" | gcloud secrets versions add vuln-agent-gmail-oauth-token --data-file=-
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

### Google Chat にメッセージが送信されない

```bash
# Chat API が有効か確認
gcloud services list --enabled --filter="chat"

# Chat アプリの設定ページを開く
echo "https://console.cloud.google.com/apis/api/chat.googleapis.com/hangouts-chat?project=$(gcloud config get-value project)"
```

Chat アプリが設定済みで、対象スペースにアプリが追加されていることを確認してください。

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
