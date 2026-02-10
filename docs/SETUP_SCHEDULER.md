# 定期実行 セットアップガイド

Cloud Scheduler + Cloud Functions で脆弱性スキャンを定期実行する設定手順です。

---

## 概要

```
┌─────────────────────────────────────────────────────────────────┐
│                    定期実行アーキテクチャ                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │   Cloud      │───▶│    Cloud     │───▶│  Agent       │       │
│  │  Scheduler   │    │  Functions   │    │  Engine      │       │
│  │  (cron設定)   │    │  (HTTP呼出)  │    │  (スキャン)   │       │
│  └──────────────┘    └──────────────┘    └──────────────┘       │
│                                                │                 │
│                                                ▼                 │
│                                    ┌──────────────────────┐     │
│                                    │ Gmail / SBOM / Chat  │     │
│                                    └──────────────────────┘     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 簡単セットアップ（推奨）

### 自動セットアップスクリプトを使用

```bash
# Agent Engine のリソース名を確認
gcloud ai reasoning-engines list --location=asia-northeast1

# セットアップスクリプトを実行
./setup_scheduler.sh
```

対話形式で以下を設定:
1. エージェントリソース名
2. 実行間隔（5分毎 / 15分毎 / 1時間毎 / 日次）
3. テスト実行の有無

---

## 手動セットアップ

### Step 1: APIの有効化

```bash
gcloud services enable cloudfunctions.googleapis.com
gcloud services enable cloudscheduler.googleapis.com
gcloud services enable cloudbuild.googleapis.com
gcloud services enable run.googleapis.com
```

### Step 2: サービスアカウント作成

```bash
PROJECT_ID=$(gcloud config get-value project)

# サービスアカウント作成
gcloud iam service-accounts create vuln-agent-scheduler-sa \
    --display-name="Vulnerability Agent Scheduler"

# 権限付与
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:vuln-agent-scheduler-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/aiplatform.user"
```

### Step 3: Cloud Functions デプロイ

```bash
cd scheduler

# デプロイ
gcloud functions deploy vuln-agent-scheduler \
    --gen2 \
    --runtime=python312 \
    --region=asia-northeast1 \
    --source=. \
    --entry-point=run_vulnerability_scan \
    --trigger-http \
    --allow-unauthenticated=false \
    --service-account="vuln-agent-scheduler-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
    --set-env-vars="GCP_PROJECT_ID=${PROJECT_ID},GCP_LOCATION=asia-northeast1" \
    --remove-env-vars="AGENT_RESOURCE_NAME" \
    --set-secrets="AGENT_RESOURCE_NAME=vuln-agent-resource-name:latest" \
    --memory=512MB \
    --timeout=540s

cd ..
```

### Step 4: Cloud Scheduler ジョブ作成

```bash
# Function URLを取得
FUNCTION_URL=$(gcloud functions describe vuln-agent-scheduler \
    --region=asia-northeast1 \
    --format='value(serviceConfig.uri)')

# Schedulerジョブ作成（1時間毎）
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

## スケジュール設定例

| 用途 | cron式 | 説明 |
|------|--------|------|
| 高頻度監視 | `*/5 * * * *` | 5分毎 |
| 標準監視 | `*/15 * * * *` | 15分毎 |
| 低頻度監視 | `0 * * * *` | 1時間毎 |
| 日次スキャン | `0 9 * * *` | 毎日9時（JST） |
| 平日のみ | `0 9 * * 1-5` | 平日9時 |
| 週次レポート | `0 9 * * 1` | 毎週月曜9時 |

---

## 運用コマンド

### 手動実行

```bash
gcloud scheduler jobs run vuln-agent-scan --location=asia-northeast1
```

### ログ確認

```bash
# Cloud Functions のログ
gcloud functions logs read vuln-agent-scheduler --region=asia-northeast1

# 最新50件
gcloud functions logs read vuln-agent-scheduler --region=asia-northeast1 --limit=50
```

### スケジュール変更

```bash
# 30分毎に変更
gcloud scheduler jobs update http vuln-agent-scan \
    --location=asia-northeast1 \
    --schedule="*/30 * * * *"
```

### 一時停止 / 再開

```bash
# 一時停止
gcloud scheduler jobs pause vuln-agent-scan --location=asia-northeast1

# 再開
gcloud scheduler jobs resume vuln-agent-scan --location=asia-northeast1
```

### 削除

```bash
# Schedulerジョブ削除
gcloud scheduler jobs delete vuln-agent-scan --location=asia-northeast1

# Cloud Functions削除
gcloud functions delete vuln-agent-scheduler --region=asia-northeast1
```

---

## 処理フロー

定期実行時のエージェントの動作:

```
1. Cloud Scheduler がトリガー
     ↓
2. Cloud Functions が起動
     ↓
3. Agent Engine にクエリ送信:
   「新しいSIDfmの脆弱性通知メールを確認してください...」
     ↓
4. エージェントが処理:
   a. get_sidfm_emails() で未読メール取得
   b. search_sbom_by_purl() で影響分析
   c. send_vulnerability_alert() で担当者に通知
   d. mark_email_as_read() でメールを既読に
     ↓
5. 処理結果をログに記録
```

---

## 監視とアラート

### Cloud Monitoring でアラート設定

```bash
# エラー率が高い場合にアラート
gcloud alpha monitoring policies create \
    --notification-channels=YOUR_CHANNEL_ID \
    --display-name="Vuln Agent Scheduler Errors" \
    --condition-display-name="Error rate > 10%" \
    --condition-filter='resource.type="cloud_function" AND resource.labels.function_name="vuln-agent-scheduler"' \
    --condition-threshold-value=0.1 \
    --condition-threshold-comparison=COMPARISON_GT
```

### ダッシュボード確認

```
https://console.cloud.google.com/functions/details/asia-northeast1/vuln-agent-scheduler
```

---

## コスト見積もり

| リソース | 料金 | 月間見積もり（1時間毎実行） |
|----------|------|--------------------------|
| Cloud Functions | $0.0000025/100ms | ~$0.50 |
| Cloud Scheduler | $0.10/job/month | $0.10 |
| Agent Engine | API呼び出し依存 | 変動 |

---

## トラブルシューティング

### エラー: "PERMISSION_DENIED"

**原因**: サービスアカウントの権限不足

**解決**:
```bash
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:vuln-agent-scheduler-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/aiplatform.user"
```

---

### エラー: "Function execution timeout"

**原因**: 処理が9分（540秒）を超えた

**解決**:
- 処理するメール数を制限
- より頻繁なスケジュールで分散処理

---

### エラー: "Agent not found"

**原因**: AGENT_RESOURCE_NAME が間違っている

**解決**:
```bash
# 正しいリソース名を確認
gcloud ai reasoning-engines list --location=asia-northeast1

# 環境変数を更新して再デプロイ
printf %s "projects/${PROJECT_ID}/locations/asia-northeast1/reasoningEngines/正しいID" | \
  gcloud secrets versions add vuln-agent-resource-name --data-file=-

# Secret 参照で再デプロイ
gcloud functions deploy vuln-agent-scheduler \
    --remove-env-vars="AGENT_RESOURCE_NAME" \
    --set-secrets="AGENT_RESOURCE_NAME=vuln-agent-resource-name:latest"
```

---

### ジョブが実行されない

**確認事項**:
1. Scheduler ジョブのステータス確認
   ```bash
   gcloud scheduler jobs describe vuln-agent-scan --location=asia-northeast1
   ```

2. 最後の実行時刻を確認
3. ジョブが「PAUSED」になっていないか確認

---

## セキュリティ考慮事項

1. **認証**: Cloud Scheduler → Cloud Functions は OIDC トークンで認証
2. **IAM**: 最小権限の原則でサービスアカウントを設定
3. **ログ**: Cloud Logging で実行履歴を監査可能
4. **ネットワーク**: VPC Service Controls で追加の保護も可能
