#!/bin/bash
set -e

# ====================================
# Cloud Scheduler + Cloud Functions セットアップ
# 定期的な脆弱性スキャンを実行するための設定
# ====================================

PROJECT_ID="${GCP_PROJECT_ID:?GCP_PROJECT_ID is required}"
REGION="${GCP_REGION:-asia-northeast1}"
AGENT_RESOURCE_NAME="${AGENT_RESOURCE_NAME:?AGENT_RESOURCE_NAME is required}"

FUNCTION_NAME="vuln-agent-scheduler"
SCHEDULER_JOB_NAME="vuln-agent-scan"

echo "============================================"
echo "  Setting up scheduled vulnerability scans"
echo "============================================"
echo ""
echo "Project: $PROJECT_ID"
echo "Region: $REGION"
echo "Agent: $AGENT_RESOURCE_NAME"
echo ""

# ====================================
# Step 1: Cloud Functions デプロイ
# ====================================
echo "==> Step 1: Deploying Cloud Function..."

cd scheduler

gcloud functions deploy "$FUNCTION_NAME" \
    --gen2 \
    --runtime=python311 \
    --region="$REGION" \
    --source=. \
    --entry-point=run_vulnerability_scan \
    --trigger-http \
    --allow-unauthenticated=false \
    --set-env-vars="GCP_PROJECT_ID=$PROJECT_ID,GCP_LOCATION=$REGION,AGENT_RESOURCE_NAME=$AGENT_RESOURCE_NAME" \
    --memory=512MB \
    --timeout=300s \
    --project="$PROJECT_ID"

cd ..

# Function URLを取得
FUNCTION_URL=$(gcloud functions describe "$FUNCTION_NAME" \
    --region="$REGION" \
    --project="$PROJECT_ID" \
    --format='value(serviceConfig.uri)')

echo "Function URL: $FUNCTION_URL"

# ====================================
# Step 2: サービスアカウント作成
# ====================================
echo ""
echo "==> Step 2: Creating service account for scheduler..."

SA_NAME="vuln-agent-scheduler-sa"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

# サービスアカウントが存在しない場合は作成
if ! gcloud iam service-accounts describe "$SA_EMAIL" --project="$PROJECT_ID" &> /dev/null; then
    gcloud iam service-accounts create "$SA_NAME" \
        --display-name="Vulnerability Agent Scheduler" \
        --project="$PROJECT_ID"
fi

# Cloud Functions呼び出し権限を付与
gcloud functions add-invoker-policy-binding "$FUNCTION_NAME" \
    --region="$REGION" \
    --member="serviceAccount:$SA_EMAIL" \
    --project="$PROJECT_ID" 2>/dev/null || true

echo "Service Account: $SA_EMAIL"

# ====================================
# Step 3: Cloud Scheduler ジョブ作成
# ====================================
echo ""
echo "==> Step 3: Creating Cloud Scheduler job..."

# 既存のジョブを削除（存在する場合）
gcloud scheduler jobs delete "$SCHEDULER_JOB_NAME" \
    --location="$REGION" \
    --project="$PROJECT_ID" \
    --quiet 2>/dev/null || true

# 新しいジョブを作成（5分毎に実行）
gcloud scheduler jobs create http "$SCHEDULER_JOB_NAME" \
    --location="$REGION" \
    --schedule="*/5 * * * *" \
    --time-zone="Asia/Tokyo" \
    --uri="$FUNCTION_URL" \
    --http-method=POST \
    --oidc-service-account-email="$SA_EMAIL" \
    --project="$PROJECT_ID"

echo ""
echo "============================================"
echo "✅ Scheduler setup completed!"
echo "============================================"
echo ""
echo "Configuration:"
echo "  Function: $FUNCTION_NAME"
echo "  URL: $FUNCTION_URL"
echo "  Scheduler: $SCHEDULER_JOB_NAME"
echo "  Schedule: Every 5 minutes"
echo ""
echo "Commands:"
echo "  # 手動実行"
echo "  gcloud scheduler jobs run $SCHEDULER_JOB_NAME --location=$REGION --project=$PROJECT_ID"
echo ""
echo "  # ログ確認"
echo "  gcloud functions logs read $FUNCTION_NAME --region=$REGION --project=$PROJECT_ID"
echo ""
