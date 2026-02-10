#!/bin/bash
#
# Cloud Scheduler + Cloud Functions セットアップスクリプト
#
# 使い方:
#   ./setup_scheduler.sh
#
# 環境変数で事前設定も可能:
#   GCP_PROJECT_ID=xxx AGENT_RESOURCE_NAME=xxx ./setup_scheduler.sh
#

set -e

# 色付き出力
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_step() {
    echo -e "\n${BLUE}==>${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║      Cloud Scheduler + Cloud Functions セットアップ               ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# ====================================
# Step 1: 設定確認
# ====================================
print_step "Step 1: 設定を確認中..."

# プロジェクトID
PROJECT_ID="${GCP_PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
if [ -z "$PROJECT_ID" ]; then
    print_error "プロジェクトIDが設定されていません"
    echo "以下のいずれかで設定してください:"
    echo "  export GCP_PROJECT_ID=your-project-id"
    echo "  gcloud config set project your-project-id"
    exit 1
fi
print_success "プロジェクト: $PROJECT_ID"

# リージョン
REGION="${GCP_LOCATION:-asia-northeast1}"
print_success "リージョン: $REGION"

# エージェントリソース名
if [ -z "$AGENT_RESOURCE_NAME" ]; then
    echo ""
    print_warning "AGENT_RESOURCE_NAME が設定されていません"
    echo ""
    echo "Agent Engine のリソース名を入力してください"
    echo "例: projects/$PROJECT_ID/locations/$REGION/reasoningEngines/123456789"
    echo ""
    echo "確認方法:"
    echo "  gcloud ai reasoning-engines list --location=$REGION --project=$PROJECT_ID"
    echo ""
    read -p "> " AGENT_RESOURCE_NAME

    if [ -z "$AGENT_RESOURCE_NAME" ]; then
        print_error "リソース名は必須です"
        exit 1
    fi
fi
print_success "Agent: $AGENT_RESOURCE_NAME"

# スケジュール設定
echo ""
echo "実行間隔を選択してください:"
echo "  1) 5分毎      (*/5 * * * *)   - 高頻度監視"
echo "  2) 15分毎     (*/15 * * * *)  - 標準"
echo "  3) 1時間毎    (0 * * * *)     - 低頻度"
echo "  4) 毎日9時    (0 9 * * *)     - 日次"
echo "  5) カスタム"
read -p "> " SCHEDULE_CHOICE

case $SCHEDULE_CHOICE in
    1) SCHEDULE="*/5 * * * *" ;;
    2) SCHEDULE="*/15 * * * *" ;;
    3) SCHEDULE="0 * * * *" ;;
    4) SCHEDULE="0 9 * * *" ;;
    5)
        echo "cron形式で入力してください (例: 0 */2 * * *):"
        read -p "> " SCHEDULE
        ;;
    *) SCHEDULE="*/15 * * * *" ;;
esac
print_success "スケジュール: $SCHEDULE"

FUNCTION_NAME="vuln-agent-scheduler"
SCHEDULER_JOB_NAME="vuln-agent-scan"
SA_NAME="vuln-agent-scheduler-sa"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

# ====================================
# Step 2: APIの有効化
# ====================================
print_step "Step 2: 必要なAPIを有効化中..."

gcloud services enable cloudfunctions.googleapis.com --project="$PROJECT_ID" --quiet
gcloud services enable cloudscheduler.googleapis.com --project="$PROJECT_ID" --quiet
gcloud services enable cloudbuild.googleapis.com --project="$PROJECT_ID" --quiet
gcloud services enable run.googleapis.com --project="$PROJECT_ID" --quiet
gcloud services enable secretmanager.googleapis.com --project="$PROJECT_ID" --quiet

print_success "APIを有効化しました"

# ====================================
# Step 3: サービスアカウントの設定
# ====================================
print_step "Step 3: サービスアカウントを設定中..."

# サービスアカウントが存在しない場合は作成
if ! gcloud iam service-accounts describe "$SA_EMAIL" --project="$PROJECT_ID" &> /dev/null; then
    echo "サービスアカウントを作成中..."
    gcloud iam service-accounts create "$SA_NAME" \
        --display-name="Vulnerability Agent Scheduler" \
        --project="$PROJECT_ID"
fi

# 必要な権限を付与
echo "権限を付与中..."
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/aiplatform.user" \
    --quiet 2>/dev/null || true

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/secretmanager.secretAccessor" \
    --quiet 2>/dev/null || true

print_success "サービスアカウント: $SA_EMAIL"

# AGENT_RESOURCE_NAME を Secret Manager に保存
print_step "Step 3.5: AGENT_RESOURCE_NAME シークレットを更新中..."

if gcloud secrets describe "vuln-agent-resource-name" --project="$PROJECT_ID" &>/dev/null; then
    echo -n "$AGENT_RESOURCE_NAME" | gcloud secrets versions add "vuln-agent-resource-name" \
        --data-file=- \
        --project="$PROJECT_ID" >/dev/null
    print_success "既存シークレットに新しいバージョン追加: vuln-agent-resource-name"
else
    echo -n "$AGENT_RESOURCE_NAME" | gcloud secrets create "vuln-agent-resource-name" \
        --data-file=- \
        --replication-policy="automatic" \
        --project="$PROJECT_ID" >/dev/null
    print_success "シークレット作成: vuln-agent-resource-name"
fi

# ====================================
# Step 4: Cloud Functions デプロイ
# ====================================
print_step "Step 4: Cloud Functions をデプロイ中..."

cd scheduler

# requirements.txt を確認
if [ ! -f requirements.txt ]; then
    cat > requirements.txt << 'EOF'
functions-framework>=3.0.0
google-cloud-aiplatform>=1.38.0
vertexai>=1.38.0
EOF
fi

# Cloud Functions (第2世代) でデプロイ
echo "デプロイ中（数分かかります）..."
gcloud functions deploy "$FUNCTION_NAME" \
    --gen2 \
    --runtime=python312 \
    --region="$REGION" \
    --source=. \
    --entry-point=run_vulnerability_scan \
    --trigger-http \
    --allow-unauthenticated=false \
    --service-account="$SA_EMAIL" \
    # AGENT_RESOURCE_NAME は Secret Manager から注入する
    --set-env-vars="GCP_PROJECT_ID=$PROJECT_ID,GCP_LOCATION=$REGION" \
    --remove-env-vars="AGENT_RESOURCE_NAME" \
    --set-env-vars="GCP_PROJECT_ID=$PROJECT_ID,GCP_LOCATION=$REGION" \
    --set-secrets="AGENT_RESOURCE_NAME=vuln-agent-resource-name:latest" \
    --memory=512MB \
    --timeout=540s \
    --project="$PROJECT_ID"

FUNCTION_URL=$(gcloud functions describe "$FUNCTION_NAME" \
    --region="$REGION" \
    --project="$PROJECT_ID" \
    --format='value(serviceConfig.uri)')

cd ..

print_success "Cloud Functions をデプロイしました"
print_success "URL: $FUNCTION_URL"

# Cloud Functions呼び出し権限を付与
gcloud functions add-invoker-policy-binding "$FUNCTION_NAME" \
    --region="$REGION" \
    --member="serviceAccount:$SA_EMAIL" \
    --project="$PROJECT_ID" 2>/dev/null || true

# ====================================
# Step 5: Cloud Scheduler ジョブ作成
# ====================================
print_step "Step 5: Cloud Scheduler を設定中..."

# 既存のジョブを削除（存在する場合）
gcloud scheduler jobs delete "$SCHEDULER_JOB_NAME" \
    --location="$REGION" \
    --project="$PROJECT_ID" \
    --quiet 2>/dev/null || true

# 新しいジョブを作成
gcloud scheduler jobs create http "$SCHEDULER_JOB_NAME" \
    --location="$REGION" \
    --schedule="$SCHEDULE" \
    --time-zone="Asia/Tokyo" \
    --uri="$FUNCTION_URL" \
    --http-method=POST \
    --oidc-service-account-email="$SA_EMAIL" \
    --oidc-token-audience="$FUNCTION_URL" \
    --project="$PROJECT_ID"

print_success "Cloud Scheduler を設定しました"

# ====================================
# Step 6: テスト実行
# ====================================
print_step "Step 6: テスト実行"

echo ""
echo "Cloud Scheduler ジョブを今すぐ実行しますか？ (y/N)"
read -p "> " RUN_NOW

if [ "$RUN_NOW" = "y" ] || [ "$RUN_NOW" = "Y" ]; then
    echo "実行中..."
    gcloud scheduler jobs run "$SCHEDULER_JOB_NAME" \
        --location="$REGION" \
        --project="$PROJECT_ID"

    echo ""
    echo "ログを確認するには数秒待ってから以下を実行:"
    echo "  gcloud functions logs read $FUNCTION_NAME --region=$REGION --project=$PROJECT_ID"
fi

# ====================================
# 完了
# ====================================
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                      セットアップ完了！                           ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║                                                                  ║"
echo "║  Cloud Functions: $FUNCTION_NAME"
echo "║  Cloud Scheduler: $SCHEDULER_JOB_NAME"
echo "║  スケジュール: $SCHEDULE (Asia/Tokyo)"
echo "║                                                                  ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║  便利なコマンド:                                                  ║"
echo "║                                                                  ║"
echo "║  # 手動実行                                                       ║"
echo "║  gcloud scheduler jobs run $SCHEDULER_JOB_NAME \\"
echo "║      --location=$REGION --project=$PROJECT_ID"
echo "║                                                                  ║"
echo "║  # ログ確認                                                       ║"
echo "║  gcloud functions logs read $FUNCTION_NAME \\"
echo "║      --region=$REGION --project=$PROJECT_ID"
echo "║                                                                  ║"
echo "║  # スケジュール変更                                               ║"
echo "║  gcloud scheduler jobs update http $SCHEDULER_JOB_NAME \\"
echo "║      --location=$REGION --schedule=\"0 * * * *\" --project=$PROJECT_ID"
echo "║                                                                  ║"
echo "║  # 一時停止                                                       ║"
echo "║  gcloud scheduler jobs pause $SCHEDULER_JOB_NAME \\"
echo "║      --location=$REGION --project=$PROJECT_ID"
echo "║                                                                  ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# 設定を保存
cat > scheduler/.env.scheduler << EOF
# Scheduler Configuration (generated by setup_scheduler.sh)
PROJECT_ID=$PROJECT_ID
REGION=$REGION
FUNCTION_NAME=$FUNCTION_NAME
FUNCTION_URL=$FUNCTION_URL
SCHEDULER_JOB_NAME=$SCHEDULER_JOB_NAME
SERVICE_ACCOUNT=$SA_EMAIL
SCHEDULE=$SCHEDULE
AGENT_RESOURCE_NAME=$AGENT_RESOURCE_NAME
EOF

print_success "設定を scheduler/.env.scheduler に保存しました"
