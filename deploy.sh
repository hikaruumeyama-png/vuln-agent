#!/bin/bash
set -e

# ====================================
# 脆弱性管理AIエージェント
# Vertex AI Agent Engine デプロイスクリプト
# ====================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_step() { echo -e "${GREEN}==>${NC} $1"; }
print_info() { echo -e "${BLUE}   $1${NC}"; }
print_warning() { echo -e "${YELLOW}Warning:${NC} $1"; }
print_error() { echo -e "${RED}Error:${NC} $1"; }

# ====================================
# 設定
# ====================================

# 環境変数または引数から設定を読み込み
PROJECT_ID="${GCP_PROJECT_ID:-}"
REGION="${GCP_REGION:-asia-northeast1}"
STAGING_BUCKET="${STAGING_BUCKET:-}"
AGENT_NAME="${AGENT_NAME:-vulnerability-management-agent}"

# 必須チェック
if [ -z "$PROJECT_ID" ]; then
    print_error "GCP_PROJECT_ID environment variable is required"
    echo "Usage: GCP_PROJECT_ID=your-project ./deploy.sh"
    exit 1
fi

if [ -z "$STAGING_BUCKET" ]; then
    STAGING_BUCKET="gs://${PROJECT_ID}-agent-staging"
    print_warning "STAGING_BUCKET not set, using: $STAGING_BUCKET"
fi

echo ""
echo "============================================"
echo "  Vulnerability Management Agent"
echo "  Deploy to Vertex AI Agent Engine"
echo "============================================"
echo ""
print_info "Project:  ${PROJECT_ID}"
print_info "Region:   ${REGION}"
print_info "Bucket:   ${STAGING_BUCKET}"
print_info "Agent:    ${AGENT_NAME}"
echo ""

# ====================================
# Step 1: 前提条件の確認
# ====================================
print_step "Step 1/5: Checking prerequisites..."

# gcloud認証確認
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | head -1 > /dev/null 2>&1; then
    print_error "Not authenticated with gcloud. Run: gcloud auth login"
    exit 1
fi

# ADK CLIの確認
if ! command -v adk &> /dev/null; then
    print_warning "ADK CLI not found. Installing..."
    pip install google-adk
fi

print_info "Prerequisites OK"

# ====================================
# Step 2: APIの有効化
# ====================================
print_step "Step 2/5: Enabling required APIs..."

apis=(
    "aiplatform.googleapis.com"
    "gmail.googleapis.com"
    "sheets.googleapis.com"
    "chat.googleapis.com"
)

for api in "${apis[@]}"; do
    gcloud services enable "$api" --project="$PROJECT_ID" 2>/dev/null || true
done

print_info "APIs enabled"

# ====================================
# Step 3: ステージングバケットの作成
# ====================================
print_step "Step 3/5: Creating staging bucket..."

# バケットが存在しない場合は作成
if ! gsutil ls "$STAGING_BUCKET" &> /dev/null; then
    gsutil mb -p "$PROJECT_ID" -l "$REGION" "$STAGING_BUCKET"
    print_info "Created bucket: $STAGING_BUCKET"
else
    print_info "Bucket already exists"
fi

# ====================================
# Step 4: 環境変数ファイルの作成
# ====================================
print_step "Step 4/5: Creating environment configuration..."

# .env ファイルが存在しない場合はテンプレートを作成
if [ ! -f "agent/.env" ]; then
    cat > agent/.env << EOF
# Gmail設定
GMAIL_USER_EMAIL=security-team@your-domain.com
SIDFM_SENDER_EMAIL=noreply@sidfm.com

# SBOM設定
SBOM_SPREADSHEET_ID=your-spreadsheet-id
SBOM_SHEET_NAME=SBOM
OWNER_SHEET_NAME=担当者マッピング

# Google Chat設定
DEFAULT_CHAT_SPACE_ID=spaces/your-space-id
EOF
    print_warning "Created agent/.env - Please edit with your configuration"
    print_info "Then run this script again"
    exit 0
fi

# ====================================
# Step 5: Agent Engineへデプロイ
# ====================================
print_step "Step 5/5: Deploying to Vertex AI Agent Engine..."

cd agent

# ADK deploy コマンドでデプロイ
adk deploy \
    --project="$PROJECT_ID" \
    --region="$REGION" \
    --staging_bucket="$STAGING_BUCKET" \
    --display_name="$AGENT_NAME" \
    --env_file=".env"

cd ..

# ====================================
# 完了
# ====================================
echo ""
echo "============================================"
print_step "🎉 Deployment completed!"
echo "============================================"
echo ""
echo "Your agent is now deployed to Vertex AI Agent Engine."
echo ""
echo "Next steps:"
echo ""
echo "1. Set up Domain-Wide Delegation in Google Workspace Admin Console"
echo "   - Go to: admin.google.com → Security → API Controls → Domain-wide Delegation"
echo "   - Add the Vertex AI service agent"
echo "   - Grant scopes: Gmail, Sheets, Chat"
echo ""
echo "2. Share SBOM spreadsheet with the service account"
echo ""
echo "3. Add the Chat Bot to your space"
echo ""
echo "4. Test the agent:"
echo "   python -c \""
echo "   import vertexai"
echo "   from vertexai.agent_engines import AdkApp"
echo "   vertexai.init(project='$PROJECT_ID', location='$REGION')"
echo "   # Get your deployed agent and test"
echo "   \""
echo ""
echo "5. View in Cloud Console:"
echo "   https://console.cloud.google.com/vertex-ai/agents?project=$PROJECT_ID"
echo ""
