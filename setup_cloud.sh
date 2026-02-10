#!/bin/bash
set -euo pipefail

# ====================================================
# 脆弱性管理AIエージェント - Google Cloud セットアップ
#
# Cloud Shell から実行してください。
# ローカル環境は不要です。
#
# Usage:
#   bash setup_cloud.sh
#   bash setup_cloud.sh --project my-project-id
# ====================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

step()    { echo -e "\n${GREEN}==> $1${NC}"; }
info()    { echo -e "${BLUE}    $1${NC}"; }
warn()    { echo -e "${YELLOW}[WARN] $1${NC}"; }
err()     { echo -e "${RED}[ERROR] $1${NC}"; }

REGION="asia-northeast1"
AGENT_NAME="vulnerability-management-agent"

# ====================================================
# 引数パース
# ====================================================
while [[ $# -gt 0 ]]; do
  case $1 in
    --project) PROJECT_ID="$2"; shift 2;;
    --region)  REGION="$2";     shift 2;;
    *) err "Unknown option: $1"; exit 1;;
  esac
done

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"

if [[ -z "$PROJECT_ID" ]]; then
  err "プロジェクトIDが未設定です。"
  echo "  gcloud config set project YOUR_PROJECT_ID"
  echo "  または  bash setup_cloud.sh --project YOUR_PROJECT_ID"
  exit 1
fi

STAGING_BUCKET="gs://${PROJECT_ID}-agent-staging"
WEB_UI_BUCKET="gs://${PROJECT_ID}-vuln-agent-ui"

echo ""
echo "============================================"
echo "  Vulnerability Management Agent"
echo "  Google Cloud Setup"
echo "============================================"
info "Project : ${PROJECT_ID}"
info "Region  : ${REGION}"
echo ""

# ====================================================
# 1. API の有効化
# ====================================================
step "1/8: API を有効化しています..."

APIS=(
  aiplatform.googleapis.com
  gmail.googleapis.com
  sheets.googleapis.com
  chat.googleapis.com
  bigquery.googleapis.com
  cloudbuild.googleapis.com
  cloudfunctions.googleapis.com
  cloudscheduler.googleapis.com
  run.googleapis.com
  secretmanager.googleapis.com
  artifactregistry.googleapis.com
)

gcloud services enable "${APIS[@]}" --project="$PROJECT_ID" 2>/dev/null
info "API 有効化完了"

# ====================================================
# 2. サービスアカウントの作成と権限付与
# ====================================================
step "2/8: サービスアカウントを設定しています..."

SA_NAME="vuln-agent-sa"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

if ! gcloud iam service-accounts describe "$SA_EMAIL" --project="$PROJECT_ID" &>/dev/null; then
  gcloud iam service-accounts create "$SA_NAME" \
    --display-name="Vulnerability Agent Service Account" \
    --project="$PROJECT_ID"
  info "サービスアカウント作成: ${SA_EMAIL}"
else
  info "サービスアカウント既存: ${SA_EMAIL}"
fi

ROLES=(
  roles/aiplatform.user
  roles/bigquery.dataEditor
  roles/secretmanager.secretAccessor
  roles/storage.objectAdmin
)

for role in "${ROLES[@]}"; do
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="$role" \
    --condition=None \
    --quiet 2>/dev/null || true
done
info "IAM ロール付与完了"

# Cloud Build サービスアカウントにも権限を付与
PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')
CB_SA="${PROJECT_NUMBER}@cloudbuild.gserviceaccount.com"

CB_ROLES=(
  roles/aiplatform.admin
  roles/run.admin
  roles/cloudfunctions.admin
  roles/storage.admin
  roles/secretmanager.secretAccessor
  roles/iam.serviceAccountUser
)
for role in "${CB_ROLES[@]}"; do
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:${CB_SA}" \
    --role="$role" \
    --condition=None \
    --quiet 2>/dev/null || true
done
info "Cloud Build サービスアカウント権限付与完了"

# ====================================================
# 3. Secret Manager にシークレットを登録
# ====================================================
step "3/8: Secret Manager を設定しています..."

create_secret() {
  local name="$1"
  local prompt="$2"
  local default_val="${3:-}"

  if gcloud secrets describe "$name" --project="$PROJECT_ID" &>/dev/null; then
    info "シークレット '${name}' は既に登録済みです (スキップ)"
    return
  fi

  local value=""
  if [[ -n "$default_val" ]]; then
    read -rp "  ${prompt} [${default_val}]: " value
    value="${value:-$default_val}"
  else
    read -rp "  ${prompt}: " value
  fi

  if [[ -z "$value" ]]; then
    warn "${name} は空のため登録をスキップしました"
    return
  fi

  echo -n "$value" | gcloud secrets create "$name" \
    --data-file=- \
    --replication-policy="automatic" \
    --project="$PROJECT_ID" 2>/dev/null
  info "登録: ${name}"
}

echo ""
echo "  エージェントの動作に必要な設定値を入力してください。"
echo "  空欄で Enter を押すとその項目はスキップされます。"
echo ""

create_secret "vuln-agent-sidfm-sender"        "SIDfm 送信元メール"                       "noreply@sidfm.com"
create_secret "vuln-agent-sbom-data-backend"   "SBOM データソース (sheets/bigquery/auto)"     "sheets"
create_secret "vuln-agent-sbom-spreadsheet-id" "SBOM スプレッドシート ID"
create_secret "vuln-agent-sbom-sheet-name"     "SBOM シート名"                             "SBOM"
create_secret "vuln-agent-owner-sheet-name"    "担当者マッピング シート名"                  "担当者マッピング"
create_secret "vuln-agent-chat-space-id"       "Google Chat スペース ID (spaces/xxx)"
create_secret "vuln-agent-gemini-api-key"      "Gemini API Key (Live Gateway 用)"
create_secret "vuln-agent-bq-table-id"         "BigQuery テーブル ID (project.dataset.table、任意)"

info "Secret Manager 設定完了"

# ====================================================
# 4. ストレージバケットの作成
# ====================================================
step "4/8: Cloud Storage バケットを作成しています..."

for bucket in "$STAGING_BUCKET" "$WEB_UI_BUCKET"; do
  if ! gsutil ls "$bucket" &>/dev/null; then
    gsutil mb -p "$PROJECT_ID" -l "$REGION" "$bucket"
    info "作成: ${bucket}"
  else
    info "既存: ${bucket}"
  fi
done

# ====================================================
# 5. BigQuery データセット / テーブルの作成
# ====================================================
step "5/8: BigQuery テーブルを作成しています..."

DATASET_ID="vuln_agent"
HISTORY_TABLE_ID="incident_response_history"
SBOM_TABLE_ID="sbom_packages"
OWNER_TABLE_ID="owner_mapping"
FULL_HISTORY_TABLE_ID="${PROJECT_ID}.${DATASET_ID}.${HISTORY_TABLE_ID}"
FULL_SBOM_TABLE_ID="${PROJECT_ID}.${DATASET_ID}.${SBOM_TABLE_ID}"
FULL_OWNER_TABLE_ID="${PROJECT_ID}.${DATASET_ID}.${OWNER_TABLE_ID}"

if ! bq show --project_id="$PROJECT_ID" "${DATASET_ID}" &>/dev/null; then
  bq --location="$REGION" mk -d "${PROJECT_ID}:${DATASET_ID}"
  info "データセット作成: ${DATASET_ID}"
else
  info "データセット既存: ${DATASET_ID}"
fi

if ! bq show --project_id="$PROJECT_ID" "${DATASET_ID}.${HISTORY_TABLE_ID}" &>/dev/null; then
  bq mk --table "${PROJECT_ID}:${DATASET_ID}.${HISTORY_TABLE_ID}"     incident_id:STRING,vulnerability_id:STRING,title:STRING,severity:STRING,affected_systems:STRING,cvss_score:FLOAT,description:STRING,remediation:STRING,owners:STRING,status:STRING,occurred_at:TIMESTAMP,source:STRING,extra:STRING
  info "テーブル作成: ${HISTORY_TABLE_ID}"
else
  info "テーブル既存: ${HISTORY_TABLE_ID}"
fi

if ! bq show --project_id="$PROJECT_ID" "${DATASET_ID}.${SBOM_TABLE_ID}" &>/dev/null; then
  bq mk --table "${PROJECT_ID}:${DATASET_ID}.${SBOM_TABLE_ID}"     type:STRING,name:STRING,version:STRING,release:STRING,purl:STRING
  info "テーブル作成: ${SBOM_TABLE_ID}"
else
  info "テーブル既存: ${SBOM_TABLE_ID}"
fi

if ! bq show --project_id="$PROJECT_ID" "${DATASET_ID}.${OWNER_TABLE_ID}" &>/dev/null; then
  bq mk --table "${PROJECT_ID}:${DATASET_ID}.${OWNER_TABLE_ID}"     pattern:STRING,system_name:STRING,owner_email:STRING,owner_name:STRING,notes:STRING
  info "テーブル作成: ${OWNER_TABLE_ID}"
else
  info "テーブル既存: ${OWNER_TABLE_ID}"
fi

# BQ テーブル ID をシークレットに保存 (未登録なら)
if ! gcloud secrets describe "vuln-agent-bq-table-id" --project="$PROJECT_ID" &>/dev/null; then
  echo -n "$FULL_HISTORY_TABLE_ID" | gcloud secrets create "vuln-agent-bq-table-id"     --data-file=- --replication-policy="automatic" --project="$PROJECT_ID" 2>/dev/null
  info "BigQuery 履歴テーブル ID を Secret Manager に登録"
fi

if ! gcloud secrets describe "vuln-agent-bq-sbom-table-id" --project="$PROJECT_ID" &>/dev/null; then
  echo -n "$FULL_SBOM_TABLE_ID" | gcloud secrets create "vuln-agent-bq-sbom-table-id"     --data-file=- --replication-policy="automatic" --project="$PROJECT_ID" 2>/dev/null
  info "BigQuery SBOM テーブル ID を Secret Manager に登録"
fi

if ! gcloud secrets describe "vuln-agent-bq-owner-table-id" --project="$PROJECT_ID" &>/dev/null; then
  echo -n "$FULL_OWNER_TABLE_ID" | gcloud secrets create "vuln-agent-bq-owner-table-id"     --data-file=- --replication-policy="automatic" --project="$PROJECT_ID" 2>/dev/null
  info "BigQuery 担当者マッピングテーブル ID を Secret Manager に登録"
fi

# ====================================================
# 6. Agent Engine のデプロイ
# ====================================================
step "6/8: Agent Engine をデプロイしています..."

# .env ファイルを Secret Manager から構築
_sm_get() {
  gcloud secrets versions access latest --secret="$1" --project="$PROJECT_ID" 2>/dev/null || echo ""
}

_engine_exists() {
  local engine_name="$1"
  [[ -z "$engine_name" ]] && return 1
  local token
  token="$(gcloud auth print-access-token)"
  local endpoint="https://${REGION}-aiplatform.googleapis.com/v1/${engine_name}"
  local status
  status="$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${token}" "${endpoint}")"
  [[ "$status" == "200" ]]
}

cat > agent/.env <<ENVEOF
GMAIL_OAUTH_TOKEN=$(_sm_get vuln-agent-gmail-oauth-token)
SIDFM_SENDER_EMAIL=$(_sm_get vuln-agent-sidfm-sender)
SBOM_DATA_BACKEND=$(_sm_get vuln-agent-sbom-data-backend)
SBOM_SPREADSHEET_ID=$(_sm_get vuln-agent-sbom-spreadsheet-id)
SBOM_SHEET_NAME=$(_sm_get vuln-agent-sbom-sheet-name)
OWNER_SHEET_NAME=$(_sm_get vuln-agent-owner-sheet-name)
BQ_SBOM_TABLE_ID=$(_sm_get vuln-agent-bq-sbom-table-id)
BQ_OWNER_MAPPING_TABLE_ID=$(_sm_get vuln-agent-bq-owner-table-id)
DEFAULT_CHAT_SPACE_ID=$(_sm_get vuln-agent-chat-space-id)
BQ_HISTORY_TABLE_ID=$(_sm_get vuln-agent-bq-table-id)
GCP_PROJECT_ID=${PROJECT_ID}
GCP_LOCATION=${REGION}
ENVEOF

info ".env ファイルを Secret Manager の値から生成しました"

pip install -q google-adk 2>/dev/null

cd agent
DEPLOY_OUTPUT=$(adk deploy agent_engine \
  --project="$PROJECT_ID" \
  --region="$REGION" \
  --display_name="$AGENT_NAME" \
  --env_file=".env" . 2>&1) || {
    err "Agent Engine のデプロイに失敗しました"
    echo "$DEPLOY_OUTPUT"
    exit 1
  }
cd ..

echo "$DEPLOY_OUTPUT"

# デプロイ出力からリソース名を抽出して Secret Manager に保存
AGENT_RESOURCE_NAME=$(echo "$DEPLOY_OUTPUT" | grep -oP 'projects/[^\s]+/reasoningEngines/\d+' | head -1 || true)
if [[ -z "$AGENT_RESOURCE_NAME" ]]; then
  warn "リソース名の自動検出に失敗しました。手動で入力してください。"
  echo "  gcloud ai reasoning-engines list --region=${REGION} --project=${PROJECT_ID}"
  read -rp "  Agent Resource Name: " AGENT_RESOURCE_NAME
fi

if [[ -n "$AGENT_RESOURCE_NAME" ]]; then
  if ! _engine_exists "$AGENT_RESOURCE_NAME"; then
    err "デプロイ直後の Agent Resource Name が存在しません: ${AGENT_RESOURCE_NAME}"
    err "Secret の更新を中止します。デプロイ出力を確認してください。"
    exit 1
  fi

  if gcloud secrets describe "vuln-agent-resource-name" --project="$PROJECT_ID" &>/dev/null; then
    echo -n "$AGENT_RESOURCE_NAME" | gcloud secrets versions add "vuln-agent-resource-name" --data-file=- --project="$PROJECT_ID"
  else
    echo -n "$AGENT_RESOURCE_NAME" | gcloud secrets create "vuln-agent-resource-name" \
      --data-file=- --replication-policy="automatic" --project="$PROJECT_ID"
  fi
  info "Agent Resource Name を Secret Manager に保存: ${AGENT_RESOURCE_NAME}"
fi

# .env をクリーンアップ
rm -f agent/.env

# ====================================================
# 7. Live Gateway / Scheduler のデプロイ
# ====================================================
step "7/8: Live Gateway と Scheduler をデプロイしています..."

if [[ -n "$AGENT_RESOURCE_NAME" ]]; then
  if ! _engine_exists "$AGENT_RESOURCE_NAME"; then
    err "Agent Resource Name が無効です（ReasoningEngine が存在しません）: ${AGENT_RESOURCE_NAME}"
    err "Live Gateway / Scheduler のデプロイを中止します。"
    exit 1
  fi

  # --- Live Gateway (Cloud Run) ---
  GEMINI_KEY=$(_sm_get vuln-agent-gemini-api-key)
  if [[ -n "$GEMINI_KEY" ]]; then
    info "Live Gateway を Cloud Run にデプロイ中..."
    gcloud run deploy vuln-agent-live-gateway \
      --source=live_gateway \
      --region="$REGION" \
      --project="$PROJECT_ID" \
      --set-env-vars="GCP_PROJECT_ID=${PROJECT_ID},GCP_LOCATION=${REGION},AGENT_RESOURCE_NAME=${AGENT_RESOURCE_NAME}" \
      --set-secrets="GEMINI_API_KEY=vuln-agent-gemini-api-key:latest" \
      --service-account="$SA_EMAIL" \
      --allow-unauthenticated \
      --memory=512Mi \
      --timeout=3600 \
      --quiet

    GATEWAY_URL=$(gcloud run services describe vuln-agent-live-gateway \
      --region="$REGION" --project="$PROJECT_ID" --format='value(status.url)')
    info "Live Gateway: ${GATEWAY_URL}"
  else
    warn "GEMINI_API_KEY が未設定のため Live Gateway のデプロイをスキップしました"
  fi

  # --- Scheduler (Cloud Functions) ---
  info "Scheduler を Cloud Functions にデプロイ中..."
  gcloud functions deploy vuln-agent-scheduler \
    --gen2 \
    --runtime=python312 \
    --region="$REGION" \
    --project="$PROJECT_ID" \
    --source=scheduler \
    --entry-point=run_vulnerability_scan \
    --trigger-http \
    --no-allow-unauthenticated \
    --service-account="$SA_EMAIL" \
    --update-env-vars="GCP_PROJECT_ID=${PROJECT_ID},GCP_LOCATION=${REGION}" \
    --remove-env-vars="AGENT_RESOURCE_NAME" \
    --set-secrets="AGENT_RESOURCE_NAME=vuln-agent-resource-name:latest" \
    --memory=512MB \
    --timeout=540s \
    --quiet

  FUNCTION_URL=$(gcloud functions describe vuln-agent-scheduler \
    --region="$REGION" --project="$PROJECT_ID" --format='value(serviceConfig.uri)')
  info "Scheduler Function: ${FUNCTION_URL}"

  # --- Cloud Scheduler ジョブ ---
  if ! gcloud scheduler jobs describe vuln-agent-scan --location="$REGION" --project="$PROJECT_ID" &>/dev/null; then
    gcloud scheduler jobs create http vuln-agent-scan \
      --location="$REGION" \
      --project="$PROJECT_ID" \
      --schedule="0 * * * *" \
      --time-zone="Asia/Tokyo" \
      --uri="$FUNCTION_URL" \
      --http-method=POST \
      --oidc-service-account-email="$SA_EMAIL" \
      --oidc-token-audience="$FUNCTION_URL"
    info "Cloud Scheduler ジョブ作成 (毎時実行)"
  else
    info "Cloud Scheduler ジョブは既に存在します"
  fi
else
  warn "Agent Resource Name が不明のため、Live Gateway / Scheduler のデプロイをスキップしました"
fi

# ====================================================
# 8. Web UI のデプロイ
# ====================================================
step "8/8: Web UI を Cloud Storage にデプロイしています..."

gsutil -m rsync -r -d web "$WEB_UI_BUCKET"
gsutil web set -m index.html -e index.html "$WEB_UI_BUCKET"
gsutil iam ch allUsers:objectViewer "$WEB_UI_BUCKET"

WEB_URL="https://storage.googleapis.com/${PROJECT_ID}-vuln-agent-ui/index.html"
info "Web UI: ${WEB_URL}"

# ====================================================
# 完了
# ====================================================
echo ""
echo "============================================"
echo -e "  ${GREEN}セットアップ完了${NC}"
echo "============================================"
echo ""
echo "  デプロイされたコンポーネント:"
echo "  ─────────────────────────────"
echo "  Agent Engine   : ${AGENT_RESOURCE_NAME:-'(手動確認が必要)'}"
echo "  Live Gateway   : ${GATEWAY_URL:-'(スキップ)'}"
echo "  Scheduler      : ${FUNCTION_URL:-'(スキップ)'}"
echo "  Web UI         : ${WEB_URL}"
echo ""
echo "  次のステップ:"
echo "  ─────────────────────────────"
echo "  1. SBOM スプレッドシートをサービスアカウントに共有:"
echo "     ${SA_EMAIL}"
echo "  2. Google Chat アプリを GCP Console で設定 (Chat API > 構成)"
echo "  3. Web UI を開いて Live Gateway に接続:"
echo "     ${WEB_URL}"
if [[ -n "${GATEWAY_URL:-}" ]]; then
  echo "     Gateway URL: wss://$(echo "$GATEWAY_URL" | sed 's|https://||')/ws"
fi
echo ""
echo "  Cloud Console:"
echo "  https://console.cloud.google.com/vertex-ai/agents?project=${PROJECT_ID}"
echo ""
echo "  以降のコード変更は Cloud Build で自動デプロイできます:"
echo "  gcloud builds submit --config cloudbuild.yaml"
echo ""
