#!/bin/bash
set -euo pipefail

# ====================================================
# 差分デプロイスクリプト
#
# 前回デプロイ時点 (git tag: last-deploy) から変更のあった
# コンポーネントだけを再デプロイします。
#
# Usage:
#   bash deploy_update.sh                  # 変更点のみデプロイ
#   bash deploy_update.sh --dry-run        # 何がデプロイされるか確認
#   bash deploy_update.sh --force          # 全コンポーネント強制デプロイ
#   bash deploy_update.sh --component agent  # 特定コンポーネントのみ
#   bash deploy_update.sh --project my-proj  # プロジェクト指定
# ====================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

step()  { echo -e "\n${GREEN}==> $1${NC}"; }
info()  { echo -e "${BLUE}    $1${NC}"; }
warn()  { echo -e "${YELLOW}[WARN] $1${NC}"; }
err()   { echo -e "${RED}[ERROR] $1${NC}"; }
ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
skip()  { echo -e "${YELLOW}[SKIP]${NC} $1"; }

# ====================================================
# 引数パース
# ====================================================
REGION="asia-northeast1"
AGENT_NAME="vulnerability-management-agent"
DRY_RUN=false
FORCE=false
TARGET_COMPONENT=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --project)     PROJECT_ID="$2";       shift 2;;
    --region)      REGION="$2";           shift 2;;
    --dry-run)     DRY_RUN=true;          shift;;
    --force)       FORCE=true;            shift;;
    --component)   TARGET_COMPONENT="$2"; shift 2;;
    -h|--help)
      echo "Usage: bash deploy_update.sh [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --dry-run              変更点の確認のみ (デプロイしない)"
      echo "  --force                全コンポーネントを強制デプロイ"
      echo "  --component NAME       特定コンポーネントのみデプロイ"
      echo "                         (agent|gateway|scheduler|web)"
      echo "  --project PROJECT_ID   GCPプロジェクトID"
      echo "  --region REGION        リージョン (default: asia-northeast1)"
      echo "  -h, --help             このヘルプを表示"
      exit 0;;
    *) err "Unknown option: $1"; exit 1;;
  esac
done

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"

if [[ -z "$PROJECT_ID" ]]; then
  err "プロジェクトIDが未設定です。"
  echo "  gcloud config set project YOUR_PROJECT_ID"
  echo "  または  bash deploy_update.sh --project YOUR_PROJECT_ID"
  exit 1
fi

SA_EMAIL="vuln-agent-sa@${PROJECT_ID}.iam.gserviceaccount.com"

echo ""
echo "============================================"
echo "  Vulnerability Management Agent"
echo "  差分デプロイ"
echo "============================================"
info "Project : ${PROJECT_ID}"
info "Region  : ${REGION}"
$DRY_RUN && info "Mode    : DRY-RUN (デプロイは実行しません)"
$FORCE   && info "Mode    : FORCE (全コンポーネントをデプロイ)"
[[ -n "$TARGET_COMPONENT" ]] && info "Target  : ${TARGET_COMPONENT}"
echo ""

# ====================================================
# 変更コンポーネントの検出
# ====================================================
step "変更コンポーネントを検出しています..."

DEPLOY_AGENT=false
DEPLOY_GATEWAY=false
DEPLOY_SCHEDULER=false
DEPLOY_WEB=false

if [[ -n "$TARGET_COMPONENT" ]]; then
  # --component 指定時: 指定コンポーネントのみ
  case "$TARGET_COMPONENT" in
    agent)     DEPLOY_AGENT=true;;
    gateway)   DEPLOY_GATEWAY=true;;
    scheduler) DEPLOY_SCHEDULER=true;;
    web)       DEPLOY_WEB=true;;
    *) err "不明なコンポーネント: $TARGET_COMPONENT (agent|gateway|scheduler|web)"; exit 1;;
  esac
elif $FORCE; then
  # --force: 全コンポーネント
  DEPLOY_AGENT=true
  DEPLOY_GATEWAY=true
  DEPLOY_SCHEDULER=true
  DEPLOY_WEB=true
else
  # 差分検出: last-deploy タグ vs HEAD
  if git rev-parse "last-deploy" &>/dev/null; then
    CHANGED_FILES=$(git diff --name-only last-deploy HEAD)

    if [[ -z "$CHANGED_FILES" ]]; then
      # タグ以降にコミットされた変更がなくても、
      # ステージされていない変更があるかチェック
      CHANGED_FILES=$(git diff --name-only HEAD)
    fi

    if [[ -z "$CHANGED_FILES" ]]; then
      echo ""
      info "前回デプロイ以降、変更はありません。"
      info "強制デプロイするには: bash deploy_update.sh --force"
      exit 0
    fi
  else
    warn "last-deploy タグが見つかりません (初回実行)。全コンポーネントをデプロイします。"
    DEPLOY_AGENT=true
    DEPLOY_GATEWAY=true
    DEPLOY_SCHEDULER=true
    DEPLOY_WEB=true
    CHANGED_FILES=""
  fi

  # ファイルパスからコンポーネントを判定
  if [[ -n "$CHANGED_FILES" ]]; then
    echo "$CHANGED_FILES" | while IFS= read -r file; do
      echo "  changed: $file"
    done

    echo "$CHANGED_FILES" | grep -q "^agent/"        && DEPLOY_AGENT=true     || true
    echo "$CHANGED_FILES" | grep -q "^live_gateway/"  && DEPLOY_GATEWAY=true   || true
    echo "$CHANGED_FILES" | grep -q "^scheduler/"     && DEPLOY_SCHEDULER=true || true
    echo "$CHANGED_FILES" | grep -q "^web/"           && DEPLOY_WEB=true       || true
  fi
fi

echo ""
echo "  デプロイ対象:"
$DEPLOY_AGENT    && echo "    - Agent Engine (agent/)"          || echo "    - Agent Engine         ... 変更なし"
$DEPLOY_GATEWAY  && echo "    - Live Gateway (live_gateway/)"   || echo "    - Live Gateway         ... 変更なし"
$DEPLOY_SCHEDULER && echo "    - Scheduler (scheduler/)"        || echo "    - Scheduler            ... 変更なし"
$DEPLOY_WEB      && echo "    - Web UI (web/)"                  || echo "    - Web UI               ... 変更なし"
echo ""

if $DRY_RUN; then
  info "DRY-RUN モード: ここで終了します。"
  info "実際にデプロイするには --dry-run を外して再実行してください。"
  exit 0
fi

# ====================================================
# Secret Manager ヘルパー
# ====================================================
_sm_get() {
  gcloud secrets versions access latest --secret="$1" --project="$PROJECT_ID" 2>/dev/null || echo ""
}

DEPLOYED_COUNT=0
FAILED_COUNT=0

# ====================================================
# Agent Engine デプロイ
# ====================================================
if $DEPLOY_AGENT; then
  step "Agent Engine をデプロイしています..."

  # .env を Secret Manager から生成
  cat > agent/.env <<ENVEOF
GMAIL_OAUTH_TOKEN=$(_sm_get vuln-agent-gmail-oauth-token)
SIDFM_SENDER_EMAIL=$(_sm_get vuln-agent-sidfm-sender)
SBOM_SPREADSHEET_ID=$(_sm_get vuln-agent-sbom-spreadsheet-id)
SBOM_SHEET_NAME=$(_sm_get vuln-agent-sbom-sheet-name)
OWNER_SHEET_NAME=$(_sm_get vuln-agent-owner-sheet-name)
DEFAULT_CHAT_SPACE_ID=$(_sm_get vuln-agent-chat-space-id)
BQ_HISTORY_TABLE_ID=$(_sm_get vuln-agent-bq-table-id)
GCP_PROJECT_ID=${PROJECT_ID}
GCP_LOCATION=${REGION}
ENVEOF

  pip install -q google-adk 2>/dev/null || true

  if (cd agent && adk deploy agent_engine \
    --project="$PROJECT_ID" \
    --region="$REGION" \
    --display_name="$AGENT_NAME" \
    --env_file=".env" . 2>&1); then
    ok "Agent Engine"
    DEPLOYED_COUNT=$((DEPLOYED_COUNT + 1))
  else
    err "Agent Engine のデプロイに失敗しました"
    FAILED_COUNT=$((FAILED_COUNT + 1))
  fi

  rm -f agent/.env
fi

# ====================================================
# Live Gateway デプロイ (Cloud Run)
# ====================================================
if $DEPLOY_GATEWAY; then
  step "Live Gateway を Cloud Run にデプロイしています..."

  AGENT_RESOURCE_NAME=$(_sm_get vuln-agent-resource-name)
  GEMINI_KEY=$(_sm_get vuln-agent-gemini-api-key)

  if [[ -z "$AGENT_RESOURCE_NAME" ]]; then
    warn "vuln-agent-resource-name が未登録。Live Gateway をスキップします。"
  elif [[ -z "$GEMINI_KEY" ]]; then
    warn "vuln-agent-gemini-api-key が未登録。Live Gateway をスキップします。"
  else
    if gcloud run deploy vuln-agent-live-gateway \
      --source=live_gateway \
      --region="$REGION" \
      --project="$PROJECT_ID" \
      --set-env-vars="GCP_PROJECT_ID=${PROJECT_ID},GCP_LOCATION=${REGION},AGENT_RESOURCE_NAME=${AGENT_RESOURCE_NAME}" \
      --set-secrets="GEMINI_API_KEY=vuln-agent-gemini-api-key:latest" \
      --service-account="$SA_EMAIL" \
      --allow-unauthenticated \
      --memory=512Mi \
      --timeout=3600 \
      --quiet; then
      GATEWAY_URL=$(gcloud run services describe vuln-agent-live-gateway \
        --region="$REGION" --project="$PROJECT_ID" --format='value(status.url)')
      ok "Live Gateway: ${GATEWAY_URL}"
      DEPLOYED_COUNT=$((DEPLOYED_COUNT + 1))
    else
      err "Live Gateway のデプロイに失敗しました"
      FAILED_COUNT=$((FAILED_COUNT + 1))
    fi
  fi
fi

# ====================================================
# Scheduler デプロイ (Cloud Functions)
# ====================================================
if $DEPLOY_SCHEDULER; then
  step "Scheduler を Cloud Functions にデプロイしています..."

  AGENT_RESOURCE_NAME=$(_sm_get vuln-agent-resource-name)

  if [[ -z "$AGENT_RESOURCE_NAME" ]]; then
    warn "vuln-agent-resource-name が未登録。Scheduler をスキップします。"
  else
    if gcloud functions deploy vuln-agent-scheduler \
      --gen2 \
      --runtime=python312 \
      --region="$REGION" \
      --project="$PROJECT_ID" \
      --source=scheduler \
      --entry-point=run_vulnerability_scan \
      --trigger-http \
      --no-allow-unauthenticated \
      --service-account="$SA_EMAIL" \
      --set-env-vars="GCP_PROJECT_ID=${PROJECT_ID},GCP_LOCATION=${REGION},AGENT_RESOURCE_NAME=${AGENT_RESOURCE_NAME}" \
      --memory=512MB \
      --timeout=540s \
      --quiet; then
      ok "Scheduler"
      DEPLOYED_COUNT=$((DEPLOYED_COUNT + 1))
    else
      err "Scheduler のデプロイに失敗しました"
      FAILED_COUNT=$((FAILED_COUNT + 1))
    fi
  fi
fi

# ====================================================
# Web UI デプロイ (Cloud Storage)
# ====================================================
if $DEPLOY_WEB; then
  step "Web UI を Cloud Storage にデプロイしています..."

  WEB_UI_BUCKET="gs://${PROJECT_ID}-vuln-agent-ui"

  if gsutil -m rsync -r -d web "$WEB_UI_BUCKET"; then
    WEB_URL="https://storage.googleapis.com/${PROJECT_ID}-vuln-agent-ui/index.html"
    ok "Web UI: ${WEB_URL}"
    DEPLOYED_COUNT=$((DEPLOYED_COUNT + 1))
  else
    err "Web UI のデプロイに失敗しました"
    FAILED_COUNT=$((FAILED_COUNT + 1))
  fi
fi

# ====================================================
# デプロイ完了 → last-deploy タグを更新
# ====================================================
echo ""
echo "============================================"

if [[ $FAILED_COUNT -eq 0 && $DEPLOYED_COUNT -gt 0 ]]; then
  git tag -f last-deploy HEAD 2>/dev/null || true
  echo -e "  ${GREEN}デプロイ完了${NC} (${DEPLOYED_COUNT} コンポーネント)"
  info "last-deploy タグを更新しました"
elif [[ $DEPLOYED_COUNT -eq 0 ]]; then
  echo -e "  ${YELLOW}デプロイ対象がありませんでした${NC}"
else
  echo -e "  ${RED}一部失敗${NC} (成功: ${DEPLOYED_COUNT}, 失敗: ${FAILED_COUNT})"
  echo -e "  ${YELLOW}last-deploy タグは更新されていません${NC}"
fi

echo "============================================"
echo ""
