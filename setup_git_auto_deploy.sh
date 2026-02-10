#!/bin/bash
set -euo pipefail

# Cloud Shell 向け: git pull 後に Cloud Build で自動再デプロイする Git Hook を設定
# 使い方:
#   ./setup_git_auto_deploy.sh            # インストール
#   ./setup_git_auto_deploy.sh --status   # 状態確認
#   ./setup_git_auto_deploy.sh --remove   # アンインストール
#   ./setup_git_auto_deploy.sh --force    # 既存hookがある場合でも上書きインストール

HOOK_PATH=".git/hooks/post-merge"
MANAGED_MARKER="vuln-agent auto deploy hook"

show_status() {
  if [[ -x "$HOOK_PATH" ]] && grep -q "$MANAGED_MARKER" "$HOOK_PATH"; then
    echo "✅ post-merge hook is installed: $HOOK_PATH"
  elif [[ -f "$HOOK_PATH" ]]; then
    echo "⚠️ post-merge hook exists but is not managed by this script: $HOOK_PATH"
  else
    echo "ℹ️  post-merge hook is not installed"
  fi
}

remove_hook() {
  if [[ -f "$HOOK_PATH" ]] && grep -q "$MANAGED_MARKER" "$HOOK_PATH"; then
    rm -f "$HOOK_PATH"
    echo "✅ Removed $HOOK_PATH"
  else
    echo "ℹ️  No managed hook to remove"
  fi
}

write_managed_hook() {
  cat > "$HOOK_PATH" <<'HOOKEOF'
#!/bin/bash
# vuln-agent auto deploy hook
set -euo pipefail

log() {
  echo "[vuln-agent:auto-deploy] $*"
}

if [[ "${SKIP_AUTO_DEPLOY:-}" == "1" ]]; then
  log "SKIP_AUTO_DEPLOY=1 のためスキップ"
  exit 0
fi

if ! command -v gcloud >/dev/null 2>&1; then
  log "gcloud コマンドが見つからないためスキップ"
  exit 0
fi

if ! command -v git >/dev/null 2>&1; then
  log "git コマンドが見つからないためスキップ"
  exit 0
fi

PROJECT_ID="$(gcloud config get-value project 2>/dev/null || true)"
if [[ -z "$PROJECT_ID" || "$PROJECT_ID" == "(unset)" ]]; then
  log "gcloud project が未設定のためスキップ"
  exit 0
fi

BASE_REF="${ORIG_HEAD:-}"
if [[ -z "$BASE_REF" ]] || ! git rev-parse --verify "$BASE_REF" >/dev/null 2>&1; then
  BASE_REF="HEAD~1"
fi

CHANGED_FILES="$(git diff --name-only "$BASE_REF" HEAD || true)"
if [[ -z "$CHANGED_FILES" ]]; then
  log "変更ファイルなし。デプロイ不要"
  exit 0
fi

if ! echo "$CHANGED_FILES" | grep -Eq '^(agent/|scheduler/|live_gateway/|web/|cloudbuild.yaml|setup_cloud.sh|setup_git_auto_deploy.sh|deploy.sh|requirements.txt)'; then
  log "インフラ/アプリ変更なし。デプロイ不要"
  exit 0
fi

if [[ ! -f "cloudbuild.yaml" ]]; then
  log "cloudbuild.yaml が見つからないためスキップ"
  exit 0
fi

if [[ "${AUTO_DEPLOY_DRY_RUN:-}" == "1" ]]; then
  log "AUTO_DEPLOY_DRY_RUN=1 のため gcloud builds submit を実行せず終了"
  exit 0
fi

log "変更を検知: Cloud Build で再デプロイを開始します"
gcloud builds submit --config cloudbuild.yaml --project "$PROJECT_ID"
log "Cloud Build 送信完了"
HOOKEOF

  chmod +x "$HOOK_PATH"
  echo "✅ Installed post-merge hook: $HOOK_PATH"
  echo "   git pull 実行後に対象変更があれば自動で Cloud Build を起動します"
  echo "   一時無効化: SKIP_AUTO_DEPLOY=1 git pull"
}

install_hook() {
  if [[ -f "$HOOK_PATH" ]] && ! grep -q "$MANAGED_MARKER" "$HOOK_PATH"; then
    echo "❌ 既存の post-merge hook があるため上書きしません: $HOOK_PATH" >&2
    echo "   上書きする場合は --force を指定してください" >&2
    exit 1
  fi
  write_managed_hook
}

force_install_hook() {
  if [[ -f "$HOOK_PATH" ]] && ! grep -q "$MANAGED_MARKER" "$HOOK_PATH"; then
    cp "$HOOK_PATH" "${HOOK_PATH}.bak.$(date +%Y%m%d%H%M%S)"
    echo "⚠️ 既存hookをバックアップしました: ${HOOK_PATH}.bak.*"
  fi
  write_managed_hook
}

case "${1:-}" in
  --status)
    show_status
    ;;
  --remove)
    remove_hook
    ;;
  --force)
    force_install_hook
    ;;
  "")
    install_hook
    ;;
  *)
    echo "Unknown option: $1" >&2
    echo "Usage: $0 [--status|--remove|--force]" >&2
    exit 1
    ;;
esac
