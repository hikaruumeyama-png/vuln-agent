#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-vuln-agent-live-gateway}"
REGION="${REGION:-asia-northeast1}"
ROLE="roles/run.invoker"
MEMBER="allUsers"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/gateway-access.sh open
  bash scripts/gateway-access.sh close
  bash scripts/gateway-access.sh status

Optional environment variables:
  SERVICE_NAME (default: vuln-agent-live-gateway)
  REGION       (default: asia-northeast1)
EOF
}

status() {
  gcloud run services get-iam-policy "${SERVICE_NAME}" \
    --region="${REGION}" \
    --format="table(bindings.role,bindings.members)"
}

open_gateway() {
  echo "[gateway-access] Opening public access for ${SERVICE_NAME} (${REGION})..."
  gcloud run services add-iam-policy-binding "${SERVICE_NAME}" \
    --region="${REGION}" \
    --member="${MEMBER}" \
    --role="${ROLE}" >/dev/null
  echo "[gateway-access] Public access enabled."
  status
}

close_gateway() {
  echo "[gateway-access] Closing public access for ${SERVICE_NAME} (${REGION})..."
  gcloud run services remove-iam-policy-binding "${SERVICE_NAME}" \
    --region="${REGION}" \
    --member="${MEMBER}" \
    --role="${ROLE}" >/dev/null
  echo "[gateway-access] Public access disabled."
  status
}

if ! command -v gcloud >/dev/null 2>&1; then
  echo "gcloud command not found. Install Google Cloud CLI first." >&2
  exit 1
fi

if [[ $# -ne 1 ]]; then
  usage
  exit 1
fi

case "$1" in
  open)
    open_gateway
    ;;
  close)
    close_gateway
    ;;
  status)
    status
    ;;
  *)
    usage
    exit 1
    ;;
esac
