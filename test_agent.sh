#!/bin/bash

MESSAGE="${1:-あなたの機能を教えてください}"

PROJECT_ID="${GCP_PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
REGION="${GCP_LOCATION:-asia-northeast1}"

if [[ -z "$PROJECT_ID" ]]; then
  echo "Error: GCP_PROJECT_ID が未設定です。gcloud config set project YOUR_PROJECT_ID を実行してください。"
  exit 1
fi

AGENT_RESOURCE_NAME=$(gcloud secrets versions access latest --secret=vuln-agent-resource-name --project="$PROJECT_ID" 2>/dev/null)

if [[ -z "$AGENT_RESOURCE_NAME" ]]; then
  echo "Error: vuln-agent-resource-name シークレットが取得できません。setup_cloud.sh を実行してください。"
  exit 1
fi

ENDPOINT="https://${REGION}-aiplatform.googleapis.com/v1/${AGENT_RESOURCE_NAME}:streamQuery"

# python3 で JSON を安全に組み立てる
JSON_PAYLOAD=$(python3 -c "
import json, sys
print(json.dumps({'input': {'user_id': 'test-user', 'message': sys.argv[1]}}))" "$MESSAGE")

curl -s -X POST \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  "$ENDPOINT" \
  -d "$JSON_PAYLOAD" | python3 -c "
import sys
import json

for line in sys.stdin:
    try:
        data = json.loads(line)
        if 'content' in data and 'parts' in data['content']:
            for part in data['content']['parts']:
                if 'text' in part:
                    print(part['text'])
    except:
        pass
"
