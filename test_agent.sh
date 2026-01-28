#!/bin/bash

MESSAGE="${1:-あなたの機能を教えてください}"

curl -s -X POST \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  "https://asia-northeast1-aiplatform.googleapis.com/v1/projects/agenticai-485616/locations/asia-northeast1/reasoningEngines/2793436833713750016:streamQuery" \
  -d "{
    \"input\": {
      \"user_id\": \"test-user\",
      \"message\": \"$MESSAGE\"
    }
  }" | python3 -c "
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
