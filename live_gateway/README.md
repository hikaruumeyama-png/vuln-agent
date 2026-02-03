# Live Gateway (Gemini Multimodal Live API)

Webクライアントの音声/テキスト入力を受け取り、Gemini Multimodal Live APIと
Vertex AI Agent Engine を橋渡しする最小構成のゲートウェイです。

## 役割
- WebSocketでクライアント接続を受ける
- 受信したテキストを Agent Engine に問い合わせ
- Gemini Live API を使った音声ストリーミング（入力/出力）
- 音声入力は書き起こして Agent Engine に渡し、応答を音声化

## 使い方（ローカル確認）
```bash
cd live_gateway
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export GCP_PROJECT_ID=YOUR_PROJECT_ID
export GCP_LOCATION=asia-northeast1
export AGENT_RESOURCE_NAME=projects/PROJECT/locations/asia-northeast1/reasoningEngines/AGENT_ID
export GEMINI_API_KEY=YOUR_API_KEY

python app.py
```

## Cloud Run デプロイ例
```bash
gcloud run deploy vuln-agent-live-gateway \
  --source=. \
  --region=asia-northeast1 \
  --set-env-vars=GCP_PROJECT_ID=YOUR_PROJECT_ID,GCP_LOCATION=asia-northeast1,AGENT_RESOURCE_NAME=projects/PROJECT/locations/asia-northeast1/reasoningEngines/AGENT_ID,GEMINI_API_KEY=YOUR_API_KEY \
  --allow-unauthenticated
```
