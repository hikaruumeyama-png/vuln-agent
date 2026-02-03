# Live API + Web UI セットアップ（最小構成）

Gemini Multimodal Live API を使ったリアルタイム音声対話のための最小構成手順です。
本リポジトリには「Live API を呼び出すゲートウェイ」と「Web UI」を追加しています。

## 構成
```
Web UI (web/)  ->  Live Gateway (live_gateway/)  ->  Agent Engine (既存)
```

## 1. Live Gateway をローカルで起動
```bash
cd live_gateway
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export GCP_PROJECT_ID=YOUR_PROJECT_ID
export GCP_LOCATION=asia-northeast1
export AGENT_RESOURCE_NAME=projects/PROJECT/locations/asia-northeast1/reasoningEngines/AGENT_ID
export GEMINI_API_KEY=YOUR_API_KEY
export GEMINI_LIVE_MODEL=gemini-2.0-flash-live-001

python app.py
```

## 2. Web UI を開く
```bash
cd web
python -m http.server 8081
```

ブラウザで `http://localhost:8081` を開き、Gateway URLに
`ws://localhost:8000/ws` を指定して接続してください。

## 3. Cloud Run にデプロイ
```bash
cd live_gateway
gcloud run deploy vuln-agent-live-gateway \
  --source=. \
  --region=asia-northeast1 \
  --set-env-vars=GCP_PROJECT_ID=YOUR_PROJECT_ID,GCP_LOCATION=asia-northeast1,AGENT_RESOURCE_NAME=projects/PROJECT/locations/asia-northeast1/reasoningEngines/AGENT_ID,GEMINI_API_KEY=YOUR_API_KEY \
  --allow-unauthenticated
```

## 4. Web UI のホスティング（GCS例）
```bash
gsutil mb gs://YOUR_PROJECT_ID-live-ui
gsutil web set -m index.html -e index.html gs://YOUR_PROJECT_ID-live-ui
gsutil rsync -R web gs://YOUR_PROJECT_ID-live-ui
```

公開URLにアクセスし、Cloud Run の `wss://.../ws` を入力します。

## 5. 音声ストリーミング（完全Barge-in）
- Web UI の「Start Audio」を押すとマイク入力が開始されます。
- 音声は Live Gateway に送られ、Gemini Live API で書き起こしされます。
- 書き起こし内容に応じて Agent Engine が応答を生成し、Live API が音声で返します。
- 返答の再生中にユーザーが話し始めると再生が止まり、そのまま聞き取りを継続します。
- 短い無音区間で応答が返るように調整され、会話テンポを保ちます。
