# Live Gateway (Gemini Multimodal Live API)

Webクライアントの音声/テキスト入力を受け取り、Gemini Multimodal Live APIと
Vertex AI Agent Engine を橋渡しする最小構成のゲートウェイです。

## 役割
- WebSocketでクライアント接続を受ける
- 受信したテキストを Agent Engine に問い合わせ
- Gemini Live API を使った音声ストリーミング（入力/出力）
- 音声入力は書き起こして Agent Engine に渡し、応答を音声化
- OIDC有効時はUI/WSを認証セッションで保護
- 認証ユーザー単位のチャット監査ログ（`chat_audit`）を出力

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

## UI保護 + OIDC（Entra ID）
必要環境変数:
- `OIDC_ENABLED=true`
- `OIDC_TENANT_ID=<entra-tenant-id>`
- `OIDC_CLIENT_ID=<app-registration-client-id>`
- `OIDC_CLIENT_SECRET=<client-secret>`
- `OIDC_REDIRECT_URI=https://<live-gateway-domain>/auth/callback`
- `OIDC_SESSION_SECRET=<32bytes以上のランダム文字列>`

補足:
- 未認証アクセス時、`/` と静的アセットは `/login` へ遷移します。
- WebSocket `/ws` は未認証だと `4401 Unauthorized` で切断します。
- `OIDC_ENABLED=false` では従来動作（UI保護なし）です。
