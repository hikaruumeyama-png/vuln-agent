# Google Chat メンション対話 セットアップガイド

`setup_cloud.sh` 実行後、以下が自動デプロイされます。

- Cloud Functions: `vuln-agent-chat-webhook`
- URL: スクリプト出力の `Chat Webhook`

## Chat API 側の設定

Google Cloud Console > Chat API > 構成 で以下を設定します。

1. `アプリのURL` に `vuln-agent-chat-webhook` の URL を設定  
2. `スペースとグループの会話でアプリを有効にする` を ON  
3. 必要なら `1:1 でのメッセージ受信` を ON  

## 送信例

スペースでアプリをメンションして質問します。

- `@脆弱性管理Bot CVE-2026-xxxx の影響を確認して`
- `@脆弱性管理Bot log4j の影響システムを教えて`

## 検証トークン（任意）

Webhook検証を有効にする場合は以下シークレットを登録します。

```bash
echo -n "your-chat-verification-token" | \
  gcloud secrets versions add vuln-agent-chat-verification-token --data-file=-
```

> Chat API の設定値と同じトークンを設定してください。

## ログ確認

```bash
gcloud functions logs read vuln-agent-chat-webhook --region=asia-northeast1 --limit=50
```

