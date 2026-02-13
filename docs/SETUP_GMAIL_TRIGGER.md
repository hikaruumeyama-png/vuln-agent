# Gmail受信トリガー セットアップガイド

`setup_cloud.sh` 実行時に、以下が自動構築されます。

- Pub/Sub topic: `vuln-agent-gmail-events`
- Cloud Functions:
  - `vuln-agent-gmail-trigger`（Pub/Sub受信）
  - `vuln-agent-gmail-watch-refresh`（watch更新用HTTP）
- Cloud Scheduler job: `vuln-agent-gmail-watch-renew`（6時間毎）

## 動作概要

1. Gmail Push 通知が Pub/Sub に届く  
2. `vuln-agent-gmail-trigger` が起動  
3. Gmail で以下クエリの未読有無を軽量チェック  
   `(from:<SIDFM_SENDER_EMAIL> OR subject:"[SIDfm]") is:unread newer_than:7d`
4. 一致があれば Agent Engine を実行  

## 手動確認コマンド

```bash
gcloud pubsub topics describe vuln-agent-gmail-events
gcloud functions describe vuln-agent-gmail-trigger --region=asia-northeast1
gcloud functions describe vuln-agent-gmail-watch-refresh --region=asia-northeast1
gcloud scheduler jobs describe vuln-agent-gmail-watch-renew --location=asia-northeast1
```

## watch更新を手動実行

```bash
gcloud scheduler jobs run vuln-agent-gmail-watch-renew --location=asia-northeast1
```

