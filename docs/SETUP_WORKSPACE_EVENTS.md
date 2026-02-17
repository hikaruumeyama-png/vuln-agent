# Workspace Events (リアクション起点) セットアップ

この機能は、Google Chat メッセージに `？` リアクションが付いたときに、
元メッセージを解析して同じスレッドへ返信します。

## デプロイ対象

- Cloud Functions: `vuln-agent-workspace-events-webhook`
- Entry point: `handle_workspace_event`
- Source: `workspace_events_webhook/`

## 事前準備

1. `setup_cloud.sh` または `cloudbuild.yaml` で上記 Function をデプロイ
2. Workspace Events API で Chat reaction イベントを購読
3. Pub/Sub Push の通知先を Function URL に設定

## 購読イベント

- `google.workspace.chat.reaction.v1.created`
- `google.workspace.chat.reaction.v1.batchCreated`

## 動作仕様

1. リアクションイベント受信
2. `？` / `❓` 系リアクションのみ処理
3. 対象メッセージ（リアクション元）を取得
4. エージェントで解析
5. 同じスレッドに返信

## 注意

- Function は重複イベントをメモリ内で簡易除外します（短期）。
- 再デプロイやスケールアウト時の重複完全排除には外部ストアの冪等管理を追加してください。

## 開発バックログ（本番向け）

1. 冪等性の永続化
- Event ID / Reaction ID を Firestore または BigQuery に保存し、再配信・再起動時も重複実行を防止する。

2. 失敗時の再実行制御
- 解析失敗イベントを DLQ（Pub/Sub dead letter）へ退避し、再処理バッチを用意する。

3. 監視とアラート
- 処理件数・失敗件数・重複スキップ件数を Cloud Monitoring 指標化し、閾値アラートを設定する。

4. リアクション対象制御
- `？` リアクション以外の拡張（例: `❗` は高優先度）を設定可能にする。

5. レート制御
- 同一スレッド/同一ユーザーの短時間連打を抑止するスロットリングを追加する。
