# Gmail連携 セットアップガイド

個人Gmail（@gmail.com）での設定手順です。

---

## 概要

```
┌─────────────────────────────────────────────────────────────────┐
│                    セットアップの流れ                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Step 1: GCPでOAuthクライアント作成           （5分）             │
│     ↓                                                            │
│  Step 2: Gmail API 有効化                      （1分）             │
│     ↓                                                            │
│  Step 3: OAuth同意画面の設定                   （3分）             │
│     ↓                                                            │
│  Step 4: セットアップスクリプト実行            （2分）             │
│     ↓                                                            │
│  Step 5: Agent Engine 再デプロイ               （3分）             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Step 1: OAuth クライアントID の作成

### 1.1 Google Cloud Console にアクセス

```
https://console.cloud.google.com/apis/credentials
```

### 1.2 OAuth クライアントID を作成

1. 「**認証情報を作成**」をクリック
2. 「**OAuth クライアントID**」を選択
3. 以下を入力:

| 項目 | 値 |
|------|-----|
| アプリケーションの種類 | **デスクトップアプリ** |
| 名前 | `vuln-agent-gmail` |

4. 「**作成**」をクリック

### 1.3 認証情報をダウンロード

1. 作成されたクライアントIDの右側「**⬇ダウンロード**」をクリック
2. JSONファイルを保存
3. ファイル名を `credentials.json` に変更
4. プロジェクトルートに配置:

```bash
mv ~/Downloads/client_secret_xxx.json /path/to/vuln-agent-engine/credentials.json
```

---

## Step 2: Gmail API の有効化

### 2.1 APIライブラリにアクセス

```
https://console.cloud.google.com/apis/library/gmail.googleapis.com
```

### 2.2 有効化

「**有効にする**」ボタンをクリック

---

## Step 3: OAuth 同意画面の設定

### 3.1 OAuth同意画面にアクセス

```
https://console.cloud.google.com/apis/credentials/consent
```

### 3.2 ユーザータイプを選択

| 選択肢 | 説明 |
|--------|------|
| **外部** | 個人Gmailの場合はこちら |
| 内部 | Google Workspace の場合 |

「**外部**」を選択して「**作成**」

### 3.3 アプリ情報を入力

| 項目 | 値 |
|------|-----|
| アプリ名 | `脆弱性管理エージェント` |
| ユーザーサポートメール | あなたのメールアドレス |
| デベロッパーの連絡先 | あなたのメールアドレス |

「**保存して次へ**」

### 3.4 スコープの設定

1. 「**スコープを追加または削除**」をクリック
2. 以下を検索して追加:

```
https://www.googleapis.com/auth/gmail.modify
```

3. 「**更新**」→「**保存して次へ**」

### 3.5 テストユーザーの追加

1. 「**ADD USERS**」をクリック
2. **あなたのGmailアドレス**を入力
3. 「**追加**」→「**保存して次へ**」

> ⚠️ **重要**: テストユーザーに追加しないと認証できません

---

## Step 4: セットアップスクリプトの実行

### 4.1 スクリプトを実行

```bash
cd /path/to/vuln-agent-engine
python setup_gmail_oauth.py
```

### 4.2 ブラウザで認証

1. ブラウザが自動で開きます
2. Googleアカウントを選択
3. 「**このアプリは確認されていません**」と表示されたら:
   - 「**詳細**」をクリック
   - 「**（安全ではないページ）に移動**」をクリック
4. 「**許可**」をクリック

### 4.3 完了確認

```
╔══════════════════════════════════════════════════════════════════╗
║                      セットアップ完了！                           ║
╠══════════════════════════════════════════════════════════════════╣
║  以下のファイルが作成/更新されました:                              ║
║    • token.json         - OAuth トークン                         ║
║    • agent/.env         - 環境変数                               ║
╚══════════════════════════════════════════════════════════════════╝
```

---

## Step 5: Agent Engine の再デプロイ

### 5.1 環境変数の確認

`agent/.env` に以下が追加されていることを確認:

```bash
cat agent/.env
```

```
GMAIL_OAUTH_TOKEN=eyJhbGci...（長いBase64文字列）
GMAIL_USER_EMAIL=your-email@gmail.com
```

### 5.2 再デプロイ

```bash
./deploy.sh
```

---

## Step 6: 動作確認

### 6.1 Gmail接続テスト

```bash
./test_agent.sh "Gmailへの接続を確認して"
```

期待される応答:
```
Gmail APIへの接続に成功しました。
メールアドレス: your-email@gmail.com
```

### 6.2 メール取得テスト

```bash
./test_agent.sh "未読メールを3件取得して"
```

---

## トラブルシューティング

### エラー: "Access Denied"

**原因**: テストユーザーに追加されていない

**解決**: OAuth同意画面 → テストユーザー → あなたのメールアドレスを追加

---

### エラー: "Token has been expired or revoked"

**原因**: トークンの期限切れ

**解決**: セットアップスクリプトを再実行

```bash
rm token.json
python setup_gmail_oauth.py
```

---

### エラー: "credentials.json not found"

**原因**: OAuthクライアントIDのJSONファイルがない

**解決**: Step 1 を再確認して credentials.json を配置

---

## 将来のGoogle Workspace移行

Google Workspaceに移行する場合は、以下の変更のみで対応可能:

1. `GMAIL_OAUTH_TOKEN` 環境変数を削除
2. `GMAIL_USER_EMAIL` に対象ユーザーのメールアドレスを設定
3. Google Workspace管理コンソールでドメイン全体の委任を設定

詳細は `docs/SETUP_WORKSPACE.md` を参照してください。
