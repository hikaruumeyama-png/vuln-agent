#!/usr/bin/env python3
"""
Gmail OAuth セットアップスクリプト

個人Gmail（@gmail.com）用のOAuth認証を設定します。
初回のみブラウザで認証が必要です。

使い方:
    python setup_gmail_oauth.py

事前準備:
    1. Google Cloud Console で OAuth 2.0 クライアントIDを作成
    2. credentials.json をダウンロードしてこのディレクトリに配置
"""

import os
import sys
import json
import base64
from pathlib import Path
from urllib.parse import urlparse, parse_qs

# Google Auth ライブラリ
try:
    from google_auth_oauthlib.flow import InstalledAppFlow
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
except ImportError:
    print("必要なライブラリをインストールしています...")
    os.system("pip install google-auth-oauthlib google-auth-httplib2 google-api-python-client")
    from google_auth_oauthlib.flow import InstalledAppFlow
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials

# Gmail API スコープ
SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",  # メール読み取り・既読マーク
]

# ファイルパス
SCRIPT_DIR = Path(__file__).parent
CREDENTIALS_FILE = SCRIPT_DIR / "credentials.json"
TOKEN_FILE = SCRIPT_DIR / "token.json"
ENV_FILE = SCRIPT_DIR / "agent" / ".env"


def check_credentials_file():
    """credentials.json の存在確認"""
    if not CREDENTIALS_FILE.exists():
        print("""
╔══════════════════════════════════════════════════════════════════╗
║  credentials.json が見つかりません                                ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  以下の手順で作成してください:                                     ║
║                                                                  ║
║  1. Google Cloud Console を開く                                  ║
║     https://console.cloud.google.com/apis/credentials            ║
║                                                                  ║
║  2. 「認証情報を作成」→「OAuth クライアントID」                    ║
║                                                                  ║
║  3. アプリケーションの種類: 「デスクトップアプリ」                  ║
║                                                                  ║
║  4. 作成後、JSONをダウンロード                                    ║
║                                                                  ║
║  5. ファイル名を credentials.json に変更して                      ║
║     このディレクトリに配置                                        ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
""")
        return False
    return True


def setup_oauth():
    """OAuth認証を実行してトークンを取得"""
    creds = None
    use_console = True

    # 既存のトークンがあれば読み込み
    if TOKEN_FILE.exists():
        creds = Credentials.from_authorized_user_file(str(TOKEN_FILE), SCOPES)

    # トークンがないか期限切れの場合
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            print("トークンを更新しています...")
            creds.refresh(Request())
        else:
            print("""
╔══════════════════════════════════════════════════════════════════╗
║  ブラウザでGoogleアカウントにログインしてください                   ║
╚══════════════════════════════════════════════════════════════════╝
""")
            flow = InstalledAppFlow.from_client_secrets_file(
                str(CREDENTIALS_FILE), SCOPES
            )
            if use_console:
                print("""
╔══════════════════════════════════════════════════════════════════╗
║  コンソール認証モードで進めます                                     ║
║  1) 表示されたURLをブラウザで開く                                   ║
║  2) 許可後に表示されるコードをここに貼り付ける                       ║
║     (localhost エラー画面でもURLをコピーしてください)             ║
╚══════════════════════════════════════════════════════════════════╝
""")
                auth_url, _ = flow.authorization_url(
                    access_type="offline",
                    include_granted_scopes="true",
                    prompt="consent",
                )
                print(f"\nURL: {auth_url}\n")
                redirect_response = input("リダイレクト先のURL (またはコード) を貼り付けてください: ").strip()
                parsed = urlparse(redirect_response)
                code = None
                if parsed.scheme and parsed.netloc:
                    query = parse_qs(parsed.query)
                    code_values = query.get("code")
                    if code_values:
                        code = code_values[0]
                if not code:
                    code = redirect_response
                flow.fetch_token(code=code)
                creds = flow.credentials
            else:
                creds = flow.run_local_server(port=8080)

        # トークンを保存
        with open(TOKEN_FILE, "w") as token:
            token.write(creds.to_json())
        print(f"✅ トークンを保存しました: {TOKEN_FILE}")

    return creds


def create_env_token(creds):
    """環境変数用のトークン文字列を生成"""
    token_data = {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes,
    }
    # Base64エンコード
    token_json = json.dumps(token_data)
    token_base64 = base64.b64encode(token_json.encode()).decode()
    return token_base64


def verify_token(creds):
    """トークンが正しく動作するか確認"""
    from googleapiclient.discovery import build

    try:
        service = build("gmail", "v1", credentials=creds)
        profile = service.users().getProfile(userId="me").execute()
        email = profile.get("emailAddress", "不明")
        print(f"✅ 認証成功: {email}")
        return email
    except Exception as e:
        print(f"❌ 認証エラー: {e}")
        return None


def update_env_file(token_base64, email):
    """環境変数ファイルを更新"""
    env_content = ""

    if ENV_FILE.exists():
        with open(ENV_FILE, "r") as f:
            env_content = f.read()

    # GMAIL_OAUTH_TOKEN を追加/更新
    lines = env_content.split("\n")
    new_lines = []
    token_added = False

    for line in lines:
        if line.startswith("GMAIL_OAUTH_TOKEN="):
            new_lines.append(f"GMAIL_OAUTH_TOKEN={token_base64}")
            token_added = True
        elif line.startswith("GMAIL_USER_EMAIL="):
            new_lines.append(f"GMAIL_USER_EMAIL={email}")
        else:
            new_lines.append(line)

    if not token_added:
        new_lines.append(f"\n# Gmail OAuth Token (個人Gmail用)")
        new_lines.append(f"GMAIL_OAUTH_TOKEN={token_base64}")

    with open(ENV_FILE, "w") as f:
        f.write("\n".join(new_lines))

    print(f"✅ 環境変数ファイルを更新しました: {ENV_FILE}")


def main():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║          Gmail OAuth セットアップ（個人Gmail用）                   ║
╚══════════════════════════════════════════════════════════════════╝
""")

    # Step 1: credentials.json 確認
    print("Step 1: credentials.json を確認中...")
    if not check_credentials_file():
        sys.exit(1)
    print("✅ credentials.json を確認しました\n")

    # Step 2: OAuth認証
    print("Step 2: OAuth認証を実行中...")
    creds = setup_oauth()
    print()

    # Step 3: 認証確認
    print("Step 3: 認証を確認中...")
    email = verify_token(creds)
    if not email:
        sys.exit(1)
    print()

    # Step 4: 環境変数用トークン生成
    print("Step 4: 環境変数を設定中...")
    token_base64 = create_env_token(creds)
    update_env_file(token_base64, email)
    print()

    # 完了メッセージ
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                      セットアップ完了！                           ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  以下のファイルが作成/更新されました:                              ║
║                                                                  ║
║    • token.json         - OAuth トークン（ローカル用）            ║
║    • agent/.env         - 環境変数（デプロイ用）                  ║
║                                                                  ║
║  次のステップ:                                                    ║
║                                                                  ║
║    1. Agent Engine を再デプロイ                                  ║
║       ./deploy.sh                                                ║
║                                                                  ║
║    2. Gmail連携をテスト                                          ║
║       ./test_agent.sh "SIDfmからのメールを確認して"               ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    main()
