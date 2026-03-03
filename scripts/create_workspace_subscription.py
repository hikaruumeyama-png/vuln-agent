"""
Workspace Events API サブスクリプション作成スクリプト

Google Chat スペースのメッセージ・リアクションイベントを
Pub/Sub トピック経由で受信するためのサブスクリプションを作成します。

PowerShell での使い方:
  # 依存パッケージインストール（初回のみ）
  pip install google-auth google-auth-oauthlib

  # 初回実行（OAuth クライアント ID JSON が必要）
  python scripts\create_workspace_subscription.py --client-secrets C:\path\to\client_secret.json

  # 2回目以降（トークンがキャッシュされるので --client-secrets 不要）
  python scripts\create_workspace_subscription.py

注意:
  - OAuth ユーザー認証が必要（サービスアカウントでは不可）
  - chat.messages.readonly スコープが必要
  - サブスクリプションは 7日間 で自動失効
"""

from __future__ import annotations

import argparse
import json
import sys

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

SCOPES = [
    "https://www.googleapis.com/auth/chat.messages.readonly",
    "https://www.googleapis.com/auth/chat.memberships.readonly",
]

WORKSPACE_EVENTS_API = "https://workspaceevents.googleapis.com/v1/subscriptions"

DEFAULT_EVENT_TYPES = [
    "google.workspace.chat.message.v1.created",
    "google.workspace.chat.reaction.v1.created",
]


def get_credentials(client_secrets_file: str | None = None) -> Credentials:
    """OAuth 認証でクレデンシャルを取得する。"""
    import os

    token_file = os.path.join(os.path.dirname(__file__), ".workspace_events_token.json")

    creds = None
    if os.path.exists(token_file):
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not client_secrets_file:
                print(
                    "初回認証には --client-secrets でOAuth クライアント ID の"
                    "JSON ファイルを指定してください。",
                    file=sys.stderr,
                )
                sys.exit(1)
            flow = InstalledAppFlow.from_client_secrets_file(client_secrets_file, SCOPES)
            creds = flow.run_local_server(port=0)

        with open(token_file, "w") as f:
            f.write(creds.to_json())
        print(f"トークンを保存しました: {token_file}", file=sys.stderr)

    return creds


def create_subscription(
    creds: Credentials,
    space_id: str,
    topic: str,
    event_types: list[str] | None = None,
) -> dict:
    """Workspace Events API でサブスクリプションを作成する。"""
    import urllib.request

    if event_types is None:
        event_types = DEFAULT_EVENT_TYPES

    target_resource = f"//chat.googleapis.com/{space_id}"

    body = {
        "targetResource": target_resource,
        "eventTypes": event_types,
        "notificationEndpoint": {
            "pubsubTopic": topic,
        },
        "payloadOptions": {
            "includeResource": True,
        },
    }

    req = urllib.request.Request(
        WORKSPACE_EVENTS_API,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {creds.token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        print(f"API エラー ({e.code}): {error_body}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Workspace Events API サブスクリプション作成"
    )
    parser.add_argument(
        "--space-id",
        default="spaces/AAAA--pjkDQ",
        help="Google Chat スペースID (デフォルト: spaces/AAAA--pjkDQ)",
    )
    parser.add_argument(
        "--topic",
        default="projects/info-sec-ai-platform/topics/vuln-agent-workspace-events",
        help="Pub/Sub トピック (デフォルト: info-sec-ai-platform のトピック)",
    )
    parser.add_argument(
        "--client-secrets",
        default=None,
        help="OAuth クライアント ID JSON ファイル（初回認証時のみ必要）",
    )
    parser.add_argument(
        "--event-types",
        nargs="+",
        default=None,
        help="購読するイベントタイプ（省略時はメッセージ+リアクション）",
    )
    args = parser.parse_args()

    creds = get_credentials(args.client_secrets)
    result = create_subscription(
        creds=creds,
        space_id=args.space_id,
        topic=args.topic,
        event_types=args.event_types,
    )

    print(json.dumps(result, indent=2, ensure_ascii=False))
    print(
        f"\nサブスクリプション作成成功。"
        f"7日後に失効するため定期更新を設定してください。",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
