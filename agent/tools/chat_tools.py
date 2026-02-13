"""
Google Chat Tools - 脆弱性アラート送信

Vertex AI Agent Engine版
"""

import os
import re
import time
import logging
from typing import Any
from datetime import datetime, timedelta

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

try:
    from .secret_config import get_config_value
except ImportError:
    from secret_config import get_config_value

logger = logging.getLogger(__name__)

# 重大度設定
SEVERITY_EMOJI = {
    "緊急": "🔴",
    "高": "🟠",
    "中": "🟡",
    "低": "🟢",
}

SEVERITY_DEADLINES = {
    "緊急": timedelta(days=1),
    "高": timedelta(days=3),
    "中": timedelta(days=7),
    "低": timedelta(days=30),
}

# スペースIDの正規表現パターン
_SPACE_ID_PATTERN = re.compile(r"^spaces/[A-Za-z0-9_-]+$")

_chat_service = None
_chat_service_timestamp = None
_SERVICE_CACHE_TTL = 1800  # 30分


_CHAT_SCOPES = ["https://www.googleapis.com/auth/chat.bot"]


def _load_sa_credentials_from_secret() -> service_account.Credentials | None:
    """Secret Manager からChat app用のSA鍵JSONを読み込んで認証情報を生成する。

    Agent Engine ランタイムではADCがGoogle管理SAになるため、
    Chat appとして構成されたSAの鍵を明示的にロードする必要がある。
    """
    import json as _json

    sa_json_str = get_config_value(
        ["CHAT_SA_CREDENTIALS_JSON"],
        secret_name="vuln-agent-chat-sa-key",
        default="",
    )
    if not sa_json_str:
        return None

    try:
        sa_info = _json.loads(sa_json_str)
        creds = service_account.Credentials.from_service_account_info(
            sa_info, scopes=_CHAT_SCOPES,
        )
        logger.info("Chat credentials loaded from Secret Manager (vuln-agent-chat-sa-key)")
        return creds
    except Exception as e:
        logger.warning(f"Secret Manager SA key parse failed: {e}")
        return None


def _get_chat_service():
    """Chat APIサービスを構築

    認証の優先順位:
      1. Secret Manager の SA鍵JSON (vuln-agent-chat-sa-key)
         → Agent Engine上でChat appのSAとして認証するために必要
      2. GOOGLE_APPLICATION_CREDENTIALS ファイル
         → ローカル開発環境向け
      3. Application Default Credentials (ADC)
         → フォールバック（Agent Engine管理SAになるため403の可能性あり）
    """
    global _chat_service, _chat_service_timestamp

    current_time = time.time()

    if _chat_service and _chat_service_timestamp:
        if current_time - _chat_service_timestamp < _SERVICE_CACHE_TTL:
            return _chat_service
        logger.info("Chat service cache expired, re-initializing")
        _chat_service = None

    credentials = None

    # 方式1: Secret Manager から Chat app 用の SA鍵を取得
    credentials = _load_sa_credentials_from_secret()

    # 方式2: ローカルファイルのサービスアカウント
    if not credentials:
        sa_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        if sa_path and os.path.exists(sa_path):
            try:
                credentials = service_account.Credentials.from_service_account_file(
                    sa_path, scopes=_CHAT_SCOPES,
                )
                logger.info("Chat credentials loaded from service account file")
            except Exception as e:
                logger.error(f"Service account file error: {e}")
                credentials = None

    # 方式3: ADC フォールバック（Agent Engineでは管理SAになるため注意）
    if not credentials:
        try:
            from google.auth import default
            credentials, _ = default(scopes=_CHAT_SCOPES)
            logger.warning(
                "Chat credentials loaded from ADC. "
                "Agent Engine上では管理SAが使われるため403になる可能性があります。"
                "vuln-agent-chat-sa-key シークレットの設定を推奨します。"
            )
        except Exception as e:
            logger.error(f"Default auth error: {e}")
            raise RuntimeError(
                "Chat認証に失敗しました。以下のいずれかを設定してください: "
                "(1) Secret Manager に vuln-agent-chat-sa-key (SA鍵JSON) "
                "(2) GOOGLE_APPLICATION_CREDENTIALS 環境変数"
            )

    _chat_service = build("chat", "v1", credentials=credentials)
    _chat_service_timestamp = current_time
    return _chat_service


def _format_http_error(error: HttpError, space_id: str | None = None) -> str:
    """HttpErrorを日本語のアクション可能なメッセージに変換する。"""
    status = error.resp.status if hasattr(error, "resp") else 0
    if status == 403:
        return (
            f"403 権限エラー: Chat appがスペース ({space_id}) へのアクセス権を持っていません。"
            " 以下を確認してください:"
            " (1) Google Cloud Console > Chat API > 構成 でアプリが設定済みか"
            " (2) 対象スペースにChat appがメンバーとして追加されているか"
            " (3) サービスアカウントがChat appに紐づいているか"
        )
    if status == 404:
        return f"404 エラー: スペース ({space_id}) が見つかりません。スペースIDを確認してください。"
    if status == 401:
        return "401 認証エラー: 認証情報が無効です。GOOGLE_APPLICATION_CREDENTIALS を確認してください。"
    return str(error)


def _resolve_space_id(space_id: str | None = None) -> str | None:
    """スペースIDを解決・正規化する。未設定時はNoneを返す。"""
    provided_space = str(space_id).strip() if space_id is not None else ""
    if not provided_space:
        space_id = get_config_value(
            ["DEFAULT_CHAT_SPACE_ID", "CHAT_SPACE_ID", "GOOGLE_CHAT_SPACE_ID"],
            secret_name="vuln-agent-chat-space-id",
            default="",
        )
    else:
        space_id = provided_space

    space_id = str(space_id).strip()
    if not space_id:
        logger.warning("Chat space ID が未設定です。DEFAULT_CHAT_SPACE_ID 環境変数を設定してください。")
        return None
    if not space_id.startswith("spaces/"):
        space_id = f"spaces/{space_id}"
    if not _SPACE_ID_PATTERN.match(space_id):
        logger.error(f"Chat space ID のフォーマットが不正です: {space_id}")
        return None
    return space_id


def send_vulnerability_alert(
    vulnerability_id: str,
    title: str,
    severity: str,
    affected_systems: list[str],
    cvss_score: float | None = None,
    description: str | None = None,
    remediation: str | None = None,
    owners: list[str] | None = None,
    space_id: str | None = None,
    record_history: bool = True,
) -> dict[str, Any]:
    """
    脆弱性アラートをGoogle Chatスペースに送信します。

    Args:
        vulnerability_id: CVE番号等
        title: 脆弱性のタイトル
        severity: 重大度（緊急/高/中/低）
        affected_systems: 影響を受けるシステム名のリスト
        cvss_score: CVSSスコア（オプション）
        description: 脆弱性の説明（オプション）
        remediation: 推奨される対策（オプション）
        owners: 担当者メールアドレス（オプション）
        space_id: 送信先スペースID（省略時はデフォルト）
        record_history: 履歴を記録するか（デフォルト: True）

    Returns:
        送信結果

    Example:
        >>> result = send_vulnerability_alert(
        ...     vulnerability_id="CVE-2024-1234",
        ...     title="Apache Log4j RCE",
        ...     severity="緊急",
        ...     affected_systems=["web-server-01"],
        ... )
        >>> print(result["status"])
        sent
    """
    try:
        service = _get_chat_service()

        resolved_space = _resolve_space_id(space_id)
        if resolved_space is None:
            return {"status": "error", "message": "Chat space ID が未設定または不正です。DEFAULT_CHAT_SPACE_ID を確認してください。"}

        # 対応期限
        deadline = _calculate_deadline(severity)

        # カードメッセージを構築
        card = _build_card(
            vulnerability_id, title, severity, cvss_score,
            affected_systems, description, remediation, deadline, owners
        )

        # テキスト本文（メンション付き）
        text = f"🚨 新しい脆弱性が検出されました: {vulnerability_id}"
        if owners:
            mentions = [f"<{email}>" for email in owners]
            text = f"📢 {', '.join(mentions)} 対応をお願いします。\n\n" + text

        # 送信
        message_body = {"text": text, "cardsV2": [card]}
        logger.info(f"Chat API 送信開始: space={resolved_space}, vuln={vulnerability_id}")

        response = service.spaces().messages().create(
            parent=resolved_space,
            body=message_body,
        ).execute()

        logger.info(f"Chat API 送信成功: space={resolved_space}, vuln={vulnerability_id}, message={response.get('name')}")

        result: dict[str, Any] = {
            "status": "sent",
            "message_id": response.get("name"),
            "space_id": resolved_space,
            "vulnerability_id": vulnerability_id,
        }

        if record_history:
            try:
                from .history_tools import log_vulnerability_history

                history_result = log_vulnerability_history(
                    vulnerability_id=vulnerability_id,
                    title=title,
                    severity=severity,
                    affected_systems=affected_systems,
                    cvss_score=cvss_score,
                    description=description,
                    remediation=remediation,
                    owners=owners,
                    status="notified",
                    source="chat_alert",
                    extra={
                        "message_id": response.get("name"),
                        "space_id": resolved_space,
                    },
                )
                result["history"] = history_result
            except Exception as history_error:
                logger.error(f"Failed to record history: {history_error}")
                result["history"] = {"status": "error", "message": str(history_error)}

        return result

    except HttpError as http_err:
        msg = _format_http_error(http_err, resolved_space if "resolved_space" in dir() else space_id)
        logger.error(f"Chat API HttpError: space={space_id}, vuln={vulnerability_id}, error={msg}")
        return {"status": "error", "message": msg, "vulnerability_id": vulnerability_id}
    except Exception as e:
        logger.error(f"Chat API 送信失敗: space={space_id}, vuln={vulnerability_id}, error={e}")
        return {"status": "error", "message": str(e), "vulnerability_id": vulnerability_id}


def send_simple_message(message: str, space_id: str | None = None) -> dict[str, Any]:
    """
    シンプルなテキストメッセージを送信します。

    Args:
        message: 送信するメッセージ
        space_id: 送信先スペースID（省略時はデフォルト）

    Returns:
        送信結果
    """
    try:
        service = _get_chat_service()

        resolved_space = _resolve_space_id(space_id)
        if resolved_space is None:
            return {"status": "error", "message": "Chat space ID が未設定または不正です。DEFAULT_CHAT_SPACE_ID を確認してください。"}

        response = service.spaces().messages().create(
            parent=resolved_space,
            body={"text": message},
        ).execute()

        logger.info(f"Chat メッセージ送信成功: space={resolved_space}")
        return {"status": "sent", "message_id": response.get("name")}

    except HttpError as http_err:
        msg = _format_http_error(http_err, resolved_space if "resolved_space" in dir() else space_id)
        logger.error(f"Chat API HttpError: space={space_id}, error={msg}")
        return {"status": "error", "message": msg}
    except Exception as e:
        logger.error(f"Chat メッセージ送信失敗: space={space_id}, error={e}")
        return {"status": "error", "message": str(e)}


def _build_card(
    vulnerability_id: str,
    title: str,
    severity: str,
    cvss_score: float | None,
    affected_systems: list[str],
    description: str | None,
    remediation: str | None,
    deadline: str,
    owners: list[str] | None,
) -> dict:
    """脆弱性カードを構築（Google Chat Cards v2 形式）"""

    severity_emoji = SEVERITY_EMOJI.get(severity, "⚪")

    # 概要セクション
    overview: list[dict[str, Any]] = [
        {"decoratedText": {"topLabel": "重大度", "text": f"{severity_emoji} {severity}"}},
    ]
    if cvss_score is not None:
        overview.append({"decoratedText": {"topLabel": "CVSSスコア", "text": str(cvss_score)}})
    overview.append({"decoratedText": {"topLabel": "対応期限", "text": deadline}})

    # 影響システム
    systems_text = "\n".join(f"• {s}" for s in affected_systems[:10])
    if len(affected_systems) > 10:
        systems_text += f"\n... 他 {len(affected_systems) - 10} システム"

    sections: list[dict[str, Any]] = [
        {"header": "概要", "widgets": overview},
        {"header": "影響を受けるシステム", "widgets": [{"textParagraph": {"text": systems_text or "該当なし"}}]},
    ]

    if description:
        sections.append({"header": "説明", "widgets": [{"textParagraph": {"text": description[:500]}}]})

    if remediation:
        sections.append({"header": "推奨対策", "widgets": [{"textParagraph": {"text": remediation[:500]}}]})

    if owners:
        sections.append({"header": "担当者", "widgets": [{"textParagraph": {"text": "\n".join(f"• {o}" for o in owners)}}]})

    # アクションボタン
    sections.append({
        "widgets": [{
            "buttonList": {
                "buttons": [{
                    "text": "NVDで詳細確認",
                    "onClick": {"openLink": {"url": f"https://nvd.nist.gov/vuln/detail/{vulnerability_id}"}},
                }],
            },
        }],
    })

    return {
        "cardId": f"vuln-{vulnerability_id}",
        "card": {
            "header": {
                "title": vulnerability_id,
                "subtitle": title[:100] if title else "",
            },
            "sections": sections,
        },
    }


def _calculate_deadline(severity: str) -> str:
    """対応期限を計算"""
    delta = SEVERITY_DEADLINES.get(severity, timedelta(days=7))
    return (datetime.now() + delta).strftime("%Y年%m月%d日")


def check_chat_connection(space_id: str | None = None) -> dict[str, Any]:
    """
    Google Chat APIへの接続を確認します。

    Args:
        space_id: 確認するスペースID（省略時はデフォルト）

    Returns:
        接続状態とスペース情報
    """
    try:
        service = _get_chat_service()

        resolved_space = _resolve_space_id(space_id)
        if resolved_space is None:
            return {"status": "error", "message": "Chat space ID が未設定または不正です。DEFAULT_CHAT_SPACE_ID を確認してください。"}

        # スペース情報を取得
        space = service.spaces().get(name=resolved_space).execute()

        return {
            "status": "connected",
            "space_id": resolved_space,
            "space_name": space.get("displayName", ""),
            "space_type": space.get("spaceType", ""),
            "member_count": space.get("membershipCount", 0),
        }

    except HttpError as http_err:
        msg = _format_http_error(http_err, resolved_space if "resolved_space" in dir() else space_id)
        logger.error(f"Chat connection check HttpError: space={space_id}, error={msg}")
        return {"status": "error", "message": msg}
    except Exception as e:
        logger.error(f"Chat connection check failed: space={space_id}, error={e}")
        return {
            "status": "error",
            "message": str(e),
        }


def list_space_members(space_id: str | None = None) -> dict[str, Any]:
    """
    スペースのメンバー一覧を取得します。

    Args:
        space_id: スペースID（省略時はデフォルト）

    Returns:
        メンバー一覧
    """
    try:
        service = _get_chat_service()

        resolved_space = _resolve_space_id(space_id)
        if resolved_space is None:
            return {"status": "error", "message": "Chat space ID が未設定または不正です。DEFAULT_CHAT_SPACE_ID を確認してください。"}

        # メンバー一覧を取得
        response = service.spaces().members().list(parent=resolved_space).execute()
        members = response.get("memberships", [])

        member_list = []
        for m in members:
            member_info = m.get("member", {})
            if member_info.get("type") == "HUMAN":
                member_list.append({
                    "name": member_info.get("displayName", ""),
                    "email": member_info.get("email", ""),
                })

        return {
            "status": "success",
            "space_id": resolved_space,
            "members": member_list,
            "count": len(member_list),
        }

    except HttpError as http_err:
        msg = _format_http_error(http_err, resolved_space if "resolved_space" in dir() else space_id)
        logger.error(f"List members HttpError: space={space_id}, error={msg}")
        return {"status": "error", "message": msg}
    except Exception as e:
        logger.error(f"Failed to list members: space={space_id}, error={e}")
        return {"status": "error", "message": str(e)}
