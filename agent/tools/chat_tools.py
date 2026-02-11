"""
Google Chat Tools - 脆弱性アラート送信

Vertex AI Agent Engine版
"""

import os
import time
import logging
from typing import Any
from datetime import datetime, timedelta

from google.oauth2 import service_account
from googleapiclient.discovery import build

logger = logging.getLogger(__name__)

# 重大度設定
SEVERITY_COLORS = {
    "緊急": "#D32F2F",
    "高": "#F57C00",
    "中": "#FBC02D",
    "低": "#388E3C",
}

SEVERITY_DEADLINES = {
    "緊急": timedelta(days=1),
    "高": timedelta(days=3),
    "中": timedelta(days=7),
    "低": timedelta(days=30),
}


_chat_service = None
_chat_service_timestamp = None
_SERVICE_CACHE_TTL = 1800  # 30分


def _get_chat_service():
    """Chat APIサービスを構築"""
    global _chat_service, _chat_service_timestamp

    current_time = time.time()

    if _chat_service and _chat_service_timestamp:
        if current_time - _chat_service_timestamp < _SERVICE_CACHE_TTL:
            return _chat_service
        logger.info("Chat service cache expired, re-initializing")
        _chat_service = None

    sa_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    credentials = None

    if sa_path and os.path.exists(sa_path):
        try:
            credentials = service_account.Credentials.from_service_account_file(
                sa_path,
                scopes=["https://www.googleapis.com/auth/chat.bot"]
            )
        except Exception as e:
            logger.error(f"Service account file error: {e}")
            credentials = None

    if not credentials:
        try:
            from google.auth import default
            credentials, _ = default(scopes=["https://www.googleapis.com/auth/chat.bot"])
        except Exception as e:
            logger.error(f"Default auth error: {e}")
            raise RuntimeError("Chat認証に失敗しました。GOOGLE_APPLICATION_CREDENTIALS を確認してください。")

    _chat_service = build("chat", "v1", credentials=credentials)
    _chat_service_timestamp = current_time
    return _chat_service


def _resolve_space_id(space_id: str | None = None) -> str | None:
    """スペースIDを解決する。未設定時はNoneを返す。"""
    if not space_id:
        space_id = os.environ.get("DEFAULT_CHAT_SPACE_ID", "")
    if not space_id:
        return None
    if not space_id.startswith("spaces/"):
        space_id = f"spaces/{space_id}"
    return space_id


def send_vulnerability_alert(
    vulnerability_id: str,
    title: str,
    severity: str,
    affected_systems: list[str],
    cvss_score: float | None = None,
    description: str = None,
    remediation: str = None,
    owners: list[str] | None = None,
    space_id: str = None,
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
    """
    try:
        service = _get_chat_service()

        space_id = _resolve_space_id(space_id)
        if space_id is None:
            return {"status": "error", "message": "Chat space ID not configured"}

        # 対応期限
        deadline = _calculate_deadline(severity)
        
        # カードメッセージを構築
        card = _build_card(
            vulnerability_id, title, severity, cvss_score,
            affected_systems, description, remediation, deadline, owners
        )
        
        # メンション
        text = f"🚨 新しい脆弱性が検出されました: {vulnerability_id}"
        if owners:
            mentions = [f"<users/{email}>" for email in owners]
            text = f"📢 {', '.join(mentions)} 対応をお願いします。\n\n" + text
        
        # 送信
        response = service.spaces().messages().create(
            parent=space_id,
            body={"text": text, "cardsV2": [card]}
        ).execute()
        
        logger.info(f"Sent alert to {space_id}: {vulnerability_id}")
        
        result = {
            "status": "sent",
            "message_id": response.get("name"),
            "space_id": space_id,
            "vulnerability_id": vulnerability_id
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
                        "space_id": space_id,
                    },
                )
                result["history"] = history_result
            except Exception as history_error:
                logger.error(f"Failed to record history: {history_error}")
                result["history"] = {"status": "error", "message": str(history_error)}
        
        return result

    except Exception as e:
        logger.error(f"Failed to send chat message: {e}")
        return {"status": "error", "message": str(e), "vulnerability_id": vulnerability_id}


def send_simple_message(message: str, space_id: str = None) -> dict[str, Any]:
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

        space_id = _resolve_space_id(space_id)
        if space_id is None:
            return {"status": "error", "message": "Chat space ID not configured"}

        response = service.spaces().messages().create(
            parent=space_id,
            body={"text": message}
        ).execute()
        
        return {"status": "sent", "message_id": response.get("name")}
        
    except Exception as e:
        logger.error(f"Failed to send message: {e}")
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
    owners: list[str] | None
) -> dict:
    """脆弱性カードを構築"""
    
    color = SEVERITY_COLORS.get(severity, "#757575")
    
    # 概要セクション
    overview = [
        {"decoratedText": {"topLabel": "重大度", "text": f"<font color='{color}'><b>{severity}</b></font>"}}
    ]
    if cvss_score is not None:
        overview.append({"decoratedText": {"topLabel": "CVSSスコア", "text": f"<b>{cvss_score}</b>"}})
    overview.append({"decoratedText": {"topLabel": "対応期限", "text": f"<b>{deadline}</b>"}})
    
    # 影響システム
    systems_text = "\n".join([f"• {s}" for s in affected_systems[:10]])
    if len(affected_systems) > 10:
        systems_text += f"\n... 他 {len(affected_systems) - 10} システム"
    
    sections = [
        {"header": "概要", "widgets": overview},
        {"header": "📋 影響を受けるシステム", "widgets": [{"textParagraph": {"text": systems_text or "該当なし"}}]}
    ]
    
    if description:
        sections.append({"header": "📝 説明", "widgets": [{"textParagraph": {"text": description[:500]}}]})
    
    if remediation:
        sections.append({"header": "✅ 推奨対策", "widgets": [{"textParagraph": {"text": remediation[:500]}}]})
    
    if owners:
        sections.append({"header": "👤 担当者", "widgets": [{"textParagraph": {"text": "\n".join(f"• {o}" for o in owners)}}]})
    
    # アクションボタン
    sections.append({
        "widgets": [{
            "buttonList": {
                "buttons": [{
                    "text": "🔍 NVDで詳細確認",
                    "onClick": {"openLink": {"url": f"https://nvd.nist.gov/vuln/detail/{vulnerability_id}"}}
                }]
            }
        }]
    })
    
    return {
        "cardId": f"vuln-{vulnerability_id}",
        "card": {
            "header": {"title": f"🛡️ {vulnerability_id}", "subtitle": title[:100] if title else ""},
            "sections": sections
        }
    }


def _calculate_deadline(severity: str) -> str:
    """対応期限を計算"""
    delta = SEVERITY_DEADLINES.get(severity, timedelta(days=7))
    return (datetime.now() + delta).strftime("%Y年%m月%d日")


def check_chat_connection(space_id: str = None) -> dict[str, Any]:
    """
    Google Chat APIへの接続を確認します。

    Args:
        space_id: 確認するスペースID（省略時はデフォルト）

    Returns:
        接続状態とスペース情報
    """
    try:
        service = _get_chat_service()

        space_id = _resolve_space_id(space_id)
        if space_id is None:
            return {"status": "error", "message": "Chat space ID not configured"}

        # スペース情報を取得
        space = service.spaces().get(name=space_id).execute()

        return {
            "status": "connected",
            "space_id": space_id,
            "space_name": space.get("displayName", ""),
            "space_type": space.get("spaceType", ""),
            "member_count": space.get("membershipCount", 0),
        }

    except Exception as e:
        logger.error(f"Chat connection check failed: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


def list_space_members(space_id: str = None) -> dict[str, Any]:
    """
    スペースのメンバー一覧を取得します。

    Args:
        space_id: スペースID（省略時はデフォルト）

    Returns:
        メンバー一覧
    """
    try:
        service = _get_chat_service()

        space_id = _resolve_space_id(space_id)
        if space_id is None:
            return {"status": "error", "message": "Chat space ID not configured"}

        # メンバー一覧を取得
        response = service.spaces().members().list(parent=space_id).execute()
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
            "space_id": space_id,
            "members": member_list,
            "count": len(member_list),
        }

    except Exception as e:
        logger.error(f"Failed to list members: {e}")
        return {"status": "error", "message": str(e)}
