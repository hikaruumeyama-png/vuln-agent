"""
Gmail Tools - SIDfmメールの取得と解析

Vertex AI Agent Engine版

認証方式:
  - 個人Gmail: OAuth 2.0（GMAIL_OAUTH_TOKEN 環境変数）
  - Google Workspace: ドメイン委任（GMAIL_USER_EMAIL + サービスアカウント）
"""

import os
import re
import base64
import json
import logging
from typing import Any

from googleapiclient.discovery import build

logger = logging.getLogger(__name__)

# Gmail APIサービスのキャッシュ
_gmail_service = None


def _get_gmail_service():
    """
    Gmail APIサービスを構築

    認証方式を自動判定:
      1. GMAIL_OAUTH_TOKEN あり → 個人Gmail（OAuth）
      2. GMAIL_USER_EMAIL あり → Workspace（ドメイン委任）
      3. どちらもなし → デフォルト認証
    """
    global _gmail_service
    if _gmail_service:
        return _gmail_service

    oauth_token = os.environ.get("GMAIL_OAUTH_TOKEN")
    gmail_user = os.environ.get("GMAIL_USER_EMAIL")

    credentials = None
    auth_method = "unknown"

    # 方式1: OAuth トークン（個人Gmail用）
    if oauth_token:
        try:
            from google.oauth2.credentials import Credentials
            from google.auth.transport.requests import Request

            # Base64デコード
            token_json = base64.b64decode(oauth_token).decode("utf-8")
            token_data = json.loads(token_json)

            credentials = Credentials(
                token=token_data.get("token"),
                refresh_token=token_data.get("refresh_token"),
                token_uri=token_data.get("token_uri", "https://oauth2.googleapis.com/token"),
                client_id=token_data.get("client_id"),
                client_secret=token_data.get("client_secret"),
                scopes=token_data.get("scopes", ["https://www.googleapis.com/auth/gmail.modify"]),
            )

            # トークンが期限切れなら更新
            if credentials.expired and credentials.refresh_token:
                credentials.refresh(Request())
                logger.info("OAuth token refreshed")

            auth_method = "oauth"
            logger.info("Using OAuth authentication (個人Gmail)")

        except Exception as e:
            logger.error(f"OAuth token error: {e}")
            credentials = None

    # 方式2: サービスアカウント + ドメイン委任（Google Workspace用）
    if not credentials and gmail_user:
        try:
            from google.oauth2 import service_account

            sa_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")

            if sa_path and os.path.exists(sa_path):
                credentials = service_account.Credentials.from_service_account_file(
                    sa_path,
                    scopes=["https://www.googleapis.com/auth/gmail.modify"],
                    subject=gmail_user
                )
                auth_method = "domain_delegation"
                logger.info(f"Using domain delegation for {gmail_user} (Google Workspace)")
            else:
                logger.warning("Service account file not found, trying default credentials")

        except Exception as e:
            logger.error(f"Domain delegation error: {e}")
            credentials = None

    # 方式3: デフォルト認証（フォールバック）
    if not credentials:
        try:
            from google.auth import default
            credentials, _ = default(scopes=["https://www.googleapis.com/auth/gmail.modify"])
            auth_method = "default"
            logger.info("Using default authentication")
        except Exception as e:
            logger.error(f"Default auth error: {e}")
            raise RuntimeError("Gmail認証に失敗しました。GMAIL_OAUTH_TOKEN または GMAIL_USER_EMAIL を設定してください。")

    _gmail_service = build("gmail", "v1", credentials=credentials)
    logger.info(f"Gmail service initialized (auth_method={auth_method})")

    return _gmail_service


def get_sidfm_emails(max_results: int = 10) -> dict[str, Any]:
    """
    SIDfmからの未読脆弱性通知メールを取得します。

    Args:
        max_results: 取得する最大件数（デフォルト: 10）

    Returns:
        取得したメールと脆弱性情報のリスト

    Example:
        >>> result = get_sidfm_emails(5)
        >>> print(result["count"])
        3
        >>> for email in result["emails"]:
        ...     print(email["subject"])
    """
    sidfm_sender = os.environ.get("SIDFM_SENDER_EMAIL", "noreply@sidfm.com")

    try:
        service = _get_gmail_service()

        # SIDfmからの未読メールを検索
        query = f"from:{sidfm_sender} is:unread"

        results = service.users().messages().list(
            userId="me",
            q=query,
            maxResults=max_results
        ).execute()

        messages = results.get("messages", [])

        if not messages:
            return {
                "emails": [],
                "count": 0,
                "message": "新しい脆弱性通知はありません"
            }

        emails = []
        for msg in messages:
            email_data = _get_email_detail(service, msg["id"])
            if email_data:
                emails.append(email_data)

        return {"emails": emails, "count": len(emails)}

    except Exception as e:
        logger.error(f"Gmail API error: {e}")
        return {"error": str(e), "emails": [], "count": 0}


def get_unread_emails(query: str = "is:unread", max_results: int = 10) -> dict[str, Any]:
    """
    任意のクエリで未読メールを取得します。

    Args:
        query: Gmail検索クエリ（デフォルト: "is:unread"）
        max_results: 取得する最大件数（デフォルト: 10）

    Returns:
        取得したメールのリスト

    Example:
        >>> # 特定の件名を含むメール
        >>> result = get_unread_emails("subject:脆弱性 is:unread", 5)
        >>> # 特定の送信者からのメール
        >>> result = get_unread_emails("from:security@example.com is:unread", 10)
    """
    try:
        service = _get_gmail_service()

        results = service.users().messages().list(
            userId="me",
            q=query,
            maxResults=max_results
        ).execute()

        messages = results.get("messages", [])

        if not messages:
            return {
                "emails": [],
                "count": 0,
                "message": f"クエリ '{query}' に一致するメールはありません"
            }

        emails = []
        for msg in messages:
            email_data = _get_email_detail(service, msg["id"])
            if email_data:
                emails.append(email_data)

        return {"emails": emails, "count": len(emails)}

    except Exception as e:
        logger.error(f"Gmail API error: {e}")
        return {"error": str(e), "emails": [], "count": 0}


def mark_email_as_read(email_id: str) -> dict[str, Any]:
    """
    指定したメールを既読にします。

    Args:
        email_id: メールID

    Returns:
        処理結果
    """
    try:
        service = _get_gmail_service()

        service.users().messages().modify(
            userId="me",
            id=email_id,
            body={"removeLabelIds": ["UNREAD"]}
        ).execute()

        return {"status": "success", "email_id": email_id}

    except Exception as e:
        logger.error(f"Failed to mark email as read: {e}")
        return {"status": "error", "message": str(e)}


def check_gmail_connection() -> dict[str, Any]:
    """
    Gmail APIへの接続を確認します。

    Returns:
        接続状態と認証済みメールアドレス
    """
    try:
        service = _get_gmail_service()
        profile = service.users().getProfile(userId="me").execute()

        return {
            "status": "connected",
            "email": profile.get("emailAddress"),
            "messages_total": profile.get("messagesTotal"),
            "threads_total": profile.get("threadsTotal"),
        }
    except Exception as e:
        logger.error(f"Gmail connection check failed: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


def _get_email_detail(service, message_id: str) -> dict[str, Any] | None:
    """メールの詳細を取得して解析"""
    try:
        message = service.users().messages().get(
            userId="me",
            id=message_id,
            format="full"
        ).execute()

        headers = {h["name"]: h["value"] for h in message["payload"]["headers"]}
        body = _extract_body(message["payload"])
        vulnerabilities = _parse_sidfm_content(body)

        return {
            "id": message_id,
            "subject": headers.get("Subject", ""),
            "from": headers.get("From", ""),
            "date": headers.get("Date", ""),
            "snippet": message.get("snippet", ""),
            "vulnerabilities": vulnerabilities,
            "body_preview": body[:500] if body else "",
        }

    except Exception as e:
        logger.error(f"Error getting email {message_id}: {e}")
        return None


def _extract_body(payload: dict) -> str:
    """メール本文を抽出"""
    body = ""

    if "body" in payload and payload["body"].get("data"):
        body = base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8")
    elif "parts" in payload:
        for part in payload["parts"]:
            if part["mimeType"] == "text/plain" and "data" in part.get("body", {}):
                body = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
                break
            elif part["mimeType"] == "text/html" and not body and "data" in part.get("body", {}):
                body = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")

    return body


def _parse_sidfm_content(body: str) -> list[dict[str, Any]]:
    """SIDfmメールの内容を解析して脆弱性情報を抽出"""
    vulnerabilities = []

    # CVE番号を抽出
    cve_ids = list(set(re.findall(r"CVE-\d{4}-\d{4,7}", body)))

    # CVSSスコアを抽出
    cvss_matches = re.findall(r"CVSS[:\s]*v?\d*\.?\d*[:\s]*(\d+\.?\d*)", body, re.IGNORECASE)

    # PURL形式の抽出
    purl_matches = re.findall(r"pkg:(\w+)/([^@\s]+)@?([\d\.\-\w]*)", body)
    purls = [f"pkg:{m[0]}/{m[1]}{'@' + m[2] if m[2] else ''}" for m in purl_matches]

    # 影響製品を抽出
    product_patterns = [
        r"(Apache\s+[\w\-\.]+\s*[\d\.]*)",
        r"(nginx[\s/][\d\.]+)",
        r"(OpenSSL\s+[\d\.]+)",
        r"(Log4j[\s\-]*[\d\.]*)",
        r"(Spring\s+[\w\-\.]+\s*[\d\.]*)",
        r"(Tomcat\s*[\d\.]*)",
        r"(PostgreSQL\s*[\d\.]*)",
        r"(MySQL\s*[\d\.]*)",
        r"(Redis\s*[\d\.]*)",
        r"(Node\.js\s*[\d\.]*)",
    ]

    affected_products = []
    for pattern in product_patterns:
        affected_products.extend(re.findall(pattern, body, re.IGNORECASE))

    # 脆弱性情報を構造化
    for i, cve_id in enumerate(cve_ids):
        vuln = {
            "cve_id": cve_id,
            "title": _extract_title(body, cve_id),
            "cvss_score": float(cvss_matches[i]) if i < len(cvss_matches) else None,
            "affected_products": list(set(affected_products)),
            "purls": purls,
            "description": _extract_section(body, ["概要", "Description", "詳細"]),
            "remediation": _extract_section(body, ["対策", "Remediation", "修正"]) or "最新バージョンへのアップデートを推奨",
        }
        vulnerabilities.append(vuln)

    return vulnerabilities


def _extract_title(body: str, cve_id: str) -> str:
    """CVEに対応するタイトルを抽出"""
    patterns = [
        rf"{cve_id}[:\s]+([^\n]+)",
        rf"【([^】]*{cve_id}[^】]*)】",
    ]
    for pattern in patterns:
        match = re.search(pattern, body)
        if match:
            return match.group(1).strip()[:200]
    return f"Vulnerability {cve_id}"


def _extract_section(body: str, keywords: list[str]) -> str:
    """キーワードに対応するセクションを抽出"""
    for keyword in keywords:
        pattern = rf"{keyword}[:\s]*\n?([^\n]+(?:\n(?!対策|影響|CVE|概要).*)*)"
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            return match.group(1).strip()[:500]
    return ""
