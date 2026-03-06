"""スクレイピングサービス クライアント。

vuln_scraper Cloud Run サービスへ HTTP 経由で
スクレイピングリクエストを送信する。
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any
from urllib import request

from .base import fetch_with_retry

logger = logging.getLogger(__name__)

# Cloud Run サービス URL (環境変数で設定)
_SCRAPER_URL = os.environ.get(
    "VULN_SCRAPER_URL", "http://localhost:8080"
)


def scrape_url(
    url: str,
    source_id: str,
    extraction_prompt: str = "",
) -> list[dict[str, Any]]:
    """スクレイピングサービスに URL を送信し、抽出結果を取得する。

    Args:
        url: スクレイピング対象 URL
        source_id: ソース識別子
        extraction_prompt: カスタム抽出プロンプト

    Returns:
        脆弱性情報の dict リスト
    """
    scraper_url = os.environ.get("VULN_SCRAPER_URL", _SCRAPER_URL)
    endpoint = f"{scraper_url.rstrip('/')}/scrape"

    body = {
        "url": url,
        "source_id": source_id,
        "extraction_prompt": extraction_prompt,
    }

    headers = {
        "Content-Type": "application/json",
    }

    # Cloud Run 認証トークン (サービス間通信)
    id_token = _get_id_token(scraper_url)
    if id_token:
        headers["Authorization"] = f"Bearer {id_token}"

    req = request.Request(
        endpoint,
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    try:
        resp_data = fetch_with_retry(req, timeout=60, max_retries=2)
        result = json.loads(resp_data.decode("utf-8", errors="replace"))
        return result.get("vulnerabilities") or []
    except Exception as exc:
        logger.error("Scraper request failed for %s/%s: %s", source_id, url, exc)
        return []


def _get_id_token(audience: str) -> str:
    """Cloud Run サービス間通信用の ID トークンを取得する。"""
    try:
        import google.auth.transport.requests
        import google.oauth2.id_token

        auth_req = google.auth.transport.requests.Request()
        token = google.oauth2.id_token.fetch_id_token(auth_req, audience)
        return token
    except Exception:
        # ローカル開発時はトークン不要
        return ""
