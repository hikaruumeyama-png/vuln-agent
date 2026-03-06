"""ソースアダプター基底クラスと共通ユーティリティ。"""

from __future__ import annotations

import json
import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any
from urllib import request
from urllib.error import HTTPError, URLError

import sys
import os

# shared/ を import パスに追加
_SHARED_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "shared")
if _SHARED_DIR not in sys.path:
    sys.path.insert(0, os.path.normpath(_SHARED_DIR))

from shared.vuln_schema import VulnEntry

logger = logging.getLogger(__name__)

_USER_AGENT = "vuln-agent/2.0 (+https://github.com/hikaruumeyama-png/vuln-agent)"


class BaseSourceAdapter(ABC):
    """脆弱性ソースアダプターの基底クラス。"""

    source_id: str = ""
    default_poll_interval_minutes: int = 30

    @abstractmethod
    def fetch_recent(self, since: datetime) -> list[VulnEntry]:
        """指定時刻以降の新規・更新エントリを取得する。

        Args:
            since: この時刻以降のエントリを取得

        Returns:
            正規化された VulnEntry のリスト
        """
        ...


def fetch_with_retry(
    url_or_req: str | request.Request,
    timeout: int = 20,
    max_retries: int = 3,
) -> bytes:
    """指数バックオフ付き HTTP リトライ。"""
    last_exc: Exception | None = None
    for attempt in range(max_retries):
        try:
            if isinstance(url_or_req, str):
                req = request.Request(
                    url_or_req,
                    headers={"User-Agent": _USER_AGENT},
                )
            else:
                req = url_or_req
            with request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except HTTPError as exc:
            # 429 (Rate Limit) や 5xx は リトライ対象
            if exc.code in (429, 500, 502, 503, 504) and attempt < max_retries - 1:
                wait = 2 ** (attempt + 1)
                logger.warning(
                    "HTTP %d from %s (attempt %d/%d), retrying in %ds",
                    exc.code,
                    getattr(url_or_req, "full_url", url_or_req),
                    attempt + 1,
                    max_retries,
                    wait,
                )
                time.sleep(wait)
                last_exc = exc
                continue
            raise
        except URLError as exc:
            last_exc = exc
            if attempt < max_retries - 1:
                wait = 2 ** (attempt + 1)
                logger.warning(
                    "URLError from %s (attempt %d/%d), retrying in %ds: %s",
                    getattr(url_or_req, "full_url", url_or_req),
                    attempt + 1,
                    max_retries,
                    wait,
                    exc,
                )
                time.sleep(wait)
                continue
            raise
        except Exception as exc:
            last_exc = exc
            if attempt < max_retries - 1:
                wait = 2 ** (attempt + 1)
                logger.warning(
                    "Fetch error (attempt %d/%d), retrying in %ds: %s",
                    attempt + 1,
                    max_retries,
                    wait,
                    exc,
                )
                time.sleep(wait)
                continue
            raise
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("fetch failed without exception")


def http_get_json(url: str, headers: dict[str, str] | None = None) -> Any:
    """HTTP GET して JSON をパースして返す。"""
    req_headers = {"User-Agent": _USER_AGENT}
    if headers:
        req_headers.update(headers)
    req = request.Request(url, headers=req_headers)
    data = fetch_with_retry(req, timeout=30)
    return json.loads(data.decode("utf-8", errors="replace"))


def http_post_json(
    url: str,
    body: dict[str, Any],
    headers: dict[str, str] | None = None,
) -> Any:
    """HTTP POST (JSON) してレスポンスをパースして返す。"""
    req_headers = {
        "User-Agent": _USER_AGENT,
        "Content-Type": "application/json",
    }
    if headers:
        req_headers.update(headers)
    req = request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers=req_headers,
        method="POST",
    )
    data = fetch_with_retry(req, timeout=30)
    return json.loads(data.decode("utf-8", errors="replace"))


def get_secret_value(env_names: list[str], secret_name: str = "", default: str = "") -> str:
    """環境変数または Secret Manager からシークレット値を取得する。"""
    # 環境変数を優先
    for name in env_names:
        value = os.environ.get(name, "").strip()
        if value:
            return value

    # Secret Manager フォールバック
    if secret_name:
        try:
            from google.cloud import secretmanager

            project_id = (
                os.environ.get("GCP_PROJECT_ID")
                or os.environ.get("GOOGLE_CLOUD_PROJECT")
                or ""
            )
            if project_id:
                client = secretmanager.SecretManagerServiceClient()
                resource = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
                response = client.access_secret_version(request={"name": resource})
                return response.payload.data.decode("utf-8").strip()
        except Exception as exc:
            logger.debug("Secret Manager lookup failed for %s: %s", secret_name, exc)

    return default
