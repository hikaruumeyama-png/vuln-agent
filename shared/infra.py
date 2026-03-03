"""インフラユーティリティ: プロジェクトID取得・Secret Manager設定読み込み。"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

_secret_client: Any = None


def _get_secret_client() -> Any:
    global _secret_client
    if _secret_client is None:
        from google.cloud import secretmanager
        _secret_client = secretmanager.SecretManagerServiceClient()
    return _secret_client


def get_project_id() -> str:
    return (
        os.environ.get("GCP_PROJECT_ID")
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
        or os.environ.get("GCLOUD_PROJECT")
        or ""
    )


def get_config(env_name: str, secret_name: str, default: str = "") -> str:
    """環境変数 → Secret Manager の順にフォールバックして設定値を取得する。"""
    value = (os.environ.get(env_name) or "").strip()
    if value:
        return value

    project_id = get_project_id()
    if not project_id:
        return default

    try:
        client = _get_secret_client()
        name = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
        response = client.access_secret_version(request={"name": name})
        secret_value = response.payload.data.decode("utf-8").strip()
        return secret_value or default
    except Exception:
        return default
