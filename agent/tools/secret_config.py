import logging
import os
from typing import Iterable

import google.auth
from google.cloud import secretmanager

logger = logging.getLogger(__name__)

_secret_cache: dict[tuple[str, str], str] = {}
_project_id_cache: str | None = None


def _resolve_project_id() -> str | None:
    global _project_id_cache
    if _project_id_cache:
        return _project_id_cache

    env_project = (os.environ.get("GCP_PROJECT_ID") or "").strip()
    if env_project:
        _project_id_cache = env_project
        return _project_id_cache

    try:
        _, detected_project = google.auth.default()
        _project_id_cache = (detected_project or "").strip() or None
    except Exception as exc:
        logger.warning("Could not detect GCP project for Secret Manager fallback: %s", exc)
        _project_id_cache = None
    return _project_id_cache


def _get_secret_value(secret_name: str) -> str:
    project_id = _resolve_project_id()
    if not project_id:
        return ""

    key = (project_id, secret_name)
    if key in _secret_cache:
        return _secret_cache[key]

    try:
        client = secretmanager.SecretManagerServiceClient()
        name = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
        response = client.access_secret_version(request={"name": name})
        value = response.payload.data.decode("utf-8").strip()
        _secret_cache[key] = value
        return value
    except Exception as exc:
        logger.warning("Secret Manager fallback failed for %s: %s", secret_name, exc)
        _secret_cache[key] = ""
        return ""


def get_config_value(
    env_names: Iterable[str],
    secret_name: str | None = None,
    default: str = "",
) -> str:
    for env_name in env_names:
        value = (os.environ.get(env_name) or "").strip()
        if value:
            return value

    if secret_name:
        secret_value = _get_secret_value(secret_name)
        if secret_value:
            return secret_value

    return default
