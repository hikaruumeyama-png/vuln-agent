"""
Config Tools

設定参照をツール化する。
"""

from __future__ import annotations

import os
from typing import Any

try:
    from .secret_config import get_config_value
except Exception:
    try:
        from agent.tools.secret_config import get_config_value
    except Exception:
        try:
            from secret_config import get_config_value
        except Exception:
            def get_config_value(
                env_names: list[str],
                secret_name: str | None = None,
                default: str = "",
            ) -> str:
                _ = secret_name
                for env_name in env_names:
                    value = (os.environ.get(env_name) or "").strip()
                    if value:
                        return value
                return default


_CONFIG_CANDIDATES: dict[str, dict[str, Any]] = {
    "project_id": {
        "env_names": ["GCP_PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT"],
        "secret_name": None,
        "default": "",
    },
    "location": {
        "env_names": ["GCP_LOCATION"],
        "secret_name": None,
        "default": "asia-northeast1",
    },
    "agent_resource_name": {
        "env_names": ["AGENT_RESOURCE_NAME"],
        "secret_name": "vuln-agent-resource-name",
        "default": "",
    },
    "agent_model": {
        "env_names": ["AGENT_MODEL", "GEMINI_MODEL", "VERTEX_MODEL"],
        "secret_name": "vuln-agent-model-name",
        "default": "gemini-2.5-pro",
    },
    "sbom_backend": {
        "env_names": ["SBOM_DATA_BACKEND"],
        "secret_name": "vuln-agent-sbom-data-backend",
        "default": "sheets",
    },
    "bq_sbom_table_id": {
        "env_names": ["BQ_SBOM_TABLE_ID"],
        "secret_name": "vuln-agent-bq-sbom-table-id",
        "default": "",
    },
    "bq_owner_mapping_table_id": {
        "env_names": ["BQ_OWNER_MAPPING_TABLE_ID"],
        "secret_name": "vuln-agent-bq-owner-table-id",
        "default": "",
    },
    "bq_history_table_id": {
        "env_names": ["BQ_HISTORY_TABLE_ID"],
        "secret_name": "vuln-agent-bq-table-id",
        "default": "",
    },
    "chat_space_id": {
        "env_names": ["DEFAULT_CHAT_SPACE_ID", "CHAT_SPACE_ID", "GOOGLE_CHAT_SPACE_ID"],
        "secret_name": "vuln-agent-chat-space-id",
        "default": "",
    },
}


def list_known_config_keys() -> dict[str, Any]:
    """参照可能な設定キー一覧を返す。"""
    return {
        "status": "success",
        "count": len(_CONFIG_CANDIDATES),
        "keys": sorted(_CONFIG_CANDIDATES.keys()),
    }


def get_runtime_config_snapshot(
    keys: list[str] | None = None,
    mask_values: bool = True,
) -> dict[str, Any]:
    """
    現在の設定値スナップショットを返す。
    機密性を考慮し、既定では値をマスクする。
    """
    targets = [k for k in (keys or _CONFIG_CANDIDATES.keys()) if k in _CONFIG_CANDIDATES]
    if not targets:
        return {"status": "error", "message": "有効な keys がありません。"}

    items: dict[str, dict[str, Any]] = {}
    for key in targets:
        spec = _CONFIG_CANDIDATES[key]
        env_names = list(spec["env_names"])
        secret_name = spec["secret_name"]
        default = spec["default"]

        value = get_config_value(env_names, secret_name=secret_name, default=default)
        source = _detect_source(env_names, secret_name, value, default)
        items[key] = {
            "value": _mask(value) if mask_values else value,
            "source": source,
            "default_applied": source == "default",
        }

    return {
        "status": "success",
        "count": len(items),
        "mask_values": bool(mask_values),
        "configs": items,
    }


def _detect_source(env_names: list[str], secret_name: str | None, value: str, default: str) -> str:
    for env_name in env_names:
        env_value = (os.environ.get(env_name) or "").strip()
        if env_value and env_value == (value or "").strip():
            return f"env:{env_name}"
    if secret_name and value and (value or "").strip() != (default or "").strip():
        return f"secret:{secret_name}"
    return "default"


def _mask(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    if len(text) <= 4:
        return "*" * len(text)
    return f"{text[:2]}{'*' * (len(text) - 4)}{text[-2:]}"
