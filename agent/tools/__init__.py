"""
Tools package for Vulnerability Management Agent.

This module keeps import-time robustness high so test discovery can run even
when optional external dependencies (googleapiclient/vertexai/etc.) are absent.
Missing dependencies are surfaced when the corresponding tool function is called.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

_EXPORT_SPECS: list[tuple[str, list[str]]] = [
    (
        "gmail_tools",
        [
            "get_sidfm_emails",
            "get_unread_emails",
            "mark_email_as_read",
            "check_gmail_connection",
        ],
    ),
    (
        "sheets_tools",
        [
            "search_sbom_by_purl",
            "search_sbom_by_product",
            "get_affected_systems",
            "get_owner_mapping",
            "get_sbom_contents",
            "list_sbom_package_types",
            "count_sbom_packages_by_type",
            "list_sbom_packages_by_type",
            "list_sbom_package_versions",
            "get_sbom_entry_by_purl",
        ],
    ),
    (
        "chat_tools",
        [
            "send_vulnerability_alert",
            "send_simple_message",
            "check_chat_connection",
            "list_space_members",
        ],
    ),
    ("history_tools", ["log_vulnerability_history"]),
    (
        "a2a_tools",
        [
            "register_remote_agent",
            "call_remote_agent",
            "list_registered_agents",
            "create_jira_ticket_request",
            "create_approval_request",
        ],
    ),
    (
        "capability_tools",
        [
            "get_runtime_capabilities",
            "inspect_bigquery_capabilities",
            "list_bigquery_tables",
            "run_bigquery_readonly_query",
        ],
    ),
    ("web_tools", ["web_search", "fetch_web_content"]),
    ("vuln_intel_tools", ["get_nvd_cve_details", "search_osv_vulnerabilities"]),
    (
        "granular_tools",
        [
            "list_sidfm_email_subjects",
            "list_unread_email_ids",
            "get_email_preview_by_id",
            "get_chat_space_info",
            "list_chat_member_emails",
            "build_history_record_preview",
            "list_registered_agent_ids",
            "get_registered_agent_details",
            "get_configured_bigquery_tables",
            "check_bigquery_readability_summary",
            "list_web_search_urls",
            "get_web_content_excerpt",
            "get_nvd_cvss_summary",
            "list_osv_vulnerability_ids",
            "save_vulnerability_history_minimal",
        ],
    ),
]


def _missing_tool_factory(tool_name: str, module_name: str, import_error: Exception):
    def _missing_tool(*args: Any, **kwargs: Any) -> dict[str, Any]:
        _ = (args, kwargs)
        return {
            "status": "error",
            "message": (
                f"Tool '{tool_name}' is unavailable because module '{module_name}' could not be imported: "
                f"{import_error}"
            ),
        }

    _missing_tool.__name__ = tool_name
    return _missing_tool


for _module_name, _tool_names in _EXPORT_SPECS:
    try:
        _module = import_module(f".{_module_name}", package=__name__)
        for _tool_name in _tool_names:
            if hasattr(_module, _tool_name):
                globals()[_tool_name] = getattr(_module, _tool_name)
            else:
                globals()[_tool_name] = _missing_tool_factory(
                    _tool_name,
                    _module_name,
                    AttributeError(f"missing attribute '{_tool_name}'"),
                )
    except Exception as _exc:
        for _tool_name in _tool_names:
            globals()[_tool_name] = _missing_tool_factory(_tool_name, _module_name, _exc)


__all__ = [name for _, names in _EXPORT_SPECS for name in names]
