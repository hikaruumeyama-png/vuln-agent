"""
Tools package for Vulnerability Management Agent
"""

from .gmail_tools import (
    get_sidfm_emails,
    get_unread_emails,
    mark_email_as_read,
    check_gmail_connection,
)
from .sheets_tools import (
    search_sbom_by_purl,
    search_sbom_by_product,
    get_affected_systems,
    get_owner_mapping,
)
from .chat_tools import (
    send_vulnerability_alert,
    send_simple_message,
    check_chat_connection,
    list_space_members,
)
from .history_tools import log_vulnerability_history
from .a2a_tools import (
    register_remote_agent,
    call_remote_agent,
    list_registered_agents,
    create_jira_ticket_request,
    create_approval_request,
)
from .capability_tools import (
    get_runtime_capabilities,
    inspect_bigquery_capabilities,
    list_bigquery_tables,
    run_bigquery_readonly_query,
)
from .web_tools import (
    web_search,
    fetch_web_content,
)

__all__ = [
    # Gmail
    "get_sidfm_emails",
    "get_unread_emails",
    "mark_email_as_read",
    "check_gmail_connection",
    # Sheets
    "search_sbom_by_purl",
    "search_sbom_by_product",
    "get_affected_systems",
    "get_owner_mapping",
    # Chat
    "send_vulnerability_alert",
    "send_simple_message",
    "check_chat_connection",
    "list_space_members",
    # History
    "log_vulnerability_history",
    # A2A
    "register_remote_agent",
    "call_remote_agent",
    "list_registered_agents",
    "create_jira_ticket_request",
    "create_approval_request",
    # Capability
    "get_runtime_capabilities",
    "inspect_bigquery_capabilities",
    "list_bigquery_tables",
    "run_bigquery_readonly_query",
    # Web
    "web_search",
    "fetch_web_content",
]
