"""Deprecated.

Gmail ingest path was removed. Chat-triggered analysis is now the only supported entrypoint.
This module is intentionally kept as a no-op placeholder for backward compatibility.
"""

from __future__ import annotations

from typing import Any


def _deprecated(*args: Any, **kwargs: Any) -> dict[str, Any]:
    _ = (args, kwargs)
    return {
        "status": "error",
        "message": "Gmail tools are deprecated. Use Chat-triggered analysis flow.",
    }


get_sidfm_emails = _deprecated
get_unread_emails = _deprecated
mark_email_as_read = _deprecated
check_gmail_connection = _deprecated
