"""
Granular Tools

既存ツールをより小さい単位で利用できるようにするラッパー群。
大きな依頼に対して、エージェントが段階的に合成して回答しやすくする。
"""

from __future__ import annotations

from typing import Any

try:
    from .gmail_tools import get_sidfm_emails, get_unread_emails
    from .chat_tools import check_chat_connection, list_space_members
    from .history_tools import log_vulnerability_history
    from .a2a_tools import list_registered_agents
    from .capability_tools import get_runtime_capabilities, inspect_bigquery_capabilities
    from .web_tools import web_search, fetch_web_content
    from .vuln_intel_tools import get_nvd_cve_details, search_osv_vulnerabilities
except ImportError:
    from gmail_tools import get_sidfm_emails, get_unread_emails
    from chat_tools import check_chat_connection, list_space_members
    from history_tools import log_vulnerability_history
    from a2a_tools import list_registered_agents
    from capability_tools import get_runtime_capabilities, inspect_bigquery_capabilities
    from web_tools import web_search, fetch_web_content
    from vuln_intel_tools import get_nvd_cve_details, search_osv_vulnerabilities


def list_sidfm_email_subjects(max_results: int = 10) -> dict[str, Any]:
    """SIDfmメールの件名一覧のみ返す。"""
    result = get_sidfm_emails(max_results=max_results)
    emails = result.get("emails") or []
    subjects = [{"id": e.get("id"), "subject": e.get("subject", "")} for e in emails]
    return {
        "status": result.get("status", "success"),
        "count": len(subjects),
        "subjects": subjects,
    }


def list_unread_email_ids(query: str = "is:unread", max_results: int = 20) -> dict[str, Any]:
    """未読メールID一覧のみ返す。"""
    result = get_unread_emails(query=query, max_results=max_results)
    emails = result.get("emails") or []
    ids = [e.get("id") for e in emails if e.get("id")]
    return {"status": result.get("status", "success"), "count": len(ids), "email_ids": ids}


def get_email_preview_by_id(email_id: str, max_results: int = 100) -> dict[str, Any]:
    """
    指定メールIDのプレビューを返す。
    Gmailクエリ制約を避けるため、未読一覧からID一致を抽出する。
    """
    target = (email_id or "").strip()
    if not target:
        return {"status": "error", "message": "email_id は必須です。"}
    result = get_unread_emails(query="is:unread", max_results=max_results)
    emails = result.get("emails") or []
    for email in emails:
        if (email.get("id") or "").strip() == target:
            return {
                "status": "success",
                "email": {
                    "id": email.get("id"),
                    "subject": email.get("subject", ""),
                    "from": email.get("from", ""),
                    "date": email.get("date", ""),
                    "body_preview": email.get("body_preview", ""),
                },
            }
    return {
        "status": "not_found",
        "message": "指定メールIDは未読一覧に見つかりませんでした。",
        "email_id": target,
    }


def get_chat_space_info(space_id: str | None = None) -> dict[str, Any]:
    """Chatスペース基本情報のみ返す。"""
    result = check_chat_connection(space_id=space_id)
    if result.get("status") != "connected":
        return result
    return {
        "status": "success",
        "space_id": result.get("space_id"),
        "space_name": result.get("space_name"),
        "space_type": result.get("space_type"),
        "member_count": result.get("member_count", 0),
    }


def list_chat_member_emails(space_id: str | None = None) -> dict[str, Any]:
    """Chatメンバーのメール一覧のみ返す。"""
    result = list_space_members(space_id=space_id)
    if result.get("status") != "success":
        return result
    members = result.get("members") or []
    emails = sorted({m.get("email", "") for m in members if m.get("email")})
    return {"status": "success", "count": len(emails), "emails": emails}


def build_history_record_preview(
    vulnerability_id: str,
    title: str,
    severity: str,
    affected_systems: list[str],
    cvss_score: float | None = None,
) -> dict[str, Any]:
    """履歴保存前の最小レコードプレビューを返す（DB書き込みなし）。"""
    return {
        "status": "ready",
        "record": {
            "vulnerability_id": (vulnerability_id or "").strip(),
            "title": (title or "").strip(),
            "severity": (severity or "").strip(),
            "affected_systems": [str(x).strip() for x in (affected_systems or []) if str(x).strip()],
            "cvss_score": cvss_score,
        },
    }


def list_registered_agent_ids() -> dict[str, Any]:
    """登録済みA2AエージェントID一覧のみ返す。"""
    result = list_registered_agents()
    agents = result.get("agents") or []
    ids = [a.get("agent_id") for a in agents if a.get("agent_id")]
    return {"status": result.get("status", "success"), "count": len(ids), "agent_ids": ids}


def get_registered_agent_details(agent_id: str) -> dict[str, Any]:
    """指定A2Aエージェントの登録情報を返す。"""
    target = (agent_id or "").strip()
    if not target:
        return {"status": "error", "message": "agent_id は必須です。"}
    result = list_registered_agents()
    for agent in result.get("agents") or []:
        if (agent.get("agent_id") or "").strip() == target:
            return {"status": "success", "agent": agent}
    return {"status": "not_found", "agent_id": target}


def get_configured_bigquery_tables() -> dict[str, Any]:
    """設定済みBigQueryテーブル情報のみ返す。"""
    result = get_runtime_capabilities(include_live_checks=False)
    configuration = result.get("configuration") or {}
    return {
        "status": "success",
        "project_id": configuration.get("project_id"),
        "bigquery_tables": configuration.get("bigquery_tables", {}),
    }


def check_bigquery_readability_summary() -> dict[str, Any]:
    """BigQuery読取可否の要約のみ返す。"""
    result = inspect_bigquery_capabilities()
    checks = result.get("table_read_checks") or []
    readable = [c.get("name") for c in checks if c.get("readable")]
    unreadable = [c.get("name") for c in checks if not c.get("readable")]
    return {
        "status": result.get("status", "error"),
        "project_id": result.get("project_id"),
        "readable_tables": readable,
        "unreadable_tables": unreadable,
    }


def list_web_search_urls(query: str, max_results: int = 5) -> dict[str, Any]:
    """Web検索結果のURL一覧のみ返す。"""
    result = web_search(query=query, max_results=max_results)
    urls = [r.get("url") for r in (result.get("results") or []) if r.get("url")]
    return {"status": result.get("status", "error"), "count": len(urls), "urls": urls}


def get_web_content_excerpt(url: str, max_chars: int = 1200) -> dict[str, Any]:
    """URL本文の短い抜粋のみ返す。"""
    result = fetch_web_content(url=url, max_chars=max_chars)
    if result.get("status") != "success":
        return result
    return {
        "status": "success",
        "url": result.get("url"),
        "excerpt": result.get("content", ""),
        "content_type": result.get("content_type"),
    }


def get_nvd_cvss_summary(cve_id: str) -> dict[str, Any]:
    """NVD詳細からCVSS要約のみ返す。"""
    result = get_nvd_cve_details(cve_id=cve_id)
    if result.get("status") != "success":
        return result
    return {
        "status": "success",
        "cve_id": result.get("cve_id"),
        "found": result.get("found", False),
        "cvss": result.get("cvss", {}),
        "published": result.get("published"),
        "last_modified": result.get("last_modified"),
    }


def list_osv_vulnerability_ids(
    ecosystem: str,
    package_name: str,
    version: str = "",
    max_results: int = 10,
) -> dict[str, Any]:
    """OSV検索結果から脆弱性ID一覧のみ返す。"""
    result = search_osv_vulnerabilities(
        ecosystem=ecosystem,
        package_name=package_name,
        version=version,
        max_results=max_results,
    )
    if result.get("status") != "success":
        return result
    ids = [v.get("id") for v in (result.get("vulnerabilities") or []) if v.get("id")]
    return {
        "status": "success",
        "query": result.get("query", {}),
        "count": len(ids),
        "vulnerability_ids": ids,
    }


def save_vulnerability_history_minimal(
    vulnerability_id: str,
    title: str,
    severity: str,
    affected_systems: list[str],
) -> dict[str, Any]:
    """最小必須項目のみで履歴保存する。"""
    return log_vulnerability_history(
        vulnerability_id=vulnerability_id,
        title=title,
        severity=severity,
        affected_systems=affected_systems,
    )
