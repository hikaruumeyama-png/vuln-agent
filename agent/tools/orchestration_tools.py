"""
Orchestration Tools

権限内で利用可能な操作を事前ツール化し、
実行時に「既存ツールを直接使う」か「ツール呼び出しコードを生成する」かを判定する。
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

try:
    from .capability_tools import get_runtime_capabilities, inspect_bigquery_capabilities
except Exception:
    try:
        from capability_tools import get_runtime_capabilities, inspect_bigquery_capabilities
    except Exception:
        def get_runtime_capabilities(include_live_checks: bool = True) -> dict[str, Any]:
            _ = include_live_checks
            return {"status": "error", "message": "capability_tools is unavailable"}

        def inspect_bigquery_capabilities(max_tables_per_dataset: int = 50) -> dict[str, Any]:
            _ = max_tables_per_dataset
            return {"status": "error", "message": "capability_tools is unavailable"}


_TOOL_OPERATIONS: list[dict[str, str]] = [
    {"tool": "search_sbom_by_purl", "domain": "sbom", "operation": "PURLでSBOM検索"},
    {"tool": "search_sbom_by_product", "domain": "sbom", "operation": "製品名でSBOM検索"},
    {"tool": "get_affected_systems", "domain": "sbom", "operation": "影響システム特定"},
    {"tool": "get_owner_mapping", "domain": "sbom", "operation": "担当者マッピング取得"},
    {"tool": "get_sbom_contents", "domain": "sbom", "operation": "SBOM一覧取得"},
    {"tool": "list_sbom_package_types", "domain": "sbom", "operation": "SBOM type一覧"},
    {"tool": "count_sbom_packages_by_type", "domain": "sbom", "operation": "SBOM type別件数"},
    {"tool": "list_sbom_packages_by_type", "domain": "sbom", "operation": "type指定SBOM一覧"},
    {"tool": "list_sbom_package_versions", "domain": "sbom", "operation": "パッケージ版一覧"},
    {"tool": "get_sbom_entry_by_purl", "domain": "sbom", "operation": "PURL一致1件取得"},
    {"tool": "send_vulnerability_alert", "domain": "chat", "operation": "脆弱性カード通知"},
    {"tool": "send_simple_message", "domain": "chat", "operation": "Chatメッセージ送信"},
    {"tool": "check_chat_connection", "domain": "chat", "operation": "Chat接続確認"},
    {"tool": "list_space_members", "domain": "chat", "operation": "スペースメンバー一覧"},
    {"tool": "log_vulnerability_history", "domain": "history", "operation": "履歴保存"},
    {"tool": "register_remote_agent", "domain": "a2a", "operation": "A2A登録"},
    {"tool": "register_master_agent", "domain": "a2a", "operation": "master_agent登録"},
    {"tool": "call_remote_agent", "domain": "a2a", "operation": "A2A呼び出し"},
    {"tool": "call_master_agent", "domain": "a2a", "operation": "master_agent呼び出し"},
    {"tool": "list_registered_agents", "domain": "a2a", "operation": "A2A登録一覧"},
    {"tool": "create_jira_ticket_request", "domain": "a2a", "operation": "Jira依頼文作成"},
    {"tool": "create_approval_request", "domain": "a2a", "operation": "承認依頼文作成"},
    {"tool": "create_master_agent_handoff_request", "domain": "a2a", "operation": "引継ぎ依頼文作成"},
    {"tool": "get_runtime_capabilities", "domain": "capability", "operation": "実行時能力確認"},
    {"tool": "inspect_bigquery_capabilities", "domain": "capability", "operation": "BQ能力診断"},
    {"tool": "list_bigquery_tables", "domain": "bigquery", "operation": "BQテーブル一覧"},
    {"tool": "run_bigquery_readonly_query", "domain": "bigquery", "operation": "BQ read-only実行"},
    {"tool": "web_search", "domain": "web", "operation": "Web検索"},
    {"tool": "fetch_web_content", "domain": "web", "operation": "Web本文取得"},
    {"tool": "get_nvd_cve_details", "domain": "intel", "operation": "NVD CVE詳細"},
    {"tool": "search_osv_vulnerabilities", "domain": "intel", "operation": "OSV脆弱性検索"},
    {"tool": "get_chat_space_info", "domain": "granular", "operation": "Chatスペース情報"},
    {"tool": "list_chat_member_emails", "domain": "granular", "operation": "Chatメンバーメール一覧"},
    {"tool": "build_history_record_preview", "domain": "granular", "operation": "履歴保存プレビュー"},
    {"tool": "list_registered_agent_ids", "domain": "granular", "operation": "A2A ID一覧"},
    {"tool": "get_registered_agent_details", "domain": "granular", "operation": "A2A詳細"},
    {"tool": "get_configured_bigquery_tables", "domain": "granular", "operation": "BQ設定取得"},
    {"tool": "check_bigquery_readability_summary", "domain": "granular", "operation": "BQ読取可否要約"},
    {"tool": "list_web_search_urls", "domain": "granular", "operation": "検索URL一覧"},
    {"tool": "get_web_content_excerpt", "domain": "granular", "operation": "Web抜粋取得"},
    {"tool": "get_nvd_cvss_summary", "domain": "granular", "operation": "NVD CVSS要約"},
    {"tool": "list_osv_vulnerability_ids", "domain": "granular", "operation": "OSV ID一覧"},
    {"tool": "save_vulnerability_history_minimal", "domain": "granular", "operation": "最小履歴保存"},
    {"tool": "list_predefined_operations", "domain": "orchestration", "operation": "事前操作一覧取得"},
    {"tool": "list_operation_catalog_health", "domain": "orchestration", "operation": "操作カタログ差分確認"},
    {"tool": "get_authorized_operations_overview", "domain": "orchestration", "operation": "権限可能操作の全体確認"},
    {"tool": "decide_execution_mode", "domain": "orchestration", "operation": "実行方式判定"},
    {"tool": "generate_tool_workflow_code", "domain": "orchestration", "operation": "ツール呼出コード生成"},
    {"tool": "execute_tool_workflow_plan", "domain": "orchestration", "operation": "ツール実行プラン段階実行"},
    {"tool": "list_known_config_keys", "domain": "config", "operation": "設定キー一覧取得"},
    {"tool": "get_runtime_config_snapshot", "domain": "config", "operation": "実行時設定スナップショット"},
]

_KEYWORD_TOOL_MAP: list[tuple[str, str]] = [
    ("cve", "get_nvd_cve_details"),
    ("osv", "search_osv_vulnerabilities"),
    ("sbom", "search_sbom_by_product"),
    ("purl", "search_sbom_by_purl"),
    ("bigquery", "run_bigquery_readonly_query"),
    ("chat", "send_simple_message"),
    ("通知", "send_vulnerability_alert"),
    ("担当者", "get_owner_mapping"),
]

_COMPLEXITY_HINTS = (
    "一括",
    "全件",
    "横断",
    "突合",
    "集計",
    "複数",
    "段階",
    "ワークフロー",
    "自動化",
    "レポート",
    "してから",
    "続けて",
    "その後",
)
_MAX_PLAN_STEPS = 10
_DEFAULT_DOMAIN_BY_PREFIX: list[tuple[str, str]] = [
    ("search_sbom_", "sbom"),
    ("get_sbom_", "sbom"),
    ("list_sbom_", "sbom"),
    ("count_sbom_", "sbom"),
    ("get_affected_", "sbom"),
    ("get_owner_", "sbom"),
    ("send_", "chat"),
    ("check_chat_", "chat"),
    ("list_space_", "chat"),
    ("register_", "a2a"),
    ("call_", "a2a"),
    ("create_", "a2a"),
    ("list_registered_", "a2a"),
    ("inspect_bigquery_", "bigquery"),
    ("list_bigquery_", "bigquery"),
    ("run_bigquery_", "bigquery"),
    ("web_", "web"),
    ("fetch_web_", "web"),
]


def list_predefined_operations(domain: str = "") -> dict[str, Any]:
    """事前ツール化された操作一覧を返す。"""
    target = (domain or "").strip().lower() or ""
    public_tools = _list_public_tool_names()
    operations = _build_operation_catalog(public_tools)
    if target:
        operations = [x for x in operations if x["domain"] == target]
    return {
        "status": "success",
        "count": len(operations),
        "domains": sorted({x["domain"] for x in operations}),
        "operations": operations,
    }


def list_operation_catalog_health() -> dict[str, Any]:
    """
    事前定義カタログと公開ツール一覧の差分を返す。
    これによりカタログ漏れを検知できる。
    """
    public_tools = _list_public_tool_names()
    cataloged = {x["tool"] for x in _TOOL_OPERATIONS}
    missing_in_catalog = sorted([name for name in public_tools if name not in cataloged])
    stale_catalog_entries = sorted([name for name in cataloged if name not in public_tools])
    return {
        "status": "success",
        "public_tool_count": len(public_tools),
        "catalog_count": len(cataloged),
        "missing_in_catalog": missing_in_catalog,
        "stale_catalog_entries": stale_catalog_entries,
        "is_synced": not missing_in_catalog and not stale_catalog_entries,
    }


def get_authorized_operations_overview(
    include_live_checks: bool = True,
    include_bigquery_probe: bool = False,
) -> dict[str, Any]:
    """
    現在権限で実行可能な操作の全体像を返す。
    """
    runtime = get_runtime_capabilities(include_live_checks=include_live_checks)
    catalog = list_predefined_operations()
    health = list_operation_catalog_health()
    overview: dict[str, Any] = {
        "status": "success",
        "runtime_capabilities": runtime,
        "operation_catalog": {
            "count": catalog.get("count", 0),
            "domains": catalog.get("domains", []),
        },
        "catalog_health": health,
    }
    if include_bigquery_probe:
        overview["bigquery_probe"] = inspect_bigquery_capabilities()
    return overview


def _suggest_tools_from_request(user_request: str) -> list[str]:
    text = (user_request or "").strip().lower()
    suggestions: list[str] = []
    for keyword, tool_name in _KEYWORD_TOOL_MAP:
        if keyword in text and tool_name not in suggestions:
            suggestions.append(tool_name)
    return suggestions[:6]


def decide_execution_mode(
    user_request: str,
    requested_operations: list[str] | None = None,
) -> dict[str, Any]:
    """
    実行方式を判定する。
    - direct_tool: 既存ツールをそのまま呼ぶ
    - codegen_with_tools: 複雑な場合にツール呼び出しコードを生成する
    """
    request_text = (user_request or "").strip()
    if not request_text:
        return {"status": "error", "message": "user_request は必須です。"}

    requested_ops = [str(x).strip() for x in (requested_operations or []) if str(x).strip()]
    normalized = request_text.lower()
    complexity_score = 0

    if len(request_text) >= 120:
        complexity_score += 1
    if len(requested_ops) >= 4:
        complexity_score += 2
    elif len(requested_ops) >= 2:
        complexity_score += 1

    complexity_hits = [hint for hint in _COMPLEXITY_HINTS if hint in normalized]
    complexity_score += min(len(complexity_hits), 3)

    mode = "codegen_with_tools" if complexity_score >= 3 else "direct_tool"
    suggested_tools = requested_ops or _suggest_tools_from_request(request_text)

    reason = (
        "複数段階または複数操作が含まれるため、ツール呼び出しコード生成を推奨します。"
        if mode == "codegen_with_tools"
        else "要求は単発または低複雑度のため、既存ツール直接実行を推奨します。"
    )
    return {
        "status": "success",
        "mode": mode,
        "complexity_score": complexity_score,
        "complexity_hints": complexity_hits,
        "suggested_tools": suggested_tools,
        "reason": reason,
    }


def generate_tool_workflow_code(
    user_request: str,
    tool_sequence: list[str] | None = None,
) -> dict[str, Any]:
    """ツール呼び出しワークフローのPythonコードを生成する（実行はしない）。"""
    request_text = (user_request or "").strip()
    if not request_text:
        return {"status": "error", "message": "user_request は必須です。"}

    sequence = [str(x).strip() for x in (tool_sequence or []) if str(x).strip()]
    if not sequence:
        sequence = _suggest_tools_from_request(request_text)
    if not sequence:
        sequence = ["get_runtime_capabilities"]

    code_lines = [
        "def run_workflow(tools):",
        '    """Generated workflow skeleton. Do not execute untrusted code."""',
        f"    request = {request_text!r}",
        "    results = []",
    ]
    for tool_name in sequence:
        code_lines.append(f"    # Step: {tool_name}")
        code_lines.append(f"    results.append({{'tool': '{tool_name}', 'result': tools['{tool_name}']()}})")
    code_lines.extend(
        [
            "    return {",
            "        'status': 'success',",
            "        'request': request,",
            "        'steps': len(results),",
            "        'results': results,",
            "    }",
        ]
    )

    return {
        "status": "success",
        "language": "python",
        "mode": "codegen_with_tools",
        "tool_sequence": sequence,
        "code": "\n".join(code_lines),
        "note": "生成コードは設計確認用です。実行時は各ツールを個別に安全に呼び出してください。",
    }


def execute_tool_workflow_plan(
    plan_steps: list[dict[str, Any]],
    fail_fast: bool = True,
) -> dict[str, Any]:
    """
    ツール実行プランを安全に段階実行する。

    step 形式:
    {"tool": "tool_name", "kwargs": {"arg": "value"}}
    """
    steps = [s for s in (plan_steps or []) if isinstance(s, dict)]
    if not steps:
        return {"status": "error", "message": "plan_steps は必須です。"}
    if len(steps) > _MAX_PLAN_STEPS:
        return {"status": "error", "message": f"plan_steps は最大 {_MAX_PLAN_STEPS} までです。"}

    public_tools = set(_list_public_tool_names())
    results: list[dict[str, Any]] = []

    for index, step in enumerate(steps, start=1):
        tool_name = str(step.get("tool") or "").strip()
        kwargs = step.get("kwargs") or {}
        if not tool_name:
            result = {"step": index, "status": "error", "message": "tool が未指定です。"}
            results.append(result)
            if fail_fast:
                return {"status": "error", "step_results": results}
            continue
        if tool_name not in public_tools:
            result = {"step": index, "tool": tool_name, "status": "error", "message": "未公開ツールです。"}
            results.append(result)
            if fail_fast:
                return {"status": "error", "step_results": results}
            continue
        if not isinstance(kwargs, dict):
            result = {"step": index, "tool": tool_name, "status": "error", "message": "kwargs は dict で指定してください。"}
            results.append(result)
            if fail_fast:
                return {"status": "error", "step_results": results}
            continue

        try:
            fn = _resolve_tool(tool_name)
            tool_result = fn(**kwargs)
            results.append(
                {
                    "step": index,
                    "tool": tool_name,
                    "status": "success",
                    "result": tool_result,
                }
            )
        except Exception as exc:
            results.append(
                {
                    "step": index,
                    "tool": tool_name,
                    "status": "error",
                    "message": str(exc),
                }
            )
            if fail_fast:
                return {"status": "error", "step_results": results}

    overall = "success" if all(r.get("status") == "success" for r in results) else "partial"
    return {"status": overall, "steps": len(results), "step_results": results}


def _list_public_tool_names() -> list[str]:
    tools_pkg = import_module("agent.tools")
    names = [name for name in getattr(tools_pkg, "__all__", []) if isinstance(name, str)]
    return sorted(set(names))


def _resolve_tool(tool_name: str):
    tools_pkg = import_module("agent.tools")
    fn = getattr(tools_pkg, tool_name, None)
    if not callable(fn):
        raise ValueError(f"Tool '{tool_name}' is not callable.")
    return fn


def _build_operation_catalog(public_tools: list[str]) -> list[dict[str, str]]:
    catalog_by_tool = {entry["tool"]: dict(entry) for entry in _TOOL_OPERATIONS}
    merged: list[dict[str, str]] = []
    for tool_name in sorted(public_tools):
        if tool_name in catalog_by_tool:
            merged.append(catalog_by_tool[tool_name])
            continue
        merged.append(
            {
                "tool": tool_name,
                "domain": _infer_domain(tool_name),
                "operation": f"{tool_name} operation",
            }
        )
    return merged


def _infer_domain(tool_name: str) -> str:
    for prefix, domain in _DEFAULT_DOMAIN_BY_PREFIX:
        if tool_name.startswith(prefix):
            return domain
    return "unclassified"
