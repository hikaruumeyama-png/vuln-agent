"""起票パイプライン メインモジュール。

公開API:
    generate_ticket(source_text, agent_query_fn=None, history_key="pipeline") -> TicketResult
"""

from __future__ import annotations

import dataclasses
import json
import logging
import re
from typing import Any, Callable

from shared.constants import MSG_FORMAT_EXPLOITED, PRODUCT_EXTRACT_PATTERNS
from shared.gemini_direct import (
    analyze_exploited_vuln,
    call_gemini_json,
    check_remediation_advice,
)
from shared.sbom_lookup import (
    build_sbom_not_registered_message,
    check_sbom_registration,
    get_sbom_almalinux_versions,
)
from shared.ticket_parsers import (
    build_entries_from_sid_links_fallback,
    classify_message_format,
    contains_specific_vuln_signal,
    extract_almalinux_versions_from_text,
    extract_sidfm_entries,
    group_sid_links_by_almalinux_version,
    infer_due_date_from_policy,
    infer_request_summary_from_source,
    is_summary_low_quality,
)
from shared.ticket_history import save_ticket_record_to_history
from shared.ticket_preferences import (
    PREFERENCE_STRONG_THRESHOLD,
    apply_preferences_to_facts,
    fetch_ticket_preferences,
)
from shared.ticket_renderers import (
    ai_final_review_with_value_lock,
    audit_ticket_candidate,
    build_exploited_not_target_message,
    build_exploited_update_message,
    build_low_quality_ticket_message,
    build_ticket_text_from_parts,
    infer_reasoning_from_facts,
    infer_ticket_detail_from_facts,
)

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class TicketResult:
    """generate_ticket() の戻り値。"""
    status: str      # "ticket" | "sbom_skip" | "exploited_update" |
                     # "exploited_not_target" | "low_quality" | "error"
    text: str        # 応答テキスト（起票テンプレート or スキップメッセージ）
    facts: dict[str, Any] | None = None
    audit_ok: bool = True
    audit_errors: list[str] = dataclasses.field(default_factory=list)


# ------------------------------------------------------------------
# ファクト組立
# ------------------------------------------------------------------


def extract_source_facts(source_text: str) -> dict[str, Any]:
    """通知テキストからファクト（エントリ、CVSS、期限等）を組み立てる。"""
    text = (source_text or "").strip()
    lowered = text.lower()
    entries = extract_sidfm_entries(text)
    pre_filter_count = len(entries)
    links = re.findall(r"https?://[^\s)>\]|]+", text)
    sid_links = [u for u in links if "sid.softek.jp/filter/sinfo/" in u]
    sid_links = list(dict.fromkeys(sid_links))
    if not entries and sid_links:
        entries = build_entries_from_sid_links_fallback(text, sid_links)
        logger.warning("[diag:facts] used sid_links_fallback, entries=%d", len(entries))
    sbom_alma_versions = get_sbom_almalinux_versions()
    logger.warning("[diag:facts] pre_filter_entries=%d sbom_versions=%r", pre_filter_count, sbom_alma_versions)
    if sbom_alma_versions:
        filtered_entries: list[dict[str, Any]] = []
        for e in entries:
            title = str(e.get("title") or "")
            m = re.search(r"almalinux\s*([0-9]{1,2})", title, re.IGNORECASE)
            if m:
                if m.group(1) in sbom_alma_versions:
                    filtered_entries.append(e)
                else:
                    logger.warning("[diag:facts] SBOM-filtered out: id=%s ver=%s title=%s", e.get("id"), m.group(1), title[:50])
            else:
                filtered_entries.append(e)
                logger.warning("[diag:facts] no AlmaLinux version in title, keeping: id=%s title=%s", e.get("id"), title[:50])
        entries = filtered_entries
    logger.warning("[diag:facts] post_filter_entries=%d", len(entries))

    due_groups: dict[str, list[dict[str, Any]]] = {}

    def _try_cvss_float(v: Any) -> float | None:
        try:
            return float(v)
        except (TypeError, ValueError):
            return None

    all_scores = [s for e in entries if (s := _try_cvss_float(e.get("cvss"))) is not None]
    max_score = max(all_scores) if all_scores else None

    for e in entries:
        score = _try_cvss_float(e.get("cvss"))
        if score is None:
            score = max_score
        due_date, due_reason = infer_due_date_from_policy(text, score)
        entry = dict(e)
        entry["due_date"] = due_date
        entry["due_reason"] = due_reason
        due_groups.setdefault(due_date, []).append(entry)

    selected_due_date = ""
    selected_entries: list[dict[str, Any]] = []
    if due_groups:
        def _due_sort_key(item: tuple[str, list[dict[str, Any]]]) -> tuple[int, str]:
            due, group = item
            due_key = due if re.fullmatch(r"\d{4}/\d{2}/\d{2}", due or "") else "9999/12/31"
            return (-len(group), due_key)
        selected_due_date, selected_entries = sorted(due_groups.items(), key=_due_sort_key)[0]
    else:
        selected_entries = []

    entry_links = [str(e.get("url") or "").strip() for e in selected_entries if str(e.get("url") or "").strip()]
    vuln_links = entry_links or sid_links or links

    grouped_links_by_version: dict[str, list[str]] = {}
    for e in (selected_entries or entries):
        title = str(e.get("title") or "")
        url = str(e.get("url") or "").strip()
        if not url:
            continue
        vm = re.search(r"AlmaLinux\s*([0-9]{1,2})", title, re.IGNORECASE)
        if not vm:
            continue
        key = f"AlmaLinux{vm.group(1)}"
        grouped_links_by_version.setdefault(key, [])
        if url not in grouped_links_by_version[key]:
            grouped_links_by_version[key].append(url)
    if not grouped_links_by_version:
        grouped_links_by_version = group_sid_links_by_almalinux_version(text, sid_links)
    if sbom_alma_versions and grouped_links_by_version:
        allowed = {f"AlmaLinux{v}" for v in sbom_alma_versions}
        grouped_links_by_version = {
            k: v for k, v in grouped_links_by_version.items() if k in allowed and v
        }

    products: list[str] = []
    entry_text_for_products = "\n".join(str(e.get("title") or "") for e in (selected_entries or entries))
    if "almalinux" in lowered or "almalinux" in entry_text_for_products.lower():
        versions = extract_almalinux_versions_from_text(entry_text_for_products or lowered)
        if not versions and sbom_alma_versions:
            versions = sorted(set(sbom_alma_versions), key=lambda x: int(x), reverse=True)
        if versions:
            products.extend([f"AlmaLinux{v}" for v in versions])
        else:
            products.append("AlmaLinux")
    if re.search(r"fortios|fortigate", lowered):
        products.append("FortiOS")
    if re.search(r"cisco\s*asa", lowered):
        products.append("Cisco ASA")
    if re.search(r"amazon\s*linux", lowered):
        products.append("Amazon Linux")
    if re.search(r"\bios\b|iphone", lowered):
        products.append("Apple iOS")
    for _pat, _pname in PRODUCT_EXTRACT_PATTERNS:
        if re.search(_pat, lowered) or re.search(_pat, entry_text_for_products.lower()):
            if _pname not in products:
                products.append(_pname)
    if not products:
        products.append("要確認")
    products = list(dict.fromkeys(products))

    scores: list[float] = []
    entry_scores = [s for e in selected_entries if (s := _try_cvss_float(e.get("cvss"))) is not None]
    if entry_scores:
        scores.extend(entry_scores)
    elif not sbom_alma_versions:
        for m in re.finditer(r"(?:cvss(?:v3)?[:\s]*)\s*(10(?:\.0)?|[0-9](?:\.[0-9])?)", lowered):
            try:
                scores.append(float(m.group(1)))
            except Exception:
                pass
        if not scores:
            for m in re.finditer(r"\b(10(?:\.0)?|[0-9]\.[0-9])\b", text):
                try:
                    value = float(m.group(1))
                    if 0.0 <= value <= 10.0:
                        scores.append(value)
                except Exception:
                    pass
    unique_scores = sorted(set(scores), reverse=True)
    max_score = unique_scores[0] if unique_scores else None
    logger.warning("[diag:facts] entry_scores=%r regex_fallback_used=%r max_score=%r selected_entries=%d",
                entry_scores, not entry_scores and not sbom_alma_versions, max_score, len(selected_entries))

    if selected_due_date:
        due_date = selected_due_date
        first_reason = str((selected_entries[0] or {}).get("due_reason") or "").strip() if selected_entries else ""
        due_reason = first_reason or "社内方針に基づき算出"
    else:
        due_date, due_reason = infer_due_date_from_policy(text, max_score)
    logger.warning("[diag:facts] final due_date=%r due_reason=%r", due_date, due_reason)
    return {
        "entries": selected_entries or entries,
        "all_entries_count": pre_filter_count,
        "selected_entries_count": len(selected_entries) if selected_entries else len(entries),
        "due_group_count": len(due_groups) if due_groups else 1,
        "products": products,
        "vuln_links": vuln_links[:20],
        "grouped_vuln_links": grouped_links_by_version,
        "scores": unique_scores[:10],
        "max_score": max_score,
        "due_date": due_date,
        "due_reason": due_reason,
        "sbom_alma_versions": sorted(sbom_alma_versions),
    }


# ------------------------------------------------------------------
# 仮説パイプライン
# ------------------------------------------------------------------


def _build_ticket_hypothesis_prompt(raw_text: str) -> str:
    return (
        "以下の脆弱性通知本文を解析し、まず仮説JSONのみを出力してください。"
        "説明文は禁止です。JSONオブジェクト以外を出力しないでください。\n"
        "必須スキーマ:\n"
        "{\n"
        '  "is_vulnerability_notification": true/false,\n'
        '  "request_summary": "string",\n'
        '  "target_products": ["string", ...],\n'
        '  "entries": [\n'
        "    {\n"
        '      "id": "string",\n'
        '      "cvss": number,\n'
        '      "title": "string",\n'
        '      "url": "string",\n'
        '      "os_version": "string (optional)",\n'
        '      "package": "string",\n'
        '      "confidence": number,\n'
        '      "evidence": "string"\n'
        "    }\n"
        "  ],\n"
        '  "grouping_plan": "single|split",\n'
        '  "assumptions": ["string", ...]\n'
        "}\n"
        "os_version はオプションです。特定OS/バージョン依存の脆弱性のみ記載してください。\n"
        "OS非依存（Webライブラリ等）の場合は `要確認` または省略可能です。\n"
        "不明値は空文字ではなく `要確認` を使ってください。\n\n"
        f"{raw_text}"
    )


def _validate_ticket_hypothesis_schema(hypothesis: dict[str, Any]) -> tuple[bool, list[str]]:
    errs: list[str] = []
    if not isinstance(hypothesis, dict):
        return False, ["hypothesis is not object"]
    for key in ("is_vulnerability_notification", "request_summary", "target_products", "entries", "grouping_plan", "assumptions"):
        if key not in hypothesis:
            errs.append(f"missing:{key}")
    if "target_products" in hypothesis and not isinstance(hypothesis.get("target_products"), list):
        errs.append("target_products must be list")
    if "entries" in hypothesis and not isinstance(hypothesis.get("entries"), list):
        errs.append("entries must be list")
    if isinstance(hypothesis.get("entries"), list):
        for idx, e in enumerate(hypothesis.get("entries") or []):
            if not isinstance(e, dict):
                errs.append(f"entries[{idx}] not object")
                continue
            for k in ("id", "cvss", "title", "url", "package", "confidence", "evidence"):
                if k not in e:
                    errs.append(f"entries[{idx}] missing:{k}")
    return (len(errs) == 0), errs


_HYPOTHESIS_RETRY_LIMIT = 2


def run_hypothesis_pipeline(source_text: str) -> dict[str, Any]:
    """Gemini直接呼び出しで脆弱性通知の仮説JSONを生成する。"""
    attempts = max(1, _HYPOTHESIS_RETRY_LIMIT + 1)
    last_errs: list[str] = []
    for attempt_num in range(attempts):
        prompt = _build_ticket_hypothesis_prompt(source_text)
        if attempt_num > 0 and last_errs:
            prompt = (
                prompt
                + "\n\n【前回の検証エラー】前回の出力が以下の理由で不正でした。修正して再出力してください。\n"
                + "\n".join(f"- {e}" for e in last_errs[:10])
                + "\n\nJSONのみ出力。説明文・マークダウン禁止。"
            )
        parsed = call_gemini_json(prompt)
        if not parsed:
            continue
        ok, errs = _validate_ticket_hypothesis_schema(parsed)
        if ok:
            return parsed
        last_errs = errs
    logger.warning("Hypothesis schema validation failed after retries: %s", ", ".join(last_errs))
    return {}


def merge_hypothesis_with_tool_facts(hypothesis: dict[str, Any], source_text: str) -> dict[str, Any]:
    """仮説JSONをツール検証済みファクトとマージする。"""
    facts = extract_source_facts(source_text)
    if not hypothesis:
        return facts

    products = [str(p).strip() for p in (hypothesis.get("target_products") or []) if str(p).strip()]
    if products:
        normalized = []
        for p in products:
            if re.search(r"almalinux\s*[0-9]{1,2}", p, re.IGNORECASE):
                m = re.search(r"([0-9]{1,2})", p)
                if m:
                    normalized.append(f"AlmaLinux{m.group(1)}")
                    continue
            normalized.append(p)
        facts["products"] = list(dict.fromkeys(normalized))

    h_entries = hypothesis.get("entries") if isinstance(hypothesis.get("entries"), list) else []
    if h_entries:
        by_id = {str(e.get("id") or "").strip(): e for e in facts.get("entries", []) if str(e.get("id") or "").strip()}
        for he in h_entries:
            if not isinstance(he, dict):
                continue
            hid = str(he.get("id") or "").strip()
            if not hid or hid not in by_id:
                continue
            if str(by_id[hid].get("title") or "").strip() in ("", "要確認"):
                by_id[hid]["title"] = str(he.get("title") or "").strip() or by_id[hid]["title"]
        facts["entries"] = list(by_id.values())

    req_summary = str(hypothesis.get("request_summary") or "").strip()
    if req_summary and not is_summary_low_quality(req_summary):
        facts["request_summary_ai"] = req_summary

    assumptions = hypothesis.get("assumptions")
    if isinstance(assumptions, list):
        facts["assumptions"] = [str(a).strip() for a in assumptions if str(a).strip()]
    return facts


# ------------------------------------------------------------------
# 公開API
# ------------------------------------------------------------------


def generate_ticket(
    source_text: str,
    agent_query_fn: Callable[[str, str], str] | None = None,
    history_key: str = "pipeline",
    space_id: str = "",
    thread_name: str = "",
) -> TicketResult:
    """脆弱性通知テキストから起票テンプレートを生成する。

    Args:
        source_text: 脆弱性通知の本文テキスト。
        agent_query_fn: Agent Engine 呼び出し関数 (DI)。None なら最終AIレビューをスキップ。
        history_key: 履歴キー（ログ用）。
        space_id: Google Chat スペースID（学習・履歴に使用）。
        thread_name: Google Chat スレッド名（履歴に使用）。

    Returns:
        TicketResult
    """
    if not (source_text or "").strip():
        return TicketResult(status="error", text="通知テキストが空です。")

    try:
        # 1. SBOM登録チェック
        sbom_should_skip, sbom_detected_products, sbom_reason = check_sbom_registration(source_text)
        if sbom_should_skip:
            return TicketResult(
                status="sbom_skip",
                text=build_sbom_not_registered_message(sbom_detected_products, sbom_reason),
            )

        # 2. メッセージフォーマット分類
        msg_format = classify_message_format(source_text)
        if msg_format == MSG_FORMAT_EXPLOITED:
            analysis = analyze_exploited_vuln(source_text)
            if not analysis:
                return TicketResult(
                    status="exploited_update",
                    text=(
                        "⚠ 悪用が確認された脆弱性の通知です（AI分析が利用できませんでした）。\n"
                        "内容を確認の上、速やかにアップデートの要否を判断してください。"
                    ),
                )
            if analysis.get("is_windows_or_apple"):
                return TicketResult(
                    status="exploited_update",
                    text=build_exploited_update_message(analysis),
                )
            return TicketResult(
                status="exploited_not_target",
                text=build_exploited_not_target_message(analysis),
            )

        # 3. 脆弱性シグナルチェック
        if not contains_specific_vuln_signal(source_text):
            return TicketResult(
                status="low_quality",
                text=build_low_quality_ticket_message(),
            )

        # 4. 仮説パイプライン
        hypothesis = run_hypothesis_pipeline(source_text)

        # 5. ファクトマージ
        merged_facts = merge_hypothesis_with_tool_facts(hypothesis, source_text)

        # 5.5. 学習システム: プリファレンス適用
        if space_id:
            try:
                preferences = fetch_ticket_preferences(
                    space_id=space_id,
                    product_names=merged_facts.get("products"),
                    cvss_score=merged_facts.get("max_score"),
                )
                if preferences:
                    merged_facts = apply_preferences_to_facts(merged_facts, preferences)
                    logger.info("Applied %d preferences for space %s", len(preferences), space_id)
            except Exception as exc:
                logger.warning("Preference fetch/apply failed: %s", exc)

        # 6. 【依頼内容】AIチェック（学習で強ロックされていない場合のみ）
        try:
            remediation_check = check_remediation_advice(merged_facts, source_text)
            if remediation_check.get("suggested_action"):
                merged_facts["remediation_text"] = remediation_check["suggested_action"]
            if remediation_check.get("risk_notes"):
                merged_facts["remediation_risk_notes"] = remediation_check["risk_notes"]
            if remediation_check.get("reasoning"):
                merged_facts["remediation_reasoning"] = remediation_check["reasoning"]
        except Exception as exc:
            logger.warning("Remediation check failed: %s", exc)

        # 7. テンプレート組立
        summary = str(
            merged_facts.get("request_summary_ai")
            or infer_request_summary_from_source(source_text)
        ).strip()
        detail = infer_ticket_detail_from_facts(merged_facts)
        reasoning = infer_reasoning_from_facts(merged_facts)

        # 8. 監査
        ok, audit_errors = audit_ticket_candidate(summary, detail, reasoning, facts=merged_facts)
        if not ok:
            logger.warning("Ticket audit failed, fallback to source-derived output: %s", ", ".join(audit_errors))
            fallback_facts = extract_source_facts(source_text)
            try:
                rc = check_remediation_advice(fallback_facts, source_text)
                if rc.get("suggested_action"):
                    fallback_facts["remediation_text"] = rc["suggested_action"]
                if rc.get("risk_notes"):
                    fallback_facts["remediation_risk_notes"] = rc["risk_notes"]
                if rc.get("reasoning"):
                    fallback_facts["remediation_reasoning"] = rc["reasoning"]
            except Exception:
                pass
            fb_summary = infer_request_summary_from_source(source_text)
            fb_detail = infer_ticket_detail_from_facts(fallback_facts)
            fb_reasoning = infer_reasoning_from_facts(fallback_facts)
            response_text = build_ticket_text_from_parts(fb_summary, fb_detail, fb_reasoning)
            # 10. 履歴保存（監査失敗時も保存）
            if space_id:
                try:
                    save_ticket_record_to_history(
                        space_id=space_id,
                        thread_name=thread_name,
                        response_text=response_text,
                        source=f"pipeline_audit_fallback:{history_key}",
                        facts=fallback_facts,
                    )
                except Exception as hist_exc:
                    logger.warning("History save failed: %s", hist_exc)
            return TicketResult(
                status="ticket",
                text=response_text,
                facts=fallback_facts,
                audit_ok=False,
                audit_errors=audit_errors,
            )

        # 9. AI最終レビュー（agent_query_fn があれば）
        response_text = ai_final_review_with_value_lock(
            summary, detail, reasoning,
            agent_query_fn=agent_query_fn,
            history_key=history_key,
        )

        # 10. 履歴保存
        if space_id:
            try:
                save_ticket_record_to_history(
                    space_id=space_id,
                    thread_name=thread_name,
                    response_text=response_text,
                    source=f"pipeline:{history_key}",
                    facts=merged_facts,
                )
            except Exception as hist_exc:
                logger.warning("History save failed: %s", hist_exc)

        return TicketResult(
            status="ticket",
            text=response_text,
            facts=merged_facts,
            audit_ok=True,
        )
    except Exception as exc:
        logger.exception("generate_ticket failed: %s", exc)
        return TicketResult(status="error", text=f"起票パイプラインエラー: {exc}")
