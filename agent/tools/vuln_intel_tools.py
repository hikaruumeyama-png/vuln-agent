"""
Vulnerability Intelligence Tools

外部脆弱性情報ソース（NVD/OSV）を参照する補助ツール。
"""

from __future__ import annotations

import json
from typing import Any
from urllib import parse, request


def get_nvd_cve_details(cve_id: str) -> dict[str, Any]:
    """
    NVD API から CVE 詳細を取得する。
    """
    normalized = (cve_id or "").strip().upper()
    if not normalized.startswith("CVE-"):
        return {"status": "error", "message": "cve_id は CVE-YYYY-NNNN 形式で指定してください。"}

    endpoint = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0?"
        + parse.urlencode({"cveId": normalized})
    )
    try:
        payload = _http_get_json(endpoint)
    except Exception as exc:
        return {"status": "error", "message": f"nvd query failed: {exc}"}

    vulns = payload.get("vulnerabilities") or []
    if not vulns:
        return {"status": "success", "cve_id": normalized, "found": False}

    cve_obj = (vulns[0] or {}).get("cve") or {}
    descriptions = cve_obj.get("descriptions") or []
    metrics = cve_obj.get("metrics") or {}
    references = cve_obj.get("references") or []

    description = _pick_description(descriptions)
    severity = _extract_cvss(metrics)
    refs = [r.get("url") for r in references if isinstance(r, dict) and r.get("url")]

    return {
        "status": "success",
        "cve_id": normalized,
        "found": True,
        "published": cve_obj.get("published"),
        "last_modified": cve_obj.get("lastModified"),
        "source_identifier": cve_obj.get("sourceIdentifier"),
        "description": description,
        "cvss": severity,
        "reference_urls": refs[:10],
    }


def search_osv_vulnerabilities(
    ecosystem: str,
    package_name: str,
    version: str = "",
    max_results: int = 10,
) -> dict[str, Any]:
    """
    OSV API でパッケージ脆弱性を検索する。
    ecosystem 例: PyPI, npm, Maven, Go
    """
    eco = (ecosystem or "").strip()
    pkg = (package_name or "").strip()
    ver = (version or "").strip()
    if not eco or not pkg:
        return {
            "status": "error",
            "message": "ecosystem と package_name は必須です。",
        }

    limit = _normalize_limit(max_results, default=10, max_value=30)
    body = {"package": {"ecosystem": eco, "name": pkg}}
    if ver:
        body["version"] = ver

    req = request.Request(
        "https://api.osv.dev/v1/query",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "vuln-agent/1.0 (+https://github.com/hikaruumeyama-png/vuln-agent)",
        },
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=20) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as exc:
        return {"status": "error", "message": f"osv query failed: {exc}"}

    vulns = payload.get("vulns") or []
    items = []
    for vuln in vulns[:limit]:
        aliases = vuln.get("aliases") or []
        refs = vuln.get("references") or []
        items.append(
            {
                "id": vuln.get("id"),
                "summary": vuln.get("summary") or "",
                "modified": vuln.get("modified"),
                "published": vuln.get("published"),
                "aliases": aliases,
                "reference_urls": [
                    r.get("url") for r in refs if isinstance(r, dict) and r.get("url")
                ][:10],
            }
        )

    return {
        "status": "success",
        "query": {
            "ecosystem": eco,
            "package_name": pkg,
            "version": ver,
        },
        "count": len(items),
        "vulnerabilities": items,
    }


def _http_get_json(url: str) -> dict[str, Any]:
    req = request.Request(
        url,
        headers={"User-Agent": "vuln-agent/1.0 (+https://github.com/hikaruumeyama-png/vuln-agent)"},
    )
    with request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def _pick_description(descriptions: list[dict[str, Any]]) -> str:
    if not descriptions:
        return ""
    en = [d for d in descriptions if (d.get("lang") or "").lower() == "en"]
    target = en[0] if en else descriptions[0]
    return (target.get("value") or "").strip()


def _extract_cvss(metrics: dict[str, Any]) -> dict[str, Any]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        first = entries[0] if isinstance(entries[0], dict) else {}
        cvss_data = first.get("cvssData") or {}
        return {
            "version": cvss_data.get("version"),
            "base_score": cvss_data.get("baseScore"),
            "base_severity": cvss_data.get("baseSeverity") or first.get("baseSeverity"),
            "vector_string": cvss_data.get("vectorString"),
        }
    return {}


def _normalize_limit(value: Any, default: int, max_value: int) -> int:
    try:
        num = int(value)
    except (TypeError, ValueError):
        return default
    if num < 1:
        return 1
    if num > max_value:
        return max_value
    return num
