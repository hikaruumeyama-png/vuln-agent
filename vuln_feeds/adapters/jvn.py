"""JVN iPedia (MyJVN API) アダプター。

ソース: https://jvndb.jvn.jp/apis/myjvn/
API: MyJVN API v3 (getVulnOverviewList) — XML レスポンス
差分取得: datePublished パラメータで公開日フィルタ
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

from shared.vuln_schema import AffectedProduct, VulnEntry, cvss_to_severity

from .base import BaseSourceAdapter, fetch_with_retry

logger = logging.getLogger(__name__)

# MyJVN API エンドポイント
_MYJVN_API_URL = "https://jvndb.jvn.jp/myjvn"

# XML 名前空間
_NS = {
    "sec": "http://jvn.jp/rss/mod_sec/3.0/",
    "marking": "http://data-marking.mitre.org/Marking-1",
    "tlpMarking": "http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1",
    "status": "http://jvndb.jvn.jp/myjvn/Status",
    "vuldef": "http://jvn.jp/vuldef/",
    "atom": "http://www.w3.org/2005/Atom",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
}

# CVE-ID 抽出パターン
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class JvnAdapter(BaseSourceAdapter):
    """JVN iPedia (MyJVN API) アダプター。"""

    source_id = "jvn"
    default_poll_interval_minutes = 60

    def fetch_recent(self, since: datetime) -> list[VulnEntry]:
        """MyJVN API から since 以降に公開された脆弱性を取得する。"""
        # datePublished のフォーマット: YYYY-MM-dd
        date_str = since.strftime("%Y-%m-%d")

        params = {
            "method": "getVulnOverviewList",
            "feed": "hnd",
            "datePublished": date_str,
            "rangeDatePublished": "n",  # 指定日以降
        }
        query = "&".join(f"{k}={v}" for k, v in params.items())
        url = f"{_MYJVN_API_URL}?{query}"

        try:
            raw = fetch_with_retry(url, timeout=30)
            xml_text = raw.decode("utf-8", errors="replace")
        except Exception as exc:
            logger.error("JVN API fetch failed: %s", exc)
            return []

        return _parse_jvn_xml(xml_text, since)


def _parse_jvn_xml(xml_text: str, since: datetime) -> list[VulnEntry]:
    """MyJVN API の XML レスポンスをパースして VulnEntry リストを返す。"""
    entries: list[VulnEntry] = []

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        logger.error("JVN XML parse failed: %s", exc)
        return []

    # Atom feed の場合: entry 要素を探す
    for item in root.findall(".//atom:entry", _NS):
        entry = _parse_atom_entry(item, since)
        if entry is not None:
            entries.append(entry)

    # VULDEF 形式の場合: Vulinfo 要素を探す
    if not entries:
        for item in root.findall(".//{http://jvn.jp/vuldef/}Vulinfo"):
            entry = _parse_vuldef_entry(item, since)
            if entry is not None:
                entries.append(entry)

    # RDF/RSS 形式: <item> 内の sec:identifier を使う
    if not entries:
        for item in root.findall(".//{http://purl.org/rss/1.0/}item"):
            entry = _parse_rdf_item(item, since)
            if entry is not None:
                entries.append(entry)

    # フォールバック: sec:item を探す (RSS形式)
    if not entries:
        for item in root.findall(".//sec:item", _NS):
            entry = _parse_sec_item(item, since)
            if entry is not None:
                entries.append(entry)

    logger.info("JVN: parsed %d entries", len(entries))
    return entries


def _parse_atom_entry(item: ET.Element, since: datetime) -> VulnEntry | None:
    """Atom feed の entry 要素をパースする。"""
    title = _text(item, "atom:title", _NS)
    jvn_id = _text(item, "atom:id", _NS)
    link_elem = item.find("atom:link", _NS)
    link = link_elem.get("href", "") if link_elem is not None else ""
    summary = _text(item, "atom:summary", _NS)
    published = _text(item, "atom:published", _NS)
    updated = _text(item, "atom:updated", _NS)

    if not jvn_id:
        return None

    # CVE-ID を抽出
    aliases = _CVE_PATTERN.findall(f"{title} {summary}")
    aliases = list(set(a.upper() for a in aliases))

    vuln_id = jvn_id.strip()
    # JVNDB ID が CVE の場合はそれを vuln_id に
    if aliases and not vuln_id.upper().startswith("CVE-"):
        primary_cve = aliases[0]
        aliases = [a for a in aliases if a != primary_cve]
        aliases.insert(0, vuln_id.upper())
        vuln_id = primary_cve
    elif vuln_id.upper().startswith("CVE-"):
        aliases = [a for a in aliases if a.upper() != vuln_id.upper()]

    # CVSS スコア抽出
    cvss_score = _extract_cvss_from_sec(item)
    severity = cvss_to_severity(cvss_score)

    return VulnEntry(
        vuln_id=vuln_id,
        aliases=aliases,
        title=title,
        description=summary,
        published=published,
        last_modified=updated or published,
        source="jvn",
        source_url=link or f"https://jvndb.jvn.jp/ja/contents/{jvn_id}.html",
        cvss_score=cvss_score,
        severity=severity,
        affected_products=_extract_products_from_sec(item),
    )


def _parse_rdf_item(item: ET.Element, since: datetime) -> VulnEntry | None:
    """RDF/RSS 1.0 形式の item 要素をパースする。

    MyJVN API の getVulnOverviewList (feed=hnd) がこの形式を返す。
    """
    _rss_ns = {"rss": "http://purl.org/rss/1.0/"}
    title = _text(item, "rss:title", _rss_ns)
    link = _text(item, "rss:link", _rss_ns)
    description = _text(item, "rss:description", _rss_ns)

    # sec:identifier から JVNDB ID を取得
    jvn_id = _text(item, "sec:identifier", _NS)
    if not jvn_id:
        return None

    # 日付フィルタ: dc:date
    date_str = _text(item, "dc:date", _NS)
    if not date_str:
        date_str = _text(item, "dcterms:issued", _NS)
    if date_str:
        try:
            pub_dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            if pub_dt.tzinfo is None:
                pub_dt = pub_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pub_dt = None
    else:
        pub_dt = None

    # CVE-ID を抽出
    text_blob = f"{title} {description}"
    aliases = list(set(c.upper() for c in _CVE_PATTERN.findall(text_blob)))

    # sec:references からも CVE-ID を抽出
    for ref in item.findall("sec:references", _NS):
        ref_source = (ref.get("source") or "").strip()
        ref_id = (ref.get("id") or "").strip()
        if ref_source == "CVE" and ref_id:
            ref_id_upper = ref_id.upper()
            if ref_id_upper not in aliases:
                aliases.append(ref_id_upper)

    vuln_id = jvn_id.strip()
    # CVE-ID があればそちらを主キーに
    if aliases and not vuln_id.upper().startswith("CVE-"):
        primary_cve = aliases[0]
        remaining = [a for a in aliases if a != primary_cve]
        remaining.insert(0, vuln_id.upper())
        aliases = remaining
        vuln_id = primary_cve
    elif vuln_id.upper().startswith("CVE-"):
        aliases = [a for a in aliases if a.upper() != vuln_id.upper()]

    # CVSS スコア抽出
    cvss_score = _extract_cvss_from_sec(item)
    severity = cvss_to_severity(cvss_score)

    published_iso = pub_dt.isoformat() if pub_dt else ""

    return VulnEntry(
        vuln_id=vuln_id,
        aliases=aliases,
        title=title,
        description=description,
        published=published_iso,
        last_modified=published_iso,
        source="jvn",
        source_url=link or f"https://jvndb.jvn.jp/ja/contents/{jvn_id}.html",
        cvss_score=cvss_score,
        severity=severity,
        affected_products=_extract_products_from_sec(item),
    )


def _parse_vuldef_entry(item: ET.Element, since: datetime) -> VulnEntry | None:
    """VULDEF 形式の Vulinfo 要素をパースする。"""
    ns_vd = "{http://jvn.jp/vuldef/}"
    vuln_id_elem = item.find(f".//{ns_vd}VulinfoID")
    title_elem = item.find(f".//{ns_vd}Title")
    overview_elem = item.find(f".//{ns_vd}Overview")

    vuln_id = (vuln_id_elem.text or "").strip() if vuln_id_elem is not None else ""
    title = (title_elem.text or "").strip() if title_elem is not None else ""
    overview = (overview_elem.text or "").strip() if overview_elem is not None else ""

    if not vuln_id:
        return None

    aliases = _CVE_PATTERN.findall(f"{title} {overview}")
    aliases = list(set(a.upper() for a in aliases))

    return VulnEntry(
        vuln_id=vuln_id,
        aliases=aliases,
        title=title,
        description=overview,
        source="jvn",
        source_url=f"https://jvndb.jvn.jp/ja/contents/{vuln_id}.html",
    )


def _parse_sec_item(item: ET.Element, since: datetime) -> VulnEntry | None:
    """sec:item 形式のエントリをパースする。"""
    title = _text(item, "sec:title", _NS)
    identifier = _text(item, "sec:identifier", _NS)
    link = _text(item, "sec:link", _NS)
    description = _text(item, "sec:description", _NS)

    if not identifier:
        return None

    aliases = _CVE_PATTERN.findall(f"{title} {description}")
    aliases = list(set(a.upper() for a in aliases))

    return VulnEntry(
        vuln_id=identifier,
        aliases=aliases,
        title=title,
        description=description,
        source="jvn",
        source_url=link or f"https://jvndb.jvn.jp/ja/contents/{identifier}.html",
    )


def _extract_cvss_from_sec(item: ET.Element) -> float | None:
    """sec:cvss 要素から CVSS スコアを抽出する。"""
    # v3 優先
    for cvss_elem in item.findall("sec:cvss", _NS):
        score_str = cvss_elem.get("score", "")
        version = cvss_elem.get("version", "")
        if score_str and version.startswith("3"):
            try:
                return float(score_str)
            except ValueError:
                pass
    # v2 フォールバック
    for cvss_elem in item.findall("sec:cvss", _NS):
        score_str = cvss_elem.get("score", "")
        if score_str:
            try:
                return float(score_str)
            except ValueError:
                pass
    return None


def _extract_products_from_sec(item: ET.Element) -> list[AffectedProduct]:
    """sec:cpe 要素から影響製品を抽出する。"""
    products: list[AffectedProduct] = []
    seen: set[str] = set()
    for cpe_elem in item.findall("sec:cpe", _NS):
        cpe_str = cpe_elem.get("name", "") or cpe_elem.get("value", "")
        product_name = cpe_elem.get("product", "") or (cpe_elem.text or "").strip()
        vendor_name = cpe_elem.get("vendor", "")
        version = cpe_elem.get("version", "")

        key = cpe_str or product_name
        if not key or key in seen:
            continue
        seen.add(key)

        products.append(
            AffectedProduct(
                vendor=vendor_name,
                product=product_name,
                versions=version,
                cpe=cpe_str,
            )
        )
    return products


def _text(parent: ET.Element, path: str, ns: dict[str, str]) -> str:
    """XML要素からテキストを取得するヘルパー。"""
    elem = parent.find(path, ns)
    if elem is not None and elem.text:
        return elem.text.strip()
    return ""
