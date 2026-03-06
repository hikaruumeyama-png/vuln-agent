"""Fortinet PSIRT RSS アダプター。

ソース: https://www.fortiguard.com/psirt
API: RSS/Atom フィード — https://filestore.fortinet.com/fortiguard/rss/ir.xml
差分取得: pubDate / updated タイムスタンプでフィルタ
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

from shared.vuln_schema import AffectedProduct, VulnEntry, cvss_to_severity

from .base import BaseSourceAdapter, fetch_with_retry

logger = logging.getLogger(__name__)

_FORTINET_RSS_URL = "https://filestore.fortinet.com/fortiguard/rss/ir.xml"

# CVE-ID 抽出パターン
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# FG-IR ID パターン
_FG_IR_PATTERN = re.compile(r"FG-IR-\d{2}-\d{3,}", re.IGNORECASE)


class FortinetAdapter(BaseSourceAdapter):
    """Fortinet PSIRT RSS アダプター。"""

    source_id = "fortinet"
    default_poll_interval_minutes = 30

    def fetch_recent(self, since: datetime) -> list[VulnEntry]:
        """Fortinet PSIRT RSS から since 以降のアドバイザリを取得する。"""
        try:
            raw = fetch_with_retry(_FORTINET_RSS_URL, timeout=30)
            xml_text = raw.decode("utf-8", errors="replace")
        except Exception as exc:
            logger.error("Fortinet RSS fetch failed: %s", exc)
            return []

        return _parse_fortinet_rss(xml_text, since)


def _parse_fortinet_rss(xml_text: str, since: datetime) -> list[VulnEntry]:
    """Fortinet RSS フィードをパースして VulnEntry リストを返す。"""
    entries: list[VulnEntry] = []

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        logger.error("Fortinet RSS XML parse failed: %s", exc)
        return []

    # RSS 2.0: channel/item
    for item in root.findall(".//item"):
        entry = _parse_rss_item(item, since)
        if entry is not None:
            entries.append(entry)

    # Atom: entry
    if not entries:
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        for item in root.findall(".//atom:entry", ns):
            entry = _parse_atom_entry(item, ns, since)
            if entry is not None:
                entries.append(entry)

    logger.info("Fortinet: parsed %d entries", len(entries))
    return entries


def _parse_rss_item(item: ET.Element, since: datetime) -> VulnEntry | None:
    """RSS item 要素を VulnEntry に変換する。"""
    title = _elem_text(item, "title")
    link = _elem_text(item, "link")
    description = _elem_text(item, "description")
    pub_date_str = _elem_text(item, "pubDate")

    if not title:
        return None

    # pubDate でフィルタ
    pub_date = _parse_rfc2822(pub_date_str)
    if pub_date and pub_date < since:
        return None

    # CVE-ID / FG-IR-ID 抽出
    text_blob = f"{title} {description}"
    cve_ids = list(set(c.upper() for c in _CVE_PATTERN.findall(text_blob)))
    fg_ir_ids = list(set(f.upper() for f in _FG_IR_PATTERN.findall(text_blob)))

    # 主キー決定
    vuln_id = cve_ids[0] if cve_ids else (fg_ir_ids[0] if fg_ir_ids else title[:50])
    aliases: list[str] = []
    if cve_ids:
        aliases = cve_ids[1:] + fg_ir_ids
    elif fg_ir_ids:
        aliases = fg_ir_ids[1:]

    published_iso = pub_date.isoformat() if pub_date else ""

    return VulnEntry(
        vuln_id=vuln_id,
        aliases=aliases,
        title=title,
        description=description,
        published=published_iso,
        last_modified=published_iso,
        source="fortinet",
        source_url=link or "https://www.fortiguard.com/psirt",
        cvss_score=_extract_cvss_from_text(description),
        severity=cvss_to_severity(_extract_cvss_from_text(description)),
        affected_products=[
            AffectedProduct(vendor="Fortinet", product=_extract_product(title))
        ] if _extract_product(title) else [],
        vendor_advisory_id=fg_ir_ids[0] if fg_ir_ids else None,
    )


def _parse_atom_entry(
    item: ET.Element, ns: dict[str, str], since: datetime
) -> VulnEntry | None:
    """Atom entry 要素を VulnEntry に変換する。"""
    title = _elem_text_ns(item, "atom:title", ns)
    link_elem = item.find("atom:link", ns)
    link = link_elem.get("href", "") if link_elem is not None else ""
    summary = _elem_text_ns(item, "atom:summary", ns) or _elem_text_ns(item, "atom:content", ns)
    updated = _elem_text_ns(item, "atom:updated", ns)
    published = _elem_text_ns(item, "atom:published", ns)

    if not title:
        return None

    # 日付フィルタ
    pub_dt = _parse_iso_date(updated or published)
    if pub_dt and pub_dt < since:
        return None

    text_blob = f"{title} {summary}"
    cve_ids = list(set(c.upper() for c in _CVE_PATTERN.findall(text_blob)))
    fg_ir_ids = list(set(f.upper() for f in _FG_IR_PATTERN.findall(text_blob)))

    vuln_id = cve_ids[0] if cve_ids else (fg_ir_ids[0] if fg_ir_ids else title[:50])
    aliases: list[str] = []
    if cve_ids:
        aliases = cve_ids[1:] + fg_ir_ids
    elif fg_ir_ids:
        aliases = fg_ir_ids[1:]

    published_iso = (pub_dt.isoformat() if pub_dt else "")

    return VulnEntry(
        vuln_id=vuln_id,
        aliases=aliases,
        title=title,
        description=summary or "",
        published=published_iso,
        last_modified=published_iso,
        source="fortinet",
        source_url=link or "https://www.fortiguard.com/psirt",
        cvss_score=_extract_cvss_from_text(summary or ""),
        severity=cvss_to_severity(_extract_cvss_from_text(summary or "")),
        affected_products=[
            AffectedProduct(vendor="Fortinet", product=_extract_product(title))
        ] if _extract_product(title) else [],
        vendor_advisory_id=fg_ir_ids[0] if fg_ir_ids else None,
    )


def _extract_product(title: str) -> str:
    """タイトルから Fortinet 製品名を抽出する。"""
    # "FortiOS", "FortiProxy", "FortiManager" etc.
    match = re.search(r"(Forti\w+)", title, re.IGNORECASE)
    if match:
        return match.group(1)
    return ""


def _extract_cvss_from_text(text: str) -> float | None:
    """テキストから CVSS スコアを抽出する。"""
    # "CVSS Score: 9.8" や "CVSSv3: 7.5" パターン
    match = re.search(r"CVSS[v3]*[\s:]+(\d+\.?\d*)", text, re.IGNORECASE)
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            pass
    return None


def _elem_text(parent: ET.Element, tag: str) -> str:
    """XML要素からテキストを取得するヘルパー。"""
    elem = parent.find(tag)
    if elem is not None and elem.text:
        return elem.text.strip()
    return ""


def _elem_text_ns(parent: ET.Element, path: str, ns: dict[str, str]) -> str:
    """名前空間付き XML要素からテキストを取得するヘルパー。"""
    elem = parent.find(path, ns)
    if elem is not None and elem.text:
        return elem.text.strip()
    return ""


def _parse_rfc2822(date_str: str) -> datetime | None:
    """RFC2822 形式の日付をパースする。"""
    date_str = (date_str or "").strip()
    if not date_str:
        return None
    try:
        dt = parsedate_to_datetime(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _parse_iso_date(date_str: str) -> datetime | None:
    """ISO8601 日付をパースする。"""
    date_str = (date_str or "").strip()
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except ValueError:
        return None
