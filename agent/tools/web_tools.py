"""
Web Tools - 外部情報の参照と要約

ネット検索とURL本文取得を提供し、回答の根拠性を上げるための補助ツール。
"""

from __future__ import annotations

import html
import ipaddress
import json
import re
import socket
from html.parser import HTMLParser
from typing import Any
from urllib import parse, request


_FORBIDDEN_HOSTS = {"localhost", "127.0.0.1", "::1"}


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._texts: list[str] = []
        self._in_script = False
        self._in_style = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        _ = attrs
        if tag.lower() == "script":
            self._in_script = True
        if tag.lower() == "style":
            self._in_style = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script":
            self._in_script = False
        if tag.lower() == "style":
            self._in_style = False

    def handle_data(self, data: str) -> None:
        if self._in_script or self._in_style:
            return
        text = (data or "").strip()
        if text:
            self._texts.append(text)

    def text(self) -> str:
        return " ".join(self._texts)


def web_search(query: str, max_results: int = 5) -> dict[str, Any]:
    """
    DuckDuckGo Instant Answer API を使って簡易 Web 検索結果を返す。
    """
    q = (query or "").strip()
    if not q:
        return {"status": "error", "message": "query は必須です。"}

    limit = _normalize_limit(max_results, default=5, max_value=10)
    params = parse.urlencode(
        {
            "q": q,
            "format": "json",
            "no_html": "1",
            "no_redirect": "1",
            "skip_disambig": "1",
        }
    )
    endpoint = f"https://api.duckduckgo.com/?{params}"

    try:
        payload = _http_get_json(endpoint)
    except Exception as exc:
        return {"status": "error", "message": f"web search failed: {exc}"}

    results: list[dict[str, str]] = []
    seen_urls: set[str] = set()

    abstract_text = (payload.get("AbstractText") or "").strip()
    abstract_url = (payload.get("AbstractURL") or "").strip()
    heading = (payload.get("Heading") or "").strip() or "Overview"
    if abstract_text and abstract_url:
        _push_result(results, seen_urls, heading, abstract_url, abstract_text)

    for item in _collect_related_topics(payload.get("RelatedTopics") or []):
        title = (item.get("Text") or "").strip()
        url = (item.get("FirstURL") or "").strip()
        if title and url:
            _push_result(results, seen_urls, title, url, title)
        if len(results) >= limit:
            break

    return {
        "status": "success",
        "query": q,
        "count": min(len(results), limit),
        "results": results[:limit],
    }


def fetch_web_content(url: str, max_chars: int = 4000) -> dict[str, Any]:
    """
    公開URLの本文テキストを取得し、短い要約用スニペットを返す。
    """
    target = (url or "").strip()
    if not target:
        return {"status": "error", "message": "url は必須です。"}
    if not _is_safe_public_url(target):
        return {
            "status": "error",
            "message": "安全でないURLのため取得できません（http/https の公開URLのみ対応）。",
        }

    limit = _normalize_limit(max_chars, default=4000, max_value=20000)
    try:
        raw_text, content_type = _http_get_text(target)
    except Exception as exc:
        return {"status": "error", "message": f"url fetch failed: {exc}"}

    content = raw_text
    if "html" in content_type:
        content = _extract_text_from_html(raw_text)
    content = _clean_text(content)

    truncated = len(content) > limit
    if truncated:
        content = content[:limit].rstrip() + " ..."

    return {
        "status": "success",
        "url": target,
        "content_type": content_type,
        "content_length": len(content),
        "truncated": truncated,
        "content": content,
    }


def _push_result(
    results: list[dict[str, str]],
    seen_urls: set[str],
    title: str,
    url: str,
    snippet: str,
) -> None:
    if url in seen_urls:
        return
    seen_urls.add(url)
    results.append({"title": title, "url": url, "snippet": snippet})


def _collect_related_topics(items: list[Any]) -> list[dict[str, str]]:
    flat: list[dict[str, str]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if "FirstURL" in item or "Text" in item:
            flat.append(item)
            continue
        nested = item.get("Topics")
        if isinstance(nested, list):
            flat.extend(_collect_related_topics(nested))
    return flat


def _http_get_json(url: str) -> dict[str, Any]:
    req = request.Request(
        url,
        headers={"User-Agent": "vuln-agent/1.0 (+https://github.com/hikaruumeyama-png/vuln-agent)"},
    )
    with request.urlopen(req, timeout=15) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    return json.loads(body)


def _http_get_text(url: str) -> tuple[str, str]:
    req = request.Request(
        url,
        headers={"User-Agent": "vuln-agent/1.0 (+https://github.com/hikaruumeyama-png/vuln-agent)"},
    )
    with request.urlopen(req, timeout=15) as resp:
        content_type = (resp.headers.get("Content-Type") or "").lower()
        body = resp.read().decode("utf-8", errors="replace")
    return body, content_type


def _extract_text_from_html(raw_html: str) -> str:
    parser = _TextExtractor()
    parser.feed(raw_html)
    return html.unescape(parser.text())


def _clean_text(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "")).strip()


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


def _is_safe_public_url(url: str) -> bool:
    try:
        parsed = parse.urlparse(url)
    except Exception:
        return False
    if parsed.scheme not in {"http", "https"}:
        return False
    hostname = (parsed.hostname or "").strip().lower()
    if not hostname or hostname in _FORBIDDEN_HOSTS:
        return False
    if _is_private_or_loopback_host(hostname):
        return False
    return True


def _is_private_or_loopback_host(hostname: str) -> bool:
    try:
        addr = ipaddress.ip_address(hostname)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(hostname, None)
    except Exception:
        return False

    for info in infos:
        ip_str = info[4][0]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return True
    return False
