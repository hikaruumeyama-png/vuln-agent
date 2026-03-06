"""Playwright + Gemini Flash スクレイピング & AI 抽出エンジン。"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

logger = logging.getLogger(__name__)

# Gemini モデル設定
_MODEL_ID = os.environ.get("SCRAPER_MODEL_ID", "gemini-2.5-flash")
_PROJECT_ID = os.environ.get("GCP_PROJECT_ID", os.environ.get("GOOGLE_CLOUD_PROJECT", ""))
_REGION = os.environ.get("GCP_REGION", "asia-northeast1")

# デフォルト抽出プロンプト
_DEFAULT_EXTRACTION_PROMPT = """以下のウェブページのテキストから、セキュリティ脆弱性に関する情報を抽出してください。

各脆弱性について以下の情報を JSON 配列で返してください:
- vuln_id: CVE-ID またはアドバイザリID (例: CVE-2024-1234)
- title: 脆弱性のタイトル
- description: 説明
- severity: 深刻度 (Critical/High/Medium/Low)
- affected_product: 影響を受ける製品名
- affected_versions: 影響を受けるバージョン
- fixed_versions: 修正バージョン (あれば)
- published_date: 公開日 (あれば)
- source_url: 元のURL

情報がない場合は空文字列にしてください。
JSON 配列のみを返してください。マークダウンや説明文は不要です。

ウェブページテキスト:
"""


async def scrape_and_extract(
    url: str,
    source_id: str,
    extraction_prompt: str = "",
) -> dict[str, Any]:
    """URL をスクレイピングし、Gemini で脆弱性情報を抽出する。

    Args:
        url: スクレイピング対象 URL
        source_id: ソース識別子 (ログ用)
        extraction_prompt: カスタム抽出プロンプト (空ならデフォルト使用)

    Returns:
        {"vulnerabilities": [...], "raw_text_length": int}
    """
    # 1. Playwright でページ取得
    raw_text = await _fetch_page_text(url)
    logger.info("Scraped %s: %d chars", url, len(raw_text))

    if not raw_text.strip():
        return {"vulnerabilities": [], "raw_text_length": 0}

    # テキストが長すぎる場合は切り詰め (Gemini のトークン制限)
    max_chars = 100_000
    if len(raw_text) > max_chars:
        raw_text = raw_text[:max_chars]
        logger.warning("Truncated text to %d chars for %s", max_chars, url)

    # 2. Gemini Flash で構造化抽出
    prompt = extraction_prompt or _DEFAULT_EXTRACTION_PROMPT
    vulnerabilities = await _extract_with_gemini(prompt, raw_text, source_id)

    return {
        "vulnerabilities": vulnerabilities,
        "raw_text_length": len(raw_text),
    }


async def _fetch_page_text(url: str) -> str:
    """Playwright でページを取得し、テキストを返す。"""
    from playwright.async_api import async_playwright

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                locale="ja-JP",
            )
            page = await context.new_page()

            await page.goto(url, wait_until="networkidle", timeout=30000)

            # JavaScript 実行後のテキスト取得
            text = await page.inner_text("body")
            return text
        finally:
            await browser.close()


async def _extract_with_gemini(
    prompt: str, page_text: str, source_id: str
) -> list[dict[str, Any]]:
    """Gemini Flash で脆弱性情報を抽出する。"""
    try:
        import vertexai
        from vertexai.generative_models import GenerativeModel

        if _PROJECT_ID:
            vertexai.init(project=_PROJECT_ID, location=_REGION)

        model = GenerativeModel(_MODEL_ID)
        full_prompt = f"{prompt}\n{page_text}"

        response = model.generate_content(
            full_prompt,
            generation_config={
                "temperature": 0.1,
                "max_output_tokens": 8192,
            },
        )

        response_text = response.text.strip()
        return _parse_json_response(response_text)

    except Exception as exc:
        logger.error("Gemini extraction failed for %s: %s", source_id, exc)
        return []


def _parse_json_response(text: str) -> list[dict[str, Any]]:
    """Gemini の応答テキストから JSON 配列を抽出する。"""
    # マークダウンコードブロックを除去
    text = re.sub(r"```json\s*", "", text)
    text = re.sub(r"```\s*", "", text)
    text = text.strip()

    try:
        data = json.loads(text)
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "vulnerabilities" in data:
            return data["vulnerabilities"]
        return [data]
    except json.JSONDecodeError:
        # 配列部分だけ抽出
        match = re.search(r"\[.*\]", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass
        logger.warning("Failed to parse Gemini response as JSON")
        return []
