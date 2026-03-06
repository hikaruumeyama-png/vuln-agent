"""スクレイピングサービス — Playwright + Gemini Flash による脆弱性情報抽出。

Cloud Run 上で動作する FastAPI サービス。
vuln_feeds アダプターから HTTP 経由で呼び出される。
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from scraper import scrape_and_extract

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="vuln-scraper", version="1.0.0")


class ScrapeRequest(BaseModel):
    """スクレイピングリクエスト。"""
    url: str
    source_id: str
    extraction_prompt: str = ""


class ScrapeResponse(BaseModel):
    """スクレイピングレスポンス。"""
    status: str
    source_id: str
    vulnerabilities: list[dict[str, Any]]
    raw_text_length: int


@app.post("/scrape", response_model=ScrapeResponse)
async def scrape_endpoint(req: ScrapeRequest) -> ScrapeResponse:
    """URL をスクレイピングし、Gemini Flash で脆弱性情報を抽出する。"""
    try:
        result = await scrape_and_extract(
            url=req.url,
            source_id=req.source_id,
            extraction_prompt=req.extraction_prompt,
        )
        return ScrapeResponse(
            status="ok",
            source_id=req.source_id,
            vulnerabilities=result["vulnerabilities"],
            raw_text_length=result["raw_text_length"],
        )
    except Exception as exc:
        logger.error("Scrape failed for %s: %s", req.url, exc)
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
