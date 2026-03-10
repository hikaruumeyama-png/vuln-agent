"""脆弱性フィードポーラー Cloud Function エントリーポイント。

Cloud Scheduler から定期的に呼び出され、各ソースから新規脆弱性を取得し、
重複排除の上 Pub/Sub に publish する。

リクエストボディ:
    {"sources": ["cisa_kev", "nvd", ...]}

環境変数:
    BQ_VULN_DEDUP_TABLE_ID      - 重複排除テーブル
    BQ_VULN_POLL_STATE_TABLE_ID - ポーリング状態テーブル
    VULN_FEEDS_PUBSUB_TOPIC     - Pub/Sub トピック名
    GCP_PROJECT_ID              - GCPプロジェクトID
    NVD_API_KEY                 - NVD APIキー (オプション)
"""

from __future__ import annotations

import json
import logging
import sys
import os
from datetime import datetime, timezone
from typing import Any

import functions_framework

# shared/ を import パスに追加
_ROOT_DIR = os.path.join(os.path.dirname(__file__), "..")
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, os.path.normpath(_ROOT_DIR))

# Cloud Function デプロイ時は vuln_feeds/ がルートになるため、
# パッケージ名付き / なし の両方を試行する
try:
    from vuln_feeds.adapters import get_adapter, ADAPTER_REGISTRY
    from vuln_feeds.dedup import DedupResult, check_and_register
    from vuln_feeds.poll_state import get_last_poll, update_poll_state
    from vuln_feeds.publisher import publish_vuln_entry
except ImportError:
    from adapters import get_adapter, ADAPTER_REGISTRY
    from dedup import DedupResult, check_and_register
    from poll_state import get_last_poll, update_poll_state
    from publisher import publish_vuln_entry

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")


@functions_framework.http
def poll_vuln_feeds(request):
    """Cloud Function エントリーポイント。

    Cloud Scheduler からの HTTP POST を受け取り、指定ソースをポーリングする。
    """
    try:
        body = request.get_json(silent=True) or {}
    except Exception:
        body = {}

    # source_id (単一) または sources (複数) を受け付ける
    single = (body.get("source_id") or "").strip()
    sources = body.get("sources") or []
    if isinstance(sources, str):
        sources = [s.strip() for s in sources.split(",") if s.strip()]

    if single and single in ADAPTER_REGISTRY:
        sources = [single]
    elif not sources:
        sources = list(ADAPTER_REGISTRY.keys())

    results: dict[str, Any] = {}
    for source_id in sources:
        result = _poll_single_source(source_id)
        results[source_id] = result

    response = {"status": "ok", "results": results}
    return json.dumps(response, ensure_ascii=False, default=str), 200, {
        "Content-Type": "application/json"
    }


def _poll_single_source(source_id: str) -> dict[str, Any]:
    """単一ソースをポーリングして結果を返す。"""
    try:
        adapter = get_adapter(source_id)
    except ValueError as exc:
        logger.warning("Unknown source: %s", source_id)
        return {"status": "error", "message": str(exc)}

    # 前回ポーリング時刻を取得
    state = get_last_poll(source_id)
    last_poll_at = state.get("last_poll_at")
    if isinstance(last_poll_at, str):
        try:
            last_poll_at = datetime.fromisoformat(last_poll_at.replace("Z", "+00:00"))
        except ValueError:
            last_poll_at = None
    if last_poll_at is None:
        last_poll_at = datetime.now(timezone.utc)

    since = last_poll_at

    # アダプターで差分取得
    try:
        entries = adapter.fetch_recent(since)
    except Exception as exc:
        logger.error("Adapter %s fetch failed: %s", source_id, exc)
        update_poll_state(
            source_id,
            items_fetched=0,
            items_new=0,
            error_message=str(exc),
        )
        return {"status": "error", "message": str(exc), "fetched": 0, "new": 0}

    # 重複排除 + Pub/Sub publish
    new_count = 0
    skip_count = 0
    error_count = 0

    for entry in entries:
        result = check_and_register(entry)
        if result == DedupResult.NEW:
            publish_vuln_entry(entry)
            new_count += 1
        elif result == DedupResult.SKIP:
            skip_count += 1
        else:
            error_count += 1

    # ポーリング状態を更新
    update_poll_state(
        source_id,
        items_fetched=len(entries),
        items_new=new_count,
        error_message="",
    )

    logger.info(
        "Source %s: fetched=%d, new=%d, skip=%d, error=%d",
        source_id,
        len(entries),
        new_count,
        skip_count,
        error_count,
    )

    return {
        "status": "ok",
        "fetched": len(entries),
        "new": new_count,
        "skip": skip_count,
        "error": error_count,
    }
