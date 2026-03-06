"""Pub/Sub パブリッシャー。

新規脆弱性エントリを Pub/Sub トピックに publish し、
vuln_intake_worker がサブスクライブして処理する。
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from google.cloud import pubsub_v1

from shared.vuln_schema import VulnEntry

logger = logging.getLogger(__name__)

_publisher_client: pubsub_v1.PublisherClient | None = None


def _get_topic_path() -> str:
    """Pub/Sub トピックパスを取得する。"""
    topic_name = (
        os.environ.get("VULN_FEEDS_PUBSUB_TOPIC")
        or "vuln-agent-new-vulnerabilities"
    ).strip()
    project_id = (
        os.environ.get("GCP_PROJECT_ID")
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
        or ""
    ).strip()
    if not project_id:
        raise RuntimeError("GCP_PROJECT_ID is not set")
    return f"projects/{project_id}/topics/{topic_name}"


def _get_client() -> pubsub_v1.PublisherClient:
    global _publisher_client
    if _publisher_client is None:
        _publisher_client = pubsub_v1.PublisherClient()
    return _publisher_client


def publish_vuln_entry(entry: VulnEntry) -> str | None:
    """VulnEntry を Pub/Sub に publish する。

    Returns:
        publish された message_id。失敗時は None。
    """
    try:
        client = _get_client()
        topic_path = _get_topic_path()

        data = entry.to_json().encode("utf-8")
        attributes = {
            "vuln_id": entry.normalize_id(),
            "source": entry.source,
            "severity": entry.severity,
        }

        future = client.publish(topic_path, data=data, **attributes)
        message_id = future.result(timeout=30)

        logger.info(
            "Published to Pub/Sub: vuln_id=%s, source=%s, message_id=%s",
            entry.vuln_id,
            entry.source,
            message_id,
        )
        return message_id

    except Exception as exc:
        logger.error("Pub/Sub publish failed for %s: %s", entry.vuln_id, exc)
        return None


def publish_batch(entries: list[VulnEntry]) -> dict[str, Any]:
    """複数の VulnEntry を一括 publish する。

    Returns:
        {"published": int, "failed": int, "message_ids": list[str]}
    """
    published = 0
    failed = 0
    message_ids: list[str] = []

    for entry in entries:
        msg_id = publish_vuln_entry(entry)
        if msg_id:
            published += 1
            message_ids.append(msg_id)
        else:
            failed += 1

    return {
        "published": published,
        "failed": failed,
        "message_ids": message_ids,
    }
