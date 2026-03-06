"""脆弱性取り込みワーカー Cloud Function エントリーポイント。

Pub/Sub トピック (vuln-agent-new-vulnerabilities) からメッセージを受信し、
SBOM照合 → 通知 → 履歴記録を行う。

環境変数:
    GCP_PROJECT_ID              - GCPプロジェクトID
    BQ_VULN_DEDUP_TABLE_ID      - 重複排除テーブル
    BQ_HISTORY_TABLE_ID         - 履歴テーブル
    DEFAULT_CHAT_SPACE_ID       - デフォルトChat スペースID
    SBOM_DATA_BACKEND           - SBOMバックエンド (sheets/bigquery/auto)
"""

from __future__ import annotations

import base64
import json
import logging
import os
import sys

import functions_framework

# Cloud Functions ではソースディレクトリがルートになるため両方試みる
_ROOT_DIR = os.path.join(os.path.dirname(__file__), "..")
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, os.path.normpath(_ROOT_DIR))

from shared.vuln_schema import VulnEntry

try:
    from vuln_intake.processor import process_vuln_entry
except ModuleNotFoundError:
    from processor import process_vuln_entry

logger = logging.getLogger(__name__)

# Cloud Functions Gen2: 既存ハンドラをクリアして stdout に強制出力
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(
    logging.Formatter('{"severity":"%(levelname)s","message":"%(name)s %(message)s"}')
)
logging.root.handlers.clear()
logging.root.addHandler(_handler)
logging.root.setLevel(logging.INFO)


@functions_framework.cloud_event
def handle_vuln_intake(cloud_event):
    """Pub/Sub push イベントハンドラー。

    CloudEvents 形式で VulnEntry JSON を受信して処理する。
    """
    try:
        data = cloud_event.data
        message = data.get("message") or {}
        encoded = message.get("data") or ""

        if not encoded:
            logger.warning("Empty Pub/Sub message data")
            return

        decoded = base64.b64decode(encoded).decode("utf-8")
        entry = VulnEntry.from_json(decoded)

        logger.info(
            "Received vuln entry: %s (source=%s, severity=%s)",
            entry.vuln_id,
            entry.source,
            entry.severity,
        )
        sys.stdout.flush()

        result = process_vuln_entry(entry)

        logger.info(
            "Processing result: vuln_id=%s, status=%s",
            entry.vuln_id,
            result.get("status"),
        )
        sys.stdout.flush()

    except Exception as exc:
        logger.exception("Failed to process vuln intake message: %s", exc)
        sys.stdout.flush()
