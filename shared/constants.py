"""起票パイプライン共通定数。"""

from __future__ import annotations

import re

# 起票テンプレートのデフォルト依頼内容
DEFAULT_REMEDIATION_TEXT = (
    "上記脆弱性情報をご確認いただき、バージョンアップが低い場合は"
    "バージョンアップのご対応お願いいたします。\n"
    "対応を実施した場合はサーバのホスト名をご教示ください。"
)

# 起票テンプレートに含めてはいけないフレーズ
TICKET_FORBIDDEN_PHRASES = (
    "はい、承知いたしました",
    "ご依頼のメール内容は",
    "テンプレートを作成します",
)

# メッセージフォーマット分類
MSG_FORMAT_SIDFM = "sidfm"
MSG_FORMAT_EXPLOITED = "exploited"
MSG_FORMAT_UPDATE = "update"
MSG_FORMAT_UNKNOWN = "unknown"

# 製品名抽出用パターン
PRODUCT_EXTRACT_PATTERNS: list[tuple[str, str]] = [
    (r"google\s*chrome", "Google Chrome"),
    (r"\bfirefox\b", "Firefox"),
    (r"\bthunderbird\b", "Thunderbird"),
    (r"\bedge\b.*(?:chromium|ブラウザ)", "Microsoft Edge"),
    (r"\bmacos\b|\bmac\s*os\b", "MacOS"),
    (r"\bwindows\s*server", "Windows Server"),
    (r"\bwindows\s*1[01]\b", "Windows"),
    (r"\besxi\b|\bvmware\b|\bvsphere\b", "ESXi"),
    (r"\bpostfix\b", "Postfix"),
    (r"\bsql\s*server\b", "SQL Server"),
    (r"\bapache\b", "Apache"),
    (r"\bnginx\b", "nginx"),
    (r"\bopenssl\b", "openssl"),
]
