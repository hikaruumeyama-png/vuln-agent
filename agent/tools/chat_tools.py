"""
Google Chat Tools - 脆弱性アラート送信

Vertex AI Agent Engine版
"""

import os
import re
import time
import uuid
import logging
from typing import Any
from datetime import datetime, timedelta, date

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

try:
    from .secret_config import get_config_value
except ImportError:
    from secret_config import get_config_value

logger = logging.getLogger(__name__)

# 重大度設定
SEVERITY_EMOJI = {
    "緊急": "🔴",
    "高": "🟠",
    "中": "🟡",
    "低": "🟢",
}

SEVERITY_DEADLINES = {
    "緊急": timedelta(days=1),
    "高": timedelta(days=3),
    "中": timedelta(days=7),
    "低": timedelta(days=30),
}

PUBLIC_RESOURCE_ALIASES = (
    "csmail",
    "ns01",
    "fortigate",
    "cisco asa",
    "zeem",
)

_JP_HOLIDAY_FALLBACK = {
    date(2026, 1, 1),
    date(2026, 1, 12),
    date(2026, 2, 11),
    date(2026, 2, 23),
    date(2026, 3, 20),
    date(2026, 4, 29),
    date(2026, 5, 3),
    date(2026, 5, 4),
    date(2026, 5, 5),
    date(2026, 5, 6),
    date(2026, 7, 20),
    date(2026, 8, 11),
    date(2026, 9, 21),
    date(2026, 9, 22),
    date(2026, 9, 23),
    date(2026, 10, 12),
    date(2026, 11, 3),
    date(2026, 11, 23),
}

DEADLINE_RULES = (
    {
        "id": "R1",
        "when": {
            "cvss_gte": 9.0,
            "source_type": "public",
            "exploit_confirmed": True,
            "exploit_code_public": True,
        },
        "deadline_type": "business_days",
        "deadline_value": 5,
    },
    {
        "id": "R2",
        "when": {
            "cvss_gte": 8.0,
            "source_type": "public",
        },
        "deadline_type": "business_days",
        "deadline_value": 10,
    },
    {
        "id": "R3",
        "when": {
            "cvss_gte": 8.0,
            "source_type": "internal",
        },
        "deadline_type": "months",
        "deadline_value": 3,
    },
)

TICKET_MAJOR_CATEGORY = "017.脆弱性対応（情シス専用）"
TICKET_MINOR_CATEGORY_DEFAULT = "定例脆弱性対応"
TICKET_MINOR_CATEGORY_PENETRATION = "ペネトレ指摘対応"
TICKET_MINOR_CATEGORY_GOVERNANCE = "運用改善・統制対応"
TICKET_DETAIL_IT = "002.IT基盤チーム"
TICKET_DETAIL_PC = "001.PCチーム"

PENETRATION_KEYWORDS = (
    "ペネトレ",
    "ペネトレーション",
    "penetration",
)
GOVERNANCE_KEYWORDS = (
    "運用変更",
    "管理者運用",
    "手順見直し",
    "統制",
)
PC_TEAM_KEYWORDS = (
    "ios",
    "iphone",
    "ipad",
    "lanscope",
    "endpoint",
    "pc",
    "windows11",
    "クライアント",
)
IT_TEAM_KEYWORDS = (
    "almalinux",
    "amazon linux",
    "fortios",
    "fortigate",
    "cisco asa",
    "server",
    "サーバ",
    "network",
)

# スペースIDの正規表現パターン
_SPACE_ID_PATTERN = re.compile(r"^spaces/[A-Za-z0-9_-]+$")

_chat_service = None
_chat_service_timestamp = None
_SERVICE_CACHE_TTL = 1800  # 30分


_CHAT_SCOPES = ["https://www.googleapis.com/auth/chat.bot"]


def _load_sa_credentials_from_secret() -> service_account.Credentials | None:
    """Secret Manager からChat app用のSA鍵JSONを読み込んで認証情報を生成する。

    Agent Engine ランタイムではADCがGoogle管理SAになるため、
    Chat appとして構成されたSAの鍵を明示的にロードする必要がある。
    """
    import json as _json

    sa_json_str = get_config_value(
        ["CHAT_SA_CREDENTIALS_JSON"],
        secret_name="vuln-agent-chat-sa-key",
        default="",
    )
    if not sa_json_str:
        return None

    try:
        sa_info = _json.loads(sa_json_str)
        creds = service_account.Credentials.from_service_account_info(
            sa_info, scopes=_CHAT_SCOPES,
        )
        logger.info("Chat credentials loaded from Secret Manager (vuln-agent-chat-sa-key)")
        return creds
    except Exception as e:
        logger.warning(f"Secret Manager SA key parse failed: {e}")
        return None


def _get_chat_service():
    """Chat APIサービスを構築

    認証の優先順位:
      1. Secret Manager の SA鍵JSON (vuln-agent-chat-sa-key)
         → Agent Engine上でChat appのSAとして認証するために必要
      2. GOOGLE_APPLICATION_CREDENTIALS ファイル
         → ローカル開発環境向け
      3. Application Default Credentials (ADC)
         → フォールバック（Agent Engine管理SAになるため403の可能性あり）
    """
    global _chat_service, _chat_service_timestamp

    current_time = time.time()

    if _chat_service and _chat_service_timestamp:
        if current_time - _chat_service_timestamp < _SERVICE_CACHE_TTL:
            return _chat_service
        logger.info("Chat service cache expired, re-initializing")
        _chat_service = None

    credentials = None

    # 方式1: Secret Manager から Chat app 用の SA鍵を取得
    credentials = _load_sa_credentials_from_secret()

    # 方式2: ローカルファイルのサービスアカウント
    if not credentials:
        sa_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        if sa_path and os.path.exists(sa_path):
            try:
                credentials = service_account.Credentials.from_service_account_file(
                    sa_path, scopes=_CHAT_SCOPES,
                )
                logger.info("Chat credentials loaded from service account file")
            except Exception as e:
                logger.error(f"Service account file error: {e}")
                credentials = None

    # 方式3: ADC フォールバック（Agent Engineでは管理SAになるため注意）
    if not credentials:
        try:
            from google.auth import default
            credentials, _ = default(scopes=_CHAT_SCOPES)
            logger.warning(
                "Chat credentials loaded from ADC. "
                "Agent Engine上では管理SAが使われるため403になる可能性があります。"
                "vuln-agent-chat-sa-key シークレットの設定を推奨します。"
            )
        except Exception as e:
            logger.error(f"Default auth error: {e}")
            raise RuntimeError(
                "Chat認証に失敗しました。以下のいずれかを設定してください: "
                "(1) Secret Manager に vuln-agent-chat-sa-key (SA鍵JSON) "
                "(2) GOOGLE_APPLICATION_CREDENTIALS 環境変数"
            )

    _chat_service = build("chat", "v1", credentials=credentials)
    _chat_service_timestamp = current_time
    return _chat_service


def _format_http_error(error: HttpError, space_id: str | None = None) -> str:
    """HttpErrorを日本語のアクション可能なメッセージに変換する。"""
    status = error.resp.status if hasattr(error, "resp") else 0
    if status == 403:
        return (
            f"403 権限エラー: Chat appがスペース ({space_id}) へのアクセス権を持っていません。"
            " 以下を確認してください:"
            " (1) Google Cloud Console > Chat API > 構成 でアプリが設定済みか"
            " (2) 対象スペースにChat appがメンバーとして追加されているか"
            " (3) サービスアカウントがChat appに紐づいているか"
        )
    if status == 404:
        return f"404 エラー: スペース ({space_id}) が見つかりません。スペースIDを確認してください。"
    if status == 401:
        return "401 認証エラー: 認証情報が無効です。GOOGLE_APPLICATION_CREDENTIALS を確認してください。"
    return str(error)


def _resolve_space_id(space_id: str | None = None) -> str | None:
    """スペースIDを解決・正規化する。未設定時はNoneを返す。"""
    provided_space = str(space_id).strip() if space_id is not None else ""
    if not provided_space:
        space_id = get_config_value(
            ["DEFAULT_CHAT_SPACE_ID", "CHAT_SPACE_ID", "GOOGLE_CHAT_SPACE_ID"],
            secret_name="vuln-agent-chat-space-id",
            default="",
        )
    else:
        space_id = provided_space

    space_id = str(space_id).strip()
    if not space_id:
        logger.warning("Chat space ID が未設定です。DEFAULT_CHAT_SPACE_ID 環境変数を設定してください。")
        return None
    if not space_id.startswith("spaces/"):
        space_id = f"spaces/{space_id}"
    if not _SPACE_ID_PATTERN.match(space_id):
        logger.error(f"Chat space ID のフォーマットが不正です: {space_id}")
        return None
    return space_id


def send_vulnerability_alert(
    vulnerability_id: str,
    title: str,
    severity: str,
    affected_systems: list[str],
    cvss_score: float | None = None,
    description: str | None = None,
    remediation: str | None = None,
    owners: list[str] | None = None,
    space_id: str | None = None,
    record_history: bool = True,
    resource_type: str = "internal",
    exploit_confirmed: bool = False,
    exploit_code_public: bool = False,
    vulnerability_links: dict[str, str] | list[dict[str, str]] | None = None,
    source_name: str = "",
    include_ticket_sections: bool = True,
) -> dict[str, Any]:
    """
    脆弱性アラートをGoogle Chatスペースに送信します。

    Args:
        vulnerability_id: CVE番号等
        title: 脆弱性のタイトル
        severity: 重大度（緊急/高/中/低）
        affected_systems: 影響を受けるシステム名のリスト
        cvss_score: CVSSスコア（オプション）
        description: 脆弱性の説明（オプション）
        remediation: 推奨される対策（オプション）
        owners: 担当者メールアドレス（オプション）
        space_id: 送信先スペースID（省略時はデフォルト）
        record_history: 履歴を記録するか（デフォルト: True）
        resource_type: 公開リソース/内部リソース（default: internal）
        exploit_confirmed: 悪用実績ありか
        exploit_code_public: エクスプロイトコード公開済みか
        vulnerability_links: 脆弱性情報リンク（機器/アプリ名→URL）
        source_name: 公開リソース判定用の情報源名（例: Fortigate）
        include_ticket_sections: 起票用/判断理由セクションを本文に含めるか

    Returns:
        送信結果

    Example:
        >>> result = send_vulnerability_alert(
        ...     vulnerability_id="CVE-2024-1234",
        ...     title="Apache Log4j RCE",
        ...     severity="緊急",
        ...     affected_systems=["web-server-01"],
        ... )
        >>> print(result["status"])
        sent
    """
    try:
        service = _get_chat_service()
        incident_id = str(uuid.uuid4())

        resolved_space = _resolve_space_id(space_id)
        if resolved_space is None:
            return {"status": "error", "message": "Chat space ID が未設定または不正です。DEFAULT_CHAT_SPACE_ID を確認してください。"}

        # 対応期限（CVSS/リソース種別ルール優先）
        policy_decision = _evaluate_deadline_policy(
            severity=severity,
            cvss_score=cvss_score,
            resource_type=resource_type,
            exploit_confirmed=exploit_confirmed,
            exploit_code_public=exploit_code_public,
            source_name=source_name,
        )
        deadline = policy_decision["due_date"]

        # カードメッセージを構築
        card = _build_card(
            vulnerability_id, title, severity, cvss_score,
            affected_systems, description, remediation, deadline, owners
        )

        # テキスト本文（指定フォーマット）
        text = _build_structured_alert_text(
            affected_systems=affected_systems,
            vulnerability_id=vulnerability_id,
            title=title,
            cvss_score=cvss_score,
            vulnerability_links=vulnerability_links,
            deadline=deadline,
            remediation=remediation,
        )
        text = f"{text}\n\n【管理ID】\n{incident_id}"
        ticket_record = _build_ticket_record(
            title=title,
            affected_systems=affected_systems,
            description=description,
            remediation=remediation,
            source_name=source_name,
            body_text=text,
        )
        text = _compose_chat_alert_text(
            base_text=text,
            ticket_record=ticket_record,
            owners=owners,
            include_ticket_sections=include_ticket_sections,
        )

        # 送信
        message_body = {"text": text, "cardsV2": [card]}
        logger.info(f"Chat API 送信開始: space={resolved_space}, vuln={vulnerability_id}")

        response = service.spaces().messages().create(
            parent=resolved_space,
            body=message_body,
        ).execute()

        logger.info(f"Chat API 送信成功: space={resolved_space}, vuln={vulnerability_id}, message={response.get('name')}")

        result: dict[str, Any] = {
            "status": "sent",
            "message_id": response.get("name"),
            "space_id": resolved_space,
            "vulnerability_id": vulnerability_id,
            "policy_decision": policy_decision,
            "ticket_record": ticket_record,
            "incident_id": incident_id,
        }

        if record_history:
            try:
                from .history_tools import log_vulnerability_history

                history_result = log_vulnerability_history(
                    vulnerability_id=vulnerability_id,
                    title=title,
                    severity=severity,
                    affected_systems=affected_systems,
                    cvss_score=cvss_score,
                    description=description,
                    remediation=remediation,
                    owners=owners,
                    status="notified",
                    incident_id=incident_id,
                    source="chat_alert",
                    extra={
                        "message_id": response.get("name"),
                        "space_id": resolved_space,
                        "policy_decision": policy_decision,
                        "ticket_record": ticket_record,
                    },
                )
                result["history"] = history_result
            except Exception as history_error:
                logger.error(f"Failed to record history: {history_error}")
                result["history"] = {"status": "error", "message": str(history_error)}

        return result

    except HttpError as http_err:
        msg = _format_http_error(http_err, resolved_space if "resolved_space" in dir() else space_id)
        logger.error(f"Chat API HttpError: space={space_id}, vuln={vulnerability_id}, error={msg}")
        return {"status": "error", "message": msg, "vulnerability_id": vulnerability_id}
    except Exception as e:
        logger.error(f"Chat API 送信失敗: space={space_id}, vuln={vulnerability_id}, error={e}")
        return {"status": "error", "message": str(e), "vulnerability_id": vulnerability_id}


def send_simple_message(message: str, space_id: str | None = None) -> dict[str, Any]:
    """
    シンプルなテキストメッセージを送信します。

    Args:
        message: 送信するメッセージ
        space_id: 送信先スペースID（省略時はデフォルト）

    Returns:
        送信結果
    """
    try:
        service = _get_chat_service()

        resolved_space = _resolve_space_id(space_id)
        if resolved_space is None:
            return {"status": "error", "message": "Chat space ID が未設定または不正です。DEFAULT_CHAT_SPACE_ID を確認してください。"}

        response = service.spaces().messages().create(
            parent=resolved_space,
            body={"text": message},
        ).execute()

        logger.info(f"Chat メッセージ送信成功: space={resolved_space}")
        return {"status": "sent", "message_id": response.get("name")}

    except HttpError as http_err:
        msg = _format_http_error(http_err, resolved_space if "resolved_space" in dir() else space_id)
        logger.error(f"Chat API HttpError: space={space_id}, error={msg}")
        return {"status": "error", "message": msg}
    except Exception as e:
        logger.error(f"Chat メッセージ送信失敗: space={space_id}, error={e}")
        return {"status": "error", "message": str(e)}


def _build_card(
    vulnerability_id: str,
    title: str,
    severity: str,
    cvss_score: float | None,
    affected_systems: list[str],
    description: str | None,
    remediation: str | None,
    deadline: str,
    owners: list[str] | None,
) -> dict:
    """脆弱性カードを構築（Google Chat Cards v2 形式）"""

    severity_emoji = SEVERITY_EMOJI.get(severity, "⚪")

    # 概要セクション
    overview: list[dict[str, Any]] = [
        {"decoratedText": {"topLabel": "重大度", "text": f"{severity_emoji} {severity}"}},
    ]
    if cvss_score is not None:
        overview.append({"decoratedText": {"topLabel": "CVSSスコア", "text": str(cvss_score)}})
    overview.append({"decoratedText": {"topLabel": "対応期限", "text": deadline}})

    # 影響システム
    systems_text = "\n".join(f"• {s}" for s in affected_systems[:10])
    if len(affected_systems) > 10:
        systems_text += f"\n... 他 {len(affected_systems) - 10} システム"

    sections: list[dict[str, Any]] = [
        {"header": "概要", "widgets": overview},
        {"header": "影響を受けるシステム", "widgets": [{"textParagraph": {"text": systems_text or "該当なし"}}]},
    ]

    if description:
        sections.append({"header": "説明", "widgets": [{"textParagraph": {"text": description[:500]}}]})

    if remediation:
        sections.append({"header": "推奨対策", "widgets": [{"textParagraph": {"text": remediation[:500]}}]})

    if owners:
        sections.append({"header": "担当者", "widgets": [{"textParagraph": {"text": "\n".join(f"• {o}" for o in owners)}}]})

    # アクションボタン
    sections.append({
        "widgets": [{
            "buttonList": {
                "buttons": [{
                    "text": "NVDで詳細確認",
                    "onClick": {"openLink": {"url": f"https://nvd.nist.gov/vuln/detail/{vulnerability_id}"}},
                }],
            },
        }],
    })

    return {
        "cardId": f"vuln-{vulnerability_id}",
        "card": {
            "header": {
                "title": vulnerability_id,
                "subtitle": title[:100] if title else "",
            },
            "sections": sections,
        },
    }


def _calculate_deadline(
    severity: str,
    cvss_score: float | None = None,
    resource_type: str = "internal",
    exploit_confirmed: bool = False,
    exploit_code_public: bool = False,
    source_name: str = "",
    now: date | None = None,
) -> str:
    """
    対応期限を計算する。

    優先ルール:
    1) CVSS 9.0以上 + 公開リソース + 悪用実績あり + エクスプロイトコード公開: 5営業日以内
    2) CVSS 8.0以上 + 公開リソース: 10営業日以内
    3) CVSS 8.0以上 + 内部リソース: 3か月以内
    4) それ以外: 重大度マッピング
    """
    decision = _evaluate_deadline_policy(
        severity=severity,
        cvss_score=cvss_score,
        resource_type=resource_type,
        exploit_confirmed=exploit_confirmed,
        exploit_code_public=exploit_code_public,
        source_name=source_name,
        now=now,
    )
    return decision["due_date"]


def _evaluate_deadline_policy(
    severity: str,
    cvss_score: float | None = None,
    resource_type: str = "internal",
    exploit_confirmed: bool = False,
    exploit_code_public: bool = False,
    source_name: str = "",
    now: date | None = None,
) -> dict[str, Any]:
    """
    期限判定を構造化して返す。
    """
    base = now or date.today()
    normalized_score = _normalize_cvss_score(cvss_score)
    resource_class = _normalize_resource_type(resource_type=resource_type, source_name=source_name)

    if normalized_score is not None:
        for rule in DEADLINE_RULES:
            if _matches_deadline_rule(
                rule=rule,
                score=normalized_score,
                source_type=resource_class["type"],
                exploit_confirmed=exploit_confirmed,
                exploit_code_public=exploit_code_public,
            ):
                target = _compute_deadline_date(base, rule["deadline_type"], rule["deadline_value"])
                return {
                    "status": "decided",
                    "rule_id": rule["id"],
                    "due_date": f"{target.year}/{target.month}/{target.day}",
                    "decision_level": "確定",
                    "resource_classification": resource_class,
                    "missing_fields": [],
                }

    fallback_due_date = _build_fallback_due_date(base, severity)
    missing_fields = []
    if normalized_score is None:
        missing_fields.append("cvss_score")
    return {
        "status": "decided",
        "rule_id": "FALLBACK_SEVERITY",
        "due_date": fallback_due_date,
        "decision_level": "暫定",
        "resource_classification": resource_class,
        "missing_fields": missing_fields,
    }


def _normalize_cvss_score(cvss_score: float | None) -> float | None:
    if cvss_score is None:
        return None
    try:
        return float(cvss_score)
    except Exception:
        return None


def _normalize_resource_type(resource_type: str, source_name: str = "") -> dict[str, str]:
    normalized_resource = (resource_type or "").strip().lower()
    normalized_source = (source_name or "").strip().lower()
    internal_aliases = {"internal", "private", "inside", "内部", "内部リソース"}
    public_aliases = {"public", "external", "公開", "公開リソース"}

    if normalized_resource in internal_aliases:
        return {"type": "internal", "matched_by": "resource_type"}
    if normalized_resource in public_aliases:
        return {"type": "public", "matched_by": "resource_type"}

    if normalized_source:
        for alias in PUBLIC_RESOURCE_ALIASES:
            if alias in normalized_source:
                return {"type": "public", "matched_by": "source_name_allowlist"}

    return {"type": "internal", "matched_by": "default_conservative"}


def _matches_deadline_rule(
    rule: dict[str, Any],
    score: float,
    source_type: str,
    exploit_confirmed: bool,
    exploit_code_public: bool,
) -> bool:
    cond = rule["when"]
    if score < float(cond.get("cvss_gte", 0)):
        return False
    if source_type != cond.get("source_type"):
        return False
    if "exploit_confirmed" in cond and exploit_confirmed != cond["exploit_confirmed"]:
        return False
    if "exploit_code_public" in cond and exploit_code_public != cond["exploit_code_public"]:
        return False
    return True


def _compute_deadline_date(base: date, deadline_type: str, deadline_value: int) -> date:
    if deadline_type == "business_days":
        return _add_business_days(base, deadline_value)
    if deadline_type == "months":
        return _add_months(base, deadline_value)
    return base


def _build_fallback_due_date(base: date, severity: str) -> str:
    delta = SEVERITY_DEADLINES.get(severity, timedelta(days=7))
    fallback = datetime.combine(base, datetime.min.time()) + delta
    return fallback.strftime("%Y年%m月%d日")


def _add_business_days(start_date: date, business_days: int) -> date:
    current = start_date
    remaining = max(0, int(business_days))
    while remaining > 0:
        current += timedelta(days=1)
        if _is_business_day(current):
            remaining -= 1
    return current


def _is_business_day(check_date: date) -> bool:
    if check_date.weekday() >= 5:
        return False
    try:
        import jpholiday

        if jpholiday.is_holiday(check_date):
            return False
        return True
    except Exception:
        return check_date not in _JP_HOLIDAY_FALLBACK


def _add_months(start_date: date, months: int) -> date:
    month_index = start_date.month - 1 + max(0, int(months))
    year = start_date.year + month_index // 12
    month = month_index % 12 + 1
    # 月末調整
    day = min(start_date.day, _days_in_month(year, month))
    return date(year, month, day)


def _days_in_month(year: int, month: int) -> int:
    if month == 12:
        next_month = date(year + 1, 1, 1)
    else:
        next_month = date(year, month + 1, 1)
    return (next_month - timedelta(days=1)).day


def _normalize_vulnerability_links(
    vulnerability_links: dict[str, str] | list[dict[str, str]] | None,
) -> list[tuple[str, str]]:
    if not vulnerability_links:
        return []
    normalized: list[tuple[str, str]] = []
    if isinstance(vulnerability_links, dict):
        for key, value in vulnerability_links.items():
            name = str(key).strip()
            url = str(value).strip()
            if name and url:
                normalized.append((name, url))
        return normalized
    if isinstance(vulnerability_links, list):
        for item in vulnerability_links:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()
            url = str(item.get("url", "")).strip()
            if name and url:
                normalized.append((name, url))
    return normalized


def _build_structured_alert_text(
    affected_systems: list[str],
    vulnerability_id: str,
    title: str,
    cvss_score: float | None,
    vulnerability_links: dict[str, str] | list[dict[str, str]] | None,
    deadline: str,
    remediation: str | None,
) -> str:
    systems = [str(s).strip() for s in (affected_systems or []) if str(s).strip()]
    if not systems:
        systems = ["不明"]

    links = _normalize_vulnerability_links(vulnerability_links)
    if not links:
        links = [(title or vulnerability_id or "脆弱性情報", f"https://nvd.nist.gov/vuln/detail/{vulnerability_id}")]

    score_label = "不明"
    if cvss_score is not None:
        try:
            score = float(cvss_score)
            if score >= 9.0:
                score_label = "9以上"
            elif score >= 8.0:
                score_label = "8以上"
            else:
                score_label = str(score)
        except Exception:
            score_label = str(cvss_score)

    request_text = (
        remediation.strip()
        if isinstance(remediation, str) and remediation.strip()
        else (
            "上記脆弱性情報をご確認いただき、バージョンが低い場合は"
            "バージョンアップのご対応をお願いいたします。\n"
            "対応を実施した場合はサーバのホスト名をご教示ください。"
        )
    )

    sections: list[str] = []
    sections.append("【対象の機器/アプリ】\n" + "\n".join(systems))

    link_lines: list[str] = []
    for name, url in links:
        link_lines.append(name)
        link_lines.append(url)
        link_lines.append("")
    sections.append("【脆弱性情報】（リンク貼り付け）\n" + "\n".join(link_lines).strip())

    sections.append(f"【CVSSスコア】\n{score_label}")
    sections.append(f"【依頼内容】\n{request_text}")
    sections.append(f"【対応完了目標】\n{deadline}")
    return "\n\n".join(sections).strip()


def _compose_chat_alert_text(
    base_text: str,
    ticket_record: dict[str, Any] | None,
    owners: list[str] | None,
    include_ticket_sections: bool = True,
) -> str:
    text = (base_text or "").strip()
    if include_ticket_sections and ticket_record:
        copy_text = str(ticket_record.get("copy_paste_text", "")).strip()
        reasoning_text = str(ticket_record.get("reasoning_text", "")).strip()
        extra_sections = [section for section in (copy_text, reasoning_text) if section]
        if extra_sections:
            text = f"{text}\n\n" + "\n\n".join(extra_sections)
    if owners:
        mentions = [f"<{email}>" for email in owners]
        text = f"📢 {', '.join(mentions)} 対応をお願いします。\n\n{text}"
    return text


def _build_ticket_record(
    title: str,
    affected_systems: list[str],
    description: str | None,
    remediation: str | None,
    source_name: str = "",
    body_text: str = "",
) -> dict[str, Any]:
    """
    起票用の4項目（大分類/小分類/依頼概要/詳細）を高再現で返す。
    """
    normalized_title = (title or "").strip()
    corpus = _build_classification_corpus(
        title=normalized_title,
        affected_systems=affected_systems,
        description=description,
        remediation=remediation,
        source_name=source_name,
        body_text=body_text,
    )
    product = _detect_primary_product(normalized_title, affected_systems, source_name, corpus)
    minor_category = _detect_minor_category(normalized_title, corpus)
    detail, detail_scores = _detect_detail_team(product, corpus)
    summary = _build_request_summary(normalized_title, product, minor_category)
    anomalies = _detect_ticket_anomalies(corpus, body_text)
    confidence, needs_review = _estimate_ticket_confidence(
        minor_category=minor_category,
        detail=detail,
        product=product,
        detail_scores=detail_scores,
        anomalies=anomalies,
    )
    reasons = _build_ticket_reasons(
        minor_category=minor_category,
        detail=detail,
        product=product,
        title=normalized_title,
        corpus=corpus,
        confidence=confidence,
        needs_review=needs_review,
        detail_scores=detail_scores,
        anomalies=anomalies,
    )
    copy_paste_text = _build_ticket_copy_paste_text(
        major_category=TICKET_MAJOR_CATEGORY,
        minor_category=minor_category,
        request_summary=summary,
        detail=detail,
    )
    reasoning_text = _build_ticket_reasoning_text(reasons)

    return {
        "major_category": TICKET_MAJOR_CATEGORY,
        "minor_category": minor_category,
        "request_summary": summary,
        "detail": detail,
        "confidence": confidence,
        "needs_review": needs_review,
        "anomalies": anomalies,
        "reasons": reasons,
        "copy_paste_text": copy_paste_text,
        "reasoning_text": reasoning_text,
    }


def _build_classification_corpus(
    title: str,
    affected_systems: list[str],
    description: str | None,
    remediation: str | None,
    source_name: str,
    body_text: str,
) -> str:
    fields = [
        title,
        " ".join(str(s).strip() for s in (affected_systems or []) if str(s).strip()),
        description or "",
        remediation or "",
        source_name or "",
        body_text or "",
    ]
    return " ".join(fields).lower()


def _detect_primary_product(
    title: str,
    affected_systems: list[str],
    source_name: str,
    corpus: str,
) -> str:
    normalized_title = title.strip()
    if normalized_title.startswith("【ペネトレ"):
        return "ペネトレ"
    if "almalinux" in corpus:
        if "almalinux 9" in corpus or "almalinux9" in corpus:
            return "AlmaLinux 9"
        if "almalinux 8" in corpus or "almalinux8" in corpus:
            return "AlmaLinux 8"
        return "AlmaLinux"
    if "fortios" in corpus or "fortigate" in corpus:
        return "FortiOS"
    if "cisco asa" in corpus:
        return "Cisco ASA"
    if "amazon linux" in corpus:
        return "Amazon Linux"
    if "lanscope" in corpus:
        return "LANSCOPE"
    if "ios" in corpus or "iphone" in corpus or "ipad" in corpus:
        return "Apple iOS"
    if source_name:
        return source_name.strip()
    for system in affected_systems or []:
        if system and str(system).strip() != "不明":
            return str(system).strip()
    return "対象製品"


def _detect_minor_category(title: str, corpus: str) -> str:
    if any(keyword in title.lower() or keyword in corpus for keyword in PENETRATION_KEYWORDS):
        return TICKET_MINOR_CATEGORY_PENETRATION
    if any(keyword in corpus for keyword in GOVERNANCE_KEYWORDS):
        return TICKET_MINOR_CATEGORY_GOVERNANCE
    return TICKET_MINOR_CATEGORY_DEFAULT


def _detect_detail_team(product: str, corpus: str) -> tuple[str, dict[str, int]]:
    pc_score = 0
    it_score = 0
    for keyword in PC_TEAM_KEYWORDS:
        if keyword in corpus:
            pc_score += 1
    for keyword in IT_TEAM_KEYWORDS:
        if keyword in corpus:
            it_score += 1

    lowered_product = product.lower()
    if "ios" in lowered_product or "lanscope" in lowered_product:
        pc_score += 2
    if any(k in lowered_product for k in ("almalinux", "fortios", "fortigate", "cisco asa", "amazon linux")):
        it_score += 2

    if pc_score > it_score:
        return TICKET_DETAIL_PC, {"pc": pc_score, "it": it_score}
    return TICKET_DETAIL_IT, {"pc": pc_score, "it": it_score}


def _build_request_summary(title: str, product: str, minor_category: str) -> str:
    if title:
        if title.startswith("【") or "対応願い" in title or "アップグレード" in title:
            return title
    if minor_category == TICKET_MINOR_CATEGORY_PENETRATION:
        return f"【ペネトレ対応】{product} 関連の対応依頼"
    return f"{product} の脆弱性確認及び該当バージョンの対応願い"


def _estimate_ticket_confidence(
    minor_category: str,
    detail: str,
    product: str,
    detail_scores: dict[str, int],
    anomalies: list[str],
) -> tuple[str, bool]:
    _ = detail
    base = "medium"
    if minor_category != TICKET_MINOR_CATEGORY_DEFAULT:
        base = "high"
    elif product != "対象製品":
        base = "high"

    score_gap = abs(int(detail_scores.get("pc", 0)) - int(detail_scores.get("it", 0)))
    if score_gap == 0:
        base = "medium"
    if anomalies:
        base = "medium"

    needs_review = base != "high" or bool(anomalies)
    return base, needs_review


def _detect_ticket_anomalies(corpus: str, body_text: str) -> list[str]:
    anomalies: list[str] = []
    lowered_body = (body_text or "").lower()
    if "添付ファイル参照" in lowered_body or "添付ファイル参照" in corpus:
        anomalies.append("添付参照のみ")
    if lowered_body and "http://" not in lowered_body and "https://" not in lowered_body:
        anomalies.append("url不足")
    return anomalies


def _build_ticket_reasons(
    minor_category: str,
    detail: str,
    product: str,
    title: str,
    corpus: str,
    confidence: str,
    needs_review: bool,
    detail_scores: dict[str, int],
    anomalies: list[str],
) -> list[str]:
    reasons: list[str] = []
    reasons.append(f"製品判定: {product}")
    if minor_category == TICKET_MINOR_CATEGORY_PENETRATION:
        reasons.append("小分類判定: ペネトレ関連キーワードを検知")
    elif minor_category == TICKET_MINOR_CATEGORY_GOVERNANCE:
        reasons.append("小分類判定: 運用変更・統制関連キーワードを検知")
    else:
        reasons.append("小分類判定: 通常の脆弱性対応パターン")

    if detail == TICKET_DETAIL_PC:
        reasons.append(f"詳細判定: クライアント/PC系キーワードを優勢検知 (pc={detail_scores.get('pc', 0)}, it={detail_scores.get('it', 0)})")
    else:
        reasons.append(f"詳細判定: サーバ/基盤系キーワードを優勢検知 (pc={detail_scores.get('pc', 0)}, it={detail_scores.get('it', 0)})")

    if title:
        reasons.append("依頼概要判定: 入力タイトルを優先採用")
    else:
        reasons.append("依頼概要判定: テンプレートで自動生成")
    reasons.append(f"信頼度: {confidence}")
    reasons.append(f"要レビュー: {'yes' if needs_review else 'no'}")
    if anomalies:
        reasons.append("注意点: " + ", ".join(anomalies))
    _ = corpus
    return reasons


def _build_ticket_copy_paste_text(
    major_category: str,
    minor_category: str,
    request_summary: str,
    detail: str,
) -> str:
    return (
        "【起票用（コピペ）】\n"
        f"大分類: {major_category}\n"
        f"小分類: {minor_category}\n"
        f"依頼概要: {request_summary}\n"
        f"詳細: {detail}"
    )


def _build_ticket_reasoning_text(reasons: list[str]) -> str:
    lines = ["【判断理由】"]
    for reason in reasons:
        lines.append(f"- {reason}")
    return "\n".join(lines)


def check_chat_connection(space_id: str | None = None) -> dict[str, Any]:
    """
    Google Chat APIへの接続を確認します。

    Args:
        space_id: 確認するスペースID（省略時はデフォルト）

    Returns:
        接続状態とスペース情報
    """
    try:
        service = _get_chat_service()

        resolved_space = _resolve_space_id(space_id)
        if resolved_space is None:
            return {"status": "error", "message": "Chat space ID が未設定または不正です。DEFAULT_CHAT_SPACE_ID を確認してください。"}

        # スペース情報を取得
        space = service.spaces().get(name=resolved_space).execute()

        return {
            "status": "connected",
            "space_id": resolved_space,
            "space_name": space.get("displayName", ""),
            "space_type": space.get("spaceType", ""),
            "member_count": space.get("membershipCount", 0),
        }

    except HttpError as http_err:
        msg = _format_http_error(http_err, resolved_space if "resolved_space" in dir() else space_id)
        logger.error(f"Chat connection check HttpError: space={space_id}, error={msg}")
        return {"status": "error", "message": msg}
    except Exception as e:
        logger.error(f"Chat connection check failed: space={space_id}, error={e}")
        return {
            "status": "error",
            "message": str(e),
        }


def list_space_members(space_id: str | None = None) -> dict[str, Any]:
    """
    スペースのメンバー一覧を取得します。

    Args:
        space_id: スペースID（省略時はデフォルト）

    Returns:
        メンバー一覧
    """
    try:
        service = _get_chat_service()

        resolved_space = _resolve_space_id(space_id)
        if resolved_space is None:
            return {"status": "error", "message": "Chat space ID が未設定または不正です。DEFAULT_CHAT_SPACE_ID を確認してください。"}

        # メンバー一覧を取得
        response = service.spaces().members().list(parent=resolved_space).execute()
        members = response.get("memberships", [])

        member_list = []
        for m in members:
            member_info = m.get("member", {})
            if member_info.get("type") == "HUMAN":
                member_list.append({
                    "name": member_info.get("displayName", ""),
                    "email": member_info.get("email", ""),
                })

        return {
            "status": "success",
            "space_id": resolved_space,
            "members": member_list,
            "count": len(member_list),
        }

    except HttpError as http_err:
        msg = _format_http_error(http_err, resolved_space if "resolved_space" in dir() else space_id)
        logger.error(f"List members HttpError: space={space_id}, error={msg}")
        return {"status": "error", "message": msg}
    except Exception as e:
        logger.error(f"Failed to list members: space={space_id}, error={e}")
        return {"status": "error", "message": str(e)}
