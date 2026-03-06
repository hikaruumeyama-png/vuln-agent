"""Cisco PSIRT (CSAF / openVuln API) アダプター。

ソース: https://sec.cloudapps.cisco.com/security/center/publicationListing.x
API: Cisco openVuln API v3 — OAuth2 クライアント認証
差分取得: lastPublished / firstPublished パラメータでフィルタ
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any
from urllib import request

from shared.vuln_schema import AffectedProduct, VulnEntry, cvss_to_severity

from .base import BaseSourceAdapter, fetch_with_retry, get_secret_value

logger = logging.getLogger(__name__)

_CISCO_API_BASE = "https://apix.cisco.com/security/advisories/v2"
_CISCO_TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"


class CiscoCsafAdapter(BaseSourceAdapter):
    """Cisco openVuln API アダプター。"""

    source_id = "cisco_csaf"
    default_poll_interval_minutes = 30

    def __init__(self) -> None:
        self._client_id = get_secret_value(
            ["CISCO_CLIENT_ID"], secret_name="vuln-agent-cisco-client-id"
        )
        self._client_secret = get_secret_value(
            ["CISCO_CLIENT_SECRET"], secret_name="vuln-agent-cisco-client-secret"
        )
        self._access_token: str = ""

    def fetch_recent(self, since: datetime) -> list[VulnEntry]:
        """Cisco openVuln API から since 以降のアドバイザリを取得する。"""
        if not self._client_id or not self._client_secret:
            logger.warning("Cisco API credentials not configured, skipping")
            return []

        try:
            self._authenticate()
        except Exception as exc:
            logger.error("Cisco OAuth2 authentication failed: %s", exc)
            return []

        # lastPublished パラメータで差分取得
        date_str = since.strftime("%Y-%m-%dT%H:%M:%S")
        url = f"{_CISCO_API_BASE}/latest/{_days_since(since)}"

        try:
            data = self._api_get(url)
        except Exception as exc:
            logger.error("Cisco API fetch failed: %s", exc)
            return []

        advisories = data.get("advisories") or []
        entries: list[VulnEntry] = []
        for adv in advisories:
            entry = _normalize_cisco_advisory(adv)
            if entry:
                entries.append(entry)

        logger.info("Cisco: %d advisories fetched", len(entries))
        return entries

    def _authenticate(self) -> None:
        """OAuth2 クライアントクレデンシャルでアクセストークンを取得する。"""
        import base64

        creds = base64.b64encode(
            f"{self._client_id}:{self._client_secret}".encode()
        ).decode()

        req = request.Request(
            _CISCO_TOKEN_URL,
            data=b"grant_type=client_credentials",
            headers={
                "Authorization": f"Basic {creds}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        resp_data = fetch_with_retry(req, timeout=15)
        token_resp = json.loads(resp_data.decode("utf-8"))
        self._access_token = token_resp.get("access_token", "")
        if not self._access_token:
            raise RuntimeError("Empty access_token from Cisco OAuth2")

    def _api_get(self, url: str) -> Any:
        """認証済み API GET リクエスト。"""
        req = request.Request(
            url,
            headers={
                "Authorization": f"Bearer {self._access_token}",
                "Accept": "application/json",
            },
        )
        data = fetch_with_retry(req, timeout=30)
        return json.loads(data.decode("utf-8", errors="replace"))


def _days_since(since: datetime) -> int:
    """since から現在までの日数を算出する (最小1、最大60)。"""
    now = datetime.now(timezone.utc)
    delta = (now - since).days
    return max(1, min(delta, 60))


def _normalize_cisco_advisory(adv: dict[str, Any]) -> VulnEntry | None:
    """Cisco openVuln レスポンスを VulnEntry に正規化する。"""
    advisory_id = (adv.get("advisoryId") or "").strip()
    if not advisory_id:
        return None

    cve_list = adv.get("cves") or []
    cve_ids = [c.strip().upper() for c in cve_list if c.strip()]

    # 主キー: CVE があればそちらを使用
    vuln_id = advisory_id
    aliases: list[str] = []
    if cve_ids:
        vuln_id = cve_ids[0]
        aliases = [advisory_id] + cve_ids[1:]
    else:
        aliases = []

    title = (adv.get("advisoryTitle") or "").strip()
    summary = (adv.get("summary") or "").strip()
    published = (adv.get("firstPublished") or "").strip()
    last_updated = (adv.get("lastUpdated") or "").strip()
    sir = (adv.get("sir") or "").strip()  # Security Impact Rating
    advisory_url = (adv.get("publicationUrl") or "").strip()

    # CVSS スコア抽出
    cvss_score = _extract_cisco_cvss(adv)
    severity = cvss_to_severity(cvss_score)

    # 影響製品
    products = _extract_cisco_products(adv)

    return VulnEntry(
        vuln_id=vuln_id,
        aliases=aliases,
        title=title or advisory_id,
        description=summary,
        published=published,
        last_modified=last_updated or published,
        source="cisco_csaf",
        source_url=advisory_url or f"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/{advisory_id}",
        cvss_score=cvss_score,
        severity=severity,
        affected_products=products,
        vendor_advisory_id=advisory_id,
        vendor_severity=sir,
    )


def _extract_cisco_cvss(adv: dict[str, Any]) -> float | None:
    """Cisco アドバイザリから CVSS スコアを抽出する。"""
    # cvssBaseScore フィールド
    score = adv.get("cvssBaseScore")
    if score is not None:
        try:
            return float(score)
        except (TypeError, ValueError):
            pass

    # CVSS 情報がネストされている場合
    for key in ("cvss", "cvssScore"):
        val = adv.get(key)
        if val is not None:
            try:
                return float(val)
            except (TypeError, ValueError):
                pass
    return None


def _extract_cisco_products(adv: dict[str, Any]) -> list[AffectedProduct]:
    """Cisco アドバイザリから影響製品を抽出する。"""
    products: list[AffectedProduct] = []
    seen: set[str] = set()

    # productNames フィールド
    product_names = adv.get("productNames") or []
    for name in product_names:
        name = (name or "").strip()
        if name and name not in seen:
            seen.add(name)
            products.append(
                AffectedProduct(
                    vendor="Cisco",
                    product=name,
                )
            )

    # platforms フィールド (バックアップ)
    if not products:
        platforms = adv.get("platforms") or []
        for p in platforms:
            p = (p or "").strip()
            if p and p not in seen:
                seen.add(p)
                products.append(
                    AffectedProduct(vendor="Cisco", product=p)
                )

    return products
