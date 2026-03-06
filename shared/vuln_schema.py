"""脆弱性フィード共通スキーマ。

vuln_feeds (ポーラー) と vuln_intake (ワーカー) の両方で使用する
正規化された脆弱性エントリの定義。
"""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timezone
from typing import Any


@dataclasses.dataclass
class AffectedProduct:
    """影響を受ける製品情報"""

    vendor: str = ""
    product: str = ""
    versions: str = ""  # 影響バージョン範囲 ("< 9.16.4" 等)
    cpe: str = ""  # CPE 2.3 形式 (あれば)
    purl: str = ""  # Package URL (あれば)

    def to_dict(self) -> dict[str, str]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AffectedProduct:
        return cls(
            vendor=str(data.get("vendor") or ""),
            product=str(data.get("product") or ""),
            versions=str(data.get("versions") or ""),
            cpe=str(data.get("cpe") or ""),
            purl=str(data.get("purl") or ""),
        )


@dataclasses.dataclass
class VulnEntry:
    """全ソースから正規化された脆弱性エントリ"""

    # --- 識別 ---
    vuln_id: str  # 主キー: CVE-2024-1234 / GHSA-xxxx / JVNDB-2024-xxxx
    aliases: list[str] = dataclasses.field(default_factory=list)

    # --- メタデータ ---
    title: str = ""
    description: str = ""
    published: str = ""  # ISO8601
    last_modified: str = ""  # ISO8601
    source: str = ""  # "cisa_kev" | "nvd" | "jvn" | "osv" | ...
    source_url: str = ""  # 元情報のURL

    # --- スコアリング ---
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: str = "低"  # "緊急" | "高" | "中" | "低"

    # --- 悪用情報 ---
    exploit_confirmed: bool = False  # KEVに掲載 or 明示的な悪用報告
    exploit_code_public: bool = False  # PoCコード公開済み
    kev_due_date: str | None = None  # CISA KEVの対応期限 (あれば)

    # --- 影響製品 ---
    affected_products: list[AffectedProduct] = dataclasses.field(
        default_factory=list
    )

    # --- ベンダー固有 ---
    vendor_advisory_id: str | None = None
    vendor_severity: str | None = None
    vendor_fixed_versions: list[str] = dataclasses.field(default_factory=list)

    # ------------------------------------------------------------------
    # ユーティリティ
    # ------------------------------------------------------------------

    def normalize_id(self) -> str:
        """vuln_id を正規化 (大文字、前後空白除去)"""
        return (self.vuln_id or "").strip().upper()

    def all_ids(self) -> set[str]:
        """vuln_id + aliases の正規化済みセット"""
        ids = {self.normalize_id()}
        for alias in self.aliases:
            normalized = (alias or "").strip().upper()
            if normalized:
                ids.add(normalized)
        ids.discard("")
        return ids

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["affected_products"] = [p.to_dict() for p in self.affected_products]
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, default=str)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VulnEntry:
        products_raw = data.get("affected_products") or []
        products = [
            AffectedProduct.from_dict(p) if isinstance(p, dict) else p
            for p in products_raw
        ]
        return cls(
            vuln_id=str(data.get("vuln_id") or ""),
            aliases=list(data.get("aliases") or []),
            title=str(data.get("title") or ""),
            description=str(data.get("description") or ""),
            published=str(data.get("published") or ""),
            last_modified=str(data.get("last_modified") or ""),
            source=str(data.get("source") or ""),
            source_url=str(data.get("source_url") or ""),
            cvss_score=data.get("cvss_score"),
            cvss_vector=data.get("cvss_vector"),
            severity=str(data.get("severity") or "低"),
            exploit_confirmed=bool(data.get("exploit_confirmed")),
            exploit_code_public=bool(data.get("exploit_code_public")),
            kev_due_date=data.get("kev_due_date"),
            affected_products=products,
            vendor_advisory_id=data.get("vendor_advisory_id"),
            vendor_severity=data.get("vendor_severity"),
            vendor_fixed_versions=list(data.get("vendor_fixed_versions") or []),
        )

    @classmethod
    def from_json(cls, json_str: str) -> VulnEntry:
        return cls.from_dict(json.loads(json_str))


def cvss_to_severity(cvss_score: float | None) -> str:
    """CVSSスコアから severity 文字列に変換する。"""
    if cvss_score is None:
        return "低"
    try:
        score = float(cvss_score)
    except (TypeError, ValueError):
        return "低"
    if score >= 9.0:
        return "緊急"
    if score >= 7.0:
        return "高"
    if score >= 4.0:
        return "中"
    return "低"


def utcnow_iso() -> str:
    """現在時刻を ISO8601 UTC 文字列で返す。"""
    return datetime.now(timezone.utc).isoformat()
