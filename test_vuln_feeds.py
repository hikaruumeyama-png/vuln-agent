"""マルチソース脆弱性フィード ユニットテスト。

shared/vuln_schema.py, vuln_feeds/adapters/, vuln_feeds/dedup.py のテスト。
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from unittest import mock

import pytest

# パスを追加
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from shared.vuln_schema import AffectedProduct, VulnEntry, cvss_to_severity


# ====================================================
# shared/vuln_schema.py テスト
# ====================================================


class TestCvssToSeverity:
    def test_critical(self):
        assert cvss_to_severity(9.0) == "緊急"
        assert cvss_to_severity(10.0) == "緊急"
        assert cvss_to_severity(9.8) == "緊急"

    def test_high(self):
        assert cvss_to_severity(7.0) == "高"
        assert cvss_to_severity(8.9) == "高"

    def test_medium(self):
        assert cvss_to_severity(4.0) == "中"
        assert cvss_to_severity(6.9) == "中"

    def test_low(self):
        assert cvss_to_severity(3.9) == "低"
        assert cvss_to_severity(0.0) == "低"

    def test_none(self):
        assert cvss_to_severity(None) == "低"

    def test_invalid(self):
        assert cvss_to_severity("abc") == "低"


class TestVulnEntry:
    def test_normalize_id(self):
        entry = VulnEntry(vuln_id="cve-2024-1234")
        assert entry.normalize_id() == "CVE-2024-1234"

    def test_normalize_id_whitespace(self):
        entry = VulnEntry(vuln_id="  CVE-2024-5678  ")
        assert entry.normalize_id() == "CVE-2024-5678"

    def test_all_ids(self):
        entry = VulnEntry(
            vuln_id="CVE-2024-1234",
            aliases=["GHSA-xxxx-yyyy", "JVNDB-2024-001234"],
        )
        ids = entry.all_ids()
        assert "CVE-2024-1234" in ids
        assert "GHSA-XXXX-YYYY" in ids
        assert "JVNDB-2024-001234" in ids
        assert len(ids) == 3

    def test_all_ids_dedup(self):
        entry = VulnEntry(
            vuln_id="CVE-2024-1234",
            aliases=["cve-2024-1234"],
        )
        ids = entry.all_ids()
        assert len(ids) == 1

    def test_all_ids_empty_alias_skipped(self):
        entry = VulnEntry(vuln_id="CVE-2024-1234", aliases=["", "  "])
        ids = entry.all_ids()
        assert len(ids) == 1

    def test_to_dict_and_from_dict(self):
        entry = VulnEntry(
            vuln_id="CVE-2024-9999",
            title="Test Vuln",
            source="nvd",
            cvss_score=7.5,
            severity="高",
            affected_products=[
                AffectedProduct(vendor="Apache", product="Log4j", versions="<2.17.0"),
            ],
        )
        d = entry.to_dict()
        restored = VulnEntry.from_dict(d)

        assert restored.vuln_id == "CVE-2024-9999"
        assert restored.title == "Test Vuln"
        assert restored.cvss_score == 7.5
        assert restored.severity == "高"
        assert len(restored.affected_products) == 1
        assert restored.affected_products[0].vendor == "Apache"

    def test_to_json_and_from_json(self):
        entry = VulnEntry(
            vuln_id="CVE-2024-0001",
            aliases=["GHSA-1234"],
            exploit_confirmed=True,
        )
        json_str = entry.to_json()
        restored = VulnEntry.from_json(json_str)

        assert restored.vuln_id == "CVE-2024-0001"
        assert restored.aliases == ["GHSA-1234"]
        assert restored.exploit_confirmed is True

    def test_from_dict_missing_fields(self):
        """不足フィールドがあってもエラーにならない"""
        entry = VulnEntry.from_dict({"vuln_id": "CVE-2024-0002"})
        assert entry.vuln_id == "CVE-2024-0002"
        assert entry.title == ""
        assert entry.cvss_score is None
        assert entry.affected_products == []


class TestAffectedProduct:
    def test_to_dict(self):
        p = AffectedProduct(vendor="Cisco", product="ASA", versions="<9.16.4")
        d = p.to_dict()
        assert d["vendor"] == "Cisco"
        assert d["product"] == "ASA"
        assert d["versions"] == "<9.16.4"

    def test_from_dict(self):
        p = AffectedProduct.from_dict({"vendor": "Fortinet", "product": "FortiOS"})
        assert p.vendor == "Fortinet"
        assert p.product == "FortiOS"
        assert p.purl == ""


# ====================================================
# CISA KEV アダプターテスト
# ====================================================


class TestCisaKevAdapter:
    """CISA KEV アダプターのテスト (HTTP モック使用)"""

    SAMPLE_CATALOG = {
        "title": "CISA Catalog",
        "catalogVersion": "2024.01.01",
        "dateReleased": "2024-01-01T00:00:00Z",
        "count": 2,
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-0001",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "Apache Log4j RCE",
                "dateAdded": "2024-06-15",
                "shortDescription": "Remote code execution in Apache Log4j",
                "requiredAction": "Apply updates per vendor instructions.",
                "dueDate": "2024-07-01",
                "knownRansomwareCampaignUse": "Known",
                "notes": "",
            },
            {
                "cveID": "CVE-2023-0001",
                "vendorProject": "Microsoft",
                "product": "Exchange",
                "vulnerabilityName": "Microsoft Exchange RCE",
                "dateAdded": "2023-01-01",
                "shortDescription": "Old vuln",
                "requiredAction": "Apply updates.",
                "dueDate": "2023-02-01",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": "",
            },
        ],
    }

    def test_fetch_recent_filters_by_date(self):
        from vuln_feeds.adapters.cisa_kev import CisaKevAdapter

        adapter = CisaKevAdapter()
        since = datetime(2024, 6, 1, tzinfo=timezone.utc)

        with mock.patch(
            "vuln_feeds.adapters.cisa_kev.http_get_json",
            return_value=self.SAMPLE_CATALOG,
        ):
            entries = adapter.fetch_recent(since)

        # 2024-06-15 のエントリのみマッチ (2023-01-01 は since より前)
        assert len(entries) == 1
        assert entries[0].vuln_id == "CVE-2024-0001"
        assert entries[0].exploit_confirmed is True
        assert entries[0].source == "cisa_kev"
        assert entries[0].kev_due_date == "2024-07-01"
        assert len(entries[0].affected_products) == 1
        assert entries[0].affected_products[0].vendor == "Apache"

    def test_fetch_recent_all_old(self):
        from vuln_feeds.adapters.cisa_kev import CisaKevAdapter

        adapter = CisaKevAdapter()
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)

        with mock.patch(
            "vuln_feeds.adapters.cisa_kev.http_get_json",
            return_value=self.SAMPLE_CATALOG,
        ):
            entries = adapter.fetch_recent(since)

        assert len(entries) == 0

    def test_fetch_recent_http_error(self):
        from vuln_feeds.adapters.cisa_kev import CisaKevAdapter

        adapter = CisaKevAdapter()
        since = datetime(2024, 1, 1, tzinfo=timezone.utc)

        with mock.patch(
            "vuln_feeds.adapters.cisa_kev.http_get_json",
            side_effect=RuntimeError("network error"),
        ):
            entries = adapter.fetch_recent(since)

        assert entries == []


# ====================================================
# NVD アダプターテスト
# ====================================================


class TestNvdAdapter:
    """NVD アダプターのテスト (HTTP モック使用)"""

    SAMPLE_RESPONSE = {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-5555",
                    "published": "2024-06-01T10:00:00.000",
                    "lastModified": "2024-06-02T12:00:00.000",
                    "sourceIdentifier": "cve@mitre.org",
                    "descriptions": [
                        {"lang": "en", "value": "A test vulnerability in TestProduct."}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "version": "3.1",
                                    "baseScore": 8.1,
                                    "baseSeverity": "HIGH",
                                    "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                },
                            }
                        ]
                    },
                    "references": [
                        {"url": "https://example.com/advisory/CVE-2024-5555"}
                    ],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:example:testproduct:*:*:*:*:*:*:*:*",
                                            "versionEndExcluding": "2.0.0",
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ],
    }

    def test_fetch_recent_parses_correctly(self):
        from vuln_feeds.adapters.nvd import NvdAdapter

        with mock.patch.object(NvdAdapter, "__init__", lambda self: None):
            adapter = NvdAdapter()
            adapter._api_key = ""

        since = datetime(2024, 1, 1, tzinfo=timezone.utc)

        with mock.patch(
            "vuln_feeds.adapters.nvd.http_get_json",
            return_value=self.SAMPLE_RESPONSE,
        ):
            entries = adapter.fetch_recent(since)

        assert len(entries) == 1
        entry = entries[0]
        assert entry.vuln_id == "CVE-2024-5555"
        assert entry.cvss_score == 8.1
        assert entry.severity == "高"
        assert entry.source == "nvd"
        assert len(entry.affected_products) == 1
        assert entry.affected_products[0].product == "testproduct"
        assert entry.affected_products[0].versions == "<2.0.0"

    def test_fetch_recent_empty_result(self):
        from vuln_feeds.adapters.nvd import NvdAdapter

        with mock.patch.object(NvdAdapter, "__init__", lambda self: None):
            adapter = NvdAdapter()
            adapter._api_key = ""

        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        empty_response = {"totalResults": 0, "vulnerabilities": []}

        with mock.patch(
            "vuln_feeds.adapters.nvd.http_get_json",
            return_value=empty_response,
        ):
            entries = adapter.fetch_recent(since)

        assert entries == []


# ====================================================
# 重複排除テスト (BigQuery モック)
# ====================================================


class TestDedup:
    """dedup.py のロジックテスト"""

    def test_check_and_register_no_table(self):
        """テーブル未設定時は ERROR を返す"""
        from vuln_feeds.dedup import DedupResult, check_and_register

        entry = VulnEntry(vuln_id="CVE-2024-0001", source="nvd")
        with mock.patch.dict(os.environ, {"BQ_VULN_DEDUP_TABLE_ID": ""}):
            result = check_and_register(entry)
        assert result == DedupResult.ERROR

    def test_check_and_register_empty_id(self):
        """空の vuln_id は ERROR"""
        from vuln_feeds.dedup import DedupResult, check_and_register

        entry = VulnEntry(vuln_id="", source="nvd")
        with mock.patch.dict(os.environ, {"BQ_VULN_DEDUP_TABLE_ID": "proj.ds.table"}):
            result = check_and_register(entry)
        assert result == DedupResult.ERROR

    @mock.patch("vuln_feeds.dedup._get_client")
    @mock.patch("vuln_feeds.dedup._find_existing", return_value=None)
    @mock.patch("vuln_feeds.dedup._insert_new")
    def test_check_and_register_new_entry(self, mock_insert, mock_find, mock_client):
        """新規エントリは NEW を返す"""
        from vuln_feeds.dedup import DedupResult, check_and_register

        entry = VulnEntry(vuln_id="CVE-2024-9999", source="cisa_kev")
        with mock.patch.dict(
            os.environ, {"BQ_VULN_DEDUP_TABLE_ID": "proj.ds.vuln_dedup"}
        ):
            result = check_and_register(entry)

        assert result == DedupResult.NEW
        mock_insert.assert_called_once()

    @mock.patch("vuln_feeds.dedup._get_client")
    @mock.patch(
        "vuln_feeds.dedup._find_existing",
        return_value={"vuln_id": "CVE-2024-9999", "first_source": "nvd", "sources_seen": ["nvd"]},
    )
    @mock.patch("vuln_feeds.dedup._update_sources_seen")
    def test_check_and_register_duplicate(self, mock_update, mock_find, mock_client):
        """既知エントリは SKIP を返す"""
        from vuln_feeds.dedup import DedupResult, check_and_register

        entry = VulnEntry(vuln_id="CVE-2024-9999", source="cisa_kev")
        with mock.patch.dict(
            os.environ, {"BQ_VULN_DEDUP_TABLE_ID": "proj.ds.vuln_dedup"}
        ):
            result = check_and_register(entry)

        assert result == DedupResult.SKIP
        mock_update.assert_called_once()


# ====================================================
# main.py テスト
# ====================================================


class TestPollVulnFeeds:
    """Cloud Function エントリーポイントのテスト"""

    @mock.patch("vuln_feeds.main._poll_single_source")
    def test_poll_specific_sources(self, mock_poll):
        from vuln_feeds.main import poll_vuln_feeds

        mock_poll.return_value = {"status": "ok", "fetched": 5, "new": 2}

        # Flask リクエストモック
        mock_request = mock.MagicMock()
        mock_request.get_json.return_value = {"sources": ["cisa_kev", "nvd"]}

        response_body, status_code, headers = poll_vuln_feeds(mock_request)
        response = json.loads(response_body)

        assert status_code == 200
        assert response["status"] == "ok"
        assert "cisa_kev" in response["results"]
        assert "nvd" in response["results"]
        assert mock_poll.call_count == 2


# ====================================================
# JVN アダプターテスト
# ====================================================


class TestJvnAdapter:
    """JVN アダプターのテスト (XML モック使用)"""

    SAMPLE_ATOM_XML = """<?xml version="1.0" encoding="UTF-8"?>
    <feed xmlns="http://www.w3.org/2005/Atom"
          xmlns:sec="http://jvn.jp/rss/mod_sec/3.0/">
      <entry>
        <title>Apache Log4j の脆弱性 (CVE-2024-1111)</title>
        <id>JVNDB-2024-001111</id>
        <link href="https://jvndb.jvn.jp/ja/contents/2024/JVNDB-2024-001111.html"/>
        <summary>Apache Log4j にリモートコード実行の脆弱性があります。CVE-2024-1111</summary>
        <published>2024-06-01T10:00:00+09:00</published>
        <updated>2024-06-02T12:00:00+09:00</updated>
        <sec:cvss version="3.0" score="9.8"/>
        <sec:cpe name="cpe:2.3:a:apache:log4j:*" vendor="Apache" product="Log4j"/>
      </entry>
    </feed>"""

    def test_parse_atom_feed(self):
        from vuln_feeds.adapters.jvn import _parse_jvn_xml

        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        entries = _parse_jvn_xml(self.SAMPLE_ATOM_XML, since)

        assert len(entries) == 1
        entry = entries[0]
        assert entry.vuln_id == "CVE-2024-1111"
        assert "JVNDB-2024-001111" in entry.aliases
        assert entry.source == "jvn"
        assert entry.cvss_score == 9.8

    def test_fetch_recent_http_error(self):
        from vuln_feeds.adapters.jvn import JvnAdapter

        adapter = JvnAdapter()
        since = datetime(2024, 1, 1, tzinfo=timezone.utc)

        with mock.patch(
            "vuln_feeds.adapters.jvn.fetch_with_retry",
            side_effect=RuntimeError("network error"),
        ):
            entries = adapter.fetch_recent(since)

        assert entries == []


# ====================================================
# OSV アダプターテスト
# ====================================================


class TestOsvAdapter:
    """OSV アダプターのテスト (HTTP モック使用)"""

    SAMPLE_OSV_RESPONSE = {
        "vulns": [
            {
                "id": "GHSA-xxxx-yyyy-zzzz",
                "summary": "Remote code execution in example-pkg",
                "details": "A vulnerability exists in example-pkg.",
                "aliases": ["CVE-2024-7777"],
                "published": "2024-06-10T00:00:00Z",
                "modified": "2024-06-11T00:00:00Z",
                "severity": [
                    {"type": "CVSS_V3", "score": "8.5"}
                ],
                "affected": [
                    {
                        "package": {
                            "ecosystem": "PyPI",
                            "name": "example-pkg",
                            "purl": "pkg:pypi/example-pkg",
                        },
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": "1.5.0"},
                                ],
                            }
                        ],
                    }
                ],
                "references": [
                    {"url": "https://example.com/advisory/7777"}
                ],
            }
        ]
    }

    def test_normalize_osv_vuln(self):
        from vuln_feeds.adapters.osv import _normalize_osv_vuln

        vuln = self.SAMPLE_OSV_RESPONSE["vulns"][0]
        entry = _normalize_osv_vuln(vuln, "PyPI")

        assert entry is not None
        assert entry.vuln_id == "CVE-2024-7777"
        assert "GHSA-XXXX-YYYY-ZZZZ" in entry.aliases
        assert entry.cvss_score == 8.5
        assert entry.source == "osv"
        assert len(entry.affected_products) == 1
        assert entry.affected_products[0].product == "example-pkg"
        assert entry.affected_products[0].versions == "<1.5.0"

    def test_osv_vuln_without_cve(self):
        from vuln_feeds.adapters.osv import _normalize_osv_vuln

        vuln = {
            "id": "GHSA-aaaa-bbbb-cccc",
            "summary": "Test vuln",
            "aliases": [],
            "published": "2024-06-10T00:00:00Z",
            "modified": "2024-06-11T00:00:00Z",
        }
        entry = _normalize_osv_vuln(vuln, "npm")

        assert entry is not None
        assert entry.vuln_id == "GHSA-aaaa-bbbb-cccc"
        assert entry.aliases == []


# ====================================================
# Fortinet アダプターテスト
# ====================================================


class TestFortinetAdapter:
    """Fortinet PSIRT RSS アダプターのテスト"""

    SAMPLE_RSS = """<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0">
      <channel>
        <item>
          <title>FortiOS - Heap buffer overflow in SSL-VPN (FG-IR-24-001, CVE-2024-8888)</title>
          <link>https://www.fortiguard.com/psirt/FG-IR-24-001</link>
          <description>A heap buffer overflow in FortiOS SSL-VPN. CVSSv3: 9.3</description>
          <pubDate>Thu, 15 Jun 2024 00:00:00 GMT</pubDate>
        </item>
        <item>
          <title>FortiManager - SQL injection (FG-IR-23-100, CVE-2023-5555)</title>
          <link>https://www.fortiguard.com/psirt/FG-IR-23-100</link>
          <description>Old advisory.</description>
          <pubDate>Thu, 01 Jan 2023 00:00:00 GMT</pubDate>
        </item>
      </channel>
    </rss>"""

    def test_parse_rss_filters_by_date(self):
        from vuln_feeds.adapters.fortinet import _parse_fortinet_rss

        since = datetime(2024, 6, 1, tzinfo=timezone.utc)
        entries = _parse_fortinet_rss(self.SAMPLE_RSS, since)

        assert len(entries) == 1
        assert entries[0].vuln_id == "CVE-2024-8888"
        assert "FG-IR-24-001" in entries[0].aliases
        assert entries[0].source == "fortinet"
        assert entries[0].cvss_score == 9.3
        assert entries[0].affected_products[0].product == "FortiOS"

    def test_fetch_recent_http_error(self):
        from vuln_feeds.adapters.fortinet import FortinetAdapter

        adapter = FortinetAdapter()
        since = datetime(2024, 1, 1, tzinfo=timezone.utc)

        with mock.patch(
            "vuln_feeds.adapters.fortinet.fetch_with_retry",
            side_effect=RuntimeError("network error"),
        ):
            entries = adapter.fetch_recent(since)

        assert entries == []


# ====================================================
# AlmaLinux アダプターテスト
# ====================================================


class TestAlmaLinuxAdapter:
    """AlmaLinux Errata アダプターのテスト"""

    SAMPLE_ERRATA = [
        {
            "id": "ALSA-2024:1234",
            "type": "security",
            "title": "Important: kernel security update",
            "description": "An update for kernel is now available. CVE-2024-3333.",
            "severity": "important",
            "issued_date": "2024-06-20",
            "updated_date": "2024-06-21",
            "CVEs": ["CVE-2024-3333", "CVE-2024-3334"],
            "packages": ["kernel-5.14.0-362.el9.x86_64"],
        },
        {
            "id": "ALSA-2023:5678",
            "type": "security",
            "title": "Low: old update",
            "severity": "low",
            "issued_date": "2023-01-01",
        },
    ]

    def test_fetch_filters_by_date(self):
        from vuln_feeds.adapters.almalinux import AlmaLinuxAdapter

        adapter = AlmaLinuxAdapter()
        since = datetime(2024, 6, 1, tzinfo=timezone.utc)

        with mock.patch(
            "vuln_feeds.adapters.almalinux.http_get_json",
            return_value=self.SAMPLE_ERRATA,
        ):
            entries = adapter.fetch_recent(since)

        # 2024-06-20 のみマッチ (各バージョンから取得するが重複排除)
        assert len(entries) >= 1
        matched = [e for e in entries if e.vuln_id == "CVE-2024-3333"]
        assert len(matched) >= 1
        entry = matched[0]
        assert entry.source == "almalinux"
        assert "ALSA-2024:1234" in entry.aliases
        assert entry.vendor_severity == "important"


# ====================================================
# Cisco CSAF アダプターテスト
# ====================================================


class TestCiscoCsafAdapter:
    """Cisco openVuln API アダプターのテスト"""

    def test_normalize_cisco_advisory(self):
        from vuln_feeds.adapters.cisco_csaf import _normalize_cisco_advisory

        adv = {
            "advisoryId": "cisco-sa-test-001",
            "advisoryTitle": "Cisco ASA RCE Vulnerability",
            "summary": "A remote code execution vulnerability.",
            "cves": ["CVE-2024-6666"],
            "cvssBaseScore": "9.1",
            "firstPublished": "2024-06-15T00:00:00Z",
            "lastUpdated": "2024-06-16T00:00:00Z",
            "sir": "Critical",
            "publicationUrl": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-test-001",
            "productNames": ["Cisco ASA 5500-X", "Cisco Firepower"],
        }

        entry = _normalize_cisco_advisory(adv)
        assert entry is not None
        assert entry.vuln_id == "CVE-2024-6666"
        assert "cisco-sa-test-001" in entry.aliases
        assert entry.cvss_score == 9.1
        assert entry.source == "cisco_csaf"
        assert entry.vendor_severity == "Critical"
        assert len(entry.affected_products) == 2

    def test_normalize_no_cve(self):
        from vuln_feeds.adapters.cisco_csaf import _normalize_cisco_advisory

        adv = {
            "advisoryId": "cisco-sa-no-cve",
            "advisoryTitle": "Test advisory",
            "cves": [],
        }
        entry = _normalize_cisco_advisory(adv)
        assert entry is not None
        assert entry.vuln_id == "cisco-sa-no-cve"
        assert entry.aliases == []


# ====================================================
# MSRC アダプターテスト
# ====================================================


class TestMsrcAdapter:
    """MSRC CVRF API アダプターのテスト"""

    def test_parse_cvrf_vulnerability(self):
        from vuln_feeds.adapters.msrc import _normalize_msrc_vuln

        vuln = {
            "CVE": "CVE-2024-9999",
            "Title": {"Value": "Windows RCE Vulnerability"},
            "Notes": [
                {"Type": "Description", "Value": "A remote code execution vulnerability in Windows."}
            ],
            "RevisionHistory": [
                {"Date": "2024-06-10T00:00:00Z", "Description": "Initial"},
            ],
            "CVSSScoreSets": [
                {"BaseScore": 8.8, "Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"}
            ],
            "ProductStatuses": [
                {"ProductID": ["pid-1", "pid-2"], "Type": 0}
            ],
            "Threats": [],
        }

        product_map = {
            "pid-1": "Windows 11 23H2",
            "pid-2": "Windows Server 2022",
        }

        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        entry = _normalize_msrc_vuln(vuln, product_map, since)

        assert entry is not None
        assert entry.vuln_id == "CVE-2024-9999"
        assert entry.cvss_score == 8.8
        assert entry.source == "msrc"
        assert len(entry.affected_products) == 2
        assert entry.affected_products[0].product == "Windows 11 23H2"


# ====================================================
# スクレイピングアダプターテスト
# ====================================================


class TestZabbixAdapter:
    """Zabbix スクレイピングアダプターのテスト"""

    def test_normalize_zabbix_vuln(self):
        from vuln_feeds.adapters.zabbix import _normalize_zabbix_vuln

        raw = {
            "vuln_id": "CVE-2024-4444",
            "zbx_id": "ZBX-25001",
            "title": "Zabbix Server RCE",
            "description": "Remote code execution in Zabbix Server",
            "severity": "Critical",
            "cvss_score": "9.8",
            "affected_versions": "6.0.0 - 6.0.30",
            "fixed_versions": "6.0.31, 7.0.1",
            "published_date": "2024-06-15",
        }
        since = datetime(2024, 6, 1, tzinfo=timezone.utc)
        entry = _normalize_zabbix_vuln(raw, since)

        assert entry is not None
        assert entry.vuln_id == "CVE-2024-4444"
        assert "ZBX-25001" in entry.aliases
        assert entry.cvss_score == 9.8
        assert entry.source == "zabbix"
        assert entry.vendor_fixed_versions == ["6.0.31", "7.0.1"]

    def test_normalize_old_vuln_filtered(self):
        from vuln_feeds.adapters.zabbix import _normalize_zabbix_vuln

        raw = {
            "vuln_id": "CVE-2023-1111",
            "title": "Old vuln",
            "published_date": "2023-01-01",
        }
        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        entry = _normalize_zabbix_vuln(raw, since)
        assert entry is None


class TestAdapterRegistry:
    """アダプターレジストリの完全性テスト"""

    def test_all_sources_registered(self):
        from vuln_feeds.adapters import ADAPTER_REGISTRY

        expected = {
            "cisa_kev", "nvd", "jvn", "osv",
            "cisco_csaf", "msrc", "fortinet", "almalinux",
            "zabbix", "motex", "skysea",
        }
        assert set(ADAPTER_REGISTRY.keys()) == expected

    def test_all_have_source_id(self):
        from vuln_feeds.adapters import ADAPTER_REGISTRY

        for source_id, cls in ADAPTER_REGISTRY.items():
            assert cls.source_id == source_id, f"{cls.__name__}.source_id != {source_id}"
