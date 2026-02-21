import importlib.util
import os
from pathlib import Path
import sys
import types
import unittest
from datetime import date


ROOT = Path(__file__).resolve().parent
CHAT_TOOLS_PATH = ROOT / "agent" / "tools" / "chat_tools.py"


def _stub_google_modules() -> None:
    google = types.ModuleType("google")
    oauth2 = types.ModuleType("google.oauth2")
    service_account = types.ModuleType("google.oauth2.service_account")

    class _Creds:
        @staticmethod
        def from_service_account_file(*args, **kwargs):
            return object()

    service_account.Credentials = _Creds
    oauth2.service_account = service_account
    google.oauth2 = oauth2

    googleapiclient = types.ModuleType("googleapiclient")
    discovery = types.ModuleType("googleapiclient.discovery")
    discovery.build = lambda *args, **kwargs: object()
    googleapiclient.discovery = discovery
    errors = types.ModuleType("googleapiclient.errors")
    errors.HttpError = type("HttpError", (Exception,), {"resp": None})
    googleapiclient.errors = errors

    sys.modules["google"] = google
    sys.modules["google.oauth2"] = oauth2
    sys.modules["google.oauth2.service_account"] = service_account
    sys.modules["googleapiclient"] = googleapiclient
    sys.modules["googleapiclient.discovery"] = discovery
    sys.modules["googleapiclient.errors"] = errors


def _stub_secret_config_module() -> None:
    mod = types.ModuleType("secret_config")

    def get_config_value(env_names, secret_name=None, default=""):
        for env_name in env_names:
            value = (os.environ.get(env_name) or "").strip()
            if value:
                return value
        return default

    mod.get_config_value = get_config_value
    sys.modules["secret_config"] = mod


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class ChatToolsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _stub_google_modules()
        _stub_secret_config_module()
        cls.chat_tools = _load_module("chat_tools_test", CHAT_TOOLS_PATH)
        cls.chat_tools_source = CHAT_TOOLS_PATH.read_text(encoding="utf-8")

    def setUp(self):
        for key in ("DEFAULT_CHAT_SPACE_ID", "CHAT_SPACE_ID", "GOOGLE_CHAT_SPACE_ID"):
            os.environ.pop(key, None)

    def tearDown(self):
        for key in ("DEFAULT_CHAT_SPACE_ID", "CHAT_SPACE_ID", "GOOGLE_CHAT_SPACE_ID"):
            os.environ.pop(key, None)

    def test_build_card_structure(self):
        """Verify _build_card() returns correct cardsV2 structure."""
        card = self.chat_tools._build_card(
            vulnerability_id="CVE-2024-1234",
            title="Test Vulnerability",
            severity="高",
            cvss_score=None,
            affected_systems=["system-a"],
            description=None,
            remediation=None,
            deadline="2025年01月15日",
            owners=None,
        )

        # Top-level keys
        self.assertIn("cardId", card)
        self.assertIn("card", card)

        inner = card["card"]
        # Header
        self.assertIn("header", inner)
        self.assertEqual(inner["header"]["title"], "CVE-2024-1234")
        self.assertEqual(inner["header"]["subtitle"], "Test Vulnerability")

        # Sections
        self.assertIn("sections", inner)
        self.assertIsInstance(inner["sections"], list)
        self.assertGreater(len(inner["sections"]), 0)

        # No HTML tags in decoratedText widgets
        for section in inner["sections"]:
            for widget in section.get("widgets", []):
                if "decoratedText" in widget:
                    text = widget["decoratedText"].get("text", "")
                    self.assertNotIn("<font", text)
                    self.assertNotIn("</font>", text)
                    self.assertNotIn("<b>", text)
                    self.assertNotIn("</b>", text)

    def test_build_card_severity_emoji(self):
        """Verify severity uses emoji instead of HTML color."""
        card_critical = self.chat_tools._build_card(
            vulnerability_id="CVE-2024-0001",
            title="Critical vuln",
            severity="緊急",
            cvss_score=None,
            affected_systems=["sys-1"],
            description=None,
            remediation=None,
            deadline="2025年01月01日",
            owners=None,
        )

        card_low = self.chat_tools._build_card(
            vulnerability_id="CVE-2024-0002",
            title="Low vuln",
            severity="低",
            cvss_score=None,
            affected_systems=["sys-2"],
            description=None,
            remediation=None,
            deadline="2025年02月01日",
            owners=None,
        )

        # Find the severity decoratedText in each card
        def _find_severity_text(card):
            for section in card["card"]["sections"]:
                for widget in section.get("widgets", []):
                    dt = widget.get("decoratedText", {})
                    if dt.get("topLabel") == "重大度":
                        return dt.get("text", "")
            return ""

        self.assertIn("\U0001f534", _find_severity_text(card_critical))  # red circle
        self.assertIn("\U0001f7e2", _find_severity_text(card_low))        # green circle

    def test_build_card_with_all_fields(self):
        """Full card with cvss_score, description, remediation, owners."""
        card = self.chat_tools._build_card(
            vulnerability_id="CVE-2024-5678",
            title="Full Card Test",
            severity="中",
            cvss_score=7.5,
            affected_systems=["app-server", "db-server"],
            description="A serious vulnerability in the parser.",
            remediation="Upgrade to version 2.0.",
            deadline="2025年01月20日",
            owners=["alice@example.com", "bob@example.com"],
        )

        sections = card["card"]["sections"]

        # Collect section headers
        headers = [s.get("header") for s in sections if s.get("header")]
        self.assertIn("概要", headers)
        self.assertIn("影響を受けるシステム", headers)
        self.assertIn("説明", headers)
        self.assertIn("推奨対策", headers)
        self.assertIn("担当者", headers)

        # CVSS score widget present in overview section
        overview_section = next(s for s in sections if s.get("header") == "概要")
        cvss_texts = [
            w["decoratedText"]["text"]
            for w in overview_section["widgets"]
            if "decoratedText" in w and w["decoratedText"].get("topLabel") == "CVSSスコア"
        ]
        self.assertEqual(len(cvss_texts), 1)
        self.assertEqual(cvss_texts[0], "7.5")

        # Button section with NVD link
        last_section = sections[-1]
        button_list = last_section["widgets"][0].get("buttonList")
        self.assertIsNotNone(button_list)
        buttons = button_list["buttons"]
        self.assertEqual(len(buttons), 1)
        self.assertIn("CVE-2024-5678", buttons[0]["onClick"]["openLink"]["url"])

    def test_resolve_space_id_rejects_invalid_format(self):
        """Verify _resolve_space_id returns None for invalid space IDs."""
        os.environ["DEFAULT_CHAT_SPACE_ID"] = "spaces/invalid!@#"
        self.assertIsNone(self.chat_tools._resolve_space_id())

        os.environ["DEFAULT_CHAT_SPACE_ID"] = ""
        self.assertIsNone(self.chat_tools._resolve_space_id())

    def test_resolve_space_id_accepts_valid_formats(self):
        """Verify valid space IDs are accepted and normalized."""
        os.environ["DEFAULT_CHAT_SPACE_ID"] = "spaces/ABC123"
        self.assertEqual(self.chat_tools._resolve_space_id(), "spaces/ABC123")

        os.environ["DEFAULT_CHAT_SPACE_ID"] = "ABC123"
        self.assertEqual(self.chat_tools._resolve_space_id(), "spaces/ABC123")

        os.environ["DEFAULT_CHAT_SPACE_ID"] = "spaces/test-space_1"
        self.assertEqual(self.chat_tools._resolve_space_id(), "spaces/test-space_1")

    def test_send_vulnerability_alert_space_id_error(self):
        """Verify send_vulnerability_alert returns error when space ID is not configured."""
        # Ensure no space ID env vars are set (cleared in setUp)
        result = self.chat_tools.send_vulnerability_alert(
            vulnerability_id="CVE-2024-9999",
            title="Test",
            severity="低",
            affected_systems=["test-sys"],
        )
        self.assertEqual(result["status"], "error")

    def test_mention_format(self):
        """Verify the text body uses <email> format not <users/email>."""
        self.assertIn('f"<{email}>"', self.chat_tools_source)
        self.assertNotIn('f"<users/{email}>"', self.chat_tools_source)

    def test_deadline_rule_public_cvss8(self):
        deadline = self.chat_tools._calculate_deadline(
            severity="高",
            cvss_score=8.2,
            resource_type="public",
            now=date(2026, 2, 15),  # Sunday
        )
        self.assertEqual(deadline, "2026/3/2")

    def test_deadline_rule_internal_cvss8(self):
        deadline = self.chat_tools._calculate_deadline(
            severity="高",
            cvss_score=8.5,
            resource_type="internal",
            now=date(2026, 2, 15),
        )
        self.assertEqual(deadline, "2026/5/15")

    def test_deadline_rule_public_cvss9_with_exploit(self):
        deadline = self.chat_tools._calculate_deadline(
            severity="緊急",
            cvss_score=9.1,
            resource_type="public",
            exploit_confirmed=True,
            exploit_code_public=True,
            now=date(2026, 2, 15),
        )
        self.assertEqual(deadline, "2026/2/20")

    def test_structured_alert_text_matches_required_sections(self):
        text = self.chat_tools._build_structured_alert_text(
            affected_systems=["Almalinux8", "Almalinux9"],
            vulnerability_id="CVE-2026-0001",
            title="OpenSSL issue",
            cvss_score=8.8,
            vulnerability_links={
                "Almalinux8": "https://sid.softek.jp/filter/sinfo/60846",
                "Almalinux9": "https://sid.softek.jp/filter/sinfo/53834",
            },
            deadline="2026/2/17",
            remediation=None,
        )

        expected = (
            "【対象の機器/アプリ】\n"
            "Almalinux8\n"
            "Almalinux9\n\n"
            "【脆弱性情報】（リンク貼り付け）\n"
            "Almalinux8\n"
            "https://sid.softek.jp/filter/sinfo/60846\n\n"
            "Almalinux9\n"
            "https://sid.softek.jp/filter/sinfo/53834\n\n"
            "【CVSSスコア】\n"
            "8以上\n\n"
            "【依頼内容】\n"
            "上記脆弱性情報をご確認いただき、バージョンが低い場合は"
            "バージョンアップのご対応をお願いいたします。\n"
            "対応を実施した場合はサーバのホスト名をご教示ください。\n\n"
            "【対応完了目標】\n"
            "2026/2/17"
        )
        self.assertEqual(text, expected)

    def test_structured_alert_text_defaults_when_inputs_missing(self):
        text = self.chat_tools._build_structured_alert_text(
            affected_systems=[],
            vulnerability_id="CVE-2026-9999",
            title="",
            cvss_score=None,
            vulnerability_links=None,
            deadline="2026/3/1",
            remediation="手順Aを実施してください。",
        )

        self.assertIn("【対象の機器/アプリ】\n不明", text)
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2026-9999", text)
        self.assertIn("【CVSSスコア】\n不明", text)
        self.assertIn("【依頼内容】\n手順Aを実施してください。", text)

    def test_evaluate_deadline_policy_returns_structured_result(self):
        result = self.chat_tools._evaluate_deadline_policy(
            severity="緊急",
            cvss_score=9.1,
            resource_type="public",
            exploit_confirmed=True,
            exploit_code_public=True,
            now=date(2026, 2, 15),
        )
        self.assertEqual(result["status"], "decided")
        self.assertEqual(result["rule_id"], "R1")
        self.assertEqual(result["due_date"], "2026/2/20")
        self.assertEqual(result["decision_level"], "確定")
        self.assertEqual(result["missing_fields"], [])

    def test_evaluate_deadline_policy_source_name_allowlist(self):
        result = self.chat_tools._evaluate_deadline_policy(
            severity="高",
            cvss_score=8.1,
            resource_type="",
            source_name="Fortigate",
            now=date(2026, 2, 15),
        )
        self.assertEqual(result["rule_id"], "R2")
        self.assertEqual(result["resource_classification"]["type"], "public")
        self.assertEqual(
            result["resource_classification"]["matched_by"],
            "source_name_allowlist",
        )

    def test_evaluate_deadline_policy_fallback_marks_missing_cvss(self):
        result = self.chat_tools._evaluate_deadline_policy(
            severity="中",
            cvss_score=None,
            resource_type="internal",
            now=date(2026, 2, 15),
        )
        self.assertEqual(result["rule_id"], "FALLBACK_SEVERITY")
        self.assertEqual(result["decision_level"], "暫定")
        self.assertIn("cvss_score", result["missing_fields"])

    def test_build_ticket_record_for_almalinux_maps_it_team(self):
        record = self.chat_tools._build_ticket_record(
            title="AlmaLinux の脆弱性確認及び該当バージョンの対応願い",
            affected_systems=["Almalinux9"],
            description=None,
            remediation=None,
            source_name="",
            body_text="",
        )
        self.assertEqual(record["major_category"], "017.脆弱性対応（情シス専用）")
        self.assertEqual(record["minor_category"], "定例脆弱性対応")
        self.assertEqual(record["detail"], "002.IT基盤チーム")
        self.assertIn("AlmaLinux", record["request_summary"])
        self.assertIn("【起票用（コピペ）】", record["copy_paste_text"])
        self.assertIn("大分類:", record["copy_paste_text"])
        self.assertIn("【判断理由】", record["reasoning_text"])
        self.assertTrue(isinstance(record["reasons"], list))
        self.assertEqual(record["needs_review"], False)

    def test_build_ticket_record_for_penetration_maps_subcategory(self):
        record = self.chat_tools._build_ticket_record(
            title="【ペネトレ対応】ドメイン管理者運用変更",
            affected_systems=[],
            description="ペネトレーションテストの対応",
            remediation=None,
            source_name="",
            body_text="",
        )
        self.assertEqual(record["minor_category"], "ペネトレ指摘対応")
        self.assertTrue(record["request_summary"].startswith("【ペネトレ対応】"))
        self.assertIn("ペネトレ関連キーワード", record["reasoning_text"])

    def test_build_ticket_record_flags_attachment_reference_for_review(self):
        record = self.chat_tools._build_ticket_record(
            title="Amazon Linux の脆弱性確認",
            affected_systems=["Amazon Linux"],
            description=None,
            remediation=None,
            source_name="",
            body_text="詳細情報は添付ファイル参照",
        )
        self.assertEqual(record["needs_review"], True)
        self.assertIn("添付参照のみ", record["anomalies"])
        self.assertIn("要レビュー: yes", record["reasoning_text"])

    def test_build_ticket_record_for_ios_maps_pc_team(self):
        record = self.chat_tools._build_ticket_record(
            title="Apple iOS のアップグレード",
            affected_systems=["iOS"],
            description=None,
            remediation=None,
            source_name="",
            body_text="",
        )
        self.assertEqual(record["detail"], "001.PCチーム")
        self.assertEqual(record["minor_category"], "定例脆弱性対応")

    def test_compose_chat_alert_text_includes_ticket_sections(self):
        ticket_record = {
            "copy_paste_text": "【起票用（コピペ）】\n大分類: 017.脆弱性対応（情シス専用）",
            "reasoning_text": "【判断理由】\n- 小分類判定: 通常の脆弱性対応パターン",
        }
        text = self.chat_tools._compose_chat_alert_text(
            base_text="【対応完了目標】\n2026/2/20",
            ticket_record=ticket_record,
            owners=["a@example.com"],
            include_ticket_sections=True,
        )
        self.assertIn("【起票用（コピペ）】", text)
        self.assertIn("【判断理由】", text)
        self.assertIn("<a@example.com>", text)

    def test_compose_chat_alert_text_can_skip_ticket_sections(self):
        ticket_record = {
            "copy_paste_text": "【起票用（コピペ）】\nX",
            "reasoning_text": "【判断理由】\nY",
        }
        text = self.chat_tools._compose_chat_alert_text(
            base_text="base",
            ticket_record=ticket_record,
            owners=None,
            include_ticket_sections=False,
        )
        self.assertEqual(text, "base")


if __name__ == "__main__":
    unittest.main()
