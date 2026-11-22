"""
Unit and integration tests for PhishGuard custom detection rule engine.
"""

from email.message import EmailMessage
from pathlib import Path
import pytest

from phishguard.models.email import AuthenticationResults, AuthStatus, EmailMetadata
from phishguard.models.forensics import (
    AttachmentArtifact,
    HeaderAnalysis,
    QuishingResult,
    UrlArtifact,
)
from phishguard.parser.eml_parser import EmlParser, ParsedEmail
from phishguard.rules.engine import RuleEngine
from phishguard.rules.models import (
    RuleCondition,
    RuleDefinition,
    RuleMitre,
    RuleSeverity,
)


@pytest.fixture
def sample_parsed_email() -> ParsedEmail:
    return ParsedEmail(
        file_path="test.eml",
        file_sha256="abc123hash",
        raw_message=EmailMessage(),
        metadata=EmailMetadata(
            subject="URGENT: Your Account Has Been Suspended",
            from_address="security@alert-paypal-update.com",
            from_name="PayPal Alert",
            from_raw='"PayPal Alert" <security@alert-paypal-update.com>',
            to_addresses=["user@target.com"],
            date="Sun, 22 Nov 2026 12:00:00 +0000",
        ),
        headers=[
            ("x-mailer", "PHPMailer 6.1.4 (https://github.com/PHPMailer/PHPMailer)"),
            ("message-id", "<xyz123@alert-paypal-update.com>"),
        ],
        received_headers=[],
        auth_results_headers=[],
        plain_body="Immediate attention required! Your account will be permanently suspended within 24 hours. Verify your credentials.",
        html_body="<p>Immediate attention required! Verify your credentials at <a href='http://phish.net/login'>here</a></p>",
        attachments=[],
    )


@pytest.fixture
def sample_header_analysis() -> HeaderAnalysis:
    return HeaderAnalysis(
        hops=[],
        originating_ip="198.51.100.22",
        auth=AuthenticationResults(spf_status=AuthStatus.FAIL, dkim_status=AuthStatus.FAIL, dmarc_status=AuthStatus.FAIL),
        risk_score=25.0,
    )


def test_rule_condition_operators(sample_parsed_email, sample_header_analysis):
    engine = RuleEngine()

    # 1. regex_search on body
    c1 = RuleCondition(
        field="body",
        operator="regex_search",
        patterns=["(?i)account.{0,40}suspended"]
    )
    matched, ev = engine.evaluate_condition(c1, sample_parsed_email, sample_header_analysis, [], [], None)
    assert matched is True
    assert "matched regex" in ev

    # 2. contains on headers
    c2 = RuleCondition(
        field="headers",
        header_name="x-mailer",
        operator="contains",
        pattern="phpmailer"
    )
    matched, ev = engine.evaluate_condition(c2, sample_parsed_email, sample_header_analysis, [], [], None)
    assert matched is True

    # 3. gt operator on url_count
    urls = [UrlArtifact(raw_url="http://phish.net", defanged_url="hxxp://phish[.]net", domain="phish.net")]
    c3 = RuleCondition(field="url_count", operator="gt", value=0)
    matched, _ = engine.evaluate_condition(c3, sample_parsed_email, sample_header_analysis, urls, [], None)
    assert matched is True

    # 4. in operator on auth_spf
    c4 = RuleCondition(field="auth_spf", operator="in", patterns=["fail", "softfail"])
    matched, _ = engine.evaluate_condition(c4, sample_parsed_email, sample_header_analysis, [], [], None)
    assert matched is True


def test_rule_boolean_logic(sample_parsed_email, sample_header_analysis):
    rule = RuleDefinition(
        id="TEST-001",
        name="Urgent Phish Test",
        description="Test urgent lure",
        severity=RuleSeverity.HIGH,
        score_impact=20.0,
        mitre=RuleMitre(technique_id="T1566.002", technique_name="Spearphishing Link"),
        conditions={
            "all": [
                RuleCondition(field="body", operator="regex_search", patterns=["(?i)suspended"]),
                RuleCondition(field="auth_spf", operator="equals", value="fail"),
            ],
            "any": [
                RuleCondition(field="subject", operator="contains", pattern="URGENT"),
            ],
            "none": [
                RuleCondition(field="from", operator="contains", pattern="legitimate.com"),
            ]
        }
    )

    engine = RuleEngine([rule])
    matches = engine.evaluate_all(sample_parsed_email, sample_header_analysis, [], [], None)
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_id == "TEST-001"
    assert m.severity == "HIGH"
    assert m.score_impact == 20.0
    assert m.mitre_technique_id == "T1566.002"


def test_load_enterprise_rules_from_dir():
    rules_dir = Path("rules")
    assert rules_dir.is_dir()
    engine = RuleEngine.from_directory(rules_dir)
    assert len(engine.rules) >= 5

    rule_ids = {r.id for r in engine.rules}
    assert "PG-RULE-001" in rule_ids
    assert "PG-RULE-002" in rule_ids
    assert "PG-RULE-003" in rule_ids
    assert "PG-RULE-004" in rule_ids
    assert "PG-RULE-005" in rule_ids


def test_enterprise_rules_against_sample_corpus():
    parser = EmlParser()
    engine = RuleEngine.from_directory("rules")

    # 1. Phishing Account Alert should match PG-RULE-001
    phish_parsed = parser.parse_file(Path("samples/phishing_account_alert.eml"))
    auth_hdr = HeaderAnalysis(
        hops=[], originating_ip="198.51.100.1",
        auth=AuthenticationResults(spf_status=AuthStatus.FAIL, dkim_status=AuthStatus.FAIL, dmarc_status=AuthStatus.FAIL)
    )
    urls = [UrlArtifact(raw_url="http://paypal-verification-alert.com", defanged_url="hxxp://paypal-verification-alert[.]com", domain="paypal-verification-alert.com")]
    matches = engine.evaluate_all(phish_parsed, auth_hdr, urls, [], None)
    rule_ids = [m.rule_id for m in matches]
    assert "PG-RULE-001" in rule_ids

    # 2. CEO Fraud Wire Transfer should match PG-RULE-002
    ceo_parsed = parser.parse_file(Path("samples/ceo_fraud_wire_transfer.eml"))
    matches_ceo = engine.evaluate_all(ceo_parsed, auth_hdr, [], [], None)
    rule_ids_ceo = [m.rule_id for m in matches_ceo]
    assert "PG-RULE-002" in rule_ids_ceo

    # 3. Quishing MFA Lure should match PG-RULE-005
    quish_parsed = parser.parse_file(Path("samples/quishing_mfa_lure.eml"))
    quish_res = QuishingResult(found=True, qr_count=1, risk_score=85.0)
    matches_quish = engine.evaluate_all(quish_parsed, auth_hdr, [], [], quish_res)
    rule_ids_quish = [m.rule_id for m in matches_quish]
    assert "PG-RULE-005" in rule_ids_quish

    # 4. Weaponized Invoice Attachment should match PG-RULE-003
    weap_parsed = parser.parse_file(Path("samples/weaponized_invoice_attachment.eml"))
    att = AttachmentArtifact(
        filename="INVOICE_OCT2026.pdf.exe",
        size_bytes=24500,
        is_executable=True,
        is_double_extension=True,
    )
    matches_weap = engine.evaluate_all(weap_parsed, auth_hdr, [], [att], None)
    rule_ids_weap = [m.rule_id for m in matches_weap]
    assert "PG-RULE-003" in rule_ids_weap

    # 5. Benign Newsletter should trigger NO critical rules
    benign_parsed = parser.parse_file(Path("samples/benign_newsletter.eml"))
    auth_benign = HeaderAnalysis(
        hops=[], originating_ip="203.0.113.1",
        auth=AuthenticationResults(spf_status=AuthStatus.PASS, dkim_status=AuthStatus.PASS, dmarc_status=AuthStatus.PASS)
    )
    matches_benign = engine.evaluate_all(benign_parsed, auth_benign, urls, [], None)
    critical_matches = [m for m in matches_benign if m.severity in ("CRITICAL", "HIGH")]
    assert len(critical_matches) == 0
