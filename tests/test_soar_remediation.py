"""
Unit and integration tests for PhishGuard SOAR incident remediation engine.
"""

from datetime import datetime, timezone
import pytest

from phishguard.models.email import AuthenticationResults, AuthStatus, EmailMetadata
from phishguard.models.forensics import AttachmentArtifact, HeaderAnalysis, UrlArtifact
from phishguard.models.report import MitreTechnique, RuleMatch, ScanResult, ScoreBreakdown, SeverityEnum, VerdictEnum
from phishguard.soar.generator import RemediationEngine
from phishguard.soar.models import PlatformType


@pytest.fixture
def mock_malicious_scan() -> ScanResult:
    return ScanResult(
        scan_id="PG-SOAR-TEST01",
        timestamp=datetime.now(timezone.utc),
        eml_file_path="test_incident.eml",
        eml_file_hash_sha256="1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
        metadata=EmailMetadata(
            subject="URGENT: Executive Wire Transfer Authorization",
            from_address="ceo@spoofed-exec.com",
            from_name="Chief Executive",
            from_raw='"Chief Executive" <ceo@spoofed-exec.com>',
            from_email="ceo@spoofed-exec.com",
            from_domain="spoofed-exec.com",
            to_emails=["finance@enterprise.com"],
            date="Mon, 23 Nov 2026 12:00:00 +0000",
        ),
        headers=HeaderAnalysis(
            hops=[],
            originating_ip="198.51.100.77",
            auth=AuthenticationResults(spf_status=AuthStatus.FAIL, dkim_status=AuthStatus.FAIL, dmarc_status=AuthStatus.FAIL),
            risk_score=30.0,
        ),
        urls=[
            UrlArtifact(
                raw_url="http://malicious-gateway.com/wire/auth",
                defanged_url="hxxp://malicious-gateway[.]com/wire/auth",
                domain="malicious-gateway.com",
                tld="com",
                scheme="http",
                threat_intel_flagged=True,
                threat_intel_source="URLhaus",
                risk_score=35.0,
            )
        ],
        attachments=[
            AttachmentArtifact(
                filename="Wire_Instructions.pdf.exe",
                size_bytes=45000,
                sha256="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                is_executable=True,
                is_double_extension=True,
                risk_score=95.0,
            )
        ],
        score=ScoreBreakdown(header_score=30.0, url_score=35.0, attachment_score=20.0, content_score=15.0, total_score=95.0),
        verdict=VerdictEnum.MALICIOUS,
        severity=SeverityEnum.CRITICAL,
        confidence_percentage=99.0,
        key_findings=["Critical BEC spoofing attack", "Executable attachment disguised as PDF"],
        matched_rules=[
            RuleMatch(
                rule_id="PG-RULE-002",
                rule_name="Executive Impersonation & BEC Wire Fraud",
                severity="CRITICAL",
                score_impact=25.0,
                description="BEC pattern requesting wire transfer",
            )
        ],
        mitre_attack=[
            MitreTechnique(
                technique_id="T1566.001",
                technique_name="Spearphishing Attachment",
                tactic="Initial Access",
                description="Weaponized payload",
                attack_url="https://attack.mitre.org/techniques/T1566/001/",
            )
        ],
        written_explanation="Confirmed malicious BEC phishing attack targeting finance wire transfers.",
        remediation_steps=["Execute M365 Compliance Purge", "Block originating IP"],
    )


def test_remediation_engine_all_platforms(mock_malicious_scan):
    engine = RemediationEngine()
    package = engine.generate_package(mock_malicious_scan, platforms=[PlatformType.ALL])

    assert package.scan_id == "PG-SOAR-TEST01"
    assert package.sender_email == "ceo@spoofed-exec.com"
    assert package.originating_ip == "198.51.100.77"
    assert len(package.actions) >= 5

    action_names = [a.name for a in package.actions]
    assert any("M365 Exchange Online Hard-Delete Purge" in name for name in action_names)
    assert any("M365 Tenant Allow/Block List" in name for name in action_names)
    assert any("Google Workspace GAM Global Message Purge" in name for name in action_names)
    assert any("Microsoft Defender Advanced Hunting" in name for name in action_names)
    assert any("Perimeter Firewall & DNS Sinkhole Block Rules" in name for name in action_names)


def test_remediation_m365_specific(mock_malicious_scan):
    engine = RemediationEngine()
    package = engine.generate_package(mock_malicious_scan, platforms=[PlatformType.M365])

    assert len(package.actions) == 2
    purge_action = next(a for a in package.actions if a.category == "purge")
    assert "Connect-IPPSSession" in purge_action.code
    assert "New-ComplianceSearch" in purge_action.code
    assert "New-ComplianceSearchAction" in purge_action.code
    assert "ceo@spoofed-exec.com" in purge_action.code


def test_remediation_edr_kql(mock_malicious_scan):
    engine = RemediationEngine()
    package = engine.generate_package(mock_malicious_scan, platforms=[PlatformType.EDR_HUNTING])

    assert len(package.actions) == 2
    kql_action = next(a for a in package.actions if a.language == "kql")
    assert "DeviceProcessEvents" in kql_action.code
    assert "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" in kql_action.code
    assert "malicious-gateway.com" in kql_action.code


def test_remediation_firewall_rules(mock_malicious_scan):
    engine = RemediationEngine()
    package = engine.generate_package(mock_malicious_scan, platforms=[PlatformType.PERIMETER_FIREWALL])

    assert len(package.actions) == 1
    fw_action = package.actions[0]
    assert "198.51.100.77" in fw_action.code
    assert "Palo Alto Networks" in fw_action.code
    assert "Cisco ASA" in fw_action.code
    assert "CNAME ." in fw_action.code  # RPZ sinkhole
