"""
Unit tests for the SQLite incident database and threat hunting query engine.
"""

from datetime import datetime, timezone
from pathlib import Path
import pytest

from phishguard.models.email import AuthenticationResults, AuthStatus, EmailMetadata
from phishguard.models.forensics import HeaderAnalysis, UrlArtifact
from phishguard.models.report import MitreTechnique, RuleMatch, ScanResult, ScoreBreakdown, SeverityEnum, VerdictEnum
from phishguard.storage.database import IncidentDatabase
from phishguard.storage.models import IncidentQueryFilter


@pytest.fixture
def temp_soc_db(tmp_path: Path) -> IncidentDatabase:
    db_file = tmp_path / "test_soc.db"
    return IncidentDatabase(db_path=db_file)


@pytest.fixture
def sample_incident() -> ScanResult:
    return ScanResult(
        scan_id="PG-HUNT-001",
        timestamp=datetime.now(timezone.utc),
        eml_file_path="sample.eml",
        eml_file_hash_sha256="abc123sha256hash",
        metadata=EmailMetadata(
            subject="Urgent Payroll Update",
            from_address="hr@payroll-direct-update.com",
            from_name="HR Dept",
            from_raw='"HR Dept" <hr@payroll-direct-update.com>',
            from_email="hr@payroll-direct-update.com",
            from_domain="payroll-direct-update.com",
            to_emails=["employee@corp.com"],
            date="Mon, 23 Nov 2026 14:00:00 +0000",
        ),
        headers=HeaderAnalysis(
            hops=[],
            originating_ip="198.51.100.55",
            auth=AuthenticationResults(spf_status=AuthStatus.FAIL, dkim_status=AuthStatus.FAIL, dmarc_status=AuthStatus.FAIL),
            risk_score=25.0,
        ),
        urls=[
            UrlArtifact(
                raw_url="http://payroll-direct-update.com/login",
                defanged_url="hxxp://payroll-direct-update[.]com/login",
                domain="payroll-direct-update.com",
                tld="com",
                scheme="http",
                threat_intel_flagged=True,
                threat_intel_source="URLhaus",
            )
        ],
        score=ScoreBreakdown(header_score=25.0, url_score=35.0, attachment_score=0.0, content_score=15.0, total_score=75.0),
        verdict=VerdictEnum.MALICIOUS,
        severity=SeverityEnum.HIGH,
        confidence_percentage=98.0,
        key_findings=["DMARC failed", "Malicious URL"],
        matched_rules=[
            RuleMatch(
                rule_id="PG-RULE-001",
                rule_name="Urgent Credential Harvesting Lure",
                severity="HIGH",
                score_impact=20.0,
                description="Urgent credential harvesting lure",
            )
        ],
        mitre_attack=[
            MitreTechnique(
                technique_id="T1566.002",
                technique_name="Spearphishing Link",
                tactic="Initial Access",
                description="Spearphishing link",
                attack_url="https://attack.mitre.org/techniques/T1566/002/",
            )
        ],
        written_explanation="Malicious payroll lure attempting to steal credentials.",
        remediation_steps=["Block domain", "Revoke user sessions"],
    )


def test_save_and_retrieve_incident(temp_soc_db, sample_incident):
    temp_soc_db.save_scan(sample_incident)

    retrieved = temp_soc_db.get_scan("PG-HUNT-001")
    assert retrieved is not None
    assert retrieved.scan_id == "PG-HUNT-001"
    assert retrieved.metadata.subject == "Urgent Payroll Update"
    assert retrieved.verdict == VerdictEnum.MALICIOUS
    assert retrieved.score.total_score == 75.0
    assert len(retrieved.matched_rules) == 1
    assert retrieved.matched_rules[0].rule_id == "PG-RULE-001"


def test_threat_hunting_search_filters(temp_soc_db, sample_incident):
    temp_soc_db.save_scan(sample_incident)

    # 1. Search by IP
    res_ip = temp_soc_db.search_incidents(IncidentQueryFilter(ip="198.51.100.55"))
    assert len(res_ip) == 1
    assert res_ip[0].scan_id == "PG-HUNT-001"

    # 2. Search by non-matching IP
    res_none = temp_soc_db.search_incidents(IncidentQueryFilter(ip="1.1.1.1"))
    assert len(res_none) == 0

    # 3. Search by domain
    res_dom = temp_soc_db.search_incidents(IncidentQueryFilter(domain="payroll-direct-update.com"))
    assert len(res_dom) == 1

    # 4. Search by MITRE technique
    res_mitre = temp_soc_db.search_incidents(IncidentQueryFilter(technique="T1566.002"))
    assert len(res_mitre) == 1

    # 5. Search by free text
    res_text = temp_soc_db.search_incidents(IncidentQueryFilter(query="Payroll"))
    assert len(res_text) == 1


def test_telemetry_stats(temp_soc_db, sample_incident):
    temp_soc_db.save_scan(sample_incident)

    stats = temp_soc_db.get_stats()
    assert stats["total_scans"] == 1
    assert stats["verdict_breakdown"]["malicious"] == 1
    assert stats["verdict_breakdown"]["clean"] == 0
    assert len(stats["top_attacker_ips"]) == 1
    assert stats["top_attacker_ips"][0]["ip"] == "198.51.100.55"
