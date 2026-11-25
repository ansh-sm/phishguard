"""Automated unit and integration tests for SOC Incident Case Management."""

import asyncio
from pathlib import Path
import pytest
from phishguard.cases import (
    CaseIoc,
    CaseManager,
    CaseSeverity,
    CaseStatus,
    SocCase,
)
from phishguard.cli import _run_analysis
from phishguard.models.email import EmailMetadata
from phishguard.models.report import ScanResult, ScoreBreakdown, VerdictEnum
from phishguard.parser.eml_parser import EmlParser


@pytest.fixture
def temp_case_manager(tmp_path: Path) -> CaseManager:
    """Fixture providing isolated CaseManager with temporary SQLite database."""
    db_file = tmp_path / "test_cases.db"
    return CaseManager(db_path=db_file)


def test_create_case_basic(temp_case_manager: CaseManager):
    """Verify manual SOC case ticket creation with auto-generated ID and audit trail."""
    case = temp_case_manager.create_case(
        title="Suspicious Wire Transfer Request",
        severity=CaseSeverity.HIGH,
        sender="ceo@compromised-csuite.org",
        subject="Urgent: Wire Payment for Acquisition",
        score=78.5,
        summary="BEC impersonation attempt targeting finance controller.",
        assigned_analyst="tier2-analyst",
    )

    assert isinstance(case, SocCase)
    assert case.case_id.startswith("CASE-")
    assert case.status == CaseStatus.NEW
    assert case.severity == CaseSeverity.HIGH
    assert case.assigned_analyst == "tier2-analyst"
    assert len(case.timeline) == 1
    assert "Case opened" in case.timeline[0].message


def test_create_case_from_scan_result(temp_case_manager: CaseManager):
    """Verify automatic translation of a completed email scan result into a tracked case."""
    parser = EmlParser()
    parsed = parser.parse_file("samples/phishing_account_alert.eml")
    scan = asyncio.run(_run_analysis(parsed, offline=True))

    case = temp_case_manager.create_case_from_scan(scan, assigned_analyst="soc-lead")

    assert case.case_id.startswith("CASE-")
    assert case.severity in (CaseSeverity.HIGH, CaseSeverity.CRITICAL)
    assert case.score > 50.0
    assert case.sender == parsed.metadata.from_email
    assert case.assigned_analyst == "soc-lead"
    assert len(case.iocs) >= 1
    ioc_types = [i.ioc_type for i in case.iocs]
    assert "ip" in ioc_types or "domain" in ioc_types or "url" in ioc_types


def test_list_cases_and_filter(temp_case_manager: CaseManager):
    """Verify case querying with severity and lifecycle status filters."""
    temp_case_manager.create_case(title="Low Risk Newsletter", severity=CaseSeverity.LOW)
    temp_case_manager.create_case(title="Critical Macro Dropper", severity=CaseSeverity.CRITICAL)
    temp_case_manager.create_case(title="High Credential Phish", severity=CaseSeverity.HIGH)

    all_cases = temp_case_manager.list_cases()
    assert len(all_cases) == 3

    critical_cases = temp_case_manager.list_cases(severity="CRITICAL")
    assert len(critical_cases) == 1
    assert critical_cases[0].title == "Critical Macro Dropper"

    low_cases = temp_case_manager.list_cases(severity="LOW")
    assert len(low_cases) == 1


def test_update_case_status_and_reassignment(temp_case_manager: CaseManager):
    """Verify lifecycle progression from NEW to IN_TRIAGE to CONTAINED."""
    case = temp_case_manager.create_case(title="Test Investigation", severity=CaseSeverity.MEDIUM)

    updated = temp_case_manager.update_case(
        case.case_id,
        status=CaseStatus.IN_TRIAGE,
        assigned_analyst="tier2-specialist",
    )
    assert updated is not None
    assert updated.status == CaseStatus.IN_TRIAGE
    assert updated.assigned_analyst == "tier2-specialist"
    assert len(updated.timeline) >= 2


def test_add_analyst_note_and_auto_transition(temp_case_manager: CaseManager):
    """Verify appending investigation notes automatically transitions NEW cases to IN_TRIAGE."""
    case = temp_case_manager.create_case(title="Pending Triage", severity=CaseSeverity.HIGH)
    assert case.status == CaseStatus.NEW

    updated = temp_case_manager.add_note(
        case_id=case.case_id,
        analyst="analyst_alice",
        message="Confirmed malware payload in attachment. Submitting to sandbox.",
    )
    assert updated is not None
    assert updated.status == CaseStatus.IN_TRIAGE
    assert any(n.analyst == "analyst_alice" for n in updated.timeline)


def test_update_ioc_containment_status(temp_case_manager: CaseManager):
    """Verify tracking containment actions on linked IOC artifacts."""
    ioc = CaseIoc(ioc_type="ip", value="198.51.100.99", status="PENDING")
    case = temp_case_manager.create_case(title="Case with IOCs", iocs=[ioc])

    updated = temp_case_manager.update_ioc_status(case.case_id, "198.51.100.99", "BLOCKED")
    assert updated is not None
    assert updated.iocs[0].status == "BLOCKED"
    assert any("BLOCKED" in n.message for n in updated.timeline)


def test_export_case_dossier_markdown_and_json(temp_case_manager: CaseManager):
    """Verify dossier export formatting for SOC shift handoffs and incident reporting."""
    case = temp_case_manager.create_case(
        title="Dossier Test Case",
        severity=CaseSeverity.CRITICAL,
        sender="attacker@spoofed.com",
        subject="Account Lockout",
        score=92.0,
        summary="Critical adversary campaign targeting executive accounts.",
    )

    md_dossier = temp_case_manager.export_case_dossier(case.case_id, format="markdown")
    assert f"# SOC Incident Dossier: {case.case_id}" in md_dossier
    assert "CRITICAL" in md_dossier
    assert "attacker@spoofed.com" in md_dossier

    json_dossier = temp_case_manager.export_case_dossier(case.case_id, format="json")
    assert case.case_id in json_dossier
    assert '"severity": "CRITICAL"' in json_dossier
