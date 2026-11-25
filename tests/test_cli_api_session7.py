"""Tests for CLI commands and FastAPI REST endpoints introduced in Session 7."""

from unittest.mock import patch
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from phishguard.cli import app
from phishguard.server.app import app as fastapi_app
from phishguard.forensics.dns_validator import (
    DnsPolicyValidator,
    DomainDnsInspection,
    DmarcValidationResult,
    SpfValidationResult,
)

runner = CliRunner()
client = TestClient(fastapi_app)


def test_cli_triage_intent_command():
    """Verify CLI 'triage-intent' command prints cognitive report."""
    res = runner.invoke(app, [
        "triage-intent",
        "samples/phishing_account_alert.eml",
        "--provider", "offline",
    ])
    assert res.exit_code == 0
    assert "AI Phishing Intent & Cognitive Triage Report" in res.stdout
    assert "Primary Intent:" in res.stdout
    assert "Urgency Index:" in res.stdout


def test_cli_triage_intent_summary_flag():
    """Verify CLI 'triage-intent' with '--summary' outputs concise assessment."""
    res = runner.invoke(app, [
        "triage-intent",
        "samples/phishing_account_alert.eml",
        "--summary",
    ])
    assert res.exit_code == 0
    assert "Executive Summary:" in res.stdout


def test_cli_dns_check_command():
    """Verify CLI 'dns-check' command outputs formatted protocol audit table."""
    mock_audit = DomainDnsInspection(
        domain="paypa1-update.com",
        originating_ip="185.220.101.5",
        mx_records=["mail.paypa1-update.com"],
        spf=SpfValidationResult(
            domain="paypa1-update.com",
            has_spf=True,
            ip_authorized=False,
            qualifier="-",
            raw_record="v=spf1 -all",
        ),
        dmarc=DmarcValidationResult(
            domain="paypa1-update.com",
            has_dmarc=True,
            policy="none",
            raw_record="v=DMARC1; p=none",
        ),
        risk_score=75.0,
        risk_reasons=["Originating IP unauthorized by SPF.", "DMARC policy is none."],
    )

    with patch.object(DnsPolicyValidator, "inspect_domain", return_value=mock_audit):
        res = runner.invoke(app, [
            "dns-check",
            "paypa1-update.com",
            "--ip", "185.220.101.5",
        ])
        assert res.exit_code == 0
        assert "DNS Authentication Audit: paypa1-update.com" in res.stdout
        assert "SPF (v=spf1)" in res.stdout
        assert "DMARC (v=DMARC1)" in res.stdout
        assert "DNS Security Risk Score:" in res.stdout


def test_api_ai_triage_endpoint():
    """Verify POST /api/ai/triage REST endpoint."""
    resp = client.post("/api/ai/triage", json={
        "subject": "Action Required: Reset Password Immediately",
        "body_text": "Your account has been locked. Click the link to verify your password within 24 hours.",
        "from_name": "Security Support",
        "from_email": "support@alert-security.xyz",
        "provider": "offline",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["primary_intent"] == "CREDENTIAL_HARVEST"
    assert data["urgency_score"] > 0.0
    assert "executive_summary" in data


def test_api_dns_verify_endpoint():
    """Verify GET /api/dns/verify/{domain} REST endpoint."""
    mock_audit = DomainDnsInspection(
        domain="test-corp.com",
        originating_ip=None,
        mx_records=[],
        spf=SpfValidationResult(domain="test-corp.com", has_spf=False),
        dmarc=DmarcValidationResult(domain="test-corp.com", has_dmarc=False),
        risk_score=55.0,
        risk_reasons=["Missing SPF", "Missing DMARC"],
    )

    with patch.object(DnsPolicyValidator, "inspect_domain", return_value=mock_audit):
        resp = client.get("/api/dns/verify/test-corp.com")
        assert resp.status_code == 200
        data = resp.json()
        assert data["domain"] == "test-corp.com"
        assert "spf" in data
        assert "dmarc" in data
        assert data["risk_score"] == 55.0
