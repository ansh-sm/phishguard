"""
Integration tests for Session 5 CLI commands and REST API endpoints.
"""

from pathlib import Path
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from phishguard.cli import app
from phishguard.server.app import app as fastapi_app

runner = CliRunner()
client = TestClient(fastapi_app)


def test_cli_remediate_sample_eml():
    result = runner.invoke(app, ["remediate", "samples/phishing_account_alert.eml", "--platform", "m365", "--offline"])
    assert result.exit_code == 0
    assert "PHISHGUARD SOAR INCIDENT REMEDIATION PACKAGE" in result.output
    assert "M365 Exchange Online Hard-Delete Purge" in result.output
    assert "Connect-IPPSSession" in result.output


def test_cli_hunt_and_stats():
    # Ingest a sample first to ensure data exists
    runner.invoke(app, ["scan", "samples/phishing_account_alert.eml", "--offline"])

    # Test hunt query
    result = runner.invoke(app, ["hunt", "--query", "PayPal"])
    assert result.exit_code == 0
    assert "SOC Threat Hunting Results" in result.output

    # Test stats output
    stats_result = runner.invoke(app, ["hunt", "--stats"])
    assert stats_result.exit_code == 0
    assert "PhishGuard SOC Threat Telemetry Statistics" in stats_result.output
    assert "Total Scans Ingested" in stats_result.output


def test_api_hunt_and_stats():
    # Query /api/stats
    resp_stats = client.get("/api/stats")
    assert resp_stats.status_code == 200
    data_stats = resp_stats.json()
    assert "total_scans" in data_stats
    assert "verdict_breakdown" in data_stats

    # Query /api/hunt
    resp_hunt = client.get("/api/hunt?verdict=MALICIOUS")
    assert resp_hunt.status_code == 200
    data_hunt = resp_hunt.json()
    assert "count" in data_hunt
    assert "results" in data_hunt
