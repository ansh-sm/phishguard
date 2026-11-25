"""Automated CLI and REST API integration tests for Session 8 (Sandbox & Case Management)."""

import re
from unittest.mock import patch
from fastapi.testclient import TestClient
import pytest
from typer.testing import CliRunner

from phishguard.cli import app
from phishguard.sandbox import DetonationVerdict, UrlDetonator, UrlDetonationResult
from phishguard.server.app import app as fastapi_app

runner = CliRunner()
client = TestClient(fastapi_app)


def test_cli_sandbox_command_json():
    """Verify CLI 'sandbox' command outputs valid JSON detonation results."""
    mock_result = UrlDetonationResult(
        target_url="http://suspicious-login.xyz",
        final_url="http://suspicious-login.xyz/login",
        status_code=200,
        page_title="Sign in to your account",
        verdict=DetonationVerdict.MALICIOUS,
        risk_score=85.0,
        has_credential_harvesting_form=True,
        suspicious_indicators=["Interactive credential harvesting password input discovered"],
    )

    with patch.object(UrlDetonator, "detonate", return_value=mock_result):
        res = runner.invoke(app, ["sandbox", "http://suspicious-login.xyz", "--json"])
        assert res.exit_code == 0
        assert '"verdict": "MALICIOUS"' in res.output
        assert '"risk_score": 85.0' in res.output


def test_cli_sandbox_command_rich_tables():
    """Verify CLI 'sandbox' command renders human-readable Rich analysis tables."""
    mock_result = UrlDetonationResult(
        target_url="http://clean-landing.com",
        final_url="http://clean-landing.com",
        status_code=200,
        page_title="Clean Portal",
        verdict=DetonationVerdict.BENIGN,
        risk_score=5.0,
    )

    with patch.object(UrlDetonator, "detonate", return_value=mock_result):
        res = runner.invoke(app, ["sandbox", "http://clean-landing.com"])
        assert res.exit_code == 0
        assert "Final URL:" in res.output
        assert "BENIGN" in res.output


def test_cli_case_create_and_list_workflow():
    """Verify CLI 'case create' from .eml and subsequent 'case list' queue rendering."""
    res_create = runner.invoke(app, [
        "case", "create", "samples/phishing_account_alert.eml",
        "--analyst", "tier1-responder",
    ])
    assert res_create.exit_code == 0
    assert "SOC Incident Case Ticket Opened Successfully" in res_create.output
    assert "CASE-" in res_create.output

    # List cases
    res_list = runner.invoke(app, ["case", "list"])
    assert res_list.exit_code == 0
    assert "SOC Incident Case Queue" in res_list.output
    assert "CASE-" in res_list.output


def test_cli_case_view_and_update():
    """Verify CLI 'case view', dossier flag, and 'case update' status transitions."""
    res_create = runner.invoke(app, ["case", "create", "samples/phishing_account_alert.eml"])
    match = re.search(r"CASE-\d+-[A-Z0-9]+", res_create.output)
    assert match is not None
    case_id = match.group(0)

    # View case
    res_view = runner.invoke(app, ["case", "view", case_id])
    assert res_view.exit_code == 0
    assert case_id in res_view.output

    # View dossier
    res_dossier = runner.invoke(app, ["case", "view", case_id, "--dossier"])
    assert res_dossier.exit_code == 0
    assert f"# SOC Incident Dossier: {case_id}" in res_dossier.output

    # Update case
    res_update = runner.invoke(app, [
        "case", "update", case_id,
        "--status", "IN_TRIAGE",
        "--analyst", "tier2-specialist",
        "--note", "Forensic memory dump verified malicious lure.",
    ])
    assert res_update.exit_code == 0
    assert "successfully updated" in res_update.output
    assert "IN_TRIAGE" in res_update.output


def test_api_sandbox_detonate_endpoint():
    """Verify FastAPI 'POST /api/sandbox/detonate' endpoint."""
    mock_result = UrlDetonationResult(
        target_url="http://detonate-api.com",
        final_url="http://detonate-api.com",
        status_code=200,
        verdict=DetonationVerdict.BENIGN,
        risk_score=10.0,
    )

    with patch.object(UrlDetonator, "detonate", return_value=mock_result):
        resp = client.post("/api/sandbox/detonate", json={"url": "http://detonate-api.com", "timeout": 6.0})
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "BENIGN"
        assert data["target_url"] == "http://detonate-api.com"


def test_api_cases_crud_lifecycle():
    """Verify full REST API CRUD lifecycle for cases."""
    # 1. Create Case
    create_payload = {
        "title": "API Test Incident",
        "severity": "CRITICAL",
        "sender": "threat@adversary.ru",
        "subject": "Tax Refund Phish",
        "score": 90.0,
        "summary": "Credential harvesting attack targeting tax documents.",
        "assigned_analyst": "api-analyst",
    }
    res_create = client.post("/api/cases", json=create_payload)
    assert res_create.status_code == 200
    case_data = res_create.json()
    case_id = case_data["case_id"]
    assert case_id.startswith("CASE-")
    assert case_data["severity"] == "CRITICAL"

    # 2. List Cases
    res_list = client.get("/api/cases?severity=CRITICAL")
    assert res_list.status_code == 200
    cases_list = res_list.json()
    assert any(c["case_id"] == case_id for c in cases_list)

    # 3. Get Case
    res_get = client.get(f"/api/cases/{case_id}")
    assert res_get.status_code == 200
    assert res_get.json()["title"] == "API Test Incident"

    # 4. Patch Case
    patch_payload = {
        "status": "CONTAINED",
        "note": "Firewall block rules established across perimeter.",
        "note_analyst": "secops-bot",
    }
    res_patch = client.patch(f"/api/cases/{case_id}", json=patch_payload)
    assert res_patch.status_code == 200
    updated_data = res_patch.json()
    assert updated_data["status"] == "CONTAINED"
    assert any("Firewall block rules" in n["message"] for n in updated_data["timeline"])

    # 5. Get Dossier (Markdown & JSON)
    res_dossier_md = client.get(f"/api/cases/{case_id}/dossier?format=markdown")
    assert res_dossier_md.status_code == 200
    assert f"# SOC Incident Dossier: {case_id}" in res_dossier_md.text

    res_dossier_json = client.get(f"/api/cases/{case_id}/dossier?format=json")
    assert res_dossier_json.status_code == 200
    assert case_id in res_dossier_json.text
