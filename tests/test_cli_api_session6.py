"""Tests for CLI commands and FastAPI REST endpoints introduced in Session 6."""

from unittest.mock import patch
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from phishguard.cli import app
from phishguard.server.app import app as fastapi_app
from phishguard.siem.models import SiemForwardResult, SiemTargetType

runner = CliRunner()
client = TestClient(fastapi_app)


def test_cli_forward_command_success():
    """Verify CLI 'forward' command dispatches to SIEM."""
    mock_res = SiemForwardResult(
        success=True,
        target_type=SiemTargetType.SPLUNK_HEC,
        status_code=200,
        response_body='{"code": 0}',
        events_forwarded=1,
    )
    with patch("phishguard.siem.forwarder.SiemForwarder.forward_scan_result", return_value=mock_res):
        res = runner.invoke(app, [
            "forward",
            "samples/phishing_account_alert.eml",
            "--target", "splunk",
            "--url", "https://splunk.corp:8088/services/collector/event",
            "--token", "test_hec_token",
            "--offline",
        ])
        assert res.exit_code == 0
        assert "Successfully forwarded incident to SPLUNK" in res.stdout


def test_cli_forward_test_command():
    """Verify CLI 'forward-test' healthcheck command."""
    mock_res = SiemForwardResult(
        success=True,
        target_type=SiemTargetType.ELASTIC_ECS,
        status_code=200,
        response_body='{"status": "ok"}',
        events_forwarded=1,
    )
    with patch("phishguard.siem.forwarder.SiemForwarder.test_connection", return_value=mock_res):
        res = runner.invoke(app, [
            "forward-test",
            "--target", "elastic",
            "--url", "https://elastic.corp:9200/_doc",
            "--api-key", "secret_key",
        ])
        assert res.exit_code == 0
        assert "Connection test PASSED" in res.stdout


def test_cli_campaign_hunt_command():
    """Verify CLI 'campaign-hunt' command output."""
    res = runner.invoke(app, ["campaign-hunt", "--min-size", "1"])
    assert res.exit_code == 0
    # Output should either list campaigns or state none available
    assert "Active Adversary Campaigns" in res.stdout or "No historical incidents" in res.stdout


def test_cli_graph_command():
    """Verify CLI 'graph' command prints Mermaid attack topology."""
    res = runner.invoke(app, [
        "graph",
        "samples/phishing_account_alert.eml",
        "--format", "mermaid",
        "--offline",
    ])
    assert res.exit_code == 0
    assert "flowchart LR" in res.stdout


def test_api_campaigns_and_graph_endpoints():
    """Verify FastAPI /api/campaigns and /api/graph endpoints."""
    # First upload a sample to have a scan in cache
    with open("samples/phishing_account_alert.eml", "rb") as f:
        scan_resp = client.post("/api/scan", files={"file": ("alert.eml", f, "message/rfc822")})
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()
    scan_id = scan_data["scan_id"]

    # Test /api/graph/{scan_id}
    graph_resp = client.get(f"/api/graph/{scan_id}")
    assert graph_resp.status_code == 200
    g_data = graph_resp.json()
    assert "mermaid" in g_data
    assert "graph" in g_data
    assert g_data["mermaid"].startswith("flowchart LR")

    # Test /api/campaigns
    camp_resp = client.get("/api/campaigns?min_size=1")
    assert camp_resp.status_code == 200
    c_data = camp_resp.json()
    assert "count" in c_data
    assert "campaigns" in c_data


def test_api_siem_endpoints():
    """Verify /api/siem/test and /api/siem/forward endpoints."""
    mock_res = SiemForwardResult(
        success=True,
        target_type=SiemTargetType.SPLUNK_HEC,
        status_code=200,
        response_body='{"code": 0}',
        events_forwarded=1,
    )
    with patch("phishguard.siem.forwarder.SiemForwarder.test_connection", return_value=mock_res):
        resp = client.post("/api/siem/test", json={
            "target_type": "splunk",
            "endpoint_url": "https://splunk.test:8088",
            "auth_token": "token123",
            "index_name": "main",
        })
        assert resp.status_code == 200
        assert resp.json()["success"] is True

    # Scan an email
    with open("samples/phishing_account_alert.eml", "rb") as f:
        scan_resp = client.post("/api/scan", files={"file": ("alert.eml", f, "message/rfc822")})
    scan_id = scan_resp.json()["scan_id"]

    with patch("phishguard.siem.forwarder.SiemForwarder.forward_scan_result", return_value=mock_res):
        resp = client.post("/api/siem/forward", json={
            "scan_id": scan_id,
            "config": {
                "target_type": "splunk",
                "endpoint_url": "https://splunk.test:8088",
                "auth_token": "token123",
                "index_name": "main",
            }
        })
        assert resp.status_code == 200
        assert resp.json()["success"] is True
        assert resp.json()["events_forwarded"] == 1
