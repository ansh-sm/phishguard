"""
Tests for new CLI commands (test-rules, alert-test) and REST API rules endpoint.
"""

from pathlib import Path
from typer.testing import CliRunner
from fastapi.testclient import TestClient

from phishguard.cli import app
from phishguard.server.app import app as fastapi_app

runner = CliRunner()
client = TestClient(fastapi_app)


def test_cli_test_rules():
    result = runner.invoke(app, ["test-rules", "--rules-dir", "rules", "--samples-dir", "samples"])
    assert result.exit_code == 0
    assert "Rule Evaluation Detection Matrix" in result.output
    assert "PG-RULE-001" in result.output
    assert "phishing_account_alert.eml" in result.output


def test_cli_alert_test_invalid_url():
    # Attempting to send to a non-existent port on localhost should gracefully fail without crashing
    result = runner.invoke(app, ["alert-test", "--webhook-url", "http://127.0.0.1:59999/webhook", "--webhook-type", "generic"])
    assert result.exit_code == 0
    assert "Failed to deliver test alert" in result.output or "Dispatching simulated incident alert" in result.output


def test_api_get_rules():
    response = client.get("/api/rules?rules_dir=rules")
    assert response.status_code == 200
    data = response.json()
    assert "total_rules" in data
    assert data["total_rules"] >= 5
    rule_ids = [r["id"] for r in data["rules"]]
    assert "PG-RULE-001" in rule_ids
    assert "PG-RULE-002" in rule_ids
