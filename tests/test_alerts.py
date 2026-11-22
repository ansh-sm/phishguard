"""
Unit and integration tests for PhishGuard SOC multi-channel alerting dispatcher.
"""

from datetime import datetime, timezone
import pytest
import httpx

from phishguard.alerts.dispatcher import AlertDispatcher
from phishguard.alerts.models import AlertConfig, AlertWebhookType
from phishguard.models.email import AuthenticationResults, AuthStatus, EmailMetadata
from phishguard.models.forensics import HeaderAnalysis, UrlArtifact
from phishguard.models.report import MitreTechnique, RuleMatch, ScanResult, ScoreBreakdown, SeverityEnum, VerdictEnum


@pytest.fixture
def mock_scan_result() -> ScanResult:
    return ScanResult(
        scan_id="PG-ALERT-TEST01",
        timestamp=datetime.now(timezone.utc),
        eml_file_path="test_alert.eml",
        eml_file_hash_sha256="abc123sha256",
        metadata=EmailMetadata(
            subject="Urgent Security Verification",
            from_address="attacker@evil-phish.com",
            from_name="Security Alert",
            from_raw='"Security Alert" <attacker@evil-phish.com>',
            to_addresses=["target@company.com"],
            date="Sun, 22 Nov 2026 10:00:00 +0000",
        ),
        headers=HeaderAnalysis(
            hops=[],
            originating_ip="198.51.100.99",
            auth=AuthenticationResults(spf_status=AuthStatus.FAIL, dkim_status=AuthStatus.FAIL, dmarc_status=AuthStatus.FAIL),
            risk_score=25.0,
        ),
        urls=[
            UrlArtifact(
                raw_url="http://evil-phish.com/login",
                defanged_url="hxxp://evil-phish[.]com/login",
                domain="evil-phish.com",
                tld="com",
                scheme="http",
                threat_intel_flagged=True,
                threat_intel_source="PhishTank",
            )
        ],
        score=ScoreBreakdown(header_score=25.0, url_score=35.0, attachment_score=0.0, content_score=15.0, total_score=75.0),
        verdict=VerdictEnum.MALICIOUS,
        severity=SeverityEnum.HIGH,
        confidence_percentage=98.0,
        key_findings=["DMARC failed", "Malicious URL detected"],
        matched_rules=[
            RuleMatch(
                rule_id="PG-RULE-001",
                rule_name="Urgent Credential Harvesting Lure",
                severity="HIGH",
                score_impact=20.0,
                description="Urgent account suspension threat",
            )
        ],
        mitre_attack=[
            MitreTechnique(
                technique_id="T1566.002",
                technique_name="Spearphishing Link",
                tactic="Initial Access",
                description="Adversary delivers spearphishing link",
                evidence=["Phishing URL found"],
                attack_url="https://attack.mitre.org/techniques/T1566/002/",
            )
        ],
        written_explanation="Confirmed malicious phishing attempt targeting credentials.",
        remediation_steps=["Block sender domain.", "Sinkhole IP."],
    )


def test_should_alert_logic(mock_scan_result):
    # Alert when score >= min_score
    config_default = AlertConfig(webhook_url="https://hooks.slack.com/services/xxx", min_score=60.0)
    dispatcher = AlertDispatcher(config_default)
    assert dispatcher.should_alert(mock_scan_result) is True

    # Do not alert when disabled
    config_disabled = AlertConfig(webhook_url="https://hooks.slack.com/services/xxx", enabled=False)
    assert AlertDispatcher(config_disabled).should_alert(mock_scan_result) is False

    # Do not alert clean email below score
    clean_result = mock_scan_result.model_copy()
    clean_result.verdict = VerdictEnum.CLEAN
    clean_result.score.total_score = 10.0
    assert dispatcher.should_alert(clean_result) is False


def test_build_slack_payload(mock_scan_result):
    config = AlertConfig(webhook_url="https://hooks.slack.com/services/xxx", webhook_type=AlertWebhookType.SLACK)
    dispatcher = AlertDispatcher(config)
    payload = dispatcher.build_slack_payload(mock_scan_result)

    assert "text" in payload
    assert "blocks" in payload
    assert len(payload["blocks"]) >= 3
    block_texts = str(payload["blocks"])
    assert "PG-ALERT-TEST01" in block_texts
    assert "PG-RULE-001" in block_texts
    assert "T1566.002" in block_texts


def test_build_discord_payload(mock_scan_result):
    config = AlertConfig(webhook_url="https://discord.com/api/webhooks/xxx", webhook_type=AlertWebhookType.DISCORD)
    dispatcher = AlertDispatcher(config)
    payload = dispatcher.build_discord_payload(mock_scan_result)

    assert "embeds" in payload
    embed = payload["embeds"][0]
    assert embed["color"] == 0xEF4444  # Red for MALICIOUS
    field_names = [f["name"] for f in embed["fields"]]
    assert "PhishScore" in field_names
    assert "MITRE ATT&CK" in field_names


def test_build_teams_payload(mock_scan_result):
    config = AlertConfig(webhook_url="https://outlook.office.com/webhook/xxx", webhook_type=AlertWebhookType.TEAMS)
    dispatcher = AlertDispatcher(config)
    payload = dispatcher.build_teams_payload(mock_scan_result)

    assert payload["@type"] == "MessageCard"
    assert "sections" in payload
    assert len(payload["sections"][0]["facts"]) >= 5


def test_build_generic_payload_with_hmac(mock_scan_result):
    config = AlertConfig(
        webhook_url="https://siem.enterprise.com/api/alerts",
        webhook_type=AlertWebhookType.GENERIC,
        hmac_secret="super-secret-key-123",
    )
    dispatcher = AlertDispatcher(config)
    payload = dispatcher.build_generic_payload(mock_scan_result)

    assert payload["event_type"] == "phishguard.incident.alert"
    assert payload["scan_id"] == "PG-ALERT-TEST01"
    assert payload["verdict"] == "MALICIOUS"
    assert len(payload["matched_rules"]) == 1
    assert payload["iocs"]["defanged_urls"][0] == "hxxp://evil-phish[.]com/login"


@pytest.mark.asyncio
async def test_send_alert_mock_transport(mock_scan_result):
    config = AlertConfig(
        webhook_url="https://mock-soar.local/webhook",
        webhook_type=AlertWebhookType.GENERIC,
        hmac_secret="secret123",
    )
    dispatcher = AlertDispatcher(config)

    # Use custom mock transport to verify HTTP POST and headers
    recorded_requests = []

    def mock_handler(request: httpx.Request):
        recorded_requests.append(request)
        return httpx.Response(200, json={"status": "received"})

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        success = await dispatcher.send_alert(mock_scan_result, client=client)

    assert success is True
    assert len(recorded_requests) == 1
    req = recorded_requests[0]
    assert req.method == "POST"
    assert req.url == "https://mock-soar.local/webhook"
    assert "X-PhishGuard-Signature" in req.headers
    assert req.headers["X-PhishGuard-Signature"].startswith("sha256=")
