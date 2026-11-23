"""Unit and integration tests for enterprise SIEM streaming forwarders."""

import base64
import json
from pathlib import Path
import httpx
import pytest

from phishguard.models.report import ScanResult
from phishguard.parser.eml_parser import EmlParser
from phishguard.siem.models import SiemConfig, SiemForwardResult, SiemTargetType
from phishguard.siem.forwarder import SiemForwarder
from phishguard.cli import _run_analysis


@pytest.fixture
def sample_scan_result() -> ScanResult:
    """Fixture providing an analyzed malicious email ScanResult."""
    sample_path = Path("samples/phishing_account_alert.eml")
    parser = EmlParser()
    parsed = parser.parse_file(sample_path)
    import asyncio
    return asyncio.run(_run_analysis(parsed, offline=True))


def test_build_splunk_payload(sample_scan_result: ScanResult):
    """Verify Splunk HEC JSON event formatting."""
    payload = SiemForwarder.build_splunk_payload(sample_scan_result, index="custom_index")
    assert payload["host"] == "phishguard-soc"
    assert payload["source"] == "phishguard:engine"
    assert payload["sourcetype"] == "phishguard:threat"
    assert payload["index"] == "custom_index"

    event = payload["event"]
    assert event["scan_id"] == sample_scan_result.scan_id
    assert event["verdict"] == sample_scan_result.verdict.value
    assert event["score"] == sample_scan_result.score.total_score
    assert "urls_count" in event
    assert "score_breakdown" in event


def test_build_elastic_payload(sample_scan_result: ScanResult):
    """Verify Elastic Common Schema (ECS 8.x) event formatting."""
    payload = SiemForwarder.build_elastic_payload(sample_scan_result, dataset="phishguard.custom")
    assert "@timestamp" in payload
    assert payload["event"]["category"] == ["email", "threat"]
    assert payload["event"]["dataset"] == "phishguard.custom"
    assert "threat" in payload
    assert "indicator" in payload["threat"]
    assert "email" in payload
    assert payload["phishguard"]["scan_id"] == sample_scan_result.scan_id


def test_sentinel_signature_and_payload(sample_scan_result: ScanResult):
    """Verify Azure Log Analytics HMAC-SHA256 SharedKey signature."""
    workspace_id = "12345678-abcd-1234-abcd-1234567890ab"
    dummy_key = base64.b64encode(b"dummy_secret_key_32_bytes_long!!").decode("utf-8")
    date_str = "Mon, 23 Nov 2026 12:00:00 GMT"

    sig = SiemForwarder.build_sentinel_signature(workspace_id, dummy_key, 120, date_str)
    assert sig.startswith(f"SharedKey {workspace_id}:")

    payload = SiemForwarder.build_sentinel_payload(sample_scan_result)
    assert isinstance(payload, list)
    assert len(payload) == 1
    item = payload[0]
    assert item["ScanId"] == sample_scan_result.scan_id
    assert item["Verdict"] == sample_scan_result.verdict.value


def test_forward_scan_result_splunk_mock(sample_scan_result: ScanResult):
    """Verify mock HTTP dispatch for Splunk HEC."""
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Splunk test_token"
        assert request.headers["Content-Type"] == "application/json"
        body = json.loads(request.read())
        assert body["index"] == "phishguard_threats"
        return httpx.Response(200, json={"text": "Success", "code": 0})

    transport = httpx.MockTransport(handler)
    config = SiemConfig(
        target_type=SiemTargetType.SPLUNK_HEC,
        endpoint_url="https://splunk.test/services/collector/event",
        auth_token="test_token",
        index_name="phishguard_threats",
    )

    res = SiemForwarder.forward_scan_result(config, sample_scan_result, transport=transport)
    assert res.success is True
    assert res.status_code == 200
    assert res.events_forwarded == 1


def test_forward_scan_result_failure_handling(sample_scan_result: ScanResult):
    """Verify error handling on HTTP 401 Unauthorized from destination SIEM."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"text": "Invalid token", "code": 4})

    transport = httpx.MockTransport(handler)
    config = SiemConfig(
        target_type=SiemTargetType.SPLUNK_HEC,
        endpoint_url="https://splunk.test/services/collector/event",
        auth_token="bad_token",
    )

    res = SiemForwarder.forward_scan_result(config, sample_scan_result, transport=transport)
    assert res.success is False
    assert res.status_code == 401
    assert "HTTP 401" in res.error_message


def test_test_connection_diagnostic():
    """Verify diagnostic heartbeat forwarding to SIEM."""
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        body = json.loads(request.read())
        assert "event" in body or "@timestamp" in body or "test_event" in body
        return httpx.Response(200, text='{"status":"ok"}')

    transport = httpx.MockTransport(handler)
    config = SiemConfig(
        target_type=SiemTargetType.ELASTIC_ECS,
        endpoint_url="https://elastic.test/_doc",
        api_key="mock_api_key",
    )

    res = SiemForwarder.test_connection(config, transport=transport)
    assert called is True
    assert res.success is True
    assert res.status_code == 200
