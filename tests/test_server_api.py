"""
Integration tests for PhishGuard FastAPI Server & Endpoints.
"""

from pathlib import Path
import pytest
from httpx import ASGITransport, AsyncClient

from phishguard.server.app import app


@pytest.fixture
def samples_dir() -> Path:
    return Path(__file__).parent.parent / "samples"


@pytest.mark.asyncio
async def test_health_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "engine" in data


@pytest.mark.asyncio
async def test_dashboard_ui_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/")
        assert resp.status_code == 200
        assert "<!DOCTYPE html>" in resp.text
        assert "PhishGuard SOC" in resp.text


@pytest.mark.asyncio
async def test_api_scan_upload(samples_dir: Path):
    eml_file = samples_dir / "phishing_account_alert.eml"
    assert eml_file.exists()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        files = {"file": ("phishing_account_alert.eml", eml_file.read_bytes(), "message/rfc822")}
        resp = await client.post("/api/scan?offline=true", files=files)
        assert resp.status_code == 200
        data = resp.json()
        assert "scan_id" in data
        assert data["verdict"] == "MALICIOUS"
        assert data["score"]["total_score"] >= 60.0
