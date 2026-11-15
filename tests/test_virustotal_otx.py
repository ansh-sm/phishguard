"""
Unit tests for VirusTotal v3 and AlienVault OTX clients.
"""

from pathlib import Path
import pytest

from phishguard.intel.cache import IntelCache
from phishguard.intel.otx import OTXClient
from phishguard.intel.virustotal import VirusTotalClient


@pytest.fixture
def temp_cache(tmp_path: Path) -> IntelCache:
    return IntelCache(db_path=tmp_path / "test_vt_otx.db")


def test_vt_url_to_id():
    url = "http://malicious-phish.com/verify"
    vt_id = VirusTotalClient.url_to_vt_id(url)
    assert vt_id is not None
    assert "=" not in vt_id  # Padding stripped per API v3 spec


@pytest.mark.asyncio
async def test_virustotal_cache_hit(temp_cache: IntelCache):
    url = "http://phish-target.com/login"
    temp_cache.set(
        provider="virustotal",
        url=url,
        is_flagged=True,
        tags=["vt_malicious:5/80"],
        details={"malicious_count": 5},
    )

    client = VirusTotalClient(cache=temp_cache)
    result = await client.check_url(url)

    assert result["is_flagged"] is True
    assert result["cached"] is True
    assert "vt_malicious:5/80" in result["tags"]


@pytest.mark.asyncio
async def test_otx_ip_cache_hit(temp_cache: IntelCache):
    ip = "185.220.101.5"
    temp_cache.set(
        provider="otx_ip",
        url=ip,
        is_flagged=True,
        tags=["otx_pulses:3"],
        details={"pulse_count": 3},
    )

    client = OTXClient(cache=temp_cache)
    result = await client.check_ip(ip)

    assert result["is_flagged"] is True
    assert result["cached"] is True
    assert result["details"]["pulse_count"] == 3
