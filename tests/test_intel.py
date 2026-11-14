"""
Unit tests for Threat Intelligence Caching and Async Pipeline.
"""

from pathlib import Path
import pytest

from phishguard.intel.cache import IntelCache
from phishguard.intel.pipeline import ThreatIntelPipeline
from phishguard.models.forensics import UrlArtifact


@pytest.fixture
def temp_cache(tmp_path: Path) -> IntelCache:
    db_file = tmp_path / "test_intel_cache.db"
    return IntelCache(db_path=db_file, default_ttl_hours=24)


def test_intel_cache_lifecycle(temp_cache: IntelCache):
    url = "http://malicious-test-link.com/login"
    temp_cache.set(
        provider="urlhaus",
        url=url,
        is_flagged=True,
        tags=["malware", "phishing"],
        details={"threat": "credential_harvest"},
        ttl_hours=1,
    )

    hit = temp_cache.get("urlhaus", url)
    assert hit is not None
    assert hit["is_flagged"] is True
    assert "malware" in hit["tags"]
    assert hit["details"]["threat"] == "credential_harvest"

    # Miss for a different URL
    miss = temp_cache.get("urlhaus", "http://another-clean-site.org")
    assert miss is None


@pytest.mark.asyncio
async def test_threat_intel_pipeline_offline_with_cache(temp_cache: IntelCache):
    target_url = "http://confirmed-phish-domain.com/auth"
    # Seed cache
    temp_cache.set(
        provider="phishtank",
        url=target_url,
        is_flagged=True,
        tags=["phishing", "verified"],
        details={"verified": True},
    )

    pipeline = ThreatIntelPipeline(cache=temp_cache)
    artifact = UrlArtifact(
        raw_url=target_url,
        defanged_url="hxxp://confirmed-phish-domain[.]com/auth",
        domain="confirmed-phish-domain.com",
        tld="com",
        scheme="http",
    )

    enriched = await pipeline.enrich_url(artifact, offline=True)

    assert enriched.threat_intel_flagged is True
    assert "PhishTank (Cache)" in enriched.threat_intel_source
    assert enriched.risk_score >= 85.0
    assert any("PhishTank" in r for r in enriched.risk_reasons)
