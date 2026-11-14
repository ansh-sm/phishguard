"""
Threat Intelligence Pipeline Orchestrator.
"""

import asyncio
from typing import Optional

from phishguard.intel.cache import IntelCache
from phishguard.intel.phishtank import PhishTankClient
from phishguard.intel.urlhaus import UrlhausClient
from phishguard.models.forensics import UrlArtifact


class ThreatIntelPipeline:
    """
    Coordinates asynchronous enrichment across threat intelligence providers.
    Supports concurrent lookups, caching, and offline air-gap execution.
    """

    def __init__(
        self,
        cache: Optional[IntelCache] = None,
        phishtank_key: Optional[str] = None,
        timeout_seconds: float = 4.0,
    ):
        self.cache = cache or IntelCache()
        self.urlhaus = UrlhausClient(cache=self.cache, timeout_seconds=timeout_seconds)
        self.phishtank = PhishTankClient(api_key=phishtank_key, cache=self.cache, timeout_seconds=timeout_seconds)

    async def enrich_url(self, artifact: UrlArtifact, offline: bool = False) -> UrlArtifact:
        """Enrich a single UrlArtifact with threat intelligence findings."""
        if offline:
            # In offline mode, check local cache only, do not hit network
            cached_urlhaus = self.cache.get("urlhaus", artifact.raw_url)
            cached_phishtank = self.cache.get("phishtank", artifact.raw_url)

            if cached_urlhaus and cached_urlhaus["is_flagged"]:
                artifact.threat_intel_flagged = True
                artifact.threat_intel_source = "URLhaus (Cache)"
                artifact.threat_intel_tags = cached_urlhaus["tags"]
                artifact.threat_intel_details = cached_urlhaus["details"]
                artifact.risk_reasons.append("Confirmed malicious URL listed in URLhaus malware database (Cached).")
                artifact.risk_score = max(artifact.risk_score, 85.0)

            elif cached_phishtank and cached_phishtank["is_flagged"]:
                artifact.threat_intel_flagged = True
                artifact.threat_intel_source = "PhishTank (Cache)"
                artifact.threat_intel_tags = cached_phishtank["tags"]
                artifact.threat_intel_details = cached_phishtank["details"]
                artifact.risk_reasons.append("Confirmed verified phishing link listed in PhishTank database (Cached).")
                artifact.risk_score = max(artifact.risk_score, 85.0)

            return artifact

        # Concurrent async queries
        urlhaus_task = self.urlhaus.check_url(artifact.raw_url)
        phishtank_task = self.phishtank.check_url(artifact.raw_url)

        res_urlhaus, res_phishtank = await asyncio.gather(urlhaus_task, phishtank_task)

        if res_urlhaus.get("is_flagged"):
            artifact.threat_intel_flagged = True
            artifact.threat_intel_source = "URLhaus"
            artifact.threat_intel_tags = res_urlhaus.get("tags", [])
            artifact.threat_intel_details = res_urlhaus.get("details", {})
            artifact.risk_reasons.append(
                f"Confirmed malicious URL listed in URLhaus database (Threat: {res_urlhaus.get('threat_type')})."
            )
            artifact.risk_score = max(artifact.risk_score, 90.0)

        elif res_phishtank.get("is_flagged"):
            artifact.threat_intel_flagged = True
            artifact.threat_intel_source = "PhishTank"
            artifact.threat_intel_tags = res_phishtank.get("tags", [])
            artifact.threat_intel_details = res_phishtank.get("details", {})
            artifact.risk_reasons.append("Confirmed verified phishing URL listed in PhishTank database.")
            artifact.risk_score = max(artifact.risk_score, 90.0)

        return artifact

    async def enrich_all(self, artifacts: list[UrlArtifact], offline: bool = False) -> list[UrlArtifact]:
        """Enrich a batch of URLs concurrently."""
        tasks = [self.enrich_url(artifact, offline=offline) for artifact in artifacts]
        return await asyncio.gather(*tasks)
