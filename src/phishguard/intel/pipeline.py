"""
Threat Intelligence Pipeline Orchestrator.
Unified asynchronous enrichment across URLhaus, PhishTank, VirusTotal, and AlienVault OTX.
"""

import asyncio
from typing import Optional

from phishguard.intel.cache import IntelCache
from phishguard.intel.otx import OTXClient
from phishguard.intel.phishtank import PhishTankClient
from phishguard.intel.urlhaus import UrlhausClient
from phishguard.intel.virustotal import VirusTotalClient
from phishguard.models.forensics import AttachmentArtifact, UrlArtifact


class ThreatIntelPipeline:
    """
    Coordinates asynchronous threat intelligence across all supported providers.
    Supports concurrent queries, local TTL caching, and complete offline air-gap mode.
    """

    def __init__(
        self,
        cache: Optional[IntelCache] = None,
        phishtank_key: Optional[str] = None,
        vt_key: Optional[str] = None,
        otx_key: Optional[str] = None,
        timeout_seconds: float = 4.0,
    ):
        self.cache = cache or IntelCache()
        self.urlhaus = UrlhausClient(cache=self.cache, timeout_seconds=timeout_seconds)
        self.phishtank = PhishTankClient(api_key=phishtank_key, cache=self.cache, timeout_seconds=timeout_seconds)
        self.virustotal = VirusTotalClient(api_key=vt_key, cache=self.cache, timeout_seconds=timeout_seconds)
        self.otx = OTXClient(api_key=otx_key, cache=self.cache, timeout_seconds=timeout_seconds)

    PROVIDER_NAMES = {
        "urlhaus": "URLhaus",
        "phishtank": "PhishTank",
        "virustotal": "VirusTotal",
        "otx": "AlienVault OTX",
    }

    async def enrich_url(self, artifact: UrlArtifact, offline: bool = False) -> UrlArtifact:
        """Enrich a single UrlArtifact with threat intelligence findings."""
        if offline:
            # Check local cache only
            for provider in ("urlhaus", "phishtank", "virustotal"):
                cached = self.cache.get(provider, artifact.raw_url)
                if cached and cached["is_flagged"]:
                    disp_name = self.PROVIDER_NAMES.get(provider, provider.capitalize())
                    artifact.threat_intel_flagged = True
                    artifact.threat_intel_source = f"{disp_name} (Cache)"
                    artifact.threat_intel_tags = cached["tags"]
                    artifact.threat_intel_details = cached["details"]
                    artifact.risk_reasons.append(f"Confirmed malicious URL listed in {disp_name} database (Cached).")
                    artifact.risk_score = max(artifact.risk_score, 85.0)
                    break
            return artifact

        # Concurrent async queries across all active URL providers
        urlhaus_task = self.urlhaus.check_url(artifact.raw_url)
        phishtank_task = self.phishtank.check_url(artifact.raw_url)
        vt_task = self.virustotal.check_url(artifact.raw_url)

        res_urlhaus, res_phishtank, res_vt = await asyncio.gather(
            urlhaus_task, phishtank_task, vt_task, return_exceptions=True
        )

        # Aggregate verdicts
        if isinstance(res_urlhaus, dict) and res_urlhaus.get("is_flagged"):
            artifact.threat_intel_flagged = True
            artifact.threat_intel_source = "URLhaus"
            artifact.threat_intel_tags = res_urlhaus.get("tags", [])
            artifact.threat_intel_details = res_urlhaus.get("details", {})
            artifact.risk_reasons.append(f"Confirmed malicious URL listed in URLhaus (Threat: {res_urlhaus.get('threat_type')}).")
            artifact.risk_score = max(artifact.risk_score, 90.0)

        elif isinstance(res_phishtank, dict) and res_phishtank.get("is_flagged"):
            artifact.threat_intel_flagged = True
            artifact.threat_intel_source = "PhishTank"
            artifact.threat_intel_tags = res_phishtank.get("tags", [])
            artifact.threat_intel_details = res_phishtank.get("details", {})
            artifact.risk_reasons.append("Confirmed verified phishing link listed in PhishTank database.")
            artifact.risk_score = max(artifact.risk_score, 90.0)

        elif isinstance(res_vt, dict) and res_vt.get("is_flagged"):
            artifact.threat_intel_flagged = True
            artifact.threat_intel_source = "VirusTotal"
            artifact.threat_intel_tags = res_vt.get("tags", [])
            artifact.threat_intel_details = res_vt.get("details", {})
            mal_count = res_vt.get("details", {}).get("malicious_count", 0)
            artifact.risk_reasons.append(f"Confirmed malicious URL on VirusTotal ({mal_count} security engines flagged).")
            artifact.risk_score = max(artifact.risk_score, 90.0)

        return artifact

    async def enrich_all_urls(self, artifacts: list[UrlArtifact], offline: bool = False) -> list[UrlArtifact]:
        """Enrich a batch of URLs concurrently."""
        tasks = [self.enrich_url(artifact, offline=offline) for artifact in artifacts]
        return await asyncio.gather(*tasks)

    # Legacy alias
    async def enrich_all(self, artifacts: list[UrlArtifact], offline: bool = False) -> list[UrlArtifact]:
        return await self.enrich_all_urls(artifacts, offline=offline)

    async def enrich_attachment(self, attachment: AttachmentArtifact, offline: bool = False) -> AttachmentArtifact:
        """Enrich attachment by looking up its SHA256 on VirusTotal."""
        if offline or not attachment.sha256:
            cached = self.cache.get("virustotal_file", attachment.sha256)
            if cached and cached["is_flagged"]:
                attachment.risk_score = max(attachment.risk_score, 90.0)
                attachment.risk_reasons.append("Known malware hash match in VirusTotal database (Cached).")
            return attachment

        vt_res = await self.virustotal.check_file_hash(attachment.sha256)
        if vt_res.get("is_flagged"):
            attachment.risk_score = max(attachment.risk_score, 95.0)
            mal_count = vt_res.get("details", {}).get("malicious_count", 0)
            attachment.risk_reasons.append(f"Known malware payload confirmed by VirusTotal ({mal_count} engines flagged).")

        return attachment

    async def enrich_all_attachments(
        self, attachments: list[AttachmentArtifact], offline: bool = False
    ) -> list[AttachmentArtifact]:
        """Enrich all attachments concurrently."""
        tasks = [self.enrich_attachment(att, offline=offline) for att in attachments]
        return await asyncio.gather(*tasks)

    async def check_ip_reputation(self, ip_address: Optional[str], offline: bool = False) -> Optional[dict]:
        """Enrich originating IP via AlienVault OTX."""
        if not ip_address or offline:
            return None
        return await self.otx.check_ip(ip_address)
