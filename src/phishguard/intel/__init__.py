"""
Threat intelligence subsystems for PhishGuard SOC.
"""

from phishguard.intel.cache import IntelCache
from phishguard.intel.otx import OTXClient
from phishguard.intel.phishtank import PhishTankClient
from phishguard.intel.pipeline import ThreatIntelPipeline
from phishguard.intel.urlhaus import UrlhausClient
from phishguard.intel.virustotal import VirusTotalClient

__all__ = [
    "IntelCache",
    "UrlhausClient",
    "PhishTankClient",
    "VirusTotalClient",
    "OTXClient",
    "ThreatIntelPipeline",
]
