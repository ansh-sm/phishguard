"""
Forensics inspection engines for PhishGuard SOC.
"""

from phishguard.forensics.auth import AuthResultsParser
from phishguard.forensics.headers import HeaderForensicsEngine, ReceivedHopParser
from phishguard.forensics.spoofing import SpoofingDetector
from phishguard.forensics.urls import UrlAnalyzer, defang_url, refang_url

__all__ = [
    "ReceivedHopParser",
    "HeaderForensicsEngine",
    "AuthResultsParser",
    "SpoofingDetector",
    "UrlAnalyzer",
    "defang_url",
    "refang_url",
]
