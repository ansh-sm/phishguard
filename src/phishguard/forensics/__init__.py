"""
Forensics inspection engines for PhishGuard SOC.
"""

from phishguard.forensics.auth import AuthResultsParser
from phishguard.forensics.headers import HeaderForensicsEngine, ReceivedHopParser
from phishguard.forensics.spoofing import SpoofingDetector

__all__ = [
    "ReceivedHopParser",
    "HeaderForensicsEngine",
    "AuthResultsParser",
    "SpoofingDetector",
]
