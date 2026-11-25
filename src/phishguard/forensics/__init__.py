"""
Forensics inspection engines for PhishGuard SOC.
"""

from phishguard.forensics.attachments import AttachmentForensicsEngine
from phishguard.forensics.auth import AuthResultsParser
from phishguard.forensics.dns_validator import (
    DnsPolicyValidator,
    DomainDnsInspection,
    DmarcValidationResult,
    SpfValidationResult,
)
from phishguard.forensics.headers import HeaderForensicsEngine, ReceivedHopParser
from phishguard.forensics.iocs import IOCBundle, IOCExporter, IOCExtractor, IOCItem
from phishguard.forensics.quishing import QuishingDetector
from phishguard.forensics.spoofing import SpoofingDetector
from phishguard.forensics.urls import UrlAnalyzer, defang_url, refang_url

__all__ = [
    "ReceivedHopParser",
    "HeaderForensicsEngine",
    "AuthResultsParser",
    "SpoofingDetector",
    "UrlAnalyzer",
    "AttachmentForensicsEngine",
    "QuishingDetector",
    "defang_url",
    "refang_url",
    "IOCExtractor",
    "IOCExporter",
    "IOCBundle",
    "IOCItem",
    "DnsPolicyValidator",
    "DomainDnsInspection",
    "SpfValidationResult",
    "DmarcValidationResult",
]
