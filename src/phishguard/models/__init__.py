"""
Pydantic Data Models for PhishGuard SOC.
"""

from phishguard.models.email import (
    AuthenticationResults,
    AuthStatus,
    EmailMetadata,
    MimePart,
    ReceivedHop,
)
from phishguard.models.forensics import (
    AttachmentArtifact,
    HeaderAnalysis,
    QuishingResult,
    UrlArtifact,
)
from phishguard.models.report import (
    ScanResult,
    ScoreBreakdown,
    SeverityEnum,
    VerdictEnum,
)

__all__ = [
    "AuthStatus",
    "ReceivedHop",
    "AuthenticationResults",
    "MimePart",
    "EmailMetadata",
    "HeaderAnalysis",
    "UrlArtifact",
    "AttachmentArtifact",
    "QuishingResult",
    "VerdictEnum",
    "SeverityEnum",
    "ScoreBreakdown",
    "ScanResult",
]
