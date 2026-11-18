"""
Incident report, scoring, and verdict data models.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field

from phishguard.models.email import EmailMetadata
from phishguard.models.forensics import (
    AttachmentArtifact,
    HeaderAnalysis,
    QuishingResult,
    UrlArtifact,
)


class MitreTechnique(BaseModel):
    """Represents an observable adversary technique mapped to MITRE ATT&CK."""
    technique_id: str = Field(description="e.g. T1566.001")
    technique_name: str = Field(description="e.g. Spearphishing Attachment")
    tactic: str = Field(description="e.g. Initial Access, Defense Evasion")
    description: str = Field(description="Adversary behavioral explanation")
    confidence: str = Field(default="HIGH", description="HIGH, MEDIUM, LOW")
    evidence: list[str] = Field(default_factory=list)
    attack_url: str = Field(description="Official MITRE ATT&CK technique reference URL")


class VerdictEnum(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class SeverityEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ScoreBreakdown(BaseModel):
    """Granular vector sub-scores contributing to final score."""
    header_score: float = Field(default=0.0, description="Header & Spoofing risk sub-score (0-30)")
    url_score: float = Field(default=0.0, description="URL, Domain & Threat Intel risk sub-score (0-35)")
    attachment_score: float = Field(default=0.0, description="Attachment forensic risk sub-score (0-20)")
    content_score: float = Field(default=0.0, description="Content, Social Engineering & Urgency sub-score (0-15)")
    total_score: float = Field(default=0.0, description="Aggregated PhishScore (0-100)")


class ScanResult(BaseModel):
    """Complete, self-contained SOC analysis report for an email."""
    scan_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    eml_file_path: str
    eml_file_hash_sha256: str

    # Core components
    metadata: EmailMetadata
    headers: HeaderAnalysis
    urls: list[UrlArtifact] = Field(default_factory=list)
    attachments: list[AttachmentArtifact] = Field(default_factory=list)
    quishing: Optional[QuishingResult] = None

    # SOC Verdict & Analysis
    score: ScoreBreakdown
    verdict: VerdictEnum
    severity: SeverityEnum
    confidence_percentage: float = Field(default=95.0, description="Forensic confidence level")

    # Actionable Intelligence & Framework Mapping
    key_findings: list[str] = Field(default_factory=list)
    mitre_attack: list[MitreTechnique] = Field(default_factory=list, description="Mapped MITRE ATT&CK techniques")
    written_explanation: str = Field(description="SOC plain-English incident summary")
    remediation_steps: list[str] = Field(default_factory=list)
