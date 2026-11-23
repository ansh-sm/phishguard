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


class RuleMatch(BaseModel):
    """Detection rule match details."""
    rule_id: str
    rule_name: str
    severity: str
    score_impact: float = 0.0
    description: str
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    matched_fields: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)

    @property
    def name(self) -> str:
        return self.rule_name


class MitreTechnique(BaseModel):
    """Represents an observable adversary technique mapped to MITRE ATT&CK."""
    technique_id: str = Field(description="e.g. T1566.001")
    technique_name: str = Field(description="e.g. Spearphishing Attachment")
    tactic: str = Field(description="e.g. Initial Access, Defense Evasion")
    description: str = Field(description="Adversary behavioral explanation")
    confidence: str = Field(default="HIGH", description="HIGH, MEDIUM, LOW")
    evidence: list[str] = Field(default_factory=list)
    attack_url: str = Field(description="Official MITRE ATT&CK technique reference URL")

    @property
    def name(self) -> str:
        return self.technique_name


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

    @property
    def headers(self) -> float:
        return self.header_score

    @property
    def urls(self) -> float:
        return self.url_score

    @property
    def attachments(self) -> float:
        return self.attachment_score

    @property
    def content(self) -> float:
        return self.content_score


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
    matched_rules: list[RuleMatch] = Field(default_factory=list, description="Matched custom detection rules")
    mitre_attack: list[MitreTechnique] = Field(default_factory=list, description="Mapped MITRE ATT&CK techniques")
    written_explanation: str = Field(description="SOC plain-English incident summary")
    remediation_steps: list[str] = Field(default_factory=list)

    @property
    def confidence(self) -> float:
        return self.confidence_percentage

    @property
    def rules_matched(self) -> list[RuleMatch]:
        return self.matched_rules

    @property
    def mitre_techniques(self) -> list[MitreTechnique]:
        return self.mitre_attack

    @property
    def flags(self) -> list[str]:
        return self.key_findings

    @property
    def score_breakdown(self) -> ScoreBreakdown:
        return self.score
