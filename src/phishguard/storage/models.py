"""
Data models for the SOC incident database and threat hunting queries.
"""

from typing import Any, Optional
from pydantic import BaseModel, Field, model_validator


class IncidentSummary(BaseModel):
    """Compact summary of a historical triage record for threat hunting."""
    scan_id: str
    timestamp: str
    subject: str = "(No Subject)"
    from_email: str = ""
    from_domain: str = ""
    originating_ip: Optional[str] = None
    recipient: Optional[str] = None
    verdict: str = "CLEAN"
    severity: str = "LOW"
    total_score: float = 0.0
    confidence: Optional[str] = "HIGH"
    file_sha256: Optional[str] = ""
    matched_rules_count: int = 0
    mitre_count: int = 0
    mitre_techniques: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def handle_score_alias(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "score" in data and "total_score" not in data:
                data["total_score"] = float(data["score"])
        return data

    @property
    def score(self) -> float:
        return self.total_score


class IncidentQueryFilter(BaseModel):
    """Search parameters for threat hunting across historical scans."""
    query: Optional[str] = Field(default=None, description="Free-text search in subject, sender, or narrative")
    ip: Optional[str] = Field(default=None, description="Originating IPv4 or IPv6 address")
    domain: Optional[str] = Field(default=None, description="Sender domain or extracted URL domain")
    hash_val: Optional[str] = Field(default=None, description="SHA256 hash of attachment or EML file")
    technique: Optional[str] = Field(default=None, description="MITRE ATT&CK technique ID (e.g. T1566.002)")
    verdict: Optional[str] = Field(default=None, description="Verdict: MALICIOUS, SUSPICIOUS, CLEAN")
    limit: int = Field(default=50, description="Maximum results to return")
