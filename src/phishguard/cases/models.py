"""Data models for SOC Incident Case Management and triage queues."""

from __future__ import annotations

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class CaseStatus(str, Enum):
    """Lifecycle status of a SOC phishing triage case."""
    NEW = "NEW"
    IN_TRIAGE = "IN_TRIAGE"
    CONTAINED = "CONTAINED"
    CLOSED_MALICIOUS = "CLOSED_MALICIOUS"
    CLOSED_FALSE_POSITIVE = "CLOSED_FALSE_POSITIVE"


class CaseSeverity(str, Enum):
    """Triage priority/severity rating."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CaseNote(BaseModel):
    """Analyst audit log entry or investigation hypothesis."""
    id: str
    timestamp: str
    analyst: str
    message: str


class CaseIoc(BaseModel):
    """Artifact indicator linked to the case with containment state."""
    ioc_type: str
    value: str
    status: str = "PENDING"  # PENDING, BLOCKED, QUARANTINED, CLEARED


class SocCase(BaseModel):
    """Enterprise SOC Incident Ticket and investigation record."""
    case_id: str
    title: str
    created_at: str
    updated_at: str
    status: CaseStatus = CaseStatus.NEW
    severity: CaseSeverity = CaseSeverity.MEDIUM
    assigned_analyst: str = "tier1-analyst"
    source_scan_id: Optional[str] = None
    sender: str = ""
    subject: str = ""
    score: float = 0.0
    summary: str = ""
    timeline: list[CaseNote] = Field(default_factory=list)
    iocs: list[CaseIoc] = Field(default_factory=list)
    containment_status: str = "OPEN"

    @property
    def is_closed(self) -> bool:
        return self.status in (CaseStatus.CLOSED_MALICIOUS, CaseStatus.CLOSED_FALSE_POSITIVE)
