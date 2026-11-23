"""
Data models for SOAR automated containment and incident response playbooks.
"""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class PlatformType(str, Enum):
    M365 = "m365"
    GOOGLE_WORKSPACE = "google"
    EDR_HUNTING = "edr"
    PERIMETER_FIREWALL = "firewall"
    ALL = "all"


class RemediationAction(BaseModel):
    """An individual actionable script or configuration snippet for SOC triage."""
    name: str = Field(description="Action title (e.g., 'Purge Mailbox Search', 'Defender KQL')")
    platform: PlatformType = Field(description="Target enterprise infrastructure platform")
    category: str = Field(description="Action category: 'purge', 'blocklist', 'hunting', 'sinkhole'")
    language: str = Field(description="Script language: 'powershell', 'bash', 'kql', 'cisco', 'json'")
    description: str = Field(description="Analyst explanation of what the command achieves")
    code: str = Field(description="Copy-paste ready executable commands or configuration")


class RemediationPackage(BaseModel):
    """Consolidated SOC incident response package across enterprise control planes."""
    scan_id: str
    timestamp: str
    verdict: str
    severity: str
    target_subject: str
    sender_email: str
    sender_domain: str
    originating_ip: Optional[str] = None
    malicious_urls: list[str] = Field(default_factory=list)
    attachment_hashes: list[str] = Field(default_factory=list)
    actions: list[RemediationAction] = Field(default_factory=list)
