"""
Forensic artifacts, detection results, and threat intelligence models.
"""

from typing import Any, Optional
from pydantic import BaseModel, Field
from phishguard.models.email import AuthenticationResults, ReceivedHop


class UrlArtifact(BaseModel):
    """Extracted and analyzed URL artifact."""
    raw_url: str
    defanged_url: str
    domain: str = ""
    tld: str = ""
    scheme: str = ""
    path: str = ""
    anchor_text: Optional[str] = None

    # Deception & Obfuscation indicators
    is_mismatched_anchor: bool = Field(default=False, description="Anchor text displays a different domain")
    is_ip_host: bool = Field(default=False, description="Host is an IP address instead of domain name")
    is_shortener: bool = Field(default=False, description="Uses URL shortener (e.g. bit.ly, tinyurl)")
    is_credential_embedded: bool = Field(default=False, description="URL contains username:password syntax")
    domain_entropy: float = Field(default=0.0, description="Shannon entropy score of the domain name")
    is_high_risk_tld: bool = Field(default=False, description="TLD matches known high-abuse TLD list")

    # Threat Intelligence Findings
    threat_intel_flagged: bool = Field(default=False)
    threat_intel_source: Optional[str] = None
    threat_intel_tags: list[str] = Field(default_factory=list)
    threat_intel_details: dict[str, Any] = Field(default_factory=dict)

    risk_score: float = Field(default=0.0, description="Calculated risk score for this individual URL (0-100)")
    risk_reasons: list[str] = Field(default_factory=list)


class AttachmentArtifact(BaseModel):
    """Forensic metadata for an extracted email attachment."""
    filename: str
    original_mime: str = "application/octet-stream"
    detected_mime: Optional[str] = None
    size_bytes: int = 0

    # Hashes
    md5: str = ""
    sha1: str = ""
    sha256: str = ""

    # Security indicators
    is_double_extension: bool = False
    is_executable: bool = False
    is_script: bool = False
    is_archive: bool = False
    has_macros: bool = False
    archive_contents: list[str] = Field(default_factory=list)
    yara_matches: list[str] = Field(default_factory=list, description="Matched YARA binary signatures")

    risk_score: float = Field(default=0.0, description="Calculated risk score for attachment (0-100)")
    risk_reasons: list[str] = Field(default_factory=list)


class QuishingResult(BaseModel):
    """Result of QR code analysis on inline images or attachments."""
    found: bool = False
    qr_count: int = 0
    decoded_payloads: list[str] = Field(default_factory=list)
    analyzed_urls: list[UrlArtifact] = Field(default_factory=list)
    risk_score: float = 0.0
    risk_reasons: list[str] = Field(default_factory=list)


class HeaderAnalysis(BaseModel):
    """Comprehensive header forensics and routing anomaly analysis."""
    hops: list[ReceivedHop] = Field(default_factory=list)
    originating_ip: Optional[str] = None
    originating_country: Optional[str] = None
    auth: AuthenticationResults = Field(default_factory=AuthenticationResults)

    # Impersonation & Spoofing flags
    display_name_spoof: bool = Field(default=False, description="Display name impersonates another identity or domain")
    reply_to_mismatch: bool = Field(default=False, description="Reply-To domain does not match From domain")
    return_path_mismatch: bool = Field(default=False, description="Return-Path domain does not match From domain")
    lookalike_domain: bool = Field(default=False, description="Domain closely resembles a protected enterprise brand")
    lookalike_target: Optional[str] = None
    punycode_detected: bool = Field(default=False, description="Domain uses Punycode / IDN encoding")
    homoglyph_detected: bool = Field(default=False, description="Mixed script homoglyphs detected in sender domain")

    anomalies: list[str] = Field(default_factory=list)
    risk_score: float = Field(default=0.0, description="Calculated header risk sub-score (0-30)")
