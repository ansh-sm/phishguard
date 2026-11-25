"""Data models for dynamic URL detonation and headless DOM analysis."""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class DetonationVerdict(str, Enum):
    """Categorical verdict for analyzed dynamic URL landing pages."""
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class RedirectHop(BaseModel):
    """Represents a single transit hop in an HTTP/JS redirect chain."""
    hop_number: int
    url: str
    status_code: int
    reason_phrase: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    elapsed_ms: float = 0.0


class FormTarget(BaseModel):
    """Represents an interactive HTML form discovered in the DOM."""
    action: str
    method: str = "POST"
    has_password_field: bool = False
    has_email_field: bool = False
    field_names: list[str] = Field(default_factory=list)
    is_external_post: bool = False


class BrandImpersonationDetection(BaseModel):
    """Diagnostic details when a landing page impersonates a known corporate brand."""
    detected: bool = False
    impersonated_brand: Optional[str] = None
    confidence: float = 0.0
    matched_indicators: list[str] = Field(default_factory=list)


class UrlDetonationResult(BaseModel):
    """Comprehensive intelligence gathered from detonating an untrusted URL."""
    target_url: str
    final_url: str
    status_code: int
    redirect_chain: list[RedirectHop] = Field(default_factory=list)
    total_redirects: int = 0
    page_title: Optional[str] = None
    server_banner: Optional[str] = None
    forms_detected: list[FormTarget] = Field(default_factory=list)
    has_credential_harvesting_form: bool = False
    brand_impersonation: BrandImpersonationDetection = Field(default_factory=BrandImpersonationDetection)
    suspicious_indicators: list[str] = Field(default_factory=list)
    verdict: DetonationVerdict = DetonationVerdict.BENIGN
    risk_score: float = 0.0
    simulated_screenshot_base64: Optional[str] = None

    @property
    def is_malicious(self) -> bool:
        return self.verdict == DetonationVerdict.MALICIOUS
