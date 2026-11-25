"""Data models for AI Phishing Intent & Social Engineering Triage."""

from __future__ import annotations

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class EmailIntentEnum(str, Enum):
    """Categorization of primary adversary objective or benign purpose."""
    BENIGN_TRANSACTIONAL = "BENIGN_TRANSACTIONAL"
    BENIGN_MARKETING = "BENIGN_MARKETING"
    CREDENTIAL_HARVEST = "CREDENTIAL_HARVEST"
    FINANCIAL_FRAUD_BEC = "FINANCIAL_FRAUD_BEC"
    INVOICE_FRAUD = "INVOICE_FRAUD"
    COERCION_URGENCY = "COERCION_URGENCY"
    PAYROLL_DIVERT = "PAYROLL_DIVERT"
    TECH_SUPPORT_LURE = "TECH_SUPPORT_LURE"
    LEGAL_THREAT = "LEGAL_THREAT"
    EXTORTION_BLACKMAIL = "EXTORTION_BLACKMAIL"


class PsychologicalTacticEnum(str, Enum):
    """Specific social engineering cognitive bias exploited by the adversary."""
    ARTIFICIAL_TIME_PRESSURE = "ARTIFICIAL_TIME_PRESSURE"
    AUTHORITY_IMPERSONATION = "AUTHORITY_IMPERSONATION"
    FEAR_OF_NEGATIVE_CONSEQUENCES = "FEAR_OF_NEGATIVE_CONSEQUENCES"
    GREED_FALSE_REWARD = "GREED_FALSE_REWARD"
    CURIOSITY_BAIT = "CURIOSITY_BAIT"
    HELPFULNESS_EXPLOITATION = "HELPFULNESS_EXPLOITATION"
    PROCEDURAL_OVERRIDE = "PROCEDURAL_OVERRIDE"


class AiTriageResult(BaseModel):
    """Detailed cognitive and semantic threat evaluation of an email's content."""
    primary_intent: EmailIntentEnum
    secondary_intents: list[EmailIntentEnum] = Field(default_factory=list)
    urgency_score: float = Field(default=0.0, ge=0.0, le=1.0, description="0.0 relaxed to 1.0 extreme pressure")
    vip_impersonation_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Likelihood of C-suite / executive spoofing")
    psychological_tactics: list[PsychologicalTacticEnum] = Field(default_factory=list)
    suspicious_phrases: list[str] = Field(default_factory=list)
    call_to_action: Optional[str] = None
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    executive_summary: str = Field(default="")
    provider_used: str = Field(default="offline_heuristics")


class AiTriageRequest(BaseModel):
    """Request payload for evaluating message intent."""
    subject: str = ""
    body_text: str = ""
    from_name: Optional[str] = None
    from_email: Optional[str] = None
    provider: str = "offline"
    api_key: Optional[str] = None
