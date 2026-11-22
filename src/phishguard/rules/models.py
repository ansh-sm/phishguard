"""
Custom detection rule data models (Sigma/YARA inspired).
"""

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field

from phishguard.models.report import RuleMatch


class RuleSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RuleCondition(BaseModel):
    """
    Atomic condition evaluated against email artifacts.
    """
    field: str = Field(description="Target field (e.g. 'subject', 'body', 'headers', 'url_count', 'auth_spf')")
    operator: str = Field(
        default="contains",
        description="Evaluation operator (regex_search, regex_match, contains, contains_any, equals, in, gt, gte, lt, lte)"
    )
    pattern: Optional[str] = None
    patterns: Optional[list[str]] = None
    value: Optional[Any] = None
    header_name: Optional[str] = None


class RuleMitre(BaseModel):
    """Adversary framework mapping attached to a detection rule."""
    technique_id: str
    technique_name: str


class RuleDefinition(BaseModel):
    """
    Complete detection rule specification loaded from YAML.
    """
    id: str
    name: str
    description: str
    author: Optional[str] = "PhishGuard SOC"
    severity: RuleSeverity = RuleSeverity.HIGH
    score_impact: float = Field(default=20.0, description="Additive PhishScore impact (0-50)")
    tags: list[str] = Field(default_factory=list)
    mitre: Optional[RuleMitre] = None
    conditions: dict[str, list[RuleCondition]] = Field(
        default_factory=dict,
        description="Logical conditions grouping: 'all', 'any', 'none'"
    )
