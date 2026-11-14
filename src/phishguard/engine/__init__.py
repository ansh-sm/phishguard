"""
Scoring and Decision Engine Subsystem for PhishGuard SOC.
"""

from phishguard.engine.narrative import NarrativeGenerator
from phishguard.engine.scorer import ScoringEngine

__all__ = ["ScoringEngine", "NarrativeGenerator"]
