"""
Scoring and Decision Engine Subsystem for PhishGuard SOC.
"""

from phishguard.engine.mitre import MitreAttackMapper, MitreTechnique
from phishguard.engine.narrative import NarrativeGenerator
from phishguard.engine.scorer import ScoringEngine

__all__ = [
    "ScoringEngine",
    "NarrativeGenerator",
    "MitreAttackMapper",
    "MitreTechnique",
]
