"""Dynamic URL detonation and headless DOM analysis subsystem."""

from phishguard.sandbox.detonator import UrlDetonator
from phishguard.sandbox.models import (
    BrandImpersonationDetection,
    DetonationVerdict,
    FormTarget,
    RedirectHop,
    UrlDetonationResult,
)

__all__ = [
    "UrlDetonator",
    "UrlDetonationResult",
    "DetonationVerdict",
    "RedirectHop",
    "FormTarget",
    "BrandImpersonationDetection",
]
