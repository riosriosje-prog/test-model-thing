"""Shadow package surface for the GALIA research bridge.

v0.1 re-exports the legacy root bridge so package adoption can be validated
without changing implementation authority, claim semantics, or checkpoint
behavior.
"""

from galia_history_bridge import (
    GaliaResearchBridge,
    ProposedClaim,
)

__all__ = [
    "GaliaResearchBridge",
    "ProposedClaim",
]
