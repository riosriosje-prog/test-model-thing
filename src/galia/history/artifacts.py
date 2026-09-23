"""Shadow package surface for historical artifact storage.

v0.1 deliberately re-exports the legacy root module so package adoption can be
validated without changing implementation authority or persistence semantics.
"""

from historical_artifacts import (
    ArtifactReceipt,
    HistoricalArtifactStore,
)

__all__ = [
    "ArtifactReceipt",
    "HistoricalArtifactStore",
]
