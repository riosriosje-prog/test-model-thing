"""Shadow package surface for historical acquisition.

v0.1 deliberately re-exports the legacy root module so package adoption can be
validated without changing runtime authority or import semantics.
"""

from historical_acquisition import (
    AcquisitionReceipt,
    AcquisitionState,
    record_acquisition_state,
)

__all__ = [
    "AcquisitionReceipt",
    "AcquisitionState",
    "record_acquisition_state",
]
