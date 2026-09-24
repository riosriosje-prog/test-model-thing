"""Fail-closed classification of explicit schema deltas."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from .models import ChangeClass, SchemaDelta


@dataclass(frozen=True, slots=True)
class Classification:
    change_class: ChangeClass
    destructive: bool
    reasons: Tuple[str, ...]


def classify_delta(delta: SchemaDelta) -> Classification:
    """Classify explicit change facts; unknown/empty change sets are rejected."""
    if delta.empty:
        raise ValueError("empty schema delta cannot be classified")

    if delta.corrective:
        return Classification(
            ChangeClass.CORRECTIVE,
            not delta.backward_compatible,
            ("corrective migration explicitly declared",),
        )

    if delta.removed_objects or (delta.altered_objects and not delta.backward_compatible):
        reasons = []
        if delta.removed_objects:
            reasons.append("objects removed")
        if delta.altered_objects and not delta.backward_compatible:
            reasons.append("incompatible object alteration")
        return Classification(ChangeClass.DESTRUCTIVE, True, tuple(reasons))

    if delta.renamed_objects:
        return Classification(
            ChangeClass.RENAMING,
            not delta.backward_compatible,
            ("objects renamed",),
        )

    if delta.backfill_required:
        return Classification(
            ChangeClass.BACKFILL,
            not delta.backward_compatible,
            ("data backfill required",),
        )

    if delta.altered_objects:
        return Classification(
            ChangeClass.COMPATIBLE_TRANSFORM,
            False,
            ("backward-compatible object alteration",),
        )

    if delta.added_objects:
        return Classification(
            ChangeClass.ADDITIVE,
            False,
            ("objects added",),
        )

    raise ValueError("schema delta cannot be classified")
