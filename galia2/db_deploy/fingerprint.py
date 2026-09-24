"""Deterministic schema fingerprints for GALIA DB deployment."""

from __future__ import annotations

import hashlib

from .models import canonical_json_bytes


def schema_fingerprint(descriptor: object) -> str:
    """Hash a normalized, JSON-serializable schema descriptor."""
    return hashlib.sha256(canonical_json_bytes(descriptor)).hexdigest()


def verify_schema_fingerprint(expected: str, descriptor: object) -> bool:
    return schema_fingerprint(descriptor) == expected.lower()
