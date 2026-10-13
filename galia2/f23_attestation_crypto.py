"""Isolated cryptographic primitive; NOT an authorization or admission gate.

The caller must obtain public keys from an independently governed trust root.
No key enrollment, reviewer authorization, revocation or policy mapping is
implemented here. Never infer authority from a valid signature alone.
"""
from __future__ import annotations
import base64
import json
from dataclasses import asdict
from typing import Mapping
from .f23_verified_scope_gate import VerifiedScopeAttestation

DOMAIN = b"GALIA-F23-P5-ATTESTATION-V1\x00"

def _canonical(attestation: VerifiedScopeAttestation) -> bytes:
    if not isinstance(attestation, VerifiedScopeAttestation):
        raise ValueError("attestation type mismatch")
    return DOMAIN + json.dumps(asdict(attestation), sort_keys=True,
        separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def verify_ed25519_signature(
    attestation: VerifiedScopeAttestation,
    signature_b64: str,
    *,
    trusted_public_keys: Mapping[str, bytes],
) -> bool:
    """Verify signature bytes only; never return an authority decision.

    Missing cryptography dependency, issuer, malformed input or bad signature
    fails closed. The trusted_public_keys mapping must be independently pinned.
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise ValueError("Ed25519 verifier unavailable") from exc
    if not isinstance(trusted_public_keys, Mapping):
        raise ValueError("trusted key mapping required")
    if not isinstance(attestation, VerifiedScopeAttestation):
        raise ValueError("attestation type mismatch")
    key_bytes = trusted_public_keys.get(attestation.issuer_id)
    if not isinstance(key_bytes, bytes) or len(key_bytes) != 32:
        raise ValueError("trusted issuer key missing")
    if not isinstance(signature_b64, str):
        raise ValueError("signature required")
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("malformed signature encoding") from exc
    if len(signature) != 64:
        raise ValueError("malformed signature length")
    try:
        Ed25519PublicKey.from_public_bytes(key_bytes).verify(signature, _canonical(attestation))
    except InvalidSignature:
        return False
    except ValueError as exc:
        raise ValueError("malformed Ed25519 public key") from exc
    return True
