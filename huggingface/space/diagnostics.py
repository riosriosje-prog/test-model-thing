from __future__ import annotations

import hashlib

DIAGNOSTIC_MODE = "READ_ONLY_DIAGNOSTIC"
AUTHORITY_SOURCE = "github"
PROMOTION_SCOPE = "SPACE_DIAGNOSTIC_CANDIDATE_ONLY"
CANONICAL_AUTHORITY_TRANSFERRED = False
MODEL_INFERENCE_ENABLED = False
CHECKPOINT_WRITES_ENABLED = False
WEIGHT_ARTIFACT_BOUND = False
HF8_WEIGHT_GATE = "HOLD"
HF10_LINUX_RUNTIME_PARITY = "PASS"


def diagnostic_payload(session_hash: str | None) -> dict:
    raw = session_hash or "anonymous-no-session"
    session_fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return {
        "mode": DIAGNOSTIC_MODE,
        "session_fingerprint": session_fingerprint,
        "session_state_persisted": False,
        "authority_source": AUTHORITY_SOURCE,
        "promotion_scope": PROMOTION_SCOPE,
        "canonical_authority_transferred": CANONICAL_AUTHORITY_TRANSFERRED,
        "model_inference_enabled": MODEL_INFERENCE_ENABLED,
        "checkpoint_writes_enabled": CHECKPOINT_WRITES_ENABLED,
        "weight_artifact_bound": WEIGHT_ARTIFACT_BOUND,
        "hf8_weight_gate": HF8_WEIGHT_GATE,
        "hf10_linux_runtime_parity": HF10_LINUX_RUNTIME_PARITY,
    }
