# GALIA 2.0 — Rust shadow migration v0.6

**Status: DRAFT / ADVISORY_ONLY / HUMAN_AUTHORITY_NOT_VERIFIED / NOT_PROMOTED**

Rust is an additive, non-authoritative sidecar to the original GALIA Python core. It does not write to production, change the real GALIA HEAD or grant human promotion authority.

## Implemented

- P1/P2: strongly typed stage/source contracts, pure guarded state transitions, human boundaries and AUTHORITY_HOLD.
- P5/P6: advisory-only exact-scope / decision / preflight checks; no independently verified human authorization.
- P7: read-only Python-compatible manifest / promotion envelope / payload / HEAD SHA-256 validation and parent chain replay.
- P7 opt-in scratch-store: local noncanonical test-only file store, cooperative exclusive lock, CAS, fsync, crash injection and orphan inspection. Disabled by default and inaccessible through all CLIs.
- P3 v0.5: SHA-256 hash-linked scratch receipts, replay/HEAD continuity and separately retained optional checkpoint.
- **P3 v0.6 — Ed25519 offline integrity attestation (new)**:
  - Externally pinned root Ed25519 public key verifies a domain-separated signature of the full trust-registry payload.
  - Root-signed registry binds namespace, case, registry epoch, and unique delegated checkpoint public keys and revocation flags.
  - Only an active delegated key may verify a separately domain-separated signed checkpoint. It binds namespace, case, epoch, signing key ID, receipt count, SHA-256 chain tip and final HEAD hash.
  - Caller-supplied minimum registry epoch, minimum receipt count and optional exact prior historical checkpoint reject stale signed registries, truncated logs and validly signed rewrites of a pinned prefix.
  - All unknown fields and duplicate keys/ids in registry are rejected structurally.
  - Ed25519 does NOT establish whether the caller's pinned root was configured independently, its record is the latest, its signer is an authorized human reviewer, or a production commit is current.
  - Revocation is enforced immediately by the supplied, root-signed registry; historical effective-time modeling remains out of scope.
- CLI: galia-attestation-shadow reads JSON AttestationRequest and emits advisory assessment. Existing four CLIs stay read-only.

## Build and verification

    cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets
    cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets --features scratch-store
    cargo build --manifest-path rust/galia-core/Cargo.toml --bins
    python -m unittest discover -s tests -p 'test_galia2_state_machine.py' -v
    python -m unittest discover -s tests -p 'test_galia2_preflight.py' -v
    python -m unittest discover -s tests -p 'test_galia2_persistence.py' -v
    python -m unittest discover -s rust/galia-core/tests -p 'test_*.py' -v

## Security / authority boundaries

A valid Ed25519 signature proves only a cryptographic relationship to a key, NOT GALIA P5 human approval or authority. The pinned TrustPolicy, minimum epoch/count and any prefix anchor are caller inputs; a trustworthy deployer MUST obtain them independently of attacker-controlled requests. A user who controls both the root and the request can fabricate a structurally valid attestation.

The v0.6 assessor remains ADVISORY_ONLY with human_authority_verified=false, authority_transfer=false, canonical_writeback=false and output_commit=null.

## Production blockers

- Independently provisioned protected root and monotonic high-water marks / external witness.
- Human P5 authority and reviewer identity, scope and decisions, revocation chronology, key rotation, replay, distributed anti-rollback.
- Security review of Ed25519, canonical JSON, weak/compromised keys and adversarial data, filesystem portability, crash/recovery matrix.
- P4 Legacy/MLX and historical/Legal Execution / DW8 integration parity; P3/P7 production receipts and durable append-only storage.
- Independent human review and explicit approval before merge or cutover.

Main, Python runtime, Supabase, DW8 and live authoritative HEAD are unchanged. Historical synthetic imagery is never evidence. EVENT_DATE != DOCUMENT_DATE; PROMPT_VERSION != ENGINE_VERSION.
