# GALIA 2.0 — Rust shadow migration v0.7

**Status: DRAFT CANDIDATE / ADVISORY_ONLY / HUMAN_AUTHORITY_NOT_VERIFIED / NOT_PROMOTED**

GALIA's original Python core and its canonical data store remain untouched. Rust is a separate experimental implementation for structural, cryptographic and differential verification.

## Implemented

- P1/P2: typed source and stage contracts, fail-closed guarded state transitions.
- P5/P6: structural authorization matching and 12-check preflight; still no trusted promotion guards.
- P7: byte-exact Python manifest/promotion/HEAD/payload SHA-256 verification and parent chain replay.
- P7 optional scratch-store: local, specially marked test-only immutable generations, exclusive cooperative lock, HEAD CAS/fsync, crash injection, orphan inventory; disabled by default.
- P3: SHA-256 hash-linked receipt audit, replay and HEAD-continuity diagnostics.
- P3 v0.6: offline Ed25519 signatures for an externally pinned registry root and signed checkpoint, optional pinned historical prefix, revocation flag.
- **P5 v0.7 NEW**: offline Ed25519 review-signature structural verification. Separate registry and decision signing domains prevent reuse of checkpoint signatures as review signatures. Exact root-signed registry binds namespace, case, epoch, unique review keys, reviewer labels, target type, revocation flags, consumed/revoked authorization IDs and consumed nonce hashes. A valid decision must be a signed SELECT, bind reviewer/key/case/scope/decision/target commit/policy/manifest hash/nonce and not appear in any root-signed or separately provided replay fence. Root key reuse as reviewer key is rejected.
- Sixth read-only stdin/stdout CLI: galia-review-shadow. Existing shadow tools continue functioning without network or canonical writes.

## Critical security boundary

- A valid review signature **does not prove** the person behind a key is an independently credentialed GALIA reviewer or actually authorized the case. Reviewer identity is a **root-signed label**, not a completed human identity-verification protocol.
- Both the root public key and external minimum epoch/replay fences are **caller inputs**. This module does not authenticate their provenance, freshness or rollback resistance.
- Replay checks are snapshots only: this module **does not atomically consume a nonce or authorization ID**, and two simultaneous processes could accept the same request. The existing Python P5 remains authoritative.
- This module does not issue P2 human guards, create authoritative receipts, sign with private keys, advance CANONICAL, move HEAD, modify Supabase or DW8, or trigger deployment.
- Successful results explicitly set human_identity_verified=false, human_authority_verified=false, executable_guards_issued=false, canonical_writeback=false, authority_transfer=false and output_commit=null.

## Build and tests

    cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets
    cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets --features scratch-store
    cargo build --manifest-path rust/galia-core/Cargo.toml --bins
    python -m unittest discover -s tests -p 'test_galia2_state_machine.py' -v
    python -m unittest discover -s tests -p 'test_galia2_preflight.py' -v
    python -m unittest discover -s tests -p 'test_galia2_persistence.py' -v
    python -m unittest discover -s rust/galia-core/tests -p 'test_*.py' -v

## Production blockers

1. Independent, protected provisioning of trusted root keys, reviewer identity, registry epochs, current revocations and expiry; secure signer rotations with accountable human delegation.
2. Trusted append-only consumption of authorization IDs / nonces under atomic concurrency, anti-replay and distributed rollback fences (never based solely on caller input).
3. Bind a verified P5 human decision to P6/P7 trusted inputs with receipt and independent human review, separate from a cryptographic diagnostic. Preserve AUTHORITY_HOLD.
4. P4 Legacy/MLX, legal evidence and DW8 parity, adversarial filesystem and clock tests, reproducible builds, code security review.
5. Explicit review and approval of any subsequent production merge/deployment. PR stays draft until then.

**Invariant:** DOCUMENT_DATE != EVENT_DATE; PROMPT_VERSION != ENGINE_VERSION; generated images are never historical evidence; DW8 / Legal Execution cannot transfer canonical authority.
