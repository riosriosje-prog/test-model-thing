# GALIA Rust v0.9 — Witness protocol simulator (CANDIDATE)

**DRAFT / NONCANONICAL / NO PRODUCTION WITNESS / HUMAN_AUTHORITY_HOLD**

The existing GALIA Python system remains authoritative. Rust never writes the canonical GALIA HEAD, Supabase, DW8, live legal evidence, or the production authority ledger.

## Implemented from v0.1 to v0.8

- P1/P2 stage state machine, fail-closed guards, typed source events.
- P5/P6 structural review and preflight; P7 Python-compatible SHA-256 snapshot verifier, parent chain check.
- P3 SHA-256 audit receipts, separately pinned checkpoints; P5 Ed25519 root-registered reviewer signing and P3 signed checkpoints, all diagnostic only.
- Optional noncanonical local scratch storage, immutable generations, locked CAS, fsync, fault and orphan inspection.
- Optional local consume-once journal: review authorization ID and nonce in one scratch record with local file lock; records include monotonic local registry epoch. NOT a real human approval.

## v0.9 NEW — independent monotonic witness protocol, simulated

- Feature-gated witness module introduces a MonotonicWitness interface: independently configured root/namespace/case, observe high-water mark and atomic compare-and-consume operation. An implementation is required to preserve durable monotonicity, identity scope, unique authorization ID and nonce, epoch rollback prevention, and a CAS token.
- InMemoryWitness implements these semantics using a mutex solely to run deterministic test scenarios. It is **NOT external, persistent, signed, authenticated or deployable**. It loses all spend history on process restart.
- ScratchConsumptionStore.consume_with_witness verifies the P5 signature and exact local case/root binding, checks local replay history, then requests the witness consume-before-local-append. If witness unavailable, signature invalid, CAS stale, nonce reused or registry epoch old, no local spend record is written.
- Separate simulated hosts (distinct scratch stores, one shared in-memory witness) are tested against same-authorization races, distinct-ID stale-CAS conflicts, retry after refreshed observation, forged signatures, wrong root, stale epoch and unavailable witness. No CLI exposes a witness or production write path.
- If external consume succeeds **but the local append fails**, the external spend remains irrevocable; the local record may be missing. The adapter **does not claim a distributed atomic transaction**. Manual fail-closed reconciliation, idempotent intent state and independent evidence are required before production.
- A witness receipt is returned to the caller but is NOT currently durably attached to the local consumption journal. Consequently future recovery cannot prove an external spend solely from local records.

## How to test

    cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets
    cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets --features scratch-store
    cargo build --manifest-path rust/galia-core/Cargo.toml --bins
    python -m unittest discover -s tests -p 'test_galia2_state_machine.py' -v
    python -m unittest discover -s tests -p 'test_galia2_preflight.py' -v
    python -m unittest discover -s tests -p 'test_galia2_persistence.py' -v
    python -m unittest discover -s rust/galia-core/tests -p 'test_*.py' -v

## Deployment gates

1. Actually provision independent trust roots, identity verification, controlled human P5 issuance and revocation; avoid caller-selected pins and false authority elevation.
2. Replace InMemoryWitness with a separately deployed, durable, authenticated service implementing linearizable unique-ID/nonce consumption and epoch CAS; negative tests across real hosts, network splits and restarts.
3. Resolve witness-success/local-failure with idempotent recoverable intent protocol, retained signed external witness receipts and independent monotonic checkpoints.
4. Formalize key rotation and revocation chronology, full audit receipts and replay/rollback tests, adversarial OS/filesystem and multi-host testing.
5. Complete P4 Legacy/MLX and governance review before any authoritative promotion, main merge or production deployment.

**Invariants:** EVENT_DATE != DOCUMENT_DATE; PROMPT_VERSION != ENGINE_VERSION; AI-rendered imagery is never archival evidence. AUTHORITY_HOLD is unchanged.
