# GALIA 2.0 Rust shadow v0.8

**DRAFT / NOT PROMOTED / NONCANONICAL / HUMAN AUTHORITY HOLD**

This Rust sidecar does NOT replace the existing Python core and never writes to the actual GALIA HEAD, Supabase or DW8.

## Implemented

- P1/P2 typed historical stage contracts, guarded pure state transitions.
- P5/P6 advisory structural decision matching and 12-check preflight.
- P7 Python-compatible SHA-256 payload/manifest/HEAD read-only verification and optional parent chain.
- P3 hash-linked scratch receipts and audit replay; Ed25519 root-signed trust registries and delegated signed checkpoints with externally pinned floors.
- P5 v0.7 root-signed reviewer key registry, precise signed SELECT decision/case/claim/target/manifest/policy/nonce binding; revoked key and authorization checks. A root-signed reviewer label is NOT a verified person.
- P7 optional scratch-store local-only immutable generations, lock/CAS, fsync and crash/orphan inspection.
- NEW v0.8: opt-in feature-only ScratchConsumptionStore, a separate explicitly marked new scratch directory with pinned root public key, namespace and case ID under an exclusive cooperative local file lock.
  - Full v0.7 review signature check precedes appending. A single create-new and fsync immutable record consumes BOTH authorization ID and nonce SHA-256, preventing reuse among cooperating local processes, including races.
  - On every write/read, records are replayed against previous SHA-256 links, monotonic root registry epochs, unique authorization IDs and nonces, strict sequence and exact expected root marker.
  - A subsequent root-signed registry with higher epoch and new delegated reviewer keys can rotate the key; older registry epochs are then rejected once a higher epoch has been consumed locally. Revoked reviewers fail.
  - An optional externally retained consumption checkpoint detects silent truncation. A caller-provided checkpoint is NOT inherently trustworthy.
  - No CLI exposes scratch write capability; the default Rust build excludes it.

## Verify

    cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets
    cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets --features scratch-store
    cargo build --manifest-path rust/galia-core/Cargo.toml --bins
    python -m unittest discover -s tests -p 'test_galia2_state_machine.py' -v
    python -m unittest discover -s tests -p 'test_galia2_preflight.py' -v
    python -m unittest discover -s tests -p 'test_galia2_persistence.py' -v
    python -m unittest discover -s rust/galia-core/tests -p 'test_*.py' -v

## Essential boundaries

- The consumed log and pinned root are only LOCAL SCRATCH state. Root provisioning, root trust and the latest epoch require a separately trusted service. Attackers controlling scratch directory can roll back the entire journal and marker.
- A local lock is NOT malicious-writer safe or distributed consensus. Atomicity is limited to cooperating clients and the single journal record; failure during write or fsync may leave a partial record and subsequent operations fail closed.
- A successful consumption means a NONCANONICAL test journal was updated, NOT that real human identity, authority or promotion was authenticated. Human authority, executable guards, canonical writing and transfer remain false.
- Python remains authoritative; true P5 identity governance, distributed fences, KMS, durable external witnesses, formal revocation lifecycle, and P4/MLX parity are pending.
- Never treat generated images as historic evidence. EVENT_DATE differs from DOCUMENT_DATE; PROMPT_VERSION differs from ENGINE_VERSION. Preserve AUTHORITY_HOLD.

## Next

Independent trusted root and monotonic witness, signed registry/key rotation lineage, true external consume-and-commit transaction, adversarial filesystem and multi-host tests, reproducible builds and security review. No deployment or merge without human approval.
