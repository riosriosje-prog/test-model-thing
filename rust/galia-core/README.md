# GALIA 2.0 — Rust shadow migration v0.4

**Status: DRAFT CANDIDATE / NOT_PROMOTED / PRODUCTION_WRITES_DISABLED**

GALIA's Python P1/P2/P5/P6/P7 reference remains in control. This additive Rust crate has two distinct boundaries:

1. **Default build (safe):** pure read-only P1/P2 state evaluation, P5/P6 advisory authorization/preflight structure and P7 verification of supplied bytes, SHA-256, canonical JSON, payload inventory and parent chain. Three stdin/stdout read-only shadow CLIs.
2. **Opt-in feature (NEW):** scratch-store = a dedicated, noncanonical local test directory with a special marker. Provides exclusive file locking, immutable staged test snapshots, fsync, HEAD compare+rename under cooperative lock, detection of corrupt bytes, parent/sequence checks, crash-failure injection and read-only orphan inventory. The feature is **disabled by default**, never exposed in any CLI and cannot accept a pre-existing unmarked directory.

## Run

~~~sh
cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets
cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets --features scratch-store
cargo build --manifest-path rust/galia-core/Cargo.toml --bins
python -m unittest discover -s tests -p 'test_galia2_state_machine.py' -v
python -m unittest discover -s tests -p 'test_galia2_preflight.py' -v
python -m unittest discover -s tests -p 'test_galia2_persistence.py' -v
python -m unittest discover -s rust/galia-core/tests -p 'test_*.py' -v
~~~

## Scratch store contract

- ScratchStore::initialize_new(path) refuses existing paths and creates an identifiable private local test root. ScratchStore::open(path) requires matching marker and structure; it cannot open a normal GALIA canonical store.
- stage_snapshot() verifies supplied P7 bytes, writes one new staging generation with create_new() and fsync, and **never** advances HEAD.
- publish_staged(commit_id, expected_head_hash) serializes **cooperating local clients** via an exclusive file lock, compares the exact previous HEAD byte hash, checks parent/case/sequence and SHA-256 from disk, moves the test generation, then atomically renames a synced HEAD temp file. This is **not** a cross-host linearizable consensus protocol or a complete security boundary against malicious filesystem actors.
- On failed HEAD swap, retain an orphan under generations/ and keep prior HEAD. inspect_recovery() only classifies reachable, staged, orphaned and corrupt orphan generations; it never silently promotes, removes or quarantines bytes.
- Tests inject interruption *after* materialization and *before* HEAD swap, race two candidates against one parent, corrupt parent data, insert undeclared files and symlinks, and validate marker gating.
- A generation can contain a syntactically plausible promotion envelope without authentic authorization; this is a **fixture** and must not be ingested by canonical P7, Supabase or the GitHub control plane.

## Unresolved production gates

- Trusted human authority, revocation and proof of intent for exact commit/scope/decision; P2 guards are not independently authenticated.
- Anti-rollback witness, fencing for hostile concurrent writers, durability guarantees on intended target filesystems, reproducible canonical fixtures, robust OS portability and full fsync crash matrix.
- P4 MLX/Legacy byte captures, P3/P7 append-only trusted receipts, discrepancy ledger/recovery adjudication, DW8 read-only projection, independent red-team review.
- A separate, explicitly approved production cutover. Nothing here merges to main automatically, changes the Python runtime, alters authentic HEAD, or elevates AUTHORITY_HOLD.

**Invariants:** EVENT_DATE != DOCUMENT_DATE; PROMPT_VERSION != ENGINE_VERSION; no DW8 or Legal Execution authority transfer; synthetic/AI imagery is never historical evidence.
