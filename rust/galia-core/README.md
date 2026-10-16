# GALIA 2.0 Rust shadow v0.10 — durable SCRATCH witness and reconciliation

**DRAFT / NOT PROMOTED / NONCANONICAL / AUTHORITY_HOLD**

The Python GALIA core remains authoritative. No production database, real GALIA HEAD, legal evidence, Supabase, DW8, or main-branch modifications. No CLI exposes scratch writes.

## Existing foundations

P1/P2 typed stages and guards; P5/P6 structural authorization/preflight; P7 byte-exact snapshot/payload/parent verification; P3 hash-linked audit receipts; P3 Ed25519 integrity checkpoints and registry; P5 Ed25519 root-registered signed review scope; optional scratch generation CAS, consume-once journal, and nonpersistent v0.9 InMemoryWitness.

## New v0.10 implementation

- DurableScratchWitness implements MonotonicWitness over a NEW, explicit, separately marked, **local noncanonical scratch root**, not the GALIA canonical root. It re-opens after process restart and retains every committed authorization ID and nonce.
- Each witness operation acquires a cooperative exclusive OS file lock; reconstructs and verifies the entire durable numbered journal; checks exact local root/namespace/case pin, observed registry epoch, expected tip CAS, duplicate authorization and nonce; then writes one canonical JSON entry with create-new, SHA-256 chain, fsync(file), fsync(directory). No caller can silently overwrite an existing record.
- Journal replay re-derives each receipt from the original request and sequence, rejects undeclared/missing/modified entries, symlinks, stale CAS and tampered receipt bytes. Failed partial journal writes cause **fail closed**; no automatic deletion or promotion.
- MonotonicWitness now optionally exposes find_spend(authorization_id). DurableScratchWitness implements replay-verified historical receipt lookup.
- The opt-in local consume-with-witness path binds the SHA-256 of the witness receipt into its scratch record. If an actual witness consumption succeeded but the **local write failed**, reconcile_with_witness can recheck the exact signed review, retrieve the already committed witness receipt, and append the missing local scratch record **without re-consuming the external authorization**. If the witness journal is corrupt or mismatched, reconciliation rejects. This is *manual diagnostic recovery*, not an automatically authorized rollback/replay policy.
- Tests exercise directory reopen, concurrent independent handles, stale-CAS and epoch after restart, corrupted and partially written journals, symlinks, nonce reuse, two separate local scratch stores using the same durable witness, and failed local write followed by verified recovery.

## Crucial limitations

- **No independently deployed network witness**: both scratch witness and local store are ordinary filesystem locations in one test runner, using cooperative local locks. The witness root/key marker can be forged or rolled back by someone controlling that filesystem, and the entire journal can be silently truncated without a genuinely independent authenticated high-water checkpoint.
- A local single-file journal commit is not a distributed transaction. A witness spend can precede a local I/O failure. If a torn local record remains, automatic replay is prohibited and human adjudication is required.
- Witness receipts are **not digitally signed by the witness**; receipt lookup is only as credible as the verified local witness journal. Calling this service remote or proof of human authority would be false.
- P5 reviewer labels and pinned root sources remain unverified; human_identity_verified=false, human_authority_verified=false, executable_guards_issued=false, canonical_writeback=false, authority_transfer=false.
- Test CI on Linux does not establish crash durability on every filesystem; no multi-host partition, hostile actor, independent KMS, signed external checkpoint or distributed quorum is implemented.

## Verify

    cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets
    cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets --features scratch-store
    cargo build --manifest-path rust/galia-core/Cargo.toml --bins
    python -m unittest discover -s tests -p 'test_galia2_state_machine.py' -v
    python -m unittest discover -s tests -p 'test_galia2_preflight.py' -v
    python -m unittest discover -s tests -p 'test_galia2_persistence.py' -v
    python -m unittest discover -s rust/galia-core/tests -p 'test_*.py' -v

## Required before production

Provision actual independent authenticated witness with durable linearizable transactional CAS and certified monotonic keys/replay; implement signed witness receipts, independently retained witness checkpoint and audited key rotation/revocation; test across hosts and restarts/network partitions; validate recovered transaction across witness and main canonical P7 with explicit human decision; complete P4 Legacy/MLX parity and independent security review. Never infer human authorization from signature correctness.

**Invariants:** EVENT_DATE != DOCUMENT_DATE; PROMPT_VERSION != ENGINE_VERSION; generated images are not historical evidence. AUTHORITY_HOLD persists.
