# GALIA 2.0 — Rust shadow migration v0.5

**Status: CANDIDATE / ADVISORY_ONLY / HUMAN_AUTHORITY_NOT_VERIFIED / NOT_PROMOTED**

The original Python GALIA core stays authoritative. This Rust code is additive and remains in a draft PR, outside the real canonical store, Supabase and DW8.

## Scope actually implemented

- **P1/P2:** typed historical stage/source models and fail-closed state machine.
- **P5/P6:** structural, untrusted promotion-envelope matching and 12-check preflight diagnostics; no executable authority guards.
- **P7:** byte-exact read-only verification of Python generation manifest, separate promotion envelope, HEAD, payload inventory and parent chain; SHA-256 and canonical JSON.
- **P7 opt-in scratch-store:** local noncanonical immutable test generations, cooperative file locking, fsync, HEAD compare-and-swap, simulated interruption and orphan/recovery inventory. This feature is **disabled by default** and absent from all CLI tools.
- **P3 v0.5:** structured receipt hash chain for scratch stages and publications, exact sequence/index, prior SHA-256 hash link, commit/manifest identity, HEAD continuity and duplicate/replay rejection.
- **Integrated with scratch-store:** emits append-only canonical JSON receipt files in scratch audit/ after staging and successful scratch HEAD publication. Re-reads and checks the complete audit chain under the cooperative lock before staging, publishing, reading the HEAD token or inspecting recovery. Aborts on tamper, gap or divergence between audit HEAD and on-disk scratch HEAD. No automatic repair or promotion.
- An optional Checkpoint can be retained **outside** the scratch tree and compared to the chain to detect truncation or wholesale reconstruction. The engine **does not authenticate** the checkpoint or establish trusted freshness.
- Four JSON stdin/stdout **read-only** diagnostics: galia-shadow, galia-preflight-shadow, galia-persistence-shadow, galia-audit-shadow. Python/Rust audit SHA-256 parity and negative fixtures.

## Build and verification

    cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets
    cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets --features scratch-store
    cargo build --manifest-path rust/galia-core/Cargo.toml --bins
    python -m unittest discover -s tests -p 'test_galia2_state_machine.py' -v
    python -m unittest discover -s tests -p 'test_galia2_preflight.py' -v
    python -m unittest discover -s tests -p 'test_galia2_persistence.py' -v
    python -m unittest discover -s rust/galia-core/tests -p 'test_*.py' -v

## Explicit audit failure states

1. Hash, sequence, commit, manifest, HEAD continuity or declared receipt filename mismatch: reject, fail closed.
2. Materialized generation but HEAD not advanced: prior HEAD remains; candidate is orphaned and retains a STAGED receipt. Human inspection is required.
3. HEAD swap succeeds but audit append fails: scratch HEAD may be advanced with incomplete journal; subsequent operations reject on audit mismatch. Do not auto-repair.
4. Truncating latest STAGED receipt with unchanged HEAD is not detectable using local hashes alone. An independently retained **authenticated** checkpoint would detect truncation; user-supplied Checkpoint is **not inherently trusted**.
5. Someone able to rewrite the entire scratch filesystem and any checkpoints may fabricate internally consistent records. A hash chain is tamper-evident **relative to a trusted anchor**, not immutable authority.

## Security boundaries and follow-on

- No authenticated reviewer signatures, P5 lifecycle/revocation, trusted provenance attestation, independent timestamping, hostile-actor protection, distributed consensus or trusted P3 receipt publication.
- Cooperative local lock/CAS is not a distributed or adversarially safe consensus protocol.
- Main, Python generation store, DW8, Supabase and all external data/control planes remain unchanged.
- Next: signed checkpoint verification, independent trust registry and revocation, P4 Legacy/MLX capture parity, adversarial filesystem tests and separately authorized production review.
- Historical source imagery must be genuinely sourced; EVENT_DATE != DOCUMENT_DATE; PROMPT_VERSION != ENGINE_VERSION; DW8 cannot write back authority.

**Never call a structural or hash PASS a human-authorized promotion.** Rust remains noncanonical.
