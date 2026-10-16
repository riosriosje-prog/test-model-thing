# GALIA Rust v0.12 — pinned append-only witness continuity (experimental)

**DRAFT / NONCANONICAL / NO HUMAN AUTHORITY / AUTHORITY_HOLD**

Original GALIA Python remains authoritative. Rust never writes the canonical HEAD, Supabase or DW8, and never issues P2 promotion guards.

## Preserved scope: v0.1–v0.11

P1/P2 stage state machine; advisory P5/P6 human decision/preflight structural diagnostics; P7 byte-exact Python payload/manifest/HEAD SHA-256 checks; P3 receipt hash chain and Ed25519 checkpoint trust registry; P5 signed-review key registry/scope diagnostics; opt-in scratch generation CAS, consumed ID/nonce journal, durable local witness and v0.11 signed observation/receipt verification. Default build and six CLI tools remain read-only.

## NEW v0.12: explicit signed historical continuity proof

- Feature-gated witness_continuity module verifies a **complete contiguous list** of signed witness receipts from an independently supplied pinned count/tip up to a signed terminal observation. Each receipt's count increments by one; prior tip must match, registry epochs must never decrease and duplicated authorization IDs / nonces **within the supplied suffix** are denied.
- A **new, separate witness rotation root** signs each key transition alongside the prior witness key. Domain-separated Ed25519 signatures bind namespace, case, witness count when rotation takes effect, old/new signer IDs, next witness public key, registry epoch floor and the SHA-256 of the previous signed rotation envelope. Transition at the wrong height, reused key/ID, role-confused key or unacknowledged transition is denied.
- After a rotation, all subsequent receipts and the signed terminal observation must use the new key; signatures from the prior key cannot be replayed. Two transitions at the same history height are prohibited.
- A terminal signed observation with a greater count but without ALL intermediate signed receipts is denied. The terminal exact count, digest and epoch must match the verified suffix.
- The continuity verifier is pure/read-only and available only with the disabled-by-default scratch-store feature. It does not alter existing witness networking, consume semantics, persistence, or production authority.
- Negative tests cover omitted/reordered receipts, altered tips and epochs, wrong/root-confused signer keys, old signing key after rotation, altered rotation signatures, height/lineage inconsistencies, revoked-by-scope keys and tampered observations.

## Security limits

- This verifies **cryptographically signed claimed continuity** relative to supplied trust anchors, not an independently deployed transparency log. A witness signer, or a compromised signing/rotation root, can equivocate between separate internally consistent histories. Independent trusted publication/gossip and external signed high-water checkpoints are still required.
- The pinned count/tip and both key roots MUST be independently provisioned and authenticated. Supplying these fields in the same request is not proof of their trustworthy origin or historical freshness.
- Receipt tip values are signed but not recomputed from an independently witnessed underlying database transaction. The suffix verifier proves chain claims, not that each historical spend really happened on an external service.
- Duplicate prevention across the unprovided historical prefix requires independently trusted ledger state; the suffix checker verifies duplicates only inside the supplied receipts.
- Rotations are diagnostic: keys are synthetic in tests; this does NOT introduce a live KMS, real reviewer identity, real key revocation/expiry chronology, distributed consensus or signed external witness deployment.
- Witness success before local-write failure remains non-atomic across services; reconciliation continues noncanonical and requires human oversight. No canonical writes.

## Validation

    cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets
    cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets --features scratch-store
    cargo build --manifest-path rust/galia-core/Cargo.toml --bins
    python -m unittest discover -s tests -p 'test_galia2_state_machine.py' -v
    python -m unittest discover -s tests -p 'test_galia2_preflight.py' -v
    python -m unittest discover -s tests -p 'test_galia2_persistence.py' -v
    python -m unittest discover -s rust/galia-core/tests -p 'test_*.py' -v

## Next before production

Externally provisioned witness and rotation roots, independent consistent transaction receipts, persistent anti-equivocation/public checkpoint service, formal human P5 identity/authority lifecycle, concurrent distributed network partition trials and receipt retention, P4 MLX/Legacy parity, independent security review and explicit human sign-off. Maintain AUTHORITY_HOLD until validated.

EVENT_DATE != DOCUMENT_DATE; PROMPT_VERSION != ENGINE_VERSION; AI-rendered imagery is never historical evidence.
