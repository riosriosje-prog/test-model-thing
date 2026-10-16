# GALIA 2.0 Rust shadow v0.11 — offline authenticated witness response adapter

**DRAFT / NOT PROMOTED / NONCANONICAL / AUTHORITY_HOLD**

Original GALIA Python remains authoritative. Main, production HEAD, Supabase, DW8 and legal evidence are unaffected.

## Established from v0.1–v0.10

- Typed P1/P2 source/stage transitions and guards; advisory P5/P6 human decision/preflight structural checks; P7 byte-exact SHA-256 payload/manifest/HEAD/parent replay.
- P3 SHA-256 audit chain, optional pinned checkpoint; Ed25519 trust registry and signed P3 checkpoint integrity.
- P5 Ed25519 root-signed reviewer registry, exact SELECT/case/claim/scope/commit/manifest/nonce matching, revocations and caller-supplied replay fences.
- Optional marked scratch-only immutable generation store, local consume-once journal, InMemoryWitness for test simulation.
- v0.10 scratch-only durable witness, local cooperative file lock, restart and corruption checks, CAS and replay-protected sequential writes. When external witness already consumed but local record is missing, replay-verified lookup and reconcile can append missing scratch record without a second consume.

## v0.11 NEW — signed witness response protocol, verified offline

- Feature-gated SignedWitnessTransport returns domain-separated Ed25519-signed observation and spend receipt envelopes; it also supports signed lookup for reconciliation.
- VerifiedWitnessAdapter binds observations and receipts to a caller-provisioned witness public key and signer ID, separate review-root public key, namespace/case and monotonic epoch/count floors. Wrong keys, tampered signed data, role-confused roots and wrong-case/namespace are rejected.
- Signed consumptions must additionally match the **exact** authorization ID, nonce, SHA-256 of signed P5 review, registry epoch and prior CAS tip. Signed lookups are checked against a fresh signed observation and cannot claim a count beyond it.
- v0.10 local scratch consume_with_witness and reconcile_with_witness already accept MonotonicWitness and may use VerifiedWitnessAdapter; witness receipt SHA-256 is bound into the local scratch record. The local scratch record does not embed the complete signed witness envelope.
- Tests use deterministic test-only signer keys and a locally durable witness mock. **The runtime contains no private signing keys, network service, remote KMS, authentication credentials or deployed external witness.**
- Existing six read-only CLIs unchanged; scratch and signed witness transport are disabled by default.

## Verify

    cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets
    cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets --features scratch-store
    cargo build --manifest-path rust/galia-core/Cargo.toml --bins
    python -m unittest discover -s tests -p 'test_galia2_state_machine.py' -v
    python -m unittest discover -s tests -p 'test_galia2_preflight.py' -v
    python -m unittest discover -s tests -p 'test_galia2_persistence.py' -v
    python -m unittest discover -s rust/galia-core/tests -p 'test_*.py' -v

## Critical limits

- A signed observation/receipt proves consistency with a **caller-pinned public key**, NOT independently established signer identity, authorization of a human reviewer, custody/legitimacy of the key, clock freshness, monotonicity beyond a separately retained high-water witness or proof of history extension after the pinned floor.
- The SignedWitnessTransport interface is not an implemented remote network client; the test fixtures sign on the local test machine. The durable scratch witness itself still issues unsigned records; production-grade witness signing/key custody does not exist.
- No distributed atomic commit. The witness may consume and sign before local write failure; reconciliation requires a trustworthy signed lookup. If returned data disagree, operations fail closed.
- A service holding the signing key can equivocate between forked histories; signatures alone do not prove append-only extensions or defeat full witness rollback. Independent anchored checkpoints/consistency proofs, trust provisioning, KMS, authenticated transport and durable distributed consensus are still required.
- No canonical store writes, no P2 executable promotion guards, no live credential enrollment or human authority. Preserve AUTHORITY_HOLD.

## Next production gates

Separately deployed authenticated witness, pinned external high-water ledger, verified append-only consistency proof and key rotation, signed durable receipt retention and remote restart/network-partition tests, true human identity/policy lifecycle, P4 Legacy/MLX and independent security review. No merge or deployment without explicit authorization.

EVENT_DATE != DOCUMENT_DATE; PROMPT_VERSION != ENGINE_VERSION; generated images are not archival evidence.
