# GALIA Rust shadow v0.13 — signed observer gossip and split-view detection

**STATUS: DRAFT / NONCANONICAL / NO DEPLOYED GOSSIP / AUTHORITY_HOLD**

The original Python GALIA core remains authoritative. No production GALIA HEAD, P2 promotion guard, Supabase, DW8 or historical evidentiary record is modified.

## Retained functionality

P1/P2 typed event/stage state machine, advisory P5/P6 exact-scope decision/preflight, P7 byte-exact Python SHA-256 manifest/payload/HEAD/parent verification, P3 hash-linked audit and Ed25519 checkpoints, P5 signed review structure and revocation, opt-in local immutable scratch store and authorization/nonce consume-once journal, scratch durable witness, signed witness receipts and the v0.12 contiguous signed receipt + dual-signed key rotation verifier. Six existing CLIs are read-only.

## NEW v0.13 — pure offline observer transparency protocol

- ObserverPolicy specifies an **out-of-band provisioned** witness verification anchor, observer roster epoch, independent Ed25519 public keys and a minimum quorum of **two** nonrevoked, unique observer keys. The code rejects observer keys identical to the review root or witness signer key, duplicate IDs/public keys and unavailable quorum.
- SignedGossipEndorsement binds its observer identity, namespace, case, roster epoch, signed witness observation **envelope SHA-256**, reported count, tip and registry epoch to a separate domain-separated Ed25519 signature. A publication passes only if the original witness observation is itself signature-valid, every endorsement is correct, and quorum is achieved. Unknown, duplicate, revoked or substituted observers fail closed.
- compare_publications() examines two independently endorsed signed witness observations. If BOTH have the same count but different signed tips or registry epochs, it returns **ConflictingSignedState** with the hashes of both signed observation envelopes for preservation as split-view evidence. Same state is not a conflict. DIFFERENT counts are always reported **DifferentHeightExtensionNotEstablished** (neither evidence of tampering nor proof of consistency).
- verify_publication_extension() requires endorsed earlier and later observations under an unchanged pinned observer roster, plus a full v0.12 chain of signed intervening receipts and optional root-authorized witness key rotations. It only returns VerifiedSignedExtension once starting count/tip/epoch, terminal signed observation, and final signer are EXACTLY bound to the published views. A new witness signing key may be used only if verified via the historical rotation proof.
- NEW 14 targeted tests validate quorum, revocation, role/key separation, forged endorsements, split-view signatures, same-state comparison, missing/reordered receipts, provenance-pinned endpoints, and changed observer roster.
- Feature gated behind scratch-store (disabled by default), no network, background gossip, publishing service or canonical write path.

## Exact security boundaries

1. Both observer roster and witness root are **caller-supplied**. The module does not independently authenticate their origin, true organizational independence, public key custody, freshness or revocation chronology. Test keys are synthetic and cannot be regarded as real independent observers.
2. If a witness key signs different tips or epochs at the SAME count, two valid publications constitute checkable signed-conflict evidence. This does NOT identify the malicious actor, prove an actual remote log diverged, or establish real-world observer identity.
3. For differing heights, a complete signed suffix establishes a **claimed cryptographic extension only**. Receipts' tip digests are not independently recomputed from a production transaction log; a compromised witness and rotation root can collude or equivocate. Authentic trusted publication/gossip, external immutable checkpoint retention, and independent ledger replay are required.
4. Duplicate authorization and nonce checks in the suffix do NOT validate against every item of the independently absent historic prefix. Signed witnesses do not prove the prior registry was complete.
5. This is an offline verifier, NOT a deployed transparency system. It cannot create signatures, perform cross-host networking, guarantee consensus, issue verified human approval or promote anything.
6. AUTHORITY_HOLD persists. Human governance, reviewer credential verification, KMS/HSM custody, witness Byzantine threat modeling, P4 MLX/Legacy parity, filesystem rollback protection and independent security review remain production blockers.

## Verify

    cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets
    cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets --features scratch-store
    cargo build --manifest-path rust/galia-core/Cargo.toml --bins
    python -m unittest discover -s tests -p 'test_galia2_state_machine.py' -v
    python -m unittest discover -s tests -p 'test_galia2_preflight.py' -v
    python -m unittest discover -s tests -p 'test_galia2_persistence.py' -v
    python -m unittest discover -s rust/galia-core/tests -p 'test_*.py' -v

**Invariants:** EVENT_DATE != DOCUMENT_DATE; PROMPT_VERSION != ENGINE_VERSION. AI-generated historical images are not evidence. Do not merge or deploy without an independently authorized human decision.
