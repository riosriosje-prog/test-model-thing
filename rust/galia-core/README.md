# GALIA Rust shadow v0.14 — durable signed-publication evidence board

**DRAFT / NONCANONICAL / NO NETWORK SERVICE / NO HUMAN AUTHORITY / AUTHORITY_HOLD**

The existing GALIA Python core is authoritative. Nothing in this Rust candidate changes the actual canonical GALIA HEAD, Supabase, DW8, historical evidence, promotion guards or main.

## Preserved functionality v0.1–v0.13

Typed P1/P2 stage transitions; advisory P5/P6 structural preflight/review; P7 byte-compatible SHA-256 payload, manifest, HEAD and parent replay; P3 hash-linked receipts and Ed25519 checkpoints; P5 scoped Ed25519 reviewer registry; opt-in scratch generation CAS/consume-once journal, durable local witness, signed witness receipts/observations, dual-signed key rotation, contiguous signed history extension verifier; v0.13 threshold-two signed observer gossip and split-view comparison. Default build and all six CLIs remain read-only.

## v0.14 NEW — durable SCRATCH transparency board and peer exchange

- New feature-gated DurableTransparencyBoard only initializes a brand-new, explicitly marked noncanonical test directory and demands a separately caller-provisioned ObserverPolicy even on reopen. Local marker configuration is NEVER trusted by itself. Two observer signatures are required for every accepted publication.
- The board appends canonical JSON journal entries, numbering them strictly and chaining each to the SHA-256 of the previous entry. Files use create-new and fsync, and a cooperative exclusive local lock serializes writes. Reopening **fully replays and re-verifies** observer signatures, journal links, historical continuity proofs and conflict evidence. Corruption, missing entries, inserted entries or symlinks reject without automatic repair.
- First publication must exactly equal the independently pinned count/tip from the board policy. A strictly higher-count observation requires a full v0.12 signed receipt extension anchored to the previous accepted observation; an unsupported forward jump rejects. Same signed state is idempotent and does not append.
- Two fully signed and quorum-endorsed observations at the SAME height with incompatible SHA-256 tips or epochs cause both signed envelopes to be retained in a journal record. The board enters a **persistently replay-derived quarantine**, refusing every subsequent write; it never selects a winning fork or rewrites history. When an imported conflicting view carries a signed extension, the verifier first checks that extension against the previously published anchored predecessor; a mismatched proof rejects without triggering quarantine.
- Offline export and re-import of complete signed publication/extension envelopes allows two scratch boards to exchange evidence. The receiving board rechecks every signature against ITS OWN separately pinned policy. No actual network gossip, transport authentication, independent observer infrastructure or cross-host consensus exists.
- Inspect, export, checkpoint and evidence APIs are read-only. An externally retained journal-count/tip checkpoint can detect full-directory journal truncation; a checkpoint kept in the same attackable directory is not trustworthy.
- 12 adversarial integration tests cover restart, signed extension, idempotence, same-height forks and durable quarantine, separate scratch board evidence exchange, corrupted journal, independently pinned policy mismatch, external checkpoint rollback, concurrent handles and symlinks.

## Security and accuracy boundaries

- **This is not a deployed transparency service.** Local files plus cooperative OS locks do not establish independence across machines, withstand malicious filesystem actors, or ensure distributed rollback/fork resistance.
- All keys, observer roster and witness root are supplied from a claimed trusted external configuration. This code does NOT prove how they were enrolled, that observers are truly independent, that the roster is fresh or that any one signer did not equivocate.
- Observers sign witness claims; receipt SHA-256 fields are NOT independently computed from a live production transaction log. Even valid contiguous signed evidence cannot prove all real-world spends or prevent coordinated signers from publishing alternative histories.
- Quarantine prevents further local scratch writes. It does NOT decide which fork is correct, initiate canonical rollback, infer bad faith, assign real-world blame, grant P5 human authority or issue P2 promotion guards.
- A full malicious rewrite of journal AND the caller's trust anchor may defeat local integrity. A durable independently managed externally authenticated checkpoint/publication, correct key lifecycle, Byzantine threat analysis and real network observers remain required.
- This board cannot promote any canon, write into Supabase or DW8, deploy a service, or merge its PR. AUTHORITY_HOLD is preserved.

## Verify

    cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets
    cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets --features scratch-store
    cargo build --manifest-path rust/galia-core/Cargo.toml --bins
    python -m unittest discover -s tests -p 'test_galia2_state_machine.py' -v
    python -m unittest discover -s tests -p 'test_galia2_preflight.py' -v
    python -m unittest discover -s tests -p 'test_galia2_persistence.py' -v
    python -m unittest discover -s rust/galia-core/tests -p 'test_*.py' -v

## Remaining production prerequisites

Authenticated externally deployed witness and quorum observers; provisioned independent keys, monotonic checkpoints and trusted key rotation/revocation; crash/network partition/BFT and multi-host consistency testing; P5 identity and governance; legal evidence audit and P4 Legacy/MLX parity; security review plus explicitly authorized human merge. No canonical cutover or publication based solely on shadow tests.

EVENT_DATE != DOCUMENT_DATE; PROMPT_VERSION != ENGINE_VERSION. AI-generated imagery must never be treated as historical evidence.
