# GALIA Rust v0.15 — externally signed checkpoint verification and recovery hold

**DRAFT / NONCANONICAL / NOT AN EXTERNAL SERVICE / AUTHORITY_HOLD**

Python GALIA, the canonical HEAD, Supabase, DW8, historical evidence and all production permissions remain untouched.

## Retained v0.1–v0.14

P1/P2 typed stage machine; P5/P6 advisory human-decision and preflight structure; P7 Python SHA-256 manifest/HEAD verification; P3 linked audit and Ed25519 checkpoints; P5 signed scoped reviews; opt-in scratch storage/consume-once logs; scratch durable witness; v0.11 signed witness observations and receipts; v0.12 signed complete continuity and dual-key witness rotations; v0.13 observer quorum, split-view detection and offline endorsements; v0.14 immutable signed-publication scratch evidence board, full replay, exported/imported evidence, quarantine and optional caller-supplied checkpoint.

## v0.15 NEW — signed external board checkpoint protocol (OFFLINE)

- The feature-gated external_checkpoint module accepts a separately provisioned CheckpointAnchorTrust, never trusting keys or history extracted from the board directory. It requires a distinct Ed25519 checkpoint-signing key (different from P5 review, witness and observer keys), exact observer policy SHA-256, expected tenant/case, external stream identifier, pinned historical sequence and hash, and an exact board floor.
- Each SignedExternalBoardCheckpoint is signed in a separate Ed25519 domain, binding the exact board journal count/tip, persistent quarantine state, and SHA-256 of the complete stored signed split-view evidence (if quarantined). No runtime private keys or signing service are shipped.
- verify_anchor_chain demands every intermediate signed checkpoint envelope since the independently pinned floor, exact monotonically increasing sequence and prior-envelope hash. The signed board count cannot decrease, a signed same-count board digest cannot change, and a quarantined board cannot clear quarantine or grow its journal under the same anchored stream.
- inspect_anchored_board replays every local immutable entry and signature via DurableTransparencyBoard and compares the ACTUAL board state and SHA-256 fork evidence with the terminal externally signed checkpoint. Any alteration, missing historical checkpoint, missing fork evidence or wrong root/roster rejects.
- A signed checkpoint chain is only as trustworthy as its independently retained trust pin and externally provisioned signing key. The v0.15 module **does not publish checkpoints to another organization or guarantee remote durability**.
- The recovery outcome for a quarantined fork is a diagnostic requiring **human review**. No code path selects the winning fork, deletes evidence, repairs canonical data, clears quarantine, issues P2 guards or transfers P5 authority.
- Eleven new signed and adversarial tests cover incremental external floors, signed honest snapshots, key substitution, stream/roster mismatch, missing checkpoint, same-count digest rewrite, synthetic full journal rollback, quarantine durability, evidence digest, forbidden unquarantine and schema smuggling.
- Six read-only binaries and default Rust remain unchanged; all new code is disabled unless scratch-store is opted in.

## Critical security and deployment limits

1. The external anchor is a **caller-supplied offline trust input**. There is no deployed network checkpoint service, authenticated independent auditor, signing HSM, protected monotonic store or publication/gossip. Signing a fake history with a legitimate/compromised key remains possible. Full rollback of the board and ALL independently anchored trust pins is not prevented.
2. The extension of signed checkpoint envelopes proves consistency of the signed claimed board snapshots. It does NOT recompute all intermediate spend events from an independently administered transaction database. An external witness could sign alternate chains to two isolated clients without a real transparency/gossip service detecting it.
3. Recovery is **fail-closed read-only diagnosis**, not automatic repair. Canonical GALIA writes are still prohibited.
4. Original GALIA governance, identity verification, P4 MLX/Legacy equivalence, security review, live operational KMS, external independent anchors and multi-host network partition testing remain unresolved.

## Verify

    cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets
    cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets --features scratch-store
    cargo build --manifest-path rust/galia-core/Cargo.toml --bins
    python -m unittest discover -s tests -p 'test_galia2_state_machine.py' -v
    python -m unittest discover -s tests -p 'test_galia2_preflight.py' -v
    python -m unittest discover -s tests -p 'test_galia2_persistence.py' -v
    python -m unittest discover -s rust/galia-core/tests -p 'test_*.py' -v

EVENT_DATE != DOCUMENT_DATE; PROMPT_VERSION != ENGINE_VERSION. No AI-rendered historical images as evidence. AUTHORITY_HOLD is still mandatory.
