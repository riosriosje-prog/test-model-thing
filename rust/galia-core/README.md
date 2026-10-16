# GALIA Rust v0.16 — external trust transport protocol (NONCANONICAL)

**CANDIDATE / DRAFT / NOT DEPLOYED / AUTHORITY_HOLD**

Rust shadow v0.16 adds OFFLINE verification of the wire contract that a future independently operated checkpoint service MUST implement. It does NOT deploy a server, TLS stack, key vault or remote witness. Python GALIA, canonical HEAD, DW8 and Supabase remain authoritative and unmodified.

## Retained safety functionality

P1/P2 state machine and stage guards; advisory P5/P6 structural decision/preflight; P7 Python-compatible SHA-256 manifest/HEAD checks; P3 audit receipts and Ed25519 checkpoints; root-registered P5 review signatures; opt-in scratch generation/consume-once ledger and durable witness; v0.11 signed witness observations and receipts; v0.12 signed historical receipt continuity and dual-signed key rotation; v0.13 quorum of pinned observer signatures and split-view detection; v0.14 immutable signed publication board with fork quarantine; v0.15 offline externally signed checkpoint chain and fail-closed manual recovery.

## NEW v0.16

- Feature-gated external_transport module supplies ExternalServiceTrust and a RemoteCheckpointTransport interface for a FUTURE externally run, mTLS-authenticated checkpoint publisher. The module itself contains no network code or signing keys.
- Externally configured pins must bind the known checkpoint signer's key, service response verifier key (a separate Ed25519 role), exact service/stream/tenant/case, pinned observer policy SHA-256, a TLS server SPKI SHA-256 pin, and an independent previous external checkpoint sequence and envelope hash.
- RemoteCheckpointChallenge binds a caller-generated cryptographic nonce, exact externally pinned checkpoint floor, a TLS exporter SHA-256 from the SAME verified connection, issuance/deadline times and scoped service identity. Maximum challenge lifetime: 300 seconds; test profile: 60 seconds. A trusted caller-provided current time is checked against issuance, expiry and signature timestamp.
- TransportPeerEvidence is ONLY a data contract to be supplied by a REAL independently implemented, correctly authenticated TLS stack. A boolean saying mTLS was done or a caller-supplied TLS exporter hash **cannot by itself prove TLS happened**.
- SignedRemoteCheckpointResponse is separately signed in an Ed25519 protocol domain by the service's pinned response key. Signature binds entire response: nonce, challenge SHA-256, same TLS channel exporter, signed time and bounded checkpoint chain. Each embedded checkpoint is then authenticated against the separately pinned external auditor signing key; its complete contiguous sequence is checked against an independently held floor.
- The local board journal is FULLY replay-verified again and checked against the latest signed external checkpoint and any quarantined signed-fork evidence. Network/transport failure, signature mismatch, stale time, wrong peer SPKI, absent claimed mutual client authentication, role-confused key, wrong namespace, forged checkpoint or local board rollback FAIL CLOSED with no write.
- **13 adversarial integration tests** cover profile/role confusion, bad response signatures, SPKI and exporter mismatch, missing mTLS assertion, wrong challenge nonce, signed timestamp expiration/future, wrong service/case/stream, invalid nested checkpoint, incompatible observer roster, full local board rollback, simulated network partition, unknown injected authority fields and repeated valid transcript.
- Existing six read-only CLI binaries and the production/default library surface remain unchanged. The new transport contract is opt-in ONLY with scratch-store feature enabled; no automatic retries or background task.

## Deployment-readiness gates (not yet satisfied)

1. Independently provision the service signing key and auditor checkpoint key in an HSM/KMS with authenticated role/rotation/revocation policy. Protect reviewer and observer roots separately; publish accountable key lineage.
2. Implement a **real, audited** TLS 1.3/mTLS network adapter that performs certificate/hostname and pin validation and supplies channel exporter and client-auth proof. Never trust a server-supplied statement about its own TLS identity. Prove externally provisioned trust roots were bootstrapped correctly.
3. Use independently trusted clock and a durable, monotonic nonce-challenge registry. This verifier is STATELESS: replay of an identical valid signed transcript during its valid challenge window can still pass. Distinct TLS session export keys limit cross-session replay only if the TLS adapter is honest.
4. Independently deploy a remotely durable linearizable witness + signed checkpoint service, externally administered append-only observer publications, out-of-band high-water checkpoints, anti-equivocation gossip and network partition drills. A mocked transport cannot prove real host security or consensus.
5. Reconcile witness/board partial commits without automatic cleanup or history deletion. Handle unavailable witnesses fail-closed. A signed remote receipt DOES NOT give P5 human approval, P2 executable promotion guards, canonical write permission, or authority transfer.
6. Complete P4 MLX/Legacy parity, security audit, reproducible build and explicit human release approval; do not merge or deploy the shadow candidate until those separately governed gates are met.

## Validation

    cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets
    cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets --features scratch-store
    cargo build --manifest-path rust/galia-core/Cargo.toml --bins
    python -m unittest discover -s tests -p 'test_galia2_state_machine.py' -v
    python -m unittest discover -s tests -p 'test_galia2_preflight.py' -v
    python -m unittest discover -s tests -p 'test_galia2_persistence.py' -v
    python -m unittest discover -s rust/galia-core/tests -p 'test_*.py' -v

**Invariants:** EVENT_DATE != DOCUMENT_DATE; PROMPT_VERSION != ENGINE_VERSION; AI-generated historical images cannot become archival evidence. AUTHORITY_HOLD persists.
