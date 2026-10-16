# GALIA Rust v0.17 — external trust transport protocol (NONCANONICAL)

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


## NEW v0.17: durable LOCAL SCRATCH transcript replay fence

- Feature-gated replay_fence module creates a separate explicitly new scratch root and requires externally provisioned ExternalServiceTrust and ObserverPolicy on every reopen. The local marker pins the digest of both policies but is not independently authenticated.
- A caller explicitly invokes DurableTranscriptReplayFence.accept_verified or fetch_and_accept. The full v0.16 verifier checks response-signature, claimed TLS channel evidence, nonce, time window, auditor checkpoint chain and full local board replay before an exclusive local file lock commits a one-shot journal record. Repeating a signed response OR challenge nonce rejects, including after a process restart or under concurrent cooperating file handles.
- Scratch records store only SHA-256 of the challenge and signed response, nonce, final checkpoint digest/sequence and caller supplied accepted time; no secret keys. Each sequential canonical JSON file is immutable create_new+fsync and linked to its predecessor with SHA-256. Reopen/replay enforces unique nonces/responses, monotonic caller times, strict naming and hash linkage. Corrupt/partial/undeclared/symlink records fail closed.
- 13 new tests cover exact transcript reuse, restart, two concurrent local handles, distinct fresh nonces, forgery, channel mismatch, outage, policy substitution, tampered/undeclared journal, clock regression, symlinks, new root precondition and the known vulnerability of complete rollback of the whole scratch directory.

## Unresolved v0.17 production limits

- The guarantee covers only cooperating processes sharing ONE local scratch filesystem. No distributed anti-replay, HSM, verified real TLS/mTLS, actual external service, independent clock, remote atomic transaction, human authority or canonical writes are implemented.
- A full snapshot rollback of the entire scratch directory can erase accepted nonces. Only an independently preserved monotonic high-water anchor can detect that; the new module does not install one. Local crash may leave a partial record that blocks further operations and needs controlled human remediation.
- The v0.16 stateless verifier still permits identical valid transcripts; callers must explicitly use the replay fence for local consume-once semantics. It is not globally authoritative.
- The TLS evidence structure is supplied by mocked fixtures; a true authenticated TLS adapter must be built separately and its peer verification must be trustworthy.
- All acceptance reports mark real transport verification, independent clock verification, external rollback anchor, P5 human authority, and canonical writeback as FALSE. AUTHORITY_HOLD is retained. No merge or deployment is authorized.


## NEW v0.18 — signed offline replay-journal high-water anchors

- Feature-gated ReplayAnchorTrust pins a DISTINCT Ed25519 public key and signer ID, separate anchor stream, exact service/tenant/case, SHA-256 of independently provisioned ExternalServiceTrust and ObserverPolicy, and a historical anchor sequence/hash plus exact prior replay journal count/tip. The key and historical floor MUST be retained outside the scratch root. No trusted signer or external publishing service is deployed.
- SignedReplayAnchor binds its strict consecutive sequence, previous signed envelope SHA-256, scope/configuration hashes and exact local replay count/tip. verify_anchor_chain rejects missing steps, key substitution/role confusion, changed tip at unchanged count, counter rollback and malformed signatures; validates a contiguous signed chain relative to the independently held floor.
- The complete local scratch journal is replayed and historical prefix tips are recalculated by DurableTranscriptReplayFence.checkpoint_at. verify_anchored_journal checks EVERY signed high-water observation against its exact replayed prefix, including the previously retained historical floor, not only the newest count.
- accept_anchored_verified first verifies the signed history and then rechecks the latest pinned historical prefix UNDER THE SAME local exclusive filesystem lock as nonce consumption. A restored older snapshot fails closed without consuming another nonce, as long as a newer authentic externally retained pin is supplied. The earlier accept_verified is still available for intentionally unanchored diagnostic scratch workflows; it is not production safe.
- 11 additional adversarial tests cover surviving signed checkpoint vs complete journal rollback, incrementally repinned high-water, two concurrent local handles, substituted signer/role/tenant/policy, missing signed sequence, same-count fork, invented future count, corrupt historical entries and authority-disabled flags.

### Remaining release blockers

- This implements an OFFLINE verifier for caller-supplied signatures and trust floor. It does NOT deploy independent checkpoint storage, trusted clock, signer HSM/KMS, remote TLS authentication, observer network, distributed anti-replay or global consensus. Test signatures are synthetic.
- A compromised real signer can sign a fork; a malicious actor rolling back BOTH the local journal and externally supplied high-water pin may evade detection. Independently protected monotonic retention/publication and accountability are still required.
- The local file lock protects cooperating processes using the same scratch directory only, not malicious filesystem writers or independent hosts; no guaranteed distributed transaction with a remote witness. An interrupted create/fsync can leave a corrupt record which fails closed.
- Successful offline signature verification is never a human P5 authorization, an executable P2 guard or a canonical HEAD/Supabase/DW8 modification. All production permissions remain held. AUTHORITY_HOLD continues. PR draft/unmerged.


## NEW v0.19 — real TLS 1.3 client transport (OPT-IN, no deployed server)

- The new tls-transport feature enables PinnedMtlsClient using rustls 0.23 and X.509 parser. Unlike v0.16 mock peer evidence, it opens a real TCP connection, negotiates TLS 1.3 with verified server certificates and locally provisioned client credentials.
- A verified server SubjectPublicKeyInfo SHA-256 is checked against an independently pinned service trust value; mismatch rejects even if the normal certificate chain is valid. A live TLS exporter is derived after the handshake. The challenge is scoped to exact service, tenant, case, stream, nonce, checkpoint floor and the exporter FROM THAT SESSION.
- The response is length-prefixed and bounded to 1 MiB, read only over TLS; callers must run the existing independently signed v0.16 checkpoint verification and opt-in anchored v0.18 nonce acceptance if appropriate.
- Three real-network loopback tests exercise an authenticated TLS 1.3 session with a test server mandating client-certificate verification, complete signed checkpoint verification, a wrong valid server SPKI pin, and a disconnected listener.
- Test certificates/keys are generated in-process, never persisted in the repository. TLS security does not imply that an arbitrary malicious server MUST request client credentials; the test server requires them and a future independently deployed service must have mandatory client authentication audited.
- No deployed server, HSM/KMS custody, independent trust root enrollment, protected monotonic external checkpoint, cross-host replay ledger, Byzantine fault tolerance or trusted clock is delivered by this client transport. All previous Rust modules remain noncanonical, with AUTHORITY_HOLD and default feature disabled. No production database or merge.


## NEW v0.20 — mandatory-client-auth TLS 1.3 test-service module

**DRAFT / NONCANONICAL / FEATURE DISABLED BY DEFAULT / AUTHORITY_HOLD**

The optional mtls_checkpoint_server module creates a controlled loopback-capable service handler (not a deployed network daemon). MandatoryMtlsCheckpointServer constructs the rustls TLS 1.3 ServerConfig internally with WebPkiClientVerifier and an independently supplied client-certificate root store. The constructor refuses empty trusted client roots, missing service certificate and an SPKI mismatch between the configured server certificate and separately pinned ExternalServiceTrust.

- serve_one negotiates real TLS 1.3, checks client certificate authentication through rustls, derives the live session TLS exporter, reads ONE bounded framed request, validates exact service/tenant/case/stream, nonce, channel binding and request issue/expiry against a supplied time, then looks up a complete contiguous suffix of separately signed checkpoint envelopes.
- ScratchCheckpointServiceStore only creates an explicitly new marked **local scratch** directory. It requires the same externally supplied trust profile on every reopen. Signed checkpoints are independently verified against CheckpointAnchorTrust and ObserverPolicy before appending to sequential canonical JSON immutable create_new/fsync entries under a cooperative OS file lock. It never creates or possesses an external auditor private key.
- The service response is signed by a caller-supplied signer callback. It verifies the signature against the externally pinned response public key BEFORE committing a durable challenge-nonce claim. The nonce journal is also strictly ordered, SHA-256-linked, fsynced and replayed before every claim and on restart. Duplicate nonces fail closed between cooperating requests/processes sharing this local store. A broken/crashed write blocks rather than silently repairs. If the reply fails after the nonce is committed, the nonce stays consumed; there is no cross-host distributed transaction.
- Eleven integration tests use in-memory synthetic test certificates and deterministic signer keys. Coverage includes successful mTLS and signed checkpoint roundtrip, duplicate nonce rejection across reopen, truly parallel identical-nonce TLS requests, refusal of invalid/duplicate signed checkpoints, wrong historical client floor, corrupt checkpoint and nonce journals, incompatible trust policy, certificate-less client rejection, incorrect server SPKI, and explicit documentation of full local checkpoint-directory rollback.
- No application-level administrative endpoints, user enrolment, approvals, archival evidence import, main/Python/Supabase/DW8 state modification, canonical HEAD, P2 guard issuance or P5 human authority are implemented.

### Hard limitations

The module is a **local test-service implementation, not an independently deployed external authority**. There is no production key custody/HSM, trusted caller clock, protected remote monotonic high-water publication, distributed consensus, multi-host failover, remotely durable anti-replay, full crash-torn-write repair, protected backups, signer revocation lifecycle or independent security audit. Caller-signed checkpoint envelopes are verified but **not generated by a separate live production board**, so valid signatures cannot certify physical transaction provenance or prevent a compromised legitimate signer from issuing conflicting histories. Local locks do not secure multi-host concurrency or a malicious filesystem actor.

A full rollback of the entire scratch service filesystem remains a residual vulnerability without authenticated independently retained signed high-water pins. The test key material is generated only for tests. AUTHORITY_HOLD is preserved. DO NOT treat a Rust unit-test SUCCESS or PR merge as a production cutover.
