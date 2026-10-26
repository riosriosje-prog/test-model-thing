# GALIA 2.0 — Secured Claim Kernel Implementation Candidate c2

Candidate:
`GALIA-SECURED-CLAIM-KERNEL-IMPLEMENTATION-CANDIDATE-v1.0-c2`

Parent candidate:
`GALIA-SECURED-CLAIM-KERNEL-IMPLEMENTATION-CANDIDATE-v1.0-c1`
(unpromoted; c2 is an engineering continuation, not an authority transfer)

Promoted architecture:
`GALIA-SECURED-CLAIM-KERNEL-ARCH-CANDIDATE-v1.0-rc1`

Architecture spec SHA-256:
`227ebe7cdfb79d430b024c9aebe6ea9a670ac8c12f86179704751fd1783187bd`

## Scope

c2 adds isolated SQLite persistence to the c1 in-memory kernel.

### Canonical persistence
- schema version 1;
- SQLite WAL + FULL synchronous;
- foreign keys enabled;
- explicit transaction boundary using BEGIN IMMEDIATE;
- append-only canonical event table;
- deterministic event SHA-256;
- idempotent replay;
- conflict rejection for reused event IDs;
- supersession lineage requiring an existing prior event;
- persisted authority-state separation.

### Derived persistence
- derived snapshot cache is physically separate from canonical events;
- every snapshot requires persisted source-event lineage;
- snapshots remain marked by calculation version, purpose and as-of date;
- cached snapshots are append-only records and do not mutate source events.

### Fail-closed
- future schema versions are rejected;
- missing source-event lineage blocks snapshot persistence;
- direct canonical UPDATE/DELETE is blocked by SQLite triggers;
- direct snapshot UPDATE is blocked.

## Explicit exclusions

- no mutation of `historical_store.py`;
- no migration of an existing HistoricalStore database;
- no `main.py` changes;
- no production database;
- no automatic import of historical claims;
- no sale/DIP/plan persistence yet;
- no merge or promotion.

## Validation target

- c1 kernel tests: 32
- c2 persistence tests: 22
- candidate-specific total: 54

The repository's full unittest suite must remain green on Python 3.12 and 3.13
before c2 can become promotion-eligible.
