# GALIA 2.0 — Secured Claim Kernel Implementation Candidate c3

Candidate:
`GALIA-SECURED-CLAIM-KERNEL-IMPLEMENTATION-CANDIDATE-v1.0-c3`

Promoted parent:
`GALIA-SECURED-CLAIM-KERNEL-IMPLEMENTATION-CANDIDATE-v1.0-c2`

Promoted architecture:
`GALIA-SECURED-CLAIM-KERNEL-ARCH-CANDIDATE-v1.0-rc1`

## Scope

c3 adds a read-only shadow bridge from HistoricalStore into the isolated
secured-claim event store.

The bridge is intentionally asymmetric:

`HistoricalStore -> deterministic shadow assertion -> SecuredClaimStore`

There is no writeback path.

## Authority boundary

A HistoricalStore claim is not automatically an operative bankruptcy-law
determination. c3 therefore accepts only explicitly tagged source claims and
maps them to an assertion-only allowlist:

- CLAIM_ASSERTION_EVENT
- LIEN_ASSERTION_EVENT
- VALUATION_ASSERTION_EVENT
- PRIORITY_ASSERTION_EVENT
- PAYMENT_ASSERTION_EVENT
- PLAN_TREATMENT_ASSERTION_EVENT

Every imported event is persisted with
`authority_state = NONFINAL`.

The bridge explicitly rejects attempted direct import as:
- CLAIM_ALLOWANCE_EVENT
- SECURED_STATUS_EVENT
- or any other non-assertion event family.

## Required source metadata

The HistoricalStore claim must include a `secured_claim_shadow` object with:

- assertion event type;
- timezone-aware legal effective timestamp;
- authority reference.

The claim must be `PROPOSED` or `VALIDATED` and must have at least one
evidence row. A source claim already marked `CANONICAL` is not imported as
legal authority.

## Lineage

The persisted assertion event binds:
- source claim id and source status;
- source document id and predicate;
- SHA-256 of claim text, not verbatim claim text;
- exact claim-bundle SHA-256;
- exact evidence-snapshot SHA-256;
- promotion blocker codes;
- shadow profile version.

The event id includes the exact source bundle hash. Replaying an unchanged
bundle is idempotent. A changed source bundle creates a new historical shadow
event rather than mutating the prior event.

## Explicit exclusions

- no HistoricalStore mutation;
- no automatic legal determination;
- no automatic promotion;
- no database migration of HistoricalStore;
- no merge to main;
- no production database;
- no model/Hugging Face mutation.

## Validation target

c3 adds 22 bridge tests on top of the promoted c2 test surface. Repository CI
must remain green on Python 3.12 and 3.13 before c3 can be promotion-eligible.
