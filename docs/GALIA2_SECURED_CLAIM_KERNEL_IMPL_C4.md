# GALIA 2.0 — Secured Claim Kernel Implementation Candidate c4

Candidate:
`GALIA-SECURED-CLAIM-KERNEL-IMPLEMENTATION-CANDIDATE-v1.0-c4`

Promoted parent:
`GALIA-SECURED-CLAIM-KERNEL-IMPLEMENTATION-CANDIDATE-v1.0-c3`

Promoted architecture:
`GALIA-SECURED-CLAIM-KERNEL-ARCH-CANDIDATE-v1.0-rc1`

## Scope

c4 adds a human-gated transition from exact NONFINAL assertion events to
operative legal-determination events inside the isolated secured-claim store.

The transition is deliberately not automatic:

`NONFINAL ASSERTION + EXACT HASH BINDING + HUMAN AUTHORIZATION + LEGAL AUTHORITY -> DETERMINATION`

## Two independent authority planes

c4 preserves two separate concepts:

1. **Human GALIA authorization**: authorizes GALIA to record a determination
   based on exact source-event hashes.
2. **Underlying legal authority**: statute, rule, court order, stipulation,
   contract, or other authority that actually supports the legal effect.

Human authorization is recorded in lineage, but it never substitutes for the
legal authority on the resulting canonical event.

## Allowed transitions

- CLAIM_ASSERTION_EVENT -> CLAIM_ALLOWANCE_EVENT
- LIEN_ASSERTION_EVENT -> LIEN_PRIORITY_EVENT
- PRIORITY_ASSERTION_EVENT -> LIEN_PRIORITY_EVENT
- VALUATION_ASSERTION_EVENT -> VALUATION_EVENT
- PAYMENT_ASSERTION_EVENT -> PAYMENT_EVENT
- PLAN_TREATMENT_ASSERTION_EVENT -> PLAN_TREATMENT_EVENT

All bound source assertions must independently support the requested
determination type. Mixed-family laundering fails closed.

## Required gates

- source assertion exists in SecuredClaimStore;
- source SHA-256 exactly matches the human authorization binding;
- source event remains `NONFINAL`;
- source event family is assertion-only;
- source blocker set is empty;
- human decision is exactly `AUTHORIZE_DETERMINATION`;
- reviewer, rationale, timestamps, determination type and payload are explicit;
- timestamps are timezone-aware;
- legal authority id/type/citation are explicit;
- new determination authority state is `OPERATIVE` or `FINAL`.

## Immutability and replay

The source assertion is never promoted or mutated. The determination is a new
canonical event with:
- human authorization id;
- human authorization SHA-256;
- reviewer identity;
- exact source event ids;
- exact source event hashes;
- determination payload;
- independent legal authority.

Replay of the exact same authorization is idempotent. A materially changed
human authorization yields a new determination event instead of overwriting
history.

## Explicit exclusions

- no automatic legal inference from HistoricalStore or shadow assertions;
- no automatic human authorization;
- no source-event mutation;
- no HistoricalStore writeback;
- no §506(a) secured-status compiler yet;
- no authority-state reversal/vacatur workflow yet;
- no merge;
- no production database;
- no main.py/model/Hugging Face mutation.

## Validation target

c4 adds 32 determination-gate tests on top of the promoted c3 surface.
Repository CI must remain green on Python 3.12 and 3.13 before c4 can become
promotion-eligible.
