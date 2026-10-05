# GALIA 2.0 — Secured Claim Kernel Implementation Candidate c5

Candidate:
`GALIA-SECURED-CLAIM-KERNEL-IMPLEMENTATION-CANDIDATE-v1.0-c5`

Promoted parent:
`GALIA-SECURED-CLAIM-KERNEL-IMPLEMENTATION-CANDIDATE-v1.0-c4`

Promoted architecture:
`GALIA-SECURED-CLAIM-KERNEL-ARCH-CANDIDATE-v1.0-rc1`

## Scope

c5 adds the §506(a) secured-status compiler.

It consumes only three already-operative/final legal determinations:

- `CLAIM_ALLOWANCE_EVENT`
- `VALUATION_EVENT`
- `LIEN_PRIORITY_EVENT`

and produces a new:

- `SECURED_STATUS_EVENT`

No raw HistoricalStore claim and no `*_ASSERTION_EVENT` can enter this compiler.

## Calculation chain

`allowed claim -> estate interest value -> value available after priority -> §506(a) classification`

The compiler applies:

`secured_portion = min(allowed_claim_amount, value_available_to_creditor)`

`unsecured_deficiency = allowed_claim_amount - secured_portion`

The arithmetic result does not erase or replace any input determination.

## Required provenance

Each input must:

- exist in the isolated SecuredClaimStore;
- match an exact caller-bound SHA-256;
- have the required event family;
- be `OPERATIVE` or `FINAL`;
- carry the c4 human-determination lineage:
  - human authorization id;
  - human authorization SHA-256;
  - human reviewer;
  - source event ids;
  - source event hashes;
- use legal authority other than `HUMAN_PROMOTION`.

This prevents a manually appended operative event without c4 provenance from
silently entering §506(a) classification.

## Cross-event consistency gates

The compiler fails closed unless:

- allowance, valuation and priority all identify the same `claim_id`;
- valuation and priority identify the same `collateral_package_id`;
- valuation and priority identify the same `priority_snapshot_id`;
- valuation provides an explicit `valuation_context_id`;
- all required monetary fields are finite and non-negative;
- `value_available_to_creditor <= estate_interest_value`.

## Authority boundary

The resulting `SECURED_STATUS_EVENT` uses an explicit §506(a) legal authority
provided to the compile request. A GALIA human-promotion authority cannot
substitute for that legal authority.

A `FINAL` secured-status result is permitted only when all three source
determinations are themselves `FINAL`. Otherwise the result may only be
`OPERATIVE`.

## Reproducibility

The result binds:

- compiler version;
- compile-request SHA-256;
- exact input event ids;
- exact input event SHA-256 values;
- claim id;
- collateral package id;
- valuation context id;
- priority snapshot id;
- allowed amount;
- estate-interest value;
- value available to creditor;
- secured portion;
- unsecured deficiency.

Replay of the exact same compile request is idempotent. A materially changed
request yields a new event.

## Explicit exclusions

- no direct assertion -> secured-status path;
- no HistoricalStore read/write path;
- no automatic priority inference;
- no automatic valuation selection;
- no §506(b) compiler in this slice;
- no reversal/vacatur state machine in this slice;
- no merge;
- no production database;
- no main.py/model/Hugging Face mutation;
- no automatic promotion.

## Validation target

c5 adds 36 secured-status compiler tests on top of the promoted c4 test
surface. Repository CI must remain green on Python 3.12 and 3.13 before c5
can become promotion-eligible.
