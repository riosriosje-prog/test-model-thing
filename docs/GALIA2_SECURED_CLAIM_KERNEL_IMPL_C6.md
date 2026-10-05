# GALIA 2.0 — Secured Claim Kernel Implementation Candidate c6

Candidate:
`GALIA-SECURED-CLAIM-KERNEL-IMPLEMENTATION-CANDIDATE-v1.0-c6`

Promoted parent:
`GALIA-SECURED-CLAIM-KERNEL-IMPLEMENTATION-CANDIDATE-v1.0-c5`

Promoted architecture:
`GALIA-SECURED-CLAIM-KERNEL-ARCH-CANDIDATE-v1.0-rc1`

## Scope

c6 adds the §506(b) oversecurity/component ceiling compiler and extends the
governed assertion/determination pipeline for:

- `SECTION_506C_ASSERTION_EVENT -> SECTION_506C_RECOVERY_EVENT`
- `SECTION_506B_COMPONENT_ASSERTION_EVENT -> SECTION_506B_COMPONENT_EVENT`

The compiler produces:

- `OVERSECURITY_DETERMINATION`
- optional `CUSHION_ALLOCATION_EVENT`
- `SECTION_506B_ACCRUAL_EVENT`

## Input chain

c6 accepts only governed inputs:

1. a promoted c5 `SECURED_STATUS_EVENT`;
2. a c4-governed `VALUATION_EVENT` explicitly for `SECTION_506B`;
3. zero or more c4-governed `SECTION_506C_RECOVERY_EVENT` records;
4. one or more c4-governed `SECTION_506B_COMPONENT_EVENT` records.

Raw assertions never enter the arithmetic compiler.

## Non-circular oversecurity calculation

The compiler applies:

`net_collateral_base = collateral_value_for_506b - allowed_506c_recoveries`

`available_506b_cushion = max(0, net_collateral_base - pre_506b_claim_base)`

The `pre_506b_claim_base` comes from the already-governed allowed claim in
the c5 secured-status event. §506(b) additions are not folded into that base
before entitlement/ceiling is determined.

## Component eligibility is upstream

c6 does not decide legal entitlement from a contract, invoice, time sheet, or
raw claim. Every component must already be a c4 legal determination marked
`ELIGIBLE`.

For `INTEREST`, an explicit `rate_source` is required.

For `FEE`, `COST`, or `CHARGE`:
- `entitlement_source` must be `AGREEMENT` or `STATE_STATUTE`;
- `reasonableness_state` must be `REASONABLE`.

Thus:

`ELIGIBLE COMPONENT != SECURED AMOUNT WITHIN CUSHION`

## No silent priority among §506(b) components

If the total eligible amount fits within the cushion, all eligible amounts may
be secured without an internal priority rule.

If the cushion is zero, all secured amounts are zero and no internal priority
rule is necessary.

If the cushion is positive but insufficient, c6 fails closed unless a
`CushionAllocationDirective` supplies:
- an explicit allocation sequence;
- an explicit rule type;
- `SUBSTANTIVE_PRIORITY` semantics;
- an independent legal authority.

A human GALIA promotion cannot establish the substantive allocation priority.

## §506(c) ordering

Allowed §506(c) recoveries reduce the §506(b) collateral base before the
oversecurity cushion is measured.

The compiler rejects:
- a recovery not marked `ALLOWED`;
- a recovery bound to the wrong claim or collateral package;
- aggregate §506(c) recovery greater than the §506(b) collateral value.

## Context and provenance

The §506(b) valuation must carry:
- the same claim id as the c5 secured status;
- the same collateral package;
- an explicit `valuation_context_id`;
- `valuation_purpose = SECTION_506B`;
- `collateral_value_for_506b`.

This permits §506(b) valuation context to differ from the earlier §506(a)
valuation without overwriting or conflating the two.

All c4-derived inputs must carry exact:
- human authorization id/hash;
- source event ids/hashes;
- independent legal authority.

The c5 secured-status input must carry its exact c5 compiler provenance.

## Output invariants

- `TOTAL_506B_SECURED_ALLOWANCE <= AVAILABLE_506B_CUSHION`
- `§506(c) RECOVERY PRECEDES §506(b) CUSHION`
- `ELIGIBILITY != CUSHION ALLOCATION`
- `INTEREST != FEE/COST/CHARGE ENTITLEMENT GATE`
- `NO POSITIVE SHORTFALL ALLOCATION WITHOUT LEGAL AUTHORITY`
- `HUMAN PROMOTION != §506(b) LEGAL AUTHORITY`

A `FINAL` c6 result requires every bound legal input to be `FINAL`.

## Reproducibility

The c6 request hash binds:
- all input ids/hashes;
- §506(b) authority;
- allocation authority and semantics when used;
- result state;
- compiler version.

The generated events bind the exact input ids/hashes, valuation context,
§506(c) recovery total, net collateral base, cushion, component eligibility,
secured amounts, and remaining cushion.

Replay is idempotent; changed requests yield different event ids.

## Explicit exclusions

- no raw assertion -> §506(b) arithmetic path;
- no automatic component entitlement;
- no automatic internal priority among §506(b) components;
- no §506(d) lien consequence compiler;
- no Chapter 11/13 plan-treatment compiler in this slice;
- no authority reversal/vacatur state machine;
- no HistoricalStore writeback;
- no production DB mutation;
- no main.py/model/Hugging Face mutation;
- no merge;
- no automatic promotion.

## Validation target

c6 adds 41 §506(b) compiler tests and extends the c3/c4 allowlists for the two
new governed assertion/determination families. The full repository unittest
suite must remain green on Python 3.12 and 3.13 before c6 can become
promotion-eligible.
