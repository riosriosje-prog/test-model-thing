# GALIA 2.0 — Secured Claim Kernel Implementation Candidate c8

Candidate:
`GALIA-SECURED-CLAIM-KERNEL-IMPLEMENTATION-CANDIDATE-v1.0-c8`

Promoted parent:
`GALIA-SECURED-CLAIM-KERNEL-IMPLEMENTATION-CANDIDATE-v1.0-c7`

## Scope

c8 adds the §506(d) lien-consequence compiler.

It implements the architecture invariant:

`§506(a) SECURED CLASSIFICATION != §506(d) LIEN CONSEQUENCE`

and refuses to treat collateral arithmetic as an automatic lien strip.

## Governed input families

c8 extends the c3/c4 pipeline with:

- `LIEN_EXISTENCE_ASSERTION_EVENT -> LIEN_EXISTENCE_EVENT`
- `CLAIM_STATUS_ASSERTION_EVENT -> CLAIM_STATUS_EVENT`

Both operative determinations must carry exact c4 human-authorization/source
lineage and must be effectively OPERATIVE or FINAL after c7 lifecycle replay.

For an ALLOWED claim with an existing lien, c8 also requires an exact promoted
c5 `SECURED_STATUS_EVENT`.

## Lien existence is upstream of §506(d)

The lien existence determination must state:

- claim id;
- lien id;
- collateral package id;
- `lien_property_interest_state = EXISTS | DOES_NOT_EXIST`;
- `perfection_state = PERFECTED | UNPERFECTED | NOT_APPLICABLE`;
- applicable nonbankruptcy law;
- property-interest basis.

If the operative legal determination says `DOES_NOT_EXIST`, c8 produces:

`NO_LIEN_PROPERTY_INTEREST`

and records:

`section_506d_effect = NOT_REACHED`

It does not pretend that §506(d) caused the absence of the lien.

Existence and perfection remain separate. An existing but unperfected lien is
not automatically voided by c8; avoidance powers outside §506(d) are outside
this slice.

## Claim-status states

The governed `CLAIM_STATUS_EVENT` supports:

- `ALLOWED`
- `DISALLOWED`
- `NOT_ALLOWED_DUE_ONLY_TO_NO_PROOF`

A DISALLOWED event must identify:

- `502B5`
- `502E`
- `OTHER`

c8 follows the text of 11 U.S.C. §506(d):

- DISALLOWED / OTHER -> lien void to extent of disallowed claim;
- DISALLOWED only under §502(b)(5) or §502(e) -> statutory exception (1);
- not allowed secured only because no proof of claim was filed under §501 ->
  statutory exception (2).

## Chapter 7

For an ALLOWED claim secured by an existing lien, c8 requires a c5 §506(a)
classification but does not use that arithmetic as an automatic lien-voiding
rule.

The request must bind an explicit rule basis and independent legal authority.

Results:

- partially undersecured Chapter 7 allowed claim:
  `DEWSNUP_CH7_NO_STRIP_DOWN`
  -> `NO_506D_STRIP_DOWN_CH7_ALLOWED_CLAIM`

- zero §506(a) secured portion Chapter 7 allowed claim:
  `CAULKETT_CH7_NO_STRIP_OFF`
  -> `NO_506D_STRIP_OFF_CH7_ALLOWED_CLAIM`

- fully secured allowed lien:
  `ALLOWED_LIEN_UNAFFECTED_506D`
  -> `LIEN_UNAFFECTED_BY_506D_ALLOWED_FULLY_SECURED`

Thus:

`SECURED_PORTION_506A = 0 != LIEN VOID UNDER §506(d) IN CHAPTER 7`

## Chapters 11 and 13

c8 does not silently transplant the Chapter 7 Dewsnup/Caulkett consequence into
plan chapters.

For an ALLOWED claim with an existing lien, c8 produces:

- `NO_AUTOMATIC_506D_CONSEQUENCE_CHAPTER_11`
- `NO_AUTOMATIC_506D_CONSEQUENCE_CHAPTER_13`

with:

`CHAPTER_SPECIFIC_TREATMENT_REQUIRED`

The actual plan-treatment consequences remain downstream and outside c8.

For Chapter 13, this preserves the separate role of §1322(b)(2), §1325 and
Nobelman-type rights analysis instead of overwriting those doctrines with a
§506(a) number.

## Explicit rule-basis gate

The caller must bind a `rule_basis_code`. c8 independently derives the rule
that the supplied inputs require and rejects a mismatch.

Supported rule bases:

- `NONBANKRUPTCY_LIEN_EXISTENCE`
- `SECTION_506D_STATUTORY_VOIDING`
- `SECTION_506D_EXCEPTION_1`
- `SECTION_506D_EXCEPTION_2`
- `DEWSNUP_CH7_NO_STRIP_DOWN`
- `CAULKETT_CH7_NO_STRIP_OFF`
- `ALLOWED_LIEN_UNAFFECTED_506D`
- `CHAPTER_SPECIFIC_TREATMENT_REQUIRED`

The resulting event carries an independent rule authority. Human GALIA
promotion cannot substitute for either §506(d) authority or rule authority.

## c7 lifecycle integration

Every input is resolved through c7 CURRENT_STATE replay.

Inputs whose effective state is:

- STAYED
- APPEAL_PENDING
- SUPERSEDED
- VACATED
- REVERSED

are rejected even when the immutable source event row still says OPERATIVE.

The c8 request hash and output bind each input lifecycle tail id/hash.

## Derivation-identity hardening

c8 does not accept copied provenance fields at face value.

For c4 inputs, the event id must exactly match:

`legal-determination:{human_authorization_id}:{human_authorization_sha256}`

For the c5 secured-status input, the event id must bind the exact
`compile_request_sha256`.

This prevents a manually appended event with copied provenance fields from
masquerading as a governed upstream determination.

## Output

c8 produces an immutable:

`LIEN_CONSEQUENCE_EVENT`

binding:

- chapter;
- claim id;
- lien id;
- collateral package;
- lien existence state;
- perfection state;
- applicable nonbankruptcy law;
- property-interest basis;
- claim allowance state;
- disallowance basis if applicable;
- rule basis;
- consequence code;
- §506(d) effect;
- §506(d) authority;
- exact input ids/hashes;
- exact lifecycle bindings;
- §506(a) allowed/secured/deficiency amounts when applicable.

## Explicit exclusions

- no mutation of lien or claim events;
- no automatic lien existence determination;
- no automatic perfection consequence;
- no §544/§545/§547/§548/§549 avoidance compiler;
- no §551 preservation compiler;
- no Chapter 11/13 plan-treatment compiler;
- no sale/proceeds engine;
- no HistoricalStore writeback;
- no production database mutation;
- no main.py/model/Hugging Face mutation;
- no merge;
- no automatic promotion.

## Legal references encoded by the candidate

- 11 U.S.C. §506(d), including exceptions (1) and (2);
- Dewsnup v. Timm, 502 U.S. 410 (1992);
- Bank of America, N.A. v. Caulkett, 575 U.S. 790 (2015);
- chapter-specific treatment remains separate, including the rights analysis
  illustrated by Nobelman v. American Savings Bank, 508 U.S. 324 (1993).

## Validation target

c8 adds 44 §506(d)/lien-consequence tests and extends the governed c3/c4
assertion/determination allowlists by two families.

The full repository unittest suite must remain green on Python 3.12 and 3.13
before c8 can become promotion-eligible.
