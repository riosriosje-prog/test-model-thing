# GALIA SAFE_DELETE Gate v1 — Recovery v3 candidate

Status: **CANDIDATE / HUMAN PROMOTION REQUIRED**

Recovery v3 does not recover or fabricate the missing `5ed030...` bytes. It fixes
the preservation model so that an irrecoverable **noncanonical transient** can be
handled explicitly without being silently treated as byte-equivalent.

## Evidence result for 5ed030

Expected SHA-256:

`5ed03098751c71efb5d87ec33f0f9d2894c6a7c729265eb322dfb37e9f42a4b6`

The cleanup manifest binds this object as `source_v1_30_sha256` for
`GALIA_WORKING_v1_31_TASK_LIFECYCLE_CLEANUP.sqlite` (`948d41...`).

The same manifest/report establishes the bounded cleanup scope:

- `master_modified = false`;
- historical knowledge mutations: sources `0`, evidence `0`, statements `0`;
- release-authority changes: `0`;
- only three task lifecycle states were repaired;
- successor `948d41...` is byte-verified;
- exhaustive recovery searches did not locate the `5ed030...` raw bytes;
- reverse reconstruction is **not** accepted as raw-byte substitution.

The evidence record is:

`governance/irrecoverable_transient_5ed030.v1.json`

SHA-256:

`e2a6359902848e3531071ade022b445acadaabc7396598771f504530179d809c`

## New fail-closed path

`cleanup_upstream_5ed030` may be classified:

`IRRECOVERABLE_TRANSIENT_DOCUMENTED`

only when all policy-bound facts match exactly. This state is **not enough** to
pass SAFE_DELETE. A separate control is required:

`EXPLICIT_HUMAN_IRRECOVERABLE_TRANSIENT_ACCEPTANCE_BOUND`

That decision must bind:

- object id;
- expected missing SHA-256;
- exact evidence-record SHA-256;
- a non-empty human decision id.

If any classification fact changes, the successor is not byte-verified, knowledge
or authority mutations are nonzero, recovery search is not exhaustive, a reverse
reconstruction is substituted, or the human acceptance does not bind the exact
record, the gate fails closed.

## Separation of decisions

Three distinct decisions remain separate:

1. promotion of Recovery v3 code/policy;
2. human acceptance of the documented irrecoverable transient loss;
3. deletion-specific authorization bound to the final vault and exact deletion manifest.

None implies another.

## Current state

`SAFE_DELETE = HOLD`

Current blockers after this candidate remains unpromoted include:

- Recovery v3 itself requires human promotion;
- irrecoverable-transient human acceptance is absent;
- final vault is not sealed;
- final clean-room restore has not passed;
- deletion manifest is absent;
- deletion-specific human authorization is absent.

No deletion operation is added.
