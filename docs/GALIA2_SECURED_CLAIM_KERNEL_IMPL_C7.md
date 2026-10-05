# GALIA 2.0 — Secured Claim Kernel Implementation Candidate c7

Candidate:
`GALIA-SECURED-CLAIM-KERNEL-IMPLEMENTATION-CANDIDATE-v1.0-c7`

Promoted parent:
`GALIA-SECURED-CLAIM-KERNEL-IMPLEMENTATION-CANDIDATE-v1.0-c6`

## Scope

c7 adds an append-only authority lifecycle for operative legal events and makes
the promoted §506(a)/§506(b) compilers consume reconstructed CURRENT_STATE
instead of trusting the immutable event row alone.

Core rule:

`LEGAL EVENT STATE CHANGE != EVENT MUTATION`

A later stay, appeal, finality determination, supersession, vacatur, or reversal
is represented by a new:

`AUTHORITY_STATE_TRANSITION_EVENT`

The original event remains byte-for-byte unchanged.

## Two authority planes remain separate

Every lifecycle transition requires:

1. an explicit human GALIA authorization binding the exact target hash and
   current lifecycle tail; and
2. a distinct legal authority supporting the change in legal effect.

`HUMAN PROMOTION != LEGAL AUTHORITY`

A human promotion authority is explicitly rejected as lifecycle legal authority.

## Reconstructed CURRENT_STATE

`resolve_effective_authority_state()` replays the exact lifecycle chain for a
target event and returns:

- original immutable state;
- effective current state;
- ordered transition event ids;
- ordered transition hashes;
- exact lifecycle tail id/hash.

The resolver fails closed on:

- multiple roots;
- forks;
- orphan transitions;
- predecessor hash mismatch;
- cycles;
- target-hash mismatch;
- invalid stored transition semantics.

CURRENT_STATE is therefore a query over immutable history, not an authoritative
mutable row.

## Allowed lifecycle transitions

The c7 policy permits governed transitions among the following states:

- `OPERATIVE`
- `APPEAL_PENDING`
- `STAYED`
- `FINAL`
- `SUPERSEDED`
- `VACATED`
- `REVERSED`

`VACATED` and `REVERSED` are terminal for the target event.

A `SUPERSEDED` transition requires an exact bound replacement event. The
replacement must exist, differ from the target, and remain legally live.

## Chain concurrency / stale authorization protection

The first transition must bind no predecessor.

Every later transition must bind the exact current lifecycle tail id and hash.
A stale human authorization cannot append a competing branch.

Exact replay of an already-recorded authorization is idempotent and does not
create a duplicate transition.

## Assertions remain outside lifecycle

`NONFINAL` shadow/assertion events are not authority-lifecycle targets.

The c4 human determination gate remains the path from NONFINAL source assertion
to operative/final legal determination.

## Downstream invalidation

c7 updates c5 and c6 so legal inputs must be effectively active after lifecycle
replay.

Therefore an immutable event whose stored row remains `OPERATIVE` is rejected
by downstream calculation once CURRENT_STATE becomes:

- `STAYED`
- `APPEAL_PENDING`
- `SUPERSEDED`
- `VACATED`
- `REVERSED`

Only effective `OPERATIVE` or `FINAL` inputs are accepted.

A FINAL derived result requires all relevant inputs to be effectively FINAL.

## Lifecycle-aware reproducibility

Input event hashes alone are insufficient once lifecycle exists because:

`OPERATIVE -> STAYED -> OPERATIVE`

does not change the original event SHA-256.

c7 therefore adds lifecycle bindings to c5/c6 compile provenance:

- target event id;
- effective state;
- lifecycle tail transition id;
- lifecycle tail transition SHA-256.

The lifecycle binding participates in the compile-request hash and is persisted
in derived output payloads.

Thus a derivation before a stay and a derivation after a later lift of the stay
cannot silently reuse the same derived event id.

## Explicit exclusions

- no mutation of historical canonical events;
- no lifecycle transitions for NONFINAL assertions;
- no automatic legal-state inference;
- no automatic successor selection;
- no automatic vacatur/reversal;
- no §506(d) consequence engine in this slice;
- no plan-treatment engine;
- no HistoricalStore writeback;
- no production DB mutation;
- no main.py/model/Hugging Face mutation;
- no merge;
- no automatic promotion.

## Validation target

c7 adds 38 authority-lifecycle/downstream invalidation tests on top of the
promoted c6 test surface.

Repository CI must remain green on Python 3.12 and 3.13 before c7 can become
promotion-eligible.
