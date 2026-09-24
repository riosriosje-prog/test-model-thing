# GALIA DB Deployment v0.2-c2 — Applied Migration History

Status: CANDIDATE / NOT PROMOTED

Parent baseline: promoted GALIA-DB-DEPLOYMENT-v0.1-c1.

## Purpose

c1 binds migration identity and schema fingerprints during an execution. c2 adds
a pure, hash-chained applied-migration history verifier so GALIA can later detect
that an already-applied migration artifact was deleted, edited, reordered, or
reused under the same migration ID.

## Properties

- append-only logical history;
- contiguous sequence validation;
- SHA-256 hash chain between applied records;
- unique migration IDs;
- schema-version continuity;
- exact artifact SHA-256 revalidation;
- exact replay recognized as ALREADY_APPLIED instead of re-executed;
- same migration ID with different bytes fails closed;
- parent schema drift fails closed.

## Boundaries

c2 is verifier-only. It does not:

- connect to a production database;
- write migration history to disk or DB;
- mutate GALIA HEAD;
- alter global StageState;
- create human authority;
- change preflight, persistence, or recovery policy.

Persistence of this registry, if later required, remains a separate candidate and
must bind into existing GALIA persistence/audit controls rather than bypass them.
