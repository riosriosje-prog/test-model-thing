# GALIA 2.0 — Secured Claim Kernel Implementation Candidate c1

Parent architecture:
`GALIA-SECURED-CLAIM-KERNEL-ARCH-CANDIDATE-v1.0-rc1`

Parent architecture specification SHA-256:
`227ebe7cdfb79d430b024c9aebe6ea9a670ac8c12f86179704751fd1783187bd`

## Candidate scope

`GALIA-SECURED-CLAIM-KERNEL-IMPLEMENTATION-CANDIDATE-v1.0-c1`

This is an implementation vertical slice only. It does not alter `main.py`,
HistoricalStore canonical data, production state, database schemas, model
weights, Hugging Face artifacts, or human-promotion authority.

## Implemented in memory

- immutable canonical legal events;
- idempotent append-only event storage;
- explicit authority references and supersession lineage;
- three-time valuation context;
- context-equivalence gate;
- §506(a) secured/unsecured classification;
- non-circular §506(b) cushion ceiling;
- explicit authority-backed component allocation when cushion is insufficient;
- lien priority waterfall;
- fail-closed disputed/undetermined priority;
- explicit pari-passu rule requirement;
- derived snapshots with source-event lineage.

## Explicitly deferred

- physical database schema/migration;
- §363 sale/proceeds persistence;
- §364 DIP persistence;
- plan-treatment persistence;
- REST/UI/API integration;
- production writeback;
- automatic promotion.

## Validation target

32 executable unit tests mirror the 32 architectural specification gates at
the vertical-slice level. The implementation is not eligible for promotion
until repository CI executes successfully and the exact commit/tree is bound
to a candidate receipt.
