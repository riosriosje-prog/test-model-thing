# GALIA Historical Store v0.1

## Scope

This is an experimental, additive research-data layer. It does **not** replace
GALIA v1.35 checkpoints and it does not change checkpoint authority.

The v0.1 store uses SQLite from the Python standard library so the first pilot
has no new runtime dependency.

## Separation of concerns

- `main.py` checkpoints: model parameters, optimizer state, recurrent state,
  generation manifests, HEAD, and checkpoint audit trail.
- `historical_store.py`: sources, documents, entities, claims, evidence,
  relations, events, discrepancies, human reviews, ingest-run lineage.
- `galia_history_bridge.py`: application-boundary adapter that records an
  engine analysis as an ingest run and creates only `PROPOSED` claims.

Engine output is never automatically canonical.

## Core invariants

1. `DOCUMENT_DATE` and `EVENT_DATE` are separate fields.
2. Raw source bytes are not silently copied into SQLite. The store records a
   locator plus SHA-256/byte length when bytes are available.
3. Engine-generated claims start as `PROPOSED`.
4. `CANONICAL` promotion requires explicit human reviewer identity and
   rationale.
5. Contradictory claims are retained and linked through the discrepancy ledger.
6. Audit records are append-only at the database layer.
7. The database has its own schema version (`PRAGMA user_version`) independent
   of the model checkpoint schema.

## Initial schema

- `sources`
- `documents`
- `ingest_runs`
- `entities`
- `entity_aliases`
- `claims`
- `claim_evidence`
- `relations`
- `events`
- `event_participants`
- `discrepancies`
- `discrepancy_claims`
- `reviews`
- `audit_log`

## Pilot strategy

Use Finca El Condado as the first dataset because it exercises:

- archival and judicial sources;
- multiple document dates and underlying event dates;
- people, places, estates, roads, and ownership relations;
- competing acreage statements;
- title-chain hypotheses that must not be promoted without primary evidence.

## Promotion policy

v0.1 remains a shadow store until:

- schema tests pass;
- a Condado pilot can be exported and reconstructed from provenance;
- discrepancy behavior is reviewed;
- no historical claim can become canonical without a human review record.

Only after those gates should integration into the canonical GALIA research
workflow be considered.
