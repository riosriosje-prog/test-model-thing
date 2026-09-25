---
license: mit
pretty_name: GALIA 2 Evidence Schema Surface
tags:
- history
- provenance
- evidence
- puerto-rico
- research
---

# GALIA 2 — Evidence dataset surface

Status: **SCHEMA-ONLY CANDIDATE / ZERO EVIDENCE RECORDS**

This private dataset repository is a distribution surface for future GALIA evidence packages. It does **not** transfer canonical authority from GitHub and it does not yet contain historical evidence, source images, transcriptions, normalized assertions, or raw source bytes.

## Governance invariants

- `DOCUMENT_DATE` and `EVENT_DATE` remain separate.
- `PROMPT_VERSION` and `ENGINE_VERSION` remain separate.
- authentication/admissibility and evidentiary weight remain separate assessments.
- image evidence must carry source/publication, page, type, date/range, place, subject, author, and gate status.
- discrepant claims route through a discrepancy record; no automatic authority selection.
- human review is explicit.
- source bytes and derived records retain hash/lineage boundaries.

The first HF9 candidate contains schemas and documentation only. A later evidence migration requires a separate byte-bound export and human promotion gate.
