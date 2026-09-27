# GALIA — Trust-root pointer reconciliation v2

Status: **CANDIDATE / HUMAN PROMOTION REQUIRED**

The active trust-root pointer predates the promoted GitHub/HF/Supabase cross-plane integration and still records the older control-plane commit `384a1b1b...`.

The effective GLOBAL_MASTER itself is not stale. This candidate changes only control-plane metadata:

- predecessor pointer SHA: `ceb60f75...`
- current GitHub main: `25db17fa...`
- Supabase current GitHub binding: `25db17fa...`
- proposed successor pointer SHA: `eac0b7af...`

Unchanged:

- GLOBAL_MASTER release `RC-GALIA-2026-09-13-004`
- master SQLite SHA `9e98bf9c...`
- trust-root v8 SHA `7aa0d35c...`
- G20/G22/G27
- G28 remains forensic/open
- SAFE_DELETE remains HOLD
- Santurce research scope remains separate
- Hugging Face artifacts are not mutated

The proposed pointer bytes are final. They become effective only when an external human promotion receipt identifies the exact pointer SHA. This avoids a post-promotion hash change.

The Supabase reconciliation is fail-closed: it only updates the pointer metadata when both the GitHub revision and predecessor pointer hash still match the expected current state.
