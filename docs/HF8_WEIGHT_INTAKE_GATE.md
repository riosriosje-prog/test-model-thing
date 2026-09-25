# HF8 — Real Weight Artifact Intake Gate

Status: **HOLD / INTAKE TOOLING READY / NO SYNTHETIC WEIGHTS**

## Discovery result

The current GALIA GitHub `main` contains no real model weight/checkpoint artifact.
No GitHub releases exist in the user fork, and audited `main` workflow runs retain
no downloadable weight artifacts.

The upstream TMT README states that a 4.5M-parameter model was trained for about
12 hours using the Simple English Wikipedia 2026-08-01 dump, with `dim=512` and
`layers=16`. The README also explicitly states that model weights are not provided
in GitHub.

The filename `smaller-4.5m.safetensors` appears in upstream discussion as the
expected checkpoint path. It is not, by itself, evidence that the bytes were
published.

Audited compatible/near-compatible forks did not expose a downloadable checkpoint.
A real 129 MB training release was located in a CUDA rewrite, but that architecture
and checkpoint format differ materially from the current MLX/GALIA checkpoint
contract and therefore cannot satisfy HF8.

## Why legacy weights cannot be auto-promoted

There are now three relevant classes:

1. **GALIA_CURRENT_BOUND**
   - authoritative generation + manifest + HEAD;
   - exact payload hash/size;
   - config/lineage binding;
   - potentially upload-eligible after complete provenance.

2. **GALIA_LEGACY_UNBOUND**
   - structurally compatible single-file checkpoint;
   - no current manifest/HEAD authority binding;
   - inspection allowed only under explicit legacy-unbound policy;
   - authoritative persistence/upload remains HOLD.

3. **TMT_UPSTREAM_LEGACY**
   - original/upstream schema using `m.blocks.*`;
   - current GALIA uses `m.layers.*` and a hardened checkpoint protocol;
   - requires a separately reviewed migration/remapping;
   - never auto-transformed or auto-promoted.

## Intake tool

`tools/hf8_weight_intake.py` performs read-only inspection.

It records:

- SHA-256;
- exact byte size;
- tensor count;
- schema family;
- inferred dimension/layer count when possible;
- model parameter element count;
- authority binding;
- provenance completeness;
- technical upload eligibility.

It performs **no upload** and **no promotion**.

Example when a real file is available:

```bash
python tools/hf8_weight_intake.py \
  --target /path/to/smaller-4.5m.safetensors \
  --provenance /path/to/provenance.json \
  --output hf8-weight-intake-receipt.json
```

Required provenance fields:

```json
{
  "origin_type": "upstream_author",
  "obtained_from": "exact handoff or URL",
  "training_dataset": "simplewiki-20260801-pages-articles.xml.bz2",
  "training_description": "what run produced these bytes",
  "trainer_or_custodian": "identified custodian",
  "claimed_not_synthetic": true
}
```

The attestation is provenance metadata, not cryptographic proof of training.
Human review remains required.

## Exit rule

HF8 may leave HOLD only when all of the following are satisfied:

- actual checkpoint bytes are present;
- exact size and SHA-256 are recorded;
- the checkpoint can be parsed;
- schema/config compatibility is known;
- provenance is complete;
- authority binding is explicit;
- any legacy transformation is separately reviewed and receipt-bound;
- remote Hugging Face bytes are re-read and hash-verified after upload;
- a separate human promotion decision is recorded.

No test fixture, randomly initialized model, synthetic checkpoint, or incompatible
third-party architecture may satisfy HF8.
