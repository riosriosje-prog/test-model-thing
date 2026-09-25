# HF8 — Real Weight Artifact Intake Gate

Status: **ACTIVE TOOLING / REAL WEIGHT PROMOTED / NO SYNTHETIC WEIGHTS**

## Historical discovery result

HF8 originally entered HOLD because no compatible real checkpoint bytes were available in the user fork, releases, audited CI artifacts, upstream releases, compatible forks or public Hugging Face search.

The upstream TMT README documented a 4.5M-parameter model trained for about 12 hours using the Simple English Wikipedia 2026-08-01 dump, with `dim=512` and `layers=16`, but did not publish the corresponding `.safetensors` bytes.

The filename `smaller-4.5m.safetensors` appeared only as an expected checkpoint path, not as a downloadable artifact.

That historical acquisition HOLD was later resolved through reproducible GALIA retraining rather than by fabricating or substituting weights.

## Current promoted HF8 weight

```text
repo_id           = Junitos/galia-2
revision          = main
candidate_path    = weights/hf8-retrain-v0.2-4k
training_steps    = 4000
payload_sha256    = 3bc46a281bdb6a031f7399d46e50612b622527bcc2528fd2f0e6220694971b3c
payload_bytes     = 70716981
manifest_sha256   = a41110548ced010da6d1462d4c0822dd527ac7411421540bdaf817d7d3b4cbb2
classification    = GALIA_CURRENT_BOUND
authority_binding = CURRENT_BOUND
quality_gate      = PASS
promotion_scope   = HF8_REAL_WEIGHT_V0_2_4K_BOOTSTRAP_ONLY
```

Durable promotion receipt:
`receipts/huggingface/hf8-v0-2-weight-promotion-receipt.json`

## Intake classifications

1. **GALIA_CURRENT_BOUND**
   - authoritative generation + manifest + HEAD;
   - exact payload hash/size;
   - config/lineage binding;
   - potentially upload-eligible after complete provenance.

2. **GALIA_LEGACY_UNBOUND**
   - structurally compatible single-file checkpoint;
   - no current manifest/HEAD authority binding;
   - inspection allowed only under explicit legacy-unbound policy;
   - authoritative persistence/upload remains HOLD until separately reviewed.

3. **TMT_UPSTREAM_LEGACY**
   - original/upstream schema using `m.blocks.*`;
   - current GALIA uses `m.layers.*` and a hardened checkpoint protocol;
   - requires a separately reviewed migration/remapping;
   - never auto-transformed or auto-promoted.

## Intake tool

`tools/hf8_weight_intake.py` remains the canonical read-only intake validator for future weight candidates.

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

## Future candidate exit rule

Every future HF8 weight candidate must still satisfy:

- actual checkpoint bytes present;
- exact size and SHA-256 recorded;
- checkpoint parse succeeds;
- schema/config compatibility known;
- provenance complete;
- authority binding explicit;
- any legacy transformation separately reviewed and receipt-bound;
- remote Hugging Face bytes re-read and hash-verified after upload;
- separate human promotion decision recorded.

No test fixture, randomly initialized model, synthetic checkpoint or incompatible third-party architecture may satisfy HF8.

## Authority boundary

```text
source_of_truth                 = github
canonical_authority_transferred = false
legacy_mutation_authorized      = false
```
