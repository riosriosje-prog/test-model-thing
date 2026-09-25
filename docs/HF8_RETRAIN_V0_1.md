# HF8 Reproducible Retraining v0.1

This branch removes dependence on unavailable upstream weight bytes by producing
a new real GALIA/TMT 4.5M-class checkpoint from a dated SimpleWiki source.

## Bootstrap objective

The first workflow run is intentionally small:

- current GALIA architecture;
- `dim=512`;
- `layers=16`;
- `spread=32`;
- seed `1976`;
- 4,000 real optimizer steps;
- SimpleWiki 2026-08-01 source;
- deterministic 16 MiB corpus extraction;
- authoritative GALIA generation/manifest/HEAD checkpoint;
- stage only to `Junitos/galia-2@hf8-retrain-v0.1`;
- remote reread/hash verification;
- no promotion.

The bootstrap exists to prove acquisition → corpus → training → checkpoint →
remote staging → remote byte verification end to end.

It does **not** claim equivalence with the unavailable upstream 12-hour
checkpoint and does not by itself constitute a promoted model.

## Governance

```text
artifact_kind = REAL_TRAINED_CHECKPOINT
staging_revision = hf8-retrain-v0.1
canonical_authority_transferred = false
automatic_promotion = false
human_promotion_required = true
```

If the bootstrap passes, later work can extend cumulative training in bounded,
resumable chunks while preserving the exact corpus hash, checkpoint lineage,
state cursor and receipts.
