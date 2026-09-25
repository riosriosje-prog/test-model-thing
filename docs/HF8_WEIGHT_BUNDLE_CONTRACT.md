# HF8 — complete checkpoint bundle contract v0.3

This layer is additive to the promoted HF8 intake v0.1.

The v0.1 tool answers: **what kind of checkpoint file is this?**

The v0.3 bundle contract answers: **is the complete authoritative checkpoint package internally consistent, lineage-complete and provenance-bound?**

HF8 remains **HOLD** until real checkpoint bytes exist.

A candidate bundle must contain:
- `HF8_WEIGHT_BUNDLE.json`;
- `<target>.head.json`;
- current `<target>.g-<generation>.safetensors`;
- current generation manifest;
- previous generation payload + manifest whenever HEAD references one.

The bundle declaration binds:
- exact Git source commit;
- training dataset identity and SHA-256;
- training steps >= 1;
- trainer/custodian;
- runtime, Python and MLX versions;
- every file's exact byte size and SHA-256;
- explicit `synthetic_or_placeholder=false`;
- explicit `claimed_not_synthetic=true`;
- `human_promotion_required=true`.

Structural validation alone never makes a checkpoint upload-eligible.
`technical_upload_eligible=true` requires `--runtime-verify`, which reconstructs
the real GALIA `Model` from the bound model configuration and requires the current
generation to load without `legacy_unbound_taint`.

No upload or promotion occurs in this tool.
