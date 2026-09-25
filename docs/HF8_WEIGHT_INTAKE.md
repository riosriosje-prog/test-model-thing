# HF8 — real trained weight intake gate

HF8 remains **HOLD** until an actual trained GALIA checkpoint bundle exists.

The intake contract does not train a model, fabricate weights, or publish anything.
It validates a future candidate bundle produced by the real GALIA checkpoint path.

Required bundle:
- `<target>.head.json`
- current `<target>.g-<generation>.safetensors`
- current `<target>.g-<generation>.manifest.json`
- previous generation payload + manifest when HEAD references one
- `HF8_WEIGHT_INTAKE.json`

The GALIA checkpoint payload already includes model parameters, optimizer state,
recurrent state, decay traces and embedding traces.

Required provenance:
- exact Git source commit
- training-data identifier and SHA-256
- training step count >= 1
- training start/end timestamps
- runtime, Python and MLX versions
- operator/workflow identity
- byte size and SHA-256 for every package file

The intake must state:
```text
synthetic_or_placeholder        = false
human_promotion_required        = true
canonical_authority_transferred = false
```

Structural validation:
`python tools/validate_hf8_weight_package.py /path/to/package`

Runtime validation:
`python tools/validate_hf8_weight_package.py /path/to/package --runtime-verify`

Runtime verification reconstructs the real `Model` from the checkpoint-bound model
configuration and requires an authoritative current-generation load without
`legacy_unbound_taint`.

A technical PASS never promotes the artifact. Remote publication and promotion remain
separate human-governed operations.
