from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

import mlx.core as mx

from tools.hf8_weight_intake import (
    classify_tensor_keys,
    inspect_single_file,
    load_provenance,
)


class HF8WeightIntakeTests(unittest.TestCase):
    def test_classifies_upstream_blocks_schema(self):
        self.assertEqual(
            classify_tensor_keys([
                "m.encoder.embed.weight",
                "m.blocks.0.decay",
                "state.0",
            ]),
            "TMT_UPSTREAM_LEGACY_SCHEMA",
        )

    def test_classifies_galia_layers_schema(self):
        self.assertEqual(
            classify_tensor_keys([
                "m.encoder.embed.weight",
                "m.layers.0.decay",
                "state.0",
            ]),
            "GALIA_LAYER_SCHEMA",
        )

    def test_missing_provenance_fails_closed(self):
        _, status = load_provenance(None)
        self.assertEqual(status["status"], "MISSING")
        self.assertFalse(status["claimed_not_synthetic"])

    def test_upstream_fixture_is_held_not_promoted(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "fixture.safetensors"
            mx.save_safetensors(str(p), {
                "m.encoder.embed.weight": mx.zeros((256, 8)),
                "m.blocks.0.decay": mx.zeros((8,)),
                "state.0": mx.zeros((8,)),
                "decaytrace.0": mx.zeros((8,)),
                "embedtrace.0": mx.zeros((256, 8)),
            })
            result = inspect_single_file(p)
            self.assertEqual(result["classification"], "TMT_UPSTREAM_LEGACY")
            self.assertEqual(result["authority_binding"], "LEGACY_UNBOUND")
            self.assertTrue(result["requires_transform"])
            self.assertGreater(result["payload_bytes"], 0)
            self.assertEqual(len(result["payload_sha256"]), 64)

    def test_complete_provenance_requires_explicit_real_artifact_attestation(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "prov.json"
            p.write_text(json.dumps({
                "origin_type": "upstream_author",
                "obtained_from": "manual handoff",
                "training_dataset": "simplewiki",
                "training_description": "trained run",
                "trainer_or_custodian": "custodian",
                "claimed_not_synthetic": True,
            }))
            _, status = load_provenance(p)
            self.assertEqual(status["status"], "COMPLETE")
            self.assertTrue(status["claimed_not_synthetic"])


if __name__ == "__main__":
    unittest.main()
