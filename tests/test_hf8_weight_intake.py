from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.validate_hf8_weight_package import IntakeError, validate_package


def row(path: Path, data: bytes) -> dict:
    path.write_bytes(data)
    return {"path": path.name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


class HF8WeightIntakeTests(unittest.TestCase):
    def make_package(self, root: Path) -> None:
        target="galia.safetensors"
        gen="gen-test-fixture"
        payload=root/f"{target}.g-{gen}.safetensors"
        payload_row=row(payload,b"fixture-not-a-promotable-weight")
        manifest={"generation_id":gen,"parent_generation":None,"checkpoint_kind":"full","commit_id":"cid","commit_seq":1,"checkpoint_file":payload.name,"sha256":payload_row["sha256"],"size_bytes":payload_row["bytes"],"model_config":{"dim":16,"layers":2,"spread":4,"temp":0.75,"lr":0.0005,"lrbegin":4,"lrend":40}}
        mp=root/f"{target}.g-{gen}.manifest.json"
        manifest_row=row(mp,(json.dumps(manifest,sort_keys=True)+"\n").encode())
        head={"current_generation":gen,"previous_generation":None,"commit_id":"cid","commit_seq":1}
        hp=root/f"{target}.head.json"
        head_row=row(hp,(json.dumps(head,sort_keys=True)+"\n").encode())
        doc={"schema_version":1,"artifact_kind":"GALIA_TRAINED_CHECKPOINT_BUNDLE","synthetic_or_placeholder":False,"human_promotion_required":True,"canonical_authority_transferred":False,"source_repo":"riosriosje-prog/test-model-thing","source_commit":"d"*40,"checkpoint_target":target,"training_provenance":{"training_data_id":"unit-test-fixture-only","training_data_sha256":"a"*64,"training_steps":1,"started_at_utc":"2026-09-25T00:00:00Z","finished_at_utc":"2026-09-25T00:00:01Z","runtime":"unit-test","python_version":"3.13","mlx_version":"0.32.2","operator_or_workflow":"unit-test"},"files":[payload_row,manifest_row,head_row]}
        (root/"HF8_WEIGHT_INTAKE.json").write_text(json.dumps(doc,indent=2,sort_keys=True)+"\n")

    def test_consistent_fixture_passes_structural_contract_only(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.make_package(root)
            out=validate_package(root)
            self.assertEqual(out["status"],"PASS")
            self.assertFalse(out["runtime_verified"])
            self.assertTrue(out["human_promotion_required"])

    def test_placeholder_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.make_package(root)
            p=root/"HF8_WEIGHT_INTAKE.json"; d=json.loads(p.read_text()); d["synthetic_or_placeholder"]=True; p.write_text(json.dumps(d))
            with self.assertRaises(IntakeError): validate_package(root)

    def test_zero_steps_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.make_package(root)
            p=root/"HF8_WEIGHT_INTAKE.json"; d=json.loads(p.read_text()); d["training_provenance"]["training_steps"]=0; p.write_text(json.dumps(d))
            with self.assertRaises(IntakeError): validate_package(root)

    def test_hash_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.make_package(root)
            p=next(root.glob("*.safetensors")); p.write_bytes(p.read_bytes()+b"x")
            with self.assertRaises(IntakeError): validate_package(root)


if __name__ == "__main__":
    unittest.main()
