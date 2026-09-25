from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.hf8_weight_bundle_validate import BundleError, validate_bundle


def add(root: Path, name: str, data: bytes) -> dict:
    p=root/name; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(data)
    return {"path":name,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}


class HF8WeightBundleTests(unittest.TestCase):
    def make_bundle(self, root: Path, *, previous: bool=False) -> None:
        target="galia.safetensors"; current="g-current"; prev="g-prev" if previous else None
        payload_name=f"{target}.g-{current}.safetensors"
        payload_row=add(root,payload_name,b"unit-test-fixture-not-promotable")
        manifest={"generation_id":current,"checkpoint_kind":"full","commit_id":"cid","commit_seq":2,"sha256":payload_row["sha256"],"size_bytes":payload_row["bytes"],"model_config":{"dim":16,"layers":2,"spread":4,"temp":0.75,"lr":0.0005,"lrbegin":4,"lrend":40}}
        manifest_name=f"{target}.g-{current}.manifest.json"
        manifest_row=add(root,manifest_name,(json.dumps(manifest,sort_keys=True)+"\n").encode())
        head={"current_generation":current,"previous_generation":prev,"commit_id":"cid","commit_seq":2}
        head_name=f"{target}.head.json"
        head_row=add(root,head_name,(json.dumps(head,sort_keys=True)+"\n").encode())
        rows=[payload_row,manifest_row,head_row]
        if previous:
            pp=f"{target}.g-{prev}.safetensors"; pm=f"{target}.g-{prev}.manifest.json"
            rows += [add(root,pp,b"previous-fixture"), add(root,pm,b"{}\n")]
        doc={"schema_version":1,"artifact_kind":"GALIA_TRAINED_CHECKPOINT_BUNDLE","synthetic_or_placeholder":False,"human_promotion_required":True,"canonical_authority_transferred":False,"source_repo":"riosriosje-prog/test-model-thing","source_commit":"d"*40,"checkpoint_target":target,"training_provenance":{"origin_type":"unit_test","obtained_from":"ephemeral fixture","training_dataset":"fixture","training_data_sha256":"a"*64,"training_description":"unit-test only","trainer_or_custodian":"unit-test","claimed_not_synthetic":True,"training_steps":1,"started_at_utc":"2026-09-25T00:00:00Z","finished_at_utc":"2026-09-25T00:00:01Z","runtime":"unit-test","python_version":"3.13","mlx_version":"0.32.2"},"files":rows}
        (root/"HF8_WEIGHT_BUNDLE.json").write_text(json.dumps(doc,indent=2,sort_keys=True)+"\n")

    def test_structural_bundle_pass_does_not_make_upload_eligible(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.make_bundle(root)
            r=validate_bundle(root)
            self.assertEqual(r["status"],"PASS")
            self.assertEqual(r["runtime_verification"],"NOT_RUN")
            self.assertFalse(r["technical_upload_eligible"])

    def test_hash_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.make_bundle(root)
            p=next(root.glob("*.safetensors")); p.write_bytes(p.read_bytes()+b"x")
            with self.assertRaises(BundleError): validate_bundle(root)

    def test_synthetic_flag_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.make_bundle(root)
            p=root/"HF8_WEIGHT_BUNDLE.json"; d=json.loads(p.read_text()); d["synthetic_or_placeholder"]=True; p.write_text(json.dumps(d))
            with self.assertRaises(BundleError): validate_bundle(root)

    def test_referenced_previous_generation_must_be_complete(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.make_bundle(root,previous=True)
            next(root.glob("*g-prev.safetensors")).unlink()
            with self.assertRaises(BundleError): validate_bundle(root)


if __name__ == "__main__":
    unittest.main()
