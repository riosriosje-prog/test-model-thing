from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import mlx.core as mx
import mlx.utils as util

from main import Model


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def tensor_copy_map(model: Model) -> dict[str, mx.array]:
    copied = {}
    for key, value in util.tree_flatten(model.parameters()):
        copied[key] = value + mx.zeros_like(value)
    mx.eval(*copied.values())
    return copied


def assert_parameter_identity(before: dict[str, mx.array], model: Model) -> None:
    after = dict(util.tree_flatten(model.parameters()))
    if set(before) != set(after):
        raise SystemExit("Parameter key set changed during frozen evaluation")
    changed = []
    for key in sorted(before):
        equal = bool(mx.array_equal(before[key], after[key]).item())
        if not equal:
            changed.append(key)
    if changed:
        raise SystemExit(f"Frozen evaluation mutated parameters: {changed[:20]}")


def verify_snapshot_manifest(snapshot_root: Path) -> dict:
    manifest_path = snapshot_root / "HF8_RETRAIN_SNAPSHOT_MANIFEST.json"
    if not manifest_path.is_file():
        raise SystemExit("Missing HF8_RETRAIN_SNAPSHOT_MANIFEST.json")
    doc = json.loads(manifest_path.read_text(encoding="utf-8"))
    if doc.get("promotion_scope") != "HF8_RETRAIN_STAGING_ONLY":
        raise SystemExit("Unexpected staging scope")
    if doc.get("canonical_authority_transferred") is not False:
        raise SystemExit("Canonical authority transfer invariant violated")
    for rel, expected in doc.get("files", {}).items():
        p = snapshot_root / rel
        if not p.is_file():
            raise SystemExit(f"Snapshot missing manifest file: {rel}")
        actual_size = p.stat().st_size
        actual_sha = sha256_file(p)
        if actual_size != expected["bytes"]:
            raise SystemExit(f"Size mismatch for {rel}")
        if actual_sha != expected["sha256"]:
            raise SystemExit(f"SHA-256 mismatch for {rel}")
    return doc


def main() -> None:
    ap = argparse.ArgumentParser(description="Validate staged HF8 real-trained checkpoint read-only")
    ap.add_argument("--snapshot-root", required=True)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--corpus-receipt", required=True)
    ap.add_argument("--receipt", required=True)
    ap.add_argument("--heldout-bytes", type=int, default=32768)
    args = ap.parse_args()

    snapshot_root = Path(args.snapshot_root).resolve()
    corpus_path = Path(args.corpus).resolve()
    local_corpus_receipt = json.loads(Path(args.corpus_receipt).read_text(encoding="utf-8"))
    remote_corpus_receipt = json.loads(
        (snapshot_root / "corpus-receipt.json").read_text(encoding="utf-8")
    )

    local_corpus_sha = sha256_file(corpus_path)
    if local_corpus_sha != local_corpus_receipt["corpus_sha256"]:
        raise SystemExit("Locally rebuilt corpus does not match its receipt")
    if local_corpus_sha != remote_corpus_receipt["corpus_sha256"]:
        raise SystemExit("Rebuilt corpus does not match staged training corpus SHA-256")

    snapshot_manifest = verify_snapshot_manifest(snapshot_root)

    training_receipt = json.loads(
        (snapshot_root / "training-receipt.json").read_text(encoding="utf-8")
    )
    if training_receipt.get("artifact_kind") != "REAL_TRAINED_CHECKPOINT":
        raise SystemExit("Staged artifact is not declared REAL_TRAINED_CHECKPOINT")
    if training_receipt.get("authority_binding") != "CURRENT_BOUND":
        raise SystemExit("Staged checkpoint is not CURRENT_BOUND")

    target = snapshot_root / "galia-hf8-4p5m"
    model = Model(
        dim=512,
        layers=16,
        spread=32,
        temp=0.75,
        lr=5e-4,
        lrbegin=40000,
        lrend=120000,
    )
    model.load(str(target))
    authority = model.checkpoint_authority_status()
    if authority["legacy_unbound_taint"]:
        raise SystemExit("Staged checkpoint loaded with legacy-unbound taint")

    load_event = model.last_checkpoint_event or {}
    if load_event.get("status") not in ("current", "fallback"):
        raise SystemExit(f"Unexpected staged load status: {load_event.get('status')}")
    if load_event.get("status") == "fallback":
        raise SystemExit("Staged checkpoint required fallback; current generation must validate")

    payload_path = snapshot_root / Path(training_receipt["payload_path"]).name
    if not payload_path.is_file():
        raise SystemExit("Training receipt payload is missing from staged snapshot")
    payload_sha_before = sha256_file(payload_path)
    if payload_sha_before != training_receipt["payload_sha256"]:
        raise SystemExit("Staged payload SHA does not match training receipt")

    params_before = tensor_copy_map(model)
    model.reset()

    corpus = corpus_path.read_bytes()
    sample = corpus[-(args.heldout_bytes + 1):]
    if len(sample) < 2:
        raise SystemExit("Held-out sample is too small")

    losses = []
    for i in range(len(sample) - 1):
        c = sample[i]
        n = sample[i + 1]
        (_, _, _), (logits, _) = model.step(mx.array(c), frozen=True)
        loss = -logits[n] + mx.logsumexp(logits)
        losses.append(float(loss.item()))

    assert_parameter_identity(params_before, model)
    payload_sha_after = sha256_file(payload_path)
    if payload_sha_after != payload_sha_before:
        raise SystemExit("Frozen evaluation changed checkpoint bytes on disk")

    mean_nats = sum(losses) / len(losses)
    mean_bpc = mean_nats / math.log(2.0)
    if not math.isfinite(mean_bpc):
        raise SystemExit("Held-out BPC is non-finite")

    receipt = {
        "gate": "HF8_STAGED_CHECKPOINT_VALIDATION",
        "status": "PASS",
        "staging_revision": snapshot_manifest["revision"],
        "promotion_scope": snapshot_manifest["promotion_scope"],
        "checkpoint_payload_sha256": payload_sha_before,
        "checkpoint_payload_bytes": payload_path.stat().st_size,
        "generation_id": training_receipt["generation_id"],
        "cumulative_training_steps": training_receipt["cumulative_steps"],
        "authority_binding": "CURRENT_BOUND",
        "legacy_unbound_taint": False,
        "load_status": load_event.get("status"),
        "corpus_sha256": local_corpus_sha,
        "heldout_bytes": len(sample) - 1,
        "heldout_mean_nats_per_byte": mean_nats,
        "heldout_mean_bits_per_byte": mean_bpc,
        "quality_gate": "OBSERVATION_ONLY",
        "frozen_parameter_identity": "PASS",
        "checkpoint_file_identity_after_eval": "PASS",
        "resume_from_staging_load": "PASS",
        "canonical_authority_transferred": False,
        "human_promotion_required": True,
        "promoted": False,
    }
    Path(args.receipt).write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("HF8_STAGED_MANIFEST_VERIFY=PASS")
    print("HF8_STAGED_CURRENT_GENERATION_LOAD=PASS")
    print("HF8_STAGED_RESUME_PRECONDITION=PASS")
    print("HF8_FROZEN_PARAMETER_IDENTITY=PASS")
    print("HF8_FROZEN_FILE_IDENTITY=PASS")
    print(f"HF8_HELDOUT_BPC={mean_bpc:.8f}")
    print("HF8_STAGED_VALIDATION=PASS")
    print("HF8_PROMOTED=false")


if __name__ == "__main__":
    main()
