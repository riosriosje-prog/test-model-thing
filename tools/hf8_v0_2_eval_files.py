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


def load_file_list(path: Path) -> list[str]:
    rows = [x.strip() for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    if not rows:
        raise SystemExit("Evaluation file list is empty")
    return rows


def copy_trainable(model: Model) -> dict[str, mx.array]:
    copied = {}
    for key, value in util.tree_flatten(model.trainable_parameters()):
        copied[key] = value + mx.zeros_like(value)
    mx.eval(*copied.values())
    return copied


def assert_trainable_identity(before: dict[str, mx.array], model: Model) -> None:
    after = dict(util.tree_flatten(model.trainable_parameters()))
    if set(before) != set(after):
        raise SystemExit("Trainable parameter key set changed during frozen evaluation")
    changed = []
    for key in sorted(before):
        if not bool(mx.array_equal(before[key], after[key]).item()):
            changed.append(key)
    if changed:
        raise SystemExit(f"Frozen evaluation mutated trainable parameters: {changed[:20]}")


def main() -> None:
    ap = argparse.ArgumentParser(description="HF8 v0.2 held-out file evaluator")
    ap.add_argument("--dataset-root", required=True)
    ap.add_argument("--eval-files", required=True)
    ap.add_argument("--dataset-manifest", required=True)
    ap.add_argument("--checkpoint-target", required=True)
    ap.add_argument("--training-receipt", required=True)
    ap.add_argument("--receipt", required=True)
    ap.add_argument("--max-pairs", type=int, default=4096)
    args = ap.parse_args()

    dataset_root = Path(args.dataset_root).resolve()
    eval_files_path = Path(args.eval_files).resolve()
    dataset_manifest_path = Path(args.dataset_manifest).resolve()
    checkpoint_target = Path(args.checkpoint_target).resolve()
    training_receipt_path = Path(args.training_receipt).resolve()
    receipt_path = Path(args.receipt).resolve()
    receipt_path.parent.mkdir(parents=True, exist_ok=True)

    manifest = json.loads(dataset_manifest_path.read_text(encoding="utf-8"))
    eval_files = load_file_list(eval_files_path)
    if len(eval_files) != int(manifest["eval_file_count"]):
        raise SystemExit("Evaluation file list count does not match dataset manifest")

    training_receipt = json.loads(training_receipt_path.read_text(encoding="utf-8"))

    model = Model(
        dim=512,
        layers=16,
        spread=32,
        temp=0.75,
        lr=5e-4,
        lrbegin=40000,
        lrend=120000,
    )
    model.load(str(checkpoint_target))
    authority = model.checkpoint_authority_status()
    if authority["legacy_unbound_taint"]:
        raise SystemExit("Evaluation checkpoint loaded with legacy-unbound taint")

    load_event = model.last_checkpoint_event or {}
    if load_event.get("status") != "current":
        raise SystemExit(f"Expected current-generation load, got {load_event.get('status')}")

    payload_path = Path(training_receipt["payload_path"])
    if not payload_path.is_absolute():
        payload_path = checkpoint_target.parent / payload_path.name
    if not payload_path.is_file():
        payload_path = checkpoint_target.parent / Path(training_receipt["payload_path"]).name
    if not payload_path.is_file():
        raise SystemExit("Could not locate checkpoint payload for identity check")

    payload_sha_before = sha256_file(payload_path)
    if payload_sha_before != training_receipt["payload_sha256"]:
        raise SystemExit("Checkpoint payload SHA differs from training receipt")

    trainable_before = copy_trainable(model)
    model.reset()

    losses = []
    pairs = 0
    files_touched = 0
    for rel in eval_files:
        path = dataset_root / rel
        if not path.is_file():
            raise FileNotFoundError(path)
        files_touched += 1

        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                data = line.encode("utf-8")
                if len(data) < 2:
                    continue
                for i in range(len(data) - 1):
                    c = data[i]
                    n = data[i + 1]
                    (_, _, _), (logits, _) = model.step(mx.array(c), frozen=True)
                    loss = -logits[n] + mx.logsumexp(logits)
                    losses.append(float(loss.item()))
                    pairs += 1
                    if pairs >= args.max_pairs:
                        break
                if pairs >= args.max_pairs:
                    break
        if pairs >= args.max_pairs:
            break

    if not losses:
        raise SystemExit("No held-out pairs evaluated")

    assert_trainable_identity(trainable_before, model)
    payload_sha_after = sha256_file(payload_path)
    if payload_sha_after != payload_sha_before:
        raise SystemExit("Frozen evaluation changed checkpoint bytes on disk")

    mean_nats = sum(losses) / len(losses)
    mean_bpc = mean_nats / math.log(2.0)
    if not math.isfinite(mean_bpc):
        raise SystemExit("Held-out BPC is non-finite")

    receipt = {
        "gate": "HF8_V0_2_HELDOUT_EVALUATION",
        "status": "PASS",
        "training_regime": "UPSTREAM_STYLE_WIKIEXTRACTOR_FILE_STREAM",
        "checkpoint_payload_sha256": payload_sha_before,
        "checkpoint_payload_bytes": payload_path.stat().st_size,
        "cumulative_training_steps": int(training_receipt["cumulative_steps"]),
        "authority_binding": "CURRENT_BOUND",
        "legacy_unbound_taint": False,
        "dataset_manifest_sha256": sha256_file(dataset_manifest_path),
        "eval_file_list_sha256": manifest["eval_file_list_sha256"],
        "heldout_pairs": pairs,
        "heldout_files_touched": files_touched,
        "heldout_mean_nats_per_byte": mean_nats,
        "heldout_mean_bits_per_byte": mean_bpc,
        "quality_gate": "OBSERVATION_ONLY",
        "frozen_trainable_parameter_identity": "PASS",
        "checkpoint_file_identity_after_eval": "PASS",
        "canonical_authority_transferred": False,
        "human_promotion_required": True,
        "promoted": False,
    }
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("HF8_V0_2_HELDOUT_EVAL=PASS")
    print("HF8_V0_2_HELDOUT_PAIRS=" + str(pairs))
    print("HF8_V0_2_HELDOUT_FILES_TOUCHED=" + str(files_touched))
    print("HF8_V0_2_HELDOUT_BPC=" + str(mean_bpc))
    print("HF8_V0_2_FROZEN_TRAINABLE_IDENTITY=PASS")
    print("HF8_V0_2_FROZEN_FILE_IDENTITY=PASS")
    print("HF8_V0_2_PROMOTED=false")


if __name__ == "__main__":
    main()
