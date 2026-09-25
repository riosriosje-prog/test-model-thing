from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import random
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import mlx.core as mx
from main import Model


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def build_model(seed: int) -> Model:
    mx.random.seed(seed)
    return Model(dim=512, layers=16, spread=32, temp=0.75, lr=5e-4, lrbegin=40000, lrend=120000)


def evaluate_bpc(model: Model, lines: list[bytes], max_pairs: int) -> tuple[float, int]:
    losses = []
    pairs = 0
    for data in lines:
        if len(data) < 2:
            continue
        model.reset()
        for i in range(len(data) - 1):
            c = data[i]
            n = data[i + 1]
            (_, _, _), (logits, _) = model.step(mx.array(c), frozen=True)
            loss = -logits[n] + mx.logsumexp(logits)
            losses.append(float(loss.item()))
            pairs += 1
            if pairs >= max_pairs:
                return (sum(losses) / len(losses)) / math.log(2.0), pairs
    if not losses:
        raise SystemExit("No evaluation pairs available")
    return (sum(losses) / len(losses)) / math.log(2.0), pairs


def main() -> None:
    ap = argparse.ArgumentParser(description="HF8 v0.2 distributed training diagnostic")
    ap.add_argument("--train", required=True)
    ap.add_argument("--eval", required=True)
    ap.add_argument("--corpus-receipt", required=True)
    ap.add_argument("--checkpoint-target", required=True)
    ap.add_argument("--receipt", required=True)
    ap.add_argument("--steps", type=int, default=4000)
    ap.add_argument("--seed", type=int, default=1976)
    ap.add_argument("--sequence-bytes", type=int, default=256)
    ap.add_argument("--eval-pairs", type=int, default=4096)
    args = ap.parse_args()

    train_path = Path(args.train)
    eval_path = Path(args.eval)
    corpus_receipt = json.loads(Path(args.corpus_receipt).read_text(encoding="utf-8"))

    if sha256_file(train_path) != corpus_receipt["train_sha256"]:
        raise SystemExit("Train corpus hash mismatch")
    if sha256_file(eval_path) != corpus_receipt["eval_sha256"]:
        raise SystemExit("Eval corpus hash mismatch")

    train_lines = [line for line in train_path.read_bytes().splitlines(keepends=True) if len(line) >= 2]
    eval_lines = [line for line in eval_path.read_bytes().splitlines(keepends=True) if len(line) >= 2]
    if not train_lines or not eval_lines:
        raise SystemExit("Corpus split empty after load")

    eval_order = sorted(
        eval_lines,
        key=lambda x: hashlib.sha256(b"eval-v0.2\0" + x).digest(),
    )

    baseline = build_model(args.seed)
    baseline_bpc, baseline_pairs = evaluate_bpc(baseline, eval_order, args.eval_pairs)

    model = build_model(args.seed)
    rng = random.Random(args.seed)
    order = list(range(len(train_lines)))
    rng.shuffle(order)

    started = time.perf_counter()
    steps_done = 0
    sequence_count = 0
    epoch = 0
    while steps_done < args.steps:
        for idx in order:
            data = train_lines[idx]
            if len(data) < 2:
                continue

            max_start = max(0, len(data) - (args.sequence_bytes + 1))
            if max_start:
                score = hashlib.sha256(
                    f"{args.seed}:{epoch}:{idx}".encode("ascii")
                ).digest()
                start = int.from_bytes(score[:8], "big") % (max_start + 1)
            else:
                start = 0

            chunk = data[start : start + args.sequence_bytes + 1]
            if len(chunk) < 2:
                continue

            model.reset()
            sequence_count += 1
            for j in range(len(chunk) - 1):
                end = j == len(chunk) - 2 and start + len(chunk) >= len(data)
                model(chunk[j], chunk[j + 1], end, frozen=False)
                steps_done += 1
                if steps_done % 500 == 0 or steps_done == args.steps:
                    elapsed = max(time.perf_counter() - started, 1e-9)
                    print(
                        f"HF8_V02_TRAIN_PROGRESS steps={steps_done}/{args.steps} "
                        f"sequences={sequence_count} rate={steps_done/elapsed:.2f}_steps_s",
                        flush=True,
                    )
                if steps_done >= args.steps:
                    break
            if steps_done >= args.steps:
                break

        epoch += 1
        rng.shuffle(order)

    checkpoint_target = Path(args.checkpoint_target)
    checkpoint_target.parent.mkdir(parents=True, exist_ok=True)
    model.save(str(checkpoint_target))
    event = model.last_checkpoint_event or {}
    generation = event.get("generation_id")
    if not generation:
        raise SystemExit("No authoritative generation after save")
    payload_raw, manifest_raw = model._generation_paths(str(checkpoint_target.resolve()), generation)
    payload = Path(payload_raw)
    manifest = Path(manifest_raw)
    head = Path(model._head_path(str(checkpoint_target.resolve())))

    trained_bpc, trained_pairs = evaluate_bpc(model, eval_order, args.eval_pairs)
    delta = trained_bpc - baseline_bpc
    elapsed = time.perf_counter() - started

    receipt = {
        "gate": "HF8_RETRAIN_V0_2_DIAGNOSTIC",
        "status": "PASS",
        "artifact_kind": "REAL_TRAINED_CHECKPOINT_DIAGNOSTIC",
        "seed": args.seed,
        "training_steps": steps_done,
        "training_sequences": sequence_count,
        "sequence_bytes": args.sequence_bytes,
        "elapsed_seconds": elapsed,
        "steps_per_second": steps_done / max(elapsed, 1e-9),
        "corpus": {
            "dump_sha256": corpus_receipt["dump_sha256"],
            "train_sha256": corpus_receipt["train_sha256"],
            "eval_sha256": corpus_receipt["eval_sha256"],
            "train_bytes": corpus_receipt["train_bytes"],
            "eval_bytes": corpus_receipt["eval_bytes"],
            "upstream_exact_cleaning_claimed": False,
        },
        "quality": {
            "metric": "heldout_bits_per_byte",
            "eval_pairs": trained_pairs,
            "random_init_baseline_bpc": baseline_bpc,
            "trained_bpc": trained_bpc,
            "delta_trained_minus_baseline": delta,
            "improved_vs_random_init": trained_bpc < baseline_bpc,
            "promotion_quality_gate": "PASS" if trained_bpc < baseline_bpc else "HOLD",
        },
        "checkpoint": {
            "generation_id": generation,
            "payload_sha256": sha256_file(payload),
            "payload_bytes": payload.stat().st_size,
            "manifest_sha256": sha256_file(manifest),
            "head_sha256": sha256_file(head),
            "authority_binding": "CURRENT_BOUND",
        },
        "canonical_authority_transferred": False,
        "human_promotion_required": True,
        "promoted": False,
    }
    Path(args.receipt).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("HF8_V02_TRAINING=PASS")
    print(f"HF8_V02_RANDOM_BASELINE_BPC={baseline_bpc:.8f}")
    print(f"HF8_V02_TRAINED_BPC={trained_bpc:.8f}")
    print(f"HF8_V02_DELTA_BPC={delta:.8f}")
    print("HF8_V02_IMPROVED_VS_RANDOM_INIT=" + str(trained_bpc < baseline_bpc).lower())
    print("HF8_V02_QUALITY_GATE=" + receipt["quality"]["promotion_quality_gate"])
    print("HF8_V02_PAYLOAD_SHA256=" + receipt["checkpoint"]["payload_sha256"])
    print("HF8_V02_PROMOTED=false")


if __name__ == "__main__":
    main()
