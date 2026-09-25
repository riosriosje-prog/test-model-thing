from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
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

def load_state(path: Path) -> dict:
    if not path.exists():
        return {
            "schema_version": 1,
            "cumulative_steps": 0,
            "cursor_line": 0,
            "cursor_pair": 0,
            "completed_chunks": 0,
        }
    return json.loads(path.read_text(encoding="utf-8"))

def pair_stream(lines: list[bytes], line_index: int, pair_index: int):
    while True:
        if line_index >= len(lines):
            line_index = 0
        data = lines[line_index]
        if len(data) < 2:
            line_index += 1
            pair_index = 0
            continue
        max_pair = len(data) - 1
        while pair_index < max_pair:
            c = data[pair_index]
            n = data[pair_index + 1]
            end = pair_index == max_pair - 1
            yield c, n, end, line_index, pair_index
            pair_index += 1
        line_index += 1
        pair_index = 0

def main() -> None:
    ap = argparse.ArgumentParser(description="GALIA HF8 reproducible 4.5M training chunk")
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--checkpoint-target", required=True)
    ap.add_argument("--state", required=True)
    ap.add_argument("--receipt", required=True)
    ap.add_argument("--steps", type=int, required=True)
    ap.add_argument("--seed", type=int, default=1976)
    ap.add_argument("--corpus-receipt", required=True)
    args = ap.parse_args()

    corpus_path = Path(args.corpus)
    state_path = Path(args.state)
    checkpoint_target = Path(args.checkpoint_target)
    checkpoint_target.parent.mkdir(parents=True, exist_ok=True)
    state_path.parent.mkdir(parents=True, exist_ok=True)

    corpus_receipt = json.loads(Path(args.corpus_receipt).read_text(encoding="utf-8"))
    corpus_sha = sha256_file(corpus_path)
    if corpus_sha != corpus_receipt["corpus_sha256"]:
        raise SystemExit("Corpus SHA-256 does not match its receipt")

    lines = corpus_path.read_bytes().splitlines(keepends=True)
    if not lines:
        raise SystemExit("Corpus is empty")

    state = load_state(state_path)
    if state.get("corpus_sha256") not in (None, corpus_sha):
        raise SystemExit("Training state is bound to a different corpus")

    mx.random.seed(args.seed)
    model = Model(
        dim=512,
        layers=16,
        spread=32,
        temp=0.75,
        lr=5e-4,
        lrbegin=40000,
        lrend=120000,
    )

    head_path = Path(str(checkpoint_target.resolve()) + ".head.json")
    resumed = head_path.exists()
    if resumed:
        model.load(str(checkpoint_target))
        if model.checkpoint_authority_status()["legacy_unbound_taint"]:
            raise SystemExit("Refusing to resume from legacy-unbound checkpoint")

    start_steps = int(state.get("cumulative_steps", 0))
    line_index = int(state.get("cursor_line", 0))
    pair_index = int(state.get("cursor_pair", 0))
    stream = pair_stream(lines, line_index, pair_index)

    started = time.time()
    last_line, last_pair = line_index, pair_index
    for local_step in range(1, args.steps + 1):
        c, n, end, li, pi = next(stream)
        model(c, n, end, frozen=False)
        last_line, last_pair = li, pi
        if local_step % 500 == 0 or local_step == args.steps:
            elapsed = max(time.time() - started, 1e-9)
            print(
                f"HF8_TRAIN_PROGRESS local={local_step}/{args.steps} "
                f"cumulative={start_steps + local_step} rate={local_step/elapsed:.2f}_steps_s",
                flush=True,
            )

    model.save(str(checkpoint_target))
    event = model.last_checkpoint_event or {}
    generation_id = event.get("generation_id")
    if not generation_id:
        raise SystemExit("Checkpoint save produced no generation ID")

    payload_raw, manifest_raw = model._generation_paths(str(checkpoint_target.resolve()), generation_id)
    payload = Path(payload_raw)
    manifest = Path(manifest_raw)
    head = Path(model._head_path(str(checkpoint_target.resolve())))

    next_pair = last_pair + 1
    next_line = last_line
    if next_pair >= max(len(lines[last_line]) - 1, 0):
        next_line = last_line + 1
        next_pair = 0

    cumulative = start_steps + args.steps
    state.update({
        "schema_version": 1,
        "corpus_sha256": corpus_sha,
        "cumulative_steps": cumulative,
        "cursor_line": next_line,
        "cursor_pair": next_pair,
        "completed_chunks": int(state.get("completed_chunks", 0)) + 1,
        "seed": args.seed,
        "model_config": {
            "dim": 512,
            "layers": 16,
            "spread": 32,
            "temp": 0.75,
            "lr": 5e-4,
            "lrbegin": 40000,
            "lrend": 120000,
        },
        "current_generation": generation_id,
        "last_source_sha": os.environ.get("GITHUB_SHA"),
    })
    state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    elapsed = time.time() - started
    receipt = {
        "gate": "HF8_RETRAIN_CHUNK",
        "artifact_kind": "REAL_TRAINED_CHECKPOINT",
        "source_sha": os.environ.get("GITHUB_SHA"),
        "seed": args.seed,
        "resumed": resumed,
        "chunk_steps": args.steps,
        "cumulative_steps": cumulative,
        "elapsed_seconds": elapsed,
        "steps_per_second": args.steps / max(elapsed, 1e-9),
        "corpus_sha256": corpus_sha,
        "generation_id": generation_id,
        "payload_path": str(payload),
        "payload_bytes": payload.stat().st_size,
        "payload_sha256": sha256_file(payload),
        "manifest_path": str(manifest),
        "manifest_sha256": sha256_file(manifest),
        "head_path": str(head),
        "head_sha256": sha256_file(head),
        "authority_binding": "CURRENT_BOUND",
        "legacy_unbound_taint": bool(model.checkpoint_authority_status()["legacy_unbound_taint"]),
        "model_parameter_count": model.count(),
        "canonical_authority_transferred": False,
        "human_promotion_required": True,
    }
    Path(args.receipt).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("HF8_REAL_TRAINED_CHECKPOINT=PASS")
    print("HF8_CHECKPOINT_SHA256=" + receipt["payload_sha256"])
    print("HF8_CHECKPOINT_BYTES=" + str(receipt["payload_bytes"]))
    print("HF8_CUMULATIVE_STEPS=" + str(cumulative))
    print("HF8_AUTHORITY_BINDING=CURRENT_BOUND")
    print("HF8_HUMAN_PROMOTION_REQUIRED=true")

if __name__ == "__main__":
    main()
