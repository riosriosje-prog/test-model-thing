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


def load_file_list(path: Path) -> list[str]:
    rows = [x.strip() for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    if not rows:
        raise SystemExit("Training file list is empty")
    return rows


def load_state(path: Path, dataset_manifest_sha256: str) -> dict:
    if not path.exists():
        return {
            "schema_version": 2,
            "cumulative_steps": 0,
            "file_index": 0,
            "line_index": 0,
            "pair_index": 0,
            "completed_file_cycles": 0,
            "dataset_manifest_sha256": dataset_manifest_sha256,
        }
    state = json.loads(path.read_text(encoding="utf-8"))
    if state.get("dataset_manifest_sha256") != dataset_manifest_sha256:
        raise SystemExit("Training state is bound to a different dataset manifest")
    return state


def pair_stream(dataset_root: Path, files: list[str], cursor: dict):
    file_index = int(cursor["file_index"])
    line_index = int(cursor["line_index"])
    pair_index = int(cursor["pair_index"])
    cycles = int(cursor.get("completed_file_cycles", 0))

    while True:
        if file_index >= len(files):
            file_index = 0
            line_index = 0
            pair_index = 0
            cycles += 1

        rel = files[file_index]
        path = dataset_root / rel
        if not path.is_file():
            raise FileNotFoundError(path)

        had_eligible_line = False
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for li, line in enumerate(fh):
                if li < line_index:
                    continue
                data = line.encode("utf-8")
                if len(data) < 2:
                    if li == line_index:
                        pair_index = 0
                    continue

                had_eligible_line = True
                start_pair = pair_index if li == line_index else 0
                last_pair = len(data) - 2
                for pi in range(start_pair, len(data) - 1):
                    end = pi == last_pair
                    if pi < last_pair:
                        next_cursor = {
                            "file_index": file_index,
                            "line_index": li,
                            "pair_index": pi + 1,
                            "completed_file_cycles": cycles,
                        }
                    else:
                        next_cursor = {
                            "file_index": file_index,
                            "line_index": li + 1,
                            "pair_index": 0,
                            "completed_file_cycles": cycles,
                        }
                    yield data[pi], data[pi + 1], end, rel, li, pi, next_cursor

                pair_index = 0

        file_index += 1
        line_index = 0
        pair_index = 0

        if not had_eligible_line:
            continue


def main() -> None:
    ap = argparse.ArgumentParser(description="HF8 v0.2 upstream-style file-stream trainer")
    ap.add_argument("--dataset-root", required=True)
    ap.add_argument("--train-files", required=True)
    ap.add_argument("--dataset-manifest", required=True)
    ap.add_argument("--checkpoint-target", required=True)
    ap.add_argument("--state", required=True)
    ap.add_argument("--receipt", required=True)
    ap.add_argument("--steps", type=int, required=True)
    ap.add_argument("--seed", type=int, default=1976)
    args = ap.parse_args()

    dataset_root = Path(args.dataset_root).resolve()
    train_files_path = Path(args.train_files).resolve()
    manifest_path = Path(args.dataset_manifest).resolve()
    checkpoint_target = Path(args.checkpoint_target).resolve()
    state_path = Path(args.state).resolve()
    receipt_path = Path(args.receipt).resolve()

    checkpoint_target.parent.mkdir(parents=True, exist_ok=True)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_sha = sha256_file(manifest_path)
    files = load_file_list(train_files_path)
    if len(files) != int(manifest["train_file_count"]):
        raise SystemExit("Training file list count does not match dataset manifest")

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

    state = load_state(state_path, manifest_sha)
    resumed = Path(str(checkpoint_target) + ".head.json").is_file()
    if resumed:
        model.load(str(checkpoint_target))
        authority = model.checkpoint_authority_status()
        if authority["legacy_unbound_taint"]:
            raise SystemExit("Refusing to resume from legacy-unbound checkpoint")

    start_steps = int(state.get("cumulative_steps", 0))
    stream = pair_stream(dataset_root, files, state)
    started = time.time()
    cursor = {
        "file_index": int(state.get("file_index", 0)),
        "line_index": int(state.get("line_index", 0)),
        "pair_index": int(state.get("pair_index", 0)),
        "completed_file_cycles": int(state.get("completed_file_cycles", 0)),
    }
    last_location = None

    for local_step in range(1, args.steps + 1):
        c, n, end, rel, li, pi, next_cursor = next(stream)
        model(c, n, end, frozen=False)
        cursor = next_cursor
        last_location = {"file": rel, "line_index": li, "pair_index": pi}
        if local_step % 500 == 0 or local_step == args.steps:
            elapsed = max(time.time() - started, 1e-9)
            print(
                f"HF8_V0_2_TRAIN_PROGRESS local={local_step}/{args.steps} "
                f"cumulative={start_steps + local_step} rate={local_step/elapsed:.2f}_steps_s",
                flush=True,
            )

    model.save(str(checkpoint_target))
    event = model.last_checkpoint_event or {}
    generation_id = event.get("generation_id")
    if not generation_id:
        raise SystemExit("Checkpoint save produced no generation identity")

    payload_raw, manifest_raw = model._generation_paths(str(checkpoint_target), generation_id)
    payload = Path(payload_raw)
    ckpt_manifest = Path(manifest_raw)
    head = Path(model._head_path(str(checkpoint_target)))

    cumulative = start_steps + args.steps
    new_state = {
        "schema_version": 2,
        "dataset_manifest_sha256": manifest_sha,
        "train_file_list_sha256": manifest["train_file_list_sha256"],
        "cumulative_steps": cumulative,
        "file_index": int(cursor["file_index"]),
        "line_index": int(cursor["line_index"]),
        "pair_index": int(cursor["pair_index"]),
        "completed_file_cycles": int(cursor["completed_file_cycles"]),
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
        "last_location": last_location,
        "last_source_sha": os.environ.get("GITHUB_SHA"),
    }
    state_path.write_text(json.dumps(new_state, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    elapsed = time.time() - started
    receipt = {
        "gate": "HF8_V0_2_TRAINING_CHUNK",
        "artifact_kind": "REAL_TRAINED_CHECKPOINT",
        "training_regime": "UPSTREAM_STYLE_WIKIEXTRACTOR_FILE_STREAM",
        "source_sha": os.environ.get("GITHUB_SHA"),
        "seed": args.seed,
        "resumed": resumed,
        "chunk_steps": args.steps,
        "cumulative_steps": cumulative,
        "elapsed_seconds": elapsed,
        "steps_per_second": args.steps / max(elapsed, 1e-9),
        "dataset_manifest_sha256": manifest_sha,
        "dump_sha256": manifest["dump_sha256"],
        "train_file_list_sha256": manifest["train_file_list_sha256"],
        "generation_id": generation_id,
        "payload_path": str(payload),
        "payload_bytes": payload.stat().st_size,
        "payload_sha256": sha256_file(payload),
        "checkpoint_manifest_path": str(ckpt_manifest),
        "checkpoint_manifest_sha256": sha256_file(ckpt_manifest),
        "head_path": str(head),
        "head_sha256": sha256_file(head),
        "authority_binding": "CURRENT_BOUND",
        "legacy_unbound_taint": bool(model.checkpoint_authority_status()["legacy_unbound_taint"]),
        "model_parameter_count": model.count(),
        "canonical_authority_transferred": False,
        "human_promotion_required": True,
    }
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("HF8_V0_2_REAL_TRAINED_CHECKPOINT=PASS")
    print("HF8_V0_2_CHECKPOINT_SHA256=" + receipt["payload_sha256"])
    print("HF8_V0_2_CHECKPOINT_BYTES=" + str(receipt["payload_bytes"]))
    print("HF8_V0_2_CUMULATIVE_STEPS=" + str(cumulative))
    print("HF8_V0_2_MODEL_PARAMETERS=" + str(receipt["model_parameter_count"]))
    print("HF8_V0_2_AUTHORITY_BINDING=CURRENT_BOUND")
    print("HF8_V0_2_HUMAN_PROMOTION_REQUIRED=true")


if __name__ == "__main__":
    main()
