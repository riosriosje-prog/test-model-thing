from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import random


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def sha256_lines(lines: list[str]) -> str:
    payload = "".join(line + "\n" for line in lines).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser(description="Build reproducible WikiExtractor file manifest for HF8 v0.2")
    ap.add_argument("--dataset-root", required=True)
    ap.add_argument("--dump", required=True)
    ap.add_argument("--source-url", required=True)
    ap.add_argument("--extractor-version", required=True)
    ap.add_argument("--seed", type=int, default=1976)
    ap.add_argument("--holdout-fraction", type=float, default=0.10)
    ap.add_argument("--output-dir", required=True)
    args = ap.parse_args()

    root = Path(args.dataset_root).resolve()
    dump = Path(args.dump).resolve()
    out = Path(args.output_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)

    files = sorted(
        p for p in root.rglob("wiki_*")
        if p.is_file()
    )
    if len(files) < 2:
        raise SystemExit(f"Expected at least 2 WikiExtractor wiki_* files, found {len(files)}")

    relative = [p.relative_to(root).as_posix() for p in files]
    rng = random.Random(args.seed)
    rng.shuffle(relative)

    holdout_count = max(1, int(round(len(relative) * args.holdout_fraction)))
    if holdout_count >= len(relative):
        holdout_count = 1

    eval_files = relative[-holdout_count:]
    train_files = relative[:-holdout_count]

    file_rows = []
    total_bytes = 0
    for rel in relative:
        p = root / rel
        size = p.stat().st_size
        total_bytes += size
        file_rows.append({
            "path": rel,
            "bytes": size,
            "sha256": sha256_file(p),
        })

    train_list = out / "train-files.txt"
    eval_list = out / "eval-files.txt"
    train_list.write_text("".join(x + "\n" for x in train_files), encoding="utf-8")
    eval_list.write_text("".join(x + "\n" for x in eval_files), encoding="utf-8")

    manifest = {
        "gate": "HF8_V0_2_DATASET_MANIFEST",
        "source_url": args.source_url,
        "dump_bytes": dump.stat().st_size,
        "dump_sha256": sha256_file(dump),
        "extractor": "WikiExtractor",
        "extractor_version": args.extractor_version,
        "extractor_output_format": "default_doc_text",
        "extractor_file_pattern": "**/wiki_*",
        "shuffle_semantics": "single_random_shuffle_then_cycle",
        "shuffle_seed": args.seed,
        "holdout_fraction": args.holdout_fraction,
        "split_strategy": "last_N_files_after_deterministic_shuffle",
        "file_count": len(relative),
        "train_file_count": len(train_files),
        "eval_file_count": len(eval_files),
        "dataset_bytes": total_bytes,
        "ordered_file_list_sha256": sha256_lines(relative),
        "train_file_list_sha256": sha256_lines(train_files),
        "eval_file_list_sha256": sha256_lines(eval_files),
        "files": file_rows,
    }
    manifest_path = out / "dataset-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("HF8_V0_2_DATASET_MANIFEST=PASS")
    print("HF8_V0_2_WIKI_FILE_COUNT=" + str(len(relative)))
    print("HF8_V0_2_TRAIN_FILE_COUNT=" + str(len(train_files)))
    print("HF8_V0_2_EVAL_FILE_COUNT=" + str(len(eval_files)))
    print("HF8_V0_2_DATASET_BYTES=" + str(total_bytes))
    print("HF8_V0_2_DUMP_SHA256=" + manifest["dump_sha256"])
    print("HF8_V0_2_TRAIN_LIST_SHA256=" + manifest["train_file_list_sha256"])
    print("HF8_V0_2_EVAL_LIST_SHA256=" + manifest["eval_file_list_sha256"])


if __name__ == "__main__":
    main()
