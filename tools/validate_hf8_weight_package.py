from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_CONFIG_KEYS = {"dim", "layers", "spread", "temp", "lr", "lrbegin", "lrend"}


class IntakeError(ValueError):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise IntakeError(f"invalid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise IntakeError(f"expected JSON object: {path}")
    return value


def safe_relpath(value: str) -> Path:
    p = Path(value)
    if p.is_absolute() or ".." in p.parts or not p.parts:
        raise IntakeError(f"unsafe package-relative path: {value!r}")
    return p


def require_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise IntakeError(f"{label} must be lowercase SHA-256")
    return value


def validate_file_rows(root: Path, rows: object) -> dict[str, dict]:
    if not isinstance(rows, list) or not rows:
        raise IntakeError("files must be a non-empty list")
    seen: dict[str, dict] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise IntakeError("each files row must be an object")
        rel = str(safe_relpath(row.get("path", "")))
        if rel in seen:
            raise IntakeError(f"duplicate file row: {rel}")
        expected_sha = require_sha(row.get("sha256"), f"files[{rel}].sha256")
        expected_bytes = row.get("bytes")
        if not isinstance(expected_bytes, int) or expected_bytes <= 0:
            raise IntakeError(f"files[{rel}].bytes must be > 0")
        path = root / rel
        if not path.is_file():
            raise IntakeError(f"missing package file: {rel}")
        if path.stat().st_size != expected_bytes:
            raise IntakeError(f"size mismatch: {rel}")
        if sha256_file(path) != expected_sha:
            raise IntakeError(f"SHA-256 mismatch: {rel}")
        seen[rel] = row
    return seen


def validate_package(root: Path, *, runtime_verify: bool = False) -> dict:
    intake_path = root / "HF8_WEIGHT_INTAKE.json"
    if not intake_path.is_file():
        raise IntakeError("missing HF8_WEIGHT_INTAKE.json")
    doc = load_json(intake_path)

    if doc.get("schema_version") != 1:
        raise IntakeError("unsupported intake schema_version")
    if doc.get("artifact_kind") != "GALIA_TRAINED_CHECKPOINT_BUNDLE":
        raise IntakeError("artifact_kind must be GALIA_TRAINED_CHECKPOINT_BUNDLE")
    if doc.get("synthetic_or_placeholder") is not False:
        raise IntakeError("synthetic_or_placeholder must be false")
    if doc.get("human_promotion_required") is not True:
        raise IntakeError("human_promotion_required must be true")
    if doc.get("canonical_authority_transferred") is not False:
        raise IntakeError("canonical_authority_transferred must be false")
    if doc.get("source_repo") != "riosriosje-prog/test-model-thing":
        raise IntakeError("unexpected source_repo")
    source_commit = doc.get("source_commit")
    if not isinstance(source_commit, str) or not COMMIT_RE.fullmatch(source_commit):
        raise IntakeError("source_commit must be an exact 40-character Git SHA")

    provenance = doc.get("training_provenance")
    if not isinstance(provenance, dict):
        raise IntakeError("training_provenance must be an object")
    steps = provenance.get("training_steps")
    if not isinstance(steps, int) or steps < 1:
        raise IntakeError("training_steps must be >= 1")
    require_sha(provenance.get("training_data_sha256"), "training_data_sha256")
    for key in (
        "training_data_id",
        "started_at_utc",
        "finished_at_utc",
        "runtime",
        "python_version",
        "mlx_version",
        "operator_or_workflow",
    ):
        if not isinstance(provenance.get(key), str) or not provenance[key].strip():
            raise IntakeError(f"training_provenance.{key} is required")

    files = validate_file_rows(root, doc.get("files"))

    target_rel = safe_relpath(doc.get("checkpoint_target", ""))
    target = root / target_rel
    head_rel = Path(str(target_rel) + ".head.json")
    if str(head_rel) not in files:
        raise IntakeError("checkpoint HEAD must be listed in files")
    head_doc = load_json(root / head_rel)

    current_generation = head_doc.get("current_generation")
    if not isinstance(current_generation, str) or not current_generation:
        raise IntakeError("checkpoint HEAD current_generation missing")
    if head_doc.get("commit_id") in (None, ""):
        raise IntakeError("checkpoint HEAD commit_id missing")
    if not isinstance(head_doc.get("commit_seq"), int) or head_doc["commit_seq"] < 1:
        raise IntakeError("checkpoint HEAD commit_seq invalid")

    current_payload_rel = Path(f"{target_rel}.g-{current_generation}.safetensors")
    current_manifest_rel = Path(f"{target_rel}.g-{current_generation}.manifest.json")
    for rel in (current_payload_rel, current_manifest_rel):
        if str(rel) not in files:
            raise IntakeError(f"current generation file not listed: {rel}")

    current_manifest = load_json(root / current_manifest_rel)
    if current_manifest.get("generation_id") != current_generation:
        raise IntakeError("generation_id does not match HEAD current_generation")
    if current_manifest.get("checkpoint_kind") != "full":
        raise IntakeError("checkpoint_kind must be full")
    if current_manifest.get("sha256") != files[str(current_payload_rel)]["sha256"]:
        raise IntakeError("generation manifest SHA does not match package file row")
    if current_manifest.get("size_bytes") != files[str(current_payload_rel)]["bytes"]:
        raise IntakeError("generation manifest size does not match package file row")
    if current_manifest.get("commit_id") != head_doc.get("commit_id"):
        raise IntakeError("generation/head commit_id mismatch")
    if current_manifest.get("commit_seq") != head_doc.get("commit_seq"):
        raise IntakeError("generation/head commit_seq mismatch")

    config = current_manifest.get("model_config")
    if not isinstance(config, dict) or set(config) != REQUIRED_CONFIG_KEYS:
        raise IntakeError("model_config does not match GALIA checkpoint contract")

    previous_generation = head_doc.get("previous_generation")
    if previous_generation:
        prev_payload = Path(f"{target_rel}.g-{previous_generation}.safetensors")
        prev_manifest = Path(f"{target_rel}.g-{previous_generation}.manifest.json")
        for rel in (prev_payload, prev_manifest):
            if str(rel) not in files:
                raise IntakeError(
                    "recovery bundle is incomplete; previous generation referenced "
                    f"by HEAD is missing: {rel}"
                )

    if runtime_verify:
        repo_root = Path(__file__).resolve().parents[1]
        if str(repo_root) not in sys.path:
            sys.path.insert(0, str(repo_root))
        try:
            from main import Model
        except Exception as exc:
            raise IntakeError("unable to import GALIA runtime for --runtime-verify") from exc
        model = Model(**config)
        model.load(str(target))
        event = model.last_checkpoint_event or {}
        if event.get("status") != "current":
            raise IntakeError(f"runtime load did not select current generation: {event}")
        if model.checkpoint_authority_status().get("legacy_unbound_taint"):
            raise IntakeError("runtime load produced legacy_unbound_taint")

    return {
        "status": "PASS",
        "source_commit": source_commit,
        "checkpoint_target": str(target_rel),
        "current_generation": current_generation,
        "previous_generation": previous_generation,
        "current_payload_sha256": files[str(current_payload_rel)]["sha256"],
        "current_payload_bytes": files[str(current_payload_rel)]["bytes"],
        "training_steps": steps,
        "training_data_sha256": provenance["training_data_sha256"],
        "runtime_verified": bool(runtime_verify),
        "human_promotion_required": True,
        "canonical_authority_transferred": False,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("package_dir")
    ap.add_argument("--runtime-verify", action="store_true")
    ap.add_argument("--receipt")
    args = ap.parse_args()
    result = validate_package(Path(args.package_dir), runtime_verify=args.runtime_verify)
    if args.receipt:
        Path(args.receipt).write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print("HF8_WEIGHT_INTAKE=PASS")
    print("HF8_CURRENT_PAYLOAD_SHA256=" + result["current_payload_sha256"])
    print("HF8_CURRENT_PAYLOAD_BYTES=" + str(result["current_payload_bytes"]))
    print("HF8_RUNTIME_VERIFIED=" + str(result["runtime_verified"]).lower())
    print("HF8_HUMAN_PROMOTION_REQUIRED=true")


if __name__ == "__main__":
    main()
