from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
CONFIG_KEYS = {"dim", "layers", "spread", "temp", "lr", "lrbegin", "lrend"}


class BundleError(ValueError):
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
        raise BundleError(f"invalid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise BundleError(f"expected JSON object: {path}")
    return value


def safe_rel(value: str) -> Path:
    p = Path(value)
    if not value or p.is_absolute() or ".." in p.parts:
        raise BundleError(f"unsafe package-relative path: {value!r}")
    return p


def validate_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise BundleError(f"{label} must be lowercase SHA-256")
    return value


def validate_rows(root: Path, rows: object) -> dict[str, dict]:
    if not isinstance(rows, list) or not rows:
        raise BundleError("files must be a non-empty list")
    out: dict[str, dict] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise BundleError("files entries must be objects")
        rel = str(safe_rel(row.get("path", "")))
        if rel in out:
            raise BundleError(f"duplicate file row: {rel}")
        expected_bytes = row.get("bytes")
        if not isinstance(expected_bytes, int) or expected_bytes <= 0:
            raise BundleError(f"invalid byte size for {rel}")
        expected_sha = validate_sha(row.get("sha256"), f"{rel}.sha256")
        path = root / rel
        if not path.is_file():
            raise BundleError(f"missing bundle file: {rel}")
        if path.stat().st_size != expected_bytes:
            raise BundleError(f"size mismatch: {rel}")
        if sha256_file(path) != expected_sha:
            raise BundleError(f"SHA-256 mismatch: {rel}")
        out[rel] = row
    return out


def validate_bundle(root: Path, *, runtime_verify: bool = False) -> dict:
    doc_path = root / "HF8_WEIGHT_BUNDLE.json"
    if not doc_path.is_file():
        raise BundleError("missing HF8_WEIGHT_BUNDLE.json")
    doc = load_json(doc_path)

    if doc.get("schema_version") != 1:
        raise BundleError("unsupported schema_version")
    if doc.get("artifact_kind") != "GALIA_TRAINED_CHECKPOINT_BUNDLE":
        raise BundleError("unexpected artifact_kind")
    if doc.get("synthetic_or_placeholder") is not False:
        raise BundleError("synthetic_or_placeholder must be false")
    if doc.get("human_promotion_required") is not True:
        raise BundleError("human_promotion_required must be true")
    if doc.get("canonical_authority_transferred") is not False:
        raise BundleError("canonical_authority_transferred must be false")
    if doc.get("source_repo") != "riosriosje-prog/test-model-thing":
        raise BundleError("unexpected source_repo")
    if not isinstance(doc.get("source_commit"), str) or not COMMIT_RE.fullmatch(doc["source_commit"]):
        raise BundleError("source_commit must be an exact 40-character Git SHA")

    prov = doc.get("training_provenance")
    if not isinstance(prov, dict):
        raise BundleError("training_provenance must be an object")
    for field in (
        "origin_type",
        "obtained_from",
        "training_dataset",
        "training_description",
        "trainer_or_custodian",
        "started_at_utc",
        "finished_at_utc",
        "runtime",
        "python_version",
        "mlx_version",
    ):
        if not isinstance(prov.get(field), str) or not prov[field].strip():
            raise BundleError(f"training_provenance.{field} is required")
    if prov.get("claimed_not_synthetic") is not True:
        raise BundleError("claimed_not_synthetic must be true")
    if not isinstance(prov.get("training_steps"), int) or prov["training_steps"] < 1:
        raise BundleError("training_steps must be >= 1")
    validate_sha(prov.get("training_data_sha256"), "training_data_sha256")

    files = validate_rows(root, doc.get("files"))

    target_rel = safe_rel(doc.get("checkpoint_target", ""))
    target = root / target_rel
    head_rel = Path(str(target_rel) + ".head.json")
    if str(head_rel) not in files:
        raise BundleError("checkpoint HEAD must be listed in files")
    head = load_json(root / head_rel)

    current = head.get("current_generation")
    if not isinstance(current, str) or not current:
        raise BundleError("HEAD current_generation missing")
    if not isinstance(head.get("commit_seq"), int) or head["commit_seq"] < 1:
        raise BundleError("HEAD commit_seq invalid")
    if not isinstance(head.get("commit_id"), str) or not head["commit_id"]:
        raise BundleError("HEAD commit_id missing")

    payload_rel = Path(f"{target_rel}.g-{current}.safetensors")
    manifest_rel = Path(f"{target_rel}.g-{current}.manifest.json")
    for rel in (payload_rel, manifest_rel):
        if str(rel) not in files:
            raise BundleError(f"current generation file missing from bundle: {rel}")

    manifest = load_json(root / manifest_rel)
    if manifest.get("generation_id") != current:
        raise BundleError("manifest generation_id != HEAD current_generation")
    if manifest.get("checkpoint_kind") != "full":
        raise BundleError("checkpoint_kind must be full")
    if manifest.get("commit_id") != head.get("commit_id"):
        raise BundleError("HEAD/manifest commit_id mismatch")
    if manifest.get("commit_seq") != head.get("commit_seq"):
        raise BundleError("HEAD/manifest commit_seq mismatch")
    if manifest.get("sha256") != files[str(payload_rel)]["sha256"]:
        raise BundleError("manifest payload SHA mismatch")
    if manifest.get("size_bytes") != files[str(payload_rel)]["bytes"]:
        raise BundleError("manifest payload size mismatch")

    config = manifest.get("model_config")
    if not isinstance(config, dict) or set(config) != CONFIG_KEYS:
        raise BundleError("model_config does not match current GALIA contract")

    previous = head.get("previous_generation")
    if previous:
        prev_payload = Path(f"{target_rel}.g-{previous}.safetensors")
        prev_manifest = Path(f"{target_rel}.g-{previous}.manifest.json")
        for rel in (prev_payload, prev_manifest):
            if str(rel) not in files:
                raise BundleError(
                    "HEAD references previous generation but recovery bundle is incomplete: "
                    f"{rel}"
                )

    runtime_status = "NOT_RUN"
    if runtime_verify:
        root_repo = Path(__file__).resolve().parents[1]
        if str(root_repo) not in sys.path:
            sys.path.insert(0, str(root_repo))
        from main import Model
        model = Model(**config)
        model.load(str(target))
        event = model.last_checkpoint_event or {}
        if event.get("status") != "current":
            raise BundleError(f"runtime did not load current generation: {event}")
        if model.checkpoint_authority_status().get("legacy_unbound_taint"):
            raise BundleError("runtime load produced legacy_unbound_taint")
        runtime_status = "PASS"

    return {
        "gate": "HF8_WEIGHT_BUNDLE_CONTRACT",
        "status": "PASS",
        "source_commit": doc["source_commit"],
        "checkpoint_target": str(target_rel),
        "current_generation": current,
        "previous_generation": previous,
        "payload_sha256": files[str(payload_rel)]["sha256"],
        "payload_bytes": files[str(payload_rel)]["bytes"],
        "training_data_sha256": prov["training_data_sha256"],
        "training_steps": prov["training_steps"],
        "runtime_verification": runtime_status,
        "technical_upload_eligible": runtime_status == "PASS",
        "human_promotion_required": True,
        "automatic_upload_performed": False,
        "automatic_promotion_performed": False,
        "canonical_authority_transferred": False,
        "source_of_truth": "github",
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Validate a complete GALIA HF8 checkpoint bundle")
    ap.add_argument("package_dir")
    ap.add_argument("--runtime-verify", action="store_true")
    ap.add_argument("--receipt")
    args = ap.parse_args()
    result = validate_bundle(Path(args.package_dir), runtime_verify=args.runtime_verify)
    if args.receipt:
        Path(args.receipt).write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print("HF8_WEIGHT_BUNDLE_CONTRACT=PASS")
    print("HF8_RUNTIME_VERIFICATION=" + result["runtime_verification"])
    print("HF8_TECHNICAL_UPLOAD_ELIGIBLE=" + str(result["technical_upload_eligible"]).lower())
    print("HF8_HUMAN_PROMOTION_REQUIRED=true")


if __name__ == "__main__":
    main()
