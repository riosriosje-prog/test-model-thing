from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import mlx.core as mx

ALLOWED_PREFIXES = ("m.", "o.", "state.", "decaytrace.", "embedtrace.")
REQUIRED_PROVENANCE_FIELDS = (
    "origin_type",
    "obtained_from",
    "training_dataset",
    "training_description",
    "trainer_or_custodian",
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def classify_tensor_keys(keys: list[str]) -> str:
    model_keys = [k[2:] for k in keys if k.startswith("m.")]
    if any(k.startswith("blocks.") for k in model_keys):
        return "TMT_UPSTREAM_LEGACY_SCHEMA"
    if any(k.startswith("layers.") for k in model_keys):
        return "GALIA_LAYER_SCHEMA"
    return "UNKNOWN_SCHEMA"


def infer_shape_metadata(data: dict[str, Any], family: str) -> dict[str, Any]:
    dim = None
    encoder = data.get("m.encoder.embed.weight")
    if encoder is not None and len(encoder.shape) == 2:
        dim = int(encoder.shape[1])

    token = "blocks" if family == "TMT_UPSTREAM_LEGACY_SCHEMA" else "layers"
    indices: set[int] = set()
    pattern = re.compile(rf"^m\.{token}\.(\d+)\.")
    for key in data:
        m = pattern.match(key)
        if m:
            indices.add(int(m.group(1)))

    layers = max(indices) + 1 if indices else None
    parameter_count = 0
    for key, value in data.items():
        if key.startswith("m."):
            count = 1
            for d in value.shape:
                count *= int(d)
            parameter_count += count

    return {
        "inferred_dim": dim,
        "inferred_layers": layers,
        "model_parameter_elements": parameter_count,
    }


def load_provenance(path: Path | None) -> tuple[dict[str, Any], dict[str, Any]]:
    if path is None:
        return {}, {
            "status": "MISSING",
            "missing_fields": list(REQUIRED_PROVENANCE_FIELDS) + ["claimed_not_synthetic"],
            "claimed_not_synthetic": False,
        }

    doc = json.loads(path.read_text(encoding="utf-8"))
    missing = [field for field in REQUIRED_PROVENANCE_FIELDS if not doc.get(field)]
    claimed = doc.get("claimed_not_synthetic") is True
    if not claimed:
        missing.append("claimed_not_synthetic")

    return doc, {
        "status": "COMPLETE" if not missing else "INCOMPLETE",
        "missing_fields": missing,
        "claimed_not_synthetic": claimed,
    }


def inspect_single_file(target: Path) -> dict[str, Any]:
    if target.suffix != ".safetensors":
        raise ValueError("HF8 intake accepts only .safetensors checkpoint payloads")
    if not target.is_file():
        raise FileNotFoundError(target)

    data = mx.load(str(target))
    keys = sorted(data.keys())
    unknown = [k for k in keys if not k.startswith(ALLOWED_PREFIXES)]
    family = classify_tensor_keys(keys)
    shape = infer_shape_metadata(data, family)

    result = {
        "payload_path": str(target.resolve()),
        "payload_bytes": target.stat().st_size,
        "payload_sha256": sha256_file(target),
        "tensor_count": len(keys),
        "unknown_key_count": len(unknown),
        "unknown_keys": unknown[:50],
        "schema_family": family,
        **shape,
    }

    if unknown:
        result["classification"] = "REJECTED_UNKNOWN_KEYS"
        result["authority_binding"] = "UNBOUND"
        result["requires_transform"] = False
        return result

    if family == "TMT_UPSTREAM_LEGACY_SCHEMA":
        result["classification"] = "TMT_UPSTREAM_LEGACY"
        result["authority_binding"] = "LEGACY_UNBOUND"
        result["requires_transform"] = True
        return result

    if family == "GALIA_LAYER_SCHEMA":
        from main import Model

        model = Model(
            dim=int(shape["inferred_dim"] or 512),
            layers=int(shape["inferred_layers"] or 16),
            spread=32,
            temp=0.75,
            lr=5e-4,
            lrbegin=40000,
            lrend=120000,
        )
        model.load(str(target), allow_legacy_unbound=True)
        authority = model.checkpoint_authority_status()
        result["classification"] = "GALIA_LEGACY_UNBOUND"
        result["authority_binding"] = "LEGACY_UNBOUND"
        result["requires_transform"] = False
        result["legacy_unbound_taint"] = bool(authority["legacy_unbound_taint"])
        return result

    result["classification"] = "REJECTED_UNKNOWN_SCHEMA"
    result["authority_binding"] = "UNBOUND"
    result["requires_transform"] = False
    return result


def inspect_bound_target(target: Path) -> dict[str, Any]:
    from main import Model

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
    event = model.last_checkpoint_event or {}
    generation = event.get("generation_id")
    if not generation:
        raise ValueError("authoritative load returned no generation identity")

    payload_path_raw, manifest_path_raw = model._generation_paths(str(target.resolve()), generation)
    payload_path = Path(payload_path_raw)
    manifest_path = Path(manifest_path_raw)
    head_path = Path(model._head_path(str(target.resolve())))

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    head = json.loads(head_path.read_text(encoding="utf-8"))

    return {
        "classification": "GALIA_CURRENT_BOUND",
        "authority_binding": "CURRENT_BOUND",
        "requires_transform": False,
        "payload_path": str(payload_path.resolve()),
        "payload_bytes": payload_path.stat().st_size,
        "payload_sha256": sha256_file(payload_path),
        "manifest_path": str(manifest_path.resolve()),
        "manifest_sha256": sha256_file(manifest_path),
        "head_path": str(head_path.resolve()),
        "head_sha256": sha256_file(head_path),
        "generation_id": generation,
        "commit_id": manifest.get("commit_id"),
        "commit_seq": manifest.get("commit_seq"),
        "model_config": manifest.get("model_config"),
        "legacy_unbound_taint": bool(model.checkpoint_authority_status()["legacy_unbound_taint"]),
        "load_status": event.get("status"),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="GALIA HF8 real-weight intake gate")
    ap.add_argument("--target", required=True, help="Checkpoint file or authoritative checkpoint target")
    ap.add_argument("--provenance", help="JSON provenance declaration")
    ap.add_argument("--output", default="hf8-weight-intake-receipt.json")
    args = ap.parse_args()

    target = Path(args.target).expanduser()
    provenance_path = Path(args.provenance).expanduser() if args.provenance else None

    head_candidate = Path(str(target.resolve()) + ".head.json")
    if head_candidate.is_file():
        artifact = inspect_bound_target(target)
    else:
        artifact = inspect_single_file(target)

    provenance, provenance_status = load_provenance(provenance_path)

    structural_pass = artifact["classification"] in {
        "GALIA_CURRENT_BOUND",
        "GALIA_LEGACY_UNBOUND",
        "TMT_UPSTREAM_LEGACY",
    }
    current_bound = artifact["authority_binding"] == "CURRENT_BOUND"
    provenance_complete = provenance_status["status"] == "COMPLETE"

    receipt = {
        "gate": "HF8_WEIGHT_INTAKE",
        "status": "PASS_INTAKE" if structural_pass else "REJECTED",
        "artifact": artifact,
        "provenance": provenance,
        "provenance_status": provenance_status,
        "technical_upload_eligible": bool(structural_pass and current_bound and provenance_complete),
        "promotion_preflight_eligible": bool(structural_pass and current_bound and provenance_complete),
        "human_promotion_required": True,
        "automatic_upload_performed": False,
        "automatic_promotion_performed": False,
        "canonical_authority_transferred": False,
        "source_of_truth": "github",
    }

    if artifact["classification"] == "TMT_UPSTREAM_LEGACY":
        receipt["hold_reason"] = (
            "Real upstream-schema artifact may be inspected, but it is not authority-bound "
            "to the current GALIA checkpoint contract and requires an explicit reviewed migration."
        )
    elif artifact["classification"] == "GALIA_LEGACY_UNBOUND":
        receipt["hold_reason"] = (
            "Artifact is structurally compatible but legacy-unbound; authoritative save/upload "
            "remains refused until a separately reviewed binding/migration decision."
        )
    elif not provenance_complete:
        receipt["hold_reason"] = "Provenance declaration is incomplete."

    Path(args.output).write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("HF8_INTAKE_STATUS=" + receipt["status"])
    print("HF8_CLASSIFICATION=" + artifact["classification"])
    print("HF8_AUTHORITY_BINDING=" + artifact["authority_binding"])
    print("HF8_PAYLOAD_SHA256=" + artifact["payload_sha256"])
    print("HF8_PAYLOAD_BYTES=" + str(artifact["payload_bytes"]))
    print("HF8_TECHNICAL_UPLOAD_ELIGIBLE=" + str(receipt["technical_upload_eligible"]).lower())
    print("HF8_HUMAN_PROMOTION_REQUIRED=true")


if __name__ == "__main__":
    main()
