from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
from pathlib import Path
import tempfile

import mlx.core as mx
import mlx.utils as util

from main import Model


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def flat_snapshot(model: Model) -> dict[str, list]:
    data = {}
    for prefix, tree in (
        ("m.", model.parameters()),
        ("o.", model.optimizer.state),
    ):
        for key, value in util.tree_flatten(tree):
            data[prefix + key] = value.tolist()
    for i, layer in enumerate(model.layers):
        data[f"state.{i}"] = layer.states.tolist()
        data[f"decaytrace.{i}"] = layer.decaytrace.tolist()
        data[f"embedtrace.{i}"] = layer.embedtrace.tolist()
    return data


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--receipt", default="hf10-linux-parity-receipt.json")
    ap.add_argument("--source-sha", required=True)
    args = ap.parse_args()

    config = dict(
        dim=16,
        layers=2,
        spread=4,
        temp=0.75,
        lr=5e-4,
        lrbegin=4,
        lrend=40,
    )

    mx.random.seed(20260925)

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        target = root / "parity.safetensors"

        a = Model(**config)
        a(65, 66, False, False)
        a(66, 67, True, False)
        a.save(str(target))
        first_snapshot = flat_snapshot(a)
        first_head = json.loads(Path(str(target) + ".head.json").read_text())
        first_generation = first_head["current_generation"]

        b = Model(**config)
        b.load(str(target))
        loaded_snapshot = flat_snapshot(b)
        if loaded_snapshot != first_snapshot:
            raise SystemExit("save/reload exact-state parity failed")
        if b.checkpoint_authority_status()["legacy_unbound_taint"]:
            raise SystemExit("authoritative generation unexpectedly tainted")

        # Create a second generation, then corrupt only the current payload.
        a(67, 68, False, False)
        a.save(str(target))
        second_head = json.loads(Path(str(target) + ".head.json").read_text())
        second_generation = second_head["current_generation"]
        if second_head["previous_generation"] != first_generation:
            raise SystemExit("generation lineage did not retain exact previous generation")

        current_manifest = json.loads(
            Path(f"{target}.gen.{second_generation}.manifest.json").read_text()
        )
        current_payload = root / current_manifest["checkpoint_file"]
        current_payload.write_bytes(current_payload.read_bytes() + b"corruption")

        c = Model(**config)
        c.load(str(target))
        if c.last_checkpoint_event["status"] != "fallback":
            raise SystemExit("corrupted current generation did not trigger fallback")
        fallback_snapshot = flat_snapshot(c)
        if fallback_snapshot != first_snapshot:
            raise SystemExit("fallback did not restore exact previous state")

        first_manifest_path = Path(f"{target}.gen.{first_generation}.manifest.json")
        first_manifest = json.loads(first_manifest_path.read_text())
        first_payload = root / first_manifest["checkpoint_file"]

        receipt = {
            "gate": "HF10_SPACE_PARITY_GATE",
            "phase": "LINUX_CPU_RUNTIME_PROBE",
            "status": "PASS",
            "source_sha": args.source_sha,
            "platform_system": platform.system(),
            "platform_machine": platform.machine(),
            "python_version": platform.python_version(),
            "mlx_version": importlib.metadata.version("mlx"),
            "backend_package_expectation": "mlx[cpu]==0.32.2",
            "model_config": config,
            "save_reload_exact": True,
            "fallback_recovery_exact": True,
            "legacy_unbound_taint_after_authoritative_load": False,
            "first_generation": first_generation,
            "second_generation": second_generation,
            "first_payload_sha256": sha256_file(first_payload),
            "first_manifest_sha256": sha256_file(first_manifest_path),
            "canonical_authority_transferred": False,
            "space_deployment_authorized": False,
            "notes": (
                "Passing this probe establishes Linux CPU runtime/checkpoint parity only. "
                "It does not authorize a Hugging Face Space or production designation."
            ),
        }

        Path(args.receipt).write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        print("HF10_LINUX_MLX_IMPORT=PASS")
        print("HF10_SAVE_RELOAD_EXACT=PASS")
        print("HF10_FALLBACK_RECOVERY=PASS")
        print("HF10_RUNTIME_PROBE=PASS")
        print("HF10_MLX_VERSION=" + receipt["mlx_version"])


if __name__ == "__main__":
    main()
