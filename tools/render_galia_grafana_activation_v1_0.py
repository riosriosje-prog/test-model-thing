#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "governance/galia_grafana_activation_candidate.v1_0.json"
SQL_PATH = ROOT / "supabase/bindings/galia_grafana_login_activation_v1_0.sql"

PROMOTED_TOKEN = "__PROMOTED_MAIN_COMMIT__"
HEAD_TOKEN = "__CANDIDATE_HEAD__"
SET_TOKEN = "__CANDIDATE_SET_SHA256__"
PASSWORD_TOKEN = "__GRAFANA_PASSWORD__"

CANDIDATE_PATHS = (
    "governance/galia_grafana_activation_candidate.v1_0.json",
    "supabase/bindings/galia_grafana_login_activation_v1_0.sql",
    "tests/test_galia_grafana_activation_v1_0.py",
    "tools/render_galia_grafana_activation_v1_0.py",
)

PASSWORD_RE = re.compile(r"^[A-Za-z0-9_-]{32,64}$")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def candidate_file_hashes(root: Path = ROOT) -> dict[str, str]:
    return {
        path: sha256_bytes((root / path).read_bytes())
        for path in CANDIDATE_PATHS
    }


def candidate_set_material(hashes: dict[str, str]) -> bytes:
    return "".join(
        f"{path}\0{hashes[path]}\n"
        for path in sorted(hashes)
    ).encode("utf-8")


def candidate_set_sha256(root: Path = ROOT) -> str:
    return sha256_bytes(candidate_set_material(candidate_file_hashes(root)))


def validate_hex(value: str, length: int, label: str) -> None:
    if not re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
        raise SystemExit(f"{label} must be exactly {length} lower-case hex characters")


def render_sql(
    promoted_main_commit: str,
    candidate_head: str,
    expected_candidate_set_sha256: str,
    password: str,
    root: Path = ROOT,
) -> tuple[str, str]:
    validate_hex(promoted_main_commit, 40, "promoted main commit")
    validate_hex(candidate_head, 40, "candidate head")
    validate_hex(expected_candidate_set_sha256, 64, "candidate-set SHA-256")

    if not PASSWORD_RE.fullmatch(password):
        raise SystemExit("Grafana password violates runtime secret contract")

    manifest = json.loads((root / MANIFEST_PATH.relative_to(ROOT)).read_text(encoding="utf-8"))
    if manifest["candidate_id"] != "GALIA-GRAFANA-ACTIVATION-CANDIDATE-v1.0":
        raise SystemExit("candidate manifest identity mismatch")

    actual_set = candidate_set_sha256(root)
    if actual_set != expected_candidate_set_sha256:
        raise SystemExit(
            f"candidate-set SHA-256 mismatch: actual={actual_set} expected={expected_candidate_set_sha256}"
        )

    sql = (root / SQL_PATH.relative_to(ROOT)).read_text(encoding="utf-8")
    rendered = (
        sql.replace(PROMOTED_TOKEN, promoted_main_commit)
        .replace(HEAD_TOKEN, candidate_head)
        .replace(SET_TOKEN, actual_set)
        .replace(PASSWORD_TOKEN, password)
    )

    for token in (PROMOTED_TOKEN, HEAD_TOKEN, SET_TOKEN, PASSWORD_TOKEN):
        if token in rendered:
            raise SystemExit(f"unresolved token remains: {token}")

    return rendered, actual_set


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--promoted-main-commit", required=True)
    parser.add_argument("--candidate-head", required=True)
    parser.add_argument("--expected-candidate-set-sha256", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    password = os.environ.get("GALIA_GRAFANA_DB_PASSWORD", "")
    if not password:
        raise SystemExit("GALIA_GRAFANA_DB_PASSWORD is required")

    rendered, actual_set = render_sql(
        args.promoted_main_commit,
        args.candidate_head,
        args.expected_candidate_set_sha256,
        password,
    )

    out = Path(args.output)
    out.write_text(rendered, encoding="utf-8")
    os.chmod(out, 0o600)

    print("GALIA_GRAFANA_ACTIVATION_RENDER=PASS")
    print("GALIA_GRAFANA_ACTIVATION_CANDIDATE_SET_SHA256=" + actual_set)
    print("GALIA_GRAFANA_ACTIVATION_OUTPUT=" + str(out))
    print("GALIA_GRAFANA_ACTIVATION_OUTPUT_MODE=0600")


if __name__ == "__main__":
    main()
