from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from historical_store import HistoricalStore, SCHEMA_VERSION

BUNDLE_FORMAT = "galia-historical-store-bundle"
BUNDLE_VERSION = 1

# Dependency-safe insertion order. Primary-key columns also define deterministic
# export ordering.
EXPORT_TABLES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("sources", ("source_id",)),
    ("ingest_runs", ("run_id",)),
    ("entities", ("entity_id",)),
    ("documents", ("document_id",)),
    ("entity_aliases", ("alias_id",)),
    ("claims", ("claim_id",)),
    ("claim_evidence", ("evidence_id",)),
    ("relations", ("relation_id",)),
    ("events", ("event_id",)),
    ("event_participants", ("event_id", "entity_id", "role")),
    ("discrepancies", ("discrepancy_id",)),
    ("discrepancy_claims", ("discrepancy_id", "claim_id")),
    ("reviews", ("review_id",)),
    ("audit_log", ("audit_id",)),
)


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")


def export_bundle(store: HistoricalStore) -> dict[str, Any]:
    """Export canonical research rows without mutating the store."""
    tables: dict[str, list[dict[str, Any]]] = {}
    for table, order_columns in EXPORT_TABLES:
        order_by = ", ".join(order_columns)
        rows = store.conn.execute(
            f"SELECT * FROM {table} ORDER BY {order_by}"
        ).fetchall()
        tables[table] = [dict(row) for row in rows]

    return {
        "format": BUNDLE_FORMAT,
        "bundle_version": BUNDLE_VERSION,
        "schema_version": SCHEMA_VERSION,
        "tables": tables,
    }


def bundle_sha256(bundle: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(bundle)).hexdigest()


def write_bundle_atomic(store: HistoricalStore, path: str) -> str:
    """Write a deterministic bundle atomically and return its SHA-256."""
    bundle = export_bundle(store)
    payload = _canonical_bytes(bundle)
    digest = hashlib.sha256(payload).hexdigest()

    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=str(target.parent),
    )
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)
        try:
            dir_fd = os.open(str(target.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return digest


def _assert_bundle_shape(bundle: dict[str, Any]) -> None:
    if bundle.get("format") != BUNDLE_FORMAT:
        raise ValueError("Unknown Historical Store bundle format")
    if bundle.get("bundle_version") != BUNDLE_VERSION:
        raise ValueError("Unsupported Historical Store bundle version")
    if bundle.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            "Historical Store bundle schema does not match runtime schema"
        )
    tables = bundle.get("tables")
    if not isinstance(tables, dict):
        raise ValueError("Historical Store bundle tables must be an object")
    expected = {table for table, _ in EXPORT_TABLES}
    actual = set(tables)
    if actual != expected:
        raise ValueError(
            f"Historical Store bundle table mismatch: "
            f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )


def reconstruct_bundle(
    bundle: dict[str, Any],
    destination: str,
) -> HistoricalStore:
    """Reconstruct a bundle into a new empty store.

    The destination must be logically empty. This is intentionally not a merge
    operation: shadow-store reconciliation is a separate authority-sensitive
    step.
    """
    _assert_bundle_shape(bundle)
    store = HistoricalStore(destination)
    try:
        nonempty = {
            table: count
            for table, count in store.health()["counts"].items()
            if count
        }
        if nonempty:
            raise ValueError(
                f"Destination Historical Store is not empty: {nonempty}"
            )

        with store.transaction():
            for table, _ in EXPORT_TABLES:
                rows = bundle["tables"][table]
                if not isinstance(rows, list):
                    raise ValueError(f"Bundle table {table!r} must be a list")
                for row in rows:
                    if not isinstance(row, dict) or not row:
                        raise ValueError(
                            f"Bundle table {table!r} contains an invalid row"
                        )
                    columns = list(row)
                    placeholders = ", ".join("?" for _ in columns)
                    column_sql = ", ".join(columns)
                    store.conn.execute(
                        f"INSERT INTO {table} ({column_sql}) "
                        f"VALUES ({placeholders})",
                        [row[column] for column in columns],
                    )

        fk_errors = store.conn.execute("PRAGMA foreign_key_check").fetchall()
        if fk_errors:
            raise ValueError(
                f"Reconstructed Historical Store has foreign-key errors: "
                f"{[tuple(row) for row in fk_errors]}"
            )
        integrity = store.conn.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise ValueError(
                f"Reconstructed Historical Store integrity check failed: {integrity}"
            )

        rebuilt = export_bundle(store)
        if bundle_sha256(rebuilt) != bundle_sha256(bundle):
            raise ValueError(
                "Reconstructed Historical Store is not byte-canonical "
                "with the exported provenance bundle"
            )
        return store
    except Exception:
        store.close()
        raise


def load_bundle(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        bundle = json.load(f)
    _assert_bundle_shape(bundle)
    return bundle
