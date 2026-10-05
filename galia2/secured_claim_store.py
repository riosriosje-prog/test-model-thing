"""SQLite persistence for GALIA 2.0 secured-claim kernel candidate c2.

This store is isolated from HistoricalStore and the model runtime. It persists
canonical legal events and optionally caches derived snapshots with explicit
source-event lineage. Canonical events are append-only and hash-verified.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
import json
import os
import sqlite3
from typing import Iterator

from .secured_claims import (
    AuthorityReference,
    CanonicalEvent,
    DerivedSnapshot,
    DuplicateEventConflict,
    EventAuthorityState,
    UnresolvedLegalState,
)

SCHEMA_VERSION = 1


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


class SecuredClaimStore:
    """Isolated SQLite event store for the secured-claim kernel."""

    def __init__(self, path: str):
        self.path = os.path.abspath(os.path.expanduser(path))
        parent = os.path.dirname(self.path) or os.curdir
        os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.execute("PRAGMA synchronous = FULL")
        self.conn.execute("PRAGMA busy_timeout = 5000")
        self._migrate()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "SecuredClaimStore":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            yield self.conn
        except Exception:
            self.conn.rollback()
            raise
        else:
            self.conn.commit()

    def _migrate(self) -> None:
        current = int(self.conn.execute("PRAGMA user_version").fetchone()[0])
        if current > SCHEMA_VERSION:
            raise RuntimeError(
                f"Secured claim store schema {current} is newer than supported "
                f"schema {SCHEMA_VERSION}"
            )
        if current == 0:
            self._create_schema_v1()
            current = 1
        if current != SCHEMA_VERSION:
            raise RuntimeError(
                f"No migration path from schema {current} to {SCHEMA_VERSION}"
            )

    def _create_schema_v1(self) -> None:
        with self.transaction():
            self.conn.executescript(
                """
                CREATE TABLE schema_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE canonical_events (
                    event_id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    event_effective_at TEXT NOT NULL,
                    event_recorded_at TEXT NOT NULL,
                    authority_id TEXT NOT NULL,
                    authority_type TEXT NOT NULL,
                    authority_citation TEXT NOT NULL,
                    authority_jurisdiction TEXT,
                    authority_effective_date TEXT,
                    payload_json TEXT NOT NULL,
                    supersedes_event_id TEXT REFERENCES canonical_events(event_id),
                    authority_state TEXT NOT NULL,
                    event_sha256 TEXT NOT NULL UNIQUE,
                    CHECK (length(event_sha256) = 64)
                );

                CREATE INDEX idx_canonical_events_effective
                    ON canonical_events(event_effective_at);
                CREATE INDEX idx_canonical_events_type
                    ON canonical_events(event_type);
                CREATE INDEX idx_canonical_events_supersedes
                    ON canonical_events(supersedes_event_id);

                CREATE TABLE derived_snapshots (
                    snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_type TEXT NOT NULL,
                    as_of TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    calculation_version TEXT NOT NULL,
                    values_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE derived_snapshot_sources (
                    snapshot_id INTEGER NOT NULL
                        REFERENCES derived_snapshots(snapshot_id) ON DELETE CASCADE,
                    ordinal INTEGER NOT NULL,
                    event_id TEXT NOT NULL REFERENCES canonical_events(event_id),
                    PRIMARY KEY(snapshot_id, ordinal),
                    UNIQUE(snapshot_id, event_id)
                );

                CREATE TRIGGER canonical_events_no_update
                BEFORE UPDATE ON canonical_events
                BEGIN
                    SELECT RAISE(ABORT, 'canonical_events is append-only');
                END;

                CREATE TRIGGER canonical_events_no_delete
                BEFORE DELETE ON canonical_events
                BEGIN
                    SELECT RAISE(ABORT, 'canonical_events is append-only');
                END;

                CREATE TRIGGER derived_snapshots_no_update
                BEFORE UPDATE ON derived_snapshots
                BEGIN
                    SELECT RAISE(ABORT, 'derived_snapshots is append-only');
                END;

                CREATE TRIGGER derived_snapshot_sources_no_update
                BEFORE UPDATE ON derived_snapshot_sources
                BEGIN
                    SELECT RAISE(ABORT, 'derived_snapshot_sources is append-only');
                END;
                """
            )
            self.conn.execute(
                "INSERT INTO schema_meta(key, value) VALUES (?, ?)",
                ("schema_version", "1"),
            )
            self.conn.execute("PRAGMA user_version = 1")

    def append_event(self, event: CanonicalEvent) -> None:
        existing = self.conn.execute(
            "SELECT event_sha256 FROM canonical_events WHERE event_id = ?",
            (event.event_id,),
        ).fetchone()
        if existing is not None:
            if existing["event_sha256"] == event.sha256:
                return
            raise DuplicateEventConflict(
                f"event_id {event.event_id!r} already exists with different content"
            )

        if event.supersedes_event_id:
            prior = self.conn.execute(
                "SELECT 1 FROM canonical_events WHERE event_id = ?",
                (event.supersedes_event_id,),
            ).fetchone()
            if prior is None:
                raise UnresolvedLegalState("superseded event must already exist")

        payload_json = _canonical_json(list(event.payload))
        with self.transaction():
            self.conn.execute(
                """
                INSERT INTO canonical_events(
                    event_id, event_type, event_effective_at, event_recorded_at,
                    authority_id, authority_type, authority_citation,
                    authority_jurisdiction, authority_effective_date,
                    payload_json, supersedes_event_id, authority_state,
                    event_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.event_type,
                    event.event_effective_at.isoformat(),
                    event.event_recorded_at.isoformat(),
                    event.authority.authority_id,
                    event.authority.authority_type,
                    event.authority.citation,
                    event.authority.jurisdiction,
                    (
                        event.authority.effective_date.isoformat()
                        if event.authority.effective_date else None
                    ),
                    payload_json,
                    event.supersedes_event_id,
                    event.authority_state.value,
                    event.sha256,
                ),
            )

    def get_event(self, event_id: str) -> CanonicalEvent:
        row = self.conn.execute(
            "SELECT * FROM canonical_events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        if row is None:
            raise KeyError(event_id)
        event = self._event_from_row(row)
        if event.sha256 != row["event_sha256"]:
            raise RuntimeError(f"canonical event hash mismatch: {event_id}")
        return event

    def list_events(self) -> tuple[CanonicalEvent, ...]:
        rows = self.conn.execute(
            """
            SELECT * FROM canonical_events
            ORDER BY event_effective_at, rowid
            """
        ).fetchall()
        events = tuple(self._event_from_row(row) for row in rows)
        for event, row in zip(events, rows):
            if event.sha256 != row["event_sha256"]:
                raise RuntimeError(f"canonical event hash mismatch: {event.event_id}")
        return events

    def append_snapshot(self, snapshot: DerivedSnapshot) -> int:
        snapshot.validate()
        for event_id in snapshot.source_event_ids:
            if self.conn.execute(
                "SELECT 1 FROM canonical_events WHERE event_id = ?",
                (event_id,),
            ).fetchone() is None:
                raise UnresolvedLegalState(
                    f"snapshot source event does not exist: {event_id}"
                )

        with self.transaction():
            cursor = self.conn.execute(
                """
                INSERT INTO derived_snapshots(
                    snapshot_type, as_of, purpose,
                    calculation_version, values_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    snapshot.snapshot_type,
                    snapshot.as_of.isoformat(),
                    snapshot.purpose,
                    snapshot.calculation_version,
                    _canonical_json(list(snapshot.values)),
                ),
            )
            snapshot_id = int(cursor.lastrowid)
            self.conn.executemany(
                """
                INSERT INTO derived_snapshot_sources(
                    snapshot_id, ordinal, event_id
                ) VALUES (?, ?, ?)
                """,
                [
                    (snapshot_id, ordinal, event_id)
                    for ordinal, event_id in enumerate(snapshot.source_event_ids)
                ],
            )
        return snapshot_id

    def get_snapshot(self, snapshot_id: int) -> DerivedSnapshot:
        row = self.conn.execute(
            "SELECT * FROM derived_snapshots WHERE snapshot_id = ?",
            (snapshot_id,),
        ).fetchone()
        if row is None:
            raise KeyError(snapshot_id)
        sources = self.conn.execute(
            """
            SELECT event_id FROM derived_snapshot_sources
            WHERE snapshot_id = ?
            ORDER BY ordinal
            """,
            (snapshot_id,),
        ).fetchall()
        snapshot = DerivedSnapshot(
            snapshot_type=row["snapshot_type"],
            as_of=datetime.fromisoformat(row["as_of"]),
            purpose=row["purpose"],
            source_event_ids=tuple(r["event_id"] for r in sources),
            calculation_version=row["calculation_version"],
            values=tuple(tuple(x) for x in json.loads(row["values_json"])),
        )
        snapshot.validate()
        return snapshot

    def health(self) -> dict[str, object]:
        return {
            "schema_version": int(
                self.conn.execute("PRAGMA user_version").fetchone()[0]
            ),
            "event_count": int(
                self.conn.execute("SELECT COUNT(*) FROM canonical_events").fetchone()[0]
            ),
            "snapshot_count": int(
                self.conn.execute("SELECT COUNT(*) FROM derived_snapshots").fetchone()[0]
            ),
            "foreign_keys": int(
                self.conn.execute("PRAGMA foreign_keys").fetchone()[0]
            ),
            "journal_mode": str(
                self.conn.execute("PRAGMA journal_mode").fetchone()[0]
            ).lower(),
        }

    @staticmethod
    def _event_from_row(row: sqlite3.Row) -> CanonicalEvent:
        authority = AuthorityReference(
            authority_id=row["authority_id"],
            authority_type=row["authority_type"],
            citation=row["authority_citation"],
            jurisdiction=row["authority_jurisdiction"],
            effective_date=(
                datetime.fromisoformat(row["authority_effective_date"])
                if row["authority_effective_date"] else None
            ),
        )
        return CanonicalEvent(
            event_id=row["event_id"],
            event_type=row["event_type"],
            event_effective_at=datetime.fromisoformat(row["event_effective_at"]),
            event_recorded_at=datetime.fromisoformat(row["event_recorded_at"]),
            authority=authority,
            payload=tuple(tuple(x) for x in json.loads(row["payload_json"])),
            supersedes_event_id=row["supersedes_event_id"],
            authority_state=EventAuthorityState(row["authority_state"]),
        )
