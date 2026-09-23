from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

SCHEMA_VERSION = 3
EVIDENCE_ROLES = {"supports", "contradicts", "mentions"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value if value is not None else {},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class HistoricalStore:
    """SQLite-backed canonical research store for GALIA.

    The store is intentionally separate from model checkpoints. Model/runtime
    outputs may create PROPOSED claims, but only explicit human review may
    promote a claim to CANONICAL.
    """

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

    def __enter__(self) -> "HistoricalStore":
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
                f"Historical store schema {current} is newer than supported "
                f"schema {SCHEMA_VERSION}"
            )
        if current == 0:
            self._create_schema_v1()
            current = 1
        if current == 1:
            self._migrate_v1_to_v2()
            current = 2
        if current == 2:
            self._migrate_v2_to_v3()
            current = 3
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

                CREATE TABLE sources (
                    source_id TEXT PRIMARY KEY,
                    source_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    custodian TEXT,
                    repository TEXT,
                    locator TEXT,
                    url TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at_utc TEXT NOT NULL
                );

                CREATE TABLE documents (
                    document_id TEXT PRIMARY KEY,
                    source_id TEXT REFERENCES sources(source_id),
                    title TEXT NOT NULL,
                    document_date TEXT,
                    event_date_start TEXT,
                    event_date_end TEXT,
                    content_sha256 TEXT,
                    byte_length INTEGER,
                    content_locator TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at_utc TEXT NOT NULL,
                    CHECK (content_sha256 IS NULL OR length(content_sha256) = 64)
                );

                CREATE TABLE ingest_runs (
                    run_id TEXT PRIMARY KEY,
                    engine_version TEXT,
                    prompt_version TEXT,
                    input_sha256 TEXT NOT NULL,
                    output_sha256 TEXT,
                    mode TEXT NOT NULL,
                    status TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at_utc TEXT NOT NULL,
                    CHECK (length(input_sha256) = 64),
                    CHECK (output_sha256 IS NULL OR length(output_sha256) = 64)
                );

                CREATE TABLE entities (
                    entity_id TEXT PRIMARY KEY,
                    entity_type TEXT NOT NULL,
                    canonical_name TEXT NOT NULL,
                    authority_status TEXT NOT NULL DEFAULT 'PROVISIONAL',
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at_utc TEXT NOT NULL
                );

                CREATE TABLE entity_aliases (
                    alias_id TEXT PRIMARY KEY,
                    entity_id TEXT NOT NULL REFERENCES entities(entity_id),
                    alias TEXT NOT NULL,
                    language TEXT,
                    valid_from TEXT,
                    valid_to TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    UNIQUE(entity_id, alias, language)
                );

                CREATE TABLE claims (
                    claim_id TEXT PRIMARY KEY,
                    document_id TEXT REFERENCES documents(document_id),
                    run_id TEXT REFERENCES ingest_runs(run_id),
                    subject_entity_id TEXT REFERENCES entities(entity_id),
                    predicate TEXT NOT NULL,
                    object_entity_id TEXT REFERENCES entities(entity_id),
                    object_value TEXT,
                    claim_text TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'PROPOSED',
                    created_by TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at_utc TEXT NOT NULL,
                    promoted_at_utc TEXT,
                    CHECK (
                        status IN (
                            'PROPOSED', 'VALIDATED', 'CANONICAL',
                            'REJECTED', 'QUARANTINED'
                        )
                    )
                );

                CREATE TABLE claim_evidence (
                    evidence_id TEXT PRIMARY KEY,
                    claim_id TEXT NOT NULL REFERENCES claims(claim_id),
                    document_id TEXT NOT NULL REFERENCES documents(document_id),
                    locator TEXT,
                    excerpt_sha256 TEXT,
                    role TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at_utc TEXT NOT NULL,
                    CHECK (role IN ('supports', 'contradicts', 'mentions')),
                    CHECK (excerpt_sha256 IS NULL OR length(excerpt_sha256) = 64)
                );

                CREATE TABLE relations (
                    relation_id TEXT PRIMARY KEY,
                    subject_entity_id TEXT NOT NULL REFERENCES entities(entity_id),
                    relation_type TEXT NOT NULL,
                    object_entity_id TEXT NOT NULL REFERENCES entities(entity_id),
                    valid_from TEXT,
                    valid_to TEXT,
                    status TEXT NOT NULL DEFAULT 'PROPOSED',
                    source_claim_id TEXT REFERENCES claims(claim_id),
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at_utc TEXT NOT NULL
                );

                CREATE TABLE events (
                    event_id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    label TEXT NOT NULL,
                    event_date_start TEXT,
                    event_date_end TEXT,
                    date_precision TEXT,
                    place_entity_id TEXT REFERENCES entities(entity_id),
                    status TEXT NOT NULL DEFAULT 'PROPOSED',
                    source_claim_id TEXT REFERENCES claims(claim_id),
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at_utc TEXT NOT NULL
                );

                CREATE TABLE event_participants (
                    event_id TEXT NOT NULL REFERENCES events(event_id),
                    entity_id TEXT NOT NULL REFERENCES entities(entity_id),
                    role TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    PRIMARY KEY(event_id, entity_id, role)
                );

                CREATE TABLE discrepancies (
                    discrepancy_id TEXT PRIMARY KEY,
                    topic_key TEXT NOT NULL,
                    description TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'OPEN',
                    resolution TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    opened_at_utc TEXT NOT NULL,
                    resolved_at_utc TEXT,
                    CHECK (
                        status IN ('OPEN', 'RESOLVED', 'CLOSED_NO_RESOLUTION')
                    )
                );

                CREATE TABLE discrepancy_claims (
                    discrepancy_id TEXT NOT NULL REFERENCES discrepancies(discrepancy_id),
                    claim_id TEXT NOT NULL REFERENCES claims(claim_id),
                    stance TEXT NOT NULL,
                    PRIMARY KEY(discrepancy_id, claim_id)
                );

                CREATE TABLE reviews (
                    review_id TEXT PRIMARY KEY,
                    object_type TEXT NOT NULL,
                    object_id TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    reviewer TEXT NOT NULL,
                    rationale TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at_utc TEXT NOT NULL
                );

                CREATE TABLE audit_log (
                    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    object_type TEXT,
                    object_id TEXT,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    created_at_utc TEXT NOT NULL
                );

                CREATE INDEX idx_documents_source ON documents(source_id);
                CREATE INDEX idx_claims_document ON claims(document_id);
                CREATE INDEX idx_claims_subject ON claims(subject_entity_id);
                CREATE INDEX idx_claims_status ON claims(status);
                CREATE INDEX idx_evidence_claim ON claim_evidence(claim_id);
                CREATE INDEX idx_relations_subject ON relations(subject_entity_id);
                CREATE INDEX idx_relations_object ON relations(object_entity_id);
                CREATE INDEX idx_events_dates ON events(event_date_start, event_date_end);
                CREATE INDEX idx_discrepancies_topic ON discrepancies(topic_key);

                CREATE TRIGGER audit_log_no_update
                BEFORE UPDATE ON audit_log
                BEGIN
                    SELECT RAISE(ABORT, 'audit_log is append-only');
                END;

                CREATE TRIGGER audit_log_no_delete
                BEFORE DELETE ON audit_log
                BEGIN
                    SELECT RAISE(ABORT, 'audit_log is append-only');
                END;
                """
            )
            self.conn.execute(
                "INSERT INTO schema_meta(key, value) VALUES (?, ?)",
                ("schema_version", "1"),
            )
            self.conn.execute("PRAGMA user_version = 1")

    def _migrate_v1_to_v2(self) -> None:
        with self.transaction():
            self.conn.executescript(
                """
                CREATE TABLE document_representations (
                    representation_id TEXT PRIMARY KEY,
                    document_id TEXT NOT NULL REFERENCES documents(document_id),
                    representation_type TEXT NOT NULL,
                    acquisition_state TEXT NOT NULL,
                    mime_type TEXT,
                    content_sha256 TEXT,
                    byte_length INTEGER,
                    locator TEXT NOT NULL,
                    source_url TEXT,
                    raw_artifact INTEGER NOT NULL DEFAULT 0,
                    preferred_for_review INTEGER NOT NULL DEFAULT 0,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at_utc TEXT NOT NULL,
                    CHECK (
                        acquisition_state IN (
                            'RAW_CAPTURED', 'TEXT_SURROGATE', 'REMOTE_BLOCKED',
                            'LOCATOR_ONLY', 'QUARANTINED'
                        )
                    ),
                    CHECK (raw_artifact IN (0, 1)),
                    CHECK (preferred_for_review IN (0, 1)),
                    CHECK (content_sha256 IS NULL OR length(content_sha256) = 64),
                    CHECK (byte_length IS NULL OR byte_length >= 0),
                    CHECK (
                        acquisition_state != 'RAW_CAPTURED'
                        OR (
                            raw_artifact = 1
                            AND content_sha256 IS NOT NULL
                            AND byte_length IS NOT NULL
                        )
                    ),
                    CHECK (
                        acquisition_state = 'RAW_CAPTURED'
                        OR raw_artifact = 0
                    ),
                    UNIQUE(document_id, representation_type, locator)
                );

                CREATE INDEX idx_document_representations_document
                    ON document_representations(document_id);
                CREATE INDEX idx_document_representations_state
                    ON document_representations(acquisition_state);
                CREATE INDEX idx_document_representations_hash
                    ON document_representations(content_sha256);
                """
            )
            self.conn.execute(
                """
                UPDATE schema_meta
                SET value = '2'
                WHERE key = 'schema_version'
                """
            )
            self.conn.execute("PRAGMA user_version = 2")

    def _migrate_v2_to_v3(self) -> None:
        with self.transaction():
            self.conn.executescript(
                """
                ALTER TABLE claim_evidence
                    ADD COLUMN representation_id TEXT
                    REFERENCES document_representations(representation_id);

                CREATE INDEX idx_evidence_representation
                    ON claim_evidence(representation_id);
                """
            )
            self.conn.execute(
                """
                UPDATE schema_meta
                SET value = '3'
                WHERE key = 'schema_version'
                """
            )
            self.conn.execute("PRAGMA user_version = 3")

    def _audit(
        self,
        event_type: str,
        *,
        object_type: str | None = None,
        object_id: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO audit_log(
                event_type, object_type, object_id, payload_json, created_at_utc
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (event_type, object_type, object_id, _canonical_json(payload), _utc_now()),
        )

    def register_source(
        self,
        *,
        source_type: str,
        title: str,
        custodian: str | None = None,
        repository: str | None = None,
        locator: str | None = None,
        url: str | None = None,
        metadata: dict[str, Any] | None = None,
        source_id: str | None = None,
    ) -> str:
        source_id = source_id or _new_id("src")
        with self.transaction():
            self.conn.execute(
                """
                INSERT INTO sources(
                    source_id, source_type, title, custodian, repository,
                    locator, url, metadata_json, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source_id, source_type, title, custodian, repository,
                    locator, url, _canonical_json(metadata), _utc_now(),
                ),
            )
            self._audit("source_registered", object_type="source", object_id=source_id)
        return source_id

    def register_document(
        self,
        *,
        title: str,
        source_id: str | None = None,
        document_date: str | None = None,
        event_date_start: str | None = None,
        event_date_end: str | None = None,
        content: bytes | None = None,
        content_sha256: str | None = None,
        byte_length: int | None = None,
        content_locator: str | None = None,
        metadata: dict[str, Any] | None = None,
        document_id: str | None = None,
    ) -> str:
        document_id = document_id or _new_id("doc")
        if content is not None:
            derived_hash = _sha256_bytes(content)
            if content_sha256 is not None and content_sha256 != derived_hash:
                raise ValueError("content_sha256 does not match supplied content")
            content_sha256 = derived_hash
            byte_length = len(content)
        if content_sha256 is not None and len(content_sha256) != 64:
            raise ValueError("content_sha256 must be a 64-character SHA-256 hex digest")
        with self.transaction():
            self.conn.execute(
                """
                INSERT INTO documents(
                    document_id, source_id, title, document_date,
                    event_date_start, event_date_end, content_sha256,
                    byte_length, content_locator, metadata_json, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    document_id, source_id, title, document_date,
                    event_date_start, event_date_end, content_sha256,
                    byte_length, content_locator, _canonical_json(metadata), _utc_now(),
                ),
            )
            self._audit(
                "document_registered",
                object_type="document",
                object_id=document_id,
                payload={
                    "content_sha256": content_sha256,
                    "document_date": document_date,
                    "event_date_start": event_date_start,
                    "event_date_end": event_date_end,
                },
            )
        return document_id

    def register_document_representation(
        self,
        *,
        document_id: str,
        representation_type: str,
        acquisition_state: str,
        locator: str,
        mime_type: str | None = None,
        content_sha256: str | None = None,
        byte_length: int | None = None,
        source_url: str | None = None,
        raw_artifact: bool = False,
        preferred_for_review: bool = False,
        metadata: dict[str, Any] | None = None,
        representation_id: str | None = None,
    ) -> str:
        allowed_states = {
            "RAW_CAPTURED",
            "TEXT_SURROGATE",
            "REMOTE_BLOCKED",
            "LOCATOR_ONLY",
            "QUARANTINED",
        }
        if acquisition_state not in allowed_states:
            raise ValueError(
                f"Unsupported acquisition_state: {acquisition_state!r}"
            )
        if not locator.strip():
            raise ValueError("Representation locator is required")
        if content_sha256 is not None and len(content_sha256) != 64:
            raise ValueError(
                "content_sha256 must be a 64-character SHA-256 hex digest"
            )
        if byte_length is not None and byte_length < 0:
            raise ValueError("byte_length cannot be negative")
        if acquisition_state == "RAW_CAPTURED":
            if not raw_artifact:
                raise ValueError("RAW_CAPTURED requires raw_artifact=True")
            if content_sha256 is None or byte_length is None:
                raise ValueError(
                    "RAW_CAPTURED requires content_sha256 and byte_length"
                )
        elif raw_artifact:
            raise ValueError(
                "Only RAW_CAPTURED may assert raw_artifact=True"
            )

        representation_id = representation_id or _new_id("repr")
        with self.transaction():
            document = self.conn.execute(
                "SELECT document_id FROM documents WHERE document_id = ?",
                (document_id,),
            ).fetchone()
            if document is None:
                raise KeyError(f"Unknown document_id: {document_id}")
            self.conn.execute(
                """
                INSERT INTO document_representations(
                    representation_id, document_id, representation_type,
                    acquisition_state, mime_type, content_sha256, byte_length,
                    locator, source_url, raw_artifact, preferred_for_review,
                    metadata_json, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    representation_id,
                    document_id,
                    representation_type,
                    acquisition_state,
                    mime_type,
                    content_sha256,
                    byte_length,
                    locator,
                    source_url,
                    1 if raw_artifact else 0,
                    1 if preferred_for_review else 0,
                    _canonical_json(metadata),
                    _utc_now(),
                ),
            )
            self._audit(
                "document_representation_registered",
                object_type="document_representation",
                object_id=representation_id,
                payload={
                    "document_id": document_id,
                    "representation_type": representation_type,
                    "acquisition_state": acquisition_state,
                    "content_sha256": content_sha256,
                    "raw_artifact": bool(raw_artifact),
                },
            )
        return representation_id

    def record_ingest_run(
        self,
        *,
        input_bytes: bytes,
        output_bytes: bytes | None,
        mode: str,
        status: str,
        engine_version: str | None = None,
        prompt_version: str | None = None,
        metadata: dict[str, Any] | None = None,
        run_id: str | None = None,
    ) -> str:
        run_id = run_id or _new_id("run")
        with self.transaction():
            self.conn.execute(
                """
                INSERT INTO ingest_runs(
                    run_id, engine_version, prompt_version, input_sha256,
                    output_sha256, mode, status, metadata_json, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id, engine_version, prompt_version, _sha256_bytes(input_bytes),
                    None if output_bytes is None else _sha256_bytes(output_bytes),
                    mode, status, _canonical_json(metadata), _utc_now(),
                ),
            )
            self._audit(
                "ingest_run_recorded",
                object_type="ingest_run",
                object_id=run_id,
                payload={
                    "engine_version": engine_version,
                    "prompt_version": prompt_version,
                    "mode": mode,
                    "status": status,
                },
            )
        return run_id

    def create_entity(
        self,
        *,
        entity_type: str,
        canonical_name: str,
        authority_status: str = "PROVISIONAL",
        metadata: dict[str, Any] | None = None,
        entity_id: str | None = None,
    ) -> str:
        entity_id = entity_id or _new_id("ent")
        with self.transaction():
            self.conn.execute(
                """
                INSERT INTO entities(
                    entity_id, entity_type, canonical_name, authority_status,
                    metadata_json, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    entity_id, entity_type, canonical_name, authority_status,
                    _canonical_json(metadata), _utc_now(),
                ),
            )
            self._audit("entity_created", object_type="entity", object_id=entity_id)
        return entity_id

    def add_alias(
        self,
        entity_id: str,
        alias: str,
        *,
        language: str | None = None,
        valid_from: str | None = None,
        valid_to: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        alias_id = _new_id("alias")
        with self.transaction():
            self.conn.execute(
                """
                INSERT INTO entity_aliases(
                    alias_id, entity_id, alias, language, valid_from, valid_to,
                    metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alias_id, entity_id, alias, language, valid_from, valid_to,
                    _canonical_json(metadata),
                ),
            )
            self._audit(
                "entity_alias_added",
                object_type="entity",
                object_id=entity_id,
                payload={"alias": alias, "language": language},
            )
        return alias_id

    def propose_claim(
        self,
        *,
        predicate: str,
        claim_text: str,
        created_by: str,
        document_id: str | None = None,
        run_id: str | None = None,
        subject_entity_id: str | None = None,
        object_entity_id: str | None = None,
        object_value: str | None = None,
        metadata: dict[str, Any] | None = None,
        claim_id: str | None = None,
    ) -> str:
        claim_id = claim_id or _new_id("clm")
        with self.transaction():
            self.conn.execute(
                """
                INSERT INTO claims(
                    claim_id, document_id, run_id, subject_entity_id, predicate,
                    object_entity_id, object_value, claim_text, status,
                    created_by, metadata_json, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PROPOSED', ?, ?, ?)
                """,
                (
                    claim_id, document_id, run_id, subject_entity_id, predicate,
                    object_entity_id, object_value, claim_text, created_by,
                    _canonical_json(metadata), _utc_now(),
                ),
            )
            self._audit(
                "claim_proposed",
                object_type="claim",
                object_id=claim_id,
                payload={"created_by": created_by, "predicate": predicate},
            )
        return claim_id

    def add_evidence(
        self,
        *,
        claim_id: str,
        document_id: str,
        role: str,
        representation_id: str | None = None,
        locator: str | None = None,
        excerpt: bytes | None = None,
        excerpt_sha256: str | None = None,
        metadata: dict[str, Any] | None = None,
        evidence_id: str | None = None,
    ) -> str:
        if role not in EVIDENCE_ROLES:
            raise ValueError(f"Unsupported evidence role: {role!r}")
        if representation_id is not None:
            representation = self.conn.execute(
                """
                SELECT document_id FROM document_representations
                WHERE representation_id = ?
                """,
                (representation_id,),
            ).fetchone()
            if representation is None:
                raise KeyError(
                    f"Unknown representation_id: {representation_id}"
                )
            if representation["document_id"] != document_id:
                raise ValueError(
                    "Evidence representation does not belong to document_id"
                )
        if excerpt is not None:
            derived_hash = _sha256_bytes(excerpt)
            if excerpt_sha256 is not None and excerpt_sha256 != derived_hash:
                raise ValueError("excerpt_sha256 does not match supplied excerpt")
            excerpt_sha256 = derived_hash
        evidence_id = evidence_id or _new_id("evd")
        with self.transaction():
            self.conn.execute(
                """
                INSERT INTO claim_evidence(
                    evidence_id, claim_id, document_id, representation_id,
                    locator, excerpt_sha256, role, metadata_json, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence_id, claim_id, document_id, representation_id,
                    locator, excerpt_sha256, role, _canonical_json(metadata),
                    _utc_now(),
                ),
            )
            self._audit(
                "claim_evidence_added",
                object_type="claim",
                object_id=claim_id,
                payload={
                    "evidence_id": evidence_id,
                    "document_id": document_id,
                    "representation_id": representation_id,
                    "role": role,
                },
            )
        return evidence_id

    def open_discrepancy(
        self,
        *,
        topic_key: str,
        description: str,
        metadata: dict[str, Any] | None = None,
        discrepancy_id: str | None = None,
    ) -> str:
        discrepancy_id = discrepancy_id or _new_id("disc")
        with self.transaction():
            self.conn.execute(
                """
                INSERT INTO discrepancies(
                    discrepancy_id, topic_key, description, status,
                    metadata_json, opened_at_utc
                ) VALUES (?, ?, ?, 'OPEN', ?, ?)
                """,
                (
                    discrepancy_id, topic_key, description,
                    _canonical_json(metadata), _utc_now(),
                ),
            )
            self._audit(
                "discrepancy_opened",
                object_type="discrepancy",
                object_id=discrepancy_id,
                payload={"topic_key": topic_key},
            )
        return discrepancy_id

    def attach_discrepancy_claim(
        self,
        *,
        discrepancy_id: str,
        claim_id: str,
        stance: str,
    ) -> None:
        with self.transaction():
            self.conn.execute(
                """
                INSERT INTO discrepancy_claims(discrepancy_id, claim_id, stance)
                VALUES (?, ?, ?)
                """,
                (discrepancy_id, claim_id, stance),
            )
            self._audit(
                "discrepancy_claim_attached",
                object_type="discrepancy",
                object_id=discrepancy_id,
                payload={"claim_id": claim_id, "stance": stance},
            )

    def claim_promotion_blockers(self, claim_id: str) -> list[dict[str, Any]]:
        """Return objective blockers that prevent CANONICAL promotion."""
        row = self.conn.execute(
            """
            SELECT document_id, metadata_json
            FROM claims WHERE claim_id = ?
            """,
            (claim_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"Unknown claim_id: {claim_id}")

        metadata = json.loads(row["metadata_json"] or "{}")
        blockers: list[dict[str, Any]] = []

        if metadata.get("promotion_blocked_until_raw_capture"):
            document_id = row["document_id"]
            required_types = metadata.get(
                "promotion_required_representation_types"
            )
            if required_types is not None:
                if (
                    not isinstance(required_types, list)
                    or not required_types
                    or not all(
                        isinstance(value, str) and value.strip()
                        for value in required_types
                    )
                ):
                    blockers.append(
                        {
                            "code": "INVALID_REQUIRED_REPRESENTATION_TYPES",
                            "message": (
                                "Claim raw-capture gate has an invalid "
                                "promotion_required_representation_types value."
                            ),
                        }
                    )
                    required_types = []
            if not document_id:
                blockers.append(
                    {
                        "code": "RAW_CAPTURE_REQUIRED_NO_DOCUMENT",
                        "message": (
                            "Claim requires raw capture before promotion but "
                            "has no primary document binding."
                        ),
                    }
                )
            elif not any(
                blocker["code"] == "INVALID_REQUIRED_REPRESENTATION_TYPES"
                for blocker in blockers
            ):
                params: list[Any] = [document_id]
                type_clause = ""
                if required_types:
                    placeholders = ", ".join("?" for _ in required_types)
                    type_clause = (
                        f" AND representation_type IN ({placeholders})"
                    )
                    params.extend(required_types)
                raw = self.conn.execute(
                    f"""
                    SELECT representation_id, representation_type,
                           content_sha256, byte_length, locator
                    FROM document_representations
                    WHERE document_id = ?
                      AND acquisition_state = 'RAW_CAPTURED'
                      AND raw_artifact = 1
                      AND content_sha256 IS NOT NULL
                      AND byte_length IS NOT NULL
                      {type_clause}
                    ORDER BY preferred_for_review DESC, created_at_utc, representation_id
                    LIMIT 1
                    """,
                    params,
                ).fetchone()
                if raw is None:
                    states = [
                        dict(r)
                        for r in self.conn.execute(
                            """
                            SELECT representation_type, acquisition_state,
                                   raw_artifact, content_sha256, byte_length,
                                   locator
                            FROM document_representations
                            WHERE document_id = ?
                            ORDER BY created_at_utc, representation_id
                            """,
                            (document_id,),
                        ).fetchall()
                    ]
                    blockers.append(
                        {
                            "code": "RAW_CAPTURE_REQUIRED",
                            "message": (
                                "Claim is explicitly blocked from canonical "
                                "promotion until a verified RAW_CAPTURED "
                                "representation exists."
                            ),
                            "document_id": document_id,
                            "required_representation_types": required_types,
                            "representations": states,
                        }
                    )

        return blockers

    def review_claim(
        self,
        claim_id: str,
        *,
        decision: str,
        reviewer: str,
        rationale: str,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        if decision not in {"VALIDATE", "PROMOTE_CANONICAL", "REJECT", "QUARANTINE"}:
            raise ValueError(f"Unsupported review decision: {decision!r}")
        if not reviewer.strip():
            raise ValueError("Human reviewer identity is required")
        if not rationale.strip():
            raise ValueError("Review rationale is required")

        if decision == "PROMOTE_CANONICAL":
            blockers = self.claim_promotion_blockers(claim_id)
            if blockers:
                with self.transaction():
                    self._audit(
                        "claim_promotion_blocked",
                        object_type="claim",
                        object_id=claim_id,
                        payload={
                            "reviewer": reviewer,
                            "blockers": blockers,
                        },
                    )
                raise ValueError(
                    "Claim cannot be promoted to CANONICAL: "
                    + "; ".join(blocker["code"] for blocker in blockers)
                )

        status_for_decision = {
            "VALIDATE": "VALIDATED",
            "PROMOTE_CANONICAL": "CANONICAL",
            "REJECT": "REJECTED",
            "QUARANTINE": "QUARANTINED",
        }
        review_id = _new_id("rev")
        with self.transaction():
            row = self.conn.execute(
                "SELECT status FROM claims WHERE claim_id = ?", (claim_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"Unknown claim_id: {claim_id}")
            new_status = status_for_decision[decision]
            promoted_at = _utc_now() if new_status == "CANONICAL" else None
            self.conn.execute(
                """
                INSERT INTO reviews(
                    review_id, object_type, object_id, decision, reviewer,
                    rationale, metadata_json, created_at_utc
                ) VALUES (?, 'claim', ?, ?, ?, ?, ?, ?)
                """,
                (
                    review_id, claim_id, decision, reviewer, rationale,
                    _canonical_json(metadata), _utc_now(),
                ),
            )
            self.conn.execute(
                """
                UPDATE claims
                SET status = ?,
                    promoted_at_utc = CASE
                        WHEN ? = 'CANONICAL' THEN ?
                        ELSE promoted_at_utc
                    END
                WHERE claim_id = ?
                """,
                (new_status, new_status, promoted_at, claim_id),
            )
            self._audit(
                "claim_reviewed",
                object_type="claim",
                object_id=claim_id,
                payload={
                    "decision": decision,
                    "reviewer": reviewer,
                    "new_status": new_status,
                },
            )
        return review_id

    def resolve_discrepancy(
        self,
        discrepancy_id: str,
        *,
        reviewer: str,
        resolution: str,
        close_without_resolution: bool = False,
    ) -> str:
        if not reviewer.strip():
            raise ValueError("Human reviewer identity is required")
        if not resolution.strip():
            raise ValueError("Resolution rationale is required")
        status = "CLOSED_NO_RESOLUTION" if close_without_resolution else "RESOLVED"
        review_id = _new_id("rev")
        with self.transaction():
            row = self.conn.execute(
                "SELECT discrepancy_id FROM discrepancies WHERE discrepancy_id = ?",
                (discrepancy_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"Unknown discrepancy_id: {discrepancy_id}")
            self.conn.execute(
                """
                UPDATE discrepancies
                SET status = ?, resolution = ?, resolved_at_utc = ?
                WHERE discrepancy_id = ?
                """,
                (status, resolution, _utc_now(), discrepancy_id),
            )
            self.conn.execute(
                """
                INSERT INTO reviews(
                    review_id, object_type, object_id, decision, reviewer,
                    rationale, metadata_json, created_at_utc
                ) VALUES (?, 'discrepancy', ?, ?, ?, ?, '{}', ?)
                """,
                (
                    review_id, discrepancy_id, status, reviewer,
                    resolution, _utc_now(),
                ),
            )
            self._audit(
                "discrepancy_resolved",
                object_type="discrepancy",
                object_id=discrepancy_id,
                payload={"status": status, "reviewer": reviewer},
            )
        return review_id

    def claim_bundle(self, claim_id: str) -> dict[str, Any]:
        claim = self.conn.execute(
            "SELECT * FROM claims WHERE claim_id = ?", (claim_id,)
        ).fetchone()
        if claim is None:
            raise KeyError(f"Unknown claim_id: {claim_id}")
        evidence_rows = self.conn.execute(
            """
            SELECT
                e.*,
                d.title AS document_title,
                d.document_date,
                d.event_date_start,
                d.event_date_end,
                d.content_sha256,
                r.representation_type,
                r.acquisition_state AS representation_acquisition_state,
                r.content_sha256 AS representation_content_sha256,
                r.byte_length AS representation_byte_length,
                r.locator AS representation_locator,
                r.raw_artifact AS representation_raw_artifact,
                s.title AS source_title,
                s.custodian,
                s.repository,
                s.locator AS source_locator
            FROM claim_evidence e
            JOIN documents d ON d.document_id = e.document_id
            LEFT JOIN document_representations r
                ON r.representation_id = e.representation_id
            LEFT JOIN sources s ON s.source_id = d.source_id
            WHERE e.claim_id = ?
            ORDER BY e.created_at_utc, e.evidence_id
            """,
            (claim_id,),
        ).fetchall()
        reviews = self.conn.execute(
            """
            SELECT * FROM reviews
            WHERE object_type = 'claim' AND object_id = ?
            ORDER BY created_at_utc, review_id
            """,
            (claim_id,),
        ).fetchall()
        return {
            "claim": dict(claim),
            "evidence": [dict(row) for row in evidence_rows],
            "reviews": [dict(row) for row in reviews],
        }

    def health(self) -> dict[str, Any]:
        tables = (
            "sources", "documents", "document_representations", "ingest_runs",
            "entities", "claims", "claim_evidence", "relations", "events",
            "discrepancies", "reviews", "audit_log",
        )
        counts = {
            table: int(self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in tables
        }
        integrity = self.conn.execute("PRAGMA integrity_check").fetchone()[0]
        return {
            "schema_version": SCHEMA_VERSION,
            "integrity_check": integrity,
            "counts": counts,
        }
