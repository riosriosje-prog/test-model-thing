import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone

from galia2.secured_claims import (
    AuthorityReference,
    CanonicalEvent,
    DuplicateEventConflict,
    EventAuthorityState,
    UnresolvedLegalState,
    make_snapshot,
)
from galia2.secured_claim_store import SCHEMA_VERSION, SecuredClaimStore

UTC = timezone.utc
T1 = datetime(2026, 1, 1, tzinfo=UTC)
T2 = datetime(2026, 2, 1, tzinfo=UTC)
AUTH = AuthorityReference(
    authority_id="auth-506",
    authority_type="STATUTE",
    citation="11 U.S.C. § 506",
    jurisdiction="US",
)

def event(event_id="e1", event_type="ALLOWANCE", *, supersedes=None,
          state=EventAuthorityState.OPERATIVE, payload=()):
    return CanonicalEvent(
        event_id=event_id,
        event_type=event_type,
        event_effective_at=T1,
        event_recorded_at=T2,
        authority=AUTH,
        payload=tuple(payload),
        supersedes_event_id=supersedes,
        authority_state=state,
    )

class SecuredClaimStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "secured.sqlite3")
        self.store = SecuredClaimStore(self.path)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_01_creates_schema_v1(self):
        self.assertEqual(self.store.health()["schema_version"], SCHEMA_VERSION)

    def test_02_enables_foreign_keys(self):
        self.assertEqual(self.store.health()["foreign_keys"], 1)

    def test_03_uses_wal(self):
        self.assertEqual(self.store.health()["journal_mode"], "wal")

    def test_04_append_and_roundtrip_event(self):
        e = event()
        self.store.append_event(e)
        self.assertEqual(self.store.get_event("e1"), e)

    def test_05_append_is_idempotent(self):
        e = event()
        self.store.append_event(e)
        self.store.append_event(e)
        self.assertEqual(self.store.health()["event_count"], 1)

    def test_06_conflicting_same_id_rejected(self):
        self.store.append_event(event())
        with self.assertRaises(DuplicateEventConflict):
            self.store.append_event(event(event_type="VALUATION"))

    def test_07_supersession_requires_existing_event(self):
        with self.assertRaises(UnresolvedLegalState):
            self.store.append_event(event("e2", supersedes="missing"))

    def test_08_supersession_roundtrip(self):
        self.store.append_event(event("e1"))
        self.store.append_event(event("e2", "RECONSIDERATION", supersedes="e1"))
        self.assertEqual(self.store.get_event("e2").supersedes_event_id, "e1")

    def test_09_old_event_remains_after_supersession(self):
        self.store.append_event(event("e1"))
        self.store.append_event(event("e2", "RECONSIDERATION", supersedes="e1"))
        self.assertEqual(self.store.get_event("e1").event_type, "ALLOWANCE")

    def test_10_authority_state_roundtrip(self):
        self.store.append_event(
            event("e1", "SALE", state=EventAuthorityState.APPEAL_PENDING)
        )
        self.assertEqual(
            self.store.get_event("e1").authority_state,
            EventAuthorityState.APPEAL_PENDING,
        )

    def test_11_payload_roundtrip(self):
        self.store.append_event(event(payload=(("amount", "100"), ("status", "ALLOWED"))))
        self.assertEqual(
            self.store.get_event("e1").payload,
            (("amount", "100"), ("status", "ALLOWED")),
        )

    def test_12_direct_event_update_blocked(self):
        self.store.append_event(event())
        with self.assertRaises(sqlite3.DatabaseError):
            with self.store.transaction():
                self.store.conn.execute(
                    "UPDATE canonical_events SET event_type='X' WHERE event_id='e1'"
                )

    def test_13_direct_event_delete_blocked(self):
        self.store.append_event(event())
        with self.assertRaises(sqlite3.DatabaseError):
            with self.store.transaction():
                self.store.conn.execute(
                    "DELETE FROM canonical_events WHERE event_id='e1'"
                )

    def test_14_transaction_rolls_back(self):
        with self.assertRaises(RuntimeError):
            with self.store.transaction():
                self.store.conn.execute(
                    """
                    INSERT INTO canonical_events(
                        event_id,event_type,event_effective_at,event_recorded_at,
                        authority_id,authority_type,authority_citation,
                        payload_json,authority_state,event_sha256
                    ) VALUES(?,?,?,?,?,?,?,?,?,?)
                    """,
                    ("tmp","X",T1.isoformat(),T2.isoformat(),"a","STATUTE","x","[]",
                     "OPERATIVE","0"*64),
                )
                raise RuntimeError("rollback")
        self.assertEqual(self.store.health()["event_count"], 0)

    def test_15_list_events_orders_by_effective_time_then_insert_order(self):
        later = CanonicalEvent("e2","VALUATION",T2,T2,AUTH)
        earlier = CanonicalEvent("e1","ALLOWANCE",T1,T2,AUTH)
        self.store.append_event(later)
        self.store.append_event(earlier)
        self.assertEqual([e.event_id for e in self.store.list_events()], ["e1","e2"])

    def test_16_snapshot_requires_persisted_sources(self):
        e = event()
        snap = make_snapshot(
            snapshot_type="CLAIM_STATE",
            as_of=T2,
            purpose="§506(b)",
            source_events=(e,),
            calculation_version="c2",
            values={"secured":"100"},
        )
        with self.assertRaises(UnresolvedLegalState):
            self.store.append_snapshot(snap)

    def test_17_snapshot_roundtrip_with_lineage(self):
        e = event()
        self.store.append_event(e)
        snap = make_snapshot(
            snapshot_type="CLAIM_STATE",
            as_of=T2,
            purpose="§506(b)",
            source_events=(e,),
            calculation_version="c2",
            values={"secured":"100","unsecured":"20"},
        )
        sid = self.store.append_snapshot(snap)
        loaded = self.store.get_snapshot(sid)
        self.assertEqual(loaded, snap)

    def test_18_snapshot_count_health(self):
        e = event()
        self.store.append_event(e)
        snap = make_snapshot(
            snapshot_type="CLAIM_STATE",
            as_of=T2,
            purpose="PLAN",
            source_events=(e,),
            calculation_version="c2",
            values={"plan_secured":"100"},
        )
        self.store.append_snapshot(snap)
        self.assertEqual(self.store.health()["snapshot_count"], 1)

    def test_19_snapshot_update_blocked(self):
        e = event()
        self.store.append_event(e)
        sid = self.store.append_snapshot(
            make_snapshot(
                snapshot_type="CLAIM_STATE",
                as_of=T2,
                purpose="PLAN",
                source_events=(e,),
                calculation_version="c2",
                values={"plan_secured":"100"},
            )
        )
        with self.assertRaises(sqlite3.DatabaseError):
            with self.store.transaction():
                self.store.conn.execute(
                    "UPDATE derived_snapshots SET purpose='X' WHERE snapshot_id=?",
                    (sid,),
                )

    def test_20_rejects_newer_schema(self):
        path = os.path.join(self.tmp.name, "future.sqlite3")
        conn = sqlite3.connect(path)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
        conn.close()
        with self.assertRaises(RuntimeError):
            SecuredClaimStore(path)

    def test_21_reopen_preserves_events(self):
        self.store.append_event(event())
        self.store.close()
        self.store = SecuredClaimStore(self.path)
        self.assertEqual(self.store.get_event("e1").event_id, "e1")

    def test_22_database_is_separate_from_historical_store_surface(self):
        tables = {
            row["name"]
            for row in self.store.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        self.assertIn("canonical_events", tables)
        self.assertNotIn("claims", tables)
        self.assertNotIn("documents", tables)

if __name__ == "__main__":
    unittest.main()
