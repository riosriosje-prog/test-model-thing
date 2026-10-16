"""Independent Python SHA-256 fixture oracle for Rust scratch audit.
A caller-supplied checkpoint is not a validated witness or human approval.
"""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[3]
BINARY=ROOT/"rust"/"galia-core"/"target"/"debug"/"galia-audit-shadow"
FORMAT="GALIA_NONCANONICAL_SCRATCH_AUDIT_V1"

def sha(data):
    return hashlib.sha256(data).hexdigest()

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")

def event(records,operation,commit,manifest_hash,head_before,head_after):
    record={
        "format":FORMAT,"index":len(records)+1,
        "previous_receipt_hash":sha(canonical(records[-1])) if records else None,
        "operation":operation,"commit_id":commit,
        "manifest_hash":manifest_hash,
        "head_before":head_before,"head_after":head_after,
    }
    records.append(record)

def history():
    rows=[]
    event(rows,"STAGED","g1","a"*64,None,None)
    event(rows,"PUBLISHED","g1","a"*64,None,"1"*64)
    event(rows,"STAGED","g2","b"*64,"1"*64,"1"*64)
    event(rows,"PUBLISHED","g2","b"*64,"1"*64,"2"*64)
    return rows

def run(receipts,checkpoint=None):
    payload={"receipts":receipts}
    if checkpoint is not None:
        payload["checkpoint"]=checkpoint
    p=subprocess.run([str(BINARY)],input=json.dumps(payload),text=True,
                     stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8)
    return p.returncode,json.loads(p.stdout)

class AuditParity(unittest.TestCase):
    def test_python_canonical_sha256_matches_rust_tip(self):
        self.assertTrue(BINARY.is_file(),"Build galia-audit-shadow first")
        rows=history()
        rc,report=run(rows)
        self.assertEqual(rc,0,report)
        self.assertEqual(report["tip_sha256"],sha(canonical(rows[-1])))
        self.assertEqual(report["head_sha256"],"2"*64)
        self.assertEqual(report["count"],4)
        self.assertEqual(report["status"],"ADVISORY_ONLY")
        self.assertFalse(report["canonical_writeback"])
        self.assertFalse(report["authority_transfer"])
        self.assertEqual(report["staged_unpublished"],[])

    def test_pinned_checkpoint_refuses_truncation(self):
        rows=history()
        cp={"count":4,"tip_sha256":sha(canonical(rows[-1])),"last_head_sha256":"2"*64}
        self.assertEqual(run(rows,cp)[0],0)
        rc,report=run(rows[:-1],cp)
        self.assertEqual(rc,2,report)
        self.assertEqual(report["status"],"REJECTED")
        # Truncation may pass in absence of an independently retained anchor.
        self.assertEqual(run(rows[:-1])[0],0)

    def test_negative_replay_tamper_fork_sequence(self):
        base=history()
        changes={
            "replay":lambda r:r.append(copy.deepcopy(r[-1])),
            "tamper":lambda r:r[1].update(manifest_hash="b"*64),
            "reorder":lambda r:r.reverse(),
            "fork":lambda r:r[2].update(previous_receipt_hash="0"*64),
            "wrong_head":lambda r:r[2].update(head_before="0"*64),
            "unknown_field":lambda r:r[0].update(authority_granted=True),
            "duplicate_stage":lambda r:r[2].update(commit_id="g1"),
            "noncanonical_hash":lambda r:r[0].update(manifest_hash="A"*64),
        }
        for name,mutation in changes.items():
            with self.subTest(name=name):
                rows=copy.deepcopy(base)
                mutation(rows)
                rc,report=run(rows)
                self.assertEqual(rc,2,report)
                self.assertEqual(report["status"],"REJECTED")
                self.assertFalse(report["canonical_writeback"])
                self.assertFalse(report["authority_transfer"])

if __name__=="__main__":
    unittest.main()
