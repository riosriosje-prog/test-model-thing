use std::collections::BTreeMap;
use galia_core_shadow::persistence::{GenerationBytes, VerificationRequest, verify_request};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn h(bytes: &[u8]) -> String { format!("{:x}",Sha256::digest(bytes)) }
fn raw(v: &Value) -> Vec<u8> { serde_json::to_vec(v).unwrap() }
fn wire(manifest: Value, promotion: Value, payloads: BTreeMap<String, Vec<u8>>) -> GenerationBytes {
    let m = raw(&manifest);
    let mut p = promotion;
    p["manifest_hash"] = json!(h(&m));
    let pb = raw(&p);
    let mut head = raw(&json!({
        "commit_id": manifest["commit_id"],
        "seq": manifest["seq"],
        "manifest_hash": h(&m),
        "promotion_hash": h(&pb),
    }));
    head.push(b'\n');
    GenerationBytes {
        manifest_hex: hex::encode(m),
        promotion_hex: hex::encode(pb),
        head_hex: hex::encode(head),
        payloads_hex: payloads.into_iter().map(|(k,v)| (k,hex::encode(v))).collect(),
    }
}
fn bundle(commit: &str, parent: &str, seq: u64) -> GenerationBytes {
    let bytes=b"historic source bytes\n".to_vec();
    let path = "evidence/raw.txt";
    let entries = json!([{"byte_size":bytes.len(),"path":path,"sha256":h(&bytes)}]);
    let manifest=json!({
        "authority_decision_id":"decision-1",
        "case_id":"cangrejos",
        "commit_id":commit,
        "created_at":"2026-10-15T12:00:00+00:00",
        "parent_commit":parent,
        "payloads":entries,
        "persistence_policy_version":"p7",
        "schema_version":"galia2-core-v1",
        "seq":seq
    });
    let promotion=json!({
        "authority_decision_id":"decision-1",
        "authorization_id":"auth-id",
        "authorization_policy_version":"p5",
        "case_id":"cangrejos",
        "commit_id":commit,
        "manifest_hash":"0".repeat(64),
        "persistence_policy_version":"p7",
        "preflight_receipt_id":"r1",
        "published_at":"2026-10-15T12:00:00+00:00",
    });
    wire(manifest,promotion,BTreeMap::from([(path.into(),bytes)]))
}
fn verified() -> VerificationRequest {
    VerificationRequest { generation:bundle("candidate-17","canonical-16",17),
        parent:Some(bundle("canonical-16","canonical-15",16)) }
}
#[test]
fn exact_candidate_and_parent_are_advisory_only() {
    let r=verify_request(&verified()).unwrap();
    assert!(r.integrity_consistent && r.parent_chain_checked);
    assert_eq!(r.commit_id, "candidate-17");
    assert_eq!(r.seq,17);
    assert!(r.output_commit.is_none());
    assert!(!r.canonical_writeback && !r.authority_transfer);
    assert_eq!(r.status,"ADVISORY_ONLY");
}
#[test]
fn orphan_snapshot_without_parent_is_never_claimed_as_chain_verified() {
    let mut q=verified();q.parent=None;
    let r=verify_request(&q).unwrap();
    assert!(r.integrity_consistent && !r.parent_chain_checked);
}
#[test]
fn tampering_one_byte_fails() {
    let mut q=verified();
    q.generation.payloads_hex.insert("evidence/raw.txt".into(),hex::encode(b"tampered"));
    assert!(verify_request(&q).is_err());
}
#[test]
fn undeclared_or_missing_payload_fails() {
    let mut q=verified();q.generation.payloads_hex.insert("extra".into(),hex::encode(b"x"));
    assert!(verify_request(&q).is_err());
    let mut q=verified();q.generation.payloads_hex.clear();
    assert!(verify_request(&q).is_err());
}
#[test]
fn parent_chain_mismatch_fails() {
    let mut q=verified();q.parent=Some(bundle("other-parent","canonical-15",16));
    assert!(verify_request(&q).is_err());
    let mut q=verified();q.parent=Some(bundle("canonical-16","canonical-15",13));
    assert!(verify_request(&q).is_err());
}
#[test]
fn damaged_parent_payload_fails_closed() {
    let mut q=verified();q.parent.as_mut().unwrap().payloads_hex.insert("evidence/raw.txt".into(),hex::encode(b"fake"));
    assert!(verify_request(&q).is_err());
}
#[test]
fn manifest_and_promotion_bytes_are_immutable() {
    let mut q=verified();
    let raw=hex::decode(&q.generation.manifest_hex).unwrap();
    let changed=raw.iter().copied().chain([b' ']).collect::<Vec<_>>();
    q.generation.manifest_hex=hex::encode(changed);
    assert!(verify_request(&q).is_err());
    let mut q=verified();
    q.generation.promotion_hex.push_str("20");
    assert!(verify_request(&q).is_err());
}
#[test]
fn hash_or_head_mismatch_fails() {
    let mut q=verified();
    let mut hd:Value=serde_json::from_slice(&hex::decode(&q.generation.head_hex).unwrap()).unwrap();
    hd["manifest_hash"]=json!("0".repeat(64));
    let mut raw=raw(&hd);raw.push(b'\n');
    q.generation.head_hex=hex::encode(raw);
    assert!(verify_request(&q).is_err());
}
#[test]
fn head_requires_exact_newline() {
    let mut q=verified();
    let raw=hex::decode(&q.generation.head_hex).unwrap();
    q.generation.head_hex=hex::encode(&raw[..raw.len()-1]);
    assert!(verify_request(&q).is_err());
}
#[test]
fn noncanonical_payload_path_cannot_pass_even_when_hashes_match() {
    let mut q=verified();let mut m:Value=serde_json::from_slice(&hex::decode(&q.generation.manifest_hex).unwrap()).unwrap();
    m["payloads"][0]["path"]=json!("../escape");
    let mut promotion:Value=serde_json::from_slice(&hex::decode(&q.generation.promotion_hex).unwrap()).unwrap();
    promotion["manifest_hash"]=json!("0".repeat(64));
    q.generation=wire(m,promotion,BTreeMap::from([("../escape".into(),b"historic source bytes\n".to_vec())]));
    assert!(verify_request(&q).is_err());
}
#[test]
fn extra_unknown_metadata_must_not_be_accepted() {
    let mut q=verified();
    let mut m:Value=serde_json::from_slice(&hex::decode(&q.generation.manifest_hex).unwrap()).unwrap();
    m["source_magic"]=json!(true);
    q.generation.manifest_hex=hex::encode(raw(&m));
    assert!(verify_request(&q).is_err());
}
