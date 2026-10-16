#![cfg(feature="tls-transport")]
//! GALIA v0.31: LOCAL scratch publication evidence with synthetic witness keys.
//! No organizational independence, publication infrastructure or P5 authority.
use ed25519_dalek::{Signer,SigningKey};
use galia_core_shadow::attestation::signing_preimage;
use galia_core_shadow::audit::sha256;
use galia_core_shadow::fenced_coordinator::{EpochGrant,FencingCheckpoint,FencingScope};
use galia_core_shadow::independent_audit::{
    AuditTrustPin,AuditStatement,SignedAuditStatement,AUDIT_FORMAT,AUDIT_DOMAIN,
};
use galia_core_shadow::fork_witness::{
    TrustedForkWitness,ForkWitnessPolicy,ForkWitnessPayload,
    SignedForkWitnessEndorsement,expected_endorsement_payload,
    verify_fork_witness_quorum,FORK_WITNESS_FORMAT,FORK_WITNESS_DOMAIN,
};
fn pubkey(seed:u8)->String{
    hex::encode(SigningKey::from_bytes(&[seed;32]).verifying_key().to_bytes())
}
fn canonical<T:serde::Serialize>(value:&T)->Vec<u8>{
    serde_json::to_value(value).and_then(|v|serde_json::to_vec(&v)).unwrap()
}
fn digest(s:&str)->String{sha256(s.as_bytes())}
fn pin()->AuditTrustPin{
    AuditTrustPin{
        auditor_id:"external-auditor-a".into(),
        auditor_public_key_hex:pubkey(101),
        stream_id:"signed-log-a".into(),
        scope:FencingScope{
            namespace:"tenant".into(),case_id:"cangrejos".into(),
            service_id:"test-service".into(),
            pinned_observer_policy_sha256:digest("pinned-observers"),
            pinned_response_signer_public_key_hex:pubkey(92),
        },
        floor_sequence:0,floor_signed_sha256:None,
        floor_checkpoint:FencingCheckpoint{
            record_count:0,journal_tip_sha256:None,
            active_grant:None,nonce_claim_count:0,
        },
    }
}
fn checkpoint(count:u64,tip:&str)->FencingCheckpoint{
    FencingCheckpoint{
        record_count:count,journal_tip_sha256:Some(digest(tip)),
        active_grant:Some(EpochGrant{host_id:"host-a".into(),epoch:1}),
        nonce_claim_count:count-1,
    }
}
fn sign_audit(p:&AuditTrustPin,seq:u64,prev:Option<String>,
    cp:FencingCheckpoint)->SignedAuditStatement{
    let statement=AuditStatement{
        format:AUDIT_FORMAT.into(),auditor_id:p.auditor_id.clone(),
        stream_id:p.stream_id.clone(),scope_sha256:sha256(&canonical(&p.scope)),
        sequence:seq,previous_signed_sha256:prev,checkpoint:cp,
    };
    let signing_key=SigningKey::from_bytes(&[101;32]);
    SignedAuditStatement{
        signature_hex:hex::encode(signing_key.sign(
            &signing_preimage(AUDIT_DOMAIN,&statement).unwrap()
        ).to_bytes()),
        statement,
    }
}
fn histories()->(AuditTrustPin,Vec<SignedAuditStatement>,Vec<SignedAuditStatement>){
    let p=pin();
    let root=sign_audit(&p,1,None,checkpoint(1,"common"));
    let prev=Some(sha256(&canonical(&root)));
    let left=sign_audit(&p,2,prev.clone(),checkpoint(2,"left"));
    let right=sign_audit(&p,2,prev,checkpoint(2,"right"));
    (p,vec![root.clone(),left],vec![root,right])
}
fn roster(p:&AuditTrustPin)->ForkWitnessPolicy{
    ForkWitnessPolicy{
        format:FORK_WITNESS_FORMAT.into(),roster_epoch:5,
        auditor_id:p.auditor_id.clone(),
        auditor_public_key_hex:p.auditor_public_key_hex.clone(),
        audit_stream_id:p.stream_id.clone(),
        audit_scope_sha256:sha256(&canonical(&p.scope)),
        required_distinct_observers:2,
        witnesses:vec![
            TrustedForkWitness{observer_id:"a".into(),public_key_hex:pubkey(111),revoked:false},
            TrustedForkWitness{observer_id:"b".into(),public_key_hex:pubkey(112),revoked:false},
            TrustedForkWitness{observer_id:"c".into(),public_key_hex:pubkey(113),revoked:false},
        ],
    }
}
fn sign_vote(payload:ForkWitnessPayload,seed:u8)->SignedForkWitnessEndorsement{
    let key=SigningKey::from_bytes(&[seed;32]);
    SignedForkWitnessEndorsement{
        signature_hex:hex::encode(key.sign(
            &signing_preimage(FORK_WITNESS_DOMAIN,&payload).unwrap()
        ).to_bytes()),
        payload,
    }
}
fn vote(p:&AuditTrustPin,w:&ForkWitnessPolicy,
    a:&[SignedAuditStatement],b:&[SignedAuditStatement],
    id:&str,seed:u8)->SignedForkWitnessEndorsement{
    let payload=expected_endorsement_payload(p,w,a,b,id).unwrap();
    sign_vote(payload,seed)
}
use galia_core_shadow::fork_publication::{ScratchForkPublication,PublishedForkBundle,PublicationCheckpoint};
use std::sync::{Arc,Barrier};
use std::thread;

fn bundle()->(AuditTrustPin,ForkWitnessPolicy,PublishedForkBundle){
    let (pin,left,right)=histories();let policy=roster(&pin);
    let witnesses=vec![
        vote(&pin,&policy,&left,&right,"a",111),
        vote(&pin,&policy,&left,&right,"b",112),
    ];
    (pin,policy,PublishedForkBundle{
        left_audit_branch:left,right_audit_branch:right,witnesses,
    })
}
fn new_store()->(tempfile::TempDir,ScratchForkPublication,PublishedForkBundle){
    let root=tempfile::tempdir().unwrap();
    let (pin,policy,packet)=bundle();
    let store=ScratchForkPublication::initialize_new(
        root.path().join("fork-custody"),pin,policy).unwrap();
    (root,store,packet)
}
#[test]fn verified_auditor_fork_and_quorum_is_custodied_as_full_bundle(){
    let (_dir,store,b)=new_store();
    let accepted=store.append(b).unwrap();
    assert_eq!(accepted.checkpoint.entry_count,1);
    assert!(accepted.signed_quorum_reverified&&accepted.auditor_fork_reverified);
    assert!(accepted.local_scratch_record_committed);
    assert!(!accepted.external_publication_verified);
    assert!(!accepted.real_witness_key_custody_verified);
    assert!(!accepted.human_authority_verified&&!accepted.canonical_writeback);
    assert!(!accepted.authority_transfer);
    assert_eq!(store.published().unwrap().len(),1);
}
#[test]fn restarted_store_revalidates_signatures_and_bundle_contents(){
    let (root,store,b)=new_store();
    let highwater=store.append(b).unwrap().checkpoint;
    let (pin,policy,_)=bundle();
    drop(store);
    let opened=ScratchForkPublication::open(
        root.path().join("fork-custody"),pin,policy).unwrap();
    assert_eq!(opened.checkpoint().unwrap(),highwater);
    assert_eq!(opened.published().unwrap().len(),1);
}
#[test]fn identical_fork_cannot_be_appended_twice(){
    let (_root,store,b)=new_store();
    store.append(b.clone()).unwrap();
    assert!(store.append(b).is_err());
    assert_eq!(store.checkpoint().unwrap().entry_count,1);
}
#[test]fn reverse_auditor_branch_order_is_same_fork_even_with_new_votes(){
    let (_root,store,b)=new_store();
    store.append(b).unwrap();
    let (p,mut a,mut b)=histories();
    std::mem::swap(&mut a,&mut b);
    let w=roster(&p);
    let reordered=PublishedForkBundle{
        witnesses:vec![
            vote(&p,&w,&a,&b,"a",111),
            vote(&p,&w,&a,&b,"b",112),
        ],left_audit_branch:a,right_audit_branch:b,
    };
    assert!(store.append(reordered).is_err());
    assert_eq!(store.checkpoint().unwrap().entry_count,1);
}
#[test]fn alternate_valid_observer_subquorum_cannot_republish_same_fork(){
    let (_root,store,b)=new_store();
    store.append(b).unwrap();
    let (p,a,b)=histories();let w=roster(&p);
    let alternate=PublishedForkBundle{
        left_audit_branch:a.clone(),right_audit_branch:b.clone(),
        witnesses:vec![
            vote(&p,&w,&a,&b,"a",111),
            vote(&p,&w,&a,&b,"c",113),
        ]
    };
    assert!(store.append(alternate).is_err());
}
#[test]fn distinct_signed_fork_appends_and_original_highwater_prefix_survives(){
    let (_root,store,b)=new_store();
    let one=store.append(b).unwrap().checkpoint;
    let (p,a,mut b)=histories();let w=roster(&p);
    b[1]=sign_audit(&p,2,Some(sha256(&canonical(&a[0]))),
        checkpoint(2,"different-right"));
    let next=PublishedForkBundle{
        witnesses:vec![
            vote(&p,&w,&a,&b,"a",111),
            vote(&p,&w,&a,&b,"b",112),
        ],left_audit_branch:a,right_audit_branch:b,
    };
    let two=store.append(next).unwrap().checkpoint;
    assert_eq!(two.entry_count,2);
    assert_eq!(store.verify_floor(&one).unwrap(),two);
    assert_eq!(store.published().unwrap().len(),2);
}
#[test]fn full_local_rollback_detected_only_if_external_highwater_survives(){
    let (dir,store,b)=new_store();
    let pinned=store.append(b).unwrap().checkpoint;
    std::fs::remove_file(dir.path()
        .join("fork-custody/entries/00000000000000000001.json")).unwrap();
    assert_eq!(store.checkpoint().unwrap().entry_count,0);
    assert!(store.verify_floor(&pinned).is_err());
    // Deliberate unanchored vulnerability: same evidence could be re-appended.
    let (_,_,packet)=bundle();
    assert!(store.append(packet).is_ok());
}
#[test]fn changed_trust_key_or_roster_epoch_rejected_on_reopen(){
    let (dir,store,b)=new_store();store.append(b).unwrap();
    let (mut p,w,_)=bundle();
    p.auditor_public_key_hex=pubkey(99);
    assert!(ScratchForkPublication::open(
        dir.path().join("fork-custody"),p,w.clone()).is_err());
    let (p,mut w,_)=bundle();w.roster_epoch+=1;
    assert!(ScratchForkPublication::open(
        dir.path().join("fork-custody"),p,w).is_err());
}
#[test]fn forged_auditor_signature_and_witness_signature_fail_before_any_append(){
    let (_dir,store,mut b)=new_store();
    b.left_audit_branch[1].signature_hex="00".repeat(64);
    assert!(store.append(b).is_err());
    let (_p,_w,mut b)=bundle();
    b.witnesses[0].signature_hex="ff".repeat(64);
    assert!(store.append(b).is_err());
    assert_eq!(store.checkpoint().unwrap().entry_count,0);
}
#[test]fn insufficient_quorum_and_identical_histories_not_publishable(){
    let (_dir,store,mut b)=new_store();
    b.witnesses.pop();
    assert!(store.append(b).is_err());
    let (_p,_w,mut b)=bundle();
    b.right_audit_branch=b.left_audit_branch.clone();
    assert!(store.append(b).is_err());
}
#[test]fn two_cooperative_file_handles_can_append_only_one_copy(){
    let (dir,store,b)=new_store();
    let (pin,w,_)=bundle();
    let second=ScratchForkPublication::open(
        dir.path().join("fork-custody"),pin,w).unwrap();
    let sync=Arc::new(Barrier::new(3));
    let jobs=[store,second].into_iter().map(|store|{
        let barrier=Arc::clone(&sync);let b=b.clone();
        thread::spawn(move||{barrier.wait();store.append(b).is_ok()})
    }).collect::<Vec<_>>();
    sync.wait();
    assert_eq!(jobs.into_iter().map(|j|j.join().unwrap()).filter(|x|*x).count(),1);
}
#[test]fn partial_corrupted_record_fails_closed_on_read_reopen_and_append(){
    let (dir,store,b)=new_store();store.append(b).unwrap();
    std::fs::write(dir.path()
        .join("fork-custody/entries/00000000000000000001.json"),b"{").unwrap();
    assert!(store.checkpoint().is_err());
    assert!(store.published().is_err());
    assert!(store.append(bundle().2).is_err());
    let (p,w,_)=bundle();
    assert!(ScratchForkPublication::open(dir.path().join("fork-custody"),p,w).is_err());
}
#[test]fn extra_unexpected_journal_files_fail_closed(){
    let (dir,store,_b)=new_store();
    std::fs::write(dir.path().join("fork-custody/entries/side-channel.json"),b"{}").unwrap();
    assert!(store.checkpoint().is_err());
}
#[cfg(unix)]
#[test]fn symlink_instead_of_immutable_entry_is_rejected(){
    use std::os::unix::fs::symlink;
    let (dir,store,_b)=new_store();
    symlink(dir.path().join("fork-custody/.GALIA_NONCANONICAL_FORK_PUBLICATION_V1"),
        dir.path().join("fork-custody/entries/00000000000000000001.json")).unwrap();
    assert!(store.checkpoint().is_err());
}
#[test]fn publication_must_initialize_a_new_and_noncanonical_directory(){
    let (dir,store,_b)=new_store();
    let (p,w,_)=bundle();
    assert!(ScratchForkPublication::initialize_new(
        dir.path().join("fork-custody"),p,w).is_err());
    assert_eq!(store.checkpoint().unwrap().entry_count,0);
}
#[test]fn highwater_with_changed_hash_or_future_count_fails_closed(){
    let (_dir,store,b)=new_store();
    let mut cp=store.append(b).unwrap().checkpoint;
    cp.last_entry_sha256=Some("f".repeat(64));
    assert!(store.verify_floor(&cp).is_err());
    cp.entry_count=2;
    assert!(store.verify_floor(&cp).is_err());
}
#[test]fn strict_bundle_deserialization_rejects_injected_canonical_authority(){
    let b=bundle().2;
    let mut data=serde_json::to_value(b).unwrap();
    data["canonical_writeback"]=serde_json::json!(true);
    assert!(serde_json::from_value::<PublishedForkBundle>(data).is_err());
}
