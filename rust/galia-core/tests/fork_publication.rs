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


// v0.32 offline synthetically signed custody receipts. No real third-party.
mod custody_receipt_tests{
    use super::*;
    use galia_core_shadow::custody_attestation::*;

    fn trust(a:&AuditTrustPin,w:&ForkWitnessPolicy,id:&str,seed:u8)
        ->CustodianTrustPin{
        CustodianTrustPin{
            custodian_id:id.into(),custodian_public_key_hex:pubkey(seed),
            publication_stream_id:a.stream_id.clone(),
            audit_pin_sha256:sha256(&canonical(a)),
            witness_policy_sha256:sha256(&canonical(w)),
            floor_receipt_sequence:0,floor_receipt_sha256:None,
            floor_publication_checkpoint:PublicationCheckpoint{
                entry_count:0,last_entry_sha256:None,
            },
        }
    }
    fn sign_receipt(
        t:&CustodianTrustPin,seed:u8,sequence:u64,
        previous:Option<String>,checkpoint:PublicationCheckpoint,
        packet:&PublishedForkBundle
    )->SignedCustodyReceipt{
        let payload=CustodyReceiptPayload{
            format:CUSTODY_RECEIPT_FORMAT.into(),
            custodian_id:t.custodian_id.clone(),
            publication_stream_id:t.publication_stream_id.clone(),
            audit_pin_sha256:t.audit_pin_sha256.clone(),
            witness_policy_sha256:t.witness_policy_sha256.clone(),
            sequence,previous_signed_receipt_sha256:previous,
            publication_checkpoint:checkpoint,
            published_bundle_sha256:sha256(&canonical(packet)),
        };
        let key=SigningKey::from_bytes(&[seed;32]);
        SignedCustodyReceipt{
            signature_hex:hex::encode(key.sign(
                &signing_preimage(CUSTODY_RECEIPT_DOMAIN,&payload).unwrap()
            ).to_bytes()),
            payload,
        }
    }
    fn second_bundle()->PublishedForkBundle{
        let (a,old_left,_old_right)=histories();
        let policy=roster(&a);
        let root=old_left[0].clone();
        let prev=Some(sha256(&canonical(&root)));
        let left=vec![root.clone(),
            sign_audit(&a,2,prev.clone(),checkpoint(2,"second-left"))];
        let right=vec![root,sign_audit(&a,2,prev,checkpoint(2,"second-right"))];
        let witnesses=vec![
            vote(&a,&policy,&left,&right,"a",111),
            vote(&a,&policy,&left,&right,"b",112),
        ];
        PublishedForkBundle{
            left_audit_branch:left,right_audit_branch:right,witnesses,
        }
    }
    #[test]fn independently_pinned_signed_custody_matches_fully_verified_local_bundle(){
        let (_root,store,packet)=new_store();
        let cp=store.append(packet.clone()).unwrap().checkpoint;
        let (a,w,_)=bundle();
        let pin=trust(&a,&w,"custodian-one",121);
        let signed=sign_receipt(&pin,121,1,None,cp,&packet);
        let report=verify_custody_against_local(&store,&pin,&a,&w,&[signed]).unwrap();
        assert_eq!(report.latest_receipt_sequence,1);
        assert!(report.all_historical_publication_prefixes_replayed);
        assert!(!report.externally_hosted_custodian_verified);
        assert!(!report.genuine_independent_signer_custody_verified);
        assert!(!report.human_authority_verified&&!report.canonical_writeback);
    }
    #[test]fn two_distinct_custodian_signatures_agree_but_not_real_organizations(){
        let (_root,store,packet)=new_store();
        let cp=store.append(packet.clone()).unwrap().checkpoint;
        let (a,w,_)=bundle();
        let t1=trust(&a,&w,"custodian-a",121);
        let t2=trust(&a,&w,"custodian-b",122);
        let r1=sign_receipt(&t1,121,1,None,cp.clone(),&packet);
        let r2=sign_receipt(&t2,122,1,None,cp,&packet);
        let result=assess_two_custodians(&store,&a,&w,&t1,&[r1],&t2,&[r2]).unwrap();
        assert!(result.exact_terminal_publication_agreement);
        assert!(result.distinct_pinned_custodian_keys);
        assert!(!result.signer_organizational_independence_verified);
        assert!(!result.real_public_gossip_verified);
        assert!(!result.automatic_recovery_permitted);
    }
    #[test]fn two_custodian_labels_cannot_reuse_the_same_public_key(){
        let (_root,store,packet)=new_store();
        let cp=store.append(packet.clone()).unwrap().checkpoint;
        let (a,w,_)=bundle();
        let t1=trust(&a,&w,"custodian-a",121);
        let t2=trust(&a,&w,"custodian-b",121);
        let x=sign_receipt(&t1,121,1,None,cp.clone(),&packet);
        let y=sign_receipt(&t2,121,1,None,cp,&packet);
        assert!(assess_two_custodians(&store,&a,&w,&t1,&[x],&t2,&[y]).is_err());
    }
    #[test]fn custodian_signer_must_not_alias_auditor_or_witness_or_service(){
        let (a,w,_)=bundle();
        let mut p=trust(&a,&w,"bad",121);
        p.custodian_public_key_hex=a.auditor_public_key_hex.clone();
        assert!(p.validate(&a,&w).is_err());
        p.custodian_public_key_hex=w.witnesses[0].public_key_hex.clone();
        assert!(p.validate(&a,&w).is_err());
        p.custodian_public_key_hex=a.scope.pinned_response_signer_public_key_hex.clone();
        assert!(p.validate(&a,&w).is_err());
    }
    #[test]fn forged_signature_rejected_without_treating_receipt_as_external_custody(){
        let (_root,store,packet)=new_store();
        let cp=store.append(packet.clone()).unwrap().checkpoint;
        let (a,w,_)=bundle();let pin=trust(&a,&w,"custodian",121);
        let forged=sign_receipt(&pin,123,1,None,cp,&packet);
        assert!(verify_custody_against_local(&store,&pin,&a,&w,&[forged]).is_err());
    }
    #[test]fn wrong_scope_policy_and_key_pins_are_rejected(){
        let (_root,store,packet)=new_store();
        let cp=store.append(packet.clone()).unwrap().checkpoint;
        let (a,w,_)=bundle();let pin=trust(&a,&w,"custodian",121);
        let receipt=sign_receipt(&pin,121,1,None,cp,&packet);
        let mut wrong=pin.clone();
        wrong.witness_policy_sha256="f".repeat(64);
        assert!(verify_receipt_chain(&wrong,&a,&w,&[receipt.clone()]).is_err());
        let mut wrong=pin.clone();
        wrong.publication_stream_id="another-stream".into();
        assert!(verify_receipt_chain(&wrong,&a,&w,&[receipt.clone()]).is_err());
        let mut wrong=pin;
        wrong.custodian_public_key_hex=pubkey(124);
        assert!(verify_receipt_chain(&wrong,&a,&w,&[receipt]).is_err());
    }
    #[test]fn signed_wrong_bundle_digest_fails_historical_content_check(){
        let (_root,store,packet)=new_store();
        let cp=store.append(packet.clone()).unwrap().checkpoint;
        let (a,w,_)=bundle();let pin=trust(&a,&w,"custodian",121);
        let mut signed=sign_receipt(&pin,121,1,None,cp,&packet);
        signed.payload.published_bundle_sha256="f".repeat(64);
        let key=SigningKey::from_bytes(&[121;32]);
        signed.signature_hex=hex::encode(key.sign(
            &signing_preimage(CUSTODY_RECEIPT_DOMAIN,&signed.payload).unwrap()
        ).to_bytes());
        assert!(verify_receipt_chain(&pin,&a,&w,&[signed.clone()]).is_ok());
        assert!(verify_custody_against_local(&store,&pin,&a,&w,&[signed]).is_err());
    }
    #[test]fn publication_truncation_detected_if_signed_receipt_survives_outside(){
        let (root,store,packet)=new_store();
        let cp=store.append(packet.clone()).unwrap().checkpoint;
        let (a,w,_)=bundle();let pin=trust(&a,&w,"custodian",121);
        let signed=sign_receipt(&pin,121,1,None,cp,&packet);
        std::fs::remove_file(root.path().join(
            "fork-custody/entries/00000000000000000001.json")).unwrap();
        assert_eq!(store.checkpoint().unwrap().entry_count,0);
        assert!(verify_custody_against_local(&store,&pin,&a,&w,&[signed]).is_err());
    }
    #[test]fn proper_two_step_receipt_chain_checks_every_bundle_and_prefix(){
        let (_root,store,packet)=new_store();
        let first=store.append(packet.clone()).unwrap().checkpoint;
        let second_packet=second_bundle();
        let second=store.append(second_packet.clone()).unwrap().checkpoint;
        let (a,w,_)=bundle();let pin=trust(&a,&w,"custodian",121);
        let r1=sign_receipt(&pin,121,1,None,first,&packet);
        let r2=sign_receipt(&pin,121,2,Some(sha256(&canonical(&r1))),
            second,&second_packet);
        let v=verify_custody_against_local(&store,&pin,&a,&w,&[r1,r2]).unwrap();
        assert_eq!(v.latest_receipt_sequence,2);
        assert_eq!(v.receipt_count,2);
    }
    #[test]fn skipped_sequence_and_modified_previous_receipt_hash_fail(){
        let (_root,store,packet)=new_store();
        let first=store.append(packet.clone()).unwrap().checkpoint;
        let second_packet=second_bundle();
        let second=store.append(second_packet.clone()).unwrap().checkpoint;
        let (a,w,_)=bundle();let pin=trust(&a,&w,"custodian",121);
        let r1=sign_receipt(&pin,121,1,None,first,&packet);
        let bad_seq=sign_receipt(&pin,121,3,
            Some(sha256(&canonical(&r1))),second.clone(),&second_packet);
        assert!(verify_receipt_chain(&pin,&a,&w,&[r1.clone(),bad_seq]).is_err());
        let bad_prev=sign_receipt(&pin,121,2,
            Some("f".repeat(64)),second,&second_packet);
        assert!(verify_receipt_chain(&pin,&a,&w,&[r1,bad_prev]).is_err());
    }
    #[test]fn externally_retained_signed_receipt_floor_can_be_rechecked_after_growth(){
        let (_root,store,packet)=new_store();
        let first=store.append(packet.clone()).unwrap().checkpoint;
        let second_packet=second_bundle();
        let second=store.append(second_packet.clone()).unwrap().checkpoint;
        let (a,w,_)=bundle();let original=trust(&a,&w,"custodian",121);
        let r1=sign_receipt(&original,121,1,None,first.clone(),&packet);
        let mut pinned=original.clone();
        pinned.floor_receipt_sequence=1;
        pinned.floor_receipt_sha256=Some(sha256(&canonical(&r1)));
        pinned.floor_publication_checkpoint=first;
        let r2=sign_receipt(&pinned,121,2,
            pinned.floor_receipt_sha256.clone(),second,&second_packet);
        let v=verify_custody_against_local(&store,&pinned,&a,&w,&[r2]).unwrap();
        assert_eq!(v.latest_receipt_sequence,2);
    }
    #[test]fn injected_authority_field_is_rejected_at_strict_deserialization(){
        let (_root,store,packet)=new_store();
        let cp=store.append(packet.clone()).unwrap().checkpoint;
        let (a,w,_)=bundle();let pin=trust(&a,&w,"custodian",121);
        let mut data=serde_json::to_value(sign_receipt(
            &pin,121,1,None,cp,&packet)).unwrap();
        data["payload"]["human_authority_verified"]=serde_json::json!(true);
        assert!(serde_json::from_value::<SignedCustodyReceipt>(data).is_err());
    }

    // v0.33: Same cryptographic custodian identity, two signed, incompatible
    // claims at one height. This is key-attributed contradiction only, not
    // proof of physical external delivery or culpable human behavior.
    fn resign(receipt:&mut SignedCustodyReceipt,seed:u8){
        let key=SigningKey::from_bytes(&[seed;32]);
        receipt.signature_hex=hex::encode(key.sign(
            &signing_preimage(CUSTODY_RECEIPT_DOMAIN,&receipt.payload).unwrap()
        ).to_bytes());
    }
    fn competing_first_receipts()->(
        AuditTrustPin,ForkWitnessPolicy,CustodianTrustPin,
        SignedCustodyReceipt,SignedCustodyReceipt,
    ){
        let (_root,store,packet)=new_store();
        let cp=store.append(packet.clone()).unwrap().checkpoint;
        let (a,w,_)=bundle();
        let pin=trust(&a,&w,"same-cryptographic-custodian",121);
        let first=sign_receipt(&pin,121,1,None,cp,&packet);
        let mut conflicting=first.clone();
        conflicting.payload.published_bundle_sha256=sha256(b"other claimed complete bundle");
        resign(&mut conflicting,121);
        (a,w,pin,first,conflicting)
    }
    #[test]fn same_key_same_sequence_different_bundle_is_signed_conflict(){
        use galia_core_shadow::custody_equivocation::*;
        let (a,w,p,x,y)=competing_first_receipts();
        assert!(verify_receipt_chain(&p,&a,&w,&[x.clone()]).is_ok());
        assert!(verify_receipt_chain(&p,&a,&w,&[y.clone()]).is_ok());
        let result=assess_custodian_fork(&p,&a,&w,&[x],&[y]).unwrap();
        assert_eq!(result.classification,CustodyForkClassification::ConflictingSignedCustodianClaims);
        assert_eq!(result.conflicting_sequence,Some(1));
        assert_eq!(result.common_prior_sequence,0);
        assert!(result.contradictory_signed_claims_verified);
        assert_ne!(result.left_signed_envelope_sha256,result.right_signed_envelope_sha256);
        assert!(!result.real_custodian_independence_verified);
        assert!(!result.independent_delivery_verified);
        assert!(!result.human_culpability_established);
        assert!(!result.automatic_repair_permitted&&!result.canonical_writeback);
        assert!(!result.human_authority_verified&&!result.authority_transfer);
    }
    #[test]fn same_key_same_height_different_checkpoint_digest_is_conflict(){
        use galia_core_shadow::custody_equivocation::*;
        let (a,w,p,x,mut y)=competing_first_receipts();
        y.payload.published_bundle_sha256=x.payload.published_bundle_sha256.clone();
        y.payload.publication_checkpoint.last_entry_sha256=
            Some(sha256(b"alternative signed journal tip"));
        resign(&mut y,121);
        let result=assess_custodian_fork(&p,&a,&w,&[x],&[y]).unwrap();
        assert_eq!(result.classification,CustodyForkClassification::ConflictingSignedCustodianClaims);
    }
    #[test]fn exact_repeated_signed_receipt_is_not_equivocation(){
        use galia_core_shadow::custody_equivocation::*;
        let (a,w,p,x,_)=competing_first_receipts();
        let r=assess_custodian_fork(&p,&a,&w,&[x.clone()],&[x]).unwrap();
        assert_eq!(r.classification,CustodyForkClassification::SameSignedClaims);
        assert!(!r.contradictory_signed_claims_verified);
    }
    #[test]fn signed_prefix_extension_is_not_a_fork(){
        use galia_core_shadow::custody_equivocation::*;
        let (a,w,p,x,_)=competing_first_receipts();
        let second=second_bundle();
        let extra=sign_receipt(&p,121,2,
            Some(sha256(&canonical(&x))),
            PublicationCheckpoint{entry_count:2,last_entry_sha256:Some(sha256(b"second journal tip"))},
            &second);
        let r=assess_custodian_fork(&p,&a,&w,
            &[x.clone()],&[x,extra]).unwrap();
        assert_eq!(r.classification,CustodyForkClassification::VerifiedPrefixExtension);
        assert!(!r.contradictory_signed_claims_verified);
    }
    #[test]fn same_shared_first_receipt_can_fork_at_second_height(){
        use galia_core_shadow::custody_equivocation::*;
        let (a,w,p,root,_)=competing_first_receipts();
        let prior=Some(sha256(&canonical(&root)));
        let cp=PublicationCheckpoint{entry_count:2,
            last_entry_sha256:Some(sha256(b"second journal checkpoint"))};
        let left=sign_receipt(&p,121,2,prior.clone(),cp.clone(),&second_bundle());
        let mut right=sign_receipt(&p,121,2,prior,cp,&second_bundle());
        right.payload.published_bundle_sha256=sha256(b"contradiction at later sequence");
        resign(&mut right,121);
        let r=assess_custodian_fork(&p,&a,&w,&[root.clone(),left],&[root,right]).unwrap();
        assert_eq!(r.conflicting_sequence,Some(2));
        assert_eq!(r.common_prior_sequence,1);
        assert!(r.common_previous_signed_sha256.is_some());
    }
    #[test]fn forged_competing_branch_fails_before_attribution(){
        use galia_core_shadow::custody_equivocation::*;
        let (a,w,p,x,mut y)=competing_first_receipts();
        resign(&mut y,123);
        assert!(assess_custodian_fork(&p,&a,&w,&[x],&[y]).is_err());
    }
    #[test]fn mismatched_pinned_public_key_rejects_both_claims(){
        use galia_core_shadow::custody_equivocation::*;
        let (a,w,mut p,x,y)=competing_first_receipts();
        p.custodian_public_key_hex=pubkey(122);
        assert!(assess_custodian_fork(&p,&a,&w,&[x],&[y]).is_err());
    }
    #[test]fn altered_scope_or_policy_cannot_be_explained_as_a_fork(){
        use galia_core_shadow::custody_equivocation::*;
        let (a,w,mut p,x,y)=competing_first_receipts();
        p.publication_stream_id="other-stream".into();
        assert!(assess_custodian_fork(&p,&a,&w,&[x.clone()],&[y.clone()]).is_err());
        let (_,_,mut p2,_,_)=competing_first_receipts();
        p2.witness_policy_sha256=sha256(b"different witness roster");
        assert!(assess_custodian_fork(&p2,&a,&w,&[x],&[y]).is_err());
    }
    #[test]fn competing_branch_with_wrong_previous_digest_is_invalid(){
        use galia_core_shadow::custody_equivocation::*;
        let (a,w,p,x,mut y)=competing_first_receipts();
        y.payload.previous_signed_receipt_sha256=Some(sha256(b"not an ancestor"));
        resign(&mut y,121);
        assert!(assess_custodian_fork(&p,&a,&w,&[x],&[y]).is_err());
    }
    #[test]fn skipped_signed_custodian_counter_is_not_valid_fork_evidence(){
        use galia_core_shadow::custody_equivocation::*;
        let (a,w,p,x,mut y)=competing_first_receipts();
        y.payload.sequence=2;
        resign(&mut y,121);
        assert!(assess_custodian_fork(&p,&a,&w,&[x],&[y]).is_err());
    }
    #[test]fn two_distinct_custodian_identifiers_are_not_one_signer_equivocation(){
        use galia_core_shadow::custody_equivocation::*;
        let (a,w,p,x,mut y)=competing_first_receipts();
        y.payload.custodian_id="different-custodian".into();
        resign(&mut y,122);
        assert!(assess_custodian_fork(&p,&a,&w,&[x],&[y]).is_err());
    }
    #[test]fn injected_authority_field_rejected_in_evidence_envelope(){
        let (a,w,p,x,_)=competing_first_receipts();
        let mut tamper=serde_json::to_value(x).unwrap();
        tamper["payload"]["human_culpability_established"]=serde_json::json!(true);
        assert!(serde_json::from_value::<SignedCustodyReceipt>(tamper).is_err());
        assert!(p.validate(&a,&w).is_ok());
    }

    // v0.34 — offline countersignatures on ONE normalized, verified
    // same-key custodian contradiction; never real public disclosure.
    fn disclosure_policy(
        a:&AuditTrustPin,w:&ForkWitnessPolicy,p:&CustodianTrustPin,
    )->galia_core_shadow::custody_disclosure::DisclosurePolicy{
        use galia_core_shadow::custody_disclosure::*;
        DisclosurePolicy{
            format:DISCLOSURE_FORMAT.into(),roster_epoch:7,
            custodian_id:p.custodian_id.clone(),
            custodian_trust_sha256:sha256(&canonical(p)),
            audit_trust_sha256:sha256(&canonical(a)),
            witness_policy_sha256:sha256(&canonical(w)),
            required_distinct_signers:2,
            observers:vec![
                DisclosureObserver{observer_id:"one".into(),public_key_hex:pubkey(131),revoked:false},
                DisclosureObserver{observer_id:"two".into(),public_key_hex:pubkey(132),revoked:false},
                DisclosureObserver{observer_id:"zthree".into(),public_key_hex:pubkey(133),revoked:false},
            ],
        }
    }
    fn disclosure_vote(
        policy:&galia_core_shadow::custody_disclosure::DisclosurePolicy,
        subject:&galia_core_shadow::custody_disclosure::DisclosureSubject,
        id:&str,seed:u8
    )->galia_core_shadow::custody_disclosure::SignedDisclosureEndorsement{
        use galia_core_shadow::custody_disclosure::*;
        let payload=expected_endorsement(policy,id,subject).unwrap();
        SignedDisclosureEndorsement{
            signature_hex:hex::encode(SigningKey::from_bytes(&[seed;32]).sign(
                &signing_preimage(DISCLOSURE_DOMAIN,&payload).unwrap()).to_bytes()),
            payload,
        }
    }
    #[test]fn valid_two_key_disclosure_has_no_human_or_canonical_authority(){
        use galia_core_shadow::custody_disclosure::*;
        let (a,w,p,x,y)=competing_first_receipts();
        let pol=disclosure_policy(&a,&w,&p);
        let (subject,_)=subject_for_fork(&p,&a,&w,&[x.clone()],&[y.clone()]).unwrap();
        let votes=[disclosure_vote(&pol,&subject,"one",131),
                   disclosure_vote(&pol,&subject,"two",132)];
        let report=assess_disclosures(&p,&a,&w,&pol,&[x],&[y],&votes).unwrap();
        assert_eq!(report.observer_count,2);
        assert!(report.signed_custodian_contradiction_verified);
        assert!(report.distinct_pinned_signing_keys_verified);
        assert!(!report.real_witness_organizational_independence_verified);
        assert!(!report.independent_public_delivery_verified);
        assert!(!report.public_consensus_verified);
        assert!(!report.human_culpability_established);
        assert!(!report.automatic_quarantine_permitted&&!report.automatic_repair_permitted);
        assert!(!report.human_authority_verified&&!report.canonical_writeback&&!report.authority_transfer);
    }
    #[test]fn disclosure_subject_is_order_independent(){
        use galia_core_shadow::custody_disclosure::*;
        let (a,w,p,x,y)=competing_first_receipts();
        let (one,_)=subject_for_fork(&p,&a,&w,&[x.clone()],&[y.clone()]).unwrap();
        let (two,_)=subject_for_fork(&p,&a,&w,&[y],&[x]).unwrap();
        assert_eq!(one,two);
    }
    #[test]fn no_fork_or_valid_prefix_extension_cannot_be_disclosed(){
        use galia_core_shadow::custody_disclosure::*;
        let (a,w,p,x,_)=competing_first_receipts();
        assert!(subject_for_fork(&p,&a,&w,&[x.clone()],&[x.clone()]).is_err());
        let next=sign_receipt(&p,121,2,Some(sha256(&canonical(&x))),
            PublicationCheckpoint{entry_count:2,last_entry_sha256:Some(sha256(b"next"))},
            &second_bundle());
        assert!(subject_for_fork(&p,&a,&w,&[x.clone()],&[x,next]).is_err());
    }
    #[test]fn one_reporter_or_duplicate_reporter_never_meets_quorum(){
        use galia_core_shadow::custody_disclosure::*;
        let (a,w,p,x,y)=competing_first_receipts();
        let pol=disclosure_policy(&a,&w,&p);
        let (s,_)=subject_for_fork(&p,&a,&w,&[x.clone()],&[y.clone()]).unwrap();
        let vote=disclosure_vote(&pol,&s,"one",131);
        assert!(assess_disclosures(&p,&a,&w,&pol,&[x.clone()],&[y.clone()],
            &[vote.clone()]).is_err());
        assert!(assess_disclosures(&p,&a,&w,&pol,&[x],&[y],
            &[vote.clone(),vote]).is_err());
    }
    #[test]fn forged_observer_signature_is_rejected(){
        use galia_core_shadow::custody_disclosure::*;
        let (a,w,p,x,y)=competing_first_receipts();
        let pol=disclosure_policy(&a,&w,&p);
        let (s,_)=subject_for_fork(&p,&a,&w,&[x.clone()],&[y.clone()]).unwrap();
        assert!(assess_disclosures(&p,&a,&w,&pol,&[x],&[y],
            &[disclosure_vote(&pol,&s,"one",133),
              disclosure_vote(&pol,&s,"two",132)]).is_err());
    }
    #[test]fn valid_signature_over_different_conflict_digest_is_rejected(){
        use galia_core_shadow::custody_disclosure::*;
        let (a,w,p,x,y)=competing_first_receipts();let pol=disclosure_policy(&a,&w,&p);
        let (s,_)=subject_for_fork(&p,&a,&w,&[x.clone()],&[y.clone()]).unwrap();
        let first=disclosure_vote(&pol,&s,"one",131);
        let mut second=disclosure_vote(&pol,&s,"two",132);
        second.payload.subject.signed_claim_pair_sha256=sha256(b"unrelated claims");
        second.signature_hex=hex::encode(SigningKey::from_bytes(&[132;32])
            .sign(&signing_preimage(DISCLOSURE_DOMAIN,&second.payload).unwrap()).to_bytes());
        assert!(assess_disclosures(&p,&a,&w,&pol,&[x],&[y],&[first,second]).is_err());
    }
    #[test]fn revoked_signer_and_duplicate_key_are_fail_closed(){
        use galia_core_shadow::custody_disclosure::*;
        let (a,w,p,x,y)=competing_first_receipts();let mut pol=disclosure_policy(&a,&w,&p);
        pol.observers[1].revoked=true;
        let (s,_)=subject_for_fork(&p,&a,&w,&[x.clone()],&[y.clone()]).unwrap();
        assert!(assess_disclosures(&p,&a,&w,&pol,&[x],&[y],
            &[disclosure_vote(&pol,&s,"one",131),
              disclosure_vote(&pol,&s,"two",132)]).is_err());
        pol=disclosure_policy(&a,&w,&p);
        pol.observers[1].public_key_hex=pol.observers[0].public_key_hex.clone();
        assert!(pol.validate(&p,&a,&w).is_err());
    }
    #[test]fn custodian_and_auditor_and_witness_key_role_aliasing_rejected(){
        let (a,w,p,_,_)=competing_first_receipts();
        let mut pol=disclosure_policy(&a,&w,&p);
        pol.observers[1].public_key_hex=p.custodian_public_key_hex.clone();
        assert!(pol.validate(&p,&a,&w).is_err());
        pol.observers[1].public_key_hex=a.auditor_public_key_hex.clone();
        assert!(pol.validate(&p,&a,&w).is_err());
        pol.observers[1].public_key_hex=w.witnesses[0].public_key_hex.clone();
        assert!(pol.validate(&p,&a,&w).is_err());
    }
    #[test]fn scope_and_roster_epoch_substitution_breaks_signed_disclosure(){
        use galia_core_shadow::custody_disclosure::*;
        let (a,w,p,x,y)=competing_first_receipts();
        let pol=disclosure_policy(&a,&w,&p);
        let (s,_)=subject_for_fork(&p,&a,&w,&[x.clone()],&[y.clone()]).unwrap();
        let votes=[disclosure_vote(&pol,&s,"one",131),
                   disclosure_vote(&pol,&s,"two",132)];
        let mut altered=pol.clone();altered.roster_epoch=8;
        assert!(assess_disclosures(&p,&a,&w,&altered,&[x.clone()],&[y.clone()],&votes).is_err());
        altered=pol;altered.custodian_trust_sha256=sha256(b"other pin");
        assert!(assess_disclosures(&p,&a,&w,&altered,&[x],&[y],&votes).is_err());
    }
    #[test]fn forged_custodian_claim_cannot_gain_signer_quorum(){
        use galia_core_shadow::custody_disclosure::*;
        let (a,w,p,x,mut y)=competing_first_receipts();
        resign(&mut y,122);
        assert!(subject_for_fork(&p,&a,&w,&[x],&[y]).is_err());
    }
    #[test]fn strict_payload_unknown_authority_fields_rejected(){
        use galia_core_shadow::custody_disclosure::*;
        let (a,w,p,x,y)=competing_first_receipts();let pol=disclosure_policy(&a,&w,&p);
        let (s,_)=subject_for_fork(&p,&a,&w,&[x],&[y]).unwrap();
        let mut data=serde_json::to_value(disclosure_vote(&pol,&s,"one",131)).unwrap();
        data["payload"]["human_authority_verified"]=serde_json::json!(true);
        assert!(serde_json::from_value::<SignedDisclosureEndorsement>(data).is_err());
    }
}
