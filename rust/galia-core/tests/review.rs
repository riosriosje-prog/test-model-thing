//! P5 review signature fixtures: keys are TEST ONLY, not real human identities.
use ed25519_dalek::{SigningKey,Signer};
use galia_core_shadow::authority::{AuthorityScope,PromotionAuthorization};
use galia_core_shadow::attestation::signing_preimage;
use galia_core_shadow::review::*;

fn signer(seed:u8)->SigningKey{SigningKey::from_bytes(&[seed;32])}
fn signature<T:serde::Serialize>(key:&SigningKey,domain:&[u8],payload:&T)->String{
    hex::encode(key.sign(&signing_preimage(domain,payload).unwrap()).to_bytes())
}
fn sha(c:u8)->String{std::iter::repeat(char::from(c)).take(64).collect()}

fn fixture()->ReviewVerificationRequest{
    let root=signer(7);let reviewer=signer(8);
    let scope=AuthorityScope{case_id:"case-1".into(),target_type:"CLAIM".into(),target_ids:vec!["claim-1".into()]};
    let auth=PromotionAuthorization{
        authorization_id:"auth-unique-11".into(),decision_id:"decision-11".into(),
        reviewer:"human-reviewer-7".into(),scope:scope.clone(),
        target_commit:"candidate-17".into(),evidence_snapshot:vec!["evidence-hash-1".into()],
        policy_version:"p5-policy-v1".into(),authorized_at:"2026-10-16T03:00:00Z".into(),
    };
    let registry=ReviewRegistry{
        format:REVIEW_REGISTRY_FORMAT.into(),namespace:"galia-tenant".into(),
        case_id:"case-1".into(),epoch:10,
        keys:vec![RegisteredReviewer{
            key_id:"key-review-7".into(),reviewer_id:"human-reviewer-7".into(),
            public_key_hex:hex::encode(reviewer.verifying_key().to_bytes()),
            case_id:"case-1".into(),target_type:"CLAIM".into(),revoked:false,
        }],
        revoked_authorization_ids:vec![],
        consumed_authorization_ids:vec![],consumed_nonce_sha256:vec![],
    };
    let decision=ReviewPayload{
        format:REVIEW_DECISION_FORMAT.into(),
        namespace:"galia-tenant".into(),case_id:"case-1".into(),
        registry_epoch:10,reviewer_key_id:"key-review-7".into(),
        decision:ReviewDecisionKind::Select,
        authorization:auth,
        manifest_sha256:sha(b'a'),nonce_sha256:sha(b'1'),
    };
    ReviewVerificationRequest{
        policy:ReviewVerificationPolicy{
            pinned_root_public_key_hex:hex::encode(root.verifying_key().to_bytes()),
            expected_namespace:"galia-tenant".into(),expected_scope:scope,
            expected_target_commit:"candidate-17".into(),
            expected_decision_id:"decision-11".into(),
            expected_manifest_sha256:sha(b'a'),
            expected_policy_version:"p5-policy-v1".into(),
            minimum_registry_epoch:10,
            independently_spent_authorization_ids:vec![],
            independently_spent_nonce_sha256:vec![],
        },
        registry:SignedReviewRegistry{
            root_signature_hex:signature(&root,REVIEW_REGISTRY_DOMAIN,&registry),
            payload:registry,
        },
        decision:SignedReviewDecision{
            reviewer_signature_hex:signature(&reviewer,REVIEW_DECISION_DOMAIN,&decision),
            payload:decision,
        },
    }
}
fn resign_root(x:&mut ReviewVerificationRequest){
    x.registry.root_signature_hex=signature(&signer(7),REVIEW_REGISTRY_DOMAIN,&x.registry.payload);
}
fn resign_review(x:&mut ReviewVerificationRequest){
    x.decision.reviewer_signature_hex=signature(&signer(8),REVIEW_DECISION_DOMAIN,&x.decision.payload);
}
fn denied(x:ReviewVerificationRequest){assert!(verify_review(&x).is_err());}
#[test]fn scoped_valid_signature_never_grants_human_authority(){
    let r=verify_review(&fixture()).unwrap();
    assert!(r.review_signature_valid&&r.active_registered_key&&r.exact_scope_matched&&r.replay_fences_checked);
    assert_eq!(r.registry_epoch,10);
    assert!(!r.human_identity_verified&&!r.human_authority_verified);
    assert!(!r.executable_guards_issued&&!r.authority_transfer&&!r.canonical_writeback);
    assert!(r.output_commit.is_none());
}
#[test]fn pinned_root_cannot_be_self_substituted(){
    let mut x=fixture();x.policy.pinned_root_public_key_hex=hex::encode(signer(9).verifying_key().to_bytes());
    denied(x);
    let mut x=fixture();x.registry.payload.epoch=11;denied(x);
}
#[test]fn delegated_key_must_be_active_and_scope_bound(){
    let mut x=fixture();x.registry.payload.keys[0].revoked=true;resign_root(&mut x);denied(x);
    let mut x=fixture();x.registry.payload.keys[0].reviewer_id="other-reviewer".into();resign_root(&mut x);denied(x);
    let mut x=fixture();x.registry.payload.keys[0].target_type="STAGE".into();resign_root(&mut x);denied(x);
    let mut x=fixture();x.registry.payload.keys[0].case_id="case-2".into();resign_root(&mut x);denied(x);
    let mut x=fixture();x.registry.payload.keys[0].public_key_hex=x.policy.pinned_root_public_key_hex.clone();
    resign_root(&mut x);denied(x);
}
#[test]fn wrong_signature_or_reused_key_is_rejected(){
    let mut x=fixture();x.decision.reviewer_signature_hex=signature(&signer(99),REVIEW_DECISION_DOMAIN,&x.decision.payload);denied(x);
    let mut x=fixture();x.decision.reviewer_signature_hex=signature(&signer(8),REVIEW_REGISTRY_DOMAIN,&x.decision.payload);denied(x);
    let mut x=fixture();x.registry.payload.keys.push(x.registry.payload.keys[0].clone());resign_root(&mut x);denied(x);
    let mut x=fixture();let mut extra=x.registry.payload.keys[0].clone();extra.key_id="new-key-id".into();
    x.registry.payload.keys.push(extra);resign_root(&mut x);denied(x);
}
#[test]fn signed_select_cannot_change_to_hold_or_reject(){
    let mut x=fixture();x.decision.payload.decision=ReviewDecisionKind::Hold;resign_review(&mut x);denied(x);
    let mut x=fixture();x.decision.payload.decision=ReviewDecisionKind::Reject;resign_review(&mut x);denied(x);
}
#[test]fn exact_claim_scope_target_decision_and_policy_required(){
    let mut x=fixture();x.decision.payload.authorization.scope.target_ids=vec!["claim-other".into()];
    resign_review(&mut x);denied(x);
    let mut x=fixture();x.decision.payload.authorization.target_commit="candidate-18".into();
    resign_review(&mut x);denied(x);
    let mut x=fixture();x.decision.payload.authorization.decision_id="other-decision".into();
    resign_review(&mut x);denied(x);
    let mut x=fixture();x.decision.payload.authorization.policy_version="wrong-policy".into();
    resign_review(&mut x);denied(x);
    let mut x=fixture();x.decision.payload.authorization.reviewer="wrong-reviewer".into();
    resign_review(&mut x);denied(x);
}
#[test]fn signed_manifest_and_nonce_cannot_be_moved_between_cases(){
    let mut x=fixture();x.decision.payload.manifest_sha256=sha(b'b');resign_review(&mut x);denied(x);
    let mut x=fixture();x.decision.payload.case_id="case-2".into();resign_review(&mut x);denied(x);
    let mut x=fixture();x.decision.payload.namespace="other-tenant".into();resign_review(&mut x);denied(x);
    let mut x=fixture();x.decision.payload.registry_epoch=11;resign_review(&mut x);denied(x);
}
#[test]fn replay_and_revocation_fences_reject_even_valid_signatures(){
    let mut x=fixture();x.registry.payload.revoked_authorization_ids.push("auth-unique-11".into());
    resign_root(&mut x);denied(x);
    let mut x=fixture();x.registry.payload.consumed_authorization_ids.push("auth-unique-11".into());
    resign_root(&mut x);denied(x);
    let mut x=fixture();x.registry.payload.consumed_nonce_sha256.push(sha(b'1'));
    resign_root(&mut x);denied(x);
    let mut x=fixture();x.policy.independently_spent_authorization_ids.push("auth-unique-11".into());
    denied(x);
    let mut x=fixture();x.policy.independently_spent_nonce_sha256.push(sha(b'1'));denied(x);
}
#[test]fn old_signed_registry_is_rejected_by_pinned_epoch(){
    let mut x=fixture();x.policy.minimum_registry_epoch=11;denied(x);
    let mut x=fixture();x.registry.payload.epoch=9;x.decision.payload.registry_epoch=9;
    resign_root(&mut x);resign_review(&mut x);denied(x);
}
#[test]fn unknown_fields_and_malformed_payload_rejected(){
    let mut x=serde_json::to_value(fixture()).unwrap();x["claims_canonical"]=serde_json::json!(true);
    assert!(serde_json::from_value::<ReviewVerificationRequest>(x).is_err());
    let mut x=fixture();x.decision.payload.nonce_sha256="not-sha".into();
    resign_review(&mut x);denied(x);
    let mut x=fixture();x.policy.expected_manifest_sha256="B".repeat(64);denied(x);
}
#[test]fn future_registry_can_revoke_previously_signed_decision(){
    let mut x=fixture();
    assert!(verify_review(&x).is_ok());
    x.registry.payload.epoch=11;
    x.decision.payload.registry_epoch=11;
    resign_review(&mut x);
    x.registry.payload.revoked_authorization_ids.push("auth-unique-11".into());
    resign_root(&mut x);
    denied(x);
}
#[test]fn review_key_does_not_sign_root_registry(){
    let mut x=fixture();
    x.registry.root_signature_hex=signature(&signer(8),REVIEW_REGISTRY_DOMAIN,&x.registry.payload);
    denied(x);
}


#[cfg(feature="scratch-store")]
mod scratch_consumption_tests {
    use super::*;
    use galia_core_shadow::consumption::{ScratchConsumptionStore,ConsumptionCheckpoint};
    use std::sync::{Arc,Barrier};
    use std::thread;
    fn fresh()->(tempfile::TempDir,ScratchConsumptionStore){
        let parent=tempfile::tempdir().unwrap();
        let fx=fixture();
        let s=ScratchConsumptionStore::initialize_new(
            parent.path().join("spent"),
            &fx.policy.pinned_root_public_key_hex,
            &fx.policy.expected_namespace,
            &fx.policy.expected_scope.case_id).unwrap();
        (parent,s)
    }
    fn rotate_request(epoch:u64,revoked:bool)->ReviewVerificationRequest{
        let mut x=fixture();
        let fresh_key=signer(9);
        x.registry.payload.epoch=epoch;
        x.registry.payload.keys[0].revoked=true;
        x.registry.payload.keys.push(RegisteredReviewer{
            key_id:"key-review-9".into(),
            reviewer_id:"human-reviewer-9".into(),
            public_key_hex:hex::encode(fresh_key.verifying_key().to_bytes()),
            case_id:"case-1".into(),target_type:"CLAIM".into(),revoked,
        });
        x.decision.payload.registry_epoch=epoch;
        x.decision.payload.reviewer_key_id="key-review-9".into();
        x.decision.payload.authorization.reviewer="human-reviewer-9".into();
        x.decision.payload.authorization.authorization_id=format!("auth-rotation-{epoch}");
        x.decision.payload.nonce_sha256=sha(b'2');
        x.policy.minimum_registry_epoch=epoch;
        resign_root(&mut x);
        x.decision.reviewer_signature_hex=signature(&fresh_key,REVIEW_DECISION_DOMAIN,&x.decision.payload);
        x
    }
    #[test]fn exact_once_replay_survives_reopening(){
        let (parent,store)=fresh();
        let response=store.consume_review(&fixture()).unwrap();
        assert!(response.spent_in_scratch_only);
        assert_eq!(response.consumed_count,1);
        assert!(!response.human_authority_verified);
        assert!(!response.canonical_writeback);
        assert!(!response.executable_guards_issued);
        assert!(store.consume_review(&fixture()).is_err());
        let reloaded=ScratchConsumptionStore::open(parent.path().join("spent")).unwrap();
        assert!(reloaded.consume_review(&fixture()).is_err());
        assert_eq!(reloaded.inspect().unwrap().0,1);
    }
    #[test]fn same_nonce_new_id_and_same_id_new_nonce_both_denied(){
        let (_parent,s)=fresh();
        s.consume_review(&fixture()).unwrap();
        let mut nonce_replay=fixture();
        nonce_replay.decision.payload.authorization.authorization_id="different-auth".into();
        resign_review(&mut nonce_replay);
        assert!(s.consume_review(&nonce_replay).is_err());
        let mut id_replay=fixture();
        id_replay.decision.payload.nonce_sha256=sha(b'2');
        resign_review(&mut id_replay);
        assert!(s.consume_review(&id_replay).is_err());
        assert_eq!(s.inspect().unwrap().0,1);
    }
    #[test]fn concurrent_same_id_elects_one_writer(){
        let (_parent,store)=fresh();
        let shared=Arc::new(store);
        let barrier=Arc::new(Barrier::new(5));
        let joins=(0..4).map(|_|{
            let shared=Arc::clone(&shared);let barrier=Arc::clone(&barrier);
            thread::spawn(move||{barrier.wait();shared.consume_review(&fixture()).is_ok()})
        }).collect::<Vec<_>>();
        barrier.wait();
        let wins=joins.into_iter().map(|j|j.join().unwrap()).filter(|ok|*ok).count();
        assert_eq!(wins,1);
        assert_eq!(shared.inspect().unwrap().0,1);
    }
    #[test]fn distinct_records_are_atomic_under_concurrency(){
        let (_parent,store)=fresh();
        let shared=Arc::new(store);
        let barrier=Arc::new(Barrier::new(3));
        let joins=(0..2).map(|i|{
            let store=Arc::clone(&shared);let b=Arc::clone(&barrier);
            thread::spawn(move||{
                let mut request=fixture();
                if i>0{
                    request.decision.payload.authorization.authorization_id="auth-unique-12".into();
                    request.decision.payload.nonce_sha256=sha(b'2');
                    resign_review(&mut request);
                }
                b.wait();store.consume_review(&request).is_ok()
            })
        }).collect::<Vec<_>>();
        barrier.wait();
        assert!(joins.into_iter().all(|j|j.join().unwrap()));
        assert_eq!(shared.inspect().unwrap().0,2);
    }
    #[test]fn registry_epoch_advances_and_blocks_stale_authority(){
        let (_parent,s)=fresh();
        s.consume_review(&fixture()).unwrap();
        let rotated=rotate_request(11,false);
        assert_eq!(s.consume_review(&rotated).unwrap().maximum_seen_registry_epoch,11);
        let mut stale=fixture();
        stale.decision.payload.authorization.authorization_id="fresh-old-epoch".into();
        stale.decision.payload.nonce_sha256=sha(b'3');
        resign_review(&mut stale);
        assert!(s.consume_review(&stale).is_err());
        assert_eq!(s.inspect().unwrap().2,11);
    }
    #[test]fn revoked_rotated_key_fails_even_when_signature_is_valid(){
        let (_parent,s)=fresh();
        let revoked=rotate_request(11,true);
        assert!(s.consume_review(&revoked).is_err());
        assert_eq!(s.inspect().unwrap().0,0);
    }
    #[test]fn invalid_signature_cannot_burn_nonce(){
        let (_parent,s)=fresh();
        let mut bad=fixture();
        bad.decision.reviewer_signature_hex="0".repeat(128);
        assert!(s.consume_review(&bad).is_err());
        assert_eq!(s.inspect().unwrap().0,0);
        assert!(s.consume_review(&fixture()).is_ok());
    }
    #[test]fn journal_tampering_and_gaps_fail_closed(){
        let (parent,s)=fresh();
        s.consume_review(&fixture()).unwrap();
        let file=parent.path().join("spent/records/00000000000000000001.json");
        std::fs::write(&file,b"garbage").unwrap();
        assert!(s.inspect().is_err());
        assert!(s.consume_review(&rotate_request(11,false)).is_err());
    }
    #[test]fn out_of_band_checkpoint_detects_silent_truncation(){
        let (parent,s)=fresh();
        s.consume_review(&fixture()).unwrap();
        let cp=s.checkpoint().unwrap();
        let file=parent.path().join("spent/records/00000000000000000001.json");
        std::fs::remove_file(file).unwrap();
        // Local-only hash chains cannot detect a complete rollback without an anchor.
        assert_eq!(s.inspect().unwrap().0,0);
        assert!(s.verify_checkpoint(&cp).is_err());
    }
    #[test]fn root_pinning_refuses_other_root_and_wrong_case(){
        let (_parent,s)=fresh();
        let mut x=fixture();
        x.policy.pinned_root_public_key_hex=hex::encode(signer(9).verifying_key().to_bytes());
        assert!(s.consume_review(&x).is_err());
        let mut x=fixture();
        x.policy.expected_scope.case_id="other".into();
        assert!(s.consume_review(&x).is_err());
    }
    #[test]fn not_a_canonical_or_unmarked_repository(){
        let parent=tempfile::tempdir().unwrap();
        assert!(ScratchConsumptionStore::open(parent.path()).is_err());
        let fx=fixture();
        assert!(ScratchConsumptionStore::initialize_new(parent.path(),
            &fx.policy.pinned_root_public_key_hex,"galia-tenant","case-1").is_err());
    }
}


#[cfg(feature="scratch-store")]
mod witness_coordination_tests{
    use super::*;
    use galia_core_shadow::consumption::ScratchConsumptionStore;
    use galia_core_shadow::witness::{
        InMemoryWitness,MonotonicWitness,WitnessConfig,WitnessConsume,
        WitnessReceipt,WitnessObservation,
    };
    use std::sync::{Arc,Barrier};
    use std::thread;
    fn registry()->InMemoryWitness{
        let f=fixture();
        InMemoryWitness::new(WitnessConfig{
            namespace:f.policy.expected_namespace.clone(),
            case_id:f.policy.expected_scope.case_id.clone(),
            pinned_root_public_key_hex:f.policy.pinned_root_public_key_hex.clone(),
            initial_registry_epoch:10,
        }).unwrap()
    }
    fn stores()->(tempfile::TempDir,Arc<ScratchConsumptionStore>,Arc<ScratchConsumptionStore>){
        let root=tempfile::tempdir().unwrap();let f=fixture();
        let newstore=|name:&str|{
            Arc::new(ScratchConsumptionStore::initialize_new(
                root.path().join(name),&f.policy.pinned_root_public_key_hex,
                &f.policy.expected_namespace,&f.policy.expected_scope.case_id).unwrap())
        };
        let a=newstore("sim-host-A");let b=newstore("sim-host-B");
        (root,a,b)
    }
    #[test]fn simulated_hosts_same_authorization_can_only_consume_once(){
        let (_directory,a,b)=stores();let witness=Arc::new(registry());
        let barrier=Arc::new(Barrier::new(3));
        let jobs=[a,b].into_iter().map(|store|{
            let service=Arc::clone(&witness);let bar=Arc::clone(&barrier);
            thread::spawn(move||{
                let request=fixture();bar.wait();
                store.consume_with_witness(&request,service.as_ref(),None).is_ok()
            })
        }).collect::<Vec<_>>();
        barrier.wait();
        let winners=jobs.into_iter().map(|j|j.join().unwrap()).filter(|x|*x).count();
        assert_eq!(winners,1);
        assert_eq!(witness.observe().unwrap().spent_count,1);
    }
    #[test]fn independently_unique_hosts_need_fresh_cas_for_second_commit(){
        let (_directory,a,b)=stores();let witness=registry();
        let first=a.consume_with_witness(&fixture(),&witness,None).unwrap();
        assert!(!first.human_authority_verified&&!first.canonical_writeback&&!first.authority_transfer);
        assert_eq!(first.witness.as_ref().unwrap().spent_count,1);
        let mut second=fixture();
        second.decision.payload.authorization.authorization_id="auth-unique-12".into();
        second.decision.payload.nonce_sha256=sha(b'2');
        resign_review(&mut second);
        assert!(b.consume_with_witness(&second,&witness,None).is_err());
        assert_eq!(b.inspect().unwrap().0,0);
        let tip=witness.observe().unwrap().tip_sha256.unwrap();
        let later=b.consume_with_witness(&second,&witness,Some(&tip)).unwrap();
        assert_eq!(later.witness.unwrap().spent_count,2);
        assert_eq!(b.inspect().unwrap().0,1);
        assert_eq!(witness.observe().unwrap().spent_count,2);
    }
    struct Unavailable;
    impl MonotonicWitness for Unavailable{
        fn observe(&self)->Result<WitnessObservation,String>{
            Err("witness unavailable".into())
        }
        fn consume(&self,_r:&WitnessConsume)->Result<WitnessReceipt,String>{
            Err("witness unavailable".into())
        }
    }
    #[test]fn unavailable_witness_fails_without_local_write(){
        let (_directory,a,_b)=stores();
        assert!(a.consume_with_witness(&fixture(),&Unavailable,None).is_err());
        assert_eq!(a.inspect().unwrap().0,0);
        assert!(a.consume_review(&fixture()).is_ok()); // Explicit scratch legacy mode only.
    }
    #[test]fn invalid_review_signature_does_not_burn_witness(){
        let (_directory,a,_b)=stores();let witness=registry();
        let mut forged=fixture();
        forged.decision.reviewer_signature_hex="0".repeat(128);
        assert!(a.consume_with_witness(&forged,&witness,None).is_err());
        assert!(witness.observe().unwrap().spent_count==0);
        assert_eq!(a.inspect().unwrap().0,0);
        assert!(a.consume_with_witness(&fixture(),&witness,None).is_ok());
    }
    #[test]fn independently_pinned_witness_blocks_root_substitution(){
        let (_directory,a,_b)=stores();let witness=registry();
        let mut forged=fixture();
        forged.policy.pinned_root_public_key_hex=
            hex::encode(signer(99).verifying_key().to_bytes());
        assert!(a.consume_with_witness(&forged,&witness,None).is_err());
        assert_eq!(witness.observe().unwrap().spent_count,0);
    }
    #[test]fn witness_epoch_floor_blocks_older_root_signed_registry(){
        let (_directory,a,b)=stores();let witness=registry();
        let mut future=fixture();
        future.registry.payload.epoch=12;
        future.decision.payload.registry_epoch=12;
        future.policy.minimum_registry_epoch=12;
        resign_root(&mut future);
        resign_review(&mut future);
        a.consume_with_witness(&future,&witness,None).unwrap();
        let mut stale=fixture();
        stale.decision.payload.authorization.authorization_id="auth-not-before-seen".into();
        stale.decision.payload.nonce_sha256=sha(b'2');
        resign_review(&mut stale);
        let tip=witness.observe().unwrap().tip_sha256.unwrap();
        assert!(b.consume_with_witness(&stale,&witness,Some(&tip)).is_err());
        assert_eq!(b.inspect().unwrap().0,0);
        assert_eq!(witness.observe().unwrap().registry_epoch,12);
    }
}
