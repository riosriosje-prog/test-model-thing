#![cfg(feature="scratch-store")]
//! v0.14 scratch transparency board tests. Keys are synthetic test fixtures.
//! Separate board directories DO NOT establish actual observer independence.
use std::sync::{Arc,Barrier};
use std::thread;
use ed25519_dalek::{Signer,SigningKey};
use galia_core_shadow::transparency::*;
use galia_core_shadow::transparency_board::*;
use galia_core_shadow::witness_proof::*;
use galia_core_shadow::witness_continuity::*;
use galia_core_shadow::witness::{WitnessReceipt,FORMAT};
use galia_core_shadow::audit::sha256;
use galia_core_shadow::attestation::signing_preimage;

fn key(i:u8)->SigningKey{SigningKey::from_bytes(&[i;32])}
fn pubkey(i:u8)->String{hex::encode(key(i).verifying_key().to_bytes())}
fn sign<T:serde::Serialize>(i:u8,domain:&[u8],obj:&T)->String{
    hex::encode(key(i).sign(&signing_preimage(domain,obj).unwrap()).to_bytes())
}
fn h(c:char)->String{std::iter::repeat(c).take(64).collect()}
fn canon<T:serde::Serialize>(v:&T)->Vec<u8>{
    serde_json::to_value(v).and_then(|x|serde_json::to_vec(&x)).unwrap()
}
fn policy()->ObserverPolicy{
    ObserverPolicy{
        witness_anchor:WitnessTrustAnchor{
            signer_key_id:"w1".into(),
            pinned_witness_public_key_hex:pubkey(33),
            pinned_review_root_public_key_hex:pubkey(7),
            expected_namespace:"tenant".into(),expected_case_id:"cangrejos".into(),
            minimum_registry_epoch:10,minimum_spent_count:0,floor_tip_sha256:None,
        },
        roster_epoch:3,required_quorum:2,
        observers:vec![
            TrustedObserver{observer_id:"o1".into(),public_key_hex:pubkey(51),revoked:false},
            TrustedObserver{observer_id:"o2".into(),public_key_hex:pubkey(52),revoked:false},
        ],
    }
}
fn publication(count:u64,tip:Option<String>,epoch:u64)->PublishedWitnessView{
    let observation=galia_core_shadow::witness::WitnessObservation{
        namespace:"tenant".into(),case_id:"cangrejos".into(),
        registry_epoch:epoch,spent_count:count,tip_sha256:tip,
    };
    let signed=SignedWitnessObservation{
        signer_key_id:"w1".into(),
        signature_hex:sign(33,OBSERVATION_DOMAIN,&observation),
        observation,
    };
    let hash=sha256(&canon(&signed));
    let endorsements=[("o1",51),("o2",52)].into_iter().map(|(id,seed)|{
        let payload=GossipEndorsementPayload{
            format:GOSSIP_FORMAT.into(),roster_epoch:3,
            observer_id:id.into(),namespace:"tenant".into(),
            case_id:"cangrejos".into(),witness_observation_sha256:hash.clone(),
            spent_count:count,tip_sha256:signed.observation.tip_sha256.clone(),
            registry_epoch:epoch,
        };
        SignedGossipEndorsement{signature_hex:sign(seed,GOSSIP_DOMAIN,&payload),payload}
    }).collect();
    PublishedWitnessView{signed_observation:signed,endorsements}
}
fn transition(prior_count:u64,prior_tip:Option<String>,new_tip:char,
    epoch:u64)->(PublishedWitnessView,WitnessContinuityRequest){
    let next_count=prior_count+1;
    let view=publication(next_count,Some(h(new_tip)),epoch);
    let receipt=WitnessReceipt{
        format:FORMAT.into(),namespace:"tenant".into(),case_id:"cangrejos".into(),
        registry_epoch:epoch,spent_count:next_count,
        prior_tip_sha256:prior_tip.clone(),tip_sha256:h(new_tip),
        authorization_id:format!("spend-{next_count}-{new_tip}"),
        nonce_sha256:h(new_tip),signed_decision_sha256:h('f'),
        canonical_writeback:false,authority_transfer:false,
    };
    let signed=SignedWitnessReceipt{
        signer_key_id:"w1".into(),
        signature_hex:sign(33,RECEIPT_DOMAIN,&receipt),receipt,
    };
    let mut anchor=policy().witness_anchor;
    anchor.minimum_spent_count=prior_count;
    anchor.floor_tip_sha256=prior_tip;
    anchor.minimum_registry_epoch=10;
    let proof=WitnessContinuityRequest{
        anchor,pinned_rotation_root_public_key_hex:pubkey(88),
        rotations:vec![],extension:vec![signed],
        current_observation:view.signed_observation.clone(),
    };
    (view,proof)
}
fn new_board()->(tempfile::TempDir,DurableTransparencyBoard){
    let root=tempfile::tempdir().unwrap();
    let board=DurableTransparencyBoard::initialize_new(root.path().join("board"),policy()).unwrap();
    (root,board)
}
fn boot(board:&DurableTransparencyBoard){
    let r=board.publish(publication(0,None,10),None).unwrap();
    assert_eq!(r.journal_count,1);
    assert!(!r.quarantined);
}
#[test]fn accepted_genesis_and_contiguous_extension_survive_reopen(){
    let (dir,b)=new_board();
    boot(&b);
    let (view,proof)=transition(0,None,'a',10);
    let result=b.publish(view.clone(),Some(proof.clone())).unwrap();
    assert_eq!(result.journal_count,2);
    assert_eq!(result.highest_published_count,1);
    assert!(!result.human_authority_verified&&!result.authority_transfer);
    let reopened=DurableTransparencyBoard::open(dir.path().join("board"),policy()).unwrap();
    assert_eq!(reopened.inspect().unwrap().journal_count,2);
    assert_eq!(reopened.export().unwrap().len(),2);
    assert_eq!(reopened.publish(view,Some(proof)).unwrap().status,"ALREADY_PUBLISHED_NO_WRITE");
    assert_eq!(reopened.inspect().unwrap().journal_count,2);
}
#[test]fn opposite_signed_views_same_height_are_quarantined_durably(){
    let (dir,b)=new_board();
    boot(&b);
    let (first,proof)=transition(0,None,'a',10);
    b.publish(first,Some(proof)).unwrap();
    let conflict=b.publish(publication(1,Some(h('b')),10),None).unwrap();
    assert_eq!(conflict.status,"SPLIT_VIEW_EVIDENCE_QUARANTINED");
    assert!(conflict.quarantined);
    assert_eq!(conflict.journal_count,3);
    let e=b.evidence().unwrap().unwrap();
    assert_ne!(e.left_observation_sha256,e.right_observation_sha256);
    assert_eq!(e.count,1);
    assert!(!e.human_authority_verified&&!e.canonical_writeback);
    let reopened=DurableTransparencyBoard::open(dir.path().join("board"),policy()).unwrap();
    assert!(reopened.inspect().unwrap().quarantined);
    assert!(reopened.evidence().unwrap().is_some());
    assert!(reopened.publish(publication(0,None,10),None).is_err());
    assert_eq!(reopened.export().unwrap().len(),3);
}
#[test]fn independent_local_boards_exchange_conflicting_signed_publications(){
    let (_root_a,a)=new_board();
    let (_root_b,b)=new_board();
    boot(&a);boot(&b);
    let (av,ap)=transition(0,None,'a',10);
    let (bv,bp)=transition(0,None,'b',10);
    a.publish(av,Some(ap)).unwrap();
    b.publish(bv,Some(bp)).unwrap();
    let foreign_from_b=b.export().unwrap();
    let foreign_from_a=a.export().unwrap();
    let f=foreign_from_b.into_iter().last().unwrap();
    assert!(a.publish(f.view,f.extension).unwrap().quarantined);
    let f=foreign_from_a.into_iter().last().unwrap();
    assert!(b.publish(f.view,f.extension).unwrap().quarantined);
    assert_eq!(a.evidence().unwrap().unwrap().count,1);
    assert_eq!(b.evidence().unwrap().unwrap().count,1);
}
#[test]fn foreign_peer_can_replay_signed_publications_with_valid_extension(){
    let (_root_a,a)=new_board();let (_root_b,b)=new_board();
    boot(&a);
    let (view,proof)=transition(0,None,'a',10);
    a.publish(view,Some(proof)).unwrap();
    for item in a.export().unwrap(){
        b.publish(item.view,item.extension).unwrap();
    }
    assert_eq!(b.inspect().unwrap().journal_count,2);
    assert_eq!(a.inspect().unwrap().journal_tip_sha256,b.inspect().unwrap().journal_tip_sha256);
}
#[test]fn unsigned_forward_jump_and_wrong_proof_are_rejected(){
    let (_root,b)=new_board();boot(&b);
    let (view,_proof)=transition(0,None,'a',10);
    assert!(b.publish(view.clone(),None).is_err());
    let (_,mut proof)=transition(0,None,'a',10);
    proof.anchor.floor_tip_sha256=Some(h('f'));
    assert!(b.publish(view.clone(),Some(proof)).is_err());
    assert_eq!(b.inspect().unwrap().journal_count,1);
    let (_next,proof)=transition(1,Some(h('a')),'c',10);
    assert!(b.publish(view,Some(proof)).is_err());
}
#[test]fn marker_is_not_self_authenticating_and_external_policy_must_match(){
    let (dir,b)=new_board();
    boot(&b);
    let mut other=policy();
    other.roster_epoch=4;
    assert!(DurableTransparencyBoard::open(dir.path().join("board"),other).is_err());
    let mut other=policy();
    other.observers[0].public_key_hex=pubkey(70);
    assert!(DurableTransparencyBoard::open(dir.path().join("board"),other).is_err());
    assert!(DurableTransparencyBoard::initialize_new(dir.path().join("board"),policy()).is_err());
}
#[test]fn corrupted_journal_is_fail_closed_without_auto_repair(){
    let (dir,b)=new_board();boot(&b);
    let raw=dir.path().join("board/publications/00000000000000000001.json");
    std::fs::write(&raw,b"{").unwrap();
    assert!(b.inspect().is_err());
    assert!(DurableTransparencyBoard::open(dir.path().join("board"),policy()).is_err());
    assert!(b.publish(publication(0,None,10),None).is_err());
}
#[test]fn pinned_external_checkpoint_detects_whole_journal_truncation(){
    let (dir,b)=new_board();boot(&b);
    let checkpoint=b.checkpoint().unwrap();
    std::fs::remove_file(dir.path().join("board/publications/00000000000000000001.json")).unwrap();
    // Without a genuine out-of-band pin, full scratch rollback is undetectable.
    assert_eq!(b.inspect().unwrap().journal_count,0);
    assert!(b.verify_checkpoint(&checkpoint).is_err());
}
#[test]fn same_height_conflict_is_detected_after_later_head(){
    let (_dir,b)=new_board();boot(&b);
    let (p1,pf1)=transition(0,None,'a',10);b.publish(p1,Some(pf1)).unwrap();
    let (p2,pf2)=transition(1,Some(h('a')),'c',11);b.publish(p2,Some(pf2)).unwrap();
    let conflict=b.publish(publication(1,Some(h('b')),10),None).unwrap();
    assert!(conflict.quarantined);
    assert_eq!(conflict.highest_published_count,2);
}
#[test]fn concurrent_handles_commit_one_branch_then_quarantine_second(){
    let (dir,a)=new_board();boot(&a);
    let b=DurableTransparencyBoard::open(dir.path().join("board"),policy()).unwrap();
    let barrier=Arc::new(Barrier::new(3));
    let jobs=[(a,'a'),(b,'b')].into_iter().map(|(board,digit)|{
        let bar=Arc::clone(&barrier);
        thread::spawn(move||{
            let (v,p)=transition(0,None,digit,10);
            bar.wait();
            board.publish(v,Some(p))
        })
    }).collect::<Vec<_>>();
    barrier.wait();
    let mut results=jobs.into_iter().map(|j|j.join().unwrap()).collect::<Vec<_>>();
    assert_eq!(results.len(),2);
    let successes=results.iter().filter(|r|r.is_ok()).count();
    // Same height conflict must not supply an extension proof. In the losing
    // write the caller can reimport only its signed view without extension.
    assert_eq!(successes,1);
    let loser=if results.remove(0).is_err(){'a'}else{'b'};
    let reopened=DurableTransparencyBoard::open(dir.path().join("board"),policy()).unwrap();
    assert!(reopened.publish(publication(1,Some(h(loser)),10),None).unwrap().quarantined);
    assert_eq!(reopened.inspect().unwrap().journal_count,3);
}
#[cfg(unix)]
#[test]fn symlinked_journal_file_is_denied(){
    use std::os::unix::fs::symlink;
    let (dir,b)=new_board();boot(&b);
    let path=dir.path().join("board/publications/00000000000000000001.json");
    std::fs::remove_file(&path).unwrap();
    symlink(dir.path().join("board/.GALIA_NONCANONICAL_TRANSPARENCY_BOARD_V1"),&path).unwrap();
    assert!(b.inspect().is_err());
}
