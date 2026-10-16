#![cfg(feature="scratch-store")]
//! Synthetic offline external checkpoint signatures; no trusted deployment.
use ed25519_dalek::{Signer,SigningKey};
use galia_core_shadow::attestation::signing_preimage;
use galia_core_shadow::audit::sha256;
use galia_core_shadow::external_checkpoint::*;
use galia_core_shadow::transparency::*;
use galia_core_shadow::transparency_board::*;
use galia_core_shadow::witness::*;
use galia_core_shadow::witness_proof::*;
use galia_core_shadow::witness_continuity::*;

fn signing_key(seed:u8)->SigningKey{SigningKey::from_bytes(&[seed;32])}
fn pubkey(seed:u8)->String{hex::encode(signing_key(seed).verifying_key().to_bytes())}
fn sign<T:serde::Serialize>(seed:u8,domain:&[u8],value:&T)->String{
    hex::encode(signing_key(seed).sign(&signing_preimage(domain,value).unwrap()).to_bytes())
}
fn hash(c:char)->String{std::iter::repeat(c).take(64).collect()}
fn canonical<T:serde::Serialize>(value:&T)->Vec<u8>{
    serde_json::to_value(value).and_then(|v|serde_json::to_vec(&v)).unwrap()
}
fn roster()->ObserverPolicy{
    ObserverPolicy{
        witness_anchor:WitnessTrustAnchor{
            signer_key_id:"w1".into(),pinned_witness_public_key_hex:pubkey(33),
            pinned_review_root_public_key_hex:pubkey(7),
            expected_namespace:"tenant".into(),expected_case_id:"cangrejos".into(),
            minimum_registry_epoch:10,minimum_spent_count:0,floor_tip_sha256:None
        },
        roster_epoch:3,required_quorum:2,
        observers:vec![
            TrustedObserver{observer_id:"a".into(),public_key_hex:pubkey(51),revoked:false},
            TrustedObserver{observer_id:"b".into(),public_key_hex:pubkey(52),revoked:false},
        ],
    }
}
fn publication(count:u64,tip:Option<String>,epoch:u64)->PublishedWitnessView{
    let observation=WitnessObservation{namespace:"tenant".into(),case_id:"cangrejos".into(),
        registry_epoch:epoch,spent_count:count,tip_sha256:tip};
    let signed=SignedWitnessObservation{
        signer_key_id:"w1".into(),signature_hex:sign(33,OBSERVATION_DOMAIN,&observation),
        observation,
    };
    let witness_observation_sha256=sha256(&canonical(&signed));
    let endorsements=[("a",51),("b",52)].into_iter().map(|(id,seed)|{
        let payload=GossipEndorsementPayload{
            format:GOSSIP_FORMAT.into(),roster_epoch:3,
            observer_id:id.into(),namespace:"tenant".into(),case_id:"cangrejos".into(),
            witness_observation_sha256:witness_observation_sha256.clone(),
            spent_count:count,tip_sha256:signed.observation.tip_sha256.clone(),
            registry_epoch:epoch,
        };
        SignedGossipEndorsement{signature_hex:sign(seed,GOSSIP_DOMAIN,&payload),payload}
    }).collect();
    PublishedWitnessView{signed_observation:signed,endorsements}
}
fn extension(tip:char)->(PublishedWitnessView,WitnessContinuityRequest){
    let view=publication(1,Some(hash(tip)),10);
    let receipt=WitnessReceipt{
        format:FORMAT.into(),namespace:"tenant".into(),case_id:"cangrejos".into(),
        registry_epoch:10,spent_count:1,prior_tip_sha256:None,
        tip_sha256:hash(tip),authorization_id:format!("auth-{tip}"),
        nonce_sha256:hash(tip),signed_decision_sha256:hash('f'),
        canonical_writeback:false,authority_transfer:false
    };
    let proof=WitnessContinuityRequest{
        anchor:roster().witness_anchor,
        pinned_rotation_root_public_key_hex:pubkey(88),
        rotations:vec![],
        extension:vec![SignedWitnessReceipt{
            signer_key_id:"w1".into(),signature_hex:sign(33,RECEIPT_DOMAIN,&receipt),
            receipt,
        }],
        current_observation:view.signed_observation.clone(),
    };
    (view,proof)
}
fn board()->(tempfile::TempDir,DurableTransparencyBoard){
    let dir=tempfile::tempdir().unwrap();
    let b=DurableTransparencyBoard::initialize_new(dir.path().join("scratch-board"),roster()).unwrap();
    (dir,b)
}
fn trust()->CheckpointAnchorTrust{
    CheckpointAnchorTrust{
        external_signer_id:"auditor-1".into(),external_signer_public_key_hex:pubkey(91),
        stream_id:"external-stream-galia-1".into(),namespace:"tenant".into(),
        case_id:"cangrejos".into(),
        pinned_observer_policy_sha256:policy_digest(&roster()).unwrap(),
        floor_sequence:0,floor_envelope_sha256:None,
        floor_board:BoardCheckpoint{
            journal_count:0,journal_tip_sha256:None,quarantined:false
        },
    }
}
fn checkpoint(b:&DurableTransparencyBoard,sequence:u64,
    previous_envelope_sha256:Option<String>)->SignedExternalBoardCheckpoint{
    let state=b.checkpoint().unwrap();
    let evidence=evidence_digest(b.evidence().unwrap().as_ref()).unwrap();
    let payload=ExternalBoardCheckpointPayload{
        format:CHECKPOINT_FORMAT.into(),external_signer_id:"auditor-1".into(),
        stream_id:"external-stream-galia-1".into(),
        namespace:"tenant".into(),case_id:"cangrejos".into(),
        observer_policy_sha256:policy_digest(&roster()).unwrap(),
        sequence,previous_envelope_sha256,board:state,
        quarantined_evidence_sha256:evidence,
    };
    SignedExternalBoardCheckpoint{
        signature_hex:sign(91,CHECKPOINT_DOMAIN,&payload),payload
    }
}
fn endhash(s:&SignedExternalBoardCheckpoint)->String{sha256(&canonical(s))}
fn boot(b:&DurableTransparencyBoard){
    assert_eq!(b.publish(publication(0,None,10),None).unwrap().journal_count,1);
}
#[test]fn externally_signed_anchor_matches_replayed_scratch_board(){
    let (_dir,b)=board();boot(&b);
    let first=checkpoint(&b,1,None);
    let (p,pr)=extension('a');b.publish(p,Some(pr)).unwrap();
    let second=checkpoint(&b,2,Some(endhash(&first)));
    let verified=inspect_anchored_board(&b,&trust(),&roster(),&[first,second]).unwrap();
    assert_eq!(verified.board_journal_count,2);
    assert_eq!(verified.latest_external_sequence,2);
    assert_eq!(verified.anchor_count,2);
    assert!(!verified.quarantined&&!verified.automatic_fork_recovery_permitted);
    assert!(!verified.human_authority_verified&&!verified.canonical_writeback);
}
#[test]fn independently_stored_floor_supports_exact_incremental_chain(){
    let (_dir,b)=board();boot(&b);
    let first=checkpoint(&b,1,None);
    let mut floor=trust();
    floor.floor_sequence=1;
    floor.floor_envelope_sha256=Some(endhash(&first));
    floor.floor_board=b.checkpoint().unwrap();
    let (p,pr)=extension('a');b.publish(p,Some(pr)).unwrap();
    let next=checkpoint(&b,2,floor.floor_envelope_sha256.clone());
    assert!(inspect_anchored_board(&b,&floor,&roster(),&[next]).is_ok());
}
#[test]fn signed_anchor_detects_full_scratch_journal_truncation(){
    let (dir,b)=board();boot(&b);
    let signed=checkpoint(&b,1,None);
    std::fs::remove_file(
        dir.path().join("scratch-board/publications/00000000000000000001.json")).unwrap();
    assert_eq!(b.inspect().unwrap().journal_count,0); // unanchored rollback
    assert!(inspect_anchored_board(&b,&trust(),&roster(),&[signed]).is_err());
}
#[test]fn forged_signature_or_external_key_substitution_fails(){
    let (_dir,b)=board();boot(&b);
    let mut s=checkpoint(&b,1,None);
    s.signature_hex=sign(99,CHECKPOINT_DOMAIN,&s.payload);
    assert!(inspect_anchored_board(&b,&trust(),&roster(),&[s]).is_err());
    let mut wrong=trust();wrong.external_signer_public_key_hex=pubkey(99);
    assert!(wrong.validate(&roster()).is_ok());
    let original=checkpoint(&b,1,None);
    assert!(inspect_anchored_board(&b,&wrong,&roster(),&[original]).is_err());
}
#[test]fn wrong_stream_policy_and_role_key_are_rejected(){
    let (_dir,b)=board();boot(&b);
    let original=checkpoint(&b,1,None);
    let mut bad=trust();bad.stream_id="different-stream".into();
    assert!(inspect_anchored_board(&b,&bad,&roster(),&[original.clone()]).is_err());
    let mut bad=trust();bad.pinned_observer_policy_sha256=hash('f');
    assert!(inspect_anchored_board(&b,&bad,&roster(),&[original.clone()]).is_err());
    let mut bad=trust();bad.external_signer_public_key_hex=pubkey(51);
    assert!(inspect_anchored_board(&b,&bad,&roster(),&[original]).is_err());
}
#[test]fn skipped_sequence_or_changed_chain_tip_rejected(){
    let (_dir,b)=board();boot(&b);
    let one=checkpoint(&b,1,None);
    let mut two=checkpoint(&b,3,Some(endhash(&one)));
    assert!(verify_anchor_chain(&trust(),&roster(),&[one.clone(),two.clone()]).is_err());
    two.payload.sequence=2;
    two.payload.previous_envelope_sha256=Some(hash('d'));
    two.signature_hex=sign(91,CHECKPOINT_DOMAIN,&two.payload);
    assert!(verify_anchor_chain(&trust(),&roster(),&[one,two]).is_err());
}
#[test]fn signed_same_height_different_digest_rejected(){
    let (_dir,b)=board();boot(&b);
    let one=checkpoint(&b,1,None);
    let mut two=checkpoint(&b,2,Some(endhash(&one)));
    two.payload.board.journal_tip_sha256=Some(hash('f'));
    two.signature_hex=sign(91,CHECKPOINT_DOMAIN,&two.payload);
    assert!(verify_anchor_chain(&trust(),&roster(),&[one,two]).is_err());
}
#[test]fn quarantine_evidence_is_signed_and_read_only_after_restart(){
    let (dir,b)=board();boot(&b);
    let one=checkpoint(&b,1,None);
    let (p,pr)=extension('a');b.publish(p,Some(pr)).unwrap();
    let two=checkpoint(&b,2,Some(endhash(&one)));
    b.publish(publication(1,Some(hash('b')),10),None).unwrap();
    let three=checkpoint(&b,3,Some(endhash(&two)));
    let reopened=DurableTransparencyBoard::open(dir.path().join("scratch-board"),roster()).unwrap();
    let report=inspect_anchored_board(&reopened,&trust(),&roster(),
        &[one,two,three]).unwrap();
    assert!(report.quarantined&&report.evidence_sha256.is_some());
    assert!(!report.automatic_fork_recovery_permitted);
    assert_eq!(report.status,"SIGNED_FORK_EVIDENCE_PINNED_MANUAL_REVIEW_REQUIRED");
    assert!(reopened.publish(publication(0,None,10),None).is_err());
}
#[test]fn signed_external_checkpoint_cannot_clear_existing_quarantine(){
    let (_dir,b)=board();boot(&b);
    let (p,pr)=extension('a');b.publish(p,Some(pr)).unwrap();
    b.publish(publication(1,Some(hash('b')),10),None).unwrap();
    let one=checkpoint(&b,1,None);
    let mut two=checkpoint(&b,2,Some(endhash(&one)));
    two.payload.board.quarantined=false;
    two.payload.quarantined_evidence_sha256=None;
    two.signature_hex=sign(91,CHECKPOINT_DOMAIN,&two.payload);
    assert!(verify_anchor_chain(&trust(),&roster(),&[one,two]).is_err());
}
#[test]fn signed_missing_or_changed_fork_evidence_is_denied(){
    let (_dir,b)=board();boot(&b);
    let (p,pr)=extension('a');b.publish(p,Some(pr)).unwrap();
    b.publish(publication(1,Some(hash('b')),10),None).unwrap();
    let mut one=checkpoint(&b,1,None);
    one.payload.quarantined_evidence_sha256=Some(hash('f'));
    one.signature_hex=sign(91,CHECKPOINT_DOMAIN,&one.payload);
    assert!(inspect_anchored_board(&b,&trust(),&roster(),&[one]).is_err());
}
#[test]fn duplicate_or_unknown_json_fields_not_trusted(){
    let (_dir,b)=board();boot(&b);
    let mut value=serde_json::to_value(checkpoint(&b,1,None)).unwrap();
    value["payload"]["canonical_promoted"]=serde_json::json!(true);
    assert!(serde_json::from_value::<SignedExternalBoardCheckpoint>(value).is_err());
}
