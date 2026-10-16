use ed25519_dalek::{SigningKey,Signer};
use galia_core_shadow::attestation::*;
use galia_core_shadow::audit::{AuditReceipt,AuditOperation,Checkpoint,next_receipt,verify_receipts};

fn signing_key(seed:u8)->SigningKey{SigningKey::from_bytes(&[seed;32])}
fn h(digit:u8)->String{std::iter::repeat(char::from(digit)).take(64).collect()}
fn ledger()->Vec<AuditReceipt>{
    let mut c=vec![];
    c.push(next_receipt(&c,AuditOperation::Staged,"g1",&h(b'a'),None,None).unwrap());
    c.push(next_receipt(&c,AuditOperation::Published,"g1",&h(b'a'),None,Some(h(b'1'))).unwrap());
    c.push(next_receipt(&c,AuditOperation::Staged,"g2",&h(b'b'),Some(h(b'1')),Some(h(b'1'))).unwrap());
    c.push(next_receipt(&c,AuditOperation::Published,"g2",&h(b'b'),Some(h(b'1')),Some(h(b'2'))).unwrap());
    c
}
fn sign_root(r:&mut AttestationRequest,key:&SigningKey){
    r.signed_registry.root_signature_hex=hex::encode(
        key.sign(&signing_preimage(REGISTRY_DOMAIN,&r.signed_registry.payload).unwrap()).to_bytes()
    );
}
fn sign_checkpoint(r:&mut AttestationRequest,key:&SigningKey){
    r.signed_checkpoint.signature_hex=hex::encode(
        key.sign(&signing_preimage(CHECKPOINT_DOMAIN,&r.signed_checkpoint.payload).unwrap()).to_bytes()
    );
}
fn baseline()->AttestationRequest{
    let root=signing_key(7);
    let delegate=signing_key(8);
    let receipts=ledger();
    let report=verify_receipts(&receipts,None).unwrap();
    let registry=TrustRegistry{
        format:REGISTRY_FORMAT.into(),namespace:"galia-tenant-1".into(),
        case_id:"cangrejos-01".into(),epoch:5,
        signers:vec![CheckpointSigner{
            key_id:"checkpoint-key-1".into(),
            public_key_hex:hex::encode(delegate.verifying_key().to_bytes()),
            case_id:"cangrejos-01".into(),revoked:false,
        }],
    };
    let payload=SignedCheckpointPayload{
        format:CHECKPOINT_FORMAT.into(),namespace:"galia-tenant-1".into(),
        case_id:"cangrejos-01".into(),registry_epoch:5,
        signer_key_id:"checkpoint-key-1".into(),count:report.count,
        tip_sha256:report.tip_sha256.unwrap(),
        last_head_sha256:report.head_sha256,
    };
    let mut r=AttestationRequest{
        policy:TrustPolicy{
            pinned_root_public_key_hex:hex::encode(root.verifying_key().to_bytes()),
            expected_namespace:"galia-tenant-1".into(),
            expected_case_id:"cangrejos-01".into(),
            minimum_registry_epoch:5,minimum_receipt_count:4,
            prior_checkpoint:None,
        },
        signed_registry:SignedRegistry{payload:registry,root_signature_hex:String::new()},
        signed_checkpoint:SignedCheckpoint{payload,signature_hex:String::new()},
        receipts,
    };
    sign_root(&mut r,&root);
    sign_checkpoint(&mut r,&delegate);
    r
}
fn prefix(r:&AttestationRequest,count:usize)->Checkpoint{
    let x=verify_receipts(&r.receipts[..count],None).unwrap();
    Checkpoint{count:x.count,tip_sha256:x.tip_sha256.unwrap(),last_head_sha256:x.head_sha256}
}
#[test]
fn valid_root_and_delegated_checkpoint_stay_non_authoritative(){
    let x=verify_attestation(&baseline()).unwrap();
    assert!(x.signature_valid&&x.registered_signer_active&&x.audit_chain_consistent);
    assert_eq!(x.receipt_count,4);
    assert_eq!(x.registry_epoch,5);
    assert!(!x.human_authority_verified&&!x.authority_transfer&&!x.canonical_writeback);
    assert!(x.output_commit.is_none());
}
#[test]
fn wrong_or_self_selected_root_never_matches_a_pinned_root(){
    let mut x=baseline();
    x.policy.pinned_root_public_key_hex=hex::encode(signing_key(9).verifying_key().to_bytes());
    assert!(verify_attestation(&x).is_err());
    let mut x=baseline();
    x.signed_registry.payload.epoch+=1;
    assert!(verify_attestation(&x).is_err());
}
#[test]
fn revoked_signer_denied_even_when_old_signature_remains_valid(){
    let mut x=baseline();
    x.signed_registry.payload.signers[0].revoked=true;
    sign_root(&mut x,&signing_key(7));
    assert!(verify_attestation(&x).is_err());
}
#[test]
fn forged_or_wrong_signer_signature_rejected(){
    let mut x=baseline();
    sign_checkpoint(&mut x,&signing_key(99));
    assert!(verify_attestation(&x).is_err());
    let mut x=baseline();
    x.signed_checkpoint.payload.signer_key_id="unknown".into();
    assert!(verify_attestation(&x).is_err());
    let mut x=baseline();
    x.signed_registry.payload.signers[0].public_key_hex =
        hex::encode(signing_key(99).verifying_key().to_bytes());
    sign_root(&mut x,&signing_key(7));
    assert!(verify_attestation(&x).is_err());
}
#[test]
fn all_namespace_case_and_epoch_bindings_are_exact(){
    let mut x=baseline();
    x.policy.expected_namespace="other".into();
    assert!(verify_attestation(&x).is_err());
    let mut x=baseline();
    x.policy.expected_case_id="other".into();
    assert!(verify_attestation(&x).is_err());
    let mut x=baseline();
    x.policy.minimum_registry_epoch=6;
    assert!(verify_attestation(&x).is_err());
    let mut x=baseline();
    x.signed_checkpoint.payload.registry_epoch=4;
    sign_checkpoint(&mut x,&signing_key(8));
    assert!(verify_attestation(&x).is_err());
}
#[test]
fn monotonic_receipt_floor_rejects_old_valid_checkpoint(){
    let mut x=baseline();x.policy.minimum_receipt_count=5;
    assert!(verify_attestation(&x).is_err());
}
#[test]
fn pinned_out_of_band_prefix_detects_rewritten_validly_signed_fork(){
    let mut x=baseline();
    let prior=prefix(&x,2);
    x.policy.prior_checkpoint=Some(prior);
    assert!(verify_attestation(&x).unwrap().prefix_anchor_checked);
    let mut altered=vec![];
    altered.push(next_receipt(&altered,AuditOperation::Staged,"altered",&h(b'a'),None,None).unwrap());
    altered.push(next_receipt(&altered,AuditOperation::Published,"altered",&h(b'a'),None,Some(h(b'1'))).unwrap());
    altered.push(next_receipt(&altered,AuditOperation::Staged,"g2",&h(b'b'),Some(h(b'1')),Some(h(b'1'))).unwrap());
    altered.push(next_receipt(&altered,AuditOperation::Published,"g2",&h(b'b'),Some(h(b'1')),Some(h(b'2'))).unwrap());
    x.receipts=altered;
    let final_report=verify_receipts(&x.receipts,None).unwrap();
    x.signed_checkpoint.payload.tip_sha256=final_report.tip_sha256.unwrap();
    sign_checkpoint(&mut x,&signing_key(8));
    // A valid delegate signature is insufficient to replace an already pinned prefix.
    assert!(verify_attestation(&x).is_err());
    x.policy.prior_checkpoint=None;
    assert!(verify_attestation(&x).is_ok());
}
#[test]
fn checkpoint_tip_head_or_count_tampering_is_detected(){
    let mut x=baseline();
    x.signed_checkpoint.payload.tip_sha256=h(b'f');
    sign_checkpoint(&mut x,&signing_key(8));
    assert!(verify_attestation(&x).is_err());
    let mut x=baseline();
    x.signed_checkpoint.payload.last_head_sha256=Some(h(b'f'));
    sign_checkpoint(&mut x,&signing_key(8));
    assert!(verify_attestation(&x).is_err());
    let mut x=baseline();
    x.signed_checkpoint.payload.count=3;
    sign_checkpoint(&mut x,&signing_key(8));
    assert!(verify_attestation(&x).is_err());
}
#[test]
fn duplicate_key_ids_and_public_keys_are_rejected(){
    let mut x=baseline();
    x.signed_registry.payload.signers.push(x.signed_registry.payload.signers[0].clone());
    sign_root(&mut x,&signing_key(7));
    assert!(verify_attestation(&x).is_err());
    let mut x=baseline();
    let mut clone=x.signed_registry.payload.signers[0].clone();
    clone.key_id="different-id".into();
    x.signed_registry.payload.signers.push(clone);
    sign_root(&mut x,&signing_key(7));
    assert!(verify_attestation(&x).is_err());
}
#[test]
fn expired_policy_epoch_and_revoked_registry_fail_closed(){
    let mut x=baseline();x.signed_registry.payload.epoch=4;
    x.signed_checkpoint.payload.registry_epoch=4;
    sign_root(&mut x,&signing_key(7));sign_checkpoint(&mut x,&signing_key(8));
    assert!(verify_attestation(&x).is_err());
    let mut x=baseline();x.signed_registry.payload.signers[0].case_id="another-case".into();
    sign_root(&mut x,&signing_key(7));
    assert!(verify_attestation(&x).is_err());
}
#[test]
fn rfc8032_ed25519_verifier_known_vector(){
    // RFC 8032 section 7.1: empty message public key and signature.
    use ed25519_dalek::{Signature,Verifier,VerifyingKey};
    let pubkey=hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
    let arr:[u8;32]=pubkey.try_into().unwrap();
    let vk=VerifyingKey::from_bytes(&arr).unwrap();
    let sig=Signature::from_slice(&hex::decode(concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )).unwrap()).unwrap();
    assert!(vk.verify(b"",&sig).is_ok());
}
