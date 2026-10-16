//! GALIA P5 Rust v0.7: offline review-signature structural verifier.
//! NO verified human identity, no promotions, no P2 guards, no persistence.
//! Only independently pinned root keys/epochs and trusted replay state can
//! justify anything beyond cryptographic consistency of *supplied* envelopes.
use std::collections::BTreeSet;
use serde::{Deserialize,Serialize};
use ed25519_dalek::{Signature,Verifier,VerifyingKey};
use crate::authority::{AuthorityScope,PromotionAuthorization,matches_target};
use crate::attestation::signing_preimage;

pub const REVIEW_REGISTRY_FORMAT: &str="GALIA_NONCANONICAL_REVIEW_REGISTRY_V1";
pub const REVIEW_DECISION_FORMAT: &str="GALIA_NONCANONICAL_SIGNED_REVIEW_V1";
pub const REVIEW_REGISTRY_DOMAIN: &[u8]=b"GALIA_REVIEW_REGISTRY_V1\0";
pub const REVIEW_DECISION_DOMAIN: &[u8]=b"GALIA_REVIEW_DECISION_V1\0";

fn required(x:&str)->bool{!x.trim().is_empty()&&!x.chars().any(|c|c.is_control())}
fn low_hex(x:&str,n:usize)->bool{
    x.len()==n && x.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
}
fn key(hex_string:&str)->Result<VerifyingKey,String>{
    if !low_hex(hex_string,64){return Err("invalid lowercase Ed25519 key".into())}
    let bytes=hex::decode(hex_string).map_err(|_|"invalid key encoding")?;
    let arr:[u8;32]=bytes.try_into().map_err(|_|"invalid Ed25519 key length")?;
    VerifyingKey::from_bytes(&arr).map_err(|_|"invalid Ed25519 public key".into())
}
fn verify_signature(public_key:&str,signature:&str,domain:&[u8],value:&impl Serialize)->Result<(),String>{
    let vk=key(public_key)?;
    if !low_hex(signature,128){return Err("invalid Ed25519 signature encoding".into())}
    let raw=hex::decode(signature).map_err(|_|"invalid signature")?;
    let sig=Signature::from_slice(&raw).map_err(|_|"invalid signature length")?;
    vk.verify(&signing_preimage(domain,value)?,&sig)
        .map_err(|_|"signature mismatch".into())
}
fn unique_ids(items:&[String])->bool{
    let mut seen=BTreeSet::new();
    items.iter().all(|v|required(v) && seen.insert(v.as_str()))
}
#[derive(Clone,Debug,Eq,PartialEq,Serialize,Deserialize)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub enum ReviewDecisionKind {Select,Hold,Reject}

#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredReviewer {
    pub key_id:String,
    pub reviewer_id:String,
    pub public_key_hex:String,
    pub case_id:String,
    pub target_type:String,
    pub revoked:bool,
}

#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRegistry {
    pub format:String,
    pub namespace:String,
    pub case_id:String,
    pub epoch:u64,
    pub keys:Vec<RegisteredReviewer>,
    pub revoked_authorization_ids:Vec<String>,
    /// Root-signed replay snapshot; cannot claim the latest snapshot without
    /// an independently pinned registry epoch and external witness.
    pub consumed_authorization_ids:Vec<String>,
    pub consumed_nonce_sha256:Vec<String>,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReviewRegistry {
    pub payload:ReviewRegistry,
    pub root_signature_hex:String,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewPayload {
    pub format:String,
    pub namespace:String,
    pub case_id:String,
    pub registry_epoch:u64,
    pub reviewer_key_id:String,
    pub decision:ReviewDecisionKind,
    pub authorization:PromotionAuthorization,
    pub manifest_sha256:String,
    pub nonce_sha256:String,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReviewDecision {
    pub payload:ReviewPayload,
    pub reviewer_signature_hex:String,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewVerificationPolicy {
    /// Must be provisioned independently; caller input is NOT evidence of origin.
    pub pinned_root_public_key_hex:String,
    pub expected_namespace:String,
    pub expected_scope:AuthorityScope,
    pub expected_target_commit:String,
    pub expected_decision_id:String,
    pub expected_manifest_sha256:String,
    pub expected_policy_version:String,
    pub minimum_registry_epoch:u64,
    /// Caller-supplied external replay fences: useful only when independently
    /// fetched from authoritative, monotonically increasing witness storage.
    pub independently_spent_authorization_ids:Vec<String>,
    pub independently_spent_nonce_sha256:Vec<String>,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewVerificationRequest {
    pub policy:ReviewVerificationPolicy,
    pub registry:SignedReviewRegistry,
    pub decision:SignedReviewDecision,
}
#[derive(Clone,Debug,Serialize)]
pub struct ReviewVerificationReport {
    pub status:&'static str,
    pub review_signature_valid:bool,
    pub active_registered_key:bool,
    pub exact_scope_matched:bool,
    pub replay_fences_checked:bool,
    pub registry_epoch:u64,
    pub authorization_id:String,
    pub human_identity_verified:bool,
    pub human_authority_verified:bool,
    pub executable_guards_issued:bool,
    pub canonical_writeback:bool,
    pub authority_transfer:bool,
    pub output_commit:Option<String>,
}

/// Verifies *only* structurally scoped signatures relative to caller-supplied
/// trust/replay inputs. Does not emit promotion guards or consume nonce.
pub fn verify_review(request:&ReviewVerificationRequest)->Result<ReviewVerificationReport,String>{
    let policy=&request.policy;
    let registry=&request.registry.payload;
    let decision=&request.decision.payload;
    let auth=&decision.authorization;

    policy.expected_scope.validate().map_err(str::to_string)?;
    auth.validate().map_err(str::to_string)?;
    if !required(&policy.expected_namespace)
        || !required(&policy.expected_target_commit)
        || !required(&policy.expected_decision_id)
        || !required(&policy.expected_policy_version)
        || !low_hex(&policy.expected_manifest_sha256,64)
        || !unique_ids(&policy.independently_spent_authorization_ids)
        || !policy.independently_spent_nonce_sha256.iter().all(|s|low_hex(s,64))
        || policy.independently_spent_nonce_sha256.iter().collect::<BTreeSet<_>>().len()
            !=policy.independently_spent_nonce_sha256.len(){
        return Err("invalid expected scope, hash or external replay fences".into())
    }
    // Trust root verification precedes use of any delegated review key.
    verify_signature(&policy.pinned_root_public_key_hex,
        &request.registry.root_signature_hex,REVIEW_REGISTRY_DOMAIN,registry)?;

    if registry.format!=REVIEW_REGISTRY_FORMAT
        || !required(&registry.namespace)
        || !required(&registry.case_id)
        || registry.namespace!=policy.expected_namespace
        || registry.case_id!=policy.expected_scope.case_id
        || registry.epoch==0 || registry.epoch<policy.minimum_registry_epoch
        || registry.keys.is_empty()
        || !unique_ids(&registry.revoked_authorization_ids)
        || !unique_ids(&registry.consumed_authorization_ids)
        || !registry.consumed_nonce_sha256.iter().all(|s|low_hex(s,64))
        || registry.consumed_nonce_sha256.iter().collect::<BTreeSet<_>>().len()
            !=registry.consumed_nonce_sha256.len(){
        return Err("root registry invalid or rolled back".into())
    }
    let mut ids=BTreeSet::new();
    let mut pubkeys=BTreeSet::new();
    for record in &registry.keys {
        if !required(&record.key_id)||!required(&record.reviewer_id)
            || record.case_id!=registry.case_id
            || !required(&record.target_type)
            || !ids.insert(record.key_id.as_str())
            || !pubkeys.insert(record.public_key_hex.as_str())
            || record.public_key_hex==policy.pinned_root_public_key_hex {
            return Err("invalid, reused or root-equivalent reviewer key".into())
        }
        key(&record.public_key_hex)?;
    }
    if decision.format!=REVIEW_DECISION_FORMAT
        || decision.namespace!=registry.namespace
        || decision.case_id!=registry.case_id
        || decision.registry_epoch!=registry.epoch
        || !required(&decision.reviewer_key_id)
        || decision.decision!=ReviewDecisionKind::Select
        || !low_hex(&decision.manifest_sha256,64)
        || !low_hex(&decision.nonce_sha256,64)
        || decision.manifest_sha256!=policy.expected_manifest_sha256
        || !matches_target(auth,&policy.expected_scope,&policy.expected_scope.case_id,
            &policy.expected_decision_id,&policy.expected_target_commit,
            &policy.expected_policy_version){
        return Err("review decision not bound to exact select/case/target/policy/manifest".into())
    }
    let reviewer=registry.keys.iter().find(|x|x.key_id==decision.reviewer_key_id)
        .ok_or("unknown reviewer key")?;
    if reviewer.revoked
        || reviewer.reviewer_id!=auth.reviewer
        || reviewer.target_type!=policy.expected_scope.target_type {
        return Err("reviewer key revoked, identity or target_type mismatch".into())
    }
    if registry.revoked_authorization_ids.contains(&auth.authorization_id)
        || registry.consumed_authorization_ids.contains(&auth.authorization_id)
        || registry.consumed_nonce_sha256.contains(&decision.nonce_sha256)
        || policy.independently_spent_authorization_ids.contains(&auth.authorization_id)
        || policy.independently_spent_nonce_sha256.contains(&decision.nonce_sha256){
        return Err("revoked or previously consumed review authorization/nonce".into())
    }
    verify_signature(&reviewer.public_key_hex,
        &request.decision.reviewer_signature_hex,REVIEW_DECISION_DOMAIN,decision)?;
    Ok(ReviewVerificationReport{
        status:"REVIEW_SIGNATURE_STRUCTURALLY_VALID_ADVISORY_ONLY",
        review_signature_valid:true,active_registered_key:true,
        exact_scope_matched:true,replay_fences_checked:true,
        registry_epoch:registry.epoch,authorization_id:auth.authorization_id.clone(),
        human_identity_verified:false,human_authority_verified:false,
        executable_guards_issued:false,canonical_writeback:false,
        authority_transfer:false,output_commit:None,
    })
}
