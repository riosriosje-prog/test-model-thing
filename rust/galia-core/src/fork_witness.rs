//! GALIA v0.30 — OFFLINE observer countersignatures over verified auditor fork.
//!
//! A threshold of distinctly pinned Ed25519 keys can endorse the *same*
//! cryptographically verified, signed-auditor fork evidence. This does NOT
//! prove that keys are in independent human/organizational custody, that a
//! remote gossip/publication network exists, that either signed audit claim is
//! historically true, or that any automatic quarantine/repair is authorized.
//! Authority remains held by human review and canonical GALIA.
use std::collections::BTreeSet;
use serde::{Serialize,Deserialize};
use crate::audit::sha256;
use crate::audit_equivocation::{
    AuditBranchFinding,SignedAuditorForkEvidence,compare_signed_audit_branches,
};
use crate::independent_audit::{AuditTrustPin,SignedAuditStatement};
use crate::witness_proof::{validate_public_key,verify_detached};

pub const FORK_WITNESS_FORMAT:&str="GALIA_NONCANONICAL_AUDITOR_FORK_WITNESS_V1";
pub const FORK_WITNESS_DOMAIN:&[u8]=b"GALIA_AUDITOR_FORK_WITNESS_V1\0";

fn canonical<T:Serialize>(value:&T)->Result<Vec<u8>,String>{
    serde_json::to_value(value).and_then(|v|serde_json::to_vec(&v))
        .map_err(|e|e.to_string())
}
fn is_hash(s:&str)->bool{
    s.len()==64&&s.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c))
}
fn is_id(s:&str)->bool{
    !s.trim().is_empty()&&s.len()<=256&&!s.chars().any(|c|c.is_control())
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedForkWitness{
    pub observer_id:String,
    pub public_key_hex:String,
    pub revoked:bool,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForkWitnessPolicy{
    pub format:String,
    pub roster_epoch:u64,
    pub auditor_id:String,
    pub auditor_public_key_hex:String,
    pub audit_stream_id:String,
    pub audit_scope_sha256:String,
    pub required_distinct_observers:usize,
    pub witnesses:Vec<TrustedForkWitness>,
}
impl ForkWitnessPolicy{
    /// Caller must independently pin this policy and its roster epoch. A
    /// policy embedded inside a network request cannot authenticate itself.
    pub fn validate(&self,pin:&AuditTrustPin)->Result<(),String>{
        pin.validate()?;
        if self.format!=FORK_WITNESS_FORMAT||self.roster_epoch==0||
            self.auditor_id!=pin.auditor_id||
            self.auditor_public_key_hex!=pin.auditor_public_key_hex||
            self.audit_stream_id!=pin.stream_id||
            self.audit_scope_sha256!=sha256(&canonical(&pin.scope)?)||
            !is_hash(&self.audit_scope_sha256)||
            self.witnesses.len()>64||self.witnesses.is_empty()||
            self.required_distinct_observers<2 {
            return Err("invalid or unpinned fork witness policy".into())
        }
        let mut ids=BTreeSet::new();
        let mut keys=BTreeSet::new();
        let mut active=0usize;
        let mut last_id:Option<&str>=None;
        for w in &self.witnesses{
            if !is_id(&w.observer_id)||
                !ids.insert(w.observer_id.as_str())||
                !keys.insert(w.public_key_hex.as_str())||
                last_id.is_some_and(|previous|w.observer_id.as_str()<=previous)||
                w.public_key_hex==pin.auditor_public_key_hex||
                w.public_key_hex==pin.scope.pinned_response_signer_public_key_hex {
                return Err("duplicate/unsorted/role-confused fork witness identity".into())
            }
            validate_public_key(&w.public_key_hex)?;
            if !w.revoked{active+=1;}
            last_id=Some(&w.observer_id);
        }
        if self.required_distinct_observers>active{
            return Err("fork witness quorum exceeds active independently pinned keys".into())
        }
        Ok(())
    }
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForkWitnessPayload{
    pub format:String,
    pub roster_epoch:u64,
    pub observer_id:String,
    pub policy_sha256:String,
    pub auditor_floor_sequence:u64,
    pub auditor_floor_signed_sha256:Option<String>,
    pub audit_scope_sha256:String,
    pub first_conflicting_audit_sequence:u64,
    pub shared_previous_signed_sha256:Option<String>,
    pub left_signed_sha256:String,
    pub right_signed_sha256:String,
    pub full_fork_evidence_sha256:String,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedForkWitnessEndorsement{
    pub payload:ForkWitnessPayload,
    pub signature_hex:String,
}
/// Constructs bytes to countersign from independently verified branches.
/// Does NOT sign them or possess any witness private key.
pub fn expected_endorsement_payload(
    pin:&AuditTrustPin,policy:&ForkWitnessPolicy,
    left:&[SignedAuditStatement],right:&[SignedAuditStatement],
    observer_id:&str,
)->Result<ForkWitnessPayload,String>{
    policy.validate(pin)?;
    let assessment=compare_signed_audit_branches(pin,left,right)?;
    if assessment.finding!=AuditBranchFinding::SignedAuditorForkEvidence {
        return Err("no verified auditor fork to witness".into())
    }
    let fork=assessment.fork.ok_or("missing signed auditor fork evidence")?;
    if !policy.witnesses.iter().any(|w|w.observer_id==observer_id&&!w.revoked){
        return Err("unknown or revoked independent observer".into())
    }
    make_payload(pin,policy,&fork,observer_id)
}
fn make_payload(
    pin:&AuditTrustPin,policy:&ForkWitnessPolicy,
    fork:&SignedAuditorForkEvidence,observer_id:&str,
)->Result<ForkWitnessPayload,String>{
    Ok(ForkWitnessPayload{
        format:FORK_WITNESS_FORMAT.into(),
        roster_epoch:policy.roster_epoch,
        observer_id:observer_id.into(),
        policy_sha256:sha256(&canonical(policy)?),
        auditor_floor_sequence:pin.floor_sequence,
        auditor_floor_signed_sha256:pin.floor_signed_sha256.clone(),
        audit_scope_sha256:policy.audit_scope_sha256.clone(),
        first_conflicting_audit_sequence:fork.first_conflicting_sequence,
        shared_previous_signed_sha256:fork.shared_previous_signed_sha256.clone(),
        left_signed_sha256:fork.left_signed_sha256.clone(),
        right_signed_sha256:fork.right_signed_sha256.clone(),
        full_fork_evidence_sha256:sha256(&canonical(fork)?),
    })
}
#[derive(Clone,Debug,Serialize)]
pub struct ForkWitnessReport{
    pub status:&'static str,
    pub first_conflicting_audit_sequence:u64,
    pub fork_evidence_sha256:String,
    pub pinned_witness_policy_sha256:String,
    pub verified_distinct_observers:usize,
    pub required_distinct_observers:usize,
    pub quorum_met:bool,
    pub auditor_signatures_reverified:bool,
    pub witness_signatures_verified:bool,
    pub real_independent_witness_custody_verified:bool,
    pub real_public_gossip_verified:bool,
    pub historical_truth_verified:bool,
    pub automatic_quarantine_permitted:bool,
    pub automatic_repair_permitted:bool,
    pub human_authority_verified:bool,
    pub canonical_writeback:bool,
    pub authority_transfer:bool,
}
/// Verify a bounded quorum of distinct, non-revoked signed *claims* about one
/// specific fork. Empty, duplicate, unknown, and forged endorsements all
/// fail closed. A quorum of synthetic keys still proves NO real independence.
pub fn verify_fork_witness_quorum(
    pin:&AuditTrustPin,policy:&ForkWitnessPolicy,
    left:&[SignedAuditStatement],right:&[SignedAuditStatement],
    signed:&[SignedForkWitnessEndorsement],
)->Result<ForkWitnessReport,String>{
    policy.validate(pin)?;
    if signed.len()<policy.required_distinct_observers||
        signed.len()>policy.witnesses.len(){
        return Err("missing/oversized fork witness quorum".into())
    }
    let assessment=compare_signed_audit_branches(pin,left,right)?;
    if assessment.finding!=AuditBranchFinding::SignedAuditorForkEvidence{
        return Err("signatures cannot notarize a non-fork or proper extension".into())
    }
    let fork=assessment.fork.ok_or("missing fork evidence")?;
    let mut observed=BTreeSet::new();
    let mut previous_id:Option<&str>=None;
    for entry in signed{
        let id=entry.payload.observer_id.as_str();
        if previous_id.is_some_and(|s|id<=s)||!observed.insert(id) {
            return Err("duplicate or unsorted witness signature".into())
        }
        previous_id=Some(id);
        let trusted=policy.witnesses.iter()
            .find(|w|w.observer_id==id&&!w.revoked)
            .ok_or("unrecognized or revoked witness")?;
        let expected=make_payload(pin,policy,&fork,id)?;
        if canonical(&expected)?!=canonical(&entry.payload)?{
            return Err("witness statement binds another fork, scope, epoch or roster".into())
        }
        verify_detached(&trusted.public_key_hex,&entry.signature_hex,
            FORK_WITNESS_DOMAIN,&entry.payload)?;
    }
    Ok(ForkWitnessReport{
        status:"OFFLINE_DISTINCT_SIGNATURE_QUORUM_ADVISORY_ONLY",
        first_conflicting_audit_sequence:fork.first_conflicting_sequence,
        fork_evidence_sha256:sha256(&canonical(&fork)?),
        pinned_witness_policy_sha256:sha256(&canonical(policy)?),
        verified_distinct_observers:observed.len(),
        required_distinct_observers:policy.required_distinct_observers,
        quorum_met:true,auditor_signatures_reverified:true,
        witness_signatures_verified:true,
        real_independent_witness_custody_verified:false,
        real_public_gossip_verified:false,historical_truth_verified:false,
        automatic_quarantine_permitted:false,automatic_repair_permitted:false,
        human_authority_verified:false,canonical_writeback:false,
        authority_transfer:false,
    })
}
