//! GALIA v0.34 — OFFLINE independently pinned keys countersign a digest
//! of SAME-KEY Ed25519 custodian contradiction evidence. This is an ADVISORY
//! cryptographic corroboration only: NOT third-party delivery, operator
//! independence, public witnessing, consensus, historical truth, P5 authority,
//! automatic quarantine/repair, or canonical writeback.
//! No network, private keys, persistence, trusted clock, or signer custody.
use std::collections::{BTreeMap,BTreeSet};
use serde::{Deserialize,Serialize};
use crate::audit::sha256;
use crate::custody_attestation::{CustodianTrustPin,SignedCustodyReceipt};
use crate::custody_equivocation::{
    assess_custodian_fork,CustodyForkClassification,CustodyForkAssessment
};
use crate::independent_audit::AuditTrustPin;
use crate::fork_witness::ForkWitnessPolicy;
use crate::witness_proof::{validate_public_key,verify_detached};

pub const DISCLOSURE_FORMAT:&str="GALIA_NONCANONICAL_CUSTODY_CONTRADICTION_DISCLOSURE_V1";
pub const DISCLOSURE_DOMAIN:&[u8]=b"GALIA_CUSTODY_CONTRADICTION_DISCLOSURE_V1\0";
fn canonical<T:Serialize>(v:&T)->Result<Vec<u8>,String>{
    serde_json::to_value(v).and_then(|v|serde_json::to_vec(&v))
        .map_err(|e|e.to_string())
}
fn hash(v:&str)->bool{v.len()==64&&v.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c))}
fn ident(v:&str)->bool{!v.trim().is_empty()&&v.len()<=256&&!v.chars().any(|c|c.is_control())}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosureObserver{
    pub observer_id:String,
    pub public_key_hex:String,
    pub revoked:bool,
}
/// Exact auditor/witness/custodian pins and reporter roster MUST come from
/// independent trusted provisioning, never from the same wire claim.
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosurePolicy{
    pub format:String,
    pub roster_epoch:u64,
    pub custodian_id:String,
    pub custodian_trust_sha256:String,
    pub audit_trust_sha256:String,
    pub witness_policy_sha256:String,
    pub required_distinct_signers:usize,
    pub observers:Vec<DisclosureObserver>,
}
impl DisclosurePolicy{
    pub fn validate(&self,pin:&CustodianTrustPin,audit:&AuditTrustPin,
        witnesses:&ForkWitnessPolicy)->Result<(),String>{
        pin.validate(audit,witnesses)?;
        if self.format!=DISCLOSURE_FORMAT||self.roster_epoch==0||
            self.custodian_id!=pin.custodian_id||
            self.custodian_trust_sha256!=sha256(&canonical(pin)?)||
            self.audit_trust_sha256!=sha256(&canonical(audit)?)||
            self.witness_policy_sha256!=sha256(&canonical(witnesses)?)||
            !hash(&self.custodian_trust_sha256)||
            !hash(&self.audit_trust_sha256)||!hash(&self.witness_policy_sha256)||
            self.observers.is_empty()||self.observers.len()>32||
            self.required_distinct_signers<2{
            return Err("disclosure roster not independently pinned to exact custody scope".into())
        }
        let mut ids=BTreeSet::new();
        let mut keys=BTreeSet::new();
        let mut previous:Option<&str>=None;
        let mut active=0usize;
        for o in &self.observers{
            if !ident(&o.observer_id)||
                previous.is_some_and(|id|o.observer_id.as_str()<=id)||
                !ids.insert(o.observer_id.as_str())||
                !keys.insert(o.public_key_hex.as_str())||
                o.public_key_hex==pin.custodian_public_key_hex||
                o.public_key_hex==audit.auditor_public_key_hex||
                o.public_key_hex==audit.scope.pinned_response_signer_public_key_hex||
                witnesses.witnesses.iter().any(|w|w.public_key_hex==o.public_key_hex){
                return Err("duplicate/unsorted/reused disclosure signing role".into())
            }
            validate_public_key(&o.public_key_hex)?;
            if !o.revoked{active+=1;}
            previous=Some(&o.observer_id);
        }
        if self.required_distinct_signers>active {
            return Err("insufficient active independently pinned disclosure keys".into())
        }
        Ok(())
    }
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct DisclosureSubject{
    pub custodian_id:String,
    pub custodian_trust_sha256:String,
    pub conflicting_sequence:u64,
    pub common_prior_sequence:u64,
    pub common_previous_signed_sha256:Option<String>,
    /// Sorted lexical order so reversing the two branches is NOT new evidence.
    pub first_signed_envelope_sha256:String,
    pub second_signed_envelope_sha256:String,
    pub signed_claim_pair_sha256:String,
}
/// Compute the subject only after BOTH complete receipt chains are verified.
/// Prefix extensions, same receipts and unverified/synthetic claims are
/// rejected; no disclosure quorum can turn non-conflict into a finding.
pub fn subject_for_fork(
    pin:&CustodianTrustPin,audit:&AuditTrustPin,witnesses:&ForkWitnessPolicy,
    left:&[SignedCustodyReceipt],right:&[SignedCustodyReceipt],
)->Result<(DisclosureSubject,CustodyForkAssessment),String>{
    let assessment=assess_custodian_fork(pin,audit,witnesses,left,right)?;
    if assessment.classification!=CustodyForkClassification::ConflictingSignedCustodianClaims||
       !assessment.contradictory_signed_claims_verified{
        return Err("custodian receipts have no verified same-key contradiction".into())
    }
    let mut hashes=[
        assessment.left_signed_envelope_sha256.clone().ok_or("missing first signed envelope")?,
        assessment.right_signed_envelope_sha256.clone().ok_or("missing second signed envelope")?,
    ];
    hashes.sort();
    if !hash(&hashes[0])||!hash(&hashes[1])||hashes[0]==hashes[1]{
        return Err("invalid or identical competing signed receipt digests".into())
    }
    let sequence=assessment.conflicting_sequence.ok_or("missing conflicting sequence")?;
    let common=assessment.common_previous_signed_sha256.clone();
    if common.as_ref().is_some_and(|x|!hash(x)){
        return Err("invalid signed predecessor digest".into())
    }
    #[derive(Serialize)]
    struct Pair<'a>{custodian_trust_sha256:&'a str,sequence:u64,
        common_previous_signed_sha256:&'a Option<String>,
        a:&'a str,b:&'a str}
    let pin_hash=sha256(&canonical(pin)?);
    let pair=sha256(&canonical(&Pair{
        custodian_trust_sha256:&pin_hash,sequence,
        common_previous_signed_sha256:&common,
        a:&hashes[0],b:&hashes[1],
    })?);
    Ok((DisclosureSubject{
        custodian_id:pin.custodian_id.clone(),
        custodian_trust_sha256:pin_hash,
        conflicting_sequence:sequence,
        common_prior_sequence:assessment.common_prior_sequence,
        common_previous_signed_sha256:common,
        first_signed_envelope_sha256:hashes[0].clone(),
        second_signed_envelope_sha256:hashes[1].clone(),
        signed_claim_pair_sha256:pair,
    },assessment))
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosureEndorsementPayload{
    pub format:String,
    pub observer_id:String,
    pub roster_epoch:u64,
    pub policy_sha256:String,
    pub subject:DisclosureSubject,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDisclosureEndorsement{
    pub payload:DisclosureEndorsementPayload,
    pub signature_hex:String,
}
pub fn expected_endorsement(
    policy:&DisclosurePolicy,observer_id:&str,
    subject:&DisclosureSubject
)->Result<DisclosureEndorsementPayload,String>{
    if !ident(observer_id){return Err("invalid disclosure observer ID".into())}
    Ok(DisclosureEndorsementPayload{
        format:DISCLOSURE_FORMAT.into(),observer_id:observer_id.into(),
        roster_epoch:policy.roster_epoch,
        policy_sha256:sha256(&canonical(policy)?),
        subject:subject.clone(),
    })
}
#[derive(Clone,Debug,Serialize)]
pub struct DisclosureAssessment{
    pub status:&'static str,
    pub custodian_id:String,
    pub conflicting_sequence:u64,
    pub signed_claim_pair_sha256:String,
    pub observer_count:usize,
    pub distinct_pinned_signing_keys_verified:bool,
    pub signed_custodian_contradiction_verified:bool,
    pub real_witness_organizational_independence_verified:bool,
    pub independent_public_delivery_verified:bool,
    pub public_consensus_verified:bool,
    pub human_culpability_established:bool,
    pub automatic_quarantine_permitted:bool,
    pub automatic_repair_permitted:bool,
    pub human_authority_verified:bool,
    pub canonical_writeback:bool,
    pub authority_transfer:bool,
}
pub fn assess_disclosures(
    pin:&CustodianTrustPin,audit:&AuditTrustPin,witnesses:&ForkWitnessPolicy,
    policy:&DisclosurePolicy,left:&[SignedCustodyReceipt],
    right:&[SignedCustodyReceipt],endorsements:&[SignedDisclosureEndorsement],
)->Result<DisclosureAssessment,String>{
    policy.validate(pin,audit,witnesses)?;
    let (subject,_fork)=subject_for_fork(pin,audit,witnesses,left,right)?;
    if endorsements.len()<policy.required_distinct_signers||
        endorsements.len()>policy.observers.len(){
        return Err("insufficient or excessive disclosure endorsements".into())
    }
    let lookup:BTreeMap<&str,&DisclosureObserver>=policy.observers.iter()
        .map(|o|(o.observer_id.as_str(),o)).collect();
    let mut ids=BTreeSet::new();
    for signed in endorsements {
        let obs=lookup.get(signed.payload.observer_id.as_str())
            .ok_or("unrecognized disclosure observer")?;
        if obs.revoked||!ids.insert(obs.observer_id.as_str()){
            return Err("revoked or duplicate disclosure signer".into())
        }
        let expected=expected_endorsement(policy,&obs.observer_id,&subject)?;
        if canonical(&signed.payload)?!=canonical(&expected)?{
            return Err("endorsement does not attest the EXACT verified conflict".into())
        }
        verify_detached(&obs.public_key_hex,&signed.signature_hex,
            DISCLOSURE_DOMAIN,&signed.payload)?;
    }
    if ids.len()<policy.required_distinct_signers{
        return Err("distinct active disclosure-signature quorum not met".into())
    }
    Ok(DisclosureAssessment{
        status:"PINNED_DISCLOSURE_KEYS_SIGN_EXACT_CUSTODY_CONFLICT_ADVISORY_ONLY",
        custodian_id:pin.custodian_id.clone(),
        conflicting_sequence:subject.conflicting_sequence,
        signed_claim_pair_sha256:subject.signed_claim_pair_sha256,
        observer_count:ids.len(),distinct_pinned_signing_keys_verified:true,
        signed_custodian_contradiction_verified:true,
        real_witness_organizational_independence_verified:false,
        independent_public_delivery_verified:false,
        public_consensus_verified:false,human_culpability_established:false,
        automatic_quarantine_permitted:false,automatic_repair_permitted:false,
        human_authority_verified:false,canonical_writeback:false,
        authority_transfer:false,
    })
}
