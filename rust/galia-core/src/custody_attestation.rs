//! GALIA v0.32: OFFLINE separately pinned custodian signatures over an
//! independently replay-verified local fork-publication journal.
//!
//! This module has NO independent real-world custodian, signing keys, network
//! client/server, delivery acknowledgment, public registry, human authority,
//! global transparency consensus, or canonical storage/write path.
//! ALL key identities, roster roots, signed receipts and historical floors
//! are supplied by the caller. Signature validity != independent custody.
use serde::{Deserialize,Serialize};
use crate::audit::sha256;
use crate::fork_publication::{PublicationCheckpoint,PublishedForkBundle,ScratchForkPublication};
use crate::independent_audit::AuditTrustPin;
use crate::fork_witness::ForkWitnessPolicy;
use crate::witness_proof::{validate_public_key,verify_detached};

pub const CUSTODY_RECEIPT_FORMAT:&str="GALIA_NONCANONICAL_FORK_CUSTODY_RECEIPT_V1";
pub const CUSTODY_RECEIPT_DOMAIN:&[u8]=b"GALIA_NONCANONICAL_FORK_CUSTODY_RECEIPT_V1\0";
fn canonical<T:Serialize>(value:&T)->Result<Vec<u8>,String>{
    serde_json::to_value(value).and_then(|v|serde_json::to_vec(&v))
        .map_err(|e|e.to_string())
}
fn is_hash(s:&str)->bool{
    s.len()==64&&s.bytes().all(|v|v.is_ascii_digit()||(b'a'..=b'f').contains(&v))
}
fn is_id(s:&str)->bool{!s.trim().is_empty()&&s.len()<=256&&!s.chars().any(|x|x.is_control())}
/// This trust root MUST be provisioned OUTSIDE BOTH the local scratch
/// publication journal and any custody service being checked.
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodianTrustPin{
    pub custodian_id:String,
    pub custodian_public_key_hex:String,
    pub publication_stream_id:String,
    pub audit_pin_sha256:String,
    pub witness_policy_sha256:String,
    pub floor_receipt_sequence:u64,
    pub floor_receipt_sha256:Option<String>,
    pub floor_publication_checkpoint:PublicationCheckpoint,
}
impl CustodianTrustPin{
    pub fn validate(&self,audit:&AuditTrustPin,witness:&ForkWitnessPolicy)->Result<(),String>{
        witness.validate(audit)?;
        self.floor_publication_checkpoint.validate()?;
        if !is_id(&self.custodian_id)||
            self.publication_stream_id!=audit.stream_id||
            self.audit_pin_sha256!=sha256(&canonical(audit)?)||
            self.witness_policy_sha256!=sha256(&canonical(witness)?)||
            !is_hash(&self.audit_pin_sha256)||!is_hash(&self.witness_policy_sha256)||
            (self.floor_receipt_sequence==0)!=self.floor_receipt_sha256.is_none()||
            self.floor_receipt_sha256.as_ref().is_some_and(|s|!is_hash(s))||
            (self.floor_receipt_sequence==0&&
             self.floor_publication_checkpoint.entry_count!=0){
            return Err("independently pinned custodian scope or historical floor mismatch".into())
        }
        validate_public_key(&self.custodian_public_key_hex)?;
        if self.custodian_public_key_hex==audit.auditor_public_key_hex||
            self.custodian_public_key_hex==audit.scope.pinned_response_signer_public_key_hex||
            witness.witnesses.iter().any(|w|w.public_key_hex==self.custodian_public_key_hex){
            return Err("custodian key aliases auditor, service signer or fork witness".into())
        }
        Ok(())
    }
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyReceiptPayload{
    pub format:String,
    pub custodian_id:String,
    pub publication_stream_id:String,
    pub audit_pin_sha256:String,
    pub witness_policy_sha256:String,
    pub sequence:u64,
    pub previous_signed_receipt_sha256:Option<String>,
    pub publication_checkpoint:PublicationCheckpoint,
    pub published_bundle_sha256:String,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCustodyReceipt{
    pub payload:CustodyReceiptPayload,
    pub signature_hex:String,
}
#[derive(Clone,Debug,Serialize)]
pub struct CustodyVerification{
    pub status:&'static str,
    pub latest_receipt_sequence:u64,
    pub latest_signed_receipt_sha256:String,
    pub latest_publication_checkpoint:PublicationCheckpoint,
    pub receipt_count:usize,
    pub all_historical_publication_prefixes_replayed:bool,
    pub externally_hosted_custodian_verified:bool,
    pub genuine_independent_signer_custody_verified:bool,
    pub live_external_publication_verified:bool,
    pub human_authority_verified:bool,
    pub canonical_writeback:bool,
    pub authority_transfer:bool,
}
/// Verify signed progression relative to independently pinned historical
/// counters. This does NOT establish that the custodian ever received bytes.
pub fn verify_receipt_chain(
    pin:&CustodianTrustPin,audit:&AuditTrustPin,witness:&ForkWitnessPolicy,
    signed:&[SignedCustodyReceipt]
)->Result<(Vec<PublicationCheckpoint>,String),String>{
    pin.validate(audit,witness)?;
    if signed.is_empty()||signed.len()>128{
        return Err("missing or oversized custodian signed receipt suffix".into())
    }
    let mut seq=pin.floor_receipt_sequence;
    let mut prior=pin.floor_receipt_sha256.clone();
    let mut publication=pin.floor_publication_checkpoint.clone();
    let mut reports=Vec::with_capacity(signed.len());
    for receipt in signed{
        let p=&receipt.payload;
        p.publication_checkpoint.validate()?;
        if p.format!=CUSTODY_RECEIPT_FORMAT||
            p.custodian_id!=pin.custodian_id||
            p.publication_stream_id!=pin.publication_stream_id||
            p.audit_pin_sha256!=pin.audit_pin_sha256||
            p.witness_policy_sha256!=pin.witness_policy_sha256||
            p.sequence!=seq.checked_add(1).ok_or("custody sequence overflow")?||
            p.previous_signed_receipt_sha256!=prior||
            p.publication_checkpoint.entry_count!=publication.entry_count
                .checked_add(1).ok_or("publication height overflow")?||
            !is_hash(&p.published_bundle_sha256){
            return Err("custody chain gap, receipt replay, scope or publication height mismatch".into())
        }
        verify_detached(&pin.custodian_public_key_hex,&receipt.signature_hex,
            CUSTODY_RECEIPT_DOMAIN,p)?;
        prior=Some(sha256(&canonical(receipt)?));
        seq=p.sequence;
        publication=p.publication_checkpoint.clone();
        reports.push(publication.clone());
    }
    Ok((reports,prior.ok_or("custody receipt chain is empty")?))
}
/// FULL local revalidation (audit signatures + fork witness quorum) of the
/// publication journal, AND each distinct historical signed custodian receipt.
/// Caller must supply separately protected historical pins to detect rollback.
/// No network or third-party deployment exists here.
pub fn verify_custody_against_local(
    store:&ScratchForkPublication,
    pin:&CustodianTrustPin,audit:&AuditTrustPin,witness:&ForkWitnessPolicy,
    signed:&[SignedCustodyReceipt],
)->Result<CustodyVerification,String>{
    let (checkpoints,last)=verify_receipt_chain(pin,audit,witness,signed)?;
    store.verify_floor(&pin.floor_publication_checkpoint)?;
    let bundles:Vec<PublishedForkBundle>=store.published()?; // fully revalidated
    for (checkpoint,receipt) in checkpoints.iter().zip(signed){
        let actual=store.verify_floor(checkpoint)?;
        if actual.entry_count<checkpoint.entry_count{
            return Err("local publication is truncated below signed custodian receipt".into())
        }
        let idx=usize::try_from(checkpoint.entry_count-1)
            .map_err(|_|"publication checkpoint index overflow")?;
        if sha256(&canonical(bundles.get(idx).ok_or("signed bundle not published locally")?)?)
            !=receipt.payload.published_bundle_sha256{
            return Err("custodian-signed bundle differs from local verified publication".into())
        }
    }
    Ok(CustodyVerification{
        status:"SIGNED_CUSTODY_RECEIPTS_MATCH_LOCAL_VERIFIED_FORKS_ADVISORY_ONLY",
        latest_receipt_sequence:signed.last().ok_or("missing receipt")?.payload.sequence,
        latest_signed_receipt_sha256:last,
        latest_publication_checkpoint:checkpoints.last().ok_or("missing checkpoint")?.clone(),
        receipt_count:signed.len(),
        all_historical_publication_prefixes_replayed:true,
        externally_hosted_custodian_verified:false,
        genuine_independent_signer_custody_verified:false,
        live_external_publication_verified:false,
        human_authority_verified:false,canonical_writeback:false,authority_transfer:false,
    })
}
#[derive(Clone,Debug,Serialize)]
pub struct TwoCustodianAssessment{
    pub status:&'static str,
    pub exact_terminal_publication_agreement:bool,
    pub distinct_pinned_custodian_keys:bool,
    pub signer_organizational_independence_verified:bool,
    pub real_public_gossip_verified:bool,
    pub automatic_recovery_permitted:bool,
    pub human_authority_verified:bool,
    pub canonical_writeback:bool,
    pub authority_transfer:bool,
}
/// Require TWO genuinely different pinned keys, not just different labels.
/// Equal verified terminal local publication checkpoint != public consensus.
pub fn assess_two_custodians(
    store:&ScratchForkPublication,audit:&AuditTrustPin,witness:&ForkWitnessPolicy,
    a_pin:&CustodianTrustPin,a:&[SignedCustodyReceipt],
    b_pin:&CustodianTrustPin,b:&[SignedCustodyReceipt],
)->Result<TwoCustodianAssessment,String>{
    if a_pin.custodian_id==b_pin.custodian_id||
       a_pin.custodian_public_key_hex==b_pin.custodian_public_key_hex{
        return Err("two custodian identities must have distinct externally pinned keys and IDs".into())
    }
    let left=verify_custody_against_local(store,a_pin,audit,witness,a)?;
    let right=verify_custody_against_local(store,b_pin,audit,witness,b)?;
    if left.latest_publication_checkpoint!=right.latest_publication_checkpoint{
        return Err("custodian receipts do not agree on exact terminal publication state".into())
    }
    Ok(TwoCustodianAssessment{
        status:"TWO_DISTINCT_PINNED_CUSTODIAN_SIGNATURES_MATCH_ADVISORY_ONLY",
        exact_terminal_publication_agreement:true,
        distinct_pinned_custodian_keys:true,
        signer_organizational_independence_verified:false,
        real_public_gossip_verified:false,automatic_recovery_permitted:false,
        human_authority_verified:false,canonical_writeback:false,authority_transfer:false,
    })
}
