//! GALIA v0.29 — OFFLINE evidence of a fork in ONE auditor's signed log.
//! Two complete signed audit branches from the SAME independently pinned
//! floor are verified before any comparison. A difference at one audit
//! sequence is evidence that the pinned key signed two incompatible audit
//! envelopes, NOT proof that either reported historical event happened.
//! No gossip/network, third-party custody, freshness, repairs or P5 authority.
use serde::{Deserialize,Serialize};
use crate::audit::sha256;
use crate::independent_audit::{
    AuditTrustPin,SignedAuditStatement,verify_signed_audit_chain,
};

fn canonical<T:Serialize>(v:&T)->Result<Vec<u8>,String>{
    serde_json::to_value(v).and_then(|v|serde_json::to_vec(&v))
        .map_err(|e|e.to_string())
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub enum AuditBranchFinding{
    IdenticalSignedHistory,
    VerifiedPrefixExtension,
    SignedAuditorForkEvidence,
}
#[derive(Clone,Debug,Serialize)]
pub struct SignedAuditorForkEvidence{
    pub first_conflicting_sequence:u64,
    pub shared_previous_signed_sha256:Option<String>,
    pub left_signed_sha256:String,
    pub right_signed_sha256:String,
    pub left:SignedAuditStatement,
    pub right:SignedAuditStatement,
    pub signed_checkpoint_diverged:bool,
    pub same_independently_pinned_auditor_key:bool,
    pub both_signatures_validated:bool,
    pub real_independent_auditor_custody_verified:bool,
    pub canonical_writeback:bool,
}
#[derive(Clone,Debug,Serialize)]
pub struct AuditBranchAssessment{
    pub status:&'static str,
    pub finding:AuditBranchFinding,
    pub shared_signed_prefix_count:usize,
    pub left_last_audit_sequence:u64,
    pub right_last_audit_sequence:u64,
    pub left_last_signed_sha256:String,
    pub right_last_signed_sha256:String,
    pub fork:Option<SignedAuditorForkEvidence>,
    pub independent_custody_verified:bool,
    pub real_public_gossip_verified:bool,
    pub signed_statements_prove_historical_truth:bool,
    pub automatic_quarantine_or_repair_permitted:bool,
    pub human_authority_verified:bool,
    pub canonical_writeback:bool,
    pub authority_transfer:bool,
}
/// Evidence is valid ONLY relative to one externally provisioned signer/floor.
/// Requiring both histories to extend the SAME pinned floor eliminates
/// misleading comparisons between unrelated auditor epochs. A proper prefix
/// is NOT evidence of a fork. A disagreement at the same sequence is proof
/// of two separately valid signed claims, but not independently verified
/// audit signing key custody, publication, freshness or historical truth.
pub fn compare_signed_audit_branches(
    pin:&AuditTrustPin,
    left:&[SignedAuditStatement],
    right:&[SignedAuditStatement],
)->Result<AuditBranchAssessment,String>{
    // A hex case change encodes the SAME Ed25519 signature, not a second
    // contradictory auditor attestation. Fail closed on noncanonical signature
    // representations rather than manufacturing a false fork finding.
    for record in left.iter().chain(right.iter()){
        if record.signature_hex.len()!=128||
            !record.signature_hex.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c)){
            return Err("noncanonical Ed25519 signature hex in audit branch".into())
        }
    }
    let (_,left_tip)=verify_signed_audit_chain(pin,left)?;
    let (_,right_tip)=verify_signed_audit_chain(pin,right)?;
    let mut common=0usize;
    let min=left.len().min(right.len());
    for i in 0..min{
        if canonical(&left[i])?==canonical(&right[i])?{
            common+=1;
        }else{
            break;
        }
    }
    let fork=if common<min{
        let a=&left[common];
        let b=&right[common];
        // The verifier required continuous sequence and signatures from one
        // pinned signer. Because all earlier envelopes are identical, the two
        // competing envelopes MUST have the same immediate predecessor.
        if a.statement.sequence!=b.statement.sequence||
            a.statement.previous_signed_sha256!=b.statement.previous_signed_sha256{
            return Err("signed branches do not share an authenticated predecessor".into())
        }
        let ah=sha256(&canonical(a)?);
        let bh=sha256(&canonical(b)?);
        if ah==bh{
            return Err("fork evidence requires distinct signed envelopes".into())
        }
        Some(SignedAuditorForkEvidence{
            first_conflicting_sequence:a.statement.sequence,
            shared_previous_signed_sha256:a.statement.previous_signed_sha256.clone(),
            left_signed_sha256:ah,right_signed_sha256:bh,
            left:a.clone(),right:b.clone(),
            signed_checkpoint_diverged:a.statement.checkpoint!=b.statement.checkpoint,
            same_independently_pinned_auditor_key:true,
            both_signatures_validated:true,
            real_independent_auditor_custody_verified:false,
            canonical_writeback:false,
        })
    }else{None};
    let finding=if fork.is_some(){AuditBranchFinding::SignedAuditorForkEvidence}
        else if left.len()==right.len(){AuditBranchFinding::IdenticalSignedHistory}
        else{AuditBranchFinding::VerifiedPrefixExtension};
    Ok(AuditBranchAssessment{
        status:"OFFLINE_SIGNED_AUDITOR_BRANCH_COMPARISON_ADVISORY_ONLY",
        finding,
        shared_signed_prefix_count:common,
        left_last_audit_sequence:left.last().ok_or("empty left audit")?.statement.sequence,
        right_last_audit_sequence:right.last().ok_or("empty right audit")?.statement.sequence,
        left_last_signed_sha256:left_tip,right_last_signed_sha256:right_tip,
        fork,
        independent_custody_verified:false,
        real_public_gossip_verified:false,
        signed_statements_prove_historical_truth:false,
        automatic_quarantine_or_repair_permitted:false,
        human_authority_verified:false,
        canonical_writeback:false,
        authority_transfer:false,
    })
}
