//! GALIA v0.33: OFFLINE cryptographic evidence of a *single pinned custodian
//! signing conflicting receipts*. This proves contradictory Ed25519 claims
//! relative to a caller-supplied key, NOT operator identity, real delivery,
//! custodial independence, human intent, or historic source validity.
//! No private keys, network, persistence, automatic repair or canonical writes.
use serde::Serialize;
use crate::audit::sha256;
use crate::custody_attestation::{
    CustodianTrustPin,SignedCustodyReceipt,verify_receipt_chain,
};
use crate::independent_audit::AuditTrustPin;
use crate::fork_witness::ForkWitnessPolicy;

fn canonical<T:Serialize>(x:&T)->Result<Vec<u8>,String>{
    serde_json::to_value(x).and_then(|v|serde_json::to_vec(&v))
        .map_err(|e|e.to_string())
}
#[derive(Clone,Debug,Serialize,PartialEq,Eq)]
pub enum CustodyForkClassification{
    /// Two independently verified receipts describe identical signed payloads.
    SameSignedClaims,
    /// One chain is a valid prefix of the other. Does not prove equivocation.
    VerifiedPrefixExtension,
    /// Same pinned Ed25519 custodian key signed incompatible first divergence
    /// at the SAME sequence, referencing the SAME previous receipt.
    ConflictingSignedCustodianClaims,
}
#[derive(Clone,Debug,Serialize)]
pub struct CustodyForkAssessment{
    pub status:&'static str,
    pub classification:CustodyForkClassification,
    pub custodian_id:String,
    pub common_prior_sequence:u64,
    pub conflicting_sequence:Option<u64>,
    pub common_previous_signed_sha256:Option<String>,
    pub left_signed_envelope_sha256:Option<String>,
    pub right_signed_envelope_sha256:Option<String>,
    pub left_payload_sha256:Option<String>,
    pub right_payload_sha256:Option<String>,
    pub contradictory_signed_claims_verified:bool,
    pub real_custodian_independence_verified:bool,
    pub independent_delivery_verified:bool,
    pub human_culpability_established:bool,
    pub automatic_repair_permitted:bool,
    pub human_authority_verified:bool,
    pub canonical_writeback:bool,
    pub authority_transfer:bool,
}
/// Compare two caller-supplied historical suffixes rooted at the EXACT same
/// independently preserved trust floor. Verify BOTH full Ed25519 chains before
/// comparison. A competing later signed branch can be reported as contradictory
/// cryptographic evidence without claiming it exists in the single local
/// publication journal or deciding the authoritative branch.
///
/// The first differing signed PAYLOAD must refer to the same prior signed
/// receipt and sequence, and differ in either bundle digest or publication
/// checkpoint. A mere differently encoded signature is NOT custody equivocation.
pub fn assess_custodian_fork(
    pinned:&CustodianTrustPin,audit:&AuditTrustPin,witness:&ForkWitnessPolicy,
    left:&[SignedCustodyReceipt],right:&[SignedCustodyReceipt],
)->Result<CustodyForkAssessment,String>{
    let _=verify_receipt_chain(pinned,audit,witness,left)?;
    let _=verify_receipt_chain(pinned,audit,witness,right)?;
    let overlap=left.len().min(right.len());
    let mut first_difference=None;
    for i in 0..overlap{
        if canonical(&left[i].payload)?!=canonical(&right[i].payload)?{
            first_difference=Some(i);
            break
        }
    }
    let (classification,conflicting_sequence,common_prev,lhash,rhash,lph,rph,prior)=
        if let Some(i)=first_difference{
            let a=&left[i];let b=&right[i];
            if a.payload.sequence!=b.payload.sequence||
                a.payload.previous_signed_receipt_sha256
                    !=b.payload.previous_signed_receipt_sha256{
                return Err("competing receipt chains have no verified common predecessor at divergence".into())
            }
            if a.payload.publication_checkpoint==b.payload.publication_checkpoint&&
                a.payload.published_bundle_sha256==b.payload.published_bundle_sha256{
                return Err("first signed-payload difference is not a custody-content conflict".into())
            }
            let seq=a.payload.sequence;
            (CustodyForkClassification::ConflictingSignedCustodianClaims,
                Some(seq),a.payload.previous_signed_receipt_sha256.clone(),
                Some(sha256(&canonical(a)?)),Some(sha256(&canonical(b)?)),
                Some(sha256(&canonical(&a.payload)?)),
                Some(sha256(&canonical(&b.payload)?)),
                seq.checked_sub(1).ok_or("invalid custody sequence zero")?)
        }else{
            let kind=if left.len()==right.len(){
                CustodyForkClassification::SameSignedClaims
            }else{
                CustodyForkClassification::VerifiedPrefixExtension
            };
            let common=left.last().zip(right.last())
                .map(|(a,b)|a.payload.sequence.min(b.payload.sequence))
                .or_else(||left.first().or_else(||right.first())
                    .map(|r|r.payload.sequence.saturating_sub(1)))
                .unwrap_or(pinned.floor_receipt_sequence);
            (kind,None,None,None,None,None,None,common)
        };
    let contradictory=classification==CustodyForkClassification::ConflictingSignedCustodianClaims;
    Ok(CustodyForkAssessment{
        status:if contradictory{
            "TWO_CONFLICTING_SIGNED_CUSTODY_CLAIMS_ADVISORY_ONLY"
        }else{
            "NO_SIGNED_CUSTODY_FORK_PROVEN_ADVISORY_ONLY"
        },
        classification,custodian_id:pinned.custodian_id.clone(),
        common_prior_sequence:prior,
        conflicting_sequence,common_previous_signed_sha256:common_prev,
        left_signed_envelope_sha256:lhash,right_signed_envelope_sha256:rhash,
        left_payload_sha256:lph,right_payload_sha256:rph,
        contradictory_signed_claims_verified:contradictory,
        real_custodian_independence_verified:false,
        independent_delivery_verified:false,
        human_culpability_established:false,
        automatic_repair_permitted:false,human_authority_verified:false,
        canonical_writeback:false,authority_transfer:false,
    })
}
