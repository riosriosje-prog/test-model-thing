//! GALIA v0.12: independently pinned append-only *witness receipt* continuity,
//! plus root- and outgoing-key-signed witness verifier-key rotation. READ ONLY.
//! This proves a cryptographic path only relative to the caller's externally
//! authenticated trust roots and pinned count/tip. It is not an authenticated
//! deployment, a transparency log, a trusted clock or GALIA human authority.
use std::collections::BTreeSet;
use serde::{Serialize,Deserialize};
use crate::attestation::signing_preimage;
use crate::audit::sha256;
use crate::witness_proof::{
    WitnessTrustAnchor,SignedWitnessReceipt,SignedWitnessObservation,
    verify_receipt,verify_observation,verify_detached,
};
pub const ROTATION_DOMAIN:&[u8]=b"GALIA_WITNESS_KEY_ROTATION_V1\0";
pub const ROTATION_FORMAT:&str="GALIA_NONCANONICAL_WITNESS_KEY_ROTATION_V1";
fn hash(s:&str)->bool{s.len()==64&&s.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c))}
fn ident(s:&str)->bool{!s.trim().is_empty()&&s.len()<=256&&!s.chars().any(|c|c.is_control())}
fn canonical<T:Serialize>(v:&T)->Result<Vec<u8>,String>{
    serde_json::to_value(v).and_then(|x|serde_json::to_vec(&x)).map_err(|e|e.to_string())
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessRotationPayload{
    pub format:String,
    pub namespace:String,
    pub case_id:String,
    /// New key signs receipt at spent_count == effective_after_count+1.
    pub effective_after_count:u64,
    pub old_signer_key_id:String,
    pub new_signer_key_id:String,
    pub new_witness_public_key_hex:String,
    pub minimum_registry_epoch:u64,
    pub previous_rotation_sha256:Option<String>,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessRotation{
    pub payload:WitnessRotationPayload,
    pub root_signature_hex:String,
    pub old_signer_signature_hex:String,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessContinuityRequest{
    pub anchor:WitnessTrustAnchor,
    /// Distinct externally pinned root dedicated to witness key rotation.
    pub pinned_rotation_root_public_key_hex:String,
    pub rotations:Vec<WitnessRotation>,
    pub extension:Vec<SignedWitnessReceipt>,
    pub current_observation:SignedWitnessObservation,
}
#[derive(Clone,Debug,Serialize)]
pub struct WitnessContinuityReport{
    pub status:&'static str,
    pub start_count:u64,
    pub final_count:u64,
    pub final_tip_sha256:Option<String>,
    pub final_registry_epoch:u64,
    pub rotations_verified:u64,
    pub receipts_verified:u64,
    pub ending_signer_key_id:String,
    pub canonical_writeback:bool,
    pub human_identity_verified:bool,
    pub human_authority_verified:bool,
    pub authority_transfer:bool,
    pub executable_guards_issued:bool,
}
/// Requires explicit receipts for EVERY spend after the pin. A signed newer
/// tip with no contiguous receipt path is REJECTED. The signed transition is
/// bound to exact chain height; old and rotation-root keys both sign its body.
/// Does NOT detect an equivocal signer returning multiple independently valid
/// forks to different clients; a real transparency witness/gossip is required.
pub fn verify_continuity(req:&WitnessContinuityRequest)->Result<WitnessContinuityReport,String>{
    req.anchor.validate()?;
    if req.pinned_rotation_root_public_key_hex==req.anchor.pinned_witness_public_key_hex
       ||req.pinned_rotation_root_public_key_hex==req.anchor.pinned_review_root_public_key_hex{
        return Err("witness rotation key must be a separate trust root".into())
    }
    // An explicit byte-length/key-curve check avoids mistaking merely well-formed
    // hex for a valid Ed25519 rotation key; caller must still pin it externally.
    crate::witness_proof::validate_public_key(&req.pinned_rotation_root_public_key_hex)?;
    let mut pin=req.anchor.clone();
    let mut previous_rotation=None;
    let mut signer_ids=BTreeSet::new();
    let mut signer_keys=BTreeSet::new();
    signer_ids.insert(pin.signer_key_id.clone());
    signer_keys.insert(pin.pinned_witness_public_key_hex.clone());
    let mut current_count=pin.minimum_spent_count;
    let mut current_tip=pin.floor_tip_sha256.clone();
    let mut current_epoch=pin.minimum_registry_epoch;
    let mut ids=BTreeSet::new();
    let mut nonces=BTreeSet::new();
    let mut pos=0usize;
    let mut changes=0u64;
    for signed in &req.extension{
        let next_count=current_count.checked_add(1).ok_or("witness receipt count overflow")?;
        while pos<req.rotations.len() &&
            req.rotations[pos].payload.effective_after_count==current_count {
            // No multi-step rotation at a single observed history height.
            if pos+1<req.rotations.len() &&
                req.rotations[pos+1].payload.effective_after_count==current_count{
                return Err("multiple key rotations at one witness count".into())
            }
            let rot=&req.rotations[pos];
            let p=&rot.payload;
            if p.format!=ROTATION_FORMAT||p.namespace!=pin.expected_namespace
                ||p.case_id!=pin.expected_case_id||
                !ident(&p.old_signer_key_id)||!ident(&p.new_signer_key_id)||
                p.old_signer_key_id!=pin.signer_key_id||
                p.minimum_registry_epoch<current_epoch||
                p.previous_rotation_sha256!=previous_rotation||
                p.old_signer_key_id==p.new_signer_key_id||
                !signer_ids.insert(p.new_signer_key_id.clone())||
                !signer_keys.insert(p.new_witness_public_key_hex.clone())||
                p.new_witness_public_key_hex==pin.pinned_review_root_public_key_hex||
                p.new_witness_public_key_hex==req.pinned_rotation_root_public_key_hex{
                return Err("invalid witness rotation scope/key/epoch/lineage".into())
            }
            crate::witness_proof::validate_public_key(&p.new_witness_public_key_hex)?;
            verify_detached(&req.pinned_rotation_root_public_key_hex,&rot.root_signature_hex,
                ROTATION_DOMAIN,p)?;
            verify_detached(&pin.pinned_witness_public_key_hex,&rot.old_signer_signature_hex,
                ROTATION_DOMAIN,p)?;
            let bytes=canonical(rot)?;
            previous_rotation=Some(sha256(&bytes));
            current_epoch=p.minimum_registry_epoch;
            pin.signer_key_id=p.new_signer_key_id.clone();
            pin.pinned_witness_public_key_hex=p.new_witness_public_key_hex.clone();
            pin.minimum_registry_epoch=current_epoch;
            pos+=1;
            changes=changes.checked_add(1).ok_or("witness rotation overflow")?;
        }
        let receipt=verify_receipt(signed,&pin)?;
        if receipt.spent_count!=next_count||
            receipt.prior_tip_sha256!=current_tip||
            receipt.registry_epoch<current_epoch||
            !ids.insert(receipt.authorization_id.clone())||
            !nonces.insert(receipt.nonce_sha256.clone()){
            return Err("witness extension count/previous-tip/epoch/duplicate mismatch".into())
        }
        current_count=receipt.spent_count;
        current_tip=Some(receipt.tip_sha256);
        current_epoch=receipt.registry_epoch;
        pin.minimum_registry_epoch=current_epoch;
    }
    // A rotation at the ending height with no next signed event has not taken
    // effect. Disallow unattached transitions and phantom key movements.
    if pos!=req.rotations.len(){
        return Err("unattached rotation outside contiguous witness extension".into())
    }
    // Verify terminal observation using CURRENT rotated key. A local externally
    // retained high-water pin must come from a genuine independent source.
    pin.minimum_spent_count=current_count;
    pin.floor_tip_sha256=current_tip.clone();
    let end=verify_observation(&req.current_observation,&pin)?;
    if end.spent_count!=current_count||
        end.tip_sha256!=current_tip||
        end.registry_epoch!=current_epoch {
        return Err("terminal signed observation does not match exact proven extension".into())
    }
    Ok(WitnessContinuityReport{
        status:"CRYPTOGRAPHIC_EXTENSION_ADVISORY_ONLY",
        start_count:req.anchor.minimum_spent_count,final_count:current_count,
        final_tip_sha256:current_tip,final_registry_epoch:current_epoch,
        rotations_verified:changes,
        receipts_verified:current_count-req.anchor.minimum_spent_count,
        ending_signer_key_id:pin.signer_key_id,
        canonical_writeback:false,human_identity_verified:false,
        human_authority_verified:false,authority_transfer:false,
        executable_guards_issued:false,
    })
}
