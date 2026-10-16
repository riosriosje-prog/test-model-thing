//! P3 scratch audit receipt chain. Pure, read-only verification primitives.
//! A SHA-256 hash chain detects internal edits, forks and out-of-order replay,
//! but WITHOUT an authenticated external checkpoint it CANNOT detect a rewritten
//! complete chain, truncation or fabrication. No human authority is conferred.
use std::collections::{BTreeMap,BTreeSet};
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};

pub const FORMAT: &str = "GALIA_NONCANONICAL_SCRATCH_AUDIT_V1";

pub fn sha256(bytes:&[u8])->String {format!("{:x}",Sha256::digest(bytes))}
fn hex_sha(s:&str)->bool{s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn simple_id(s:&str)->bool{!s.trim().is_empty()&&s!="."&&s!=".."&&!s.chars().any(|c| matches!(c, '/' | '\\' | ':' | '\0'))}
fn optional_hash(h:&Option<String>)->bool{h.as_ref().is_none_or(|v|hex_sha(v))}

#[derive(Clone,Debug,Eq,PartialEq,Serialize,Deserialize)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub enum AuditOperation{Staged,Published}

#[derive(Clone,Debug,Eq,PartialEq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditReceipt{
    pub format:String,
    pub index:u64,
    pub previous_receipt_hash:Option<String>,
    pub operation:AuditOperation,
    pub commit_id:String,
    pub manifest_hash:String,
    pub head_before:Option<String>,
    pub head_after:Option<String>,
}

impl AuditReceipt{
    pub fn canonical_bytes(&self)->Result<Vec<u8>,String>{
        let v=serde_json::to_value(self).map_err(|e|e.to_string())?;
        serde_json::to_vec(&v).map_err(|e|e.to_string())
    }
    pub fn receipt_hash(&self)->Result<String,String>{Ok(sha256(&self.canonical_bytes()?))}
    fn validate(&self)->Result<(),String>{
        if self.format!=FORMAT || self.index==0 || !simple_id(&self.commit_id)
            || !hex_sha(&self.manifest_hash)
            || !optional_hash(&self.previous_receipt_hash)
            || !optional_hash(&self.head_before)||!optional_hash(&self.head_after){
            return Err("invalid scratch audit receipt metadata".into());
        }
        if self.operation==AuditOperation::Staged && self.head_before!=self.head_after{
            return Err("STAGED receipt cannot change HEAD".into());
        }
        if self.operation==AuditOperation::Published &&
            (self.head_after.is_none() || self.head_before==self.head_after){
            return Err("PUBLISHED receipt must advance HEAD".into());
        }
        Ok(())
    }
}

#[derive(Clone,Debug,Eq,PartialEq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint{
    pub count:u64,
    pub tip_sha256:String,
    pub last_head_sha256:Option<String>,
}

#[derive(Clone,Debug,Serialize)]
pub struct AuditReport{
    pub status:&'static str,
    pub count:u64,
    pub tip_sha256:Option<String>,
    pub head_sha256:Option<String>,
    pub staged_unpublished:Vec<String>,
    pub canonical_writeback:bool,
    pub authority_transfer:bool,
}

/// Verify the complete sequence from genesis; an optional pre-trusted, out-of-band
/// checkpoint rejects truncation or a wholly rehashed/forked replacement chain.
pub fn verify_receipts(receipts:&[AuditReceipt],trusted_checkpoint:Option<&Checkpoint>)
    -> Result<AuditReport,String>{
    let mut previous:Option<String>=None;
    let mut current_head:Option<String>=None;
    let mut staged:BTreeMap<String,String>=BTreeMap::new();
    let mut published:BTreeSet<String>=BTreeSet::new();
    for (i,r) in receipts.iter().enumerate(){
        r.validate()?;
        if r.index != u64::try_from(i+1).map_err(|_|"receipt index overflow")? ||
            r.previous_receipt_hash!=previous{
            return Err("audit sequence/hash link invalid".into());
        }
        if r.head_before!=current_head{
            return Err("audit history HEAD continuity broken".into());
        }
        match r.operation{
            AuditOperation::Staged=>{
                if staged.insert(r.commit_id.clone(),r.manifest_hash.clone()).is_some() ||
                    published.contains(&r.commit_id){
                    return Err("duplicate/replayed STAGED receipt".into());
                }
            }
            AuditOperation::Published=>{
                if published.contains(&r.commit_id) ||
                    staged.get(&r.commit_id)!=Some(&r.manifest_hash){
                    return Err("PUBLISHED lacks exact prior STAGED receipt".into());
                }
                staged.remove(&r.commit_id);
                published.insert(r.commit_id.clone());
                current_head=r.head_after.clone();
            }
        }
        previous=Some(r.receipt_hash()?);
    }
    let count=u64::try_from(receipts.len()).map_err(|_|"audit length overflow")?;
    if let Some(cp)=trusted_checkpoint{
        if !hex_sha(&cp.tip_sha256)||cp.count!=count||
            Some(cp.tip_sha256.clone())!=previous||
            cp.last_head_sha256!=current_head{
            return Err("audit trusted checkpoint mismatch".into());
        }
    }
    Ok(AuditReport{
        status:"ADVISORY_ONLY",count,tip_sha256:previous,
        head_sha256:current_head,
        staged_unpublished:staged.into_keys().collect(),
        canonical_writeback:false,authority_transfer:false,
    })
}

/// Reject noncanonical raw JSON and duplicate-key malleability. The caller must
/// supply the whole sequence; a trusted out-of-band checkpoint is still required.
pub fn decode_receipts(raw_records:&[Vec<u8>],trusted_checkpoint:Option<&Checkpoint>)
    -> Result<AuditReport,String>{
    let mut receipts=Vec::with_capacity(raw_records.len());
    for raw in raw_records{
        let r:AuditReceipt=serde_json::from_slice(raw)
            .map_err(|e|format!("invalid audit JSON: {e}"))?;
        if r.canonical_bytes()?!=*raw {return Err("noncanonical audit receipt".into());}
        receipts.push(r);
    }
    verify_receipts(&receipts,trusted_checkpoint)
}

/// Make one diagnostic scratch receipt (never an authenticated attestation).
pub fn next_receipt(
    prior:&[AuditReceipt], operation:AuditOperation, commit_id:&str,
    manifest_hash:&str, head_before:Option<String>, head_after:Option<String>
)->Result<AuditReceipt,String>{
    let report=verify_receipts(prior,None)?;
    if report.head_sha256!=head_before{
        return Err("receipt HEAD does not match current audit chain".into());
    }
    let receipt=AuditReceipt{
        format:FORMAT.into(),
        index:report.count.checked_add(1).ok_or("audit index overflow")?,
        previous_receipt_hash:report.tip_sha256,
        operation,commit_id:commit_id.into(),manifest_hash:manifest_hash.into(),
        head_before,head_after,
    };
    let mut extended=prior.to_vec();
    extended.push(receipt.clone());
    verify_receipts(&extended,None)?;
    Ok(receipt)
}

#[cfg(test)]
mod tests{
 use super::*;
 fn h(b:u8)->String{std::iter::repeat(char::from(b)).take(64).collect()}
 fn chain()->Vec<AuditReceipt>{
    let mut c=vec![];
    c.push(next_receipt(&c,AuditOperation::Staged,"g1",&h(b'a'),None,None).unwrap());
    c.push(next_receipt(&c,AuditOperation::Published,"g1",&h(b'a'),None,Some(h(b'1'))).unwrap());
    c.push(next_receipt(&c,AuditOperation::Staged,"g2",&h(b'b'),Some(h(b'1')),Some(h(b'1'))).unwrap());
    c.push(next_receipt(&c,AuditOperation::Published,"g2",&h(b'b'),Some(h(b'1')),Some(h(b'2'))).unwrap());
    c
 }
 #[test]fn healthy_chain_replays_and_pins(){
    let c=chain();let r=verify_receipts(&c,None).unwrap();
    assert_eq!(r.count,4);assert_eq!(r.head_sha256,Some(h(b'2')));
    assert!(!r.canonical_writeback&&!r.authority_transfer);
    let cp=Checkpoint{count:r.count,tip_sha256:r.tip_sha256.unwrap(),last_head_sha256:r.head_sha256};
    verify_receipts(&c,Some(&cp)).unwrap();
    assert!(verify_receipts(&c[..3],Some(&cp)).is_err());
 }
 #[test]fn tamper_reorder_replay_fail(){
    let c=chain();
    let mut bad=c.clone();bad[1].manifest_hash=h(b'b');assert!(verify_receipts(&bad,None).is_err());
    let mut bad=c.clone();bad.swap(1,2);assert!(verify_receipts(&bad,None).is_err());
    let mut bad=c.clone();bad.push(c[3].clone());assert!(verify_receipts(&bad,None).is_err());
    let mut bad=c.clone();bad[2].head_before=None;assert!(verify_receipts(&bad,None).is_err());
 }
 #[test]fn publishing_without_stage_or_duplicate_staging_fails(){
    let mut c=chain();c.truncate(2);
    let duplicate=next_receipt(&c,AuditOperation::Staged,"g2",&h(b'b'),Some(h(b'1')),Some(h(b'1'))).unwrap();
    c.push(duplicate);
    assert!(next_receipt(&c,AuditOperation::Staged,"g2",&h(b'b'),Some(h(b'1')),Some(h(b'1'))).is_err());
    assert!(next_receipt(&c,AuditOperation::Published,"unseen",&h(b'c'),Some(h(b'1')),Some(h(b'2'))).is_err());
 }
 #[test]fn noncanonical_json_rejected(){
    let c=chain();let mut bytes=c.iter().map(|r|r.canonical_bytes().unwrap()).collect::<Vec<_>>();
    bytes[0].push(b' ');
    assert!(decode_receipts(&bytes,None).is_err());
 }
 #[test]fn forged_payload_with_correct_new_hash_needs_external_checkpoint(){
    let c=chain();let r=verify_receipts(&c,None).unwrap();
    let cp=Checkpoint{count:r.count,tip_sha256:r.tip_sha256.unwrap(),last_head_sha256:r.head_sha256};
    let mut rewritten=vec![];
    rewritten.push(next_receipt(&rewritten,AuditOperation::Staged,"h1",&h(b'a'),None,None).unwrap());
    rewritten.push(next_receipt(&rewritten,AuditOperation::Published,"h1",&h(b'a'),None,Some(h(b'1'))).unwrap());
    assert!(verify_receipts(&rewritten,None).is_ok());
    assert!(verify_receipts(&rewritten,Some(&cp)).is_err());
 }
 #[test]fn malformed_head_and_receipt_rejected(){
    let c=chain();
    let mut bad=c.clone();bad[0].manifest_hash="XYZ".into();
    assert!(verify_receipts(&bad,None).is_err());
    let mut bad=c;bad[0].head_after=Some(h(b'1'));
    assert!(verify_receipts(&bad,None).is_err());
 }
}
