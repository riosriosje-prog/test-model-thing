//! GALIA v0.8: NONCANONICAL scratch-only atomic replay consumption.
//! An immutable single record consumes BOTH authorization ID and nonce in one
//! local append under a cooperative file lock. No P5 human authority is created.
//! The on-disk root marker is NOT an independently authenticated trust anchor.
//! Whole-directory rollback, multi-host attacks and malicious local writers remain out of scope.
use std::collections::BTreeSet;
use std::fs::{self,File,OpenOptions};
use std::io::Write;
use std::path::{Path,PathBuf};
use fs2::FileExt;
use ed25519_dalek::VerifyingKey;
use serde::{Serialize,Deserialize};
use sha2::{Digest,Sha256};
use crate::review::{ReviewVerificationRequest,verify_review};
use crate::witness::{MonotonicWitness,WitnessConsume,WitnessReceipt,FORMAT as WITNESS_FORMAT};

const FORMAT:&str="GALIA_NONCANONICAL_SCRATCH_CONSUMPTION_V1";
const MARKER:&str=".GALIA_SCRATCH_CONSUMPTION_V1";
const LOCK:&str=".consumption.lock";

fn sha(bytes:&[u8])->String{format!("{:x}",Sha256::digest(bytes))}
fn canonical<T:Serialize>(value:&T)->Result<Vec<u8>,String>{
    serde_json::to_value(value).and_then(|v|serde_json::to_vec(&v))
        .map_err(|e|e.to_string())
}
fn id(s:&str)->bool{!s.trim().is_empty()&&s.len()<=256&&!s.chars().any(|c|c.is_control())}
fn digest(s:&str)->bool{s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn directory(path:&Path)->Result<(),String>{
    let m=fs::symlink_metadata(path).map_err(|e|e.to_string())?;
    if !m.file_type().is_dir(){return Err("expected non-symlink directory".into())}Ok(())
}
fn regular(path:&Path)->Result<(),String>{
    let m=fs::symlink_metadata(path).map_err(|e|e.to_string())?;
    if !m.file_type().is_file(){return Err("expected non-symlink regular file".into())}Ok(())
}
fn bytes(path:&Path)->Result<Vec<u8>,String>{
    regular(path)?;fs::read(path).map_err(|e|e.to_string())
}
fn write_new(path:&Path,raw:&[u8])->Result<(),String>{
    let mut f=OpenOptions::new().write(true).create_new(true).open(path)
        .map_err(|e|e.to_string())?;
    f.write_all(raw).map_err(|e|e.to_string())?;
    f.sync_all().map_err(|e|e.to_string())
}
fn fsync_dir(dir:&Path)->Result<(),String>{
    File::open(dir).and_then(|f|f.sync_all()).map_err(|e|e.to_string())
}
fn validate_root(hexkey:&str)->Result<(),String>{
    if !digest(hexkey){return Err("invalid pinned Ed25519 root hex".into());}
    let raw=hex::decode(hexkey).map_err(|e|e.to_string())?;
    let array:[u8;32]=raw.try_into().map_err(|_|"invalid root key length")?;
    VerifyingKey::from_bytes(&array).map_err(|e|e.to_string())?;
    Ok(())
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreMarker{
    format:String,namespace:String,case_id:String,pinned_root_public_key_hex:String,
}
impl StoreMarker{
    fn validate(&self)->Result<(),String>{
        if self.format!=FORMAT||!id(&self.namespace)||!id(&self.case_id){
            return Err("invalid scratch consumption root marker".into())
        }
        validate_root(&self.pinned_root_public_key_hex)
    }
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct SpendRecord{
    format:String,index:u64,previous_record_sha256:Option<String>,
    namespace:String,case_id:String,registry_epoch:u64,
    reviewer_key_id:String,authorization_id:String,decision_id:String,
    nonce_sha256:String,manifest_sha256:String,target_commit:String,
    signed_review_sha256:String,
}
impl SpendRecord{
    fn validate(&self,marker:&StoreMarker)->Result<(),String>{
        if self.format!=FORMAT||self.index==0
            || self.namespace!=marker.namespace||self.case_id!=marker.case_id
            || self.registry_epoch==0||!id(&self.reviewer_key_id)
            ||!id(&self.authorization_id)||!id(&self.decision_id)
            ||!id(&self.target_commit)||!digest(&self.nonce_sha256)
            ||!digest(&self.manifest_sha256)||!digest(&self.signed_review_sha256)
            ||self.previous_record_sha256.as_ref().is_some_and(|s|!digest(s)){
            return Err("invalid scratch consumption record".into())
        }
        Ok(())
    }
}
#[derive(Clone,Debug,Serialize)]
pub struct ConsumptionReport{
    pub status:&'static str,pub spent_in_scratch_only:bool,
    pub consumed_count:u64,pub tip_sha256:String,
    pub maximum_seen_registry_epoch:u64,
    pub human_identity_verified:bool,pub human_authority_verified:bool,
    pub executable_guards_issued:bool,pub canonical_writeback:bool,
    pub authority_transfer:bool,pub output_commit:Option<String>,
}
#[derive(Clone,Debug,Serialize)]
pub struct WitnessBoundSpendReport{
    pub local:ConsumptionReport,
    pub witness:Option<WitnessReceipt>,
    pub human_authority_verified:bool,
    pub canonical_writeback:bool,
    pub authority_transfer:bool,
}

#[derive(Clone,Debug)]
pub struct ScratchConsumptionStore{root:PathBuf,marker:StoreMarker}
struct LockGuard(File);
impl Drop for LockGuard{
    fn drop(&mut self){let _=FileExt::unlock(&self.0);}
}
struct History{
    rows:Vec<SpendRecord>,tip:Option<String>,epoch:u64,
    ids:BTreeSet<String>,nonces:BTreeSet<String>,
}
impl ScratchConsumptionStore{
    /// Explicitly initializes a NEW noncanonical scratch root (never an existing GALIA root).
    pub fn initialize_new(root:impl AsRef<Path>,root_public_key_hex:&str,
        namespace:&str,case_id:&str)->Result<Self,String>{
        let root=root.as_ref();
        if fs::symlink_metadata(root).is_ok(){return Err("scratch consumption root already exists".into());}
        let marker=StoreMarker{
            format:FORMAT.into(),namespace:namespace.into(),case_id:case_id.into(),
            pinned_root_public_key_hex:root_public_key_hex.into(),
        };
        marker.validate()?;
        fs::create_dir(root).map_err(|e|e.to_string())?;
        #[cfg(unix)]{
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root,fs::Permissions::from_mode(0o700))
                .map_err(|e|e.to_string())?;
        }
        write_new(&root.join(MARKER),&canonical(&marker)?)?;
        fs::create_dir(root.join("records")).map_err(|e|e.to_string())?;
        write_new(&root.join(LOCK),b"")?;
        fsync_dir(root)?;
        Self::open(root)
    }
    pub fn open(root:impl AsRef<Path>)->Result<Self,String>{
        let root=root.as_ref();directory(root)?;
        let raw=bytes(&root.join(MARKER))?;
        let marker:StoreMarker=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
        marker.validate()?;
        if canonical(&marker)?!=raw{return Err("noncanonical scratch root marker".into())}
        directory(&root.join("records"))?;
        regular(&root.join(LOCK))?;
        let canonical_root=fs::canonicalize(root).map_err(|e|e.to_string())?;
        Ok(Self{root:canonical_root,marker})
    }
    fn lock(&self)->Result<LockGuard,String>{
        // Integrity is checked under lock; no unguarded consume transition.
        regular(&self.root.join(LOCK))?;
        let file=OpenOptions::new().read(true).write(true).open(self.root.join(LOCK))
            .map_err(|e|e.to_string())?;
        FileExt::lock_exclusive(&file).map_err(|e|e.to_string())?;
        if bytes(&self.root.join(MARKER))?!=canonical(&self.marker)?{
            return Err("scratch consumption root marker modified".into())
        }
        Ok(LockGuard(file))
    }
    fn history(&self)->Result<History,String>{
        directory(&self.root.join("records"))?;
        let mut entries=vec![];
        for p in fs::read_dir(self.root.join("records")).map_err(|e|e.to_string())?{
            let e=p.map_err(|e|e.to_string())?;
            regular(&e.path())?;
            entries.push((e.file_name().into_string().map_err(|_|"non-UTF8 record name")?,e.path()));
        }
        entries.sort_by(|a,b|a.0.cmp(&b.0));
        let mut rows=Vec::new();let mut tip=None;let mut epoch=0;
        let mut ids=BTreeSet::new();let mut nonces=BTreeSet::new();
        for (position,(name,path)) in entries.into_iter().enumerate(){
            if name!=format!("{:020}.json",position+1){return Err("record gap or undeclared entry".into());}
            let raw=bytes(&path)?;
            let record:SpendRecord=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
            if canonical(&record)?!=raw{return Err("noncanonical scratch consumption record".into());}
            record.validate(&self.marker)?;
            if record.index!=u64::try_from(position+1).map_err(|_|"index overflow")?
                ||record.previous_record_sha256!=tip
                ||record.registry_epoch<epoch{
                return Err("scratch log hash link, index or registry epoch rollback".into())
            }
            if !ids.insert(record.authorization_id.clone())
                ||!nonces.insert(record.nonce_sha256.clone()){
                return Err("duplicate consumed authorization or nonce".into())
            }
            epoch=record.registry_epoch;
            tip=Some(sha(&raw));
            rows.push(record);
        }
        Ok(History{rows,tip,epoch,ids,nonces})
    }
    /// A single immutable record commits both identifiers under one local lock.
    /// Approval and signature authenticity are limited by the caller-supplied policy.
    pub fn consume_review(&self,request:&ReviewVerificationRequest)->Result<ConsumptionReport,String>{
        Ok(self.consume_inner(request,None)?.local)
    }
    /// Simulated cross-root witness gate. The caller must obtain the expected
    /// CAS tip from its separately configured witness before calling this API.
    /// The witness spend is BEFORE local append: local I/O failure after
    /// witness commit burns the token and needs manual fail-closed recovery.
    /// No end-to-end distributed transaction, human authority or automatic repair.
    pub fn consume_with_witness(
        &self,request:&ReviewVerificationRequest,
        witness:&dyn MonotonicWitness,expected_witness_tip:Option<&str>
    )->Result<WitnessBoundSpendReport,String>{
        self.consume_inner(request,Some((witness,expected_witness_tip)))
    }
    fn consume_inner(
        &self,request:&ReviewVerificationRequest,
        witness:Option<(&dyn MonotonicWitness,Option<&str>)>
    )->Result<WitnessBoundSpendReport,String>{
        let _guard=self.lock()?;
        let history=self.history()?;
        if request.policy.pinned_root_public_key_hex!=self.marker.pinned_root_public_key_hex
            ||request.policy.expected_namespace!=self.marker.namespace
            ||request.policy.expected_scope.case_id!=self.marker.case_id{
            return Err("caller policy differs from pinned scratch root".into())
        }
        if request.policy.minimum_registry_epoch<history.epoch{
            return Err("caller registry minimum epoch behind observed scratch high-water mark".into())
        }
        let assessed=verify_review(request)?;
        let payload=&request.decision.payload;
        let registry_epoch=request.registry.payload.epoch;
        if registry_epoch<history.epoch{
            return Err("rollback to older root-signed registry epoch".into())
        }
        let auth=&payload.authorization;
        if history.ids.contains(&auth.authorization_id)||history.nonces.contains(&payload.nonce_sha256){
            return Err("review authorization or nonce already consumed in scratch".into())
        }
        let record=SpendRecord{
            format:FORMAT.into(),
            index:u64::try_from(history.rows.len()).map_err(|_|"record index overflow")?
                .checked_add(1).ok_or("record index overflow")?,
            previous_record_sha256:history.tip,
            namespace:self.marker.namespace.clone(),case_id:self.marker.case_id.clone(),
            registry_epoch,reviewer_key_id:payload.reviewer_key_id.clone(),
            authorization_id:auth.authorization_id.clone(),decision_id:auth.decision_id.clone(),
            nonce_sha256:payload.nonce_sha256.clone(),
            manifest_sha256:payload.manifest_sha256.clone(),
            target_commit:auth.target_commit.clone(),
            signed_review_sha256:sha(&canonical(&request.decision)?),
        };
        record.validate(&self.marker)?;
        // Commit the independently scoped witness *before* local append.
        // An unavailable witness rejects without touching the scratch log.
        let witness_receipt=match witness{
            Some((service,expected_tip))=>{
                let stamp=WitnessConsume{
                    format:WITNESS_FORMAT.into(),
                    namespace:self.marker.namespace.clone(),
                    case_id:self.marker.case_id.clone(),
                    pinned_root_public_key_hex:self.marker.pinned_root_public_key_hex.clone(),
                    registry_epoch,authorization_id:auth.authorization_id.clone(),
                    nonce_sha256:payload.nonce_sha256.clone(),
                    signed_decision_sha256:record.signed_review_sha256.clone(),
                    expected_tip_sha256:expected_tip.map(str::to_owned)
                };
                let receipt=service.consume(&stamp)?;
                if receipt.format!=WITNESS_FORMAT||
                    receipt.namespace!=stamp.namespace||
                    receipt.case_id!=stamp.case_id||
                    receipt.registry_epoch!=stamp.registry_epoch||
                    receipt.authorization_id!=stamp.authorization_id||
                    receipt.nonce_sha256!=stamp.nonce_sha256||
                    receipt.signed_decision_sha256!=stamp.signed_decision_sha256||
                    receipt.prior_tip_sha256!=stamp.expected_tip_sha256||
                    receipt.canonical_writeback||receipt.authority_transfer{
                    return Err("witness returned mismatched receipt; manual reconciliation required".into())
                }
                Some(receipt)
            }
            None=>None
        };
        let encoded=canonical(&record)?;
        let digest=sha(&encoded);
        let path=self.root.join("records").join(format!("{:020}.json",record.index));
        write_new(&path,&encoded)?;
        fsync_dir(&self.root.join("records"))?;
        if !assessed.review_signature_valid{
            return Err("review signature not validated".into())
        }
        Ok(WitnessBoundSpendReport{
            local:ConsumptionReport{
                status:"SCRATCH_SPENT_NONCANONICAL_ONLY",spent_in_scratch_only:true,
                consumed_count:record.index,tip_sha256:digest,
                maximum_seen_registry_epoch:registry_epoch,
                human_identity_verified:false,human_authority_verified:false,
                executable_guards_issued:false,canonical_writeback:false,
                authority_transfer:false,output_commit:None,
            },
            witness:witness_receipt,
            human_authority_verified:false,
            canonical_writeback:false,
            authority_transfer:false,
        })
    }
    pub fn inspect(&self)->Result<(u64,Option<String>,u64),String>{
        let _guard=self.lock()?;let h=self.history()?;
        Ok((u64::try_from(h.rows.len()).map_err(|_|"count overflow")?,h.tip,h.epoch))
    }
}


/// An external high-water checkpoint can reveal wholesale local ledger rollback,
/// but only if the caller has kept and authenticated it OUTSIDE the scratch root.
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumptionCheckpoint{
    pub count:u64,
    pub tip_sha256:Option<String>,
    pub maximum_seen_registry_epoch:u64,
}
impl ScratchConsumptionStore{
    pub fn checkpoint(&self)->Result<ConsumptionCheckpoint,String>{
        let (count,tip_sha256,maximum_seen_registry_epoch)=self.inspect()?;
        Ok(ConsumptionCheckpoint{count,tip_sha256,maximum_seen_registry_epoch})
    }
    pub fn verify_checkpoint(&self,previous:&ConsumptionCheckpoint)->Result<(),String>{
        // Exact history pin; this is an offline consistency check, not signer identity.
        let now=self.checkpoint()?;
        if now.count!=previous.count
            ||now.tip_sha256!=previous.tip_sha256
            ||now.maximum_seen_registry_epoch!=previous.maximum_seen_registry_epoch{
            return Err("external scratch consumption checkpoint mismatch".into());
        }
        Ok(())
    }
}
