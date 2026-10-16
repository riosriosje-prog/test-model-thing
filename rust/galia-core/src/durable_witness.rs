//! v0.10: noncanonical, single-filesystem durable scratch witness.
//! Persistent across process restarts, but NOT a remote or authenticated
//! independent witness, production authority, cluster quorum or human approval.
//! Only cooperating processes on one local filesystem are serialized.
use std::collections::BTreeSet;
use std::fs::{self,File,OpenOptions};
use std::io::Write;
use std::path::{Path,PathBuf};
use fs2::FileExt;
use serde::{Serialize,Deserialize};
use crate::witness::{MonotonicWitness,WitnessConfig,WitnessObservation,WitnessConsume,WitnessReceipt,FORMAT};
use crate::audit::sha256;

const MARKER:&str=".GALIA_NONCANONICAL_DURABLE_WITNESS_V1";
const LOCK:&str=".witness.lock";
const JOURNAL:&str="journal";
fn fail(message:&str)->String {message.into()}
fn canonical<T:Serialize>(v:&T)->Result<Vec<u8>,String>{
    let sorted=serde_json::to_value(v).map_err(|e|e.to_string())?;
    serde_json::to_vec(&sorted).map_err(|e|e.to_string())
}
fn dir(path:&Path)->Result<(),String>{
    let m=fs::symlink_metadata(path).map_err(|e|e.to_string())?;
    if !m.file_type().is_dir(){return Err(fail("durable witness directory must not be symlink"))}Ok(())
}
fn regular(path:&Path)->Result<(),String>{
    let m=fs::symlink_metadata(path).map_err(|e|e.to_string())?;
    if !m.file_type().is_file(){return Err(fail("durable witness file must be regular and not symlink"))}Ok(())
}
fn read(path:&Path)->Result<Vec<u8>,String>{regular(path)?;fs::read(path).map_err(|e|e.to_string())}
fn sync_dir(path:&Path)->Result<(),String>{
    File::open(path).and_then(|f|f.sync_all()).map_err(|e|e.to_string())
}
fn create_new(path:&Path,data:&[u8])->Result<(),String>{
    let mut f=OpenOptions::new().write(true).create_new(true).open(path)
        .map_err(|e|e.to_string())?;
    f.write_all(data).map_err(|e|e.to_string())?;
    f.sync_all().map_err(|e|e.to_string())
}
fn lower_hash(s:&str)->bool{
    s.len()==64 && s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
}
fn receipt_for(config:&WitnessConfig,req:&WitnessConsume,count:u64,
    prior:Option<String>)->Result<WitnessReceipt,String>{
    let mut wire=canonical(req)?;
    wire.extend_from_slice(&count.to_be_bytes());
    Ok(WitnessReceipt{
        format:FORMAT.into(),namespace:config.namespace.clone(),
        case_id:config.case_id.clone(),registry_epoch:req.registry_epoch,
        spent_count:count,prior_tip_sha256:prior,tip_sha256:sha256(&wire),
        authorization_id:req.authorization_id.clone(),nonce_sha256:req.nonce_sha256.clone(),
        signed_decision_sha256:req.signed_decision_sha256.clone(),
        canonical_writeback:false,authority_transfer:false,
    })
}
fn validate_request(config:&WitnessConfig,req:&WitnessConsume)->Result<(),String>{
    if req.format!=FORMAT||req.namespace!=config.namespace||req.case_id!=config.case_id
        ||req.pinned_root_public_key_hex!=config.pinned_root_public_key_hex
        ||req.registry_epoch==0||req.authorization_id.is_empty()
        ||req.authorization_id.len()>256||req.authorization_id.chars().any(|c|c.is_control())
        ||!lower_hash(&req.nonce_sha256)||!lower_hash(&req.signed_decision_sha256)
        ||req.expected_tip_sha256.as_ref().is_some_and(|x|!lower_hash(x)){
        return Err(fail("witness request mismatches configured scratch root/scope"));
    }
    Ok(())
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalEntry{
    index:u64,
    prior_entry_sha256:Option<String>,
    request:WitnessConsume,
    receipt:WitnessReceipt,
}
struct State{
    entries:Vec<JournalEntry>,
    tip:Option<String>,
    epoch:u64,
    ids:BTreeSet<String>,
    nonces:BTreeSet<String>,
}
struct Guard(File);
impl Drop for Guard{fn drop(&mut self){let _=FileExt::unlock(&self.0);}}
#[derive(Debug,Clone)]
pub struct DurableScratchWitness{
    root:PathBuf,
    config:WitnessConfig,
}
impl DurableScratchWitness{
    /// Refuses *any* existing directory, even if empty.
    /// Scratch root and its marker must not be used as a production trust anchor.
    pub fn initialize_new(root:impl AsRef<Path>,config:WitnessConfig)->Result<Self,String>{
        config.validate()?;
        let root=root.as_ref();
        if fs::symlink_metadata(root).is_ok(){return Err(fail("witness scratch root exists"));}
        fs::create_dir(root).map_err(|e|e.to_string())?;
        #[cfg(unix)]{
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root,fs::Permissions::from_mode(0o700))
                .map_err(|e|e.to_string())?;
        }
        create_new(&root.join(MARKER),&canonical(&config)?)?;
        fs::create_dir(root.join(JOURNAL)).map_err(|e|e.to_string())?;
        create_new(&root.join(LOCK),b"")?;
        sync_dir(root)?;
        Self::open(root)
    }
    pub fn open(root:impl AsRef<Path>)->Result<Self,String>{
        let root=root.as_ref();
        dir(root)?;dir(&root.join(JOURNAL))?;
        regular(&root.join(LOCK))?;
        let raw=read(&root.join(MARKER))?;
        let config:WitnessConfig=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
        config.validate()?;
        if raw!=canonical(&config)? {return Err(fail("noncanonical witness marker"));}
        let root=fs::canonicalize(root).map_err(|e|e.to_string())?;
        let witness=Self{root,config};
        // Any on-disk error prevents reopening; no auto-repair.
        let _guard=witness.lock()?;
        witness.replay()?;
        Ok(witness)
    }
    fn lock(&self)->Result<Guard,String>{
        regular(&self.root.join(LOCK))?;
        let file=OpenOptions::new().read(true).write(true).open(self.root.join(LOCK))
            .map_err(|e|e.to_string())?;
        FileExt::lock_exclusive(&file).map_err(|e|e.to_string())?;
        if read(&self.root.join(MARKER))?!=canonical(&self.config)?{
            return Err(fail("scratch witness marker changed"))
        }
        Ok(Guard(file))
    }
    fn replay(&self)->Result<State,String>{
        let path=self.root.join(JOURNAL);
        dir(&path)?;
        let mut files=vec![];
        for ent in fs::read_dir(&path).map_err(|e|e.to_string())?{
            let ent=ent.map_err(|e|e.to_string())?;
            regular(&ent.path())?;
            let name=ent.file_name().into_string().map_err(|_|fail("non UTF8 journal filename"))?;
            files.push((name,ent.path()));
        }
        files.sort_by(|a,b|a.0.cmp(&b.0));
        let mut state=State{
            entries:vec![],tip:None,epoch:self.config.initial_registry_epoch,
            ids:BTreeSet::new(),nonces:BTreeSet::new(),
        };
        let mut previous_entry_hash=None;
        for (idx,(name,path)) in files.into_iter().enumerate(){
            let position=u64::try_from(idx).map_err(|_|fail("journal index overflow"))?
                .checked_add(1).ok_or("journal index overflow")?;
            if name!=format!("{position:020}.json"){return Err(fail("missing or undeclared witness journal file"))}
            let raw=read(&path)?;
            let entry:JournalEntry=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
            if raw!=canonical(&entry)?{return Err(fail("noncanonical witness journal entry"))}
            if entry.index!=position||entry.prior_entry_sha256!=previous_entry_hash{
                return Err(fail("witness journal chain/index mismatch"))
            }
            validate_request(&self.config,&entry.request)?;
            if entry.request.registry_epoch<state.epoch
                ||entry.request.expected_tip_sha256!=state.tip
                ||!state.ids.insert(entry.request.authorization_id.clone())
                ||!state.nonces.insert(entry.request.nonce_sha256.clone()){
                return Err(fail("witness journal epoch, CAS, ID or nonce replay invalid"))
            }
            let expected=receipt_for(&self.config,&entry.request,position,state.tip.clone())?;
            // Serialized receipt identity exactly: no caller-supplied receipt can
            // retroactively claim a different decision, count or digest.
            if canonical(&expected)?!=canonical(&entry.receipt)?{
                return Err(fail("witness journal receipt corruption"))
            }
            previous_entry_hash=Some(sha256(&raw));
            state.tip=Some(expected.tip_sha256.clone());
            state.epoch=entry.request.registry_epoch;
            state.entries.push(entry);
        }
        Ok(state)
    }
    /// Return a replay-verified receipt for a previously committed spend.
    /// This alone does not authenticate a remote identity or external timestamp.
    pub fn lookup(&self,authorization_id:&str)->Result<Option<WitnessReceipt>,String>{
        let _guard=self.lock()?;
        let state=self.replay()?;
        Ok(state.entries.into_iter()
            .find(|e|e.request.authorization_id==authorization_id)
            .map(|e|e.receipt))
    }
}
impl MonotonicWitness for DurableScratchWitness{
    fn observe(&self)->Result<WitnessObservation,String>{
        let _guard=self.lock()?;let state=self.replay()?;
        Ok(WitnessObservation{
            namespace:self.config.namespace.clone(),case_id:self.config.case_id.clone(),
            registry_epoch:state.epoch,
            spent_count:u64::try_from(state.entries.len()).map_err(|_|"count overflow")?,
            tip_sha256:state.tip,
        })
    }
    fn consume(&self,req:&WitnessConsume)->Result<WitnessReceipt,String>{
        validate_request(&self.config,req)?;
        let _guard=self.lock()?;
        let state=self.replay()?;
        if req.registry_epoch<state.epoch{return Err(fail("registry epoch rollback"))}
        if req.expected_tip_sha256!=state.tip{return Err(fail("stale witness CAS token"))}
        if state.ids.contains(&req.authorization_id)||state.nonces.contains(&req.nonce_sha256){
            return Err(fail("witness authorization/nonce already consumed"))
        }
        let index=u64::try_from(state.entries.len()).map_err(|_|"index overflow")?
            .checked_add(1).ok_or("index overflow")?;
        let receipt=receipt_for(&self.config,req,index,state.tip.clone())?;
        let previous_entry_sha256=if let Some(last)=state.entries.last(){
            let previous=canonical(last)?;
            Some(sha256(&previous))
        }else{None};
        let entry=JournalEntry{
            index,prior_entry_sha256:previous_entry_sha256,
            request:req.clone(),receipt:receipt.clone()
        };
        let file=self.root.join(JOURNAL).join(format!("{index:020}.json"));
        // Creation of a single canonical file represents the exact spend.
        // A torn write is detectable and blocks further operations.
        create_new(&file,&canonical(&entry)?)?;
        sync_dir(&self.root.join(JOURNAL))?;
        Ok(receipt)
    }
    fn find_spend(&self,authorization_id:&str)->Result<Option<WitnessReceipt>,String>{
        self.lookup(authorization_id)
    }
}
