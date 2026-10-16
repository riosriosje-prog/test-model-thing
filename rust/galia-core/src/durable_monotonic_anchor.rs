//! GALIA Rust v0.27: durable OUT-OF-TREE local monotonic CAS anchor.
//!
//! This is one LOCAL filesystem and cooperating OS file locks, NOT an
//! independently administered server, HSM, consensus/quorum, Byzantine
//! service or cryptographic anti-rollback guarantee. Keep anchor storage on
//! an explicitly separate scratch root from the fencing coordinator.
//! Signed archival provenance, P5 human authority and canonical writeback
//! remain permanently outside this adapter (AUTHORITY_HOLD).
use std::fs::{self,File,OpenOptions};
use std::io::Write;
use std::path::{Path,PathBuf};
use fs2::FileExt;
use serde::{Serialize,Deserialize};
use crate::audit::sha256;
use crate::fenced_coordinator::{
    FencingCheckpoint,FencingScope,IndependentMonotonicFencingAnchor,
};

const FORMAT:&str="GALIA_NONCANONICAL_DURABLE_ANCHOR_V1";
const MARKER:&str=".GALIA_NONCANONICAL_DURABLE_ANCHOR_V1";
const LOCK:&str=".anchor.lock";
const JOURNAL:&str="cas_history";

fn canonical<T:Serialize>(v:&T)->Result<Vec<u8>,String>{
    serde_json::to_value(v).and_then(|x|serde_json::to_vec(&x))
        .map_err(|e|e.to_string())
}
fn is_regular(path:&Path)->Result<(),String>{
    if !fs::symlink_metadata(path).map_err(|e|e.to_string())?.file_type().is_file(){
        return Err("anchor path is not a regular file".into())
    }
    Ok(())
}
fn is_directory(path:&Path)->Result<(),String>{
    if !fs::symlink_metadata(path).map_err(|e|e.to_string())?.file_type().is_dir(){
        return Err("anchor path is not a real directory".into())
    }
    Ok(())
}
fn read(path:&Path)->Result<Vec<u8>,String>{
    is_regular(path)?;
    fs::read(path).map_err(|e|e.to_string())
}
fn create_file(path:&Path,data:&[u8])->Result<(),String>{
    let mut f=OpenOptions::new().write(true).create_new(true).open(path)
        .map_err(|e|e.to_string())?;
    f.write_all(data).map_err(|e|e.to_string())?;
    f.sync_all().map_err(|e|e.to_string())
}
fn sync_dir(path:&Path)->Result<(),String>{
    File::open(path).and_then(|f|f.sync_all()).map_err(|e|e.to_string())
}
fn genesis()->FencingCheckpoint{
    FencingCheckpoint{
        record_count:0,journal_tip_sha256:None,
        active_grant:None,nonce_claim_count:0,
    }
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
struct AnchorMarker{
    format:String,
    scope:FencingScope,
    genesis:FencingCheckpoint,
}
impl AnchorMarker{
    fn new(scope:FencingScope)->Result<Self,String>{
        scope.validate()?;
        Ok(Self{format:FORMAT.into(),scope,genesis:genesis()})
    }
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct CasEntry{
    format:String,
    sequence:u64,
    previous_entry_sha256:Option<String>,
    from:FencingCheckpoint,
    to:FencingCheckpoint,
}
fn validate_transition(old:&FencingCheckpoint,new:&FencingCheckpoint)->Result<(),String>{
    old.validate()?;new.validate()?;
    if new.record_count!=old.record_count.checked_add(1).ok_or("anchor record overflow")?||
        new.journal_tip_sha256==old.journal_tip_sha256 {
        return Err("anchor successor must advance exactly one journal height and tip".into())
    }
    let new_grant=new.active_grant.as_ref().ok_or("anchored successor missing grant")?;
    match old.active_grant.as_ref(){
        None=>{
            if old.record_count!=0||new_grant.epoch!=1||
                new.nonce_claim_count!=0{
                return Err("anchor initial epoch transition invalid".into())
            }
        }
        Some(prior)=>{
            let rotation=prior!=new_grant;
            if rotation{
                if new_grant.epoch!=prior.epoch.checked_add(1).ok_or("epoch overflow")?||
                    new.nonce_claim_count!=old.nonce_claim_count{
                    return Err("anchor successor invalid epoch rotation".into())
                }
            }else if new.nonce_claim_count!=old.nonce_claim_count
                    .checked_add(1).ok_or("nonce count overflow")?{
                return Err("anchored commit must advance exactly one nonce claim".into())
            }
        }
    }
    Ok(())
}
struct AnchorState{
    value:FencingCheckpoint,
    count:u64,
    last_hash:Option<String>,
}
struct Guard(File);
impl Drop for Guard{
    fn drop(&mut self){let _=FileExt::unlock(&self.0);}
}
#[derive(Clone)]
pub struct DurableLocalMonotonicAnchor{
    root:PathBuf,
    marker:AnchorMarker,
}
impl DurableLocalMonotonicAnchor{
    /// Create a NEW local root, separate from the coordinator journal.
    /// Never treat a writable scratch directory as independent trust custody.
    pub fn initialize_new(root:impl AsRef<Path>,scope:FencingScope)
        ->Result<Self,String>{
        let marker=AnchorMarker::new(scope)?;
        let path=root.as_ref();
        if fs::symlink_metadata(path).is_ok(){
            return Err("anchor scratch root must not already exist".into())
        }
        fs::create_dir(path).map_err(|e|e.to_string())?;
        #[cfg(unix)]{
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path,fs::Permissions::from_mode(0o700))
                .map_err(|e|e.to_string())?;
        }
        create_file(&path.join(MARKER),&canonical(&marker)?)?;
        fs::create_dir(path.join(JOURNAL)).map_err(|e|e.to_string())?;
        create_file(&path.join(LOCK),b"")?;
        sync_dir(path)?;
        Self::open(path,marker.scope)
    }
    pub fn open(root:impl AsRef<Path>,scope:FencingScope)->Result<Self,String>{
        let marker=AnchorMarker::new(scope)?;
        let path=root.as_ref();
        is_directory(path)?;is_directory(&path.join(JOURNAL))?;
        is_regular(&path.join(LOCK))?;
        if read(&path.join(MARKER))?!=canonical(&marker)?{
            return Err("anchor marker and separately pinned scope differ".into())
        }
        let me=Self{root:fs::canonicalize(path).map_err(|e|e.to_string())?,marker};
        let _lock=me.lock()?;
        let _state=me.replay()?;
        Ok(me)
    }
    fn lock(&self)->Result<Guard,String>{
        is_regular(&self.root.join(LOCK))?;
        let file=OpenOptions::new().read(true).write(true).open(self.root.join(LOCK))
            .map_err(|e|e.to_string())?;
        FileExt::lock_exclusive(&file).map_err(|e|e.to_string())?;
        if read(&self.root.join(MARKER))?!=canonical(&self.marker)?{
            return Err("anchor marker changed under lock".into())
        }
        Ok(Guard(file))
    }
    fn replay(&self)->Result<AnchorState,String>{
        let dir=self.root.join(JOURNAL);
        is_directory(&dir)?;
        let mut list=Vec::new();
        for item in fs::read_dir(&dir).map_err(|e|e.to_string())?{
            let item=item.map_err(|e|e.to_string())?;
            is_regular(&item.path())?;
            list.push((item.file_name().into_string()
                .map_err(|_|"invalid anchor filename")?,item.path()));
        }
        list.sort_by(|a,b|a.0.cmp(&b.0));
        let mut state=AnchorState{
            value:self.marker.genesis.clone(),count:0,last_hash:None
        };
        for (i,(name,path)) in list.iter().enumerate(){
            let count=u64::try_from(i).map_err(|_|"anchor count overflow")?
                .checked_add(1).ok_or("anchor count overflow")?;
            if *name!=format!("{count:020}.json"){
                return Err("anchor journal has missing/extra/nonsequential entries".into())
            }
            let bytes=read(path)?;
            let entry:CasEntry=serde_json::from_slice(&bytes).map_err(|e|e.to_string())?;
            if canonical(&entry)?!=bytes||entry.format!=FORMAT||
                entry.sequence!=count||
                entry.previous_entry_sha256!=state.last_hash||
                entry.from!=state.value{
                return Err("anchor journal CAS lineage or canonical bytes corrupted".into())
            }
            validate_transition(&entry.from,&entry.to)?;
            state.value=entry.to;
            state.count=count;
            state.last_hash=Some(sha256(&bytes));
        }
        Ok(state)
    }
    /// Local, cooperative CAS: check exact old anchor and persist successor
    /// under the SAME exclusive lock. A second process sharing this root can
    /// never publish the same old->different successor.
    pub fn inspect(&self)->Result<(u64,FencingCheckpoint),String>{
        let _lock=self.lock()?;
        let s=self.replay()?;
        Ok((s.count,s.value))
    }
}
impl IndependentMonotonicFencingAnchor for DurableLocalMonotonicAnchor{
    fn current(&self,scope:&FencingScope)->Result<FencingCheckpoint,String>{
        if scope!=&self.marker.scope{return Err("foreign anchor scope".into())}
        Ok(self.inspect()?.1)
    }
    fn advance(&self,scope:&FencingScope,old:&FencingCheckpoint,
        next:&FencingCheckpoint)->Result<(),String>{
        if scope!=&self.marker.scope{return Err("foreign anchor CAS scope".into())}
        validate_transition(old,next)?;
        let _lock=self.lock()?;
        let mut state=self.replay()?;
        if &state.value!=old {
            return Err("durable local anchor CAS rejected stale/highwater floor".into())
        }
        let seq=state.count.checked_add(1).ok_or("anchor count overflow")?;
        let entry=CasEntry{
            format:FORMAT.into(),
            sequence:seq,previous_entry_sha256:state.last_hash.take(),
            from:old.clone(),to:next.clone(),
        };
        let bytes=canonical(&entry)?;
        create_file(&self.root.join(JOURNAL).join(format!("{seq:020}.json")),&bytes)?;
        sync_dir(&self.root.join(JOURNAL))?;
        Ok(())
    }
}
