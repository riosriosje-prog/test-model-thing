//! GALIA v0.31: LOCAL SCRATCH custody of independently pinned, signed fork
//! witness evidence. The full signed audit histories and separate signed
//! witness quorum are REVERIFIED at every read and append. Append-only
//! numbered canonical JSON records are hash-linked and fsynced.
//!
//! There is NO independently hosted publication network, real-world
//! organizational custody proof, production key store, P5 human approval,
//! automatic quarantine/repair, or canonical writeback. AUTHORITY_HOLD.
use std::collections::BTreeSet;
use std::fs::{self,File,OpenOptions};
use std::io::Write;
use std::path::{Path,PathBuf};
use fs2::FileExt;
use serde::{Serialize,Deserialize};
use crate::audit::sha256;
use crate::audit_equivocation::{compare_signed_audit_branches,AuditBranchFinding};
use crate::fork_witness::{
    ForkWitnessPolicy,SignedForkWitnessEndorsement,verify_fork_witness_quorum,
};
use crate::independent_audit::{AuditTrustPin,SignedAuditStatement};

pub const PUBLICATION_FORMAT:&str="GALIA_NONCANONICAL_FORK_PUBLICATION_V1";
const MARKER:&str=".GALIA_NONCANONICAL_FORK_PUBLICATION_V1";
const LOCK:&str=".publication.lock";
const ENTRIES:&str="entries";
const MAX_RECORD_BYTES:usize=2*1024*1024;
const MAX_RECORDS:u64=4096;
fn canon<T:Serialize>(v:&T)->Result<Vec<u8>,String>{
    serde_json::to_value(v).and_then(|x|serde_json::to_vec(&x))
        .map_err(|e|e.to_string())
}
fn valid_hash(s:&str)->bool{
    s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
}
fn regular(p:&Path)->Result<(),String>{
    let m=fs::symlink_metadata(p).map_err(|e|e.to_string())?;
    if !m.file_type().is_file(){return Err("publication entry must be a real regular file".into())}
    Ok(())
}
fn directory(p:&Path)->Result<(),String>{
    let m=fs::symlink_metadata(p).map_err(|e|e.to_string())?;
    if !m.file_type().is_dir(){return Err("publication directory must not be a symlink".into())}
    Ok(())
}
fn read(p:&Path)->Result<Vec<u8>,String>{
    regular(p)?;fs::read(p).map_err(|e|e.to_string())
}
fn write_new(p:&Path,bytes:&[u8])->Result<(),String>{
    let mut f=OpenOptions::new().write(true).create_new(true).open(p)
        .map_err(|e|e.to_string())?;
    f.write_all(bytes).map_err(|e|e.to_string())?;
    f.sync_all().map_err(|e|e.to_string())
}
fn sync_dir(p:&Path)->Result<(),String>{
    File::open(p).and_then(|f|f.sync_all()).map_err(|e|e.to_string())
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationMarker{
    format:String,
    audit_pin_sha256:String,
    witness_policy_sha256:String,
    stream_id:String,
}
impl PublicationMarker{
    fn expected(pin:&AuditTrustPin,policy:&ForkWitnessPolicy)->Result<Self,String>{
        policy.validate(pin)?;
        Ok(Self{
            format:PUBLICATION_FORMAT.into(),
            audit_pin_sha256:sha256(&canon(pin)?),
            witness_policy_sha256:sha256(&canon(policy)?),
            stream_id:pin.stream_id.clone(),
        })
    }
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedForkBundle{
    pub left_audit_branch:Vec<SignedAuditStatement>,
    pub right_audit_branch:Vec<SignedAuditStatement>,
    pub witnesses:Vec<SignedForkWitnessEndorsement>,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationEntry{
    format:String,
    sequence:u64,
    previous_entry_sha256:Option<String>,
    auditor_fork_fingerprint_sha256:String,
    full_fork_evidence_sha256:String,
    policy_sha256:String,
    bundle:PublishedForkBundle,
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicationCheckpoint{
    pub entry_count:u64,
    pub last_entry_sha256:Option<String>,
}
impl PublicationCheckpoint{
    pub fn validate(&self)->Result<(),String>{
        if self.entry_count>MAX_RECORDS||
            (self.entry_count==0)!=self.last_entry_sha256.is_none()||
            self.last_entry_sha256.as_ref().is_some_and(|s|!valid_hash(s)){
            return Err("invalid publication high-water count or digest".into())
        }
        Ok(())
    }
}
#[derive(Clone,Debug,Serialize)]
pub struct PublicationReceipt{
    pub status:&'static str,
    pub checkpoint:PublicationCheckpoint,
    pub fork_fingerprint_sha256:String,
    pub signed_quorum_reverified:bool,
    pub auditor_fork_reverified:bool,
    pub local_scratch_record_committed:bool,
    pub external_publication_verified:bool,
    pub real_witness_key_custody_verified:bool,
    pub human_authority_verified:bool,
    pub canonical_writeback:bool,
    pub authority_transfer:bool,
}
fn prove_fork(
    pin:&AuditTrustPin,policy:&ForkWitnessPolicy,
    bundle:&PublishedForkBundle
)->Result<(String,String),String>{
    let report=verify_fork_witness_quorum(pin,policy,
        &bundle.left_audit_branch,&bundle.right_audit_branch,
        &bundle.witnesses)?;
    let a=compare_signed_audit_branches(pin,&bundle.left_audit_branch,
        &bundle.right_audit_branch)?;
    if a.finding!=AuditBranchFinding::SignedAuditorForkEvidence{
        return Err("only a signed auditor fork with actual distinct witness quorum may publish".into())
    }
    let f=a.fork.ok_or("missing double-signed auditor fork")?;
    let mut pair=[f.left_signed_sha256,f.right_signed_sha256];
    pair.sort();
    // A swapped branch ordering or different signer-quorum combination MUST
    // map to the same fingerprint. Exact same audit floor/scope is pinned.
    let fingerprint=sha256(&canon(&(
        pin.stream_id.as_str(),&pin.scope,pin.floor_sequence,
        &pin.floor_signed_sha256,f.first_conflicting_sequence,
        &f.shared_previous_signed_sha256,pair
    ))?);
    Ok((fingerprint,report.fork_evidence_sha256))
}
struct PublicationState{
    tip:Option<String>,
    count:u64,
    distinct_forks:BTreeSet<String>,
    prefix:Vec<String>,
    bundles:Vec<PublishedForkBundle>,
}
struct Guard(File);
impl Drop for Guard{fn drop(&mut self){let _=FileExt::unlock(&self.0);}}
#[derive(Clone)]
pub struct ScratchForkPublication{
    root:PathBuf,
    marker:PublicationMarker,
    pin:AuditTrustPin,
    policy:ForkWitnessPolicy,
}
impl ScratchForkPublication{
    pub fn initialize_new(root:impl AsRef<Path>,pin:AuditTrustPin,
        policy:ForkWitnessPolicy)->Result<Self,String>{
        let marker=PublicationMarker::expected(&pin,&policy)?;
        let root=root.as_ref();
        if fs::symlink_metadata(root).is_ok(){
            return Err("refuse pre-existing scratch publication root".into())
        }
        fs::create_dir(root).map_err(|e|e.to_string())?;
        #[cfg(unix)]{
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root,fs::Permissions::from_mode(0o700))
                .map_err(|e|e.to_string())?;
        }
        write_new(&root.join(MARKER),&canon(&marker)?)?;
        fs::create_dir(root.join(ENTRIES)).map_err(|e|e.to_string())?;
        write_new(&root.join(LOCK),b"")?;
        sync_dir(root)?;
        Self::open(root,pin,policy)
    }
    pub fn open(root:impl AsRef<Path>,pin:AuditTrustPin,
        policy:ForkWitnessPolicy)->Result<Self,String>{
        let marker=PublicationMarker::expected(&pin,&policy)?;
        let p=root.as_ref();
        directory(p)?;directory(&p.join(ENTRIES))?;regular(&p.join(LOCK))?;
        if read(&p.join(MARKER))?!=canon(&marker)?{
            return Err("external trust pin/policy disagrees with existing publication root".into())
        }
        let store=Self{
            root:fs::canonicalize(p).map_err(|e|e.to_string())?,
            marker,pin,policy,
        };
        let _lock=store.lock()?;
        store.replay()?;
        Ok(store)
    }
    fn lock(&self)->Result<Guard,String>{
        regular(&self.root.join(LOCK))?;
        let f=OpenOptions::new().read(true).write(true).open(self.root.join(LOCK))
            .map_err(|e|e.to_string())?;
        FileExt::lock_exclusive(&f).map_err(|e|e.to_string())?;
        if read(&self.root.join(MARKER))?!=canon(&self.marker)?{
            return Err("publication marker changed after open".into())
        }
        Ok(Guard(f))
    }
    fn replay(&self)->Result<PublicationState,String>{
        let path=self.root.join(ENTRIES);
        directory(&path)?;
        let mut names=Vec::new();
        for item in fs::read_dir(&path).map_err(|e|e.to_string())?{
            let item=item.map_err(|e|e.to_string())?;
            regular(&item.path())?;
            let name=item.file_name().into_string().map_err(|_|"non-UTF8 publication record")?;
            names.push((name,item.path()));
        }
        if names.len()>MAX_RECORDS as usize{return Err("publication exceeds journal record cap".into())}
        names.sort_by(|a,b|a.0.cmp(&b.0));
        let mut s=PublicationState{
            tip:None,count:0,distinct_forks:BTreeSet::new(),
            prefix:Vec::new(),bundles:Vec::new()
        };
        for (i,(filename,path)) in names.into_iter().enumerate(){
            let sequence=u64::try_from(i).map_err(|_|"publication count overflow")?
                .checked_add(1).ok_or("publication count overflow")?;
            if filename!=format!("{sequence:020}.json"){
                return Err("gap, undeclared file or misleading publication filename".into())
            }
            let raw=read(&path)?;
            if raw.is_empty()||raw.len()>MAX_RECORD_BYTES{
                return Err("empty or oversized publication entry".into())
            }
            let entry:PublicationEntry=serde_json::from_slice(&raw)
                .map_err(|e|e.to_string())?;
            if raw!=canon(&entry)?||entry.format!=PUBLICATION_FORMAT||
                entry.sequence!=sequence||entry.previous_entry_sha256!=s.tip||
                entry.policy_sha256!=self.marker.witness_policy_sha256{
                return Err("publication record altered or noncanonical".into())
            }
            let (fingerprint,evidence)=prove_fork(&self.pin,&self.policy,&entry.bundle)?;
            if entry.auditor_fork_fingerprint_sha256!=fingerprint||
                entry.full_fork_evidence_sha256!=evidence||
                !s.distinct_forks.insert(fingerprint){
                return Err("duplicate or forged signed fork publication".into())
            }
            s.tip=Some(sha256(&raw));
            s.count=sequence;
            s.prefix.push(s.tip.clone().ok_or("missing hash")?);
            s.bundles.push(entry.bundle);
        }
        Ok(s)
    }
    pub fn checkpoint(&self)->Result<PublicationCheckpoint,String>{
        let _guard=self.lock()?;
        let s=self.replay()?;
        Ok(PublicationCheckpoint{entry_count:s.count,last_entry_sha256:s.tip})
    }
    /// Caller must protect this exact pin OUTSIDE mutable scratch storage.
    /// A local re-written floor is not a monotonic trust root.
    pub fn verify_floor(&self,external:&PublicationCheckpoint)->Result<PublicationCheckpoint,String>{
        external.validate()?;
        let _guard=self.lock()?;
        let s=self.replay()?;
        if external.entry_count>s.count{
            return Err("publication rolled back behind external high-water".into())
        }
        let local=if external.entry_count==0{None}else{
            let i=usize::try_from(external.entry_count-1).map_err(|_|"floor overflow")?;
            Some(s.prefix.get(i).ok_or("missing publication prefix")?.clone())
        };
        if local!=external.last_entry_sha256{
            return Err("published signed history diverges from externally retained prefix".into())
        }
        Ok(PublicationCheckpoint{entry_count:s.count,last_entry_sha256:s.tip})
    }
    /// Full signature revalidation before ANY returned historical bundles.
    pub fn published(&self)->Result<Vec<PublishedForkBundle>,String>{
        let _guard=self.lock()?;
        Ok(self.replay()?.bundles)
    }
    /// No online network calls; this is NOT publication to a third party.
    pub fn append(&self,bundle:PublishedForkBundle)->Result<PublicationReceipt,String>{
        let _guard=self.lock()?;
        let mut s=self.replay()?;
        let (fingerprint,evidence)=prove_fork(&self.pin,&self.policy,&bundle)?;
        if s.distinct_forks.contains(&fingerprint){
            return Err("same verified fork was already published to local scratch".into())
        }
        let sequence=s.count.checked_add(1).ok_or("publication sequence overflow")?;
        if sequence>MAX_RECORDS{return Err("publication record cap exceeded".into())}
        let entry=PublicationEntry{
            format:PUBLICATION_FORMAT.into(),
            sequence,previous_entry_sha256:s.tip,
            auditor_fork_fingerprint_sha256:fingerprint.clone(),
            full_fork_evidence_sha256:evidence,
            policy_sha256:self.marker.witness_policy_sha256.clone(),
            bundle,
        };
        let raw=canon(&entry)?;
        if raw.len()>MAX_RECORD_BYTES{return Err("fork evidence packet exceeds size cap".into())}
        let entry_path=self.root.join(ENTRIES).join(format!("{sequence:020}.json"));
        write_new(&entry_path,&raw)?;
        sync_dir(&self.root.join(ENTRIES))?;
        s.tip=Some(sha256(&raw));s.count=sequence;
        Ok(PublicationReceipt{
            status:"SCRATCH_SIGNED_FORK_PUBLICATION_ONLY",
            checkpoint:PublicationCheckpoint{entry_count:sequence,last_entry_sha256:s.tip},
            fork_fingerprint_sha256:fingerprint,
            signed_quorum_reverified:true,auditor_fork_reverified:true,
            local_scratch_record_committed:true,
            external_publication_verified:false,real_witness_key_custody_verified:false,
            human_authority_verified:false,canonical_writeback:false,
            authority_transfer:false,
        })
    }
}
