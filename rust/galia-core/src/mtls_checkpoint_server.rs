//! GALIA v0.20: EXPERIMENTAL local mTLS checkpoint-response service.
//! The fixture actually negotiates TLS 1.3 and requires client certificates.
//! Checkpoint and nonce journals are restricted to an explicitly new local
//! scratch root. No production deployment, independent signer custody,
//! remote consensus, P5 human authority, or canonical GALIA writeback.
//!
//! Signed checkpoint envelopes are caller-supplied: signatures authenticate a
//! signed claim, NOT the physical provenance of the underlying board events.
use std::collections::BTreeSet;
use std::fs::{self,File,OpenOptions};
use std::io::{Read,Write};
use std::net::TcpStream;
use std::path::{Path,PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fs2::FileExt;
use rustls::{ProtocolVersion,RootCertStore,ServerConfig,ServerConnection,StreamOwned};
use rustls::pki_types::{CertificateDer,PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use serde::{Deserialize,Serialize};

use crate::audit::sha256;
use crate::attestation::signing_preimage;
use crate::external_checkpoint::{
    CheckpointAnchorTrust,SignedExternalBoardCheckpoint,verify_anchor_chain,policy_digest,
};
use crate::external_transport::{
    ExternalServiceTrust,RemoteCheckpointChallenge,RemoteCheckpointPayload,
    SignedRemoteCheckpointResponse,REQUEST_FORMAT,RESPONSE_FORMAT,RESPONSE_DOMAIN,
};
use crate::transparency::ObserverPolicy;
use crate::witness_proof::verify_detached;
use crate::fenced_coordinator::{FencingAuthority,EpochGrant};
use crate::external_checkpoint::policy_digest;

const MARKER:&str=".GALIA_NONCANONICAL_MTLS_CHECKPOINT_SERVER_V1";
const CHECKPOINTS:&str="checkpoints";
const NONCES:&str="nonce_claims";
const LOCK:&str=".server.lock";
const FORMAT:&str="GALIA_NONCANONICAL_MTLS_CHECKPOINT_SERVER_V1";
const MAX_WIRE:usize=1024*1024;
const EXPORTER_LABEL:&[u8]=b"EXPORTER-GALIA-CHECKPOINT-V0.19";

fn canonical<T:Serialize>(v:&T)->Result<Vec<u8>,String>{
    serde_json::to_value(v).and_then(|x|serde_json::to_vec(&x))
        .map_err(|e|e.to_string())
}
fn digest(s:&str)->bool{s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn real_dir(p:&Path)->Result<(),String>{
    let m=fs::symlink_metadata(p).map_err(|e|e.to_string())?;
    if !m.file_type().is_dir(){return Err("scratch directory must be real and not a symlink".into())}
    Ok(())
}
fn regular(p:&Path)->Result<(),String>{
    let m=fs::symlink_metadata(p).map_err(|e|e.to_string())?;
    if !m.file_type().is_file(){return Err("scratch file must be regular, not symlink".into())}
    Ok(())
}
fn read(p:&Path)->Result<Vec<u8>,String>{
    regular(p)?;
    fs::read(p).map_err(|e|e.to_string())
}
fn write_new(p:&Path,bytes:&[u8])->Result<(),String>{
    let mut file=OpenOptions::new().write(true).create_new(true).open(p)
        .map_err(|e|e.to_string())?;
    file.write_all(bytes).map_err(|e|e.to_string())?;
    file.sync_all().map_err(|e|e.to_string())
}
fn sync_dir(p:&Path)->Result<(),String>{
    File::open(p).and_then(|f|f.sync_all()).map_err(|e|e.to_string())
}
fn numbered_files(p:&Path)->Result<Vec<Vec<u8>>,String>{
    real_dir(p)?;
    let mut files=Vec::new();
    for f in fs::read_dir(p).map_err(|e|e.to_string())?{
        let f=f.map_err(|e|e.to_string())?;
        regular(&f.path())?;
        let name=f.file_name().into_string().map_err(|_|"non UTF-8 scratch name")?;
        files.push((name,f.path()));
    }
    files.sort_by(|a,b|a.0.cmp(&b.0));
    let mut records=Vec::new();
    for (i,(name,path)) in files.into_iter().enumerate(){
        let seq=u64::try_from(i).map_err(|_|"journal count overflow")?
            .checked_add(1).ok_or("journal count overflow")?;
        if name!=format!("{seq:020}.json"){
            return Err("unexpected, missing or renamed scratch journal entry".into())
        }
        records.push(read(&path)?);
    }
    Ok(records)
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreMarker{
    format:String,
    service_trust_sha256:String,
    observer_policy_sha256:String,
    base_anchor_sha256:String,
}
impl StoreMarker{
    fn expected(t:&ExternalServiceTrust,p:&ObserverPolicy)->Result<Self,String>{
        t.validate(p)?;
        if t.checkpoint.floor_sequence!=0||
            t.checkpoint.floor_envelope_sha256.is_some()||
            t.checkpoint.floor_board.journal_count!=0||
            t.checkpoint.floor_board.journal_tip_sha256.is_some()||
            t.checkpoint.floor_board.quarantined{
            return Err("new test service requires empty externally pinned checkpoint genesis".into())
        }
        Ok(Self{
            format:FORMAT.into(),
            service_trust_sha256:sha256(&canonical(t)?),
            observer_policy_sha256:policy_digest(p)?,
            base_anchor_sha256:sha256(&canonical(&t.checkpoint)?),
        })
    }
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct NonceClaim{
    format:String,
    sequence:u64,
    previous_sha256:Option<String>,
    nonce_sha256:String,
    challenge_sha256:String,
}
struct NonceHistory{
    count:u64,
    tip:Option<String>,
    seen:BTreeSet<String>,
}

/// Verified *local scratch* service journal heads; not independently anchored.
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct ServiceSnapshot {
    pub checkpoint_count:u64,
    pub checkpoint_tip_sha256:Option<String>,
    pub nonce_count:u64,
    pub nonce_tip_sha256:Option<String>,
}
impl ServiceSnapshot{
    pub fn validate(&self)->Result<(),String>{
        if (self.checkpoint_count==0)!=self.checkpoint_tip_sha256.is_none()
            ||(self.nonce_count==0)!=self.nonce_tip_sha256.is_none()
            ||self.checkpoint_tip_sha256.as_ref().is_some_and(|s|!digest(s))
            ||self.nonce_tip_sha256.as_ref().is_some_and(|s|!digest(s)){
            return Err("invalid local service snapshot count/hash".into())
        }
        Ok(())
    }
}
struct Guard(File);
impl Drop for Guard{
    fn drop(&mut self){let _=FileExt::unlock(&self.0);}
}
#[derive(Clone)]
pub struct ScratchCheckpointServiceStore{
    root:PathBuf,
    marker:StoreMarker,
    trust:ExternalServiceTrust,
    policy:ObserverPolicy,
}
impl ScratchCheckpointServiceStore{
    pub fn initialize_new(root:impl AsRef<Path>,
        trust:ExternalServiceTrust,policy:ObserverPolicy)->Result<Self,String>{
        let marker=StoreMarker::expected(&trust,&policy)?;
        let root=root.as_ref();
        if fs::symlink_metadata(root).is_ok(){
            return Err("refuse to use an existing root as a scratch test service".into())
        }
        fs::create_dir(root).map_err(|e|e.to_string())?;
        #[cfg(unix)]{
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root,fs::Permissions::from_mode(0o700))
                .map_err(|e|e.to_string())?;
        }
        write_new(&root.join(MARKER),&canonical(&marker)?)?;
        fs::create_dir(root.join(CHECKPOINTS)).map_err(|e|e.to_string())?;
        fs::create_dir(root.join(NONCES)).map_err(|e|e.to_string())?;
        write_new(&root.join(LOCK),b"")?;
        sync_dir(root)?;
        Self::open(root,trust,policy)
    }
    pub fn open(root:impl AsRef<Path>,
        trust:ExternalServiceTrust,policy:ObserverPolicy)->Result<Self,String>{
        let marker=StoreMarker::expected(&trust,&policy)?;
        let root=root.as_ref();
        real_dir(root)?;real_dir(&root.join(CHECKPOINTS))?;
        real_dir(&root.join(NONCES))?;regular(&root.join(LOCK))?;
        if read(&root.join(MARKER))?!=canonical(&marker)?{
            return Err("store differs from separately supplied pinned service/observer trust".into())
        }
        let store=Self{
            root:fs::canonicalize(root).map_err(|e|e.to_string())?,
            marker,trust,policy,
        };
        let _lock=store.lock()?;
        let _=store.checkpoints()?;
        let _=store.nonces()?;
        Ok(store)
    }
    fn lock(&self)->Result<Guard,String>{
        regular(&self.root.join(LOCK))?;
        let f=OpenOptions::new().read(true).write(true).open(self.root.join(LOCK))
            .map_err(|e|e.to_string())?;
        FileExt::lock_exclusive(&f).map_err(|e|e.to_string())?;
        if read(&self.root.join(MARKER))?!=canonical(&self.marker)?{
            return Err("scratch service marker changed".into())
        }
        Ok(Guard(f))
    }
    fn checkpoints(&self)->Result<Vec<SignedExternalBoardCheckpoint>,String>{
        let mut entries=Vec::new();
        for bytes in numbered_files(&self.root.join(CHECKPOINTS))?{
            let signed:SignedExternalBoardCheckpoint=serde_json::from_slice(&bytes)
                .map_err(|e|e.to_string())?;
            if bytes!=canonical(&signed)?{
                return Err("noncanonical signed service checkpoint".into())
            }
            entries.push(signed);
        }
        if !entries.is_empty(){
            verify_anchor_chain(&self.trust.checkpoint,&self.policy,&entries)?;
        }
        Ok(entries)
    }
    fn nonces(&self)->Result<NonceHistory,String>{
        let mut previous=None;
        let mut seen=BTreeSet::new();
        let mut count=0u64;
        for bytes in numbered_files(&self.root.join(NONCES))?{
            let e:NonceClaim=serde_json::from_slice(&bytes).map_err(|e|e.to_string())?;
            count=count.checked_add(1).ok_or("nonce count overflow")?;
            if bytes!=canonical(&e)?||e.format!=FORMAT||
                e.sequence!=count||e.previous_sha256!=previous||
                !digest(&e.nonce_sha256)||!digest(&e.challenge_sha256)||
                !seen.insert(e.nonce_sha256) {
                return Err("nonce service journal corrupted, replayed or wrong scope".into())
            }
            previous=Some(sha256(&bytes));
        }
        Ok(NonceHistory{count,tip:previous,seen})
    }
    /// The offline signer has already signed this checkpoint; the store ONLY
    /// verifies its signature and appends it. It does NOT possess a private key
    /// and cannot attest that underlying board events really happened.
    pub fn append_signed(&self,signed:SignedExternalBoardCheckpoint)->Result<u64,String>{
        let _lock=self.lock()?;
        let mut chain=self.checkpoints()?;
        let next=u64::try_from(chain.len()).map_err(|_|"checkpoint count overflow")?
            .checked_add(1).ok_or("checkpoint overflow")?;
        chain.push(signed.clone());
        verify_anchor_chain(&self.trust.checkpoint,&self.policy,&chain)?;
        let raw=canonical(&signed)?;
        write_new(&self.root.join(CHECKPOINTS).join(format!("{next:020}.json")),&raw)?;
        sync_dir(&self.root.join(CHECKPOINTS))?;
        Ok(next)
    }
    /// Signed suffix only from a caller's EXACT previously known digest.
    /// Different histories at the same height fail closed; never reset a pin.
    pub fn checkpoint_suffix(&self,floor:u64,
        floor_hash:Option<&str>)->Result<Vec<SignedExternalBoardCheckpoint>,String>{
        let _lock=self.lock()?;
        self.checkpoint_suffix_locked(floor,floor_hash)
    }
    fn checkpoint_suffix_locked(&self,floor:u64,
        floor_hash:Option<&str>)->Result<Vec<SignedExternalBoardCheckpoint>,String>{
        let chain=self.checkpoints()?;
        let n=usize::try_from(floor).map_err(|_|"checkpoint height out of range")?;
        if n>chain.len(){return Err("client checkpoint floor is ahead of service".into())}
        let existing=if n==0{None}else{
            Some(sha256(&canonical(&chain[n-1])?))
        };
        if existing.as_deref()!=floor_hash {
            return Err("client floor is not in this signed checkpoint history".into())
        }
        let suffix=chain[n..].to_vec();
        if suffix.is_empty()||suffix.len()>128{
            return Err("no new checkpoint or suffix exceeds 128 envelopes".into())
        }
        Ok(suffix)
    }
    fn claim_nonce_locked(&self,nonce:&str,challenge_hash:&str)->Result<(),String>{
        if !digest(nonce)||!digest(challenge_hash){return Err("invalid nonce/challenge SHA-256".into())}
        let current=self.nonces()?;
        if current.seen.contains(nonce){return Err("server nonce already consumed".into())}
        let sequence=current.count.checked_add(1).ok_or("nonce journal count overflow")?;
        let e=NonceClaim{
            format:FORMAT.into(),sequence,previous_sha256:current.tip,
            nonce_sha256:nonce.into(),challenge_sha256:challenge_hash.into(),
        };
        let raw=canonical(&e)?;
        write_new(&self.root.join(NONCES).join(format!("{sequence:020}.json")),&raw)?;
        sync_dir(&self.root.join(NONCES))
    }
    /// Snapshot is generated under one filesystem lock after BOTH journals are
    /// completely replayed. It has no independent authenticity without a
    /// separately retained signature/key and trusted monotonic high-water.
    pub fn snapshot(&self)->Result<ServiceSnapshot,String>{
        let _guard=self.lock()?;
        self.snapshot_locked()
    }
    fn snapshot_locked(&self)->Result<ServiceSnapshot,String>{
        let chain=self.checkpoints()?;
        let nonce=self.nonces()?;
        let snapshot=ServiceSnapshot{
            checkpoint_count:u64::try_from(chain.len()).map_err(|_|"checkpoint count overflow")?,
            checkpoint_tip_sha256:chain.last()
                .map(|last|canonical(last).map(|raw|sha256(&raw))).transpose()?,
            nonce_count:nonce.count,
            nonce_tip_sha256:nonce.tip,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }
    /// Fail-closed read-only check against a checkpoint pinned OUTSIDE this
    /// mutable scratch root. A prior head remains comparable after growth:
    /// both historical prefix hashes must be byte-for-byte identical.
    pub fn verify_external_floor(&self,pinned:&ServiceSnapshot)->Result<ServiceSnapshot,String>{
        pinned.validate()?;
        let _guard=self.lock()?;
        let chain=self.checkpoints()?;
        let nonces=self.nonces()?;
        let saved=usize::try_from(pinned.checkpoint_count)
            .map_err(|_|"checkpoint floor count overflow")?;
        if saved>chain.len()||pinned.nonce_count>nonces.count{
            return Err("local scratch service was truncated below external signed floor".into())
        }
        let checkpoint_tip=if saved==0{None}else{
            Some(sha256(&canonical(&chain[saved-1])?))
        };
        // nonce entries are completely validated before checking historical
        // bytes, under the same cooperative local lock.
        let raw_nonce=numbered_files(&self.root.join(NONCES))?;
        let nonce_tip=if pinned.nonce_count==0{None}else{
            let index=usize::try_from(pinned.nonce_count-1)
                .map_err(|_|"nonce floor count overflow")?;
            Some(sha256(raw_nonce.get(index).ok_or("nonce floor truncated")?))
        };
        if checkpoint_tip!=pinned.checkpoint_tip_sha256||
            nonce_tip!=pinned.nonce_tip_sha256{
            return Err("service journal prefix diverges from independently pinned snapshot".into())
        }
        let current=ServiceSnapshot{
            checkpoint_count:u64::try_from(chain.len()).map_err(|_|"count overflow")?,
            checkpoint_tip_sha256:chain.last()
                .map(|last|canonical(last).map(|raw|sha256(&raw))).transpose()?,
            nonce_count:nonces.count,
            nonce_tip_sha256:nonces.tip,
        };
        current.validate()?;
        Ok(current)
    }
    pub fn inspect(&self)->Result<(u64,u64),String>{
        let _lock=self.lock()?;
        let c=self.checkpoints()?;
        let n=self.nonces()?;
        Ok((u64::try_from(c.len()).map_err(|_|"count overflow")?,n.count))
    }
}
/// The server embeds the mandatory client-certificate verifier during config
/// creation. Callers cannot pass a server config with mTLS turned OFF.
pub struct MandatoryMtlsCheckpointServer{
    config:Arc<ServerConfig>,
    store:Arc<ScratchCheckpointServiceStore>,
    service:ExternalServiceTrust,
    signer:Arc<dyn Fn(&RemoteCheckpointPayload)->Result<String,String>+Send+Sync>,
    timeout:Duration,
}
impl MandatoryMtlsCheckpointServer{
    pub fn new(
        client_roots:RootCertStore,
        server_certificates:Vec<CertificateDer<'static>>,
        server_private_key:PrivateKeyDer<'static>,
        store:Arc<ScratchCheckpointServiceStore>,
        signer:Arc<dyn Fn(&RemoteCheckpointPayload)->Result<String,String>+Send+Sync>,
        timeout:Duration,
    )->Result<Self,String>{
        if server_certificates.is_empty()||client_roots.is_empty()||
            timeout.is_zero()||timeout>Duration::from_secs(30){
            return Err("mandatory mTLS requires roots, certificates and bounded timeout".into())
        }
        let (_,server_x509)=x509_parser::parse_x509_certificate(
            server_certificates[0].as_ref()).map_err(|e|e.to_string())?;
        if sha256(server_x509.public_key().raw)!=store.trust.pinned_tls_peer_spki_sha256{
            return Err("server certificate SPKI differs from externally pinned service identity".into())
        }
        let verifier=WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build().map_err(|e|e.to_string())?;
        let config=ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_certificates,server_private_key)
            .map_err(|e|e.to_string())?;
        Ok(Self{
            config:Arc::new(config),service:store.trust.clone(),store,signer,timeout,
        })
    }
    /// Original uncoordinated scratch-only handler (retained for v0.20
    /// compatibility). It is NOT safe as a globally unique nonce path.
    pub fn serve_one(&self,socket:TcpStream,trusted_now:u64)->Result<(),String>{
        self.serve_inner(socket,trusted_now,None)
    }
    /// Opt-in fenced handler. A remote/partitioned coordinator adapter MUST
    /// return Err; there is NO fallback to the local-only nonce journal.
    /// Local scratch service writes are NOT independently protected against
    /// old-epoch late commits across real hosts; storage-side fencing remains
    /// required before production.
    pub fn serve_one_fenced(&self,socket:TcpStream,trusted_now:u64,
        authority:&dyn FencingAuthority,grant:&EpochGrant)->Result<(),String>{
        let scope=authority.scope()?;
        if scope.namespace!=self.service.checkpoint.namespace||
            scope.case_id!=self.service.checkpoint.case_id||
            scope.service_id!=self.service.service_id||
            scope.pinned_observer_policy_sha256!=policy_digest(&self.store.policy)?{
            return Err("coordinator scope does not match independently provisioned GALIA policy".into())
        }
        self.serve_inner(socket,trusted_now,Some((authority,grant)))
    }
    fn serve_inner(&self,mut socket:TcpStream,trusted_now:u64,
        fencing:Option<(&dyn FencingAuthority,&EpochGrant)>)->Result<(),String>{
        socket.set_read_timeout(Some(self.timeout)).map_err(|e|e.to_string())?;
        socket.set_write_timeout(Some(self.timeout)).map_err(|e|e.to_string())?;
        let mut conn=ServerConnection::new(Arc::clone(&self.config)).map_err(|e|e.to_string())?;
        while conn.is_handshaking(){
            conn.complete_io(&mut socket).map_err(|e|e.to_string())?;
        }
        if conn.protocol_version()!=Some(ProtocolVersion::TLSv1_3)||
            conn.peer_certificates().and_then(|c|c.first()).is_none(){
            return Err("mandatory client certificate was not authenticated".into())
        }
        let mut exporter=[0u8;32];
        conn.export_keying_material(
            &mut exporter,EXPORTER_LABEL,Some(self.service.service_id.as_bytes())
        ).map_err(|e|e.to_string())?;
        let channel_hash=sha256(&exporter);
        let mut stream=StreamOwned::new(conn,socket);
        let mut len=[0u8;4];
        stream.read_exact(&mut len).map_err(|e|e.to_string())?;
        let n=u32::from_be_bytes(len) as usize;
        if n==0||n>MAX_WIRE{return Err("invalid/oversized checkpoint challenge".into())}
        let mut bytes=vec![0u8;n];
        stream.read_exact(&mut bytes).map_err(|e|e.to_string())?;
        let challenge:RemoteCheckpointChallenge=serde_json::from_slice(&bytes)
            .map_err(|e|e.to_string())?;
        let c=&challenge;
        if c.format!=REQUEST_FORMAT||
            c.service_id!=self.service.service_id||
            c.stream_id!=self.service.checkpoint.stream_id||
            c.namespace!=self.service.checkpoint.namespace||
            c.case_id!=self.service.checkpoint.case_id||
            c.tls_exporter_sha256!=channel_hash||
            !digest(&c.nonce_sha256)||
            c.expires_at_unix_seconds<=c.issued_at_unix_seconds||
            c.expires_at_unix_seconds-c.issued_at_unix_seconds>self.service.max_challenge_seconds||
            trusted_now<c.issued_at_unix_seconds||
            trusted_now>c.expires_at_unix_seconds{
            return Err("checkpoint challenge is stale, invalid or not bound to live TLS".into())
        }
        let _guard=self.store.lock()?;
        let suffix=self.store.checkpoint_suffix_locked(
            c.floor_sequence,c.floor_envelope_sha256.as_deref())?;
        let payload=RemoteCheckpointPayload{
            format:RESPONSE_FORMAT.into(),
            service_id:self.service.service_id.clone(),
            signer_id:self.service.response_signer_id.clone(),
            challenge_sha256:sha256(&canonical(c)?),
            nonce_sha256:c.nonce_sha256.clone(),
            tls_exporter_sha256:channel_hash,
            signed_at_unix_seconds:trusted_now,
            checkpoint_chain:suffix,
        };
        let signature_hex=(self.signer)(&payload)?;
        verify_detached(&self.service.response_signer_public_key_hex,
            &signature_hex,RESPONSE_DOMAIN,&payload)?;
        // Consume at the single shared coordinator FIRST. If it is unavailable,
        // stale, or knows the nonce, fail closed without a local service claim.
        // The two commits are intentionally NOT atomic: if the local write or
        // delivery fails, the global nonce is spent and needs human diagnosis.
        if let Some((authority,grant))=fencing{
            authority.claim(grant,&c.nonce_sha256)?;
        }
        // Consume BEFORE returning response. A failure after consumption burns
        // this nonce, which fails closed. It is NOT atomic with the client ack.
        self.store.claim_nonce_locked(&c.nonce_sha256,&payload.challenge_sha256)?;
        let response=SignedRemoteCheckpointResponse{payload,signature_hex};
        let raw=canonical(&response)?;
        if raw.is_empty()||raw.len()>MAX_WIRE {
            return Err("bounded response length exceeded after nonce claim".into())
        }
        stream.write_all(&(raw.len() as u32).to_be_bytes()).map_err(|e|e.to_string())?;
        stream.write_all(&raw).map_err(|e|e.to_string())?;
        stream.flush().map_err(|e|e.to_string())
    }
}
