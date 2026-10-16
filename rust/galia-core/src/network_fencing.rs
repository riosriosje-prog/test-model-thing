//! GALIA Rust v0.24: experimental mTLS 1.3 remote fencing RPC, loopback-tested.
//! Real authenticated TCP/TLS is used; NO public daemon, quorum, HSM, external
//! checkpoint custody, globally trusted epoch grants or canonical authority.
//! The server pins every authorized client's certificate SubjectPublicKeyInfo
//! to a host ID and refuses a token naming any other host. The client pins the
//! verified server SPKI and authenticated hostname. A partition fails closed.
use std::collections::{BTreeMap,BTreeSet};
use std::io::{Read,Write};
use std::net::{SocketAddr,TcpStream};
use std::sync::Arc;
use std::time::Duration;
use rustls::{ClientConfig,ClientConnection,ProtocolVersion,RootCertStore,
    ServerConfig,ServerConnection,StreamOwned};
use rustls::pki_types::{CertificateDer,PrivateKeyDer,ServerName};
use rustls::server::WebPkiClientVerifier;
use serde::{Deserialize,Serialize};
use crate::audit::sha256;
use crate::external_transport::{SignedRemoteCheckpointResponse,RESPONSE_DOMAIN};
use crate::witness_proof::verify_detached;
use crate::fenced_coordinator::{DurableFencingCoordinator,FencingAuthority,
    FencingScope,EpochGrant,FencingCheckpoint,FencedCommitReceipt};

const MAX_FRAME:usize=1024*1024+8192;
fn valid_name(s:&str)->bool{!s.trim().is_empty()&&s.len()<=256&&!s.chars().any(|c|c.is_control())}
fn digest(s:&str)->bool{s.len()==64&&s.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c))}
fn spki(cert:&CertificateDer<'_>)->Result<String,String>{
    let (_,x509)=x509_parser::parse_x509_certificate(cert.as_ref())
        .map_err(|e|e.to_string())?;
    Ok(sha256(x509.public_key().raw))
}
fn write_frame<W:Write,T:Serialize>(stream:&mut W,value:&T)->Result<(),String>{
    let bytes=serde_json::to_vec(value).map_err(|e|e.to_string())?;
    if bytes.is_empty()||bytes.len()>MAX_FRAME{
        return Err("fencing RPC oversized or empty outbound frame".into())
    }
    let len=u32::try_from(bytes.len()).map_err(|_|"frame length overflow")?;
    stream.write_all(&len.to_be_bytes()).map_err(|e|e.to_string())?;
    stream.write_all(&bytes).map_err(|e|e.to_string())?;
    stream.flush().map_err(|e|e.to_string())
}
fn read_frame<R:Read,T:for<'de>Deserialize<'de>>(stream:&mut R)->Result<T,String>{
    let mut header=[0u8;4];
    stream.read_exact(&mut header).map_err(|e|e.to_string())?;
    let len=u32::from_be_bytes(header) as usize;
    if len==0||len>MAX_FRAME{return Err("fencing RPC invalid frame length".into())}
    let mut bytes=vec![0u8;len];
    stream.read_exact(&mut bytes).map_err(|e|e.to_string())?;
    serde_json::from_slice(&bytes).map_err(|e|e.to_string())
}
#[derive(Serialize,Deserialize)]
#[serde(tag="method",rename_all="SCREAMING_SNAKE_CASE",deny_unknown_fields)]
enum RpcRequest{
    Scope,
    Commit{grant:EpochGrant,nonce_sha256:String,response_json:String},
    Recover{nonce_sha256:String},
}
#[derive(Serialize,Deserialize)]
#[serde(tag="kind",rename_all="SCREAMING_SNAKE_CASE",deny_unknown_fields)]
enum RpcReply{
    Scope{scope:FencingScope},
    Committed{receipt:FencedCommitReceipt},
    Recovered{nonce_sha256:String,response_sha256:String,response_json:String},
    NotFound,
    Rejected{reason:String},
}
/// The only storage authority is one local cooperative scratch coordinator.
pub struct TlsFencingRpcServer{
    config:Arc<ServerConfig>,
    store:Arc<DurableFencingCoordinator>,
    allowed_hosts:BTreeMap<String,String>,
    timeout:Duration,
}
impl TlsFencingRpcServer{
    pub fn new(store:Arc<DurableFencingCoordinator>,
        server_certificates:Vec<CertificateDer<'static>>,
        server_private_key:PrivateKeyDer<'static>,
        trusted_client_roots:RootCertStore,
        pinned_client_spki_by_host:BTreeMap<String,String>,
        timeout:Duration)->Result<Self,String>{
        if server_certificates.is_empty()||trusted_client_roots.is_empty()||
            pinned_client_spki_by_host.is_empty()||
            timeout.is_zero()||timeout>Duration::from_secs(30){
            return Err("invalid mandatory-mTLS server configuration".into())
        }
        let mut identities=BTreeSet::new();
        for (host,key) in &pinned_client_spki_by_host{
            if !valid_name(host)||!digest(key)||!identities.insert(key.clone()){
                return Err("client host pins are malformed or reuse one credential".into())
            }
        }
        let verifier=WebPkiClientVerifier::builder(Arc::new(trusted_client_roots))
            .build().map_err(|e|e.to_string())?;
        let config=ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_certificates,server_private_key)
            .map_err(|e|e.to_string())?;
        Ok(Self{config:Arc::new(config),store,allowed_hosts:pinned_client_spki_by_host,timeout})
    }
    pub fn serve_one(&self,mut socket:TcpStream)->Result<(),String>{
        socket.set_read_timeout(Some(self.timeout)).map_err(|e|e.to_string())?;
        socket.set_write_timeout(Some(self.timeout)).map_err(|e|e.to_string())?;
        let mut tls=ServerConnection::new(Arc::clone(&self.config))
            .map_err(|e|e.to_string())?;
        while tls.is_handshaking(){tls.complete_io(&mut socket).map_err(|e|e.to_string())?;}
        if tls.protocol_version()!=Some(ProtocolVersion::TLSv1_3){
            return Err("TLS 1.3 required".into())
        }
        let cert=tls.peer_certificates().and_then(|v|v.first())
            .ok_or("missing TLS-authenticated client certificate")?;
        let key=spki(cert)?;
        let authenticated_host=self.allowed_hosts.iter().find_map(|(host,pin)|
            if *pin==key{Some(host.clone())}else{None})
            .ok_or("client certificate not pinned to a registered replica")?;
        let mut stream=StreamOwned::new(tls,socket);
        let request:RpcRequest=read_frame(&mut stream)?;
        let reply=match request{
            RpcRequest::Scope=>RpcReply::Scope{scope:self.store.scope()?},
            RpcRequest::Recover{nonce_sha256}=>{
                if !digest(&nonce_sha256){
                    RpcReply::Rejected{reason:"invalid recovery nonce digest".into()}
                }else{
                    // Identity is taken ONLY from validated TLS client SPKI pin.
                    // Read-only, no epoch takeover, no nonce re-consumption.
                    match self.store.committed_response_for_host(
                        &nonce_sha256,&authenticated_host
                    ){
                        Ok(Some(response_json))=>RpcReply::Recovered{
                            nonce_sha256,
                            response_sha256:sha256(response_json.as_bytes()),
                            response_json,
                        },
                        Ok(None)=>RpcReply::NotFound,
                        Err(e)=>RpcReply::Rejected{reason:e},
                    }
                }
            },
            RpcRequest::Commit{grant,nonce_sha256,response_json}=>{
                if grant.host_id!=authenticated_host{
                    RpcReply::Rejected{reason:"epoch holder does not match authenticated client certificate".into()}
                }else{
                    match self.store.commit_response(&grant,&nonce_sha256,&response_json){
                        Ok(receipt)=>RpcReply::Committed{receipt},
                        Err(e)=>RpcReply::Rejected{reason:e},
                    }
                }
            }
        };
        write_frame(&mut stream,&reply)
    }
}
/// Real TLS client. No plaintext fallback and no claim-only RPC. Even the
/// Scope query requires a fresh authenticated network session.
pub struct RemoteTlsFencingAuthority{
    config:Arc<ClientConfig>,
    address:SocketAddr,
    dns_name:String,
    expected_server_spki_sha256:String,
    expected_scope:FencingScope,
    host_id:String,
    timeout:Duration,
}
impl RemoteTlsFencingAuthority{
    pub fn new(address:SocketAddr,dns_name:&str,
        server_roots:RootCertStore,
        client_certificates:Vec<CertificateDer<'static>>,
        client_private_key:PrivateKeyDer<'static>,
        pinned_server_spki_sha256:String,
        expected_scope:FencingScope,host_id:&str,
        timeout:Duration)->Result<Self,String>{
        expected_scope.validate()?;
        if !valid_name(host_id)||!valid_name(dns_name)||!digest(&pinned_server_spki_sha256)||
            client_certificates.is_empty()||timeout.is_zero()||timeout>Duration::from_secs(30){
            return Err("invalid independently provisioned remote coordinator client".into())
        }
        let config=ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(server_roots)
            .with_client_auth_cert(client_certificates,client_private_key)
            .map_err(|e|e.to_string())?;
        Ok(Self{config:Arc::new(config),address,dns_name:dns_name.into(),
            expected_server_spki_sha256:pinned_server_spki_sha256,
            expected_scope,host_id:host_id.into(),timeout})
    }
    /// Read-only authenticated recovery after an ambiguous network failure.
    /// Caller MUST supply the SHA-256 of the exact response it prepared
    /// before the commit. No retry/second consumption is performed.
    /// A recovered signed response must still undergo the usual independent
    /// witness/auditor/checkpoint/board verification before scientific use.
    pub fn recover_committed(
        &self,nonce_sha256:&str,expected_response_sha256:&str
    )->Result<String,String>{
        if !digest(nonce_sha256)||!digest(expected_response_sha256){
            return Err("valid externally retained nonce and response digests required".into())
        }
        match self.exchange(&RpcRequest::Recover{nonce_sha256:nonce_sha256.into()})?{
            RpcReply::Recovered{
                nonce_sha256:returned_nonce,response_sha256,response_json
            }=>{
                if returned_nonce!=nonce_sha256||
                    response_sha256!=expected_response_sha256||
                    sha256(response_json.as_bytes())!=response_sha256||
                    response_json.is_empty()||response_json.len()>1024*1024{
                    return Err("recovered response/nonce does not match original intent".into())
                }
                let value:serde_json::Value=serde_json::from_str(&response_json)
                    .map_err(|e|e.to_string())?;
                let canonical=serde_json::to_vec(&value).map_err(|e|e.to_string())?;
                if canonical!=response_json.as_bytes(){
                    return Err("recovered response JSON is not canonical".into())
                }
                let signed:SignedRemoteCheckpointResponse=
                    serde_json::from_str(&response_json).map_err(|e|e.to_string())?;
                if signed.payload.nonce_sha256!=nonce_sha256||
                    signed.payload.service_id!=self.expected_scope.service_id{
                    return Err("recovered response signed for another nonce or service".into())
                }
                verify_detached(&self.expected_scope.pinned_response_signer_public_key_hex,
                    &signed.signature_hex,RESPONSE_DOMAIN,&signed.payload)?;
                Ok(response_json)
            },
            RpcReply::NotFound=>Err("no committed response for authenticated host/nonce".into()),
            RpcReply::Rejected{reason}=>Err(format!("authenticated recovery refused: {reason}")),
            _=>Err("unexpected or unsafe receipt recovery RPC response".into()),
        }
    }
    fn exchange(&self,request:&RpcRequest)->Result<RpcReply,String>{
        let mut socket=TcpStream::connect_timeout(&self.address,self.timeout)
            .map_err(|e|e.to_string())?;
        socket.set_read_timeout(Some(self.timeout)).map_err(|e|e.to_string())?;
        socket.set_write_timeout(Some(self.timeout)).map_err(|e|e.to_string())?;
        let dns=ServerName::try_from(self.dns_name.as_str())
            .map_err(|e|e.to_string())?.to_owned();
        let mut tls=ClientConnection::new(Arc::clone(&self.config),dns)
            .map_err(|e|e.to_string())?;
        while tls.is_handshaking(){tls.complete_io(&mut socket).map_err(|e|e.to_string())?;}
        if tls.protocol_version()!=Some(ProtocolVersion::TLSv1_3){
            return Err("remote coordinator requires TLS 1.3".into())
        }
        let server=tls.peer_certificates().and_then(|v|v.first())
            .ok_or("remote coordinator missing authenticated certificate")?;
        if spki(server)?!=self.expected_server_spki_sha256{
            return Err("coordinator authenticated SPKI differs from independent pin".into())
        }
        let mut stream=StreamOwned::new(tls,socket);
        write_frame(&mut stream,request)?;
        read_frame(&mut stream)
    }
}
impl FencingAuthority for RemoteTlsFencingAuthority{
    fn scope(&self)->Result<FencingScope,String>{
        match self.exchange(&RpcRequest::Scope)?{
            RpcReply::Scope{scope} if scope==self.expected_scope=>Ok(scope),
            _=>Err("untrusted or unavailable remote coordinator scope".into()),
        }
    }
    fn claim(&self,_grant:&EpochGrant,_nonce_sha256:&str)->Result<FencingCheckpoint,String>{
        Err("claim-only remote fencing disabled: require atomic signed response commit".into())
    }
    fn commit_response(&self,grant:&EpochGrant,nonce_sha256:&str,
        response_json:&str)->Result<FencedCommitReceipt,String>{
        if grant.host_id!=self.host_id||!digest(nonce_sha256){
            return Err("requested epoch holder not bound to local client identity".into())
        }
        // This sends the entire signed response over independently pinned TLS.
        // The server verifies identity/epoch and commits atomically. If the
        // connection drops AFTER remote commit, the client gets an error and
        // must reconcile; retry of the nonce is rejected, never double-committed.
        match self.exchange(&RpcRequest::Commit{
            grant:grant.clone(),nonce_sha256:nonce_sha256.into(),
            response_json:response_json.into(),
        })?{
            RpcReply::Committed{receipt} if receipt.grant==*grant &&
                receipt.nonce_sha256==nonce_sha256 &&
                receipt.response_sha256==sha256(response_json.as_bytes()) &&
                receipt.durable_scratch_record_committed &&
                !receipt.canonical_writeback&&!receipt.authority_transfer &&
                !receipt.human_authority_verified&&!receipt.cross_host_consensus_verified
                =>Ok(receipt),
            RpcReply::Rejected{reason}=>Err(format!("remote coordinator denied fenced commit: {reason}")),
            _=>Err("remote coordinator returned invalid or unsafe commit response".into()),
        }
    }
}
