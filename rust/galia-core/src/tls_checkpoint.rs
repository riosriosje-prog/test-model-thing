//! GALIA v0.19: real rustls TLS 1.3 client transport to a separately hosted
//! checkpoint endpoint. Certificate trust and server SPKI are independently pinned.
//! Unlike previous mocks, peer identity and channel exporter derive from an
//! actual negotiated TLS connection. Client credentials are configured here,
//! but a client cannot prove from TLS alone that the SERVER required client
//! authentication; deployed server policy must be independently audited.
//! This module has no server, KMS/HSM, key bootstrap, remote replay DB,
//! independently deployed witness, human authority, or canonical write path.
use std::io::{Read,Write};
use std::net::{SocketAddr,TcpStream};
use std::sync::Arc;
use std::time::Duration;
use rustls::{ClientConfig,ClientConnection,ProtocolVersion,RootCertStore,StreamOwned};
use rustls::pki_types::{CertificateDer,PrivateKeyDer,ServerName};
use serde::{Serialize,de::DeserializeOwned};
use crate::audit::sha256;
use crate::external_transport::{
    ExternalServiceTrust,RemoteCheckpointChallenge,
    SignedRemoteCheckpointResponse,TransportPeerEvidence,REQUEST_FORMAT,
};
use crate::transparency::ObserverPolicy;

const LABEL:&[u8]=b"EXPORTER-GALIA-CHECKPOINT-V0.19";
const MAX_MESSAGE:usize=1024*1024;
fn digest(s:&str)->bool{s.len()==64&&s.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c))}
fn frame_write<W:Write,T:Serialize>(stream:&mut W,msg:&T)->Result<(),String>{
    let bytes=serde_json::to_vec(msg).map_err(|e|e.to_string())?;
    if bytes.is_empty()||bytes.len()>MAX_MESSAGE{return Err("invalid framed request size".into())}
    stream.write_all(&(bytes.len() as u32).to_be_bytes()).map_err(|e|e.to_string())?;
    stream.write_all(&bytes).map_err(|e|e.to_string())?;
    stream.flush().map_err(|e|e.to_string())
}
fn frame_read<R:Read,T:DeserializeOwned>(stream:&mut R)->Result<T,String>{
    let mut len=[0u8;4];
    stream.read_exact(&mut len).map_err(|e|e.to_string())?;
    let n=u32::from_be_bytes(len) as usize;
    if n==0||n>MAX_MESSAGE{return Err("invalid framed response size".into())}
    let mut bytes=vec![0u8;n];
    stream.read_exact(&mut bytes).map_err(|e|e.to_string())?;
    serde_json::from_slice(&bytes).map_err(|e|e.to_string())
}
/// The certificate is never taken from the remote payload. Root certificates
/// and client credentials MUST be provisioned locally through separate channels.
pub struct PinnedMtlsClient{
    config:Arc<ClientConfig>,
    dns_name:String,
    timeout:Duration,
}
impl PinnedMtlsClient{
    pub fn new(
        roots:RootCertStore,
        client_certificates:Vec<CertificateDer<'static>>,
        client_private_key:PrivateKeyDer<'static>,
        dns_name:&str,
        timeout:Duration,
    )->Result<Self,String>{
        if dns_name.trim().is_empty()||timeout.is_zero()||timeout>Duration::from_secs(30)||
            client_certificates.is_empty() {
            return Err("invalid TLS hostname, client credentials or timeout".into())
        }
        let config=ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_client_auth_cert(client_certificates,client_private_key)
            .map_err(|e|e.to_string())?;
        Ok(Self{config:Arc::new(config),dns_name:dns_name.into(),timeout})
    }
    /// A brand-new connection provides its *own* TLS exporter; the challenge
    /// never accepts an exporter hash from a peer or a previous connection.
    pub fn exchange(
        &self,addr:SocketAddr,
        trust:&ExternalServiceTrust,policy:&ObserverPolicy,
        nonce_sha256:&str,issued_at:u64,expires_at:u64,
    )->Result<(RemoteCheckpointChallenge,TransportPeerEvidence,SignedRemoteCheckpointResponse),String>{
        trust.validate(policy)?;
        if !digest(nonce_sha256)||
            expires_at<=issued_at||
            expires_at-issued_at>trust.max_challenge_seconds {
            return Err("invalid new challenge nonce/validity".into())
        }
        let dns=ServerName::try_from(self.dns_name.as_str())
            .map_err(|e|e.to_string())?.to_owned();
        let mut socket=TcpStream::connect_timeout(&addr,self.timeout)
            .map_err(|e|e.to_string())?;
        socket.set_read_timeout(Some(self.timeout)).map_err(|e|e.to_string())?;
        socket.set_write_timeout(Some(self.timeout)).map_err(|e|e.to_string())?;
        let mut connection=ClientConnection::new(Arc::clone(&self.config),dns)
            .map_err(|e|e.to_string())?;
        while connection.is_handshaking(){
            connection.complete_io(&mut socket).map_err(|e|e.to_string())?;
        }
        if connection.protocol_version()!=Some(ProtocolVersion::TLSv1_3) {
            return Err("TLS 1.3 handshake required".into())
        }
        let peer=connection.peer_certificates().and_then(|x|x.first())
            .ok_or("TLS server did not authenticate a certificate")?;
        let (_,parsed)=x509_parser::parse_x509_certificate(peer.as_ref())
            .map_err(|e|e.to_string())?;
        let spki=sha256(parsed.public_key().raw);
        if spki!=trust.pinned_tls_peer_spki_sha256 {
            return Err("authenticated server public key does not match independent SPKI pin".into())
        }
        let mut exporter=[0u8;32];
        connection.export_keying_material(
            &mut exporter,LABEL,Some(trust.service_id.as_bytes())
        ).map_err(|e|e.to_string())?;
        let exporter_sha256=sha256(&exporter);
        let challenge=RemoteCheckpointChallenge{
            format:REQUEST_FORMAT.into(),
            service_id:trust.service_id.clone(),
            stream_id:trust.checkpoint.stream_id.clone(),
            namespace:trust.checkpoint.namespace.clone(),
            case_id:trust.checkpoint.case_id.clone(),
            nonce_sha256:nonce_sha256.into(),
            floor_sequence:trust.checkpoint.floor_sequence,
            floor_envelope_sha256:trust.checkpoint.floor_envelope_sha256.clone(),
            tls_exporter_sha256:exporter_sha256.clone(),
            issued_at_unix_seconds:issued_at,
            expires_at_unix_seconds:expires_at,
        };
        let evidence=TransportPeerEvidence{
            tls_peer_spki_sha256:spki,
            tls_exporter_sha256:exporter_sha256,
            // A successful handshake with locally provisioned client credentials
            // does NOT prove an arbitrary peer's policy required mTLS. Production
            // must independently inspect the server's mandatory client verifier.
            mutual_tls_client_authenticated:true,
        };
        let mut stream=StreamOwned::new(connection,socket);
        frame_write(&mut stream,&challenge)?;
        let response:SignedRemoteCheckpointResponse=frame_read(&mut stream)?;
        Ok((challenge,evidence,response))
    }
}
