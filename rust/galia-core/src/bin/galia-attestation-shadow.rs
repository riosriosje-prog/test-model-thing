//! Offline Ed25519 registry/checkpoint integrity diagnostic.
//! Trust policy and public root are caller-supplied, not autonomously authenticated.
//! NEVER use result as proof of human promotion authority or freshness.
use std::io::{self,Read};
use serde_json::json;
use galia_core_shadow::attestation::{AttestationRequest,verify_attestation};
fn run()->Result<serde_json::Value,String>{
    let mut input=String::new();
    io::stdin().take(16*1024*1024).read_to_string(&mut input)
        .map_err(|e|e.to_string())?;
    let req:AttestationRequest=serde_json::from_str(&input).map_err(|e|e.to_string())?;
    Ok(json!(verify_attestation(&req)?))
}
fn main(){
    match run(){
        Ok(value)=>println!("{}",value),
        Err(message)=>{
            println!("{}",json!({
                "status":"REJECTED",
                "error":message,
                "canonical_writeback":false,
                "human_authority_verified":false,
                "authority_transfer":false,
                "output_commit":null
            }));
            std::process::exit(2);
        }
    }
}
