//! Offline read-only signed-review consistency check.
//! No verified human identities, no guards, no nonce consumption or canonical promotion.
use std::io::{self,Read};
use serde_json::json;
use galia_core_shadow::review::{ReviewVerificationRequest,verify_review};
fn run()->Result<serde_json::Value,String>{
    let mut input=String::new();
    io::stdin().take(16*1024*1024).read_to_string(&mut input)
        .map_err(|e|e.to_string())?;
    let req:ReviewVerificationRequest=serde_json::from_str(&input).map_err(|e|e.to_string())?;
    Ok(json!(verify_review(&req)?))
}
fn main(){
    match run(){
        Ok(value)=>println!("{}",value),
        Err(message)=>{
            println!("{}",json!({
                "status":"REJECTED",
                "error":message,
                "human_identity_verified":false,
                "human_authority_verified":false,
                "executable_guards_issued":false,
                "canonical_writeback":false,
                "authority_transfer":false,
                "output_commit":null
            }));
            std::process::exit(2);
        }
    }
}
