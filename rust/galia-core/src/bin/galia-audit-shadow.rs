//! Read-only replay of supplied diagnostic scratch receipts.
//! The checkpoint must have been authenticated outside this process.
use std::io::{self,Read};
use serde::Deserialize;
use serde_json::json;
use galia_core_shadow::audit::{AuditReceipt,Checkpoint,verify_receipts};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    receipts:Vec<AuditReceipt>,
    #[serde(default)]
    checkpoint:Option<Checkpoint>,
}
fn run()->Result<serde_json::Value,String>{
    let mut input=String::new();
    io::stdin().take(8*1024*1024).read_to_string(&mut input)
        .map_err(|e|e.to_string())?;
    let req:Request=serde_json::from_str(&input).map_err(|e|e.to_string())?;
    Ok(json!(verify_receipts(&req.receipts,req.checkpoint.as_ref())?))
}
fn main(){
    match run(){
        Ok(value)=>println!("{}",value),
        Err(message)=>{
            println!("{}",json!({
                "status":"REJECTED",
                "error":message,
                "canonical_writeback":false,
                "authority_transfer":false,
                "output_commit":null
            }));
            std::process::exit(2);
        }
    }
}
