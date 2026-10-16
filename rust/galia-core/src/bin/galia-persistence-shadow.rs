//! One-shot snapshot verification only. No canonical publication, filesystem or HEAD writes.
use std::io::{self, Read};
use serde_json::json;
use galia_core_shadow::persistence::{VerificationRequest, verify_request};
fn run() -> Result<serde_json::Value,String> {
    let mut input = String::new();
    io::stdin().take(16 * 1024 * 1024).read_to_string(&mut input).map_err(|e| e.to_string())?;
    let req: VerificationRequest = serde_json::from_str(&input).map_err(|e| e.to_string())?;
    let result = verify_request(&req)?;
    Ok(json!(result))
}
fn main() {
    match run() {
        Ok(v) => println!("{}",v),
        Err(e) => {
            println!("{}",json!({
                "status":"REJECTED",
                "error":e,
                "canonical_writeback":false,
                "authority_transfer":false,
                "output_commit":null
            }));
            std::process::exit(2);
        }
    }
}
