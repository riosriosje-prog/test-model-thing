//! One-shot JSON request -> untrusted structural preflight diagnostic.
//! No receipts, preflight guards, human authority, disk/database/network writes.
use std::io::{self, Read};
use galia_core_shadow::preflight::{PreflightRequest, assess_preflight};
use serde_json::json;

fn run() -> Result<serde_json::Value, String> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).map_err(|e| e.to_string())?;
    let request: PreflightRequest = serde_json::from_str(&input).map_err(|e| e.to_string())?;
    let decision = assess_preflight(&request).map_err(str::to_owned)?;
    Ok(json!({"status": "ADVISORY_ONLY", "assessment": decision}))
}

fn main() {
    match run() {
        Ok(json) => println!("{}", json),
        Err(message) => {
            println!("{}", json!({
                "status": "REJECTED",
                "canonical_writeback": false,
                "authority_transfer": false,
                "output_commit": null,
                "error": message
            }));
            std::process::exit(2);
        }
    }
}
