//! JSON-lines-free single request CLI: stdin request, stdout advisory result.
//! No file writes, network, database or Git mutations.
use std::collections::BTreeSet;
use std::io::{self, Read};
use serde::Deserialize;
use serde_json::json;
use galia_core_shadow::core::Stage;
use galia_core_shadow::state_machine::{evaluate_transition, TransitionEvent};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    stage: Stage,
    event: TransitionEvent,
    #[serde(default)]
    satisfied_guards: BTreeSet<String>,
}

fn run() -> Result<serde_json::Value, String> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).map_err(|e| e.to_string())?;
    let req: Request = serde_json::from_str(&input).map_err(|e| e.to_string())?;
    let decision = evaluate_transition(&req.stage, req.event, &req.satisfied_guards)
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "status": "ADVISORY_ONLY",
        "schema": "galia.rust.shadow.transition.v0.1",
        "canonical_writeback": false,
        "authority_transfer": false,
        "output_commit": null,
        "decision": decision
    }))
}

fn main() {
    match run() {
        Ok(result) => println!("{}", result),
        Err(error) => {
            println!("{}", json!({
                "status": "REJECTED",
                "schema": "galia.rust.shadow.transition.v0.1",
                "canonical_writeback": false,
                "authority_transfer": false,
                "output_commit": null,
                "error": error
            }));
            std::process::exit(2);
        }
    }
}
