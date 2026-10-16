//! GALIA 2.0 Rust noncanonical shadow. No human authority or production writes.
#![forbid(unsafe_code)]
pub mod core;
pub mod state_machine;
pub mod authority;
pub mod preflight;
pub mod persistence;
pub mod audit;
pub mod attestation;
pub mod review;
#[cfg(feature = "scratch-store")]
pub mod scratch_store;
#[cfg(feature = "scratch-store")]
pub mod consumption;
#[cfg(feature = "scratch-store")]
pub mod witness;
