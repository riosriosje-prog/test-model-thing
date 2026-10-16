//! GALIA 2.0 Rust shadow core.
//! No persistence writes, canonical writeback, promotion, external I/O or authority grants.
#![forbid(unsafe_code)]
pub mod core;
pub mod state_machine;
pub mod authority;
pub mod preflight;
pub mod persistence;
