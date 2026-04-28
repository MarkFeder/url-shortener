//! Cross-cutting infrastructure: persistence, caching, metrics, error
//! types, configuration, constants, and QR code generation.
//!
//! Everything here is used across multiple domains and has no inherent
//! domain logic of its own.

pub mod cache;
pub mod config;
pub mod constants;
pub mod db;
pub mod errors;
pub mod metrics;
pub mod qr;
