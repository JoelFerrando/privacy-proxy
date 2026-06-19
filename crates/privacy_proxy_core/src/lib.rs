#![forbid(unsafe_code)]

mod config;
mod engine;
mod error;
mod stats;

pub use config::{Config, DetectorKind, Mode};
pub use engine::{
    redact_str, redact_value, scan_str, scan_value, Engine, RedactResult, RedactTextResult,
};
pub use error::{Error, Result};
pub use stats::ScanReport;
