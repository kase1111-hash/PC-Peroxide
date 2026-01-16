//! PC-Peroxide: A lightweight, portable malware detection and removal utility
//!
//! This crate provides the core functionality for detecting and removing malware
//! from Windows systems. It includes signature-based detection, heuristic analysis,
//! registry scanning, process analysis, and quarantine management.

pub mod core;
pub mod detection;
pub mod quarantine;
pub mod scanner;
pub mod ui;
pub mod utils;

// Re-export commonly used types
pub use crate::core::config::Config;
pub use crate::core::error::{Error, Result};
pub use crate::core::types::*;
