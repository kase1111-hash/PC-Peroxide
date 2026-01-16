//! PC-Peroxide: A lightweight, portable malware detection and removal utility
//!
//! This crate provides the core functionality for detecting and removing malware
//! from Windows systems. It includes signature-based detection, heuristic analysis,
//! registry scanning, process analysis, quarantine management, and LLM-powered
//! analysis for enhanced threat detection.

pub mod analysis;
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

// Re-export analysis types
pub use crate::analysis::{MalwareAnalyzer, ProviderConfig};
