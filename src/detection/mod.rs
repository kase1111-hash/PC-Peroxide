//! Malware detection engines and algorithms.
//!
//! This module provides various detection methods:
//! - Signature-based detection (hash matching)
//! - Heuristic analysis (PE inspection, entropy, imports) - Phase 4
//! - YARA rules integration - Phase 8
//! - Behavioral pattern detection - Phase 6

pub mod database;
pub mod matcher;
pub mod signature;

pub use database::{ImportResult, SignatureDatabase};
pub use matcher::{DetectionEngine, HashMatcher, MatchResult};
pub use signature::{DatabaseInfo, RemediationAction, Signature, SignatureFile, SignatureType};
