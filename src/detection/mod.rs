//! Malware detection engines and algorithms.
//!
//! This module provides various detection methods:
//! - Signature-based detection (hash matching)
//! - Heuristic analysis (PE inspection, entropy, imports)
//! - YARA-like rules integration
//! - Behavioral pattern detection

pub mod database;
pub mod heuristic;
pub mod matcher;
pub mod signature;
pub mod yara;

pub use database::{ImportResult, SignatureDatabase};
pub use heuristic::{HeuristicEngine, HeuristicResult, PeAnalyzer, PeInfo, ScoreCategory};
pub use matcher::{DetectionEngine, HashMatcher, MatchResult};
pub use signature::{DatabaseInfo, RemediationAction, Signature, SignatureFile, SignatureType};
pub use yara::{YaraEngine, YaraRule, RuleMatch};
