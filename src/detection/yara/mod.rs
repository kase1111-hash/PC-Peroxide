//! YARA-like rule engine for pattern matching.
//!
//! This module provides a simple pattern matching engine inspired by YARA:
//! - Rule definition with meta, strings, and conditions
//! - Hex pattern matching
//! - Text pattern matching (case-sensitive and case-insensitive)
//! - Regex pattern matching
//! - Basic condition evaluation

pub mod engine;
pub mod rules;

pub use engine::YaraEngine;
pub use rules::{PatternType, RuleMatch, RuleMeta, StringPattern, YaraRule};
