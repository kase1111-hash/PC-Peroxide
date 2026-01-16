//! YARA-like rule engine for pattern matching.
//!
//! This module provides a simple pattern matching engine inspired by YARA:
//! - Rule definition with meta, strings, and conditions
//! - Hex pattern matching
//! - Text pattern matching (case-sensitive and case-insensitive)
//! - Regex pattern matching
//! - Basic condition evaluation

pub mod rules;
pub mod engine;

pub use rules::{YaraRule, RuleMeta, StringPattern, PatternType, RuleMatch};
pub use engine::YaraEngine;
