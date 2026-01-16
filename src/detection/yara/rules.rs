//! YARA rule definitions.
//!
//! Provides structures for defining detection rules similar to YARA format.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Pattern type for string matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PatternType {
    /// Plain text (case-sensitive)
    Text,
    /// Plain text (case-insensitive)
    TextNocase,
    /// Hex bytes pattern
    Hex,
    /// Regular expression
    Regex,
    /// Wide string (UTF-16)
    Wide,
}

/// A string pattern in a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringPattern {
    /// Pattern identifier (e.g., "$a")
    pub id: String,
    /// The pattern content
    pub pattern: String,
    /// Pattern type
    pub pattern_type: PatternType,
    /// Compiled regex (for regex and text patterns)
    #[serde(skip)]
    pub compiled: Option<Regex>,
    /// Compiled hex bytes (for hex patterns)
    #[serde(skip)]
    pub hex_bytes: Option<Vec<u8>>,
}

impl StringPattern {
    /// Create a new text pattern.
    pub fn text(id: &str, pattern: &str) -> Self {
        Self {
            id: id.to_string(),
            pattern: pattern.to_string(),
            pattern_type: PatternType::Text,
            compiled: None,
            hex_bytes: None,
        }
    }

    /// Create a case-insensitive text pattern.
    pub fn text_nocase(id: &str, pattern: &str) -> Self {
        Self {
            id: id.to_string(),
            pattern: pattern.to_string(),
            pattern_type: PatternType::TextNocase,
            compiled: None,
            hex_bytes: None,
        }
    }

    /// Create a hex pattern.
    pub fn hex(id: &str, hex: &str) -> Self {
        Self {
            id: id.to_string(),
            pattern: hex.to_string(),
            pattern_type: PatternType::Hex,
            compiled: None,
            hex_bytes: None,
        }
    }

    /// Create a regex pattern.
    pub fn regex(id: &str, pattern: &str) -> Self {
        Self {
            id: id.to_string(),
            pattern: pattern.to_string(),
            pattern_type: PatternType::Regex,
            compiled: None,
            hex_bytes: None,
        }
    }

    /// Compile the pattern for matching.
    pub fn compile(&mut self) -> Result<(), String> {
        match self.pattern_type {
            PatternType::Text => {
                let escaped = regex::escape(&self.pattern);
                self.compiled = Some(
                    Regex::new(&escaped)
                        .map_err(|e| format!("Failed to compile pattern: {}", e))?,
                );
            }
            PatternType::TextNocase => {
                let escaped = regex::escape(&self.pattern);
                self.compiled = Some(
                    Regex::new(&format!("(?i){}", escaped))
                        .map_err(|e| format!("Failed to compile pattern: {}", e))?,
                );
            }
            PatternType::Regex => {
                self.compiled = Some(
                    Regex::new(&self.pattern)
                        .map_err(|e| format!("Failed to compile regex: {}", e))?,
                );
            }
            PatternType::Hex => {
                self.hex_bytes = Some(Self::parse_hex(&self.pattern)?);
            }
            PatternType::Wide => {
                // Wide strings are UTF-16LE encoded
                let wide: Vec<u8> = self
                    .pattern
                    .encode_utf16()
                    .flat_map(|c| c.to_le_bytes())
                    .collect();
                self.hex_bytes = Some(wide);
            }
        }
        Ok(())
    }

    /// Parse hex string to bytes.
    fn parse_hex(hex: &str) -> Result<Vec<u8>, String> {
        let hex = hex.replace([' ', '\n', '\r', '\t'], "");
        let hex = hex.replace("??", ".."); // Wildcards

        if hex.contains("..") {
            // Has wildcards, can't use simple parsing
            return Err("Hex wildcards not yet supported".to_string());
        }

        hex::decode(&hex).map_err(|e| format!("Invalid hex: {}", e))
    }

    /// Check if pattern matches in data.
    pub fn matches(&self, data: &[u8]) -> Vec<usize> {
        let mut offsets = Vec::new();

        match self.pattern_type {
            PatternType::Text | PatternType::TextNocase | PatternType::Regex => {
                if let Some(ref regex) = self.compiled {
                    // Try to match as UTF-8 text (lossy to handle binary data)
                    let text = String::from_utf8_lossy(data);
                    for m in regex.find_iter(&text) {
                        offsets.push(m.start());
                    }
                }
            }
            PatternType::Hex | PatternType::Wide => {
                if let Some(ref bytes) = self.hex_bytes {
                    // Search for byte sequence
                    for i in 0..=data.len().saturating_sub(bytes.len()) {
                        if data[i..].starts_with(bytes) {
                            offsets.push(i);
                        }
                    }
                }
            }
        }

        offsets
    }
}

/// Rule metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleMeta {
    /// Rule description
    pub description: Option<String>,
    /// Author
    pub author: Option<String>,
    /// Reference URL
    pub reference: Option<String>,
    /// Severity level
    pub severity: Option<String>,
    /// Category (e.g., "malware", "trojan", "ransomware")
    pub category: Option<String>,
    /// Additional key-value metadata
    #[serde(flatten)]
    pub extra: HashMap<String, String>,
}

/// Condition type for rule matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Condition {
    /// All patterns must match
    All,
    /// Any pattern must match
    Any,
    /// At least N patterns must match
    AtLeast(usize),
    /// Specific pattern must match
    Pattern(String),
    /// PE file check (MZ header)
    IsPE,
    /// ELF file check
    IsELF,
    /// File size check
    FileSize { min: Option<u64>, max: Option<u64> },
    /// Logical AND
    And(Box<Condition>, Box<Condition>),
    /// Logical OR
    Or(Box<Condition>, Box<Condition>),
    /// Logical NOT
    Not(Box<Condition>),
}

impl Condition {
    /// Evaluate the condition against match results.
    pub fn evaluate(&self, matches: &HashMap<String, Vec<usize>>, data: &[u8]) -> bool {
        match self {
            Condition::All => matches.values().all(|m| !m.is_empty()),
            Condition::Any => matches.values().any(|m| !m.is_empty()),
            Condition::AtLeast(n) => {
                matches.values().filter(|m| !m.is_empty()).count() >= *n
            }
            Condition::Pattern(id) => {
                matches.get(id).map_or(false, |m| !m.is_empty())
            }
            Condition::IsPE => {
                data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A
            }
            Condition::IsELF => {
                data.len() >= 4 && data[..4] == [0x7F, 0x45, 0x4C, 0x46]
            }
            Condition::FileSize { min, max } => {
                let size = data.len() as u64;
                let min_ok = min.map_or(true, |m| size >= m);
                let max_ok = max.map_or(true, |m| size <= m);
                min_ok && max_ok
            }
            Condition::And(a, b) => {
                a.evaluate(matches, data) && b.evaluate(matches, data)
            }
            Condition::Or(a, b) => {
                a.evaluate(matches, data) || b.evaluate(matches, data)
            }
            Condition::Not(c) => !c.evaluate(matches, data),
        }
    }
}

/// A YARA-like detection rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRule {
    /// Rule name
    pub name: String,
    /// Rule metadata
    pub meta: RuleMeta,
    /// String patterns
    pub strings: Vec<StringPattern>,
    /// Condition for matching
    pub condition: Condition,
    /// Whether the rule is enabled
    pub enabled: bool,
}

impl YaraRule {
    /// Create a new rule.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            meta: RuleMeta::default(),
            strings: Vec::new(),
            condition: Condition::Any,
            enabled: true,
        }
    }

    /// Set rule description.
    pub fn with_description(mut self, desc: &str) -> Self {
        self.meta.description = Some(desc.to_string());
        self
    }

    /// Set rule severity.
    pub fn with_severity(mut self, severity: &str) -> Self {
        self.meta.severity = Some(severity.to_string());
        self
    }

    /// Set rule category.
    pub fn with_category(mut self, category: &str) -> Self {
        self.meta.category = Some(category.to_string());
        self
    }

    /// Add a string pattern.
    pub fn with_string(mut self, pattern: StringPattern) -> Self {
        self.strings.push(pattern);
        self
    }

    /// Set the condition.
    pub fn with_condition(mut self, condition: Condition) -> Self {
        self.condition = condition;
        self
    }

    /// Compile all patterns.
    pub fn compile(&mut self) -> Result<(), String> {
        for pattern in &mut self.strings {
            pattern.compile()?;
        }
        Ok(())
    }

    /// Match the rule against data.
    pub fn matches(&self, data: &[u8]) -> Option<RuleMatch> {
        if !self.enabled {
            return None;
        }

        let mut pattern_matches: HashMap<String, Vec<usize>> = HashMap::new();

        for pattern in &self.strings {
            let offsets = pattern.matches(data);
            pattern_matches.insert(pattern.id.clone(), offsets);
        }

        if self.condition.evaluate(&pattern_matches, data) {
            Some(RuleMatch {
                rule_name: self.name.clone(),
                meta: self.meta.clone(),
                matches: pattern_matches,
            })
        } else {
            None
        }
    }
}

/// Result of a rule match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    /// Name of the matched rule
    pub rule_name: String,
    /// Rule metadata
    pub meta: RuleMeta,
    /// Pattern matches with offsets
    pub matches: HashMap<String, Vec<usize>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_text_pattern() {
        let mut pattern = StringPattern::text("$a", "malware");
        pattern.compile().unwrap();

        let data = b"This is malware detected";
        let matches = pattern.matches(data);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], 8); // "malware" starts at offset 8
    }

    #[test]
    fn test_text_nocase_pattern() {
        let mut pattern = StringPattern::text_nocase("$a", "MALWARE");
        pattern.compile().unwrap();

        let data = b"This is Malware detected";
        let matches = pattern.matches(data);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_hex_pattern() {
        let mut pattern = StringPattern::hex("$mz", "4D5A");
        pattern.compile().unwrap();

        let data = &[0x4D, 0x5A, 0x90, 0x00];
        let matches = pattern.matches(data);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], 0);
    }

    #[test]
    fn test_regex_pattern() {
        let mut pattern = StringPattern::regex("$ip", r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}");
        pattern.compile().unwrap();

        let data = b"Connect to 192.168.1.1 for C2";
        let matches = pattern.matches(data);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_rule_matching() {
        let mut rule = YaraRule::new("TestMalware")
            .with_description("Test malware detection")
            .with_severity("high")
            .with_string(StringPattern::text_nocase("$ransom", "your files have been encrypted"))
            .with_string(StringPattern::hex("$mz", "4D5A"))
            .with_condition(Condition::And(
                Box::new(Condition::IsPE),
                Box::new(Condition::Pattern("$ransom".to_string())),
            ));

        rule.compile().unwrap();

        // PE header + ransom message
        let mut data = vec![0x4D, 0x5A, 0x90, 0x00];
        data.extend(b"Warning: YOUR FILES HAVE BEEN ENCRYPTED!");

        let result = rule.matches(&data);
        assert!(result.is_some());
    }

    #[test]
    fn test_condition_all() {
        let cond = Condition::All;
        let mut matches = HashMap::new();
        matches.insert("$a".to_string(), vec![0]);
        matches.insert("$b".to_string(), vec![10]);

        assert!(cond.evaluate(&matches, &[]));

        matches.insert("$c".to_string(), vec![]);
        assert!(!cond.evaluate(&matches, &[]));
    }

    #[test]
    fn test_condition_any() {
        let cond = Condition::Any;
        let mut matches = HashMap::new();
        matches.insert("$a".to_string(), vec![]);
        matches.insert("$b".to_string(), vec![10]);

        assert!(cond.evaluate(&matches, &[]));
    }

    #[test]
    fn test_condition_at_least() {
        let cond = Condition::AtLeast(2);
        let mut matches = HashMap::new();
        matches.insert("$a".to_string(), vec![0]);
        matches.insert("$b".to_string(), vec![10]);
        matches.insert("$c".to_string(), vec![]);

        assert!(cond.evaluate(&matches, &[]));
    }

    #[test]
    fn test_is_pe_condition() {
        let cond = Condition::IsPE;
        let pe_data = &[0x4D, 0x5A, 0x90, 0x00];
        let not_pe = &[0x7F, 0x45, 0x4C, 0x46];

        assert!(cond.evaluate(&HashMap::new(), pe_data));
        assert!(!cond.evaluate(&HashMap::new(), not_pe));
    }

    #[test]
    fn test_is_elf_condition() {
        let cond = Condition::IsELF;
        let elf_data = &[0x7F, 0x45, 0x4C, 0x46];
        let not_elf = &[0x4D, 0x5A, 0x90, 0x00];

        assert!(cond.evaluate(&HashMap::new(), elf_data));
        assert!(!cond.evaluate(&HashMap::new(), not_elf));
    }
}
