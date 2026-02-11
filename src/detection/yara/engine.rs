//! YARA rule engine for scanning files.
//!
//! Manages loading, compiling, and executing YARA-like rules.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use super::rules::{Condition, RuleMatch, StringPattern, YaraRule};
use crate::core::error::{Error, Result};

/// YARA-like scanning engine.
pub struct YaraEngine {
    /// Loaded rules
    rules: Vec<YaraRule>,
    /// Rules indexed by name
    rules_by_name: HashMap<String, usize>,
}

impl YaraEngine {
    /// Create a new YARA engine.
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            rules_by_name: HashMap::new(),
        }
    }

    /// Create an engine with default rules.
    pub fn with_default_rules() -> Result<Self> {
        let mut engine = Self::new();
        engine.load_default_rules()?;
        Ok(engine)
    }

    /// Load default built-in rules.
    fn load_default_rules(&mut self) -> Result<()> {
        // Ransomware detection
        self.add_rule(
            YaraRule::new("Ransomware_Generic")
                .with_description("Generic ransomware detection")
                .with_severity("critical")
                .with_category("ransomware")
                .with_string(StringPattern::text_nocase(
                    "$ransom1",
                    "your files have been encrypted",
                ))
                .with_string(StringPattern::text_nocase(
                    "$ransom2",
                    "your personal files are encrypted",
                ))
                .with_string(StringPattern::text_nocase("$ransom3", "decrypt your files"))
                .with_string(StringPattern::text_nocase("$ransom4", "bitcoin"))
                .with_string(StringPattern::text_nocase("$ransom5", "pay the ransom"))
                .with_string(StringPattern::text_nocase("$ransom6", "restore your files"))
                .with_condition(Condition::And(
                    Box::new(Condition::IsPE),
                    Box::new(Condition::AtLeast(2)),
                )),
        )?;

        // Keylogger detection
        self.add_rule(
            YaraRule::new("Keylogger_Generic")
                .with_description("Generic keylogger detection")
                .with_severity("high")
                .with_category("spyware")
                .with_string(StringPattern::text("$api1", "GetAsyncKeyState"))
                .with_string(StringPattern::text("$api2", "GetKeyboardState"))
                .with_string(StringPattern::text("$api3", "SetWindowsHookEx"))
                .with_string(StringPattern::text("$api4", "GetForegroundWindow"))
                .with_condition(Condition::And(
                    Box::new(Condition::IsPE),
                    Box::new(Condition::AtLeast(3)),
                )),
        )?;

        // Process injection detection
        self.add_rule(
            YaraRule::new("ProcessInjection_Generic")
                .with_description("Generic process injection detection")
                .with_severity("high")
                .with_category("injection")
                .with_string(StringPattern::text("$api1", "VirtualAllocEx"))
                .with_string(StringPattern::text("$api2", "WriteProcessMemory"))
                .with_string(StringPattern::text("$api3", "CreateRemoteThread"))
                .with_string(StringPattern::text("$api4", "NtCreateThreadEx"))
                .with_string(StringPattern::text("$api5", "RtlCreateUserThread"))
                .with_condition(Condition::And(
                    Box::new(Condition::IsPE),
                    Box::new(Condition::AtLeast(2)),
                )),
        )?;

        // Shellcode patterns
        self.add_rule(
            YaraRule::new("Shellcode_Meterpreter")
                .with_description("Meterpreter shellcode pattern")
                .with_severity("critical")
                .with_category("shellcode")
                .with_string(StringPattern::hex("$stub1", "FC4883E4F0E8"))
                .with_string(StringPattern::hex("$stub2", "FCEBD74898"))
                .with_condition(Condition::Any),
        )?;

        // Cobalt Strike beacon
        self.add_rule(
            YaraRule::new("CobaltStrike_Beacon")
                .with_description("Cobalt Strike beacon detection")
                .with_severity("critical")
                .with_category("c2")
                .with_string(StringPattern::text("$beacon1", "beacon.dll"))
                .with_string(StringPattern::text("$beacon2", "%s.4444"))
                .with_string(StringPattern::text("$beacon3", "ReflectiveLoader"))
                .with_string(StringPattern::hex("$magic", "4D5A4552"))
                .with_condition(Condition::And(
                    Box::new(Condition::IsPE),
                    Box::new(Condition::Any),
                )),
        )?;

        // Credential stealer
        self.add_rule(
            YaraRule::new("CredentialStealer_Generic")
                .with_description("Generic credential stealer detection")
                .with_severity("high")
                .with_category("stealer")
                .with_string(StringPattern::text("$path1", "Login Data"))
                .with_string(StringPattern::text("$path2", "logins.json"))
                .with_string(StringPattern::text("$path3", "signons.sqlite"))
                .with_string(StringPattern::text("$api1", "CryptUnprotectData"))
                .with_string(StringPattern::text("$api2", "sqlite3_"))
                .with_condition(Condition::And(
                    Box::new(Condition::IsPE),
                    Box::new(Condition::AtLeast(2)),
                )),
        )?;

        // Cryptocurrency miner
        self.add_rule(
            YaraRule::new("CryptoMiner_Generic")
                .with_description("Generic cryptocurrency miner detection")
                .with_severity("medium")
                .with_category("miner")
                .with_string(StringPattern::text_nocase("$pool1", "stratum+tcp://"))
                .with_string(StringPattern::text_nocase("$pool2", "stratum+ssl://"))
                .with_string(StringPattern::text_nocase("$xmr1", "xmrig"))
                .with_string(StringPattern::text_nocase("$xmr2", "randomx"))
                .with_string(StringPattern::text_nocase("$xmr3", "cryptonight"))
                .with_condition(Condition::AtLeast(2)),
        )?;

        // EICAR test file
        self.add_rule(
            YaraRule::new("EICAR_TestFile")
                .with_description("EICAR test file")
                .with_severity("info")
                .with_category("test")
                .with_string(StringPattern::text(
                    "$eicar",
                    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
                ))
                .with_condition(Condition::Any),
        )?;

        Ok(())
    }

    /// Add a rule to the engine.
    pub fn add_rule(&mut self, mut rule: YaraRule) -> Result<()> {
        rule.compile()
            .map_err(|e| Error::YaraCompilation(format!("Rule '{}': {}", rule.name, e)))?;

        let index = self.rules.len();
        self.rules_by_name.insert(rule.name.clone(), index);
        self.rules.push(rule);

        Ok(())
    }

    /// Load rules from a JSON file.
    pub fn load_rules_file(&mut self, path: &Path) -> Result<()> {
        let content = fs::read_to_string(path).map_err(|e| Error::file_read(path, e))?;

        let rules: Vec<YaraRule> = serde_json::from_str(&content)
            .map_err(|e| Error::YaraCompilation(format!("Failed to parse rules: {}", e)))?;

        for rule in rules {
            self.add_rule(rule)?;
        }

        Ok(())
    }

    /// Get the number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Get a rule by name.
    pub fn get_rule(&self, name: &str) -> Option<&YaraRule> {
        self.rules_by_name
            .get(name)
            .and_then(|&idx| self.rules.get(idx))
    }

    /// Enable or disable a rule.
    pub fn set_rule_enabled(&mut self, name: &str, enabled: bool) -> bool {
        if let Some(&idx) = self.rules_by_name.get(name) {
            if let Some(rule) = self.rules.get_mut(idx) {
                rule.enabled = enabled;
                return true;
            }
        }
        false
    }

    /// Scan data against all rules.
    pub fn scan_data(&self, data: &[u8]) -> Vec<RuleMatch> {
        let mut matches = Vec::new();

        for rule in &self.rules {
            if let Some(m) = rule.matches(data) {
                matches.push(m);
            }
        }

        matches
    }

    /// Scan a file against all rules.
    pub fn scan_file(&self, path: &Path) -> Result<Vec<RuleMatch>> {
        let data = fs::read(path).map_err(|e| Error::file_read(path, e))?;

        Ok(self.scan_data(&data))
    }

    /// List all rule names.
    pub fn list_rules(&self) -> Vec<&str> {
        self.rules.iter().map(|r| r.name.as_str()).collect()
    }
}

impl Default for YaraEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let engine = YaraEngine::new();
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn test_default_rules() {
        let engine = YaraEngine::with_default_rules().unwrap();
        assert!(engine.rule_count() > 0);
    }

    #[test]
    fn test_add_rule() {
        let mut engine = YaraEngine::new();

        engine
            .add_rule(
                YaraRule::new("TestRule")
                    .with_string(StringPattern::text("$test", "hello"))
                    .with_condition(Condition::Any),
            )
            .unwrap();

        assert_eq!(engine.rule_count(), 1);
        assert!(engine.get_rule("TestRule").is_some());
    }

    #[test]
    fn test_scan_data() {
        let mut engine = YaraEngine::new();

        engine
            .add_rule(
                YaraRule::new("HelloWorld")
                    .with_string(StringPattern::text_nocase("$hello", "hello world"))
                    .with_condition(Condition::Any),
            )
            .unwrap();

        let data = b"This contains Hello World text";
        let matches = engine.scan_data(data);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "HelloWorld");
    }

    #[test]
    fn test_eicar_detection() {
        let engine = YaraEngine::with_default_rules().unwrap();

        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let matches = engine.scan_data(eicar);

        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.rule_name == "EICAR_TestFile"));
    }

    #[test]
    fn test_ransomware_detection() {
        let engine = YaraEngine::with_default_rules().unwrap();

        // Simulated PE with ransomware strings
        let mut data = vec![0x4D, 0x5A]; // MZ header
        data.extend(vec![0; 100]);
        data.extend(b"Your files have been encrypted. Pay bitcoin to restore.");

        let matches = engine.scan_data(&data);

        assert!(matches.iter().any(|m| m.rule_name == "Ransomware_Generic"));
    }

    #[test]
    fn test_enable_disable_rule() {
        let mut engine = YaraEngine::with_default_rules().unwrap();

        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

        // Initially should detect
        let matches = engine.scan_data(eicar);
        assert!(matches.iter().any(|m| m.rule_name == "EICAR_TestFile"));

        // Disable the rule
        engine.set_rule_enabled("EICAR_TestFile", false);

        // Should not detect now
        let matches = engine.scan_data(eicar);
        assert!(!matches.iter().any(|m| m.rule_name == "EICAR_TestFile"));

        // Re-enable
        engine.set_rule_enabled("EICAR_TestFile", true);

        // Should detect again
        let matches = engine.scan_data(eicar);
        assert!(matches.iter().any(|m| m.rule_name == "EICAR_TestFile"));
    }

    #[test]
    fn test_list_rules() {
        let engine = YaraEngine::with_default_rules().unwrap();
        let rules = engine.list_rules();

        assert!(!rules.is_empty());
        assert!(rules.contains(&"EICAR_TestFile"));
        assert!(rules.contains(&"Ransomware_Generic"));
    }
}
