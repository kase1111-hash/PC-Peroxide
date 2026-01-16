//! Suspicious memory patterns and indicators.
//!
//! Defines patterns to detect in process memory and suspicious indicators.

/// A pattern to search for in process memory.
#[derive(Debug, Clone)]
pub struct MemoryPattern {
    /// Pattern name/identifier
    pub name: String,
    /// Byte sequence to match
    pub bytes: Vec<u8>,
    /// Description of what this pattern indicates
    pub description: String,
    /// Severity score (0-100)
    pub severity: u8,
    /// Category of the pattern
    pub category: PatternCategory,
}

impl MemoryPattern {
    /// Create a new memory pattern.
    pub fn new(name: impl Into<String>, bytes: &[u8]) -> Self {
        Self {
            name: name.into(),
            bytes: bytes.to_vec(),
            description: String::new(),
            severity: 50,
            category: PatternCategory::Generic,
        }
    }

    /// Set the description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Set the severity.
    pub fn with_severity(mut self, severity: u8) -> Self {
        self.severity = severity.min(100);
        self
    }

    /// Set the category.
    pub fn with_category(mut self, category: PatternCategory) -> Self {
        self.category = category;
        self
    }
}

/// Category of memory pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternCategory {
    /// Generic/uncategorized
    Generic,
    /// Shellcode indicators
    Shellcode,
    /// Remote access tool (RAT)
    RemoteAccess,
    /// Credential theft
    CredentialTheft,
    /// Process injection
    Injection,
    /// Ransomware indicators
    Ransomware,
    /// Keylogger indicators
    Keylogger,
    /// Command and control (C2)
    CommandControl,
    /// Packer/crypter
    Packer,
}

impl std::fmt::Display for PatternCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Generic => write!(f, "Generic"),
            Self::Shellcode => write!(f, "Shellcode"),
            Self::RemoteAccess => write!(f, "RAT"),
            Self::CredentialTheft => write!(f, "Credential Theft"),
            Self::Injection => write!(f, "Injection"),
            Self::Ransomware => write!(f, "Ransomware"),
            Self::Keylogger => write!(f, "Keylogger"),
            Self::CommandControl => write!(f, "C2"),
            Self::Packer => write!(f, "Packer"),
        }
    }
}

/// A match found in process memory.
#[derive(Debug, Clone)]
pub struct PatternMatch {
    /// Name of the pattern that matched
    pub pattern_name: String,
    /// Address where the pattern was found
    pub address: u64,
    /// Description of what this indicates
    pub description: String,
    /// Severity of this match
    pub severity: u8,
}

impl PatternMatch {
    /// Create a new pattern match.
    pub fn new(pattern_name: impl Into<String>, address: u64) -> Self {
        Self {
            pattern_name: pattern_name.into(),
            address,
            description: String::new(),
            severity: 50,
        }
    }

    /// Set the description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Set the severity.
    pub fn with_severity(mut self, severity: u8) -> Self {
        self.severity = severity;
        self
    }
}

impl std::fmt::Display for PatternMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} at 0x{:x} (severity: {})",
            self.pattern_name, self.address, self.severity
        )
    }
}

/// A suspicious indicator found during process analysis.
#[derive(Debug, Clone)]
pub struct SuspiciousIndicator {
    /// Short name of the indicator
    pub name: String,
    /// Detailed description
    pub description: String,
    /// Severity score (0-100)
    pub severity: u8,
    /// Category of indicator
    pub category: IndicatorCategory,
}

impl SuspiciousIndicator {
    /// Create a new suspicious indicator.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        severity: u8,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            severity: severity.min(100),
            category: IndicatorCategory::Behavioral,
        }
    }

    /// Set the category.
    pub fn with_category(mut self, category: IndicatorCategory) -> Self {
        self.category = category;
        self
    }
}

impl std::fmt::Display for SuspiciousIndicator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} (severity: {})",
            self.category, self.name, self.severity
        )
    }
}

/// Category of suspicious indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndicatorCategory {
    /// Behavioral indicator
    Behavioral,
    /// Memory anomaly
    Memory,
    /// Process anomaly
    Process,
    /// Network indicator
    Network,
    /// File system indicator
    FileSystem,
    /// Registry indicator
    Registry,
}

impl std::fmt::Display for IndicatorCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Behavioral => write!(f, "Behavioral"),
            Self::Memory => write!(f, "Memory"),
            Self::Process => write!(f, "Process"),
            Self::Network => write!(f, "Network"),
            Self::FileSystem => write!(f, "FileSystem"),
            Self::Registry => write!(f, "Registry"),
        }
    }
}

/// Collection of predefined patterns for common threats.
pub struct PatternDatabase;

impl PatternDatabase {
    /// Get shellcode detection patterns.
    pub fn shellcode_patterns() -> Vec<MemoryPattern> {
        vec![
            // x64 shellcode patterns
            MemoryPattern::new("x64_syscall_stub", &[0x4c, 0x8b, 0xd1, 0xb8])
                .with_description("x64 syscall stub pattern")
                .with_severity(55)
                .with_category(PatternCategory::Shellcode),

            MemoryPattern::new("x64_gs_access", &[0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00])
                .with_description("x64 GS segment TEB access")
                .with_severity(50)
                .with_category(PatternCategory::Shellcode),

            // x86 shellcode patterns
            MemoryPattern::new("x86_fs_access", &[0x64, 0xa1, 0x30, 0x00, 0x00, 0x00])
                .with_description("x86 FS segment PEB access")
                .with_severity(50)
                .with_category(PatternCategory::Shellcode),

            MemoryPattern::new("x86_getpc", &[0xe8, 0x00, 0x00, 0x00, 0x00, 0x58])
                .with_description("x86 GetPC technique (call/pop)")
                .with_severity(55)
                .with_category(PatternCategory::Shellcode),

            // Egg hunter patterns
            MemoryPattern::new("egg_hunter_scasd", &[0xaf, 0x75])
                .with_description("Egg hunter scasd loop")
                .with_severity(60)
                .with_category(PatternCategory::Shellcode),
        ]
    }

    /// Get RAT/backdoor detection patterns.
    pub fn rat_patterns() -> Vec<MemoryPattern> {
        vec![
            // Meterpreter
            MemoryPattern::new("metsrv", b"metsrv")
                .with_description("Meterpreter server")
                .with_severity(85)
                .with_category(PatternCategory::RemoteAccess),

            MemoryPattern::new("meterpreter", b"meterpreter")
                .with_description("Meterpreter string")
                .with_severity(80)
                .with_category(PatternCategory::RemoteAccess),

            // Cobalt Strike
            MemoryPattern::new("beacon", b"beacon")
                .with_description("Cobalt Strike Beacon")
                .with_severity(85)
                .with_category(PatternCategory::RemoteAccess),

            MemoryPattern::new("cobaltstrike", b"cobaltstrike")
                .with_description("Cobalt Strike string")
                .with_severity(85)
                .with_category(PatternCategory::RemoteAccess),

            // Empire
            MemoryPattern::new("empire", b"empire")
                .with_description("Empire framework")
                .with_severity(75)
                .with_category(PatternCategory::RemoteAccess),

            // Generic RAT indicators
            MemoryPattern::new("reverse_shell", b"reverse shell")
                .with_description("Reverse shell string")
                .with_severity(70)
                .with_category(PatternCategory::RemoteAccess),
        ]
    }

    /// Get credential theft detection patterns.
    pub fn credential_patterns() -> Vec<MemoryPattern> {
        vec![
            // Mimikatz
            MemoryPattern::new("mimikatz", b"mimikatz")
                .with_description("Mimikatz tool")
                .with_severity(95)
                .with_category(PatternCategory::CredentialTheft),

            MemoryPattern::new("sekurlsa", b"sekurlsa")
                .with_description("Mimikatz sekurlsa module")
                .with_severity(90)
                .with_category(PatternCategory::CredentialTheft),

            MemoryPattern::new("wdigest", b"wdigest")
                .with_description("WDigest credential access")
                .with_severity(60)
                .with_category(PatternCategory::CredentialTheft),

            MemoryPattern::new("lsadump", b"lsadump")
                .with_description("LSA dump functionality")
                .with_severity(85)
                .with_category(PatternCategory::CredentialTheft),

            // LaZagne
            MemoryPattern::new("lazagne", b"lazagne")
                .with_description("LaZagne credential harvester")
                .with_severity(85)
                .with_category(PatternCategory::CredentialTheft),
        ]
    }

    /// Get injection detection patterns.
    pub fn injection_patterns() -> Vec<MemoryPattern> {
        vec![
            // Reflective loading
            MemoryPattern::new("reflective_loader", b"ReflectiveLoader")
                .with_description("Reflective DLL loader")
                .with_severity(75)
                .with_category(PatternCategory::Injection),

            // Process hollowing
            MemoryPattern::new("ntunmapview", b"NtUnmapViewOfSection")
                .with_description("NT unmap section (hollowing)")
                .with_severity(50)
                .with_category(PatternCategory::Injection),

            // APC injection
            MemoryPattern::new("ntqueueapc", b"NtQueueApcThread")
                .with_description("APC queue injection")
                .with_severity(55)
                .with_category(PatternCategory::Injection),

            // Thread hijacking
            MemoryPattern::new("setthreadcontext", b"SetThreadContext")
                .with_description("Thread context manipulation")
                .with_severity(45)
                .with_category(PatternCategory::Injection),
        ]
    }

    /// Get ransomware detection patterns.
    pub fn ransomware_patterns() -> Vec<MemoryPattern> {
        vec![
            // Encryption indicators
            MemoryPattern::new("cryptoapi", b"CryptEncrypt")
                .with_description("Windows Crypto API encryption")
                .with_severity(30)
                .with_category(PatternCategory::Ransomware),

            // Ransom note patterns
            MemoryPattern::new("readme_txt", b"README.txt")
                .with_description("Ransom note filename")
                .with_severity(35)
                .with_category(PatternCategory::Ransomware),

            MemoryPattern::new("decrypt_files", b"decrypt your files")
                .with_description("Ransom message")
                .with_severity(70)
                .with_category(PatternCategory::Ransomware),

            MemoryPattern::new("bitcoin", b"bitcoin")
                .with_description("Bitcoin reference")
                .with_severity(25)
                .with_category(PatternCategory::Ransomware),

            MemoryPattern::new("onion", b".onion")
                .with_description("Tor hidden service")
                .with_severity(40)
                .with_category(PatternCategory::Ransomware),

            // Shadow copy deletion
            MemoryPattern::new("vssadmin", b"vssadmin")
                .with_description("VSS admin tool")
                .with_severity(45)
                .with_category(PatternCategory::Ransomware),

            MemoryPattern::new("shadowcopy", b"shadowcopy")
                .with_description("Shadow copy reference")
                .with_severity(40)
                .with_category(PatternCategory::Ransomware),
        ]
    }

    /// Get all patterns combined.
    pub fn all_patterns() -> Vec<MemoryPattern> {
        let mut patterns = Vec::new();
        patterns.extend(Self::shellcode_patterns());
        patterns.extend(Self::rat_patterns());
        patterns.extend(Self::credential_patterns());
        patterns.extend(Self::injection_patterns());
        patterns.extend(Self::ransomware_patterns());
        patterns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_pattern_new() {
        let pattern = MemoryPattern::new("test", b"TEST");
        assert_eq!(pattern.name, "test");
        assert_eq!(pattern.bytes, b"TEST");
        assert_eq!(pattern.severity, 50);
    }

    #[test]
    fn test_memory_pattern_with_options() {
        let pattern = MemoryPattern::new("test", b"TEST")
            .with_description("Test pattern")
            .with_severity(75)
            .with_category(PatternCategory::Shellcode);

        assert_eq!(pattern.description, "Test pattern");
        assert_eq!(pattern.severity, 75);
        assert_eq!(pattern.category, PatternCategory::Shellcode);
    }

    #[test]
    fn test_memory_pattern_severity_cap() {
        let pattern = MemoryPattern::new("test", b"TEST").with_severity(150);
        assert_eq!(pattern.severity, 100); // Capped at 100
    }

    #[test]
    fn test_pattern_match_display() {
        let m = PatternMatch::new("test_pattern", 0x1234)
            .with_severity(75);
        let display = format!("{}", m);
        assert!(display.contains("test_pattern"));
        assert!(display.contains("0x1234"));
        assert!(display.contains("75"));
    }

    #[test]
    fn test_suspicious_indicator_new() {
        let indicator = SuspiciousIndicator::new("test", "Test indicator", 60);
        assert_eq!(indicator.name, "test");
        assert_eq!(indicator.description, "Test indicator");
        assert_eq!(indicator.severity, 60);
    }

    #[test]
    fn test_suspicious_indicator_display() {
        let indicator = SuspiciousIndicator::new("test", "desc", 50)
            .with_category(IndicatorCategory::Memory);
        let display = format!("{}", indicator);
        assert!(display.contains("Memory"));
        assert!(display.contains("test"));
    }

    #[test]
    fn test_pattern_category_display() {
        assert_eq!(format!("{}", PatternCategory::Shellcode), "Shellcode");
        assert_eq!(format!("{}", PatternCategory::RemoteAccess), "RAT");
        assert_eq!(format!("{}", PatternCategory::CredentialTheft), "Credential Theft");
    }

    #[test]
    fn test_indicator_category_display() {
        assert_eq!(format!("{}", IndicatorCategory::Behavioral), "Behavioral");
        assert_eq!(format!("{}", IndicatorCategory::Memory), "Memory");
        assert_eq!(format!("{}", IndicatorCategory::Process), "Process");
    }

    #[test]
    fn test_pattern_database_shellcode() {
        let patterns = PatternDatabase::shellcode_patterns();
        assert!(!patterns.is_empty());

        // All should be shellcode category
        assert!(patterns.iter().all(|p| p.category == PatternCategory::Shellcode));
    }

    #[test]
    fn test_pattern_database_all() {
        let patterns = PatternDatabase::all_patterns();

        // Should have patterns from all categories
        assert!(!patterns.is_empty());

        let has_shellcode = patterns.iter().any(|p| p.category == PatternCategory::Shellcode);
        let has_rat = patterns.iter().any(|p| p.category == PatternCategory::RemoteAccess);
        let has_cred = patterns.iter().any(|p| p.category == PatternCategory::CredentialTheft);

        assert!(has_shellcode);
        assert!(has_rat);
        assert!(has_cred);
    }
}
