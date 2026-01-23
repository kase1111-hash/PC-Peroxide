//! Import table analysis for detecting suspicious API usage.
//!
//! Malware often uses specific Windows APIs for:
//! - Process injection (VirtualAllocEx, WriteProcessMemory)
//! - Keylogging (GetAsyncKeyState, SetWindowsHookEx)
//! - Ransomware (CryptEncrypt, CryptDecrypt)
//! - Evasion (IsDebuggerPresent, CheckRemoteDebuggerPresent)

use super::pe::PeInfo;

/// Suspicious import detection result.
#[derive(Debug, Clone)]
pub struct SuspiciousImport {
    /// API name
    pub name: String,
    /// DLL it's imported from
    pub dll: String,
    /// Risk category
    pub category: String,
    /// Risk level description
    pub risk_level: String,
    /// Suspicion score (0-100)
    pub score: u8,
    /// Description of why it's suspicious
    pub description: String,
}

/// Import table analyzer.
pub struct ImportAnalyzer {
    /// Suspicious API definitions
    suspicious_apis: Vec<SuspiciousApiDef>,
    /// Suspicious API combinations
    combinations: Vec<ApiCombination>,
}

/// Definition of a suspicious API.
struct SuspiciousApiDef {
    name: &'static str,
    category: &'static str,
    risk_level: &'static str,
    score: u8,
    description: &'static str,
}

/// Suspicious API combination.
struct ApiCombination {
    apis: Vec<&'static str>,
    category: &'static str,
    risk_level: &'static str,
    bonus_score: u8,
    description: &'static str,
}

impl Default for ImportAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl ImportAnalyzer {
    /// Create a new import analyzer with default suspicious API definitions.
    pub fn new() -> Self {
        Self {
            suspicious_apis: Self::default_suspicious_apis(),
            combinations: Self::default_combinations(),
        }
    }

    /// Default list of suspicious APIs.
    fn default_suspicious_apis() -> Vec<SuspiciousApiDef> {
        vec![
            // Process injection APIs
            SuspiciousApiDef {
                name: "VirtualAllocEx",
                category: "injection",
                risk_level: "high",
                score: 15,
                description: "Allocates memory in another process (process injection)",
            },
            SuspiciousApiDef {
                name: "WriteProcessMemory",
                category: "injection",
                risk_level: "high",
                score: 15,
                description: "Writes to another process's memory (process injection)",
            },
            SuspiciousApiDef {
                name: "CreateRemoteThread",
                category: "injection",
                risk_level: "critical",
                score: 20,
                description: "Creates thread in another process (code injection)",
            },
            SuspiciousApiDef {
                name: "NtUnmapViewOfSection",
                category: "injection",
                risk_level: "critical",
                score: 25,
                description: "Unmaps section (process hollowing)",
            },
            SuspiciousApiDef {
                name: "QueueUserAPC",
                category: "injection",
                risk_level: "high",
                score: 15,
                description: "Queues APC to thread (APC injection)",
            },
            SuspiciousApiDef {
                name: "NtQueueApcThread",
                category: "injection",
                risk_level: "high",
                score: 15,
                description: "Native APC queuing (injection)",
            },

            // Input handling APIs (common in games, input managers, accessibility software)
            SuspiciousApiDef {
                name: "SetWindowsHookEx",
                category: "keylogger",
                risk_level: "medium",
                score: 8,  // Reduced: used by hotkey managers, accessibility
                description: "Sets Windows hook",
            },
            SuspiciousApiDef {
                name: "GetAsyncKeyState",
                category: "keylogger",
                risk_level: "low",
                score: 2,  // Reduced: extremely common in games
                description: "Gets key state",
            },
            SuspiciousApiDef {
                name: "GetKeyState",
                category: "keylogger",
                risk_level: "low",
                score: 0,  // Reduced to 0: basic input handling
                description: "Gets key state",
            },
            SuspiciousApiDef {
                name: "RegisterRawInputDevices",
                category: "keylogger",
                risk_level: "low",
                score: 2,  // Reduced: used by games, input software
                description: "Registers raw input",
            },

            // Cryptography APIs (ransomware indicators when combined, but commonly used by legitimate software)
            SuspiciousApiDef {
                name: "CryptEncrypt",
                category: "ransomware",
                risk_level: "low",
                score: 3,  // Reduced: commonly used by legitimate crypto libraries
                description: "Encrypts data (common in legitimate software)",
            },
            SuspiciousApiDef {
                name: "CryptDecrypt",
                category: "ransomware",
                risk_level: "low",
                score: 2,  // Reduced: very common
                description: "Decrypts data",
            },
            SuspiciousApiDef {
                name: "CryptGenKey",
                category: "ransomware",
                risk_level: "low",
                score: 3,  // Reduced: commonly used legitimately
                description: "Generates crypto key",
            },
            SuspiciousApiDef {
                name: "CryptAcquireContext",
                category: "ransomware",
                risk_level: "low",
                score: 2,  // Reduced: very common
                description: "Acquires crypto context",
            },

            // Downloading/networking (common in all internet-connected apps)
            SuspiciousApiDef {
                name: "URLDownloadToFile",
                category: "downloader",
                risk_level: "medium",
                score: 8,  // Reduced: used by updaters, installers
                description: "Downloads file from URL",
            },
            SuspiciousApiDef {
                name: "InternetReadFile",
                category: "downloader",
                risk_level: "low",
                score: 1,  // Reduced: extremely common
                description: "Reads from internet",
            },
            SuspiciousApiDef {
                name: "HttpSendRequest",
                category: "networking",
                risk_level: "low",
                score: 0,  // Reduced to 0: basic networking
                description: "Sends HTTP request",
            },

            // Anti-debugging (also used by legitimate software like games, anti-cheat, debuggers)
            SuspiciousApiDef {
                name: "IsDebuggerPresent",
                category: "anti_debug",
                risk_level: "low",
                score: 3,  // Reduced: used by anti-cheat systems, games
                description: "Checks for debugger",
            },
            SuspiciousApiDef {
                name: "CheckRemoteDebuggerPresent",
                category: "anti_debug",
                risk_level: "low",
                score: 4,  // Reduced: used by anti-cheat systems
                description: "Checks for remote debugger",
            },
            SuspiciousApiDef {
                name: "NtQueryInformationProcess",
                category: "anti_debug",
                risk_level: "low",
                score: 3,  // Reduced: legitimate uses
                description: "Queries process info",
            },
            SuspiciousApiDef {
                name: "OutputDebugString",
                category: "anti_debug",
                risk_level: "low",
                score: 0,  // Reduced to 0: debugging is normal
                description: "Debug output",
            },

            // Persistence (common in legitimate installers and applications)
            SuspiciousApiDef {
                name: "RegSetValueEx",
                category: "persistence",
                risk_level: "low",
                score: 1,  // Reduced: extremely common in legitimate software
                description: "Sets registry value",
            },
            SuspiciousApiDef {
                name: "CreateService",
                category: "persistence",
                risk_level: "low",
                score: 4,  // Reduced: used by legitimate installers
                description: "Creates Windows service",
            },
            SuspiciousApiDef {
                name: "ChangeServiceConfig",
                category: "persistence",
                risk_level: "low",
                score: 3,  // Reduced: used by service managers
                description: "Modifies service config",
            },

            // Privilege operations (used by installers, admin tools)
            SuspiciousApiDef {
                name: "AdjustTokenPrivileges",
                category: "privilege",
                risk_level: "low",
                score: 4,  // Reduced: used by installers, backup tools
                description: "Adjusts token privileges",
            },
            SuspiciousApiDef {
                name: "LookupPrivilegeValue",
                category: "privilege",
                risk_level: "low",
                score: 1,  // Reduced: common setup operation
                description: "Looks up privilege value",
            },
            SuspiciousApiDef {
                name: "ImpersonateLoggedOnUser",
                category: "privilege",
                risk_level: "medium",
                score: 8,  // Reduced: used by services, admin tools
                description: "Impersonates user",
            },

            // Shell execution (very common in legitimate software)
            SuspiciousApiDef {
                name: "ShellExecute",
                category: "execution",
                risk_level: "low",
                score: 2,  // Reduced: very common
                description: "Executes shell command",
            },
            SuspiciousApiDef {
                name: "CreateProcess",
                category: "execution",
                risk_level: "low",
                score: 1,  // Reduced: extremely common in all software
                description: "Creates new process",
            },
            SuspiciousApiDef {
                name: "WinExec",
                category: "execution",
                risk_level: "low",
                score: 4,  // Reduced: legacy but still used
                description: "Executes program (legacy API)",
            },

            // Screen/graphics operations (extremely common in GUI applications)
            SuspiciousApiDef {
                name: "BitBlt",
                category: "spyware",
                risk_level: "low",
                score: 0,  // Reduced to 0: used by all GUI apps
                description: "Copies bitmap",
            },
            SuspiciousApiDef {
                name: "GetDC",
                category: "spyware",
                risk_level: "low",
                score: 0,  // Reduced to 0: used by all GUI apps
                description: "Gets device context",
            },

            // Process manipulation
            SuspiciousApiDef {
                name: "OpenProcess",
                category: "process",
                risk_level: "low",
                score: 2,  // Reduced: common in legitimate software
                description: "Opens process handle",
            },
            SuspiciousApiDef {
                name: "TerminateProcess",
                category: "process",
                risk_level: "low",
                score: 3,  // Reduced: used by process managers, installers
                description: "Terminates process",
            },
            SuspiciousApiDef {
                name: "SuspendThread",
                category: "process",
                risk_level: "low",
                score: 4,  // Reduced: used by debuggers, profilers
                description: "Suspends thread",
            },

            // Module loading (extremely common - nearly every program uses these)
            SuspiciousApiDef {
                name: "LoadLibrary",
                category: "loading",
                risk_level: "low",
                score: 0,  // Reduced to 0: used by virtually every program
                description: "Loads library dynamically",
            },
            SuspiciousApiDef {
                name: "GetProcAddress",
                category: "loading",
                risk_level: "low",
                score: 0,  // Reduced to 0: used by virtually every program
                description: "Gets function address",
            },
            SuspiciousApiDef {
                name: "LdrLoadDll",
                category: "loading",
                risk_level: "medium",
                score: 5,  // Reduced: native but still legitimate in some cases
                description: "Native DLL loading (evasion)",
            },
        ]
    }

    /// Default suspicious API combinations.
    fn default_combinations() -> Vec<ApiCombination> {
        vec![
            // Classic process injection
            ApiCombination {
                apis: vec!["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
                category: "injection",
                risk_level: "critical",
                bonus_score: 30,
                description: "Classic process injection pattern",
            },
            // Process hollowing
            ApiCombination {
                apis: vec!["CreateProcess", "NtUnmapViewOfSection", "VirtualAllocEx", "WriteProcessMemory"],
                category: "injection",
                risk_level: "critical",
                bonus_score: 40,
                description: "Process hollowing pattern",
            },
            // Keylogger pattern
            ApiCombination {
                apis: vec!["SetWindowsHookEx", "GetAsyncKeyState"],
                category: "keylogger",
                risk_level: "high",
                bonus_score: 20,
                description: "Keylogger pattern",
            },
            // Ransomware pattern
            ApiCombination {
                apis: vec!["CryptAcquireContext", "CryptGenKey", "CryptEncrypt"],
                category: "ransomware",
                risk_level: "high",
                bonus_score: 25,
                description: "Ransomware encryption pattern",
            },
            // Anti-debugging combo
            ApiCombination {
                apis: vec!["IsDebuggerPresent", "CheckRemoteDebuggerPresent"],
                category: "anti_debug",
                risk_level: "medium",
                bonus_score: 10,
                description: "Anti-debugging checks",
            },
            // Dropper pattern
            ApiCombination {
                apis: vec!["URLDownloadToFile", "CreateProcess"],
                category: "downloader",
                risk_level: "high",
                bonus_score: 20,
                description: "Dropper/downloader pattern",
            },
            // Privilege escalation
            ApiCombination {
                apis: vec!["AdjustTokenPrivileges", "ImpersonateLoggedOnUser"],
                category: "privilege",
                risk_level: "high",
                bonus_score: 15,
                description: "Privilege escalation pattern",
            },
        ]
    }

    /// Analyze PE imports for suspicious patterns.
    pub fn analyze(&self, pe_info: &PeInfo) -> Vec<SuspiciousImport> {
        let mut results = Vec::new();
        let mut found_apis: Vec<&str> = Vec::new();

        // Check each import
        for import in &pe_info.imports {
            let func_name = &import.function;

            // Check against suspicious API list
            for api_def in &self.suspicious_apis {
                // Case-insensitive match, also handle A/W suffixes
                let matches = func_name.eq_ignore_ascii_case(api_def.name)
                    || func_name.eq_ignore_ascii_case(&format!("{}A", api_def.name))
                    || func_name.eq_ignore_ascii_case(&format!("{}W", api_def.name))
                    || func_name.eq_ignore_ascii_case(&format!("{}Ex", api_def.name))
                    || func_name.eq_ignore_ascii_case(&format!("{}ExA", api_def.name))
                    || func_name.eq_ignore_ascii_case(&format!("{}ExW", api_def.name));

                if matches {
                    found_apis.push(api_def.name);
                    results.push(SuspiciousImport {
                        name: func_name.clone(),
                        dll: import.dll.clone(),
                        category: api_def.category.to_string(),
                        risk_level: api_def.risk_level.to_string(),
                        score: api_def.score,
                        description: api_def.description.to_string(),
                    });
                }
            }
        }

        // Check for suspicious combinations
        for combo in &self.combinations {
            let all_present = combo
                .apis
                .iter()
                .all(|api| found_apis.iter().any(|f| f.eq_ignore_ascii_case(api)));

            if all_present {
                // Add a bonus indicator for the combination
                results.push(SuspiciousImport {
                    name: format!("API Combination: {:?}", combo.apis),
                    dll: "multiple".to_string(),
                    category: combo.category.to_string(),
                    risk_level: combo.risk_level.to_string(),
                    score: combo.bonus_score,
                    description: combo.description.to_string(),
                });
            }
        }

        results
    }

    /// Get total score from suspicious imports.
    pub fn total_score(&self, imports: &[SuspiciousImport]) -> u8 {
        let score: u32 = imports.iter().map(|i| i.score as u32).sum();
        score.min(100) as u8
    }

    /// Check if imports indicate a specific threat category.
    pub fn categorize_threat(&self, imports: &[SuspiciousImport]) -> Option<String> {
        // Count categories
        let mut category_counts: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();

        for import in imports {
            *category_counts.entry(&import.category).or_insert(0) += 1;
        }

        // Find dominant category
        category_counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(cat, _)| cat.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::heuristic::pe::ImportEntry;

    fn create_test_pe_info(imports: Vec<(&str, &str)>) -> PeInfo {
        PeInfo {
            is_64bit: false,
            is_dll: false,
            image_base: 0x400000,
            entry_point: 0x1000,
            num_sections: 1,
            sections: vec![],
            imports: imports
                .into_iter()
                .map(|(dll, func)| ImportEntry {
                    dll: dll.to_string(),
                    function: func.to_string(),
                })
                .collect(),
            exports: vec![],
            timestamp: 0,
            subsystem: 3,
            characteristics: 0,
            dll_characteristics: 0,
            has_aslr: true,
            has_dep: true,
            has_seh: true,
            has_cfg: false,
            header_size: 0x200,
            file_alignment: 0x200,
            section_alignment: 0x1000,
            has_debug_info: false,
            has_tls: false,
            has_resources: false,
            has_signature: false,
        }
    }

    #[test]
    fn test_suspicious_import_detection() {
        let analyzer = ImportAnalyzer::new();
        let pe = create_test_pe_info(vec![
            ("kernel32.dll", "VirtualAllocEx"),
            ("kernel32.dll", "WriteProcessMemory"),
            ("kernel32.dll", "CreateRemoteThread"),
        ]);

        let results = analyzer.analyze(&pe);
        assert!(!results.is_empty());

        // Should detect individual APIs and the combination
        let api_names: Vec<&str> = results.iter().map(|r| r.name.as_str()).collect();
        assert!(api_names.contains(&"VirtualAllocEx"));
        assert!(api_names.contains(&"WriteProcessMemory"));
        assert!(api_names.contains(&"CreateRemoteThread"));

        // Should have high total score due to injection pattern
        let total = analyzer.total_score(&results);
        assert!(total > 50);
    }

    #[test]
    fn test_clean_imports() {
        let analyzer = ImportAnalyzer::new();
        let pe = create_test_pe_info(vec![
            ("kernel32.dll", "GetModuleHandle"),
            ("user32.dll", "MessageBox"),
            ("gdi32.dll", "CreateFont"),
        ]);

        let results = analyzer.analyze(&pe);
        assert!(results.is_empty());
    }

    #[test]
    fn test_keylogger_pattern() {
        let analyzer = ImportAnalyzer::new();
        let pe = create_test_pe_info(vec![
            ("user32.dll", "SetWindowsHookExW"),
            ("user32.dll", "GetAsyncKeyState"),
        ]);

        let results = analyzer.analyze(&pe);
        assert!(!results.is_empty());

        // Should detect keylogger combination
        let has_combo = results
            .iter()
            .any(|r| r.description.contains("Keylogger pattern"));
        assert!(has_combo);
    }

    #[test]
    fn test_threat_categorization() {
        let analyzer = ImportAnalyzer::new();
        let pe = create_test_pe_info(vec![
            ("advapi32.dll", "CryptAcquireContextW"),
            ("advapi32.dll", "CryptGenKey"),
            ("advapi32.dll", "CryptEncrypt"),
        ]);

        let results = analyzer.analyze(&pe);
        let category = analyzer.categorize_threat(&results);

        assert_eq!(category, Some("ransomware".to_string()));
    }
}
