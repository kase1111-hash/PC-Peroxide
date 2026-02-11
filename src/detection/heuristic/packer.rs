//! Packer/protector detection for identifying obfuscated executables.
//!
//! Malware often uses packers to:
//! - Evade signature detection
//! - Make reverse engineering harder
//! - Compress the executable
//!
//! Common packers: UPX, ASPack, Themida, VMProtect, PECompact

use super::pe::PeInfo;

/// Information about a detected packer.
#[derive(Debug, Clone)]
pub struct PackerInfo {
    /// Packer name
    pub name: String,
    /// Version (if detectable)
    pub version: Option<String>,
    /// Detection method used
    pub detection_method: String,
    /// Suspicion score (0-100)
    pub suspicion_score: u8,
    /// Whether this packer is commonly used for malware
    pub malware_associated: bool,
}

/// Packer signature for detection.
struct PackerSignature {
    name: &'static str,
    /// Byte patterns to look for
    patterns: &'static [PackerPattern],
    /// Section names associated with this packer
    section_names: &'static [&'static str],
    /// Suspicion score
    suspicion_score: u8,
    /// Whether commonly used for malware
    malware_associated: bool,
}

/// A byte pattern for packer detection.
struct PackerPattern {
    /// Bytes to match (None = wildcard)
    bytes: &'static [Option<u8>],
    /// Where to look for this pattern
    location: PatternLocation,
    /// Description
    #[allow(dead_code)]
    description: &'static str,
}

/// Where to look for a pattern.
#[derive(Clone, Copy)]
enum PatternLocation {
    /// At entry point
    EntryPoint,
    /// Anywhere in the file
    Anywhere,
    /// At a specific offset
    #[allow(dead_code)]
    Offset(usize),
}

/// Packer detector.
pub struct PackerDetector {
    signatures: Vec<PackerSignature>,
}

impl Default for PackerDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PackerDetector {
    /// Create a new packer detector with default signatures.
    pub fn new() -> Self {
        Self {
            signatures: Self::default_signatures(),
        }
    }

    /// Default packer signatures.
    fn default_signatures() -> Vec<PackerSignature> {
        vec![
            // UPX - legitimate open-source packer, commonly used
            PackerSignature {
                name: "UPX",
                patterns: &[
                    PackerPattern {
                        bytes: &[
                            Some(0x60), // PUSHAD
                            Some(0xBE),
                            None,
                            None,
                            None,
                            None,
                            Some(0x8D),
                            Some(0xBE),
                        ],
                        location: PatternLocation::EntryPoint,
                        description: "UPX entry point signature",
                    },
                    PackerPattern {
                        bytes: &[
                            Some(0x55),
                            Some(0x50),
                            Some(0x58), // "UPX"
                            Some(0x21),
                        ],
                        location: PatternLocation::Anywhere,
                        description: "UPX! string",
                    },
                ],
                section_names: &["UPX0", "UPX1", "UPX2", ".UPX"],
                suspicion_score: 5, // Reduced from 15: UPX is a legitimate packer
                malware_associated: false,
            },
            // ASPack
            PackerSignature {
                name: "ASPack",
                patterns: &[PackerPattern {
                    bytes: &[
                        Some(0x60), // PUSHAD
                        Some(0xE8),
                        Some(0x03),
                        Some(0x00),
                        Some(0x00),
                        Some(0x00),
                    ],
                    location: PatternLocation::EntryPoint,
                    description: "ASPack entry signature",
                }],
                section_names: &[".aspack", ".adata", ".ASPack"],
                suspicion_score: 25,
                malware_associated: true,
            },
            // Themida / WinLicense
            PackerSignature {
                name: "Themida",
                patterns: &[],
                section_names: &[".themida", ".winlic", "Themida", ".vm"],
                suspicion_score: 40,
                malware_associated: true,
            },
            // VMProtect
            PackerSignature {
                name: "VMProtect",
                patterns: &[],
                section_names: &[".vmp0", ".vmp1", ".vmp2", "vmp0", "vmp1", ".VMProtect"],
                suspicion_score: 40,
                malware_associated: true,
            },
            // PECompact
            PackerSignature {
                name: "PECompact",
                patterns: &[PackerPattern {
                    bytes: &[
                        Some(0xB8),
                        None,
                        None,
                        None,
                        None,
                        Some(0x50),
                        Some(0x64),
                        Some(0xFF),
                        Some(0x35),
                    ],
                    location: PatternLocation::EntryPoint,
                    description: "PECompact entry signature",
                }],
                section_names: &["PEC2", "pec1", "pec2", "PEC2MO"],
                suspicion_score: 25,
                malware_associated: true,
            },
            // FSG
            PackerSignature {
                name: "FSG",
                patterns: &[PackerPattern {
                    bytes: &[Some(0x87), Some(0x25), None, None, None, None],
                    location: PatternLocation::EntryPoint,
                    description: "FSG entry signature",
                }],
                section_names: &[],
                suspicion_score: 30,
                malware_associated: true,
            },
            // MPRESS
            PackerSignature {
                name: "MPRESS",
                patterns: &[PackerPattern {
                    bytes: &[
                        Some(0x60),
                        Some(0xE8),
                        Some(0x00),
                        Some(0x00),
                        Some(0x00),
                        Some(0x00),
                        Some(0x58),
                        Some(0x05),
                    ],
                    location: PatternLocation::EntryPoint,
                    description: "MPRESS entry signature",
                }],
                section_names: &[".MPRESS1", ".MPRESS2", "MPRESS1", "MPRESS2"],
                suspicion_score: 25,
                malware_associated: true,
            },
            // Obsidium
            PackerSignature {
                name: "Obsidium",
                patterns: &[PackerPattern {
                    bytes: &[Some(0xEB), Some(0x02), None, None, Some(0xE8)],
                    location: PatternLocation::EntryPoint,
                    description: "Obsidium entry signature",
                }],
                section_names: &[".obsidium"],
                suspicion_score: 35,
                malware_associated: true,
            },
            // Enigma Protector
            PackerSignature {
                name: "Enigma Protector",
                patterns: &[],
                section_names: &[".enigma1", ".enigma2", "ENIGMA"],
                suspicion_score: 35,
                malware_associated: true,
            },
            // Armadillo
            PackerSignature {
                name: "Armadillo",
                patterns: &[PackerPattern {
                    bytes: &[
                        Some(0x60),
                        Some(0xE8),
                        Some(0x00),
                        Some(0x00),
                        Some(0x00),
                        Some(0x00),
                        Some(0x5D),
                        Some(0x50),
                    ],
                    location: PatternLocation::EntryPoint,
                    description: "Armadillo entry signature",
                }],
                section_names: &[".arma", ".text1", ".text2", ".text3"],
                suspicion_score: 35,
                malware_associated: true,
            },
            // NsPack
            PackerSignature {
                name: "NsPack",
                patterns: &[PackerPattern {
                    bytes: &[
                        Some(0x9C),
                        Some(0x60),
                        Some(0xE8),
                        Some(0x00),
                        Some(0x00),
                        Some(0x00),
                        Some(0x00),
                    ],
                    location: PatternLocation::EntryPoint,
                    description: "NsPack entry signature",
                }],
                section_names: &["nsp0", "nsp1", "nsp2", ".nsp"],
                suspicion_score: 30,
                malware_associated: true,
            },
            // ConfuserEx (for .NET, but shows in section names)
            PackerSignature {
                name: "ConfuserEx",
                patterns: &[],
                section_names: &[".confuser"],
                suspicion_score: 30,
                malware_associated: true,
            },
        ]
    }

    /// Detect packer from file data and PE information.
    pub fn detect(&self, data: &[u8], pe_info: &PeInfo) -> Option<PackerInfo> {
        // First check section names
        if let Some(packer) = self.check_section_names(pe_info) {
            return Some(packer);
        }

        // Then check byte patterns
        if let Some(packer) = self.check_byte_patterns(data, pe_info) {
            return Some(packer);
        }

        // Check for generic packing indicators
        self.check_generic_packing(pe_info)
    }

    /// Check section names for packer indicators.
    fn check_section_names(&self, pe_info: &PeInfo) -> Option<PackerInfo> {
        for sig in &self.signatures {
            for section in &pe_info.sections {
                let section_name = section.name.to_uppercase();
                for packer_section in sig.section_names {
                    if section_name == packer_section.to_uppercase()
                        || section_name.contains(&packer_section.to_uppercase())
                    {
                        return Some(PackerInfo {
                            name: sig.name.to_string(),
                            version: None,
                            detection_method: format!("Section name: {}", section.name),
                            suspicion_score: sig.suspicion_score,
                            malware_associated: sig.malware_associated,
                        });
                    }
                }
            }
        }
        None
    }

    /// Check byte patterns for packer indicators.
    fn check_byte_patterns(&self, data: &[u8], pe_info: &PeInfo) -> Option<PackerInfo> {
        for sig in &self.signatures {
            for pattern in sig.patterns {
                let matched = match pattern.location {
                    PatternLocation::EntryPoint => {
                        self.match_at_entry_point(data, pe_info, pattern.bytes)
                    }
                    PatternLocation::Anywhere => self.match_anywhere(data, pattern.bytes),
                    PatternLocation::Offset(offset) => {
                        self.match_at_offset(data, offset, pattern.bytes)
                    }
                };

                if matched {
                    return Some(PackerInfo {
                        name: sig.name.to_string(),
                        version: None,
                        detection_method: format!("Byte pattern: {}", pattern.description),
                        suspicion_score: sig.suspicion_score,
                        malware_associated: sig.malware_associated,
                    });
                }
            }
        }
        None
    }

    /// Match pattern at entry point.
    fn match_at_entry_point(&self, data: &[u8], pe_info: &PeInfo, pattern: &[Option<u8>]) -> bool {
        // Find file offset of entry point
        let entry_rva = pe_info.entry_point;

        for section in &pe_info.sections {
            let section_end_rva = section.virtual_address + section.virtual_size;
            if entry_rva >= section.virtual_address && entry_rva < section_end_rva {
                // Entry point is in this section
                let offset_in_section = entry_rva - section.virtual_address;
                let file_offset = section.raw_offset + offset_in_section;

                return self.match_at_offset(data, file_offset as usize, pattern);
            }
        }

        false
    }

    /// Match pattern anywhere in data.
    fn match_anywhere(&self, data: &[u8], pattern: &[Option<u8>]) -> bool {
        if pattern.is_empty() || data.len() < pattern.len() {
            return false;
        }

        for i in 0..=data.len() - pattern.len() {
            if self.pattern_matches(&data[i..], pattern) {
                return true;
            }
        }
        false
    }

    /// Match pattern at specific offset.
    fn match_at_offset(&self, data: &[u8], offset: usize, pattern: &[Option<u8>]) -> bool {
        if offset + pattern.len() > data.len() {
            return false;
        }
        self.pattern_matches(&data[offset..], pattern)
    }

    /// Check if pattern matches at position.
    fn pattern_matches(&self, data: &[u8], pattern: &[Option<u8>]) -> bool {
        if data.len() < pattern.len() {
            return false;
        }

        for (i, &expected) in pattern.iter().enumerate() {
            if let Some(byte) = expected {
                if data[i] != byte {
                    return false;
                }
            }
            // None = wildcard, always matches
        }
        true
    }

    /// Check for generic packing indicators.
    fn check_generic_packing(&self, pe_info: &PeInfo) -> Option<PackerInfo> {
        let mut indicators = Vec::new();
        let mut score = 0u8;

        // Very few imports
        if pe_info.imports.len() < 5 && !pe_info.is_dll {
            indicators.push("Very few imports");
            score += 10;
        }

        // Only imports from kernel32
        let dlls: std::collections::HashSet<&str> = pe_info
            .imports
            .iter()
            .map(|i| i.dll.to_lowercase())
            .map(|s| {
                if s.contains("kernel32") {
                    "kernel32"
                } else {
                    "other"
                }
            })
            .collect();
        if dlls.len() == 1 && dlls.contains("kernel32") {
            indicators.push("Only kernel32 imports");
            score += 10;
        }

        // LoadLibrary + GetProcAddress only (dynamic resolution)
        let has_loadlib = pe_info
            .imports
            .iter()
            .any(|i| i.function.to_lowercase().contains("loadlibrary"));
        let has_getproc = pe_info
            .imports
            .iter()
            .any(|i| i.function.to_lowercase().contains("getprocaddress"));
        if has_loadlib && has_getproc && pe_info.imports.len() < 10 {
            indicators.push("Dynamic import resolution pattern");
            score += 15;
        }

        // Entry point in unusual section
        let mut entry_section_name = String::new();
        for section in &pe_info.sections {
            let section_end = section.virtual_address + section.virtual_size;
            if pe_info.entry_point >= section.virtual_address && pe_info.entry_point < section_end {
                entry_section_name = section.name.clone();
                break;
            }
        }
        if !entry_section_name.is_empty()
            && !entry_section_name.starts_with(".text")
            && !entry_section_name.starts_with("CODE")
        {
            indicators.push("Entry point in non-.text section");
            score += 10;
        }

        // High entropy in executable section
        for section in &pe_info.sections {
            if section.is_executable && section.entropy > 7.0 {
                indicators.push("High entropy executable section");
                score += 15;
                break;
            }
        }

        if score >= 20 {
            Some(PackerInfo {
                name: "Unknown Packer".to_string(),
                version: None,
                detection_method: indicators.join(", "),
                suspicion_score: score.min(50),
                malware_associated: true,
            })
        } else {
            None
        }
    }

    /// Check if a packer is commonly associated with malware.
    pub fn is_malware_packer(name: &str) -> bool {
        let known_malware_packers = [
            "themida",
            "vmprotect",
            "aspack",
            "obsidium",
            "enigma",
            "armadillo",
            "pecompact",
            "fsg",
            "nspack",
            "mpress",
            "confuserex",
        ];

        let lower = name.to_lowercase();
        known_malware_packers.iter().any(|p| lower.contains(p))
    }

    /// Check if a packer is considered legitimate.
    pub fn is_legitimate_packer(name: &str) -> bool {
        let legitimate_packers = ["upx"];

        let lower = name.to_lowercase();
        legitimate_packers.iter().any(|p| lower.contains(p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::heuristic::pe::SectionInfo;

    fn create_test_pe(sections: Vec<(&str, f64)>) -> PeInfo {
        PeInfo {
            is_64bit: false,
            is_dll: false,
            image_base: 0x400000,
            entry_point: 0x1000,
            num_sections: sections.len(),
            sections: sections
                .into_iter()
                .enumerate()
                .map(|(i, (name, entropy))| SectionInfo {
                    name: name.to_string(),
                    virtual_address: 0x1000 * (i + 1) as u32,
                    virtual_size: 0x1000,
                    raw_size: 0x1000,
                    raw_offset: 0x200 + 0x1000 * i as u32,
                    characteristics: 0x60000000,
                    is_executable: true,
                    is_writable: false,
                    is_readable: true,
                    entropy,
                })
                .collect(),
            imports: vec![],
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
    fn test_upx_section_detection() {
        let detector = PackerDetector::new();
        let pe = create_test_pe(vec![("UPX0", 0.5), ("UPX1", 7.5), (".rsrc", 3.0)]);

        let result = detector.detect(&[], &pe);
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "UPX");
    }

    #[test]
    fn test_themida_section_detection() {
        let detector = PackerDetector::new();
        let pe = create_test_pe(vec![(".text", 6.0), (".themida", 7.8)]);

        let result = detector.detect(&[], &pe);
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "Themida");
    }

    #[test]
    fn test_clean_pe() {
        let detector = PackerDetector::new();
        let pe = create_test_pe(vec![(".text", 6.0), (".data", 4.0), (".rsrc", 3.0)]);

        let result = detector.detect(&[], &pe);
        // Clean PE should not detect any packer
        assert!(result.is_none());
    }

    #[test]
    fn test_malware_packer_check() {
        assert!(PackerDetector::is_malware_packer("Themida"));
        assert!(PackerDetector::is_malware_packer("VMProtect"));
        assert!(!PackerDetector::is_malware_packer("UPX"));
    }

    #[test]
    fn test_legitimate_packer_check() {
        assert!(PackerDetector::is_legitimate_packer("UPX"));
        assert!(!PackerDetector::is_legitimate_packer("Themida"));
    }
}
