//! PE (Portable Executable) file parser and analyzer.

use super::entropy::EntropyAnalyzer;
use goblin::pe::PE;

/// Check if data starts with PE magic bytes.
pub fn is_pe(data: &[u8]) -> bool {
    if data.len() < 64 {
        return false;
    }
    // Check for MZ header
    if data[0] != 0x4D || data[1] != 0x5A {
        return false;
    }
    // Get PE header offset from DOS header
    if data.len() < 64 {
        return false;
    }
    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if pe_offset + 4 > data.len() {
        return false;
    }
    // Check for PE signature
    data[pe_offset] == 0x50
        && data[pe_offset + 1] == 0x45
        && data[pe_offset + 2] == 0x00
        && data[pe_offset + 3] == 0x00
}

/// PE file information extracted during analysis.
#[derive(Debug, Clone)]
pub struct PeInfo {
    /// Whether this is a 64-bit PE
    pub is_64bit: bool,
    /// Whether this is a DLL
    pub is_dll: bool,
    /// Image base address
    pub image_base: u64,
    /// Entry point RVA
    pub entry_point: u32,
    /// Number of sections
    pub num_sections: usize,
    /// Section information
    pub sections: Vec<SectionInfo>,
    /// Imported DLLs and functions
    pub imports: Vec<ImportEntry>,
    /// Exported functions
    pub exports: Vec<String>,
    /// Timestamp from PE header
    pub timestamp: u32,
    /// Subsystem type
    pub subsystem: u16,
    /// PE characteristics flags
    pub characteristics: u16,
    /// DLL characteristics flags
    pub dll_characteristics: u16,
    /// Whether ASLR is enabled
    pub has_aslr: bool,
    /// Whether DEP/NX is enabled
    pub has_dep: bool,
    /// Whether SEH is used
    pub has_seh: bool,
    /// Whether CFG is enabled
    pub has_cfg: bool,
    /// Size of headers
    pub header_size: u32,
    /// File alignment
    pub file_alignment: u32,
    /// Section alignment
    pub section_alignment: u32,
    /// Debug info present
    pub has_debug_info: bool,
    /// TLS callbacks present
    pub has_tls: bool,
    /// Resources present
    pub has_resources: bool,
    /// Digital signature present
    pub has_signature: bool,
}

/// Information about a PE section.
#[derive(Debug, Clone)]
pub struct SectionInfo {
    /// Section name
    pub name: String,
    /// Virtual address
    pub virtual_address: u32,
    /// Virtual size
    pub virtual_size: u32,
    /// Raw data size
    pub raw_size: u32,
    /// Raw data offset
    pub raw_offset: u32,
    /// Section characteristics
    pub characteristics: u32,
    /// Whether section is executable
    pub is_executable: bool,
    /// Whether section is writable
    pub is_writable: bool,
    /// Whether section is readable
    pub is_readable: bool,
    /// Entropy of section data
    pub entropy: f64,
}

/// Import entry (DLL and function).
#[derive(Debug, Clone)]
pub struct ImportEntry {
    /// DLL name
    pub dll: String,
    /// Function name (or ordinal as string)
    pub function: String,
}

/// PE anomaly detection result.
#[derive(Debug, Clone)]
pub struct PeAnomaly {
    /// Description of the anomaly
    pub description: String,
    /// Severity score (0-100)
    pub severity: u8,
}

impl PeAnomaly {
    pub fn new(description: impl Into<String>, severity: u8) -> Self {
        Self {
            description: description.into(),
            severity,
        }
    }

    pub fn score(&self) -> u8 {
        self.severity
    }
}

impl std::fmt::Display for PeAnomaly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description)
    }
}

/// PE file analyzer.
pub struct PeAnalyzer {
    entropy_analyzer: EntropyAnalyzer,
}

impl Default for PeAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl PeAnalyzer {
    /// Create a new PE analyzer.
    pub fn new() -> Self {
        Self {
            entropy_analyzer: EntropyAnalyzer::new(),
        }
    }

    /// Analyze PE file data and extract information.
    pub fn analyze(&self, data: &[u8]) -> Result<PeInfo, String> {
        let pe = PE::parse(data).map_err(|e| format!("Failed to parse PE: {}", e))?;

        let is_64bit = pe.is_64;
        let is_dll = pe.is_lib;

        let header = &pe.header;
        let optional_header = header
            .optional_header
            .ok_or_else(|| "Missing optional header".to_string())?;

        let standard_fields = optional_header.standard_fields;
        let windows_fields = optional_header.windows_fields;

        // Extract DLL characteristics for security features
        let dll_characteristics = windows_fields.dll_characteristics;
        let has_aslr = dll_characteristics & 0x0040 != 0; // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        let has_dep = dll_characteristics & 0x0100 != 0; // IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        let has_seh = dll_characteristics & 0x0400 == 0; // IMAGE_DLLCHARACTERISTICS_NO_SEH (inverted)
        let has_cfg = dll_characteristics & 0x4000 != 0; // IMAGE_DLLCHARACTERISTICS_GUARD_CF

        // Extract sections
        let mut sections = Vec::new();
        for section in &pe.sections {
            let name = String::from_utf8_lossy(&section.name)
                .trim_end_matches('\0')
                .to_string();

            let char = section.characteristics;
            let is_executable = char & 0x20000000 != 0; // IMAGE_SCN_MEM_EXECUTE
            let is_writable = char & 0x80000000 != 0; // IMAGE_SCN_MEM_WRITE
            let is_readable = char & 0x40000000 != 0; // IMAGE_SCN_MEM_READ

            // Calculate section entropy
            let section_start = section.pointer_to_raw_data as usize;
            let section_size = section.size_of_raw_data as usize;
            let entropy = if section_start + section_size <= data.len() && section_size > 0 {
                self.entropy_analyzer
                    .calculate(&data[section_start..section_start + section_size])
            } else {
                0.0
            };

            sections.push(SectionInfo {
                name,
                virtual_address: section.virtual_address,
                virtual_size: section.virtual_size,
                raw_size: section.size_of_raw_data,
                raw_offset: section.pointer_to_raw_data,
                characteristics: char,
                is_executable,
                is_writable,
                is_readable,
                entropy,
            });
        }

        // Extract imports
        let mut imports = Vec::new();
        for import in pe.imports {
            imports.push(ImportEntry {
                dll: import.dll.to_string(),
                function: import.name.to_string(),
            });
        }

        // Extract exports
        let exports: Vec<String> = pe
            .exports
            .iter()
            .filter_map(|e| e.name.map(|n| n.to_string()))
            .collect();

        // Check for various data directories
        let data_dirs = &optional_header.data_directories;
        let has_debug_info = data_dirs.get_debug_table().is_some();
        let has_tls = data_dirs.get_tls_table().is_some();
        let has_resources = data_dirs.get_resource_table().is_some();
        let has_signature = data_dirs.get_certificate_table().is_some();

        Ok(PeInfo {
            is_64bit,
            is_dll,
            image_base: windows_fields.image_base,
            entry_point: standard_fields.address_of_entry_point as u32,
            num_sections: sections.len(),
            sections,
            imports,
            exports,
            timestamp: header.coff_header.time_date_stamp,
            subsystem: windows_fields.subsystem,
            characteristics: header.coff_header.characteristics,
            dll_characteristics,
            has_aslr,
            has_dep,
            has_seh,
            has_cfg,
            header_size: windows_fields.size_of_headers,
            file_alignment: windows_fields.file_alignment,
            section_alignment: windows_fields.section_alignment,
            has_debug_info,
            has_tls,
            has_resources,
            has_signature,
        })
    }

    /// Check for PE header anomalies that might indicate malware.
    pub fn check_anomalies(&self, pe: &PeInfo) -> Vec<PeAnomaly> {
        let mut anomalies = Vec::new();

        // Check for suspicious timestamps
        if pe.timestamp == 0 {
            anomalies.push(PeAnomaly::new("PE timestamp is zero (might be wiped)", 5));
        } else if pe.timestamp > 0xFFFFFF00 {
            anomalies.push(PeAnomaly::new("PE timestamp appears invalid", 10));
        }

        // Check for missing security features
        if !pe.has_aslr {
            anomalies.push(PeAnomaly::new("ASLR not enabled", 5));
        }
        if !pe.has_dep {
            anomalies.push(PeAnomaly::new("DEP/NX not enabled", 5));
        }

        // Check for executable and writable sections (RWX)
        for section in &pe.sections {
            if section.is_executable && section.is_writable {
                anomalies.push(PeAnomaly::new(
                    format!("Section '{}' is both executable and writable (RWX)", section.name),
                    20,
                ));
            }
        }

        // Check for unusual section names
        for section in &pe.sections {
            let name = section.name.to_lowercase();
            if name.contains("upx") || name.contains("aspack") || name.contains("themida") {
                anomalies.push(PeAnomaly::new(
                    format!("Suspicious section name: {}", section.name),
                    15,
                ));
            }
            // Empty or unusual names
            if section.name.is_empty() || section.name.starts_with('.') && section.name.len() == 1 {
                anomalies.push(PeAnomaly::new(
                    format!("Unusual section name: '{}'", section.name),
                    5,
                ));
            }
        }

        // Check for section size mismatches
        for section in &pe.sections {
            if section.virtual_size > 0 && section.raw_size > 0 {
                let ratio = section.raw_size as f64 / section.virtual_size as f64;
                if ratio > 5.0 {
                    anomalies.push(PeAnomaly::new(
                        format!(
                            "Section '{}' raw size much larger than virtual size",
                            section.name
                        ),
                        10,
                    ));
                }
            }
            // Zero-sized raw data with executable permissions
            if section.raw_size == 0 && section.is_executable && section.virtual_size > 0 {
                anomalies.push(PeAnomaly::new(
                    format!(
                        "Section '{}' has zero raw size but is executable",
                        section.name
                    ),
                    10,
                ));
            }
        }

        // Check for TLS callbacks (often used for anti-debugging)
        if pe.has_tls {
            anomalies.push(PeAnomaly::new("TLS callbacks present (potential anti-debug)", 10));
        }

        // Entry point in unusual location
        if pe.entry_point == 0 && !pe.is_dll {
            anomalies.push(PeAnomaly::new("Entry point is zero", 15));
        }

        // Check if entry point is outside normal sections
        let mut entry_in_section = false;
        for section in &pe.sections {
            let section_end = section.virtual_address + section.virtual_size;
            if pe.entry_point >= section.virtual_address && pe.entry_point < section_end {
                entry_in_section = true;
                // Entry point in non-executable section
                if !section.is_executable {
                    anomalies.push(PeAnomaly::new(
                        format!(
                            "Entry point in non-executable section: {}",
                            section.name
                        ),
                        25,
                    ));
                }
                // Entry point in last section (common for packed files)
                if section.name != ".text" && pe.sections.last().map(|s| &s.name) == Some(&section.name) {
                    anomalies.push(PeAnomaly::new(
                        format!("Entry point in last section: {}", section.name),
                        10,
                    ));
                }
                break;
            }
        }
        if !entry_in_section && pe.entry_point != 0 {
            anomalies.push(PeAnomaly::new("Entry point outside any section", 20));
        }

        // Too few sections might indicate packing
        if pe.num_sections < 2 && !pe.is_dll {
            anomalies.push(PeAnomaly::new("Very few sections (possible packing)", 10));
        }

        // Check for no imports (suspicious for executables)
        if pe.imports.is_empty() && !pe.is_dll {
            anomalies.push(PeAnomaly::new("No imports (possible packing or shellcode)", 15));
        }

        anomalies
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_pe() {
        // Valid PE header start (MZ)
        let mut data = vec![0u8; 256];
        data[0] = 0x4D; // M
        data[1] = 0x5A; // Z
        // PE offset at 60-63
        data[60] = 0x80; // PE header at offset 128
        data[128] = 0x50; // P
        data[129] = 0x45; // E
        data[130] = 0x00;
        data[131] = 0x00;

        assert!(is_pe(&data));

        // Not a PE file
        assert!(!is_pe(b"Not a PE file"));
    }

    #[test]
    fn test_pe_analyzer_creation() {
        let analyzer = PeAnalyzer::new();
        // Just verify it creates successfully
        assert!(analyzer.entropy_analyzer.calculate(b"test") > 0.0);
    }

    #[test]
    fn test_anomaly_detection() {
        let pe_info = PeInfo {
            is_64bit: false,
            is_dll: false,
            image_base: 0x400000,
            entry_point: 0,
            num_sections: 1,
            sections: vec![SectionInfo {
                name: ".text".to_string(),
                virtual_address: 0x1000,
                virtual_size: 0x1000,
                raw_size: 0x1000,
                raw_offset: 0x200,
                characteristics: 0xE0000000, // RWX
                is_executable: true,
                is_writable: true,
                is_readable: true,
                entropy: 7.5,
            }],
            imports: vec![],
            exports: vec![],
            timestamp: 0,
            subsystem: 3,
            characteristics: 0,
            dll_characteristics: 0,
            has_aslr: false,
            has_dep: false,
            has_seh: true,
            has_cfg: false,
            header_size: 0x200,
            file_alignment: 0x200,
            section_alignment: 0x1000,
            has_debug_info: false,
            has_tls: false,
            has_resources: false,
            has_signature: false,
        };

        let analyzer = PeAnalyzer::new();
        let anomalies = analyzer.check_anomalies(&pe_info);

        // Should detect: timestamp zero, no ASLR, no DEP, RWX section, no imports, entry point zero
        assert!(!anomalies.is_empty());
        assert!(anomalies.iter().any(|a| a.description.contains("RWX")));
        assert!(anomalies.iter().any(|a| a.description.contains("ASLR")));
    }
}
