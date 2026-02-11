//! Process and memory scanning functionality.
//!
//! This module provides process enumeration and memory scanning capabilities:
//! - Process listing with metadata (PID, name, path, user)
//! - Memory region enumeration
//! - Pattern matching in process memory
//! - Suspicious process detection

pub mod enumerate;
pub mod memory;
pub mod patterns;

pub use enumerate::{ProcessEntry, ProcessEnumerator, ProcessInfo};
pub use memory::{MemoryRegion, MemoryScanner, ProtectionFlags};
pub use patterns::{MemoryPattern, PatternMatch, SuspiciousIndicator};

use crate::core::error::Result;
use std::path::PathBuf;

/// Result of scanning a process for suspicious activity.
#[derive(Debug, Clone)]
pub struct ProcessScanResult {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub name: String,
    /// Process executable path
    pub path: Option<PathBuf>,
    /// Whether the process is suspicious
    pub suspicious: bool,
    /// Suspicion score (0-100)
    pub score: u8,
    /// Detected indicators
    pub indicators: Vec<SuspiciousIndicator>,
    /// Memory pattern matches
    pub pattern_matches: Vec<PatternMatch>,
    /// Memory statistics
    pub memory_stats: MemoryStats,
}

impl ProcessScanResult {
    /// Create a new process scan result.
    pub fn new(pid: u32, name: impl Into<String>) -> Self {
        Self {
            pid,
            name: name.into(),
            path: None,
            suspicious: false,
            score: 0,
            indicators: Vec::new(),
            pattern_matches: Vec::new(),
            memory_stats: MemoryStats::default(),
        }
    }

    /// Set the executable path.
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Add a suspicious indicator.
    pub fn add_indicator(&mut self, indicator: SuspiciousIndicator) {
        self.score = self.score.saturating_add(indicator.severity);
        self.suspicious = self.score > 30;
        self.indicators.push(indicator);
    }

    /// Add a pattern match.
    pub fn add_pattern_match(&mut self, match_info: PatternMatch) {
        self.pattern_matches.push(match_info);
    }

    /// Set memory statistics.
    pub fn with_memory_stats(mut self, stats: MemoryStats) -> Self {
        self.memory_stats = stats;
        self
    }
}

/// Memory usage statistics for a process.
#[derive(Debug, Clone, Default)]
pub struct MemoryStats {
    /// Total virtual memory size
    pub virtual_size: u64,
    /// Resident/working set size
    pub resident_size: u64,
    /// Number of memory regions
    pub region_count: usize,
    /// Number of executable regions
    pub executable_regions: usize,
    /// Number of RWX (read-write-execute) regions
    pub rwx_regions: usize,
    /// Total size of executable memory
    pub executable_size: u64,
}

/// Main process scanner combining enumeration and memory analysis.
pub struct ProcessScanner {
    /// Process enumerator
    enumerator: ProcessEnumerator,
    /// Memory scanner
    memory_scanner: MemoryScanner,
    /// Whether to scan memory (requires elevated privileges)
    scan_memory: bool,
    /// Minimum score threshold for suspicious processes
    threshold: u8,
}

impl Default for ProcessScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessScanner {
    /// Create a new process scanner.
    pub fn new() -> Self {
        Self {
            enumerator: ProcessEnumerator::new(),
            memory_scanner: MemoryScanner::new(),
            scan_memory: false,
            threshold: 30,
        }
    }

    /// Enable memory scanning (requires elevated privileges).
    pub fn with_memory_scan(mut self, enabled: bool) -> Self {
        self.scan_memory = enabled;
        self
    }

    /// Set the suspicion threshold.
    pub fn with_threshold(mut self, threshold: u8) -> Self {
        self.threshold = threshold;
        self
    }

    /// Scan all processes.
    pub fn scan_all(&self) -> Result<Vec<ProcessScanResult>> {
        let processes = self.enumerator.enumerate()?;
        let mut results = Vec::new();

        for process in processes {
            let result = self.scan_process(&process)?;
            results.push(result);
        }

        Ok(results)
    }

    /// Scan only suspicious processes.
    pub fn scan_suspicious(&self) -> Result<Vec<ProcessScanResult>> {
        Ok(self
            .scan_all()?
            .into_iter()
            .filter(|r| r.suspicious)
            .collect())
    }

    /// Scan a specific process by PID.
    pub fn scan_pid(&self, pid: u32) -> Result<Option<ProcessScanResult>> {
        if let Some(process) = self.enumerator.get_process(pid)? {
            Ok(Some(self.scan_process(&process)?))
        } else {
            Ok(None)
        }
    }

    /// Scan a single process.
    fn scan_process(&self, process: &ProcessInfo) -> Result<ProcessScanResult> {
        let mut result = ProcessScanResult::new(process.pid, &process.name);

        if let Some(ref path) = process.path {
            result = result.with_path(path);
        }

        // Check process-level indicators
        self.check_process_indicators(process, &mut result);

        // Scan memory if enabled
        if self.scan_memory {
            self.scan_process_memory(process, &mut result)?;
        }

        // Update suspicious flag based on threshold
        result.suspicious = result.score >= self.threshold;

        Ok(result)
    }

    /// Check process-level suspicious indicators.
    fn check_process_indicators(&self, process: &ProcessInfo, result: &mut ProcessScanResult) {
        // Check for missing executable path
        if process.path.is_none() {
            result.add_indicator(SuspiciousIndicator::new(
                "Missing executable path",
                "Process has no associated executable file",
                20,
            ));
        }

        // Check for suspicious process names
        let name_lower = process.name.to_lowercase();

        // Check for name masquerading (looks like system process but from wrong location)
        let system_names = [
            "svchost.exe",
            "csrss.exe",
            "lsass.exe",
            "services.exe",
            "smss.exe",
        ];
        if system_names.iter().any(|n| name_lower == *n) {
            if let Some(ref path) = process.path {
                let path_lower = path.to_string_lossy().to_lowercase();
                if !path_lower.contains("system32") && !path_lower.contains("syswow64") {
                    result.add_indicator(SuspiciousIndicator::new(
                        "Potential masquerading",
                        format!(
                            "System process name '{}' running from non-system location",
                            process.name
                        ),
                        60,
                    ));
                }
            }
        }

        // Check for suspicious paths
        if let Some(ref path) = process.path {
            let path_str = path.to_string_lossy().to_lowercase();

            if path_str.contains("\\temp\\") || path_str.contains("\\tmp\\") {
                result.add_indicator(SuspiciousIndicator::new(
                    "Temp directory execution",
                    "Process running from temp directory",
                    40,
                ));
            }

            if path_str.contains("\\appdata\\local\\temp") {
                result.add_indicator(SuspiciousIndicator::new(
                    "User temp execution",
                    "Process running from user temp directory",
                    35,
                ));
            }

            if path_str.contains("\\users\\public") {
                result.add_indicator(SuspiciousIndicator::new(
                    "Public folder execution",
                    "Process running from public users folder",
                    30,
                ));
            }
        }

        // Check command line for suspicious patterns
        if let Some(ref cmdline) = process.command_line {
            let cmdline_lower = cmdline.to_lowercase();

            if cmdline_lower.contains("-encodedcommand") || cmdline_lower.contains("-enc ") {
                result.add_indicator(SuspiciousIndicator::new(
                    "Encoded PowerShell",
                    "Process using encoded PowerShell command",
                    50,
                ));
            }

            if cmdline_lower.contains("-windowstyle hidden") || cmdline_lower.contains("-w hidden")
            {
                result.add_indicator(SuspiciousIndicator::new(
                    "Hidden window",
                    "Process running with hidden window",
                    30,
                ));
            }

            if cmdline_lower.contains("bypass") && cmdline_lower.contains("executionpolicy") {
                result.add_indicator(SuspiciousIndicator::new(
                    "Execution policy bypass",
                    "Process bypassing PowerShell execution policy",
                    40,
                ));
            }
        }

        // Check parent process (if available)
        if let Some(parent_pid) = process.parent_pid {
            // Explorer spawning cmd/powershell directly is normal
            // But unusual parents for system processes is suspicious
            if system_names.iter().any(|n| name_lower == *n) && parent_pid != 4 {
                // System processes should usually be spawned by System (PID 4) or smss
                result.add_indicator(SuspiciousIndicator::new(
                    "Unusual parent process",
                    format!(
                        "System process '{}' has unusual parent PID: {}",
                        process.name, parent_pid
                    ),
                    25,
                ));
            }
        }
    }

    /// Scan process memory for suspicious patterns.
    fn scan_process_memory(
        &self,
        process: &ProcessInfo,
        result: &mut ProcessScanResult,
    ) -> Result<()> {
        // Get memory regions
        let regions = self.memory_scanner.get_regions(process.pid)?;

        let mut stats = MemoryStats {
            region_count: regions.len(),
            ..Default::default()
        };

        for region in &regions {
            stats.virtual_size += region.size;

            if region.protection.execute {
                stats.executable_regions += 1;
                stats.executable_size += region.size;
            }

            if region.protection.read && region.protection.write && region.protection.execute {
                stats.rwx_regions += 1;
                result.add_indicator(SuspiciousIndicator::new(
                    "RWX memory region",
                    format!(
                        "Process has read-write-execute memory at 0x{:x}",
                        region.base_address
                    ),
                    25,
                ));
            }
        }

        // Too many RWX regions is very suspicious
        if stats.rwx_regions > 5 {
            result.add_indicator(SuspiciousIndicator::new(
                "Multiple RWX regions",
                format!("Process has {} RWX memory regions", stats.rwx_regions),
                40,
            ));
        }

        // Scan memory for patterns if we have access
        let patterns = self.memory_scanner.get_patterns();
        for region in &regions {
            if region.protection.read && region.size < 10 * 1024 * 1024 {
                // Only scan readable regions under 10MB
                if let Ok(matches) = self
                    .memory_scanner
                    .scan_region(process.pid, region, patterns)
                {
                    for m in matches {
                        result.add_pattern_match(m);
                    }
                }
            }
        }

        result.memory_stats = stats;
        Ok(())
    }

    /// Get list of all processes without scanning.
    pub fn list_processes(&self) -> Result<Vec<ProcessInfo>> {
        self.enumerator.enumerate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_scan_result_new() {
        let result = ProcessScanResult::new(1234, "test.exe");
        assert_eq!(result.pid, 1234);
        assert_eq!(result.name, "test.exe");
        assert!(!result.suspicious);
        assert_eq!(result.score, 0);
    }

    #[test]
    fn test_process_scan_result_with_path() {
        let result = ProcessScanResult::new(1234, "test.exe").with_path("/usr/bin/test");
        assert!(result.path.is_some());
    }

    #[test]
    fn test_add_indicator() {
        let mut result = ProcessScanResult::new(1234, "test.exe");
        result.add_indicator(SuspiciousIndicator::new("Test", "Test indicator", 40));

        assert_eq!(result.indicators.len(), 1);
        assert_eq!(result.score, 40);
        assert!(result.suspicious); // Score > 30
    }

    #[test]
    fn test_process_scanner_creation() {
        let scanner = ProcessScanner::new();
        assert!(!scanner.scan_memory);
        assert_eq!(scanner.threshold, 30);
    }

    #[test]
    fn test_process_scanner_with_options() {
        let scanner = ProcessScanner::new()
            .with_memory_scan(true)
            .with_threshold(50);

        assert!(scanner.scan_memory);
        assert_eq!(scanner.threshold, 50);
    }
}
