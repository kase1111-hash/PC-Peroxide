//! Memory region scanning functionality.
//!
//! Provides memory enumeration and pattern scanning for processes.

use super::patterns::{MemoryPattern, PatternMatch};
use crate::core::error::Result;

/// Memory protection flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProtectionFlags {
    /// Memory is readable
    pub read: bool,
    /// Memory is writable
    pub write: bool,
    /// Memory is executable
    pub execute: bool,
    /// Memory is copy-on-write
    pub copy_on_write: bool,
    /// Memory is guarded
    pub guard: bool,
}

impl ProtectionFlags {
    /// Create new protection flags.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create flags for readable memory.
    pub fn readable() -> Self {
        Self {
            read: true,
            ..Default::default()
        }
    }

    /// Create flags for readable and writable memory.
    pub fn read_write() -> Self {
        Self {
            read: true,
            write: true,
            ..Default::default()
        }
    }

    /// Create flags for executable memory.
    pub fn executable() -> Self {
        Self {
            read: true,
            execute: true,
            ..Default::default()
        }
    }

    /// Create flags for RWX (read-write-execute) memory.
    pub fn rwx() -> Self {
        Self {
            read: true,
            write: true,
            execute: true,
            ..Default::default()
        }
    }

    /// Check if this is RWX memory.
    pub fn is_rwx(&self) -> bool {
        self.read && self.write && self.execute
    }
}

impl std::fmt::Display for ProtectionFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut flags = String::new();
        if self.read {
            flags.push('R');
        } else {
            flags.push('-');
        }
        if self.write {
            flags.push('W');
        } else {
            flags.push('-');
        }
        if self.execute {
            flags.push('X');
        } else {
            flags.push('-');
        }
        if self.copy_on_write {
            flags.push('C');
        }
        if self.guard {
            flags.push('G');
        }
        write!(f, "{}", flags)
    }
}

/// A memory region within a process.
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// Base address of the region
    pub base_address: u64,
    /// Size of the region in bytes
    pub size: u64,
    /// Protection flags
    pub protection: ProtectionFlags,
    /// Region type (if known)
    pub region_type: MemoryRegionType,
    /// Associated module/file path
    pub mapped_file: Option<String>,
}

impl MemoryRegion {
    /// Create a new memory region.
    pub fn new(base_address: u64, size: u64) -> Self {
        Self {
            base_address,
            size,
            protection: ProtectionFlags::default(),
            region_type: MemoryRegionType::Unknown,
            mapped_file: None,
        }
    }

    /// Set protection flags.
    pub fn with_protection(mut self, protection: ProtectionFlags) -> Self {
        self.protection = protection;
        self
    }

    /// Set region type.
    pub fn with_type(mut self, region_type: MemoryRegionType) -> Self {
        self.region_type = region_type;
        self
    }

    /// Set mapped file.
    pub fn with_mapped_file(mut self, path: impl Into<String>) -> Self {
        self.mapped_file = Some(path.into());
        self
    }

    /// Get the end address of this region.
    pub fn end_address(&self) -> u64 {
        self.base_address.saturating_add(self.size)
    }
}

/// Type of memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryRegionType {
    /// Unknown/unclassified
    Unknown,
    /// Image/module (DLL, EXE)
    Image,
    /// Mapped file
    MappedFile,
    /// Private memory (heap, etc.)
    Private,
    /// Stack
    Stack,
    /// Heap
    Heap,
}

impl std::fmt::Display for MemoryRegionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "Unknown"),
            Self::Image => write!(f, "Image"),
            Self::MappedFile => write!(f, "MappedFile"),
            Self::Private => write!(f, "Private"),
            Self::Stack => write!(f, "Stack"),
            Self::Heap => write!(f, "Heap"),
        }
    }
}

/// Memory scanner for process memory analysis.
pub struct MemoryScanner {
    /// Patterns to scan for
    patterns: Vec<MemoryPattern>,
    /// Maximum region size to scan (default 10MB)
    max_scan_size: u64,
}

impl Default for MemoryScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryScanner {
    /// Create a new memory scanner with default patterns.
    pub fn new() -> Self {
        Self {
            patterns: Self::default_patterns(),
            max_scan_size: 10 * 1024 * 1024, // 10MB
        }
    }

    /// Set maximum region size to scan.
    pub fn with_max_scan_size(mut self, size: u64) -> Self {
        self.max_scan_size = size;
        self
    }

    /// Add a custom pattern.
    pub fn add_pattern(&mut self, pattern: MemoryPattern) {
        self.patterns.push(pattern);
    }

    /// Get the current patterns.
    pub fn get_patterns(&self) -> &[MemoryPattern] {
        &self.patterns
    }

    /// Default suspicious patterns to detect in memory.
    fn default_patterns() -> Vec<MemoryPattern> {
        vec![
            // Metasploit/Meterpreter shellcode markers
            MemoryPattern::new("metsrv_dll", b"metsrv.dll")
                .with_description("Meterpreter DLL marker")
                .with_severity(80),
            MemoryPattern::new("meterpreter", b"meterpreter")
                .with_description("Meterpreter string")
                .with_severity(75),

            // Cobalt Strike markers
            MemoryPattern::new("beacon_dll", b"beacon.dll")
                .with_description("Cobalt Strike Beacon marker")
                .with_severity(85),
            MemoryPattern::new("cobaltstrike", b"cobaltstrike")
                .with_description("Cobalt Strike string")
                .with_severity(80),

            // Common shellcode patterns
            MemoryPattern::new("shellcode_x64_start", &[0x48, 0x31, 0xc9, 0x48, 0x81, 0xe9])
                .with_description("x64 shellcode prologue pattern")
                .with_severity(60),
            MemoryPattern::new("shellcode_x86_start", &[0x31, 0xc9, 0x64, 0x8b, 0x41, 0x30])
                .with_description("x86 shellcode PEB access pattern")
                .with_severity(60),

            // API hashing patterns (common in shellcode)
            MemoryPattern::new("ror13_hash", &[0xc1, 0xcf, 0x0d]) // ror edi, 0xd
                .with_description("ROR13 API hashing pattern")
                .with_severity(50),

            // Mimikatz markers
            MemoryPattern::new("mimikatz", b"mimikatz")
                .with_description("Mimikatz string")
                .with_severity(90),
            MemoryPattern::new("sekurlsa", b"sekurlsa")
                .with_description("Mimikatz sekurlsa module")
                .with_severity(85),

            // Process injection markers
            MemoryPattern::new("ntdll_inject", b"NtAllocateVirtualMemory")
                .with_description("NT memory allocation API")
                .with_severity(30),
            MemoryPattern::new("kernel32_inject", b"VirtualAllocEx")
                .with_description("Remote memory allocation API")
                .with_severity(35),
            MemoryPattern::new("writeprocessmemory", b"WriteProcessMemory")
                .with_description("Process memory write API")
                .with_severity(35),

            // Reflective DLL markers
            MemoryPattern::new("reflective_loader", b"ReflectiveLoader")
                .with_description("Reflective DLL loader function")
                .with_severity(70),

            // Empire/PowerShell markers
            MemoryPattern::new("empire", b"Empire")
                .with_description("Empire framework marker")
                .with_severity(70),

            // Generic suspicious strings
            MemoryPattern::new("keylogger", b"keylog")
                .with_description("Keylogger string")
                .with_severity(60),
            MemoryPattern::new("ransomware", b".onion")
                .with_description("Tor .onion address")
                .with_severity(40),
            MemoryPattern::new("bitcoin_addr", b"bitcoin:")
                .with_description("Bitcoin URI scheme")
                .with_severity(30),
        ]
    }

    /// Get memory regions for a process.
    pub fn get_regions(&self, pid: u32) -> Result<Vec<MemoryRegion>> {
        #[cfg(target_os = "windows")]
        {
            self.get_regions_windows(pid)
        }

        #[cfg(target_os = "linux")]
        {
            self.get_regions_linux(pid)
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            let _ = pid;
            Ok(Vec::new())
        }
    }

    /// Get memory regions on Windows.
    #[cfg(target_os = "windows")]
    fn get_regions_windows(&self, pid: u32) -> Result<Vec<MemoryRegion>> {
        use std::mem;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED,
            PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
            PAGE_GUARD, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
        };
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

        let mut regions = Vec::new();

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                .map_err(|e| crate::core::error::Error::Internal(format!("Failed to open process: {}", e)))?;

            let mut address: usize = 0;
            let mut mbi: MEMORY_BASIC_INFORMATION = mem::zeroed();

            loop {
                let result = VirtualQueryEx(
                    handle,
                    Some(address as *const std::ffi::c_void),
                    &mut mbi,
                    mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );

                if result == 0 {
                    break;
                }

                // Only include committed memory
                if mbi.State == MEM_COMMIT {
                    let protection = self.parse_windows_protection(mbi.Protect.0);
                    let region_type = if mbi.Type == MEM_IMAGE {
                        MemoryRegionType::Image
                    } else if mbi.Type == MEM_MAPPED {
                        MemoryRegionType::MappedFile
                    } else {
                        MemoryRegionType::Private
                    };

                    let region = MemoryRegion::new(mbi.BaseAddress as u64, mbi.RegionSize as u64)
                        .with_protection(protection)
                        .with_type(region_type);

                    regions.push(region);
                }

                address = mbi.BaseAddress as usize + mbi.RegionSize;

                // Prevent infinite loop
                if address == 0 {
                    break;
                }
            }

            let _ = CloseHandle(handle);
        }

        Ok(regions)
    }

    /// Parse Windows memory protection flags.
    #[cfg(target_os = "windows")]
    fn parse_windows_protection(&self, protect: u32) -> ProtectionFlags {
        use windows::Win32::System::Memory::{
            PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
            PAGE_GUARD, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
        };

        let mut flags = ProtectionFlags::new();

        // Base protection
        let base_protect = protect & 0xFF;

        if base_protect == PAGE_READONLY.0 {
            flags.read = true;
        } else if base_protect == PAGE_READWRITE.0 {
            flags.read = true;
            flags.write = true;
        } else if base_protect == PAGE_WRITECOPY.0 {
            flags.read = true;
            flags.write = true;
            flags.copy_on_write = true;
        } else if base_protect == PAGE_EXECUTE.0 {
            flags.execute = true;
        } else if base_protect == PAGE_EXECUTE_READ.0 {
            flags.read = true;
            flags.execute = true;
        } else if base_protect == PAGE_EXECUTE_READWRITE.0 {
            flags.read = true;
            flags.write = true;
            flags.execute = true;
        } else if base_protect == PAGE_EXECUTE_WRITECOPY.0 {
            flags.read = true;
            flags.write = true;
            flags.execute = true;
            flags.copy_on_write = true;
        }

        // Modifiers
        if protect & PAGE_GUARD.0 != 0 {
            flags.guard = true;
        }

        flags
    }

    /// Get memory regions on Linux.
    #[cfg(target_os = "linux")]
    fn get_regions_linux(&self, pid: u32) -> Result<Vec<MemoryRegion>> {
        use std::fs;

        let mut regions = Vec::new();

        let maps_path = format!("/proc/{}/maps", pid);
        let maps_content = fs::read_to_string(&maps_path).map_err(|e| {
            crate::core::error::Error::FileRead {
                path: maps_path.into(),
                source: e,
            }
        })?;

        for line in maps_content.lines() {
            if let Some(region) = self.parse_linux_maps_line(line) {
                regions.push(region);
            }
        }

        Ok(regions)
    }

    /// Parse a line from /proc/[pid]/maps.
    #[cfg(target_os = "linux")]
    fn parse_linux_maps_line(&self, line: &str) -> Option<MemoryRegion> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            return None;
        }

        // Parse address range
        let addr_parts: Vec<&str> = parts[0].split('-').collect();
        if addr_parts.len() != 2 {
            return None;
        }

        let start = u64::from_str_radix(addr_parts[0], 16).ok()?;
        let end = u64::from_str_radix(addr_parts[1], 16).ok()?;
        let size = end - start;

        // Parse permissions
        let perms = parts.get(1).unwrap_or(&"----");
        let protection = ProtectionFlags {
            read: perms.contains('r'),
            write: perms.contains('w'),
            execute: perms.contains('x'),
            copy_on_write: perms.contains('p'), // private
            guard: false,
        };

        // Determine region type
        let region_type = if parts.len() > 5 {
            let path = parts[5..].join(" ");
            if path.contains(".so") || path.ends_with(']') {
                MemoryRegionType::Image
            } else if path.starts_with('/') {
                MemoryRegionType::MappedFile
            } else if path.contains("[stack") {
                MemoryRegionType::Stack
            } else if path.contains("[heap") {
                MemoryRegionType::Heap
            } else {
                MemoryRegionType::Private
            }
        } else {
            MemoryRegionType::Private
        };

        let mut region = MemoryRegion::new(start, size)
            .with_protection(protection)
            .with_type(region_type);

        // Set mapped file path
        if parts.len() > 5 {
            let path = parts[5..].join(" ");
            if path.starts_with('/') {
                region = region.with_mapped_file(path);
            }
        }

        Some(region)
    }

    /// Scan a memory region for patterns.
    pub fn scan_region(
        &self,
        pid: u32,
        region: &MemoryRegion,
        patterns: &[MemoryPattern],
    ) -> Result<Vec<PatternMatch>> {
        // Skip regions that are too large
        if region.size > self.max_scan_size {
            return Ok(Vec::new());
        }

        // Skip non-readable regions
        if !region.protection.read {
            return Ok(Vec::new());
        }

        // Read memory
        let data = self.read_memory(pid, region.base_address, region.size as usize)?;

        // Scan for patterns
        let mut matches = Vec::new();
        for pattern in patterns {
            for (offset, _) in data
                .windows(pattern.bytes.len())
                .enumerate()
                .filter(|(_, window)| *window == pattern.bytes.as_slice())
            {
                matches.push(PatternMatch {
                    pattern_name: pattern.name.clone(),
                    address: region.base_address + offset as u64,
                    description: pattern.description.clone(),
                    severity: pattern.severity,
                });
            }
        }

        Ok(matches)
    }

    /// Read memory from a process.
    fn read_memory(&self, pid: u32, address: u64, size: usize) -> Result<Vec<u8>> {
        #[cfg(target_os = "windows")]
        {
            self.read_memory_windows(pid, address, size)
        }

        #[cfg(target_os = "linux")]
        {
            self.read_memory_linux(pid, address, size)
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            let _ = (pid, address, size);
            Ok(Vec::new())
        }
    }

    /// Read memory on Windows.
    #[cfg(target_os = "windows")]
    fn read_memory_windows(&self, pid: u32, address: u64, size: usize) -> Result<Vec<u8>> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ};

        let mut buffer = vec![0u8; size];

        unsafe {
            let handle = OpenProcess(PROCESS_VM_READ, false, pid).map_err(|e| {
                crate::core::error::Error::Internal(format!("Failed to open process: {}", e))
            })?;

            let mut bytes_read = 0usize;
            let result = ReadProcessMemory(
                handle,
                address as *const std::ffi::c_void,
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                size,
                Some(&mut bytes_read),
            );

            let _ = CloseHandle(handle);

            if result.is_err() {
                return Err(crate::core::error::Error::Internal(
                    "Failed to read process memory".to_string(),
                ));
            }

            buffer.truncate(bytes_read);
        }

        Ok(buffer)
    }

    /// Read memory on Linux.
    #[cfg(target_os = "linux")]
    fn read_memory_linux(&self, pid: u32, address: u64, size: usize) -> Result<Vec<u8>> {
        use std::fs::File;
        use std::io::{Read, Seek, SeekFrom};

        let mem_path = format!("/proc/{}/mem", pid);
        let mut file = File::open(&mem_path).map_err(|e| crate::core::error::Error::FileRead {
            path: mem_path.into(),
            source: e,
        })?;

        file.seek(SeekFrom::Start(address)).map_err(|e| {
            crate::core::error::Error::Internal(format!("Failed to seek in process memory: {}", e))
        })?;

        let mut buffer = vec![0u8; size];
        let bytes_read = file.read(&mut buffer).unwrap_or(0);
        buffer.truncate(bytes_read);

        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protection_flags_default() {
        let flags = ProtectionFlags::default();
        assert!(!flags.read);
        assert!(!flags.write);
        assert!(!flags.execute);
    }

    #[test]
    fn test_protection_flags_readable() {
        let flags = ProtectionFlags::readable();
        assert!(flags.read);
        assert!(!flags.write);
        assert!(!flags.execute);
    }

    #[test]
    fn test_protection_flags_rwx() {
        let flags = ProtectionFlags::rwx();
        assert!(flags.read);
        assert!(flags.write);
        assert!(flags.execute);
        assert!(flags.is_rwx());
    }

    #[test]
    fn test_protection_flags_display() {
        let flags = ProtectionFlags::rwx();
        assert_eq!(format!("{}", flags), "RWX");

        let ro_flags = ProtectionFlags::readable();
        assert_eq!(format!("{}", ro_flags), "R--");
    }

    #[test]
    fn test_memory_region_new() {
        let region = MemoryRegion::new(0x1000, 4096);
        assert_eq!(region.base_address, 0x1000);
        assert_eq!(region.size, 4096);
        assert_eq!(region.end_address(), 0x2000);
    }

    #[test]
    fn test_memory_region_with_protection() {
        let region = MemoryRegion::new(0x1000, 4096).with_protection(ProtectionFlags::rwx());
        assert!(region.protection.is_rwx());
    }

    #[test]
    fn test_memory_scanner_creation() {
        let scanner = MemoryScanner::new();
        assert!(!scanner.patterns.is_empty());
        assert_eq!(scanner.max_scan_size, 10 * 1024 * 1024);
    }

    #[test]
    fn test_memory_scanner_add_pattern() {
        let mut scanner = MemoryScanner::new();
        let initial_count = scanner.patterns.len();

        scanner.add_pattern(
            MemoryPattern::new("test", b"TEST")
                .with_description("Test pattern")
                .with_severity(50),
        );

        assert_eq!(scanner.patterns.len(), initial_count + 1);
    }

    #[test]
    fn test_memory_region_type_display() {
        assert_eq!(format!("{}", MemoryRegionType::Image), "Image");
        assert_eq!(format!("{}", MemoryRegionType::Stack), "Stack");
        assert_eq!(format!("{}", MemoryRegionType::Heap), "Heap");
    }

    #[test]
    fn test_get_regions_current_process() {
        let scanner = MemoryScanner::new();
        let pid = std::process::id();

        // This may fail without proper permissions, which is OK
        if let Ok(regions) = scanner.get_regions(pid) {
            // Should have at least some regions
            assert!(!regions.is_empty());

            // Should have at least one executable region (our code)
            let has_executable = regions.iter().any(|r| r.protection.execute);
            assert!(has_executable);
        }
    }
}
