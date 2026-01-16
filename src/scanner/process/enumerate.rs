//! Process enumeration functionality.
//!
//! Provides cross-platform process listing with metadata.

use crate::core::error::Result;
use std::path::PathBuf;

/// Information about a running process.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub name: String,
    /// Full path to executable
    pub path: Option<PathBuf>,
    /// Command line arguments
    pub command_line: Option<String>,
    /// Parent process ID
    pub parent_pid: Option<u32>,
    /// User/owner of the process
    pub user: Option<String>,
    /// Process start time
    pub start_time: Option<u64>,
    /// Whether this is a 64-bit process
    pub is_64bit: Option<bool>,
    /// Session ID (Windows)
    pub session_id: Option<u32>,
}

impl ProcessInfo {
    /// Create a new process info entry.
    pub fn new(pid: u32, name: impl Into<String>) -> Self {
        Self {
            pid,
            name: name.into(),
            path: None,
            command_line: None,
            parent_pid: None,
            user: None,
            start_time: None,
            is_64bit: None,
            session_id: None,
        }
    }

    /// Set the executable path.
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Set the command line.
    pub fn with_command_line(mut self, cmdline: impl Into<String>) -> Self {
        self.command_line = Some(cmdline.into());
        self
    }

    /// Set the parent PID.
    pub fn with_parent_pid(mut self, ppid: u32) -> Self {
        self.parent_pid = Some(ppid);
        self
    }

    /// Set the user.
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }
}

/// A single entry from process enumeration (simplified).
#[derive(Debug, Clone)]
pub struct ProcessEntry {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub name: String,
    /// Executable path
    pub path: Option<PathBuf>,
}

impl From<ProcessInfo> for ProcessEntry {
    fn from(info: ProcessInfo) -> Self {
        Self {
            pid: info.pid,
            name: info.name,
            path: info.path,
        }
    }
}

/// Process enumerator for listing running processes.
pub struct ProcessEnumerator {
    /// Include system processes
    include_system: bool,
    /// Include processes without executable path
    include_pathless: bool,
}

impl Default for ProcessEnumerator {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessEnumerator {
    /// Create a new process enumerator.
    pub fn new() -> Self {
        Self {
            include_system: true,
            include_pathless: true,
        }
    }

    /// Configure whether to include system processes.
    pub fn with_system_processes(mut self, include: bool) -> Self {
        self.include_system = include;
        self
    }

    /// Configure whether to include processes without executable path.
    pub fn with_pathless_processes(mut self, include: bool) -> Self {
        self.include_pathless = include;
        self
    }

    /// Enumerate all running processes.
    pub fn enumerate(&self) -> Result<Vec<ProcessInfo>> {
        #[cfg(target_os = "windows")]
        {
            self.enumerate_windows()
        }

        #[cfg(target_os = "linux")]
        {
            self.enumerate_linux()
        }

        #[cfg(target_os = "macos")]
        {
            self.enumerate_macos()
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Ok(Vec::new())
        }
    }

    /// Get information about a specific process.
    pub fn get_process(&self, pid: u32) -> Result<Option<ProcessInfo>> {
        #[cfg(target_os = "windows")]
        {
            self.get_process_windows(pid)
        }

        #[cfg(target_os = "linux")]
        {
            self.get_process_linux(pid)
        }

        #[cfg(target_os = "macos")]
        {
            self.get_process_macos(pid)
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            let _ = pid;
            Ok(None)
        }
    }

    /// Enumerate processes on Windows.
    #[cfg(target_os = "windows")]
    fn enumerate_windows(&self) -> Result<Vec<ProcessInfo>> {
        use std::mem;
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        use windows::Win32::Foundation::{CloseHandle, MAX_PATH};
        use windows::core::PWSTR;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
            PROCESSENTRY32W, TH32CS_SNAPPROCESS,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW,
            PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        let mut processes = Vec::new();

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
                .map_err(|e| crate::core::error::Error::Internal(format!("Failed to create snapshot: {}", e)))?;

            let mut entry: PROCESSENTRY32W = mem::zeroed();
            entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let pid = entry.th32ProcessID;

                    // Get process name from entry
                    let name_len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                    let name = OsString::from_wide(&entry.szExeFile[..name_len])
                        .to_string_lossy()
                        .to_string();

                    // Skip System Idle Process (PID 0)
                    if pid == 0 && !self.include_system {
                        if Process32NextW(snapshot, &mut entry).is_err() {
                            break;
                        }
                        continue;
                    }

                    let mut info = ProcessInfo::new(pid, &name)
                        .with_parent_pid(entry.th32ParentProcessID);

                    // Try to get full path
                    if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                        let mut buffer = [0u16; MAX_PATH as usize];
                        let mut size = buffer.len() as u32;

                        if QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR::from_raw(buffer.as_mut_ptr()), &mut size).is_ok() {
                            let path = OsString::from_wide(&buffer[..size as usize])
                                .to_string_lossy()
                                .to_string();
                            info.path = Some(PathBuf::from(path));
                        }

                        let _ = CloseHandle(handle);
                    }

                    // Filter based on settings
                    if !self.include_pathless && info.path.is_none() {
                        if Process32NextW(snapshot, &mut entry).is_err() {
                            break;
                        }
                        continue;
                    }

                    processes.push(info);

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }

        Ok(processes)
    }

    /// Get process info on Windows.
    #[cfg(target_os = "windows")]
    fn get_process_windows(&self, pid: u32) -> Result<Option<ProcessInfo>> {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        use windows::Win32::Foundation::{CloseHandle, MAX_PATH};
        use windows::core::PWSTR;
        use windows::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW,
            PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                let mut buffer = [0u16; MAX_PATH as usize];
                let mut size = buffer.len() as u32;

                let path = if QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR::from_raw(buffer.as_mut_ptr()), &mut size).is_ok() {
                    let path_str = OsString::from_wide(&buffer[..size as usize])
                        .to_string_lossy()
                        .to_string();
                    Some(PathBuf::from(&path_str))
                } else {
                    None
                };

                let _ = CloseHandle(handle);

                // Get process name from path or use PID
                let name = path.as_ref()
                    .and_then(|p| p.file_name())
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| format!("pid_{}", pid));

                let mut info = ProcessInfo::new(pid, name);
                info.path = path;

                return Ok(Some(info));
            }
        }

        Ok(None)
    }

    /// Enumerate processes on Linux.
    #[cfg(target_os = "linux")]
    fn enumerate_linux(&self) -> Result<Vec<ProcessInfo>> {
        use std::fs;

        let mut processes = Vec::new();

        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.filter_map(|e| e.ok()) {
                let file_name = entry.file_name();
                let name_str = file_name.to_string_lossy();

                // Only process numeric directories (PIDs)
                if let Ok(pid) = name_str.parse::<u32>() {
                    if let Some(info) = self.read_proc_info(pid) {
                        if !self.include_pathless && info.path.is_none() {
                            continue;
                        }
                        processes.push(info);
                    }
                }
            }
        }

        Ok(processes)
    }

    /// Read process info from /proc on Linux.
    #[cfg(target_os = "linux")]
    fn read_proc_info(&self, pid: u32) -> Option<ProcessInfo> {
        use std::fs;
        use std::path::Path;

        let proc_dir = format!("/proc/{}", pid);

        // Check if the process directory exists
        if !Path::new(&proc_dir).exists() {
            return None;
        }

        // Read comm (process name)
        let name = fs::read_to_string(format!("{}/comm", proc_dir))
            .ok()
            .map(|s| s.trim().to_string())?; // Return None if we can't read the name

        let mut info = ProcessInfo::new(pid, name);

        // Read exe symlink (executable path)
        if let Ok(exe_path) = fs::read_link(format!("{}/exe", proc_dir)) {
            info.path = Some(exe_path);
        }

        // Read cmdline
        if let Ok(cmdline) = fs::read_to_string(format!("{}/cmdline", proc_dir)) {
            let cmdline = cmdline.replace('\0', " ").trim().to_string();
            if !cmdline.is_empty() {
                info.command_line = Some(cmdline);
            }
        }

        // Read stat for parent PID
        if let Ok(stat) = fs::read_to_string(format!("{}/stat", proc_dir)) {
            // Format: pid (comm) state ppid ...
            if let Some(ppid_str) = stat.split(')').nth(1).and_then(|s| s.split_whitespace().nth(1)) {
                if let Ok(ppid) = ppid_str.parse::<u32>() {
                    info.parent_pid = Some(ppid);
                }
            }
        }

        Some(info)
    }

    /// Get process info on Linux.
    #[cfg(target_os = "linux")]
    fn get_process_linux(&self, pid: u32) -> Result<Option<ProcessInfo>> {
        Ok(self.read_proc_info(pid))
    }

    /// Enumerate processes on macOS.
    #[cfg(target_os = "macos")]
    fn enumerate_macos(&self) -> Result<Vec<ProcessInfo>> {
        // Simplified implementation using sysctl
        // Full implementation would use libproc
        use std::process::Command;

        let mut processes = Vec::new();

        if let Ok(output) = Command::new("ps")
            .args(["-axo", "pid,ppid,comm"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) {
                // Skip header
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    if let Ok(pid) = parts[0].parse::<u32>() {
                        let ppid = parts[1].parse::<u32>().ok();
                        let name = parts[2..].join(" ");

                        let mut info = ProcessInfo::new(pid, name);
                        info.parent_pid = ppid;

                        // Try to get full path
                        if let Ok(path_output) = Command::new("ps")
                            .args(["-p", &pid.to_string(), "-o", "comm="])
                            .output()
                        {
                            let path = String::from_utf8_lossy(&path_output.stdout)
                                .trim()
                                .to_string();
                            if !path.is_empty() && path.starts_with('/') {
                                info.path = Some(PathBuf::from(path));
                            }
                        }

                        processes.push(info);
                    }
                }
            }
        }

        Ok(processes)
    }

    /// Get process info on macOS.
    #[cfg(target_os = "macos")]
    fn get_process_macos(&self, pid: u32) -> Result<Option<ProcessInfo>> {
        use std::process::Command;

        if let Ok(output) = Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "pid,ppid,comm"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(line) = stdout.lines().nth(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let ppid = parts[1].parse::<u32>().ok();
                    let name = parts[2..].join(" ");

                    let mut info = ProcessInfo::new(pid, name);
                    info.parent_pid = ppid;

                    return Ok(Some(info));
                }
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_info_new() {
        let info = ProcessInfo::new(1234, "test.exe");
        assert_eq!(info.pid, 1234);
        assert_eq!(info.name, "test.exe");
        assert!(info.path.is_none());
    }

    #[test]
    fn test_process_info_with_path() {
        let info = ProcessInfo::new(1234, "test.exe")
            .with_path("/usr/bin/test");
        assert!(info.path.is_some());
        assert_eq!(info.path.unwrap().to_str().unwrap(), "/usr/bin/test");
    }

    #[test]
    fn test_process_info_with_parent() {
        let info = ProcessInfo::new(1234, "test.exe")
            .with_parent_pid(1);
        assert_eq!(info.parent_pid, Some(1));
    }

    #[test]
    fn test_process_enumerator_creation() {
        let enumerator = ProcessEnumerator::new();
        assert!(enumerator.include_system);
        assert!(enumerator.include_pathless);
    }

    #[test]
    fn test_process_enumerator_options() {
        let enumerator = ProcessEnumerator::new()
            .with_system_processes(false)
            .with_pathless_processes(false);

        assert!(!enumerator.include_system);
        assert!(!enumerator.include_pathless);
    }

    #[test]
    fn test_enumerate_processes() {
        let enumerator = ProcessEnumerator::new();
        let processes = enumerator.enumerate().unwrap();

        // Should find at least one process (ourselves)
        assert!(!processes.is_empty());

        // Check that we found our own process
        let current_pid = std::process::id();
        let found_self = processes.iter().any(|p| p.pid == current_pid);
        assert!(found_self, "Should find current process in list");
    }

    #[test]
    fn test_get_process() {
        let enumerator = ProcessEnumerator::new();
        let current_pid = std::process::id();

        let result = enumerator.get_process(current_pid).unwrap();
        assert!(result.is_some());

        let info = result.unwrap();
        assert_eq!(info.pid, current_pid);
    }

    #[test]
    fn test_get_nonexistent_process() {
        let enumerator = ProcessEnumerator::new();
        // Use a very high PID that's unlikely to exist
        let result = enumerator.get_process(999999999).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_process_entry_from_info() {
        let info = ProcessInfo::new(1234, "test.exe")
            .with_path("/usr/bin/test");

        let entry: ProcessEntry = info.into();
        assert_eq!(entry.pid, 1234);
        assert_eq!(entry.name, "test.exe");
        assert!(entry.path.is_some());
    }
}
