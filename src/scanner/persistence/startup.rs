//! Startup folder scanner for persistence detection.
//!
//! Scans Windows startup folders:
//! - User startup folder (shell:startup)
//! - Common startup folder (shell:common startup)

use super::{PersistenceEntry, PersistenceType};
use crate::core::error::Result;
use std::fs;
use std::path::{Path, PathBuf};

/// Startup entry found in startup folders.
#[derive(Debug, Clone)]
pub struct StartupEntry {
    /// Name of the startup item
    pub name: String,
    /// Full path to the startup item
    pub path: PathBuf,
    /// Target path (for shortcuts)
    pub target: Option<PathBuf>,
    /// Arguments (for shortcuts)
    pub arguments: Option<String>,
    /// Whether it's a shortcut (.lnk)
    pub is_shortcut: bool,
    /// Whether the target exists
    pub target_exists: bool,
    /// File extension
    pub extension: String,
}

impl StartupEntry {
    /// Create a new startup entry from a path.
    pub fn from_path(path: &Path) -> Self {
        let name = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();

        let extension = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        let is_shortcut = extension == "lnk";

        Self {
            name,
            path: path.to_path_buf(),
            target: None,
            arguments: None,
            is_shortcut,
            target_exists: path.exists(),
            extension,
        }
    }

    /// Set the target for a shortcut.
    pub fn with_target(mut self, target: PathBuf, arguments: Option<String>) -> Self {
        self.target_exists = target.exists();
        self.target = Some(target);
        self.arguments = arguments;
        self
    }
}

/// Startup folder scanner.
pub struct StartupScanner {
    /// User startup folder path
    user_startup: Option<PathBuf>,
    /// Common (all users) startup folder path
    common_startup: Option<PathBuf>,
    /// Suspicious file extensions
    suspicious_extensions: Vec<String>,
    /// Known legitimate startup items
    known_items: Vec<String>,
}

impl Default for StartupScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl StartupScanner {
    /// Create a new startup scanner.
    pub fn new() -> Self {
        let user_startup = Self::get_user_startup_folder();
        let common_startup = Self::get_common_startup_folder();

        Self {
            user_startup,
            common_startup,
            suspicious_extensions: vec![
                "bat".to_string(),
                "cmd".to_string(),
                "vbs".to_string(),
                "vbe".to_string(),
                "js".to_string(),
                "jse".to_string(),
                "wsf".to_string(),
                "wsh".to_string(),
                "ps1".to_string(),
                "hta".to_string(),
                "scr".to_string(),
                "pif".to_string(),
                "com".to_string(),
            ],
            known_items: vec![
                "desktop.ini".to_string(),
                "Send to OneNote".to_string(),
                "Zoom".to_string(),
                "Spotify".to_string(),
                "Discord".to_string(),
            ],
        }
    }

    /// Get user startup folder path.
    fn get_user_startup_folder() -> Option<PathBuf> {
        #[cfg(target_os = "windows")]
        {
            // Try to get from environment
            if let Ok(appdata) = std::env::var("APPDATA") {
                let startup = PathBuf::from(&appdata)
                    .join("Microsoft")
                    .join("Windows")
                    .join("Start Menu")
                    .join("Programs")
                    .join("Startup");
                if startup.exists() {
                    return Some(startup);
                }
            }

            // Fallback to known path pattern
            if let Ok(userprofile) = std::env::var("USERPROFILE") {
                let startup = PathBuf::from(&userprofile)
                    .join("AppData")
                    .join("Roaming")
                    .join("Microsoft")
                    .join("Windows")
                    .join("Start Menu")
                    .join("Programs")
                    .join("Startup");
                if startup.exists() {
                    return Some(startup);
                }
            }

            None
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Return a test path for non-Windows systems
            None
        }
    }

    /// Get common (all users) startup folder path.
    fn get_common_startup_folder() -> Option<PathBuf> {
        #[cfg(target_os = "windows")]
        {
            // Try ProgramData
            if let Ok(programdata) = std::env::var("ProgramData") {
                let startup = PathBuf::from(&programdata)
                    .join("Microsoft")
                    .join("Windows")
                    .join("Start Menu")
                    .join("Programs")
                    .join("StartUp");
                if startup.exists() {
                    return Some(startup);
                }
            }

            // Fallback path
            let startup = PathBuf::from(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp");
            if startup.exists() {
                return Some(startup);
            }

            None
        }

        #[cfg(not(target_os = "windows"))]
        {
            None
        }
    }

    /// Scan all startup folders.
    pub fn scan_all(&self) -> Result<Vec<PersistenceEntry>> {
        let mut entries = Vec::new();

        if let Some(ref user_startup) = self.user_startup {
            entries.extend(self.scan_folder(user_startup, "User Startup")?);
        }

        if let Some(ref common_startup) = self.common_startup {
            entries.extend(self.scan_folder(common_startup, "Common Startup")?);
        }

        Ok(entries)
    }

    /// Scan a specific startup folder.
    pub fn scan_folder(&self, folder: &Path, location_name: &str) -> Result<Vec<PersistenceEntry>> {
        let mut entries = Vec::new();

        if !folder.exists() {
            return Ok(entries);
        }

        let dir_entries = fs::read_dir(folder).map_err(|e| {
            crate::core::error::Error::FileRead {
                path: folder.to_path_buf(),
                source: e,
            }
        })?;

        for entry in dir_entries.filter_map(|e| e.ok()) {
            let path = entry.path();

            // Skip directories
            if path.is_dir() {
                continue;
            }

            let startup_entry = self.analyze_startup_item(&path);
            let persistence_entry = self.to_persistence_entry(&startup_entry, location_name);

            entries.push(persistence_entry);
        }

        Ok(entries)
    }

    /// Analyze a startup item.
    fn analyze_startup_item(&self, path: &Path) -> StartupEntry {
        let mut entry = StartupEntry::from_path(path);

        // For shortcuts, try to read the target
        if entry.is_shortcut {
            if let Some((target, args)) = self.read_shortcut_target(path) {
                entry = entry.with_target(target, args);
            }
        }

        entry
    }

    /// Read the target of a shortcut file.
    #[cfg(target_os = "windows")]
    fn read_shortcut_target(&self, _path: &Path) -> Option<(PathBuf, Option<String>)> {
        // On Windows, we would use COM to read .lnk files
        // For now, return None and mark shortcuts for manual review
        // Full implementation would use windows-rs or winapi
        None
    }

    #[cfg(not(target_os = "windows"))]
    fn read_shortcut_target(&self, _path: &Path) -> Option<(PathBuf, Option<String>)> {
        None
    }

    /// Convert a startup entry to a persistence entry.
    fn to_persistence_entry(&self, entry: &StartupEntry, location: &str) -> PersistenceEntry {
        let mut persistence = PersistenceEntry::new(
            PersistenceType::StartupFolder,
            &entry.name,
            format!("{}: {}", location, entry.path.display()),
        )
        .with_path(&entry.path);

        if let Some(ref args) = entry.arguments {
            persistence = persistence.with_arguments(args);
        }

        // Determine suspicion level
        let suspicious_score = self.calculate_suspicion(&entry);

        if suspicious_score > 0 {
            let reason = self.get_suspicion_reason(entry);
            persistence = persistence.mark_suspicious(reason, suspicious_score);
        }

        persistence
    }

    /// Calculate suspicion score for a startup entry.
    fn calculate_suspicion(&self, entry: &StartupEntry) -> u8 {
        let mut score = 0u8;

        // Check file extension
        if self.suspicious_extensions.contains(&entry.extension) {
            score = score.saturating_add(40);
        }

        // Check if it's a known item
        let is_known = self.known_items.iter().any(|k| {
            entry.name.to_lowercase().contains(&k.to_lowercase())
        });

        if is_known {
            return 0; // Known items are not suspicious
        }

        // Executable files that aren't shortcuts are unusual in startup
        if entry.extension == "exe" && !entry.is_shortcut {
            score = score.saturating_add(25);
        }

        // Check if shortcut target exists
        if entry.is_shortcut {
            if let Some(ref target) = entry.target {
                if !entry.target_exists {
                    score = score.saturating_add(30); // Broken shortcut
                }

                // Check target path for suspicious indicators
                let target_str = target.to_string_lossy().to_lowercase();
                if target_str.contains("temp") || target_str.contains("tmp") {
                    score = score.saturating_add(35);
                }
                if target_str.contains("powershell") || target_str.contains("cmd.exe") {
                    score = score.saturating_add(30);
                }
            }
        }

        // Hidden files are suspicious
        #[cfg(target_os = "windows")]
        {
            if let Ok(metadata) = fs::metadata(&entry.path) {
                use std::os::windows::fs::MetadataExt;
                let attrs = metadata.file_attributes();
                if attrs & 0x2 != 0 {
                    // FILE_ATTRIBUTE_HIDDEN
                    score = score.saturating_add(20);
                }
            }
        }

        score.min(100)
    }

    /// Get the reason for suspicion.
    fn get_suspicion_reason(&self, entry: &StartupEntry) -> String {
        let mut reasons = Vec::new();

        if self.suspicious_extensions.contains(&entry.extension) {
            reasons.push(format!("Suspicious extension: .{}", entry.extension));
        }

        if entry.extension == "exe" && !entry.is_shortcut {
            reasons.push("Direct executable in startup folder".to_string());
        }

        if entry.is_shortcut && !entry.target_exists {
            reasons.push("Shortcut target does not exist".to_string());
        }

        if let Some(ref target) = entry.target {
            let target_str = target.to_string_lossy().to_lowercase();
            if target_str.contains("temp") || target_str.contains("tmp") {
                reasons.push("Target in temp directory".to_string());
            }
        }

        if reasons.is_empty() {
            "Unknown startup item".to_string()
        } else {
            reasons.join("; ")
        }
    }

    /// Get list of all startup items without suspicion analysis.
    pub fn list_all(&self) -> Result<Vec<StartupEntry>> {
        let mut entries = Vec::new();

        if let Some(ref user_startup) = self.user_startup {
            if user_startup.exists() {
                if let Ok(dir) = fs::read_dir(user_startup) {
                    for entry in dir.filter_map(|e| e.ok()) {
                        let path = entry.path();
                        if path.is_file() {
                            entries.push(self.analyze_startup_item(&path));
                        }
                    }
                }
            }
        }

        if let Some(ref common_startup) = self.common_startup {
            if common_startup.exists() {
                if let Ok(dir) = fs::read_dir(common_startup) {
                    for entry in dir.filter_map(|e| e.ok()) {
                        let path = entry.path();
                        if path.is_file() {
                            entries.push(self.analyze_startup_item(&path));
                        }
                    }
                }
            }
        }

        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::TempDir;

    #[test]
    fn test_startup_entry_from_path() {
        // Use forward slashes for cross-platform compatibility
        let entry = StartupEntry::from_path(Path::new("/Startup/test.lnk"));
        assert_eq!(entry.name, "test");
        assert_eq!(entry.extension, "lnk");
        assert!(entry.is_shortcut);
    }

    #[test]
    fn test_startup_entry_extension() {
        let entry = StartupEntry::from_path(Path::new("/Startup/script.vbs"));
        assert_eq!(entry.extension, "vbs");
        assert!(!entry.is_shortcut);
    }

    #[test]
    fn test_startup_scanner_creation() {
        let scanner = StartupScanner::new();
        assert!(!scanner.suspicious_extensions.is_empty());
        assert!(scanner.suspicious_extensions.contains(&"bat".to_string()));
        assert!(scanner.suspicious_extensions.contains(&"vbs".to_string()));
    }

    #[test]
    fn test_calculate_suspicion_normal() {
        let scanner = StartupScanner::new();
        let entry = StartupEntry::from_path(Path::new("/Startup/Zoom.lnk"));
        let score = scanner.calculate_suspicion(&entry);
        assert_eq!(score, 0); // Known item
    }

    #[test]
    fn test_calculate_suspicion_script() {
        let scanner = StartupScanner::new();
        let entry = StartupEntry::from_path(Path::new("/Startup/malware.vbs"));
        let score = scanner.calculate_suspicion(&entry);
        assert!(score >= 40); // Suspicious extension
    }

    #[test]
    fn test_scan_folder() {
        let scanner = StartupScanner::new();
        let temp_dir = TempDir::new().unwrap();

        // Create test files
        File::create(temp_dir.path().join("test.lnk")).unwrap();
        File::create(temp_dir.path().join("script.bat")).unwrap();

        let entries = scanner.scan_folder(temp_dir.path(), "Test Startup").unwrap();

        assert_eq!(entries.len(), 2);

        // The .bat file should be suspicious
        let bat_entry = entries.iter().find(|e| e.name == "script").unwrap();
        assert!(bat_entry.suspicious);
    }

    #[test]
    fn test_scan_nonexistent_folder() {
        let scanner = StartupScanner::new();
        let entries = scanner
            .scan_folder(Path::new("/NonExistent/Path"), "Test")
            .unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_to_persistence_entry() {
        let scanner = StartupScanner::new();
        let startup_entry = StartupEntry::from_path(Path::new("/Startup/malware.ps1"));
        let persistence = scanner.to_persistence_entry(&startup_entry, "Test");

        assert_eq!(persistence.persistence_type, PersistenceType::StartupFolder);
        assert!(persistence.suspicious);
    }
}
