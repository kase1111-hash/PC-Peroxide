//! Windows Registry scanner for persistence mechanisms.
//!
//! Scans common autorun registry locations:
//! - HKCU/HKLM Run and RunOnce keys
//! - Services
//! - Image File Execution Options (IFEO)
//! - AppInit_DLLs
//! - Shell extensions
//! - Winlogon and LSA packages

use super::PersistenceEntry;
#[cfg(target_os = "windows")]
use super::PersistenceType;
use crate::core::error::Result;
use std::path::PathBuf;

/// Known registry paths for autorun locations.
pub const AUTORUN_PATHS: &[(&str, &str)] = &[
    // User Run keys
    (
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
        "User Run",
    ),
    (
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "User RunOnce",
    ),
    // Machine Run keys
    (
        r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
        "Machine Run",
    ),
    (
        r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "Machine RunOnce",
    ),
    // 64-bit specific on Wow64
    (
        r"HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        "Machine Run (32-bit)",
    ),
    // RunServices (legacy but still checked)
    (
        r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices",
        "Machine RunServices",
    ),
];

/// IFEO registry path.
pub const IFEO_PATH: &str =
    r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

/// AppInit_DLLs registry path.
pub const APPINIT_PATH: &str =
    r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows";

/// Winlogon registry path.
pub const WINLOGON_PATH: &str =
    r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon";

/// LSA registry path.
pub const LSA_PATH: &str = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa";

/// Shell extension paths.
pub const SHELL_PATHS: &[(&str, &str)] = &[
    (
        r"HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers",
        "Context Menu Handlers",
    ),
    (
        r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers",
        "Shell Icon Overlays",
    ),
    (
        r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
        "Approved Shell Extensions",
    ),
];

/// Services registry path.
pub const SERVICES_PATH: &str = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services";

/// Registry entry representing an autorun item.
#[derive(Debug, Clone)]
pub struct RegistryEntry {
    /// Registry key path
    pub key_path: String,
    /// Value name
    pub value_name: String,
    /// Value data
    pub value_data: String,
    /// Parsed executable path
    pub executable_path: Option<PathBuf>,
    /// Arguments
    pub arguments: Option<String>,
}

impl RegistryEntry {
    /// Create a new registry entry.
    pub fn new(key_path: impl Into<String>, value_name: impl Into<String>, value_data: impl Into<String>) -> Self {
        let data = value_data.into();
        let (executable_path, arguments) = Self::parse_command_line(&data);

        Self {
            key_path: key_path.into(),
            value_name: value_name.into(),
            value_data: data,
            executable_path,
            arguments,
        }
    }

    /// Parse a command line string into executable and arguments.
    fn parse_command_line(cmd: &str) -> (Option<PathBuf>, Option<String>) {
        let cmd = cmd.trim();
        if cmd.is_empty() {
            return (None, None);
        }

        // Handle quoted paths
        #[allow(clippy::manual_strip)]
        if cmd.starts_with('"') {
            if let Some(end_quote) = cmd[1..].find('"') {
                let path = &cmd[1..=end_quote];
                let args = cmd[end_quote + 2..].trim();
                return (
                    Some(PathBuf::from(path)),
                    if args.is_empty() { None } else { Some(args.to_string()) },
                );
            }
        }

        // Handle unquoted paths
        if let Some(space_idx) = cmd.find(' ') {
            let path = &cmd[..space_idx];
            let args = cmd[space_idx + 1..].trim();
            (
                Some(PathBuf::from(path)),
                if args.is_empty() { None } else { Some(args.to_string()) },
            )
        } else {
            (Some(PathBuf::from(cmd)), None)
        }
    }
}

/// Autorun entry from Run/RunOnce keys.
#[derive(Debug, Clone)]
pub struct AutorunEntry {
    /// Name of the autorun entry
    pub name: String,
    /// Registry location
    pub location: String,
    /// Command to execute
    pub command: String,
    /// Executable path
    pub executable: Option<PathBuf>,
    /// Whether the executable exists
    pub file_exists: bool,
    /// Whether this is a known legitimate entry
    pub is_known: bool,
}

/// Registry scanner for persistence mechanisms.
pub struct RegistryScanner {
    /// Known legitimate autorun entries
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    known_entries: Vec<String>,
    /// Suspicious keywords in paths
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    suspicious_keywords: Vec<String>,
    /// Suspicious locations (temp, appdata, etc.)
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    suspicious_locations: Vec<String>,
}

impl Default for RegistryScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistryScanner {
    /// Create a new registry scanner.
    pub fn new() -> Self {
        Self {
            known_entries: vec![
                "SecurityHealth".to_string(),
                "WindowsDefender".to_string(),
                "iTunesHelper".to_string(),
                "Spotify".to_string(),
                "Discord".to_string(),
                "Steam".to_string(),
                "OneDrive".to_string(),
                "GoogleUpdate".to_string(),
                "AdobeAAMUpdater".to_string(),
                "Dropbox".to_string(),
            ],
            suspicious_keywords: vec![
                "powershell".to_string(),
                "cmd.exe".to_string(),
                "wscript".to_string(),
                "cscript".to_string(),
                "mshta".to_string(),
                "regsvr32".to_string(),
                "rundll32".to_string(),
                "certutil".to_string(),
                "bitsadmin".to_string(),
            ],
            suspicious_locations: vec![
                r"\temp\".to_string(),
                r"\tmp\".to_string(),
                r"\appdata\local\temp".to_string(),
                r"\users\public".to_string(),
                r"\programdata\".to_string(),
                r"\downloads\".to_string(),
            ],
        }
    }

    /// Scan all registry persistence locations.
    pub fn scan_all(&self) -> Result<Vec<PersistenceEntry>> {
        let mut entries = Vec::new();

        // Scan Run/RunOnce keys
        entries.extend(self.scan_autorun_keys()?);

        // Scan IFEO
        entries.extend(self.scan_ifeo()?);

        // Scan AppInit_DLLs
        entries.extend(self.scan_appinit_dlls()?);

        // Scan Winlogon
        entries.extend(self.scan_winlogon()?);

        // Scan LSA
        entries.extend(self.scan_lsa()?);

        // Scan Services
        entries.extend(self.scan_services()?);

        Ok(entries)
    }

    /// Scan autorun registry keys.
    pub fn scan_autorun_keys(&self) -> Result<Vec<PersistenceEntry>> {
        #[cfg(target_os = "windows")]
        {
            let mut entries = Vec::new();
            use winreg::enums::*;
            use winreg::RegKey;

            for (path, description) in AUTORUN_PATHS {
                if let Some(entry) = self.scan_registry_key(path, description, PersistenceType::RegistryRun) {
                    entries.extend(entry);
                }
            }
            Ok(entries)
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Return empty on non-Windows for testing
            let _ = AUTORUN_PATHS;
            Ok(Vec::new())
        }
    }

    /// Scan Image File Execution Options for debugger hijacking.
    pub fn scan_ifeo(&self) -> Result<Vec<PersistenceEntry>> {
        #[cfg(target_os = "windows")]
        {
            let mut entries = Vec::new();
            use winreg::enums::*;
            use winreg::RegKey;

            let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
            if let Ok(ifeo) = hklm.open_subkey(r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options") {
                for key_name in ifeo.enum_keys().filter_map(|k| k.ok()) {
                    if let Ok(subkey) = ifeo.open_subkey(&key_name) {
                        // Check for Debugger value (IFEO hijacking)
                        if let Ok(debugger) = subkey.get_value::<String, _>("Debugger") {
                            let mut entry = PersistenceEntry::new(
                                PersistenceType::Ifeo,
                                &key_name,
                                format!("{}\\{}", IFEO_PATH, key_name),
                            );

                            let (exe_path, args) = RegistryEntry::parse_command_line(&debugger);
                            if let Some(ref path) = exe_path {
                                entry = entry.with_path(path);
                            }
                            if let Some(args) = args {
                                entry = entry.with_arguments(args);
                            }

                            // IFEO debugger entries are highly suspicious
                            entry = entry.mark_suspicious(
                                format!("IFEO debugger hijack for {}: {}", key_name, debugger),
                                70,
                            );
                            entries.push(entry);
                        }

                        // Check for GlobalFlag (silent process exit monitoring)
                        if let Ok(flag) = subkey.get_value::<u32, _>("GlobalFlag") {
                            if flag & 0x200 != 0 {
                                // FLG_MONITOR_SILENT_PROCESS_EXIT
                                let entry = PersistenceEntry::new(
                                    PersistenceType::Ifeo,
                                    format!("{} (GlobalFlag)", key_name),
                                    format!("{}\\{}", IFEO_PATH, key_name),
                                )
                                .mark_suspicious(
                                    "Silent process exit monitoring enabled",
                                    50,
                                );
                                entries.push(entry);
                            }
                        }
                    }
                }
            }
            Ok(entries)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Ok(Vec::new())
        }
    }

    /// Scan AppInit_DLLs for DLL injection.
    pub fn scan_appinit_dlls(&self) -> Result<Vec<PersistenceEntry>> {
        #[cfg(target_os = "windows")]
        {
            let mut entries = Vec::new();
            use winreg::enums::*;
            use winreg::RegKey;

            let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
            if let Ok(windows_key) = hklm.open_subkey(r"Software\Microsoft\Windows NT\CurrentVersion\Windows") {
                // Check if AppInit_DLLs is enabled
                let load_appinit: u32 = windows_key.get_value("LoadAppInit_DLLs").unwrap_or(0);

                if load_appinit != 0 {
                    if let Ok(appinit_dlls) = windows_key.get_value::<String, _>("AppInit_DLLs") {
                        if !appinit_dlls.is_empty() {
                            for dll in appinit_dlls.split([',', ' ', ';']) {
                                let dll = dll.trim();
                                if !dll.is_empty() {
                                    let mut entry = PersistenceEntry::new(
                                        PersistenceType::AppInitDll,
                                        dll,
                                        APPINIT_PATH,
                                    )
                                    .with_path(dll);

                                    // AppInit_DLLs is a known persistence mechanism
                                    entry = entry.mark_suspicious(
                                        format!("AppInit_DLLs persistence: {}", dll),
                                        60,
                                    );
                                    entries.push(entry);
                                }
                            }
                        }
                    }
                }
            }

            // Also check 64-bit path on Wow64
            if let Ok(windows_key) = hklm.open_subkey(r"Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows") {
                let load_appinit: u32 = windows_key.get_value("LoadAppInit_DLLs").unwrap_or(0);

                if load_appinit != 0 {
                    if let Ok(appinit_dlls) = windows_key.get_value::<String, _>("AppInit_DLLs") {
                        if !appinit_dlls.is_empty() {
                            for dll in appinit_dlls.split([',', ' ', ';']) {
                                let dll = dll.trim();
                                if !dll.is_empty() {
                                    let entry = PersistenceEntry::new(
                                        PersistenceType::AppInitDll,
                                        dll,
                                        "AppInit_DLLs (32-bit)",
                                    )
                                    .with_path(dll)
                                    .mark_suspicious(
                                        format!("AppInit_DLLs persistence (32-bit): {}", dll),
                                        60,
                                    );
                                    entries.push(entry);
                                }
                            }
                        }
                    }
                }
            }
            Ok(entries)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Ok(Vec::new())
        }
    }

    /// Scan Winlogon persistence mechanisms.
    pub fn scan_winlogon(&self) -> Result<Vec<PersistenceEntry>> {
        #[cfg(target_os = "windows")]
        {
            let mut entries = Vec::new();
            use winreg::enums::*;
            use winreg::RegKey;

            let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
            if let Ok(winlogon) = hklm.open_subkey(r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon") {
                // Check Shell (should be explorer.exe)
                if let Ok(shell) = winlogon.get_value::<String, _>("Shell") {
                    let shell_lower = shell.to_lowercase();
                    if shell_lower != "explorer.exe" && !shell_lower.ends_with("\\explorer.exe") {
                        let entry = PersistenceEntry::new(
                            PersistenceType::Winlogon,
                            "Shell",
                            WINLOGON_PATH,
                        )
                        .with_path(&shell)
                        .mark_suspicious(
                            format!("Modified Winlogon Shell: {}", shell),
                            80,
                        );
                        entries.push(entry);
                    }
                }

                // Check Userinit (should be userinit.exe)
                if let Ok(userinit) = winlogon.get_value::<String, _>("Userinit") {
                    // Userinit can have multiple entries separated by comma
                    let has_suspicious = userinit.split(',').any(|entry| {
                        let entry = entry.trim().to_lowercase();
                        !entry.is_empty() && !entry.contains("userinit.exe")
                    });

                    if has_suspicious {
                        let entry = PersistenceEntry::new(
                            PersistenceType::Winlogon,
                            "Userinit",
                            WINLOGON_PATH,
                        )
                        .mark_suspicious(
                            format!("Modified Userinit: {}", userinit),
                            75,
                        );
                        entries.push(entry);
                    }
                }

                // Check Notify packages
                if let Ok(notify) = winlogon.get_value::<String, _>("Notify") {
                    if !notify.is_empty() {
                        let entry = PersistenceEntry::new(
                            PersistenceType::Winlogon,
                            "Notify",
                            WINLOGON_PATH,
                        )
                        .mark_suspicious(
                            format!("Winlogon Notify package: {}", notify),
                            60,
                        );
                        entries.push(entry);
                    }
                }
            }
            Ok(entries)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Ok(Vec::new())
        }
    }

    /// Scan LSA persistence mechanisms.
    pub fn scan_lsa(&self) -> Result<Vec<PersistenceEntry>> {
        #[cfg(target_os = "windows")]
        {
            let mut entries = Vec::new();
            use winreg::enums::*;
            use winreg::RegKey;

            let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
            if let Ok(lsa) = hklm.open_subkey(r"SYSTEM\CurrentControlSet\Control\Lsa") {
                // Check Security Packages
                if let Ok(packages) = lsa.get_value::<Vec<String>, _>("Security Packages") {
                    let known_packages = ["kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap"];

                    for pkg in packages {
                        let pkg_lower = pkg.to_lowercase();
                        if !known_packages.contains(&pkg_lower.as_str()) && !pkg.is_empty() {
                            let entry = PersistenceEntry::new(
                                PersistenceType::LsaPackage,
                                &pkg,
                                LSA_PATH,
                            )
                            .mark_suspicious(
                                format!("Unknown LSA Security Package: {}", pkg),
                                70,
                            );
                            entries.push(entry);
                        }
                    }
                }

                // Check Authentication Packages
                if let Ok(auth_packages) = lsa.get_value::<Vec<String>, _>("Authentication Packages") {
                    let known_auth = ["msv1_0"];

                    for pkg in auth_packages {
                        let pkg_lower = pkg.to_lowercase();
                        if !known_auth.contains(&pkg_lower.as_str()) && !pkg.is_empty() {
                            let entry = PersistenceEntry::new(
                                PersistenceType::LsaPackage,
                                format!("Auth: {}", pkg),
                                LSA_PATH,
                            )
                            .mark_suspicious(
                                format!("Unknown LSA Authentication Package: {}", pkg),
                                65,
                            );
                            entries.push(entry);
                        }
                    }
                }

                // Check Notification Packages
                if let Ok(notify_packages) = lsa.get_value::<Vec<String>, _>("Notification Packages") {
                    let known_notify = ["scecli"];

                    for pkg in notify_packages {
                        let pkg_lower = pkg.to_lowercase();
                        if !known_notify.contains(&pkg_lower.as_str()) && !pkg.is_empty() {
                            let entry = PersistenceEntry::new(
                                PersistenceType::LsaPackage,
                                format!("Notify: {}", pkg),
                                LSA_PATH,
                            )
                            .mark_suspicious(
                                format!("Unknown LSA Notification Package: {}", pkg),
                                60,
                            );
                            entries.push(entry);
                        }
                    }
                }
            }
            Ok(entries)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Ok(Vec::new())
        }
    }

    /// Scan services for suspicious entries.
    pub fn scan_services(&self) -> Result<Vec<PersistenceEntry>> {
        #[cfg(target_os = "windows")]
        {
            let mut entries = Vec::new();
            use winreg::enums::*;
            use winreg::RegKey;

            let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
            if let Ok(services) = hklm.open_subkey(r"SYSTEM\CurrentControlSet\Services") {
                for service_name in services.enum_keys().filter_map(|k| k.ok()) {
                    if let Ok(service_key) = services.open_subkey(&service_name) {
                        // Get service type
                        let service_type: u32 = service_key.get_value("Type").unwrap_or(0);

                        // Only check driver and service types (not kernel drivers usually)
                        // Type 0x10 = Own process, 0x20 = Share process
                        if service_type != 0x10 && service_type != 0x20 {
                            continue;
                        }

                        // Get ImagePath
                        if let Ok(image_path) = service_key.get_value::<String, _>("ImagePath") {
                            let suspicious_score = self.check_path_suspicious(&image_path);

                            if suspicious_score > 0 {
                                let mut entry = PersistenceEntry::new(
                                    PersistenceType::Service,
                                    &service_name,
                                    format!("{}\\{}", SERVICES_PATH, service_name),
                                );

                                let (exe_path, args) = RegistryEntry::parse_command_line(&image_path);
                                if let Some(ref path) = exe_path {
                                    entry = entry.with_path(path);
                                }
                                if let Some(args) = args {
                                    entry = entry.with_arguments(args);
                                }

                                entry = entry.mark_suspicious(
                                    format!("Suspicious service path: {}", image_path),
                                    suspicious_score,
                                );
                                entries.push(entry);
                            }
                        }
                    }
                }
            }
            Ok(entries)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Ok(Vec::new())
        }
    }

    /// Check if a path is suspicious.
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    fn check_path_suspicious(&self, path: &str) -> u8 {
        let path_lower = path.to_lowercase();
        let mut score = 0u8;

        // Check for suspicious keywords
        for keyword in &self.suspicious_keywords {
            if path_lower.contains(keyword) {
                score = score.saturating_add(20);
            }
        }

        // Check for suspicious locations
        for location in &self.suspicious_locations {
            if path_lower.contains(location) {
                score = score.saturating_add(30);
            }
        }

        // Check for file extension masquerading
        if path_lower.contains(".exe.") || path_lower.contains(".dll.") {
            score = score.saturating_add(25);
        }

        // Check for very long paths (possible obfuscation)
        if path.len() > 260 {
            score = score.saturating_add(15);
        }

        // Check for non-standard characters
        if path.chars().any(|c| c as u32 > 127) {
            score = score.saturating_add(10);
        }

        score.min(100)
    }

    /// Check if an autorun entry is known/legitimate.
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    fn is_known_entry(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        self.known_entries.iter().any(|k| name_lower.contains(&k.to_lowercase()))
    }

    /// Scan a specific registry key for autorun entries.
    #[cfg(target_os = "windows")]
    fn scan_registry_key(
        &self,
        path: &str,
        description: &str,
        persistence_type: PersistenceType,
    ) -> Option<Vec<PersistenceEntry>> {
        use winreg::enums::*;
        use winreg::RegKey;

        let mut entries = Vec::new();

        // Parse the root key and subpath
        let (root, subpath) = if path.starts_with("HKEY_CURRENT_USER") {
            (RegKey::predef(HKEY_CURRENT_USER), &path[18..])
        } else if path.starts_with("HKEY_LOCAL_MACHINE") {
            (RegKey::predef(HKEY_LOCAL_MACHINE), &path[19..])
        } else if path.starts_with("HKEY_CLASSES_ROOT") {
            (RegKey::predef(HKEY_CLASSES_ROOT), &path[18..])
        } else {
            return None;
        };

        let subpath = subpath.trim_start_matches('\\');

        if let Ok(key) = root.open_subkey(subpath) {
            for (name, value) in key.enum_values().filter_map(|v| v.ok()) {
                if let Ok(data) = value.to_string() {
                    let is_known = self.is_known_entry(&name);
                    let suspicious_score = self.check_path_suspicious(&data);

                    let mut entry = PersistenceEntry::new(
                        persistence_type,
                        &name,
                        path,
                    );

                    let (exe_path, args) = RegistryEntry::parse_command_line(&data);
                    if let Some(ref p) = exe_path {
                        entry = entry.with_path(p);
                    }
                    if let Some(a) = args {
                        entry = entry.with_arguments(a);
                    }

                    if !is_known && suspicious_score > 0 {
                        entry = entry.mark_suspicious(
                            format!("{}: {} -> {}", description, name, data),
                            suspicious_score,
                        );
                    }

                    entries.push(entry);
                }
            }
        }

        if entries.is_empty() {
            None
        } else {
            Some(entries)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_entry_parse_quoted_path() {
        let entry = RegistryEntry::new(
            r"HKCU\Software\Test",
            "TestApp",
            r#""C:\Program Files\Test\app.exe" --start"#,
        );

        assert_eq!(
            entry.executable_path,
            Some(PathBuf::from(r"C:\Program Files\Test\app.exe"))
        );
        assert_eq!(entry.arguments, Some("--start".to_string()));
    }

    #[test]
    fn test_registry_entry_parse_unquoted_path() {
        let entry = RegistryEntry::new(
            r"HKCU\Software\Test",
            "TestApp",
            r"C:\Test\app.exe /silent",
        );

        assert_eq!(entry.executable_path, Some(PathBuf::from(r"C:\Test\app.exe")));
        assert_eq!(entry.arguments, Some("/silent".to_string()));
    }

    #[test]
    fn test_registry_scanner_creation() {
        let scanner = RegistryScanner::new();
        assert!(!scanner.known_entries.is_empty());
        assert!(!scanner.suspicious_keywords.is_empty());
    }

    #[test]
    fn test_check_path_suspicious() {
        let scanner = RegistryScanner::new();

        // Normal path
        assert_eq!(scanner.check_path_suspicious(r"C:\Program Files\App\app.exe"), 0);

        // Suspicious - temp folder
        assert!(scanner.check_path_suspicious(r"C:\Users\User\AppData\Local\Temp\mal.exe") > 0);

        // Suspicious - powershell
        assert!(scanner.check_path_suspicious(r"powershell.exe -enc base64") > 0);

        // Suspicious - multiple indicators
        let score = scanner.check_path_suspicious(r"C:\temp\powershell.exe -hidden");
        assert!(score >= 40); // Both temp and powershell
    }

    #[test]
    fn test_is_known_entry() {
        let scanner = RegistryScanner::new();

        assert!(scanner.is_known_entry("SecurityHealth"));
        assert!(scanner.is_known_entry("WindowsDefender")); // Match exact known entry
        assert!(!scanner.is_known_entry("RandomMalware"));
    }

    #[test]
    fn test_scan_all_non_windows() {
        let scanner = RegistryScanner::new();
        // Should return empty results on non-Windows
        let entries = scanner.scan_all().unwrap();

        #[cfg(not(target_os = "windows"))]
        assert!(entries.is_empty());
    }
}
