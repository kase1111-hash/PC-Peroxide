//! Browser extension scanner.
//!
//! Enumerates and analyzes browser extensions for:
//! - Chrome/Chromium
//! - Microsoft Edge
//! - Mozilla Firefox
//! - Brave
//! - Opera

use crate::core::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

/// Supported browser types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BrowserType {
    /// Google Chrome
    Chrome,
    /// Microsoft Edge (Chromium-based)
    Edge,
    /// Mozilla Firefox
    Firefox,
    /// Brave Browser
    Brave,
    /// Opera Browser
    Opera,
}

impl std::fmt::Display for BrowserType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Chrome => write!(f, "Chrome"),
            Self::Edge => write!(f, "Edge"),
            Self::Firefox => write!(f, "Firefox"),
            Self::Brave => write!(f, "Brave"),
            Self::Opera => write!(f, "Opera"),
        }
    }
}

/// Risk level of an extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtensionRisk {
    /// No risk identified
    None,
    /// Low risk
    Low,
    /// Medium risk
    Medium,
    /// High risk
    High,
    /// Critical risk
    Critical,
}

impl std::fmt::Display for ExtensionRisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// Extension permission category.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionPermission {
    /// Access to all URLs
    AllUrls,
    /// Access to tabs
    Tabs,
    /// Access to cookies
    Cookies,
    /// Access to browsing history
    History,
    /// Access to downloads
    Downloads,
    /// Web request modification
    WebRequest,
    /// Web request blocking
    WebRequestBlocking,
    /// Native messaging
    NativeMessaging,
    /// Clipboard access
    ClipboardRead,
    /// Clipboard write
    ClipboardWrite,
    /// Geolocation
    Geolocation,
    /// Storage
    Storage,
    /// Management of other extensions
    Management,
    /// Privacy settings
    Privacy,
    /// Proxy settings
    Proxy,
    /// Debug access
    Debugger,
    /// Content scripts
    ContentScripts,
    /// Background scripts
    Background,
    /// Other permission
    Other(String),
}

impl ExtensionPermission {
    /// Get the risk level of a permission.
    pub fn risk_level(&self) -> ExtensionRisk {
        match self {
            Self::AllUrls => ExtensionRisk::High,
            Self::WebRequest | Self::WebRequestBlocking => ExtensionRisk::High,
            Self::NativeMessaging => ExtensionRisk::High,
            Self::Cookies => ExtensionRisk::Medium,
            Self::History => ExtensionRisk::Medium,
            Self::ClipboardRead => ExtensionRisk::Medium,
            Self::Management => ExtensionRisk::High,
            Self::Privacy => ExtensionRisk::Medium,
            Self::Proxy => ExtensionRisk::Medium,
            Self::Debugger => ExtensionRisk::Critical,
            Self::Tabs => ExtensionRisk::Low,
            Self::Downloads => ExtensionRisk::Low,
            Self::Storage => ExtensionRisk::None,
            Self::ClipboardWrite => ExtensionRisk::Low,
            Self::Geolocation => ExtensionRisk::Low,
            Self::ContentScripts => ExtensionRisk::Low,
            Self::Background => ExtensionRisk::Low,
            Self::Other(_) => ExtensionRisk::Low,
        }
    }
}

/// Browser extension information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserExtension {
    /// Extension ID
    pub id: String,
    /// Extension name
    pub name: String,
    /// Extension version
    pub version: String,
    /// Extension description
    pub description: Option<String>,
    /// Browser type
    pub browser: BrowserType,
    /// Is the extension enabled
    pub enabled: bool,
    /// Extension permissions
    pub permissions: Vec<ExtensionPermission>,
    /// Path to extension directory
    pub path: PathBuf,
    /// Risk assessment
    pub risk: ExtensionRisk,
    /// Risk reasons
    pub risk_reasons: Vec<String>,
}

/// Known suspicious extension IDs.
const SUSPICIOUS_EXTENSION_IDS: &[&str] = &[
    // Add known malicious extension IDs here
    // These would be populated from threat intelligence
];

/// Known suspicious extension names (partial match).
const SUSPICIOUS_EXTENSION_NAMES: &[&str] = &[
    "video downloader",
    "free vpn",
    "proxy",
    "ad injector",
    "coupon",
    "price tracker",
    "crypto miner",
];

/// Extension scanner.
pub struct ExtensionScanner {
    /// Known suspicious IDs
    suspicious_ids: HashSet<String>,
    /// Suspicious name patterns
    suspicious_names: Vec<String>,
}

impl ExtensionScanner {
    /// Create a new extension scanner.
    pub fn new() -> Self {
        let suspicious_ids: HashSet<String> = SUSPICIOUS_EXTENSION_IDS
            .iter()
            .map(|s| s.to_string())
            .collect();

        let suspicious_names: Vec<String> = SUSPICIOUS_EXTENSION_NAMES
            .iter()
            .map(|s| s.to_lowercase())
            .collect();

        Self {
            suspicious_ids,
            suspicious_names,
        }
    }

    /// Get extension directories for a browser.
    fn get_extension_paths(&self, browser: BrowserType) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        #[cfg(target_os = "windows")]
        {
            if let Some(local_app_data) = dirs::data_local_dir() {
                match browser {
                    BrowserType::Chrome => {
                        paths.push(local_app_data.join("Google/Chrome/User Data/Default/Extensions"));
                    }
                    BrowserType::Edge => {
                        paths.push(local_app_data.join("Microsoft/Edge/User Data/Default/Extensions"));
                    }
                    BrowserType::Firefox => {
                        if let Some(roaming) = dirs::data_dir() {
                            paths.push(roaming.join("Mozilla/Firefox/Profiles"));
                        }
                    }
                    BrowserType::Brave => {
                        paths.push(local_app_data.join("BraveSoftware/Brave-Browser/User Data/Default/Extensions"));
                    }
                    BrowserType::Opera => {
                        paths.push(local_app_data.join("Opera Software/Opera Stable/Extensions"));
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            if let Some(home) = dirs::home_dir() {
                match browser {
                    BrowserType::Chrome => {
                        paths.push(home.join(".config/google-chrome/Default/Extensions"));
                        paths.push(home.join(".config/chromium/Default/Extensions"));
                    }
                    BrowserType::Edge => {
                        paths.push(home.join(".config/microsoft-edge/Default/Extensions"));
                    }
                    BrowserType::Firefox => {
                        paths.push(home.join(".mozilla/firefox"));
                    }
                    BrowserType::Brave => {
                        paths.push(home.join(".config/BraveSoftware/Brave-Browser/Default/Extensions"));
                    }
                    BrowserType::Opera => {
                        paths.push(home.join(".config/opera/Extensions"));
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            if let Some(home) = dirs::home_dir() {
                match browser {
                    BrowserType::Chrome => {
                        paths.push(home.join("Library/Application Support/Google/Chrome/Default/Extensions"));
                    }
                    BrowserType::Edge => {
                        paths.push(home.join("Library/Application Support/Microsoft Edge/Default/Extensions"));
                    }
                    BrowserType::Firefox => {
                        paths.push(home.join("Library/Application Support/Firefox/Profiles"));
                    }
                    BrowserType::Brave => {
                        paths.push(home.join("Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions"));
                    }
                    BrowserType::Opera => {
                        paths.push(home.join("Library/Application Support/com.operasoftware.Opera/Extensions"));
                    }
                }
            }
        }

        paths.into_iter().filter(|p| p.exists()).collect()
    }

    /// Scan all browsers for extensions.
    pub fn scan_all_browsers(&self) -> Result<Vec<BrowserExtension>> {
        let mut extensions = Vec::new();

        for browser in [
            BrowserType::Chrome,
            BrowserType::Edge,
            BrowserType::Firefox,
            BrowserType::Brave,
            BrowserType::Opera,
        ] {
            if let Ok(browser_exts) = self.scan_browser(browser) {
                extensions.extend(browser_exts);
            }
        }

        Ok(extensions)
    }

    /// Scan a specific browser for extensions.
    pub fn scan_browser(&self, browser: BrowserType) -> Result<Vec<BrowserExtension>> {
        let paths = self.get_extension_paths(browser);
        let mut extensions = Vec::new();

        for path in paths {
            if browser == BrowserType::Firefox {
                extensions.extend(self.scan_firefox_extensions(&path)?);
            } else {
                extensions.extend(self.scan_chromium_extensions(&path, browser)?);
            }
        }

        Ok(extensions)
    }

    /// Scan Chromium-based browser extensions.
    fn scan_chromium_extensions(
        &self,
        extensions_dir: &PathBuf,
        browser: BrowserType,
    ) -> Result<Vec<BrowserExtension>> {
        let mut extensions = Vec::new();

        let entries = match fs::read_dir(extensions_dir) {
            Ok(e) => e,
            Err(_) => return Ok(Vec::new()),
        };

        for entry in entries.filter_map(|e| e.ok()) {
            let ext_id = entry.file_name().to_string_lossy().to_string();
            let ext_path = entry.path();

            if !ext_path.is_dir() {
                continue;
            }

            // Find the version directory
            let version_dirs: Vec<_> = fs::read_dir(&ext_path)
                .ok()
                .into_iter()
                .flatten()
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_dir())
                .collect();

            for version_dir in version_dirs {
                let manifest_path = version_dir.path().join("manifest.json");
                if let Ok(manifest) = self.parse_chromium_manifest(&manifest_path) {
                    let permissions = self.parse_chromium_permissions(&manifest);
                    let (risk, reasons) = self.assess_extension_risk(
                        &ext_id,
                        &manifest.name,
                        &permissions,
                    );

                    extensions.push(BrowserExtension {
                        id: ext_id.clone(),
                        name: manifest.name,
                        version: manifest.version,
                        description: manifest.description,
                        browser,
                        enabled: true, // Would need to check Preferences file
                        permissions,
                        path: version_dir.path(),
                        risk,
                        risk_reasons: reasons,
                    });
                }
            }
        }

        Ok(extensions)
    }

    /// Parse Chromium manifest.json.
    fn parse_chromium_manifest(&self, path: &PathBuf) -> Result<ChromiumManifest> {
        let content = fs::read_to_string(path)
            .map_err(|e| Error::file_read(path, e))?;

        serde_json::from_str(&content)
            .map_err(|e| Error::Internal(format!("Failed to parse manifest: {}", e)))
    }

    /// Parse Chromium permissions from manifest.
    fn parse_chromium_permissions(&self, manifest: &ChromiumManifest) -> Vec<ExtensionPermission> {
        let mut permissions = Vec::new();

        if let Some(perms) = &manifest.permissions {
            for perm in perms {
                let p = match perm.as_str() {
                    "<all_urls>" | "http://*/*" | "https://*/*" => ExtensionPermission::AllUrls,
                    "tabs" => ExtensionPermission::Tabs,
                    "cookies" => ExtensionPermission::Cookies,
                    "history" => ExtensionPermission::History,
                    "downloads" => ExtensionPermission::Downloads,
                    "webRequest" => ExtensionPermission::WebRequest,
                    "webRequestBlocking" => ExtensionPermission::WebRequestBlocking,
                    "nativeMessaging" => ExtensionPermission::NativeMessaging,
                    "clipboardRead" => ExtensionPermission::ClipboardRead,
                    "clipboardWrite" => ExtensionPermission::ClipboardWrite,
                    "geolocation" => ExtensionPermission::Geolocation,
                    "storage" => ExtensionPermission::Storage,
                    "management" => ExtensionPermission::Management,
                    "privacy" => ExtensionPermission::Privacy,
                    "proxy" => ExtensionPermission::Proxy,
                    "debugger" => ExtensionPermission::Debugger,
                    other => ExtensionPermission::Other(other.to_string()),
                };
                permissions.push(p);
            }
        }

        if manifest.background.is_some() {
            permissions.push(ExtensionPermission::Background);
        }

        if manifest.content_scripts.is_some() {
            permissions.push(ExtensionPermission::ContentScripts);
        }

        permissions
    }

    /// Scan Firefox extensions.
    fn scan_firefox_extensions(&self, profiles_dir: &PathBuf) -> Result<Vec<BrowserExtension>> {
        let mut extensions = Vec::new();

        let entries = match fs::read_dir(profiles_dir) {
            Ok(e) => e,
            Err(_) => return Ok(Vec::new()),
        };

        for entry in entries.filter_map(|e| e.ok()) {
            let profile_path = entry.path();
            if !profile_path.is_dir() {
                continue;
            }

            let extensions_dir = profile_path.join("extensions");
            if extensions_dir.exists() {
                if let Ok(ext_entries) = fs::read_dir(&extensions_dir) {
                    for ext_entry in ext_entries.filter_map(|e| e.ok()) {
                        let ext_path = ext_entry.path();
                        let ext_id = ext_entry.file_name().to_string_lossy().to_string();

                        // Firefox extensions can be .xpi files or directories
                        let manifest_path = if ext_path.is_dir() {
                            ext_path.join("manifest.json")
                        } else if ext_path.extension().map_or(false, |e| e == "xpi") {
                            // Would need to extract XPI to read manifest
                            continue;
                        } else {
                            continue;
                        };

                        if let Ok(manifest) = self.parse_chromium_manifest(&manifest_path) {
                            let permissions = self.parse_chromium_permissions(&manifest);
                            let (risk, reasons) =
                                self.assess_extension_risk(&ext_id, &manifest.name, &permissions);

                            extensions.push(BrowserExtension {
                                id: ext_id,
                                name: manifest.name,
                                version: manifest.version,
                                description: manifest.description,
                                browser: BrowserType::Firefox,
                                enabled: true,
                                permissions,
                                path: ext_path,
                                risk,
                                risk_reasons: reasons,
                            });
                        }
                    }
                }
            }
        }

        Ok(extensions)
    }

    /// Assess extension risk level.
    fn assess_extension_risk(
        &self,
        id: &str,
        name: &str,
        permissions: &[ExtensionPermission],
    ) -> (ExtensionRisk, Vec<String>) {
        let mut risk = ExtensionRisk::None;
        let mut reasons = Vec::new();

        // Check if ID is in suspicious list
        if self.suspicious_ids.contains(id) {
            risk = ExtensionRisk::Critical;
            reasons.push("Known malicious extension ID".to_string());
        }

        // Check name against suspicious patterns
        let name_lower = name.to_lowercase();
        for pattern in &self.suspicious_names {
            if name_lower.contains(pattern) {
                if risk < ExtensionRisk::Medium {
                    risk = ExtensionRisk::Medium;
                }
                reasons.push(format!("Suspicious name pattern: {}", pattern));
            }
        }

        // Check permissions
        let mut has_all_urls = false;
        let mut has_web_request = false;
        let mut dangerous_perms = 0;

        for perm in permissions {
            let perm_risk = perm.risk_level();
            if perm_risk > risk {
                risk = perm_risk;
            }

            match perm {
                ExtensionPermission::AllUrls => has_all_urls = true,
                ExtensionPermission::WebRequest | ExtensionPermission::WebRequestBlocking => {
                    has_web_request = true
                }
                ExtensionPermission::Debugger => {
                    reasons.push("Has debugger access (very high risk)".to_string());
                }
                ExtensionPermission::NativeMessaging => {
                    reasons.push("Can communicate with native applications".to_string());
                }
                ExtensionPermission::Management => {
                    reasons.push("Can manage other extensions".to_string());
                }
                _ => {}
            }

            if perm_risk >= ExtensionRisk::Medium {
                dangerous_perms += 1;
            }
        }

        // Combination checks
        if has_all_urls && has_web_request {
            if risk < ExtensionRisk::High {
                risk = ExtensionRisk::High;
            }
            reasons.push("Can intercept all web traffic".to_string());
        }

        if dangerous_perms >= 3 && risk < ExtensionRisk::Medium {
            risk = ExtensionRisk::Medium;
            reasons.push(format!("Has {} sensitive permissions", dangerous_perms));
        }

        (risk, reasons)
    }
}

impl Default for ExtensionScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Chromium manifest.json structure.
#[derive(Debug, Deserialize)]
struct ChromiumManifest {
    name: String,
    version: String,
    description: Option<String>,
    permissions: Option<Vec<String>>,
    #[serde(default)]
    background: Option<serde_json::Value>,
    content_scripts: Option<Vec<serde_json::Value>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_browser_type_display() {
        assert_eq!(format!("{}", BrowserType::Chrome), "Chrome");
        assert_eq!(format!("{}", BrowserType::Firefox), "Firefox");
        assert_eq!(format!("{}", BrowserType::Edge), "Edge");
    }

    #[test]
    fn test_extension_risk_display() {
        assert_eq!(format!("{}", ExtensionRisk::None), "None");
        assert_eq!(format!("{}", ExtensionRisk::Critical), "Critical");
    }

    #[test]
    fn test_permission_risk() {
        assert_eq!(
            ExtensionPermission::AllUrls.risk_level(),
            ExtensionRisk::High
        );
        assert_eq!(
            ExtensionPermission::Storage.risk_level(),
            ExtensionRisk::None
        );
        assert_eq!(
            ExtensionPermission::Debugger.risk_level(),
            ExtensionRisk::Critical
        );
    }

    #[test]
    fn test_scanner_creation() {
        let scanner = ExtensionScanner::new();
        assert!(!scanner.suspicious_names.is_empty());
    }

    #[test]
    fn test_risk_assessment() {
        let scanner = ExtensionScanner::new();

        // Test suspicious name
        let (risk, reasons) =
            scanner.assess_extension_risk("test-id", "Free VPN Extension", &[]);
        assert!(risk >= ExtensionRisk::Medium);
        assert!(!reasons.is_empty());

        // Test dangerous permissions
        let (risk, _) = scanner.assess_extension_risk(
            "safe-id",
            "Safe Extension",
            &[
                ExtensionPermission::AllUrls,
                ExtensionPermission::WebRequest,
            ],
        );
        assert!(risk >= ExtensionRisk::High);
    }

    #[test]
    fn test_scan_all_browsers() {
        let scanner = ExtensionScanner::new();
        // Should not panic even if no browsers installed
        let result = scanner.scan_all_browsers();
        assert!(result.is_ok());
    }
}
