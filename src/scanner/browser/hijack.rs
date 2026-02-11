//! Browser hijack detection.
//!
//! Detects modifications to:
//! - Homepage settings
//! - Default search engine
//! - New tab page
//! - Startup pages

use crate::core::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use super::extensions::BrowserType;

/// Type of browser hijack.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HijackType {
    /// Homepage changed
    Homepage,
    /// Search engine changed
    SearchEngine,
    /// New tab page changed
    NewTab,
    /// Startup page changed
    Startup,
    /// Proxy settings modified
    Proxy,
    /// DNS settings modified
    Dns,
}

impl std::fmt::Display for HijackType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Homepage => write!(f, "Homepage"),
            Self::SearchEngine => write!(f, "Search Engine"),
            Self::NewTab => write!(f, "New Tab"),
            Self::Startup => write!(f, "Startup Page"),
            Self::Proxy => write!(f, "Proxy"),
            Self::Dns => write!(f, "DNS"),
        }
    }
}

/// Detected browser hijack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserHijack {
    /// Browser affected
    pub browser: BrowserType,
    /// Type of hijack
    pub hijack_type: HijackType,
    /// Current value (the hijacked setting)
    pub current_value: String,
    /// Suspicious URL or domain
    pub suspicious_domain: Option<String>,
    /// Description of the issue
    pub description: String,
    /// Severity (0-100)
    pub severity: u8,
}

/// Known legitimate search engines.
const LEGITIMATE_SEARCH_ENGINES: &[&str] = &[
    "google.com",
    "google.",
    "bing.com",
    "duckduckgo.com",
    "yahoo.com",
    "yandex.com",
    "yandex.ru",
    "baidu.com",
    "ecosia.org",
    "startpage.com",
    "qwant.com",
    "brave.com",
];

/// Known hijacker domains.
const HIJACKER_DOMAINS: &[&str] = &[
    "searchqu.com",
    "delta-homes.com",
    "ask.com",
    "myway.com",
    "conduit.com",
    "babylon.com",
    "sweetim.com",
    "iminent.com",
    "snap.do",
    "searchult.com",
    "ilivid.com",
    "softonic.com",
    "trovi.com",
    "binkiland.com",
    "mysearch.com",
    "mystartsearch.com",
    "searchgol.com",
    "dosearches.com",
    "v9.com",
    "qvo6.com",
    "nationzoom.com",
    "awesomehp.com",
    "sweet-page.com",
    "aartemis.com",
    "omniboxes.com",
    "yoursearching.com",
    "istartsurf.com",
    "webssearches.com",
    "golsearch.com",
    "searches.safefinder.com",
    "www.search.ask.com",
    "searchpagefix.com",
    "safesearch.net",
    "vosteran.com",
];

/// Browser hijack scanner.
pub struct HijackScanner {
    /// Known hijacker domains
    hijacker_domains: HashSet<String>,
    /// Legitimate search engines
    legitimate_search: HashSet<String>,
}

impl HijackScanner {
    /// Create a new hijack scanner.
    pub fn new() -> Self {
        let hijacker_domains: HashSet<String> =
            HIJACKER_DOMAINS.iter().map(|s| s.to_lowercase()).collect();

        let legitimate_search: HashSet<String> = LEGITIMATE_SEARCH_ENGINES
            .iter()
            .map(|s| s.to_lowercase())
            .collect();

        Self {
            hijacker_domains,
            legitimate_search,
        }
    }

    /// Scan all browsers for hijacks.
    pub fn scan_all_browsers(&self) -> Result<Vec<BrowserHijack>> {
        let mut hijacks = Vec::new();

        for browser in [
            BrowserType::Chrome,
            BrowserType::Edge,
            BrowserType::Firefox,
            BrowserType::Brave,
            BrowserType::Opera,
        ] {
            if let Ok(browser_hijacks) = self.scan_browser(browser) {
                hijacks.extend(browser_hijacks);
            }
        }

        Ok(hijacks)
    }

    /// Scan a specific browser for hijacks.
    pub fn scan_browser(&self, browser: BrowserType) -> Result<Vec<BrowserHijack>> {
        let mut hijacks = Vec::new();

        let prefs_paths = self.get_preferences_paths(browser);

        for path in prefs_paths {
            if let Ok(content) = fs::read_to_string(&path) {
                if browser == BrowserType::Firefox {
                    hijacks.extend(self.scan_firefox_prefs(&content, browser)?);
                } else {
                    hijacks.extend(self.scan_chromium_prefs(&content, browser)?);
                }
            }
        }

        Ok(hijacks)
    }

    /// Get preferences file paths for a browser.
    fn get_preferences_paths(&self, browser: BrowserType) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        #[cfg(target_os = "windows")]
        {
            if let Some(local_app_data) = dirs::data_local_dir() {
                match browser {
                    BrowserType::Chrome => {
                        paths.push(
                            local_app_data.join("Google/Chrome/User Data/Default/Preferences"),
                        );
                        paths.push(
                            local_app_data
                                .join("Google/Chrome/User Data/Default/Secure Preferences"),
                        );
                    }
                    BrowserType::Edge => {
                        paths.push(
                            local_app_data.join("Microsoft/Edge/User Data/Default/Preferences"),
                        );
                    }
                    BrowserType::Firefox => {
                        if let Some(roaming) = dirs::data_dir() {
                            // Firefox uses prefs.js in profile directory
                            if let Ok(entries) =
                                fs::read_dir(roaming.join("Mozilla/Firefox/Profiles"))
                            {
                                for entry in entries.filter_map(|e| e.ok()) {
                                    let prefs = entry.path().join("prefs.js");
                                    if prefs.exists() {
                                        paths.push(prefs);
                                    }
                                }
                            }
                        }
                    }
                    BrowserType::Brave => {
                        paths.push(
                            local_app_data
                                .join("BraveSoftware/Brave-Browser/User Data/Default/Preferences"),
                        );
                    }
                    BrowserType::Opera => {
                        paths.push(local_app_data.join("Opera Software/Opera Stable/Preferences"));
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            if let Some(home) = dirs::home_dir() {
                match browser {
                    BrowserType::Chrome => {
                        paths.push(home.join(".config/google-chrome/Default/Preferences"));
                        paths.push(home.join(".config/chromium/Default/Preferences"));
                    }
                    BrowserType::Edge => {
                        paths.push(home.join(".config/microsoft-edge/Default/Preferences"));
                    }
                    BrowserType::Firefox => {
                        if let Ok(entries) = fs::read_dir(home.join(".mozilla/firefox")) {
                            for entry in entries.filter_map(|e| e.ok()) {
                                let prefs = entry.path().join("prefs.js");
                                if prefs.exists() {
                                    paths.push(prefs);
                                }
                            }
                        }
                    }
                    BrowserType::Brave => {
                        paths.push(
                            home.join(".config/BraveSoftware/Brave-Browser/Default/Preferences"),
                        );
                    }
                    BrowserType::Opera => {
                        paths.push(home.join(".config/opera/Preferences"));
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            if let Some(home) = dirs::home_dir() {
                match browser {
                    BrowserType::Chrome => {
                        paths.push(
                            home.join(
                                "Library/Application Support/Google/Chrome/Default/Preferences",
                            ),
                        );
                    }
                    BrowserType::Edge => {
                        paths.push(home.join(
                            "Library/Application Support/Microsoft Edge/Default/Preferences",
                        ));
                    }
                    BrowserType::Firefox => {
                        if let Ok(entries) =
                            fs::read_dir(home.join("Library/Application Support/Firefox/Profiles"))
                        {
                            for entry in entries.filter_map(|e| e.ok()) {
                                let prefs = entry.path().join("prefs.js");
                                if prefs.exists() {
                                    paths.push(prefs);
                                }
                            }
                        }
                    }
                    BrowserType::Brave => {
                        paths.push(home.join("Library/Application Support/BraveSoftware/Brave-Browser/Default/Preferences"));
                    }
                    BrowserType::Opera => {
                        paths.push(home.join(
                            "Library/Application Support/com.operasoftware.Opera/Preferences",
                        ));
                    }
                }
            }
        }

        paths.into_iter().filter(|p| p.exists()).collect()
    }

    /// Scan Chromium-based browser preferences.
    fn scan_chromium_prefs(
        &self,
        content: &str,
        browser: BrowserType,
    ) -> Result<Vec<BrowserHijack>> {
        let mut hijacks = Vec::new();

        let prefs: serde_json::Value = match serde_json::from_str(content) {
            Ok(v) => v,
            Err(_) => return Ok(Vec::new()),
        };

        // Check homepage
        if let Some(homepage) = prefs.get("homepage").and_then(|v| v.as_str()) {
            if let Some(hijack) = self.check_url_hijack(homepage, HijackType::Homepage, browser) {
                hijacks.push(hijack);
            }
        }

        // Check search engine
        if let Some(search_url) = prefs
            .get("default_search_provider_data")
            .and_then(|v| v.get("template_url_data"))
            .and_then(|v| v.get("url"))
            .and_then(|v| v.as_str())
        {
            if let Some(hijack) = self.check_search_hijack(search_url, browser) {
                hijacks.push(hijack);
            }
        }

        // Also check default_search_provider
        if let Some(search_url) = prefs
            .get("default_search_provider")
            .and_then(|v| v.get("search_url"))
            .and_then(|v| v.as_str())
        {
            if let Some(hijack) = self.check_search_hijack(search_url, browser) {
                hijacks.push(hijack);
            }
        }

        // Check startup URLs
        if let Some(startup) = prefs.get("session").and_then(|v| v.get("startup_urls")) {
            if let Some(urls) = startup.as_array() {
                for url in urls {
                    if let Some(url_str) = url.as_str() {
                        if let Some(hijack) =
                            self.check_url_hijack(url_str, HijackType::Startup, browser)
                        {
                            hijacks.push(hijack);
                        }
                    }
                }
            }
        }

        // Check new tab URL
        if let Some(ntp_url) = prefs
            .get("browser")
            .and_then(|v| v.get("new_tab_page_location"))
            .and_then(|v| v.as_str())
        {
            if let Some(hijack) = self.check_url_hijack(ntp_url, HijackType::NewTab, browser) {
                hijacks.push(hijack);
            }
        }

        Ok(hijacks)
    }

    /// Scan Firefox preferences.
    fn scan_firefox_prefs(
        &self,
        content: &str,
        browser: BrowserType,
    ) -> Result<Vec<BrowserHijack>> {
        let mut hijacks = Vec::new();

        // Firefox prefs.js format: user_pref("key", "value");
        for line in content.lines() {
            let line = line.trim();
            if !line.starts_with("user_pref(") {
                continue;
            }

            // Parse the preference
            if let Some((key, value)) = self.parse_firefox_pref(line) {
                match key.as_str() {
                    "browser.startup.homepage" => {
                        if let Some(hijack) =
                            self.check_url_hijack(&value, HijackType::Homepage, browser)
                        {
                            hijacks.push(hijack);
                        }
                    }
                    "browser.newtab.url" | "browser.newtabpage.url" => {
                        if let Some(hijack) =
                            self.check_url_hijack(&value, HijackType::NewTab, browser)
                        {
                            hijacks.push(hijack);
                        }
                    }
                    "keyword.URL" | "browser.search.defaulturl" => {
                        if let Some(hijack) = self.check_search_hijack(&value, browser) {
                            hijacks.push(hijack);
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(hijacks)
    }

    /// Parse a Firefox preference line.
    fn parse_firefox_pref(&self, line: &str) -> Option<(String, String)> {
        // Format: user_pref("key", "value");
        let start = line.find('(')? + 1;
        let end = line.rfind(')')?;
        let content = &line[start..end];

        let mut parts = content.splitn(2, ',');
        let key = parts.next()?.trim().trim_matches('"');
        let value = parts.next()?.trim().trim_matches('"');

        Some((key.to_string(), value.to_string()))
    }

    /// Check if a URL is a hijack.
    fn check_url_hijack(
        &self,
        url: &str,
        hijack_type: HijackType,
        browser: BrowserType,
    ) -> Option<BrowserHijack> {
        let url_lower = url.to_lowercase();

        // Extract domain from URL
        let domain = self.extract_domain(&url_lower);

        // Check against known hijacker domains
        for hijacker in &self.hijacker_domains {
            if domain.contains(hijacker) || url_lower.contains(hijacker) {
                return Some(BrowserHijack {
                    browser,
                    hijack_type: hijack_type.clone(),
                    current_value: url.to_string(),
                    suspicious_domain: Some(hijacker.clone()),
                    description: format!(
                        "Known hijacker domain '{}' detected in {:?} settings",
                        hijacker, hijack_type
                    ),
                    severity: 80,
                });
            }
        }

        None
    }

    /// Check if a search URL is a hijack.
    fn check_search_hijack(&self, url: &str, browser: BrowserType) -> Option<BrowserHijack> {
        let url_lower = url.to_lowercase();
        let domain = self.extract_domain(&url_lower);

        // Check if it's a legitimate search engine
        let is_legitimate = self
            .legitimate_search
            .iter()
            .any(|engine| domain.contains(engine) || url_lower.contains(engine));

        if is_legitimate {
            return None;
        }

        // Check against hijacker domains
        for hijacker in &self.hijacker_domains {
            if domain.contains(hijacker) || url_lower.contains(hijacker) {
                return Some(BrowserHijack {
                    browser,
                    hijack_type: HijackType::SearchEngine,
                    current_value: url.to_string(),
                    suspicious_domain: Some(hijacker.clone()),
                    description: format!(
                        "Search engine hijacked to known malicious domain '{}'",
                        hijacker
                    ),
                    severity: 90,
                });
            }
        }

        // If not legitimate and not a known hijacker, flag as suspicious
        if !domain.is_empty() && !is_legitimate {
            Some(BrowserHijack {
                browser,
                hijack_type: HijackType::SearchEngine,
                current_value: url.to_string(),
                suspicious_domain: Some(domain),
                description: "Unknown search engine configured".to_string(),
                severity: 50,
            })
        } else {
            None
        }
    }

    /// Extract domain from a URL.
    fn extract_domain(&self, url: &str) -> String {
        let url = url
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_start_matches("www.");

        if let Some(slash) = url.find('/') {
            url[..slash].to_string()
        } else {
            url.to_string()
        }
    }
}

impl Default for HijackScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hijack_type_display() {
        assert_eq!(format!("{}", HijackType::Homepage), "Homepage");
        assert_eq!(format!("{}", HijackType::SearchEngine), "Search Engine");
    }

    #[test]
    fn test_scanner_creation() {
        let scanner = HijackScanner::new();
        assert!(!scanner.hijacker_domains.is_empty());
        assert!(!scanner.legitimate_search.is_empty());
    }

    #[test]
    fn test_extract_domain() {
        let scanner = HijackScanner::new();

        assert_eq!(
            scanner.extract_domain("https://www.google.com/search"),
            "google.com"
        );
        assert_eq!(scanner.extract_domain("http://example.com"), "example.com");
        assert_eq!(
            scanner.extract_domain("delta-homes.com/page"),
            "delta-homes.com"
        );
    }

    #[test]
    fn test_check_hijacker_domain() {
        let scanner = HijackScanner::new();

        let hijack = scanner.check_url_hijack(
            "http://delta-homes.com",
            HijackType::Homepage,
            BrowserType::Chrome,
        );
        assert!(hijack.is_some());

        let hijack = hijack.unwrap();
        assert_eq!(hijack.hijack_type, HijackType::Homepage);
        assert!(hijack.severity >= 70);
    }

    #[test]
    fn test_legitimate_search() {
        let scanner = HijackScanner::new();

        let hijack = scanner.check_search_hijack(
            "https://www.google.com/search?q={searchTerms}",
            BrowserType::Chrome,
        );
        assert!(hijack.is_none());

        let hijack = scanner.check_search_hijack(
            "https://duckduckgo.com/?q={searchTerms}",
            BrowserType::Chrome,
        );
        assert!(hijack.is_none());
    }

    #[test]
    fn test_search_hijack() {
        let scanner = HijackScanner::new();

        let hijack = scanner.check_search_hijack(
            "http://searchqu.com/search?q={searchTerms}",
            BrowserType::Chrome,
        );
        assert!(hijack.is_some());

        let hijack = hijack.unwrap();
        assert_eq!(hijack.hijack_type, HijackType::SearchEngine);
        assert!(hijack.severity >= 80);
    }

    #[test]
    fn test_parse_firefox_pref() {
        let scanner = HijackScanner::new();

        let result = scanner
            .parse_firefox_pref(r#"user_pref("browser.startup.homepage", "https://google.com");"#);
        assert!(result.is_some());

        let (key, value) = result.unwrap();
        assert_eq!(key, "browser.startup.homepage");
        assert_eq!(value, "https://google.com");
    }

    #[test]
    fn test_scan_all_browsers() {
        let scanner = HijackScanner::new();
        // Should not panic even if no browsers installed
        let result = scanner.scan_all_browsers();
        assert!(result.is_ok());
    }
}
