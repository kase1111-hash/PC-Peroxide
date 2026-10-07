//! GUI module for PC-Peroxide.
//!
//! Provides a graphical user interface using egui/eframe.
//! This module is only compiled when the `gui` feature is enabled.

#[cfg(feature = "gui")]
mod app;
#[cfg(feature = "gui")]
mod dashboard;
#[cfg(feature = "gui")]
mod quarantine_view;
#[cfg(feature = "gui")]
mod results_view;
#[cfg(feature = "gui")]
mod scan_view;
#[cfg(feature = "gui")]
mod settings_view;
#[cfg(feature = "gui")]
mod theme;
#[cfg(feature = "gui")]
mod updates;

#[cfg(feature = "gui")]
pub use app::PeroxideApp;
#[cfg(feature = "gui")]
pub use theme::Theme;
#[cfg(feature = "gui")]
pub use updates::SignatureUpdater;

/// View state for navigation.
#[cfg(feature = "gui")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum View {
    #[default]
    Dashboard,
    Scan,
    Results,
    Quarantine,
    Settings,
    Updates,
}

/// Shorten text to at most `max_chars` characters by replacing its start with
/// "...". Works on characters, not bytes, so non-ASCII paths cannot panic.
#[cfg(feature = "gui")]
pub(crate) fn truncate_start(text: &str, max_chars: usize) -> String {
    let len = text.chars().count();
    if len <= max_chars {
        return text.to_string();
    }
    let keep = max_chars.saturating_sub(3);
    let tail: String = text.chars().skip(len - keep).collect();
    format!("...{}", tail)
}

/// Formats `n` with the singular or plural form of a noun, e.g. "1 threat".
pub(crate) fn count(n: u64, singular: &str, plural: &str) -> String {
    format!("{} {}", n, if n == 1 { singular } else { plural })
}

#[cfg(all(test, feature = "gui"))]
mod tests {
    use super::{count, truncate_start};

    #[test]
    fn test_count() {
        assert_eq!(count(0, "threat", "threats"), "0 threats");
        assert_eq!(count(1, "threat", "threats"), "1 threat");
        assert_eq!(count(2, "file", "files"), "2 files");
    }

    #[test]
    fn test_truncate_start() {
        assert_eq!(truncate_start("short", 10), "short");
        assert_eq!(truncate_start("abcdefghij", 8), "...fghij");
        // Multi-byte characters must not split (this used to panic).
        let path = "C:\\Users\\Jürgen\\Документы\\файл.exe";
        let out = truncate_start(path, 12);
        assert_eq!(out.chars().count(), 12);
        assert!(out.ends_with("файл.exe"));
    }
}
