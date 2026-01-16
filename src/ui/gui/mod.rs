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
