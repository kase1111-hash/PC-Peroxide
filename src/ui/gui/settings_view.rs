//! Settings/configuration view component.

use eframe::egui::{self, RichText, Rounding, Ui, Vec2};

use super::theme::Theme;
use crate::core::config::Config;
use std::sync::Arc;

/// Settings view state.
pub struct SettingsView {
    theme: Theme,
    config: Arc<Config>,
    /// Edited config values
    edited: EditedSettings,
    /// Whether changes have been made
    has_changes: bool,
    /// Show save confirmation
    show_saved: bool,
    /// Error from the last save attempt
    save_error: Option<String>,
}

/// Edited settings (mutable copy).
///
/// Only settings the application acts on are offered here; others in the
/// config file (retention, online updates) have no implementation yet.
#[derive(Clone)]
struct EditedSettings {
    // Scan settings
    skip_large_files_mb: u64,
    scan_archives: bool,
    max_archive_depth: u8,
    follow_symlinks: bool,
    scan_threads: usize,

    // Action/Quarantine settings
    auto_quarantine_critical: bool,
    vault_path: String,

    // Logging
    log_level: String,
}

impl From<&Config> for EditedSettings {
    fn from(config: &Config) -> Self {
        Self {
            skip_large_files_mb: config.scan.skip_large_files_mb,
            scan_archives: config.scan.scan_archives,
            // Out-of-range values would be shown clamped but saved unchanged
            max_archive_depth: config.scan.max_archive_depth.clamp(1, 10),
            follow_symlinks: config.scan.follow_symlinks,
            scan_threads: config.scan.scan_threads,
            auto_quarantine_critical: config.actions.auto_quarantine_critical,
            vault_path: config
                .quarantine
                .vault_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            log_level: config.logging.log_level.clone(),
        }
    }
}

impl SettingsView {
    /// Create a new settings view.
    pub fn new(config: Arc<Config>, theme: Theme) -> Self {
        let edited = EditedSettings::from(config.as_ref());
        Self {
            theme,
            config,
            edited,
            has_changes: false,
            show_saved: false,
            save_error: None,
        }
    }

    /// Use a different theme.
    pub fn set_theme(&mut self, theme: Theme) {
        self.theme = theme;
    }

    /// Render the settings view. Returns true if settings were saved.
    pub fn render(&mut self, ui: &mut Ui) -> bool {
        let mut saved = false;

        ui.vertical(|ui| {
            ui.add_space(20.0);
            ui.horizontal(|ui| {
                ui.add_space(20.0);
                ui.label(self.theme.heading("Settings"));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_space(20.0);

                    // Save button
                    ui.add_enabled_ui(self.has_changes, |ui| {
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("Save Changes").color(egui::Color32::WHITE),
                                )
                                .fill(self.theme.primary)
                                .min_size(Vec2::new(120.0, 36.0)),
                            )
                            .clicked()
                        {
                            match self.save_settings() {
                                Ok(()) => {
                                    saved = true;
                                    self.has_changes = false;
                                    self.show_saved = true;
                                    self.save_error = None;
                                }
                                Err(e) => self.save_error = Some(e),
                            }
                        }
                    });

                    // Reset button
                    if ui.button("Reset to Defaults").clicked() {
                        self.reset_to_defaults();
                    }
                });
            });

            ui.add_space(20.0);

            if let Some(ref error) = self.save_error {
                ui.horizontal(|ui| {
                    ui.add_space(20.0);
                    ui.colored_label(self.theme.danger, format!("Settings not saved: {}", error));
                });
                ui.add_space(10.0);
            }

            // Settings sections
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.add_space(20.0);

                    ui.vertical(|ui| {
                        ui.set_max_width(600.0);

                        self.render_scan_settings(ui);
                        ui.add_space(20.0);

                        self.render_quarantine_settings(ui);
                        ui.add_space(20.0);

                        self.render_logging_settings(ui);
                    });
                });
            });
        });

        // Saved confirmation toast
        if self.show_saved {
            egui::Window::new("Settings Saved")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ui.ctx(), |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(10.0);
                        ui.label(
                            RichText::new("Settings saved successfully!").color(self.theme.success),
                        );
                        ui.add_space(10.0);
                        if ui.button("OK").clicked() {
                            self.show_saved = false;
                        }
                    });
                });
        }

        saved
    }

    /// Render scan settings section.
    fn render_scan_settings(&mut self, ui: &mut Ui) {
        self.render_section(ui, "Scan Settings", |this, ui| {
            // Skip large files
            ui.horizontal(|ui| {
                ui.label("Skip files larger than:");
                // Keep a larger value set elsewhere (e.g. `config set`) reachable
                let max_mb = this.edited.skip_large_files_mb.max(1000);
                if ui
                    .add(
                        egui::Slider::new(&mut this.edited.skip_large_files_mb, 1..=max_mb)
                            .suffix(" MB"),
                    )
                    .changed()
                {
                    this.has_changes = true;
                }
            });

            // Scan archives
            if ui
                .checkbox(
                    &mut this.edited.scan_archives,
                    "Scan inside ZIP-based archives (ZIP, JAR, APK, Office documents)",
                )
                .changed()
            {
                this.has_changes = true;
            }

            // Archive depth
            ui.add_enabled_ui(this.edited.scan_archives, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Max archive nesting depth:");
                    if ui
                        .add(egui::Slider::new(
                            &mut this.edited.max_archive_depth,
                            1..=10,
                        ))
                        .changed()
                    {
                        this.has_changes = true;
                    }
                });
            });

            // Follow symlinks
            if ui
                .checkbox(&mut this.edited.follow_symlinks, "Follow symbolic links")
                .changed()
            {
                this.has_changes = true;
            }

            // Parallel workers (the scanner uses at most 8)
            ui.horizontal(|ui| {
                ui.label("Scan threads:");
                let max_threads = num_cpus().clamp(1, 8);
                this.edited.scan_threads = this.edited.scan_threads.clamp(1, max_threads);
                if ui
                    .add(egui::Slider::new(
                        &mut this.edited.scan_threads,
                        1..=max_threads,
                    ))
                    .on_hover_text("Number of files scanned in parallel")
                    .changed()
                {
                    this.has_changes = true;
                }
            });
        });
    }

    /// Render quarantine settings section.
    fn render_quarantine_settings(&mut self, ui: &mut Ui) {
        self.render_section(ui, "Quarantine Settings", |this, ui| {
            // Auto quarantine critical
            if ui
                .checkbox(
                    &mut this.edited.auto_quarantine_critical,
                    "Automatically quarantine critical threats after a scan",
                )
                .changed()
            {
                this.has_changes = true;
            }

            // Vault path
            ui.horizontal(|ui| {
                ui.label("Quarantine folder:");
                if ui
                    .text_edit_singleline(&mut this.edited.vault_path)
                    .changed()
                {
                    this.has_changes = true;
                }
                if ui.button("Browse...").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .set_title("Select Quarantine Folder")
                        .pick_folder()
                    {
                        this.edited.vault_path = path.display().to_string();
                        this.has_changes = true;
                    }
                }
            });
            ui.label(this.theme.label(&format!(
                "Leave empty for the default ({}). Items already quarantined stay in the old folder.",
                crate::quarantine::get_quarantine_path().display()
            )));
        });
    }

    /// Render logging settings section.
    fn render_logging_settings(&mut self, ui: &mut Ui) {
        self.render_section(ui, "Logging", |this, ui| {
            // Log level
            ui.horizontal(|ui| {
                ui.label("Log level:");
                egui::ComboBox::from_id_source("log_level")
                    .selected_text(&this.edited.log_level)
                    .show_ui(ui, |ui| {
                        for level in ["error", "warn", "info", "debug", "trace"] {
                            if ui
                                .selectable_label(this.edited.log_level == level, level)
                                .clicked()
                            {
                                this.edited.log_level = level.to_string();
                                this.has_changes = true;
                            }
                        }
                    });
            });
            ui.label(this.theme.label(&format!(
                "Takes effect on restart. Log file: {}",
                this.config.logging.log_dir().join("pc-peroxide.log").display()
            )));
        });
    }

    /// Render a settings section.
    fn render_section<F>(&mut self, ui: &mut Ui, title: &str, content: F)
    where
        F: FnOnce(&mut Self, &mut Ui),
    {
        egui::Frame::none()
            .fill(self.theme.surface)
            .rounding(Rounding::same(8.0))
            .inner_margin(20.0)
            .show(ui, |ui| {
                ui.set_min_width(550.0);

                ui.vertical(|ui| {
                    ui.label(self.theme.subheading(title));
                    ui.add_space(15.0);
                    content(self, ui);
                });
            });
    }

    /// Save settings to config file.
    fn save_settings(&mut self) -> Result<(), String> {
        let mut config = (*self.config).clone();

        // Apply edited values
        config.scan.skip_large_files_mb = self.edited.skip_large_files_mb;
        config.scan.scan_archives = self.edited.scan_archives;
        config.scan.max_archive_depth = self.edited.max_archive_depth;
        config.scan.follow_symlinks = self.edited.follow_symlinks;
        config.scan.scan_threads = self.edited.scan_threads;

        config.actions.auto_quarantine_critical = self.edited.auto_quarantine_critical;
        let vault_path = self.edited.vault_path.trim();
        config.quarantine.vault_path = if vault_path.is_empty() {
            None
        } else {
            Some(vault_path.into())
        };

        config.logging.log_level = self.edited.log_level.clone();

        // A vault folder that cannot be used would only fail later, when
        // a threat needs quarantining; opening it creates it if needed.
        if config.quarantine.vault_path != self.config.quarantine.vault_path {
            config.validate().map_err(|e| e.to_string())?;
            let dir = config.quarantine.quarantine_dir();
            crate::quarantine::QuarantineVault::open(&dir)
                .map_err(|e| format!("Cannot use quarantine folder {}: {}", dir.display(), e))?;
        }

        // Validate, then save to file
        let config_path = Config::default_config_path();
        match config.validate().and_then(|()| config.save(&config_path)) {
            Ok(()) => {
                self.config = Arc::new(config);
                log::info!("Settings saved successfully");
                Ok(())
            }
            Err(e) => {
                log::error!("Failed to save settings: {}", e);
                Err(e.to_string())
            }
        }
    }

    /// Reset settings to defaults.
    fn reset_to_defaults(&mut self) {
        let default_config = Config::default();
        self.edited = EditedSettings::from(&default_config);
        self.has_changes = true;
    }
}

/// Get number of CPUs (simplified).
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settings_view_creation() {
        let config = Arc::new(Config::default());
        let theme = Theme::default();
        let _view = SettingsView::new(config, theme);
    }

    #[test]
    fn test_edited_settings_from_config() {
        let config = Config::default();
        let edited = EditedSettings::from(&config);
        assert_eq!(edited.scan_threads, config.scan.scan_threads);
    }
}
