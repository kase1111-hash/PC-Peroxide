//! Settings/configuration view component.

#[cfg(feature = "gui")]
use eframe::egui::{self, RichText, Rounding, Ui, Vec2};

use super::theme::Theme;
use crate::config::Config;
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
}

/// Edited settings (mutable copy).
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
    retention_days: u32,

    // Update settings
    auto_update_signatures: bool,
    update_check_interval_hours: u32,

    // Logging
    log_level: String,
    verbose_console: bool,
}

impl From<&Config> for EditedSettings {
    fn from(config: &Config) -> Self {
        Self {
            skip_large_files_mb: config.scan.skip_large_files_mb,
            scan_archives: config.scan.scan_archives,
            max_archive_depth: config.scan.max_archive_depth,
            follow_symlinks: config.scan.follow_symlinks,
            scan_threads: config.scan.scan_threads,
            auto_quarantine_critical: config.actions.auto_quarantine_critical,
            vault_path: config
                .quarantine
                .vault_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            retention_days: config.quarantine.retention_days,
            auto_update_signatures: config.updates.auto_update_signatures,
            update_check_interval_hours: config.updates.update_check_interval_hours,
            log_level: config.logging.log_level.clone(),
            verbose_console: config.logging.verbose_console,
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
        }
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
                                    RichText::new("Save Changes")
                                        .color(egui::Color32::WHITE),
                                )
                                .fill(self.theme.primary)
                                .min_size(Vec2::new(120.0, 36.0)),
                            )
                            .clicked()
                        {
                            if self.save_settings() {
                                saved = true;
                                self.has_changes = false;
                                self.show_saved = true;
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

                        self.render_update_settings(ui);
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
                            RichText::new("Settings saved successfully!")
                                .color(self.theme.success),
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
                let mut value = this.edited.skip_large_files_mb as f32;
                if ui
                    .add(egui::Slider::new(&mut value, 0.0..=1000.0).suffix(" MB"))
                    .changed()
                {
                    this.edited.skip_large_files_mb = value as u64;
                    this.has_changes = true;
                }
            });

            // Scan archives
            if ui
                .checkbox(&mut this.edited.scan_archives, "Scan inside archives (ZIP, RAR, etc.)")
                .changed()
            {
                this.has_changes = true;
            }

            // Archive depth
            ui.add_enabled_ui(this.edited.scan_archives, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Max archive nesting depth:");
                    let mut value = this.edited.max_archive_depth as f32;
                    if ui
                        .add(egui::Slider::new(&mut value, 1.0..=10.0))
                        .changed()
                    {
                        this.edited.max_archive_depth = value as u8;
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

            // Parallel threads
            ui.horizontal(|ui| {
                ui.label("Scan threads:");
                let max_threads = num_cpus().max(1);
                let mut value = this.edited.scan_threads as f32;
                if ui
                    .add(egui::Slider::new(&mut value, 1.0..=(max_threads as f32)))
                    .on_hover_text("Number of parallel threads for scanning")
                    .changed()
                {
                    this.edited.scan_threads = value as usize;
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
                    "Automatically quarantine critical threats",
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

            // Retention days
            ui.horizontal(|ui| {
                ui.label("Auto-delete quarantined files after:");
                let mut value = this.edited.retention_days as f32;
                if ui
                    .add(egui::Slider::new(&mut value, 0.0..=365.0).suffix(" days"))
                    .on_hover_text("Set to 0 to never auto-delete")
                    .changed()
                {
                    this.edited.retention_days = value as u32;
                    this.has_changes = true;
                }
            });
        });
    }

    /// Render update settings section.
    fn render_update_settings(&mut self, ui: &mut Ui) {
        self.render_section(ui, "Update Settings", |this, ui| {
            // Auto update
            if ui
                .checkbox(
                    &mut this.edited.auto_update_signatures,
                    "Automatically update signatures",
                )
                .changed()
            {
                this.has_changes = true;
            }

            // Update interval
            ui.add_enabled_ui(this.edited.auto_update_signatures, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Check for updates every:");
                    let mut value = this.edited.update_check_interval_hours as f32;
                    if ui
                        .add(egui::Slider::new(&mut value, 1.0..=168.0).suffix(" hours"))
                        .changed()
                    {
                        this.edited.update_check_interval_hours = value as u32;
                        this.has_changes = true;
                    }
                });
            });
        });
    }

    /// Render logging settings section.
    fn render_logging_settings(&mut self, ui: &mut Ui) {
        self.render_section(ui, "Logging", |this, ui| {
            // Log level
            ui.horizontal(|ui| {
                ui.label("Log level:");
                egui::ComboBox::from_id_salt("log_level")
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

            // Verbose console
            if ui
                .checkbox(&mut this.edited.verbose_console, "Verbose console output")
                .changed()
            {
                this.has_changes = true;
            }
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
    fn save_settings(&mut self) -> bool {
        let mut config = (*self.config).clone();

        // Apply edited values
        config.scan.skip_large_files_mb = self.edited.skip_large_files_mb;
        config.scan.scan_archives = self.edited.scan_archives;
        config.scan.max_archive_depth = self.edited.max_archive_depth;
        config.scan.follow_symlinks = self.edited.follow_symlinks;
        config.scan.scan_threads = self.edited.scan_threads;

        config.actions.auto_quarantine_critical = self.edited.auto_quarantine_critical;
        config.quarantine.vault_path = if self.edited.vault_path.is_empty() {
            None
        } else {
            Some(self.edited.vault_path.clone().into())
        };
        config.quarantine.retention_days = self.edited.retention_days;

        config.updates.auto_update_signatures = self.edited.auto_update_signatures;
        config.updates.update_check_interval_hours = self.edited.update_check_interval_hours;

        config.logging.log_level = self.edited.log_level.clone();
        config.logging.verbose_console = self.edited.verbose_console;

        // Save to file
        let config_path = Config::default_config_path();
        match config.save(&config_path) {
            Ok(_) => {
                self.config = Arc::new(config);
                log::info!("Settings saved successfully");
                true
            }
            Err(e) => {
                log::error!("Failed to save settings: {}", e);
                false
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
