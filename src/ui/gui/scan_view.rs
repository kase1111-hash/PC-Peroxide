//! Scan progress view component.

use eframe::egui::{self, Color32, RichText, Rounding, Ui, Vec2};

use super::app::{ScanAction, ScanState};
use super::theme::Theme;
use crate::core::types::{ScanStatus, ScanType};
use crate::scanner::ScanRequest;
use std::path::PathBuf;

/// Scan view state.
pub struct ScanView {
    theme: Theme,
    /// Selected scan type for new scans
    selected_scan_type: ScanType,
    /// Custom paths input
    custom_paths_text: String,
}

impl ScanView {
    /// Create a new scan view.
    pub fn new(theme: Theme) -> Self {
        Self {
            theme,
            selected_scan_type: ScanType::Quick,
            custom_paths_text: String::new(),
        }
    }

    /// Use a different theme.
    pub fn set_theme(&mut self, theme: Theme) {
        self.theme = theme;
    }

    /// Render the scan view.
    pub fn render(&mut self, ui: &mut Ui, state: &ScanState) -> Option<ScanAction> {
        let mut action = None;

        ui.vertical(|ui| {
            ui.add_space(20.0);
            ui.horizontal(|ui| {
                ui.add_space(20.0);
                ui.label(self.theme.heading("Scan"));
            });
            ui.add_space(20.0);

            if state.is_scanning {
                if let Some(a) = self.render_scan_progress(ui, state) {
                    action = Some(a);
                }
            } else if let Some(a) = self.render_scan_options(ui, state) {
                action = Some(a);
            }
        });

        action
    }

    /// Render scan progress.
    fn render_scan_progress(&self, ui: &mut Ui, state: &ScanState) -> Option<ScanAction> {
        let mut action = None;

        ui.horizontal(|ui| {
            ui.add_space(20.0);

            egui::Frame::none()
                .fill(self.theme.surface)
                .rounding(Rounding::same(8.0))
                .inner_margin(30.0)
                .show(ui, |ui| {
                    ui.set_min_width(500.0);

                    ui.vertical(|ui| {
                        // Scan type header
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.add_space(10.0);
                            ui.label(
                                RichText::new(format!("{} in Progress", state.scan_type))
                                    .size(18.0)
                                    .strong()
                                    .color(self.theme.text_primary),
                            );
                        });

                        ui.add_space(20.0);

                        // Progress bar; the total is unknown until discovery ends
                        let bar = match state.total_files {
                            Some(_) => egui::ProgressBar::new(state.progress)
                                .text(format!("{:.1}%", state.progress * 100.0)),
                            None => egui::ProgressBar::new(0.0).text(format!(
                                "Discovering files... {} folders",
                                state.directories_found
                            )),
                        };
                        ui.add(bar.animate(true));

                        ui.add_space(15.0);

                        // Stats
                        ui.horizontal(|ui| {
                            ui.label(self.theme.label("Files scanned:"));
                            let files = match state.total_files {
                                Some(total) => format!("{} / {}", state.files_scanned, total),
                                None => state.files_scanned.to_string(),
                            };
                            ui.label(self.theme.value(&files));

                            ui.add_space(30.0);

                            ui.label(self.theme.label("Threats found:"));
                            let threat_color = if state.threats_found.is_empty() {
                                self.theme.success
                            } else {
                                self.theme.danger
                            };
                            ui.label(
                                RichText::new(state.threats_found.len().to_string())
                                    .size(18.0)
                                    .color(threat_color)
                                    .strong(),
                            );
                        });

                        ui.add_space(10.0);

                        // Current file
                        if !state.current_file.is_empty() {
                            ui.horizontal(|ui| {
                                ui.label(self.theme.label("Scanning:"));
                                ui.label(
                                    RichText::new(super::truncate_start(&state.current_file, 80))
                                        .size(12.0)
                                        .color(self.theme.text_secondary)
                                        .monospace(),
                                );
                            });
                        }

                        ui.add_space(20.0);

                        // Cancel button
                        let label = if state.cancelling {
                            "Cancelling..."
                        } else {
                            "Cancel Scan"
                        };
                        let cancel = ui.add_enabled(
                            !state.cancelling,
                            egui::Button::new(RichText::new(label).color(Color32::WHITE))
                                .fill(self.theme.danger)
                                .min_size(Vec2::new(120.0, 36.0)),
                        );
                        if cancel.clicked() {
                            action = Some(ScanAction::Cancel);
                        }
                    });
                });
        });

        // Threat list during scan
        if !state.threats_found.is_empty() {
            ui.add_space(20.0);
            ui.horizontal(|ui| {
                ui.add_space(20.0);
                ui.label(self.theme.subheading("Threats Found During Scan"));
            });
            ui.add_space(10.0);

            ui.indent("scan_view_1", |ui| {
                egui::ScrollArea::vertical()
                    .max_height(200.0)
                    .show(ui, |ui| {
                        for threat in &state.threats_found {
                            ui.horizontal(|ui| {
                                let severity_color =
                                    self.theme.severity_color(&threat.severity.to_string());
                                ui.colored_label(severity_color, format!("[{}]", threat.severity));
                                ui.label(&threat.threat_name);
                                ui.label(
                                    RichText::new(threat.path.display().to_string())
                                        .monospace()
                                        .size(11.0),
                                );
                            });
                        }
                    });
            });
        }

        action
    }

    /// Render scan options when not scanning.
    fn render_scan_options(&mut self, ui: &mut Ui, state: &ScanState) -> Option<ScanAction> {
        let mut action = None;

        ui.horizontal(|ui| {
            ui.add_space(20.0);

            // Scan type selection
            egui::Frame::none()
                .fill(self.theme.surface)
                .rounding(Rounding::same(8.0))
                .inner_margin(20.0)
                .show(ui, |ui| {
                    ui.set_min_width(300.0);

                    ui.vertical(|ui| {
                        ui.label(self.theme.subheading("Scan Type"));
                        ui.add_space(15.0);

                        // Quick scan option
                        let quick_selected = self.selected_scan_type == ScanType::Quick;
                        if ui
                            .add(self.scan_type_radio("Quick Scan", quick_selected))
                            .clicked()
                        {
                            self.selected_scan_type = ScanType::Quick;
                        }
                        ui.label(
                            self.theme
                                .label("Fast scan of common malware locations (~2 min)"),
                        );
                        ui.add_space(10.0);

                        // Full scan option
                        let full_selected = self.selected_scan_type == ScanType::Full;
                        if ui
                            .add(self.scan_type_radio("Full Scan", full_selected))
                            .clicked()
                        {
                            self.selected_scan_type = ScanType::Full;
                        }
                        ui.label(
                            self.theme
                                .label("Comprehensive scan of entire system (~30 min)"),
                        );
                        ui.add_space(10.0);

                        // Custom scan option
                        let custom_selected = self.selected_scan_type == ScanType::Custom;
                        if ui
                            .add(self.scan_type_radio("Custom Scan", custom_selected))
                            .clicked()
                        {
                            self.selected_scan_type = ScanType::Custom;
                        }
                        ui.label(self.theme.label("Scan specific files or folders"));

                        if custom_selected {
                            ui.add_space(10.0);

                            ui.horizontal(|ui| {
                                ui.text_edit_singleline(&mut self.custom_paths_text);
                                if ui.button("Folders...").clicked() {
                                    if let Some(paths) = rfd::FileDialog::new()
                                        .set_title("Select folders to scan")
                                        .pick_folders()
                                    {
                                        self.set_custom_paths(&paths);
                                    }
                                }
                                if ui.button("Files...").clicked() {
                                    if let Some(paths) = rfd::FileDialog::new()
                                        .set_title("Select files to scan")
                                        .pick_files()
                                    {
                                        self.set_custom_paths(&paths);
                                    }
                                }
                            });
                            ui.label(
                                self.theme
                                    .label("Separate multiple paths with semicolon (;)"),
                            );
                        }

                        ui.add_space(20.0);

                        // Start scan button
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("Start Scan").size(16.0).color(Color32::WHITE),
                                )
                                .fill(self.theme.primary)
                                .min_size(Vec2::new(150.0, 45.0)),
                            )
                            .clicked()
                        {
                            let request = match self.selected_scan_type {
                                ScanType::Full => ScanRequest::Full,
                                ScanType::Custom => ScanRequest::Custom(self.custom_paths()),
                                _ => ScanRequest::Quick,
                            };
                            action = Some(ScanAction::StartScan(request));
                        }
                    });
                });

            ui.add_space(20.0);

            // Last scan summary
            if let Some(ref summary) = state.last_scan {
                egui::Frame::none()
                    .fill(self.theme.surface)
                    .rounding(Rounding::same(8.0))
                    .inner_margin(20.0)
                    .show(ui, |ui| {
                        ui.set_min_width(250.0);

                        ui.vertical(|ui| {
                            ui.label(self.theme.subheading("Last Scan Results"));
                            ui.add_space(15.0);

                            ui.horizontal(|ui| {
                                ui.label(self.theme.label("Type:"));
                                ui.label(self.theme.value(&format!("{}", summary.scan_type)));
                            });

                            if summary.status == ScanStatus::Cancelled {
                                ui.label(
                                    RichText::new("Cancelled before finishing")
                                        .color(self.theme.warning),
                                );
                            }

                            ui.horizontal(|ui| {
                                ui.label(self.theme.label("Files:"));
                                ui.label(self.theme.value(&summary.files_scanned.to_string()));
                            });

                            ui.horizontal(|ui| {
                                ui.label(self.theme.label("Threats:"));
                                let color = if summary.threats_found > 0 {
                                    self.theme.danger
                                } else {
                                    self.theme.success
                                };
                                ui.label(
                                    RichText::new(summary.threats_found.to_string())
                                        .size(18.0)
                                        .color(color)
                                        .strong(),
                                );
                            });

                            if let Some(duration) = summary.duration_secs() {
                                ui.horizontal(|ui| {
                                    ui.label(self.theme.label("Duration:"));
                                    ui.label(self.theme.value(&format!("{}s", duration)));
                                });
                            }

                            ui.add_space(15.0);

                            if summary.threats_found > 0 && ui.button("View Results").clicked() {
                                action = Some(ScanAction::ViewResults);
                            }
                        });
                    });
            }
        });

        action
    }

    /// Replace the custom path list with picked paths.
    fn set_custom_paths(&mut self, paths: &[PathBuf]) {
        self.custom_paths_text = paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(";");
    }

    /// Parse the semicolon-separated custom path list.
    fn custom_paths(&self) -> Vec<PathBuf> {
        self.custom_paths_text
            .split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect()
    }

    /// Create a scan type radio button.
    fn scan_type_radio(&self, label: &str, selected: bool) -> egui::Button<'_> {
        let text_color = if selected {
            self.theme.primary
        } else {
            self.theme.text_primary
        };

        egui::Button::new(RichText::new(label).size(15.0).color(text_color))
            .fill(if selected {
                self.theme.primary.linear_multiply(0.15)
            } else {
                Color32::TRANSPARENT
            })
            .stroke(if selected {
                egui::Stroke::new(1.0_f32, self.theme.primary)
            } else {
                egui::Stroke::NONE
            })
            .min_size(Vec2::new(200.0, 32.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_view_creation() {
        let _view = ScanView::new(Theme::default());
    }

    #[test]
    fn test_custom_paths_parsing() {
        let mut view = ScanView::new(Theme::default());
        view.custom_paths_text = " /a/b ; ;/c d/e;".to_string();
        assert_eq!(
            view.custom_paths(),
            [PathBuf::from("/a/b"), PathBuf::from("/c d/e")]
        );
    }
}
