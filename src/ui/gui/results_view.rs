//! Scan results view component.

#[cfg(feature = "gui")]
use eframe::egui::{self, Color32, RichText, Rounding, Ui, Vec2};

use super::app::{ExportFormat, ResultsAction};
use super::theme::Theme;
use crate::core::types::{Detection, ScanSummary, Severity};
use std::path::PathBuf;

/// Results view state.
pub struct ResultsView {
    theme: Theme,
    /// Filter by severity
    severity_filter: Option<Severity>,
    /// Search filter
    search_filter: String,
    /// Selected detection for details
    selected_detection: Option<usize>,
    /// Show export dialog
    show_export: bool,
}

impl ResultsView {
    /// Create a new results view.
    pub fn new(theme: Theme) -> Self {
        Self {
            theme,
            severity_filter: None,
            search_filter: String::new(),
            selected_detection: None,
            show_export: false,
        }
    }

    /// Render the results view.
    pub fn render(
        &mut self,
        ui: &mut Ui,
        summary: Option<&ScanSummary>,
        threats: &[Detection],
    ) -> Option<ResultsAction> {
        let mut action = None;

        ui.vertical(|ui| {
            ui.add_space(20.0);
            ui.horizontal(|ui| {
                ui.add_space(20.0);
                ui.label(self.theme.heading("Scan Results"));
            });
            ui.add_space(20.0);

            if let Some(summary) = summary {
                action = self.render_summary(ui, summary).or(action);
                ui.add_space(20.0);
                action = self.render_detections(ui, threats).or(action);
            } else {
                self.render_no_results(ui);
            }
        });

        action
    }

    /// Render scan summary.
    fn render_summary(&mut self, ui: &mut Ui, summary: &ScanSummary) -> Option<ResultsAction> {
        let mut action = None;

        ui.horizontal(|ui| {
            ui.add_space(20.0);

            // Summary cards
            let cards = [
                (
                    "Files Scanned",
                    summary.files_scanned.to_string(),
                    self.theme.text_primary,
                ),
                (
                    "Threats Found",
                    summary.threats_found.to_string(),
                    if summary.threats_found > 0 {
                        self.theme.danger
                    } else {
                        self.theme.success
                    },
                ),
                ("Errors", summary.errors.to_string(), self.theme.warning),
                (
                    "Duration",
                    format!("{}s", summary.duration_secs().unwrap_or(0)),
                    self.theme.text_primary,
                ),
            ];

            for (label, value, color) in cards {
                egui::Frame::none()
                    .fill(self.theme.surface)
                    .rounding(Rounding::same(8.0))
                    .inner_margin(15.0)
                    .show(ui, |ui| {
                        ui.set_min_size(Vec2::new(120.0, 80.0));
                        ui.vertical_centered(|ui| {
                            ui.label(RichText::new(value).size(28.0).color(color).strong());
                            ui.label(self.theme.label(label));
                        });
                    });
                ui.add_space(10.0);
            }

            // Export button
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(20.0);

                egui::ComboBox::from_label("")
                    .selected_text("Export")
                    .show_ui(ui, |ui| {
                        if ui.selectable_label(false, "HTML Report").clicked() {
                            action = Some(ResultsAction::Export(ExportFormat::Html));
                        }
                        if ui.selectable_label(false, "CSV").clicked() {
                            action = Some(ResultsAction::Export(ExportFormat::Csv));
                        }
                        if ui.selectable_label(false, "PDF").clicked() {
                            action = Some(ResultsAction::Export(ExportFormat::Pdf));
                        }
                        if ui.selectable_label(false, "JSON").clicked() {
                            action = Some(ResultsAction::Export(ExportFormat::Json));
                        }
                    });
            });
        });

        action
    }

    /// Render detections list.
    fn render_detections(&mut self, ui: &mut Ui, threats: &[Detection]) -> Option<ResultsAction> {
        let mut action = None;

        ui.horizontal(|ui| {
            ui.add_space(20.0);
            ui.label(self.theme.subheading("Detected Threats"));
        });
        ui.add_space(10.0);

        // Filters
        ui.horizontal(|ui| {
            ui.add_space(20.0);

            // Search
            ui.label("Search:");
            ui.add(egui::TextEdit::singleline(&mut self.search_filter).desired_width(200.0));

            ui.add_space(20.0);

            // Severity filter
            ui.label("Severity:");
            egui::ComboBox::from_id_salt("severity_filter")
                .selected_text(
                    self.severity_filter
                        .map(|s| format!("{:?}", s))
                        .unwrap_or_else(|| "All".to_string()),
                )
                .show_ui(ui, |ui| {
                    if ui
                        .selectable_label(self.severity_filter.is_none(), "All")
                        .clicked()
                    {
                        self.severity_filter = None;
                    }
                    for severity in [
                        Severity::Critical,
                        Severity::High,
                        Severity::Medium,
                        Severity::Low,
                    ] {
                        if ui
                            .selectable_label(
                                self.severity_filter == Some(severity),
                                format!("{:?}", severity),
                            )
                            .clicked()
                        {
                            self.severity_filter = Some(severity);
                        }
                    }
                });
        });

        ui.add_space(10.0);

        // Detections table
        ui.horizontal(|ui| {
            ui.add_space(20.0);

            egui::Frame::none()
                .fill(self.theme.surface)
                .rounding(Rounding::same(8.0))
                .inner_margin(10.0)
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width() - 40.0);

                    // Filter threats
                    let filtered: Vec<_> = threats
                        .iter()
                        .enumerate()
                        .filter(|(_, t)| {
                            // Severity filter
                            if let Some(severity) = self.severity_filter {
                                if t.severity != severity {
                                    return false;
                                }
                            }
                            // Search filter
                            if !self.search_filter.is_empty() {
                                let search = self.search_filter.to_lowercase();
                                if !t.threat_name.to_lowercase().contains(&search)
                                    && !t
                                        .path
                                        .display()
                                        .to_string()
                                        .to_lowercase()
                                        .contains(&search)
                                {
                                    return false;
                                }
                            }
                            true
                        })
                        .collect();

                    if filtered.is_empty() {
                        ui.vertical_centered(|ui| {
                            ui.add_space(40.0);
                            if threats.is_empty() {
                                ui.label(
                                    RichText::new("No threats detected!")
                                        .size(18.0)
                                        .color(self.theme.success),
                                );
                                ui.label(self.theme.subheading("Your system appears to be clean."));
                            } else {
                                ui.label(self.theme.subheading("No threats match your filter."));
                            }
                            ui.add_space(40.0);
                        });
                    } else {
                        egui::ScrollArea::vertical()
                            .max_height(400.0)
                            .show(ui, |ui| {
                                // Header
                                ui.horizontal(|ui| {
                                    ui.allocate_ui(Vec2::new(80.0, 20.0), |ui| {
                                        ui.label(self.theme.label("SEVERITY"));
                                    });
                                    ui.allocate_ui(Vec2::new(200.0, 20.0), |ui| {
                                        ui.label(self.theme.label("THREAT NAME"));
                                    });
                                    ui.allocate_ui(Vec2::new(300.0, 20.0), |ui| {
                                        ui.label(self.theme.label("PATH"));
                                    });
                                    ui.label(self.theme.label("ACTION"));
                                });
                                ui.separator();

                                // Rows
                                for (idx, threat) in filtered {
                                    let is_selected = self.selected_detection == Some(idx);
                                    let bg_color = if is_selected {
                                        self.theme.primary.linear_multiply(0.2)
                                    } else {
                                        Color32::TRANSPARENT
                                    };

                                    egui::Frame::none().fill(bg_color).show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            // Severity
                                            ui.allocate_ui(Vec2::new(80.0, 25.0), |ui| {
                                                let color = self.theme.severity_color(&format!(
                                                    "{:?}",
                                                    threat.severity
                                                ));
                                                ui.colored_label(
                                                    color,
                                                    format!("{:?}", threat.severity),
                                                );
                                            });

                                            // Threat name
                                            ui.allocate_ui(Vec2::new(200.0, 25.0), |ui| {
                                                if ui
                                                    .selectable_label(
                                                        is_selected,
                                                        &threat.threat_name,
                                                    )
                                                    .clicked()
                                                {
                                                    self.selected_detection =
                                                        if is_selected { None } else { Some(idx) };
                                                }
                                            });

                                            // Path
                                            ui.allocate_ui(Vec2::new(300.0, 25.0), |ui| {
                                                ui.label(
                                                    RichText::new(truncate_path(&threat.path, 40))
                                                        .monospace()
                                                        .size(11.0),
                                                )
                                                .on_hover_text(threat.path.display().to_string());
                                            });

                                            // Actions
                                            if ui.small_button("Quarantine").clicked() {
                                                action = Some(ResultsAction::Quarantine(
                                                    threat.path.clone(),
                                                ));
                                            }
                                        });
                                    });
                                }
                            });
                    }
                });
        });

        // Detail panel for selected detection
        if let Some(idx) = self.selected_detection {
            if let Some(threat) = threats.get(idx) {
                ui.add_space(20.0);
                ui.horizontal(|ui| {
                    ui.add_space(20.0);
                    self.render_detection_detail(ui, threat);
                });
            }
        }

        action
    }

    /// Render detection details.
    fn render_detection_detail(&self, ui: &mut Ui, threat: &Detection) {
        egui::Frame::none()
            .fill(self.theme.surface)
            .rounding(Rounding::same(8.0))
            .inner_margin(20.0)
            .show(ui, |ui| {
                ui.set_min_width(500.0);

                ui.label(self.theme.subheading("Detection Details"));
                ui.add_space(15.0);

                egui::Grid::new("detection_details")
                    .num_columns(2)
                    .spacing([20.0, 8.0])
                    .show(ui, |ui| {
                        ui.label(self.theme.label("Threat Name:"));
                        ui.label(&threat.threat_name);
                        ui.end_row();

                        ui.label(self.theme.label("Severity:"));
                        let color = self.theme.severity_color(&format!("{:?}", threat.severity));
                        ui.colored_label(color, format!("{:?}", threat.severity));
                        ui.end_row();

                        ui.label(self.theme.label("Category:"));
                        ui.label(format!("{:?}", threat.category));
                        ui.end_row();

                        ui.label(self.theme.label("Path:"));
                        ui.label(
                            RichText::new(threat.path.display().to_string())
                                .monospace()
                                .size(11.0),
                        );
                        ui.end_row();

                        if !threat.description.is_empty() {
                            ui.label(self.theme.label("Description:"));
                            ui.label(&threat.description);
                            ui.end_row();
                        }

                        if let Some(ref hash) = threat.sha256 {
                            ui.label(self.theme.label("SHA-256:"));
                            ui.label(RichText::new(hash).monospace().size(10.0));
                            ui.end_row();
                        }

                        ui.label(self.theme.label("Detection Method:"));
                        ui.label(format!("{:?}", threat.method));
                        ui.end_row();

                        ui.label(self.theme.label("Score:"));
                        ui.label(format!("{}", threat.score));
                        ui.end_row();
                    });
            });
    }

    /// Render no results placeholder.
    fn render_no_results(&self, ui: &mut Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(100.0);
            ui.label(
                RichText::new("No Scan Results")
                    .size(24.0)
                    .color(self.theme.text_secondary),
            );
            ui.add_space(10.0);
            ui.label(self.theme.subheading("Run a scan to see results here."));
        });
    }
}

/// Truncate a path for display.
fn truncate_path(path: &PathBuf, max_len: usize) -> String {
    let s = path.display().to_string();
    if s.len() <= max_len {
        s
    } else {
        format!("...{}", &s[s.len() - max_len + 3..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_results_view_creation() {
        let theme = Theme::default();
        let _view = ResultsView::new(theme);
    }

    #[test]
    fn test_truncate_path() {
        let path = PathBuf::from("/very/long/path/to/some/file.exe");
        let truncated = truncate_path(&path, 20);
        assert!(truncated.len() <= 20 || truncated.starts_with("..."));
    }
}
