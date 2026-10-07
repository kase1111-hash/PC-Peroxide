//! Scan results view component.

use eframe::egui::{self, RichText, Rounding, Ui, Vec2};

use super::app::{ExportFormat, ResultsAction};
use super::theme::Theme;
use crate::core::types::{Detection, ScanStatus, ScanSummary, Severity};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Results view state.
pub struct ResultsView {
    theme: Theme,
    /// Filter by severity
    severity_filter: Option<Severity>,
    /// Search filter
    search_filter: String,
    /// Path of the detection whose details are shown (one detection per file)
    selected_detection: Option<PathBuf>,
}

impl ResultsView {
    /// Create a new results view.
    pub fn new(theme: Theme) -> Self {
        Self {
            theme,
            severity_filter: None,
            search_filter: String::new(),
            selected_detection: None,
        }
    }

    /// Use a different theme.
    pub fn set_theme(&mut self, theme: Theme) {
        self.theme = theme;
    }

    /// Render the results view.
    ///
    /// `quarantined` lists files already moved to quarantine; `busy` disables
    /// quarantine buttons while a vault operation runs.
    pub fn render(
        &mut self,
        ui: &mut Ui,
        summary: Option<&ScanSummary>,
        threats: &[Detection],
        quarantined: &HashSet<PathBuf>,
        allowed: &HashSet<PathBuf>,
        busy: bool,
    ) -> Option<ResultsAction> {
        let mut action = None;

        // The table plus the details panel can exceed the window height
        egui::ScrollArea::vertical()
            .id_source("results_page")
            .show(ui, |ui| {
                ui.vertical(|ui| {
                    ui.add_space(20.0);
                    ui.horizontal(|ui| {
                        ui.add_space(20.0);
                        ui.label(self.theme.heading("Scan Results"));
                    });
                    ui.add_space(20.0);

                    if let Some(summary) = summary {
                        if summary.status == ScanStatus::Cancelled {
                            ui.horizontal(|ui| {
                                ui.add_space(20.0);
                                ui.colored_label(
                            self.theme.warning,
                            "This scan was cancelled before it finished; results are partial.",
                        );
                            });
                            ui.add_space(10.0);
                        }
                        if let Some(a) = self.render_summary(ui, summary) {
                            action = Some(a);
                        }
                        ui.add_space(20.0);
                        let partial = summary.status == ScanStatus::Cancelled;
                        if let Some(a) =
                            self.render_detections(ui, threats, quarantined, allowed, busy, partial)
                        {
                            action = Some(a);
                        }
                    } else {
                        self.render_no_results(ui);
                    }
                });
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
                        // vertical_centered would otherwise take the whole row
                        ui.set_max_width(120.0);
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
    fn render_detections(
        &mut self,
        ui: &mut Ui,
        threats: &[Detection],
        quarantined: &HashSet<PathBuf>,
        allowed: &HashSet<PathBuf>,
        busy: bool,
        partial: bool,
    ) -> Option<ResultsAction> {
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
            egui::ComboBox::from_id_source("severity_filter")
                .selected_text(
                    self.severity_filter
                        .map(|s| s.to_string())
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
                                severity.to_string(),
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
        ui.indent("results_view_1", |ui| {

            egui::Frame::none()
                .fill(self.theme.surface)
                .rounding(Rounding::same(8.0))
                .inner_margin(10.0)
                .show(ui, |ui| {
 ui.vertical(|ui| {
                    ui.set_min_width(ui.available_width() - 40.0);

                    // Filter threats
                    let filtered: Vec<_> = threats
                        .iter()
                        .filter(|t| {
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
                                // A cancelled scan says nothing about the files it skipped
                                ui.label(self.theme.subheading(if partial {
                                    "None of the files scanned before cancelling were flagged."
                                } else {
                                    "None of the scanned files were flagged."
                                }));
                            } else {
                                ui.label(self.theme.subheading("No threats match your filter."));
                            }
                            ui.add_space(40.0);
                        });
                    } else {
                        egui::ScrollArea::vertical()
                            .max_height(400.0)
                            .show(ui, |ui| {
                                // A grid keeps the columns aligned
                                egui::Grid::new("detections_table")
                                    .num_columns(4)
                                    .striped(true)
                                    .spacing([16.0, 6.0])
                                    .show(ui, |ui| {
                                        for header in ["SEVERITY", "THREAT NAME", "PATH", "ACTION"] {
                                            ui.label(self.theme.label(header));
                                        }
                                        ui.end_row();

                                        for threat in filtered {
                                            let is_selected = self.selected_detection.as_ref()
                                                == Some(&threat.path);

                                            let color = self
                                                .theme
                                                .severity_color(&threat.severity.to_string());
                                            ui.colored_label(color, threat.severity.to_string());

                                            if ui
                                                .selectable_label(is_selected, &threat.threat_name)
                                                .on_hover_text("Show details")
                                                .clicked()
                                            {
                                                self.selected_detection = if is_selected {
                                                    None
                                                } else {
                                                    Some(threat.path.clone())
                                                };
                                            }

                                            ui.label(
                                                RichText::new(truncate_path(&threat.path, 60))
                                                    .monospace()
                                                    .size(11.0),
                                            )
                                            .on_hover_text(threat.path.display().to_string());

                                            if quarantined.contains(&threat.path) {
                                                ui.colored_label(self.theme.success, "Quarantined");
                                            } else if allowed.contains(&threat.path) {
                                                ui.colored_label(self.theme.text_secondary, "Allowed");
                                            } else {
                                                ui.horizontal(|ui| {
                                                    if ui
                                                        .add_enabled(
                                                            !busy,
                                                            egui::Button::new("Quarantine").small(),
                                                        )
                                                        .on_hover_text(
                                                            "Move this file into the encrypted quarantine vault",
                                                        )
                                                        .clicked()
                                                    {
                                                        action = Some(ResultsAction::Quarantine(
                                                            threat.clone(),
                                                        ));
                                                    }
                                                    if ui
                                                        .add_enabled(
                                                            !busy,
                                                            egui::Button::new("Allow").small(),
                                                        )
                                                        .on_hover_text(
                                                            "Not a threat: leave the file and stop reporting it",
                                                        )
                                                        .clicked()
                                                    {
                                                        action =
                                                            Some(ResultsAction::Allow(threat.clone()));
                                                    }
                                                });
                                            }
                                            ui.end_row();
                                        }
                                    });
                            });
                    }
                });
});
        });

        // Detail panel for selected detection
        if let Some(ref selected) = self.selected_detection {
            if let Some(threat) = threats.iter().find(|t| &t.path == selected) {
                ui.add_space(20.0);
                ui.indent("results_view_2", |ui| {
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
                        let color = self.theme.severity_color(&threat.severity.to_string());
                        ui.colored_label(color, threat.severity.to_string());
                        ui.end_row();

                        ui.label(self.theme.label("Category:"));
                        ui.label(threat.category.to_string());
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
                        ui.label(threat.method.to_string());
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

/// Truncate a path for display, keeping its end.
fn truncate_path(path: &Path, max_len: usize) -> String {
    super::truncate_start(&path.display().to_string(), max_len)
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
