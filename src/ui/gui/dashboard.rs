//! Dashboard view component.

use eframe::egui::{self, Color32, RichText, Rounding, Ui, Vec2};

use super::app::{DashboardAction, ScanState};
use super::theme::Theme;
use crate::core::types::ScanStatus;

/// Dashboard view state.
pub struct DashboardView {
    theme: Theme,
}

impl DashboardView {
    /// Create a new dashboard view.
    pub fn new(theme: Theme) -> Self {
        Self { theme }
    }

    /// Use a different theme.
    pub fn set_theme(&mut self, theme: Theme) {
        self.theme = theme;
    }

    /// Render the dashboard.
    pub fn render(
        &mut self,
        ui: &mut Ui,
        scan_state: &ScanState,
        quarantine_count: usize,
    ) -> Option<DashboardAction> {
        let mut action = None;

        ui.vertical(|ui| {
            // Header
            ui.add_space(20.0);
            ui.horizontal(|ui| {
                ui.add_space(20.0);
                ui.label(self.theme.heading("Dashboard"));
            });
            ui.add_space(20.0);

            // Status cards row
            ui.horizontal(|ui| {
                ui.add_space(20.0);

                // System Status card
                if let Some(a) = self.render_status_card(ui, scan_state) {
                    action = Some(a);
                }

                ui.add_space(10.0);

                // Quarantine card
                if let Some(a) = self.render_quarantine_card(ui, quarantine_count) {
                    action = Some(a);
                }

                ui.add_space(10.0);

                // Last Scan card
                if let Some(a) = self.render_last_scan_card(ui, scan_state) {
                    action = Some(a);
                }
            });

            ui.add_space(30.0);

            // Quick actions
            ui.horizontal(|ui| {
                ui.add_space(20.0);
                ui.label(self.theme.subheading("Quick Actions"));
            });
            ui.add_space(10.0);

            ui.horizontal(|ui| {
                ui.add_space(20.0);
                if let Some(a) = self.render_quick_actions(ui, scan_state) {
                    action = Some(a);
                }
            });

            ui.add_space(30.0);

            // Drop zone hint
            ui.horizontal(|ui| {
                ui.add_space(20.0);
                self.render_drop_zone(ui);
            });
        });

        action
    }

    /// Render system status card.
    fn render_status_card(&self, ui: &mut Ui, scan_state: &ScanState) -> Option<DashboardAction> {
        // An on-demand scanner can only report what its last scan saw.
        let (status_text, status_color) = match scan_state.last_scan {
            _ if scan_state.is_scanning => ("Scanning...", self.theme.warning),
            None => ("Not scanned yet", self.theme.text_secondary),
            Some(ref s) if s.threats_found > 0 => ("Threats Found", self.theme.danger),
            Some(ref s) if s.status == ScanStatus::Cancelled => {
                ("Last scan incomplete", self.theme.warning)
            }
            Some(_) => ("No threats found", self.theme.success),
        };

        egui::Frame::none()
            .fill(self.theme.surface)
            .rounding(Rounding::same(8.0))
            .inner_margin(20.0)
            .show(ui, |ui| {
                ui.set_min_size(Vec2::new(200.0, 120.0));

                ui.vertical(|ui| {
                    ui.label(self.theme.label("SYSTEM STATUS"));
                    ui.add_space(10.0);

                    // Status indicator
                    ui.horizontal(|ui| {
                        let indicator_size = 16.0;
                        let (rect, _) = ui
                            .allocate_exact_size(Vec2::splat(indicator_size), egui::Sense::hover());
                        ui.painter().circle_filled(
                            rect.center(),
                            indicator_size / 2.0,
                            status_color,
                        );

                        ui.add_space(8.0);
                        ui.label(
                            RichText::new(status_text)
                                .size(18.0)
                                .color(status_color)
                                .strong(),
                        );
                    });

                    if scan_state.is_scanning {
                        ui.add_space(10.0);
                        let bar = match scan_state.total_files {
                            Some(_) => egui::ProgressBar::new(scan_state.progress)
                                .text(format!("{:.0}%", scan_state.progress * 100.0)),
                            None => egui::ProgressBar::new(0.0).text("Discovering files..."),
                        };
                        // A bar takes all available width; keep it inside the card
                        ui.add(bar.desired_width(200.0).animate(true));
                    }
                });
            });

        None
    }

    /// Render quarantine card.
    fn render_quarantine_card(&self, ui: &mut Ui, count: usize) -> Option<DashboardAction> {
        let mut action = None;

        egui::Frame::none()
            .fill(self.theme.surface)
            .rounding(Rounding::same(8.0))
            .inner_margin(20.0)
            .show(ui, |ui| {
                ui.set_min_size(Vec2::new(200.0, 120.0));

                ui.vertical(|ui| {
                    ui.label(self.theme.label("QUARANTINE"));
                    ui.add_space(10.0);

                    ui.label(self.theme.large_value(&count.to_string()));
                    ui.label(self.theme.subheading(if count == 1 {
                        "item quarantined"
                    } else {
                        "items quarantined"
                    }));

                    ui.add_space(10.0);

                    if count > 0
                        && ui
                            .small_button("View Quarantine")
                            .on_hover_text("Manage quarantined files")
                            .clicked()
                    {
                        action = Some(DashboardAction::ViewQuarantine);
                    }
                });
            });

        action
    }

    /// Render last scan card.
    fn render_last_scan_card(
        &self,
        ui: &mut Ui,
        scan_state: &ScanState,
    ) -> Option<DashboardAction> {
        let mut action = None;

        egui::Frame::none()
            .fill(self.theme.surface)
            .rounding(Rounding::same(8.0))
            .inner_margin(20.0)
            .show(ui, |ui| {
                ui.set_min_size(Vec2::new(200.0, 120.0));

                ui.vertical(|ui| {
                    ui.label(self.theme.label("LAST SCAN"));
                    ui.add_space(10.0);

                    if let Some(ref summary) = scan_state.last_scan {
                        let threats = summary.threats_found;
                        let color = if threats > 0 {
                            self.theme.danger
                        } else {
                            self.theme.success
                        };

                        ui.label(
                            RichText::new(format!("{}", threats))
                                .size(32.0)
                                .color(color)
                                .strong(),
                        );
                        ui.label(self.theme.subheading(if threats == 1 {
                            "threat found"
                        } else {
                            "threats found"
                        }));

                        ui.add_space(5.0);
                        ui.label(self.theme.label(&format!(
                            "{} scanned",
                            super::count(summary.files_scanned, "file", "files")
                        )));

                        if ui.small_button("View Details").clicked() {
                            action = Some(DashboardAction::ViewResults);
                        }
                    } else {
                        ui.label(self.theme.value("No scans yet"));
                        ui.label(self.theme.subheading("Run a scan to get started"));
                    }
                });
            });

        action
    }

    /// Render quick action buttons.
    fn render_quick_actions(&self, ui: &mut Ui, scan_state: &ScanState) -> Option<DashboardAction> {
        let mut action = None;
        let is_scanning = scan_state.is_scanning;

        // Quick Scan button
        let quick_btn =
            egui::Button::new(RichText::new("Quick Scan").size(16.0).color(Color32::WHITE))
                .fill(self.theme.primary)
                .min_size(Vec2::new(150.0, 50.0))
                .rounding(Rounding::same(6.0));

        ui.add_enabled_ui(!is_scanning, |ui| {
            if ui
                .add(quick_btn)
                .on_hover_text("Scan common malware locations quickly")
                .clicked()
            {
                action = Some(DashboardAction::StartQuickScan);
            }
        });

        ui.add_space(10.0);

        // Full Scan button
        let full_btn = egui::Button::new(
            RichText::new("Full Scan")
                .size(16.0)
                .color(self.theme.text_primary),
        )
        .fill(self.theme.surface)
        .stroke(egui::Stroke::new(1.0_f32, self.theme.border))
        .min_size(Vec2::new(150.0, 50.0))
        .rounding(Rounding::same(6.0));

        ui.add_enabled_ui(!is_scanning, |ui| {
            if ui
                .add(full_btn)
                .on_hover_text("Comprehensive system scan")
                .clicked()
            {
                action = Some(DashboardAction::StartFullScan);
            }
        });

        action
    }

    /// Render drop zone hint.
    fn render_drop_zone(&self, ui: &mut Ui) {
        // Highlight while files are dragged over the window
        let hovering = ui.ctx().input(|i| !i.raw.hovered_files.is_empty());
        let (stroke_color, text) = if hovering {
            (self.theme.primary, "Release to scan")
        } else {
            (self.theme.border, "Drop files or folders here to scan")
        };
        egui::Frame::none()
            .fill(Color32::TRANSPARENT)
            .stroke(egui::Stroke::new(2.0_f32, stroke_color))
            .rounding(Rounding::same(8.0))
            .inner_margin(30.0)
            .show(ui, |ui| {
                ui.set_min_width(400.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        RichText::new(text)
                            .size(14.0)
                            .color(self.theme.text_secondary),
                    );
                    ui.add_space(5.0);
                    ui.label(
                        RichText::new("or use the buttons above")
                            .size(12.0)
                            .color(self.theme.text_secondary.linear_multiply(0.7)),
                    );
                });
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dashboard_creation() {
        let _dashboard = DashboardView::new(Theme::default());
    }
}
