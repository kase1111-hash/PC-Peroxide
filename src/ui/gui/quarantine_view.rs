//! Quarantine management view component.

#[cfg(feature = "gui")]
use eframe::egui::{self, Color32, RichText, Rounding, Ui, Vec2};

use super::app::QuarantineAction;
use super::theme::Theme;
use crate::quarantine::QuarantineEntry;

/// Quarantine view state.
pub struct QuarantineView {
    theme: Theme,
    /// Search filter
    search_filter: String,
    /// Selected item for details
    selected_item: Option<String>,
    /// Show delete confirmation
    confirm_delete: Option<String>,
    /// Show clear all confirmation
    confirm_clear: bool,
}

impl QuarantineView {
    /// Create a new quarantine view.
    pub fn new(theme: Theme) -> Self {
        Self {
            theme,
            search_filter: String::new(),
            selected_item: None,
            confirm_delete: None,
            confirm_clear: false,
        }
    }

    /// Render the quarantine view.
    pub fn render(&mut self, ui: &mut Ui, items: &[QuarantineEntry]) -> Option<QuarantineAction> {
        let mut action = None;

        ui.vertical(|ui| {
            ui.add_space(20.0);
            ui.horizontal(|ui| {
                ui.add_space(20.0);
                ui.label(self.theme.heading("Quarantine"));
            });
            ui.add_space(20.0);

            // Summary
            action = self.render_summary(ui, items).or(action);
            ui.add_space(20.0);

            // Items list
            action = self.render_items(ui, items).or(action);
        });

        // Confirmations
        action = self.render_confirmations(ui).or(action);

        action
    }

    /// Render quarantine summary.
    fn render_summary(
        &mut self,
        ui: &mut Ui,
        items: &[QuarantineEntry],
    ) -> Option<QuarantineAction> {
        ui.horizontal(|ui| {
            ui.add_space(20.0);

            // Stats card
            egui::Frame::none()
                .fill(self.theme.surface)
                .rounding(Rounding::same(8.0))
                .inner_margin(20.0)
                .show(ui, |ui| {
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(items.len().to_string())
                                    .size(36.0)
                                    .color(if items.is_empty() {
                                        self.theme.success
                                    } else {
                                        self.theme.warning
                                    })
                                    .strong(),
                            );
                            ui.add_space(10.0);
                            ui.label(self.theme.subheading(if items.len() == 1 {
                                "item quarantined"
                            } else {
                                "items quarantined"
                            }));
                        });

                        if !items.is_empty() {
                            ui.add_space(10.0);

                            // Total size
                            let total_size: u64 = items.iter().map(|i| i.original_size).sum();
                            ui.label(
                                self.theme
                                    .label(&format!("Total size: {}", format_size(total_size))),
                            );
                        }
                    });
                });

            ui.add_space(20.0);

            // Actions
            if !items.is_empty() {
                ui.vertical(|ui| {
                    if ui
                        .add(
                            egui::Button::new(RichText::new("Clear All").color(Color32::WHITE))
                                .fill(self.theme.danger)
                                .min_size(Vec2::new(120.0, 36.0)),
                        )
                        .clicked()
                    {
                        self.confirm_clear = true;
                    }
                });
            }
        });

        None
    }

    /// Render quarantine items list.
    fn render_items(&mut self, ui: &mut Ui, items: &[QuarantineEntry]) -> Option<QuarantineAction> {
        let mut action = None;

        ui.horizontal(|ui| {
            ui.add_space(20.0);
            ui.label(self.theme.subheading("Quarantined Files"));
            ui.add_space(20.0);

            // Search
            ui.label("Search:");
            ui.add(egui::TextEdit::singleline(&mut self.search_filter).desired_width(200.0));
        });

        ui.add_space(10.0);

        ui.horizontal(|ui| {
            ui.add_space(20.0);

            egui::Frame::none()
                .fill(self.theme.surface)
                .rounding(Rounding::same(8.0))
                .inner_margin(10.0)
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width() - 40.0);

                    // Filter items
                    let filtered: Vec<_> = items
                        .iter()
                        .filter(|item| {
                            if self.search_filter.is_empty() {
                                return true;
                            }
                            let search = self.search_filter.to_lowercase();
                            item.original_path
                                .display()
                                .to_string()
                                .to_lowercase()
                                .contains(&search)
                                || item.threat_name.to_lowercase().contains(&search)
                        })
                        .collect();

                    if filtered.is_empty() {
                        ui.vertical_centered(|ui| {
                            ui.add_space(40.0);
                            if items.is_empty() {
                                ui.label(
                                    RichText::new("No quarantined items")
                                        .size(18.0)
                                        .color(self.theme.success),
                                );
                                ui.label(self.theme.subheading(
                                    "Threats will appear here after being quarantined.",
                                ));
                            } else {
                                ui.label(self.theme.subheading("No items match your search."));
                            }
                            ui.add_space(40.0);
                        });
                    } else {
                        egui::ScrollArea::vertical()
                            .max_height(400.0)
                            .show(ui, |ui| {
                                // Header
                                ui.horizontal(|ui| {
                                    ui.allocate_ui(Vec2::new(200.0, 20.0), |ui| {
                                        ui.label(self.theme.label("THREAT"));
                                    });
                                    ui.allocate_ui(Vec2::new(250.0, 20.0), |ui| {
                                        ui.label(self.theme.label("ORIGINAL PATH"));
                                    });
                                    ui.allocate_ui(Vec2::new(100.0, 20.0), |ui| {
                                        ui.label(self.theme.label("DATE"));
                                    });
                                    ui.allocate_ui(Vec2::new(80.0, 20.0), |ui| {
                                        ui.label(self.theme.label("SIZE"));
                                    });
                                    ui.label(self.theme.label("ACTIONS"));
                                });
                                ui.separator();

                                // Rows
                                for item in filtered {
                                    let is_selected = self.selected_item.as_ref() == Some(&item.id);
                                    let bg_color = if is_selected {
                                        self.theme.primary.linear_multiply(0.2)
                                    } else {
                                        Color32::TRANSPARENT
                                    };

                                    egui::Frame::none().fill(bg_color).show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            // Threat name
                                            ui.allocate_ui(Vec2::new(200.0, 25.0), |ui| {
                                                if ui
                                                    .selectable_label(
                                                        is_selected,
                                                        &item.threat_name,
                                                    )
                                                    .clicked()
                                                {
                                                    self.selected_item = if is_selected {
                                                        None
                                                    } else {
                                                        Some(item.id.clone())
                                                    };
                                                }
                                            });

                                            // Original path
                                            ui.allocate_ui(Vec2::new(250.0, 25.0), |ui| {
                                                ui.label(
                                                    RichText::new(truncate_path(
                                                        &item.original_path.display().to_string(),
                                                        35,
                                                    ))
                                                    .monospace()
                                                    .size(11.0),
                                                )
                                                .on_hover_text(
                                                    item.original_path.display().to_string(),
                                                );
                                            });

                                            // Date
                                            ui.allocate_ui(Vec2::new(100.0, 25.0), |ui| {
                                                ui.label(
                                                    item.quarantine_date
                                                        .format("%Y-%m-%d")
                                                        .to_string(),
                                                );
                                            });

                                            // Size
                                            ui.allocate_ui(Vec2::new(80.0, 25.0), |ui| {
                                                ui.label(format_size(item.original_size));
                                            });

                                            // Actions
                                            if ui
                                                .add(
                                                    egui::Button::new("Restore")
                                                        .min_size(Vec2::new(60.0, 24.0)),
                                                )
                                                .on_hover_text("Restore file to original location")
                                                .clicked()
                                            {
                                                action = Some(QuarantineAction::Restore(
                                                    item.id.clone(),
                                                ));
                                            }

                                            ui.add_space(5.0);

                                            if ui
                                                .add(
                                                    egui::Button::new(
                                                        RichText::new("Delete")
                                                            .color(self.theme.danger),
                                                    )
                                                    .min_size(Vec2::new(60.0, 24.0)),
                                                )
                                                .on_hover_text("Permanently delete this file")
                                                .clicked()
                                            {
                                                self.confirm_delete = Some(item.id.clone());
                                            }
                                        });
                                    });
                                }
                            });
                    }
                });
        });

        // Selected item details
        if let Some(ref id) = self.selected_item {
            if let Some(item) = items.iter().find(|i| &i.id == id) {
                ui.add_space(20.0);
                ui.horizontal(|ui| {
                    ui.add_space(20.0);
                    self.render_item_detail(ui, item);
                });
            }
        }

        action
    }

    /// Render item details.
    fn render_item_detail(&self, ui: &mut Ui, item: &QuarantineEntry) {
        egui::Frame::none()
            .fill(self.theme.surface)
            .rounding(Rounding::same(8.0))
            .inner_margin(20.0)
            .show(ui, |ui| {
                ui.set_min_width(500.0);

                ui.label(self.theme.subheading("Quarantine Details"));
                ui.add_space(15.0);

                egui::Grid::new("quarantine_details")
                    .num_columns(2)
                    .spacing([20.0, 8.0])
                    .show(ui, |ui| {
                        ui.label(self.theme.label("ID:"));
                        ui.label(RichText::new(&item.id).monospace().size(11.0));
                        ui.end_row();

                        ui.label(self.theme.label("Threat Name:"));
                        ui.label(&item.threat_name);
                        ui.end_row();

                        ui.label(self.theme.label("Original Path:"));
                        ui.label(
                            RichText::new(item.original_path.display().to_string())
                                .monospace()
                                .size(11.0),
                        );
                        ui.end_row();

                        ui.label(self.theme.label("Original Size:"));
                        ui.label(format_size(item.original_size));
                        ui.end_row();

                        ui.label(self.theme.label("Quarantine Date:"));
                        ui.label(item.quarantine_date.format("%Y-%m-%d %H:%M:%S").to_string());
                        ui.end_row();

                        ui.label(self.theme.label("SHA-256:"));
                        ui.label(RichText::new(&item.original_hash).monospace().size(10.0));
                        ui.end_row();

                        if !item.reason.is_empty() {
                            ui.label(self.theme.label("Reason:"));
                            ui.label(&item.reason);
                            ui.end_row();
                        }
                    });
            });
    }

    /// Render confirmation dialogs.
    fn render_confirmations(&mut self, ui: &mut Ui) -> Option<QuarantineAction> {
        let mut action = None;

        // Delete confirmation
        if let Some(ref id) = self.confirm_delete.clone() {
            egui::Window::new("Confirm Delete")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ui.ctx(), |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(10.0);
                        ui.label("Are you sure you want to permanently delete this file?");
                        ui.label(
                            RichText::new("This action cannot be undone.").color(self.theme.danger),
                        );
                        ui.add_space(20.0);

                        ui.horizontal(|ui| {
                            if ui.button("Cancel").clicked() {
                                self.confirm_delete = None;
                            }
                            ui.add_space(20.0);
                            if ui
                                .add(
                                    egui::Button::new(
                                        RichText::new("Delete").color(Color32::WHITE),
                                    )
                                    .fill(self.theme.danger),
                                )
                                .clicked()
                            {
                                action = Some(QuarantineAction::Delete(id.clone()));
                                self.confirm_delete = None;
                            }
                        });
                    });
                });
        }

        // Clear all confirmation
        if self.confirm_clear {
            egui::Window::new("Confirm Clear All")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ui.ctx(), |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(10.0);
                        ui.label("Are you sure you want to delete ALL quarantined files?");
                        ui.label(
                            RichText::new("This action cannot be undone.").color(self.theme.danger),
                        );
                        ui.add_space(20.0);

                        ui.horizontal(|ui| {
                            if ui.button("Cancel").clicked() {
                                self.confirm_clear = false;
                            }
                            ui.add_space(20.0);
                            if ui
                                .add(
                                    egui::Button::new(
                                        RichText::new("Delete All").color(Color32::WHITE),
                                    )
                                    .fill(self.theme.danger),
                                )
                                .clicked()
                            {
                                action = Some(QuarantineAction::DeleteAll);
                                self.confirm_clear = false;
                            }
                        });
                    });
                });
        }

        action
    }
}

/// Format file size for display.
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Truncate a path for display.
fn truncate_path(path: &str, max_len: usize) -> String {
    if path.len() <= max_len {
        path.to_string()
    } else {
        format!("...{}", &path[path.len() - max_len + 3..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quarantine_view_creation() {
        let theme = Theme::default();
        let _view = QuarantineView::new(theme);
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(500), "500 B");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1024 * 1024), "1.00 MB");
    }
}
