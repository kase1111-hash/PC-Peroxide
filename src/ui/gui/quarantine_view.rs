//! Quarantine management view component.

use eframe::egui::{self, Color32, RichText, Rounding, Ui, Vec2};

use super::app::QuarantineAction;
use super::theme::Theme;
use crate::quarantine::QuarantineItem;

/// A quarantined item awaiting confirmation of an action.
#[derive(Clone)]
struct Pending {
    id: String,
    detection_name: String,
    path: String,
}

impl Pending {
    fn from_item(item: &QuarantineItem) -> Self {
        Self {
            id: item.id.clone(),
            detection_name: item.detection_name.clone(),
            path: item.original_path.display().to_string(),
        }
    }
}

/// Quarantine view state.
pub struct QuarantineView {
    theme: Theme,
    /// Search filter
    search_filter: String,
    /// Selected item for details
    selected_item: Option<String>,
    /// Show delete confirmation
    confirm_delete: Option<Pending>,
    /// Show restore confirmation
    confirm_restore: Option<Pending>,
    /// Items to delete if "Clear All" is confirmed (those listed when it
    /// was clicked, so items added meanwhile are never deleted unseen)
    confirm_clear: Option<Vec<String>>,
    /// Whether a vault operation is running (actions are disabled)
    busy: bool,
}

impl QuarantineView {
    /// Create a new quarantine view.
    pub fn new(theme: Theme) -> Self {
        Self {
            theme,
            search_filter: String::new(),
            selected_item: None,
            confirm_delete: None,
            confirm_restore: None,
            confirm_clear: None,
            busy: false,
        }
    }

    /// Whether a confirmation dialog is open (row actions are disabled so a
    /// second click cannot silently change what is being confirmed).
    fn confirming(&self) -> bool {
        self.confirm_delete.is_some()
            || self.confirm_restore.is_some()
            || self.confirm_clear.is_some()
    }

    /// Use a different theme.
    pub fn set_theme(&mut self, theme: Theme) {
        self.theme = theme;
    }

    /// Render the quarantine view.
    ///
    /// `error` is shown when the vault could not be read; `busy` disables
    /// actions while a vault operation runs.
    pub fn render(
        &mut self,
        ui: &mut Ui,
        items: &[QuarantineItem],
        error: Option<&str>,
        busy: bool,
    ) -> Option<QuarantineAction> {
        let mut action = None;
        self.busy = busy;

        // The table plus the details panel can exceed the window height
        egui::ScrollArea::vertical()
            .id_source("quarantine_page")
            .show(ui, |ui| {
                ui.vertical(|ui| {
                    ui.add_space(20.0);
                    ui.horizontal(|ui| {
                        ui.add_space(20.0);
                        ui.label(self.theme.heading("Quarantine"));
                        ui.add_space(20.0);
                        if ui.button("Refresh").clicked() {
                            action = Some(QuarantineAction::Refresh);
                        }
                    });
                    ui.add_space(20.0);

                    if let Some(error) = error {
                        ui.horizontal(|ui| {
                            ui.add_space(20.0);
                            ui.colored_label(self.theme.danger, error);
                        });
                        ui.add_space(10.0);
                    }

                    // Summary
                    if let Some(a) = self.render_summary(ui, items) {
                        action = Some(a);
                    }
                    ui.add_space(20.0);

                    // Items list (its actions go through confirmations)
                    self.render_items(ui, items);
                });
            });

        // Confirmations
        if let Some(a) = self.render_confirmations(ui) {
            action = Some(a);
        }

        action
    }

    /// Render quarantine summary.
    fn render_summary(
        &mut self,
        ui: &mut Ui,
        items: &[QuarantineItem],
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
                        .add_enabled(
                            !self.busy && !self.confirming(),
                            egui::Button::new(RichText::new("Clear All").color(Color32::WHITE))
                                .fill(self.theme.danger)
                                .min_size(Vec2::new(120.0, 36.0)),
                        )
                        .clicked()
                    {
                        self.confirm_clear = Some(items.iter().map(|i| i.id.clone()).collect());
                    }
                });
            }
        });

        None
    }

    /// Render quarantine items list.
    fn render_items(&mut self, ui: &mut Ui, items: &[QuarantineItem]) {
        ui.horizontal(|ui| {
            ui.add_space(20.0);
            ui.label(self.theme.subheading("Quarantined Files"));
            ui.add_space(20.0);

            // Search
            ui.label("Search:");
            ui.add(egui::TextEdit::singleline(&mut self.search_filter).desired_width(200.0));
        });

        ui.add_space(10.0);

        ui.indent("quarantine_view_1", |ui| {
            egui::Frame::none()
                .fill(self.theme.surface)
                .rounding(Rounding::same(8.0))
                .inner_margin(10.0)
                .show(ui, |ui| {
                    ui.vertical(|ui| {
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
                                    || item.detection_name.to_lowercase().contains(&search)
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
                                    // A grid keeps the columns aligned
                                    egui::Grid::new("quarantine_table")
                                        .num_columns(5)
                                        .striped(true)
                                        .spacing([16.0, 6.0])
                                        .show(ui, |ui| {
                                            for header in [
                                                "THREAT",
                                                "ORIGINAL PATH",
                                                "DATE",
                                                "SIZE",
                                                "ACTIONS",
                                            ] {
                                                ui.label(self.theme.label(header));
                                            }
                                            ui.end_row();

                                            for item in filtered {
                                                let is_selected =
                                                    self.selected_item.as_ref() == Some(&item.id);

                                                if ui
                                                    .selectable_label(
                                                        is_selected,
                                                        &item.detection_name,
                                                    )
                                                    .on_hover_text("Show details")
                                                    .clicked()
                                                {
                                                    self.selected_item = if is_selected {
                                                        None
                                                    } else {
                                                        Some(item.id.clone())
                                                    };
                                                }

                                                let path = item.original_path.display().to_string();
                                                ui.label(
                                                    RichText::new(truncate_path(&path, 50))
                                                        .monospace()
                                                        .size(11.0),
                                                )
                                                .on_hover_text(&path);

                                                ui.label(
                                                    item.quarantine_time
                                                        .with_timezone(&chrono::Local)
                                                        .format("%Y-%m-%d")
                                                        .to_string(),
                                                );
                                                ui.label(format_size(item.original_size));

                                                ui.horizontal(|ui| {
                                                    let can_act = !self.busy && !self.confirming();
                                                    if ui
                                                        .add_enabled(
                                                            can_act && item.restorable,
                                                            egui::Button::new("Restore"),
                                                        )
                                                        .on_hover_text(
                                                            "Restore file to original location",
                                                        )
                                                        .clicked()
                                                    {
                                                        self.confirm_restore =
                                                            Some(Pending::from_item(item));
                                                    }
                                                    if ui
                                                        .add_enabled(
                                                            can_act,
                                                            egui::Button::new(
                                                                RichText::new("Delete")
                                                                    .color(self.theme.danger),
                                                            ),
                                                        )
                                                        .on_hover_text(
                                                            "Permanently delete this file",
                                                        )
                                                        .clicked()
                                                    {
                                                        self.confirm_delete =
                                                            Some(Pending::from_item(item));
                                                    }
                                                });
                                                ui.end_row();
                                            }
                                        });
                                });
                        }
                    });
                });
        });

        // Selected item details
        if let Some(ref id) = self.selected_item {
            if let Some(item) = items.iter().find(|i| &i.id == id) {
                ui.add_space(20.0);
                ui.indent("quarantine_view_2", |ui| {
                    self.render_item_detail(ui, item);
                });
            }
        }
    }

    /// Render item details.
    fn render_item_detail(&self, ui: &mut Ui, item: &QuarantineItem) {
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
                        ui.label(&item.detection_name);
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
                        ui.label(
                            item.quarantine_time
                                .with_timezone(&chrono::Local)
                                .format("%Y-%m-%d %H:%M:%S")
                                .to_string(),
                        );
                        ui.end_row();

                        ui.label(self.theme.label("SHA-256:"));
                        ui.label(RichText::new(&item.hash_sha256).monospace().size(10.0));
                        ui.end_row();

                        ui.label(self.theme.label("Category:"));
                        ui.label(&item.category);
                        ui.end_row();

                        if let Some(ref notes) = item.notes {
                            ui.label(self.theme.label("Notes:"));
                            ui.label(notes);
                            ui.end_row();
                        }
                    });
            });
    }

    /// Render confirmation dialogs.
    fn render_confirmations(&mut self, ui: &mut Ui) -> Option<QuarantineAction> {
        let mut action = None;

        // Delete confirmation
        if let Some(pending) = self.confirm_restore.clone() {
            egui::Window::new("Confirm Restore")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ui.ctx(), |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(10.0);
                        ui.label(format!(
                            "Restore this file, detected as {}?",
                            pending.detection_name
                        ));
                        ui.label(RichText::new(&pending.path).monospace().size(11.0));
                        ui.label(
                            RichText::new("Only restore files you know are safe.")
                                .color(self.theme.warning),
                        );
                        ui.add_space(20.0);

                        ui.horizontal(|ui| {
                            if ui.button("Cancel").clicked() {
                                self.confirm_restore = None;
                            }
                            ui.add_space(20.0);
                            if ui
                                .add_enabled(!self.busy, egui::Button::new("Restore"))
                                .clicked()
                            {
                                action = Some(QuarantineAction::Restore(pending.id.clone()));
                                self.confirm_restore = None;
                            }
                        });
                    });
                });
        }

        if let Some(pending) = self.confirm_delete.clone() {
            egui::Window::new("Confirm Delete")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ui.ctx(), |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(10.0);
                        ui.label(format!(
                            "Permanently delete this file, detected as {}?",
                            pending.detection_name
                        ));
                        ui.label(RichText::new(&pending.path).monospace().size(11.0));
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
                                .add_enabled(
                                    !self.busy,
                                    egui::Button::new(
                                        RichText::new("Delete").color(Color32::WHITE),
                                    )
                                    .fill(self.theme.danger),
                                )
                                .clicked()
                            {
                                action = Some(QuarantineAction::Delete(pending.id.clone()));
                                self.confirm_delete = None;
                            }
                        });
                    });
                });
        }

        // Clear all confirmation
        if let Some(ids) = self.confirm_clear.clone() {
            egui::Window::new("Confirm Clear All")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ui.ctx(), |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(10.0);
                        ui.label(format!(
                            "Are you sure you want to permanently delete {} quarantined file(s)?",
                            ids.len()
                        ));
                        ui.label(
                            RichText::new("This action cannot be undone.").color(self.theme.danger),
                        );
                        ui.add_space(20.0);

                        ui.horizontal(|ui| {
                            if ui.button("Cancel").clicked() {
                                self.confirm_clear = None;
                            }
                            ui.add_space(20.0);
                            if ui
                                .add_enabled(
                                    !self.busy,
                                    egui::Button::new(
                                        RichText::new("Delete All").color(Color32::WHITE),
                                    )
                                    .fill(self.theme.danger),
                                )
                                .clicked()
                            {
                                action = Some(QuarantineAction::DeleteAll(ids.clone()));
                                self.confirm_clear = None;
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

/// Truncate a path for display, keeping its end.
fn truncate_path(path: &str, max_len: usize) -> String {
    super::truncate_start(path, max_len)
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
