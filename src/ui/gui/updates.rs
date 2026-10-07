//! Signature database status and import.

use eframe::egui::{self, RichText, Ui};

use super::theme::Theme;
use crate::detection::{DatabaseInfo, ImportResult, SignatureDatabase};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};

/// Signature database status shown in the Signatures view, plus importing
/// signature files.
///
/// Online updates are not implemented yet (the CLI says the same), so this
/// only reports real database state and imports local files.
pub struct SignatureUpdater {
    /// Database info from the last refresh
    info: Option<DatabaseInfo>,
    /// Error from the last refresh
    error: Option<String>,
    /// Running import, if any
    import_task: Option<Receiver<Result<ImportResult, String>>>,
    /// Message describing the last import
    last_import: Option<(String, bool)>,
}

impl SignatureUpdater {
    /// Create an updater and read the current database state.
    pub fn new() -> Self {
        let mut updater = Self {
            info: None,
            error: None,
            import_task: None,
            last_import: None,
        };
        updater.refresh();
        updater
    }

    /// Re-read the signature database state.
    pub fn refresh(&mut self) {
        match SignatureDatabase::open_default().and_then(|db| db.info()) {
            Ok(info) => {
                self.info = Some(info);
                self.error = None;
            }
            Err(e) => {
                self.info = None;
                self.error = Some(format!("Cannot read signature database: {}", e));
            }
        }
    }

    /// Whether an import is running.
    pub fn is_busy(&self) -> bool {
        self.import_task.is_some()
    }

    /// Import a signature file on a worker thread.
    pub fn start_import(&mut self, path: PathBuf) {
        if self.import_task.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("signature-import".to_string())
            .spawn(move || {
                let result = SignatureDatabase::open_default()
                    .and_then(|db| db.import_file(&path))
                    .map_err(|e| e.to_string());
                let _ = tx.send(result);
            });
        match spawned {
            Ok(_) => {
                self.import_task = Some(rx);
                self.last_import = None;
            }
            Err(e) => self.last_import = Some((format!("Failed to start import: {}", e), true)),
        }
    }

    /// Handle completion of a running import.
    pub fn poll(&mut self) {
        let Some(ref rx) = self.import_task else {
            return;
        };
        let result = match rx.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => Err("Import failed unexpectedly".to_string()),
        };
        self.import_task = None;
        self.last_import = Some(match result {
            // Nothing usable in the file: report it as a failure with reasons
            Ok(result) if result.imported == 0 && result.skipped > 0 => {
                log::error!("Signature import added nothing: {}", result);
                let reasons: Vec<&str> = result.errors.iter().take(3).map(String::as_str).collect();
                (
                    format!(
                        "No signatures imported ({} skipped): {}",
                        result.skipped,
                        reasons.join("; ")
                    ),
                    true,
                )
            }
            Ok(result) => {
                log::info!("Signature import: {}", result);
                (result.to_string(), result.skipped > 0)
            }
            Err(e) => {
                log::error!("Signature import failed: {}", e);
                (format!("Import failed: {}", e), true)
            }
        });
        self.refresh();
    }

    /// Render the Signatures view.
    pub fn render(&mut self, ui: &mut Ui, theme: &Theme) {
        ui.add_space(20.0);
        ui.label(theme.heading("Signatures"));
        ui.add_space(20.0);

        ui.group(|ui| {
            ui.label(theme.subheading("Signature Database"));
            ui.add_space(10.0);

            if let Some(ref error) = self.error {
                ui.colored_label(theme.danger, error);
            } else if let Some(ref info) = self.info {
                egui::Grid::new("signature_info")
                    .num_columns(2)
                    .spacing([20.0, 6.0])
                    .show(ui, |ui| {
                        ui.label("Version:");
                        ui.label(&info.version);
                        ui.end_row();

                        ui.label("Signatures:");
                        ui.label(format!(
                            "{} ({} hash, {} pattern)",
                            info.signature_count, info.hash_count, info.pattern_count
                        ));
                        ui.end_row();

                        ui.label("Last updated:");
                        ui.label(
                            info.last_updated
                                .map(|t| {
                                    t.with_timezone(&chrono::Local)
                                        .format("%Y-%m-%d %H:%M")
                                        .to_string()
                                })
                                .unwrap_or_else(|| "Never".to_string()),
                        );
                        ui.end_row();
                    });
                ui.add_space(5.0);
                ui.label(theme.label(
                    "Built-in EICAR, YARA and heuristic detection work without signatures.",
                ));
            }
        });

        ui.add_space(20.0);

        ui.horizontal(|ui| {
            let import = ui.add_enabled(
                self.import_task.is_none(),
                egui::Button::new("Import Signature File..."),
            );
            if import.clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .set_title("Import Signatures")
                    .add_filter("Signature file", &["json"])
                    .pick_file()
                {
                    self.start_import(path);
                }
            }
            if ui.button("Refresh").clicked() {
                self.refresh();
            }
            if self.import_task.is_some() {
                ui.spinner();
                ui.label("Importing...");
            }
        });

        if let Some((ref message, is_error)) = self.last_import {
            ui.add_space(10.0);
            let color = if is_error {
                theme.danger
            } else {
                theme.success
            };
            ui.colored_label(color, message);
        }

        ui.add_space(20.0);
        ui.label(
            RichText::new(
                "Online signature updates are not available yet. Import a signature \
                 file (JSON) to add signatures.",
            )
            .color(theme.text_secondary),
        );
    }
}

impl Default for SignatureUpdater {
    fn default() -> Self {
        Self::new()
    }
}
