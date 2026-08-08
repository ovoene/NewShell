//! Native file / folder pickers.
//!
//! `rfd` is a *blocking* GUI call and must never run on the Slint event loop or a
//! tokio worker (it would freeze the UI / stall the runtime). Every helper here
//! therefore either (a) assumes the *caller* is already on a dedicated thread
//! ([`pick_files`] / [`pick_folder`]), or (b) spawns its own thread and bridges
//! the result back over a `tokio::oneshot` ([`pick_files_async`]).
//!
//! Unlike rfd's bare `Option`, [`PickResult`] distinguishes "user cancelled"
//! from "picker failed to open", so callers no longer silently swallow `None`
//! (#dialog-helper). rfd itself collapses cancel and error into `None`, so a
//! plain `None` is reported as [`PickResult::Cancelled`]; the `Error` variant is
//! reserved for genuine failures (e.g. the picker thread being dropped).

use std::path::PathBuf;

/// Outcome of a native picker interaction.
#[derive(Debug, Clone)]
pub enum PickResult<T> {
    /// The user selected something (and it wasn't empty).
    Selected(T),
    /// The user dismissed the dialog (or selected nothing).
    Cancelled,
    /// The native picker could not be shown at all (no GUI, platform error, …).
    Error(String),
}

impl<T> PickResult<T> {
    /// Log the outcome (debug for `Cancelled`, warn for `Error`) and return the
    /// inner value or `None`. Call at a site that previously did
    /// `if let Some(x) = rfd::… { }` so cancel/error are no longer silent.
    pub fn unwrap_or_log(self, what: &str) -> Option<T> {
        match self {
            PickResult::Selected(v) => Some(v),
            PickResult::Cancelled => {
                tracing::debug!("{what}: picker cancelled");
                None
            }
            PickResult::Error(e) => {
                tracing::warn!("{what}: picker error: {e}");
                None
            }
        }
    }
}

fn base_dialog() -> rfd::FileDialog {
    rfd::FileDialog::new().set_title("NewShell")
}

/// Pick one or more files. Must be called from a dedicated thread (see module
/// docs). Returns [`PickResult::Cancelled`] when the dialog is dismissed.
pub fn pick_files() -> PickResult<Vec<PathBuf>> {
    match base_dialog().pick_files() {
        Some(files) if !files.is_empty() => PickResult::Selected(files),
        _ => PickResult::Cancelled,
    }
}

/// Pick a single folder. Must be called from a dedicated thread (see module
/// docs). Returns [`PickResult::Cancelled`] when the dialog is dismissed.
pub fn pick_folder() -> PickResult<PathBuf> {
    match base_dialog().pick_folder() {
        Some(dir) => PickResult::Selected(dir),
        None => PickResult::Cancelled,
    }
}

/// Async bridge for tokio contexts (e.g. the SSH session loop). Spawns a thread
/// to run the blocking picker and resolves with the result.
pub async fn pick_files_async() -> PickResult<Vec<PathBuf>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let _ = tx.send(pick_files());
    });
    match rx.await {
        Ok(r) => r,
        Err(_) => PickResult::Error("picker thread dropped".into()),
    }
}
