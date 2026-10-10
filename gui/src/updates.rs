//! Automatic updates. FilePigeon checks the invite site for a newer version
//! shortly after starting and then every few hours, downloads it in the
//! background, and installs it when nothing is going on (no transfers, no
//! requests waiting, not in do-not-disturb), then restarts itself. Every
//! update must carry a valid signature from the release key, whose public half
//! is built into the app; anything else is refused.

use crate::GuiState;
use filepigeon::config::{load_json, Config, Paths};
use filepigeon::ui::Ui;
use serde::Serialize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_updater::{Update, UpdaterExt};

const FIRST_CHECK: Duration = Duration::from_secs(60);
const CHECK_EVERY: Duration = Duration::from_secs(6 * 3600);
const IDLE_POLL: Duration = Duration::from_secs(60);
/// Marker left before installing when FilePigeon was in the tray, so the new
/// version starts back in the tray instead of popping its window up.
const RELAUNCH_HIDDEN: &str = "relaunch-hidden";
/// Marker holding the version we updated from, for a "Updated to …" note.
const UPDATED_FROM: &str = "updated-from";

#[derive(Debug, Clone, Serialize, Default)]
pub struct UpdateView {
    pub current: String,
    /// idle, checking, up_to_date, downloading, ready, installing, error
    pub stage: String,
    pub available: Option<String>,
    pub notes: Option<String>,
    pub progress: Option<u8>,
    pub error: Option<String>,
    pub last_check: Option<u64>,
    pub auto_install: bool,
}

#[derive(Default)]
pub struct Updates {
    view: Mutex<UpdateView>,
    /// A downloaded, signature-checked update waiting to be installed.
    ready: Mutex<Option<(Update, Vec<u8>)>>,
    busy: tokio::sync::Mutex<()>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn auto_install_enabled() -> bool {
    Paths::resolve().ok().and_then(|p| load_json::<Config>(&p.config()).ok()).map(|c| c.auto_update).unwrap_or(true)
}

impl Updates {
    pub fn view(&self, app: &AppHandle) -> UpdateView {
        let mut v = self.view.lock().unwrap().clone();
        v.current = app.package_info().version.to_string();
        v.auto_install = auto_install_enabled();
        if v.stage.is_empty() {
            v.stage = "idle".into();
        }
        v
    }

    fn set(&self, app: &AppHandle, change: impl FnOnce(&mut UpdateView)) {
        change(&mut self.view.lock().unwrap());
        let _ = app.emit("update", self.view(app));
    }

    /// Check, and download if there's something newer. Returns true when an
    /// update is ready to install.
    pub async fn check(&self, app: &AppHandle) -> bool {
        let _one = self.busy.lock().await;
        if self.ready.lock().unwrap().is_some() {
            return true;
        }
        self.set(app, |v| {
            v.stage = "checking".into();
            v.error = None;
        });
        let found = match app.updater() {
            Ok(u) => u.check().await,
            Err(e) => Err(e),
        };
        let update = match found {
            Ok(Some(u)) => u,
            Ok(None) => {
                self.set(app, |v| {
                    v.stage = "up_to_date".into();
                    v.last_check = Some(now());
                });
                return false;
            }
            Err(e) => {
                self.set(app, |v| {
                    v.stage = "error".into();
                    v.error = Some(format!("Couldn't check for updates: {e}"));
                    v.last_check = Some(now());
                });
                return false;
            }
        };
        let version = update.version.clone();
        let notes = update.body.clone();
        self.set(app, |v| {
            v.stage = "downloading".into();
            v.available = Some(version.clone());
            v.notes = notes.clone();
            v.progress = Some(0);
            v.last_check = Some(now());
        });
        let mut got = 0usize;
        let mut last_pct = 0u8;
        // The plugin verifies the signature against the built-in key as part
        // of the download; a bad or missing signature is an error here.
        let downloaded = update
            .download(
                |chunk, total| {
                    got += chunk;
                    if let Some(total) = total.filter(|t| *t > 0) {
                        let pct = ((got as u64 * 100) / total).min(100) as u8;
                        if pct >= last_pct + 5 {
                            last_pct = pct;
                            self.set(app, |v| v.progress = Some(pct));
                        }
                    }
                },
                || {},
            )
            .await;
        match downloaded {
            Ok(bytes) => {
                *self.ready.lock().unwrap() = Some((update, bytes));
                self.set(app, |v| {
                    v.stage = "ready".into();
                    v.progress = Some(100);
                });
                let gui = app.state::<Arc<GuiState>>();
                gui.ui.log(format!("FilePigeon {version} is downloaded and ready to install."));
                true
            }
            Err(e) => {
                self.set(app, |v| {
                    v.stage = "error".into();
                    v.error = Some(format!("The update couldn't be downloaded or verified: {e}"));
                });
                false
            }
        }
    }

    /// Install the downloaded update and restart. Does nothing if none is ready.
    pub fn install(&self, app: &AppHandle) -> Result<(), String> {
        let Some((update, bytes)) = self.ready.lock().unwrap().take() else {
            return Err("No update is ready yet.".into());
        };
        self.set(app, |v| v.stage = "installing".into());
        if let Ok(paths) = Paths::resolve() {
            let hidden = app.get_webview_window("main").map(|w| !w.is_visible().unwrap_or(false)).unwrap_or(true);
            if hidden {
                let _ = std::fs::write(paths.home.join(RELAUNCH_HIDDEN), b"");
            }
            let _ = std::fs::write(paths.home.join(UPDATED_FROM), app.package_info().version.to_string());
        }
        // Runs the installer and exits; the installer restarts FilePigeon.
        update.install(bytes).map_err(|e| {
            self.set(app, |v| {
                v.stage = "error".into();
                v.error = Some(format!("Installing the update failed: {e}"));
            });
            format!("Installing the update failed: {e}")
        })
    }
}

/// Should this start go straight to the tray because an update relaunched us?
/// Also returns the version we were updated from, if any.
pub fn after_update() -> (bool, Option<String>) {
    let Ok(paths) = Paths::resolve() else { return (false, None) };
    let hidden = std::fs::remove_file(paths.home.join(RELAUNCH_HIDDEN)).is_ok();
    let from = std::fs::read_to_string(paths.home.join(UPDATED_FROM)).ok();
    let _ = std::fs::remove_file(paths.home.join(UPDATED_FROM));
    (hidden, from.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
}

/// The background loop: check, download, and (if allowed) install when idle.
pub async fn run(app: AppHandle, gui: Arc<GuiState>) {
    tokio::time::sleep(FIRST_CHECK).await;
    loop {
        let ready = gui.updates.check(&app).await;
        let mut waited = Duration::ZERO;
        while waited < CHECK_EVERY {
            if ready && auto_install_enabled() && gui.is_idle() {
                // Idle twice in a row a minute apart, so a transfer that is just
                // starting isn't cut off.
                tokio::time::sleep(IDLE_POLL).await;
                if gui.is_idle() && auto_install_enabled() {
                    gui.ui.log("Installing the FilePigeon update; it restarts in a moment.".into());
                    let _ = gui.updates.install(&app);
                }
            }
            tokio::time::sleep(IDLE_POLL).await;
            waited += IDLE_POLL;
        }
    }
}
