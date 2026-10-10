//! FilePigeon desktop app: runs the background service, lives in the system
//! tray, and asks the user to accept or deny each request in a pop-up window.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod autostart;
mod linkscheme;
mod updates;

use filepigeon::app::App;
use filepigeon::client::{self, Outcome};
use filepigeon::config::{load_json, save_json, simplify_path, Config, Paths, Peer};
use filepigeon::daemon;
use filepigeon::identity::Identity;
use filepigeon::pairing;
use filepigeon::proto::DirEntry;
use filepigeon::ui::{Approval, BoxFuture, TransferState, TransferUpdate, Ui};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::async_runtime::JoinHandle;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State, UserAttentionType, WebviewUrl, WebviewWindow, WebviewWindowBuilder, WindowEvent};
use tauri_plugin_dialog::DialogExt;
use tokio::sync::oneshot;

type CmdResult<T> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// App commands are only for the main window. Approval pop-ups get just the
/// two commands they need, and only for their own request.
fn main_only(window: &WebviewWindow) -> CmdResult<()> {
    if window.label() == "main" {
        Ok(())
    } else {
        Err("not allowed from this window".into())
    }
}

fn main_or_own_popup(window: &WebviewWindow, id: u64) -> CmdResult<()> {
    if window.label() == "main" || window.label() == format!("approve-{id}") {
        Ok(())
    } else {
        Err("not allowed from this window".into())
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Ui implementation: events to the web view, approvals as pop-up windows
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize)]
struct LogLine {
    time: u64,
    text: String,
}

struct PendingApproval {
    approval: Approval,
    deadline: u64,
    /// Has a pop-up window been shown for it? (False while queued by DND.)
    popped: bool,
    reply: Option<oneshot::Sender<bool>>,
}

/// While quiet, requests wait this long (just under the sender's 15-minute
/// limit) so they can be answered after the game or meeting ends.
const DND_WAIT_SECS: u64 = 14 * 60;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default, Debug)]
#[serde(rename_all = "lowercase")]
enum DndMode {
    Off,
    On,
    /// Quiet while Windows reports a full-screen app, game or presentation.
    #[default]
    Auto,
}

/// Desktop-only preferences (the CLI doesn't need these).
#[derive(Serialize, Deserialize, Default)]
struct DesktopPrefs {
    #[serde(default)]
    dnd: DndMode,
}

fn prefs_path() -> Option<PathBuf> {
    Paths::resolve().ok().map(|p| p.home.join("desktop.json"))
}

/// Windows' own "is the user busy?" signal: a full-screen app or game, or
/// presentation mode. Nothing about the screen contents is inspected.
#[cfg(windows)]
fn fullscreen_busy() -> bool {
    #[link(name = "shell32")]
    extern "system" {
        fn SHQueryUserNotificationState(state: *mut i32) -> i32;
    }
    const QUNS_BUSY: i32 = 2;
    const QUNS_RUNNING_D3D_FULL_SCREEN: i32 = 3;
    const QUNS_PRESENTATION_MODE: i32 = 4;
    let mut state = 0;
    // SAFETY: the function only writes one i32 through the pointer we pass.
    let hr = unsafe { SHQueryUserNotificationState(&mut state) };
    hr == 0 && matches!(state, QUNS_BUSY | QUNS_RUNNING_D3D_FULL_SCREEN | QUNS_PRESENTATION_MODE)
}

#[cfg(not(windows))]
fn fullscreen_busy() -> bool {
    false
}

#[derive(Serialize, Clone)]
struct ApprovalItem {
    id: u64,
    approval: Approval,
    seconds_left: u64,
}

struct GuiUi {
    handle: AppHandle,
    pending: Arc<Mutex<HashMap<u64, PendingApproval>>>,
    next_approval: AtomicU64,
    logs: Mutex<VecDeque<LogLine>>,
    transfers: Mutex<HashMap<u64, TransferUpdate>>,
    online: AtomicBool,
    dnd: Mutex<DndMode>,
    /// Last computed "quiet right now" value, to emit changes only.
    quiet: AtomicBool,
    /// The approval pop-up currently on screen; only one at a time, so a peer
    /// can't flood the screen or slide a new prompt under the cursor.
    open_window: Arc<Mutex<Option<u64>>>,
}

impl GuiUi {
    fn new(handle: AppHandle) -> Self {
        let dnd = prefs_path().and_then(|p| load_json::<DesktopPrefs>(&p).ok()).unwrap_or_default().dnd;
        Self {
            handle,
            pending: Default::default(),
            next_approval: AtomicU64::new(1),
            logs: Default::default(),
            transfers: Default::default(),
            online: AtomicBool::new(false),
            dnd: Mutex::new(dnd),
            quiet: AtomicBool::new(false),
            open_window: Default::default(),
        }
    }

    fn toast(&self, kind: &str, text: impl Into<String>) {
        let text = filepigeon::text::display_safe(&text.into(), 300);
        let _ = self.handle.emit("toast", serde_json::json!({ "kind": kind, "text": text }));
    }

    fn dnd_mode(&self) -> DndMode {
        *self.dnd.lock().unwrap()
    }

    fn is_quiet(&self) -> bool {
        match self.dnd_mode() {
            DndMode::Off => false,
            DndMode::On => true,
            DndMode::Auto => fullscreen_busy(),
        }
    }

    fn approvals(&self) -> Vec<ApprovalItem> {
        let now = now_secs();
        let mut items: Vec<_> = self
            .pending
            .lock()
            .unwrap()
            .iter()
            .map(|(id, p)| ApprovalItem { id: *id, approval: p.approval.clone(), seconds_left: p.deadline.saturating_sub(now) })
            .collect();
        items.sort_by_key(|i| i.id);
        items
    }

    /// Push the waiting-request list to the main window and refresh the tray.
    fn approvals_changed(&self) {
        let _ = self.handle.emit("approvals", self.approvals());
        self.update_tray();
    }

    fn update_tray(&self) {
        let Some(tray) = self.handle.tray_by_id("main") else { return };
        let mut tip =
            String::from(if self.online.load(Ordering::Relaxed) { "FilePigeon: online" } else { "FilePigeon: offline" });
        if self.quiet.load(Ordering::Relaxed) {
            tip.push_str(" · do not disturb");
        }
        let waiting = self.pending.lock().unwrap().len();
        if waiting > 0 {
            tip.push_str(&format!(" · {waiting} request{} waiting", if waiting == 1 { "" } else { "s" }));
        }
        let _ = tray.set_tooltip(Some(tip));
    }

    /// Re-check quiet state; when it ends, show pop-ups for queued requests.
    fn refresh_quiet(&self) {
        let quiet = self.is_quiet();
        if self.quiet.swap(quiet, Ordering::Relaxed) != quiet {
            let _ = self.handle.emit("quiet", quiet);
            self.update_tray();
        }
        if !quiet {
            self.show_next();
        }
    }

    /// Show the oldest waiting request, unless a pop-up is already open (the
    /// rest wait their turn here and on the Requests page).
    fn show_next(&self) {
        if self.is_quiet() {
            return;
        }
        let mut open = self.open_window.lock().unwrap();
        if open.is_some() {
            return;
        }
        let next = {
            let mut pending = self.pending.lock().unwrap();
            let id = pending.iter().filter(|(_, p)| !p.popped && p.reply.is_some()).map(|(id, _)| *id).min();
            if let Some(id) = id {
                pending.get_mut(&id).unwrap().popped = true;
            }
            id
        };
        if let Some(id) = next {
            *open = Some(id);
            drop(open);
            open_approval_window(&self.handle, &self.pending, id);
        }
    }
}

/// Resolve a pending approval (first answer wins; later ones are ignored).
fn answer_approval(pending: &Mutex<HashMap<u64, PendingApproval>>, id: u64, accept: bool) {
    if let Some(tx) = pending.lock().unwrap().get_mut(&id).and_then(|p| p.reply.take()) {
        let _ = tx.send(accept);
    }
}

fn open_approval_window(handle: &AppHandle, pending: &Arc<Mutex<HashMap<u64, PendingApproval>>>, id: u64) {
    let window = WebviewWindowBuilder::new(handle, format!("approve-{id}"), WebviewUrl::App("approve.html".into()))
        .title("FilePigeon: incoming request")
        .inner_size(480.0, 460.0)
        .resizable(false)
        .minimizable(false)
        .maximizable(false)
        .always_on_top(true)
        .center()
        .focused(true)
        .build();
    match window {
        Ok(w) => {
            let _ = w.request_user_attention(Some(UserAttentionType::Critical));
            // Closing the pop-up without answering counts as Deny.
            let p = pending.clone();
            w.on_window_event(move |e| {
                if matches!(e, WindowEvent::Destroyed) {
                    answer_approval(&p, id, false);
                }
            });
        }
        // The request stays answerable from the main window's Requests page;
        // free the pop-up slot so later requests still get theirs.
        Err(e) => {
            eprintln!("could not open approval window: {e}");
            let ui = handle.state::<Arc<GuiState>>().ui.clone();
            {
                let mut open = ui.open_window.lock().unwrap();
                if *open == Some(id) {
                    *open = None;
                }
            }
            let _ = handle.emit("toast", serde_json::json!({ "kind": "warn", "text": "A request is waiting on the Requests page." }));
        }
    }
}

impl Ui for GuiUi {
    fn ask(&self, mut approval: Approval) -> BoxFuture<bool> {
        let id = self.next_approval.fetch_add(1, Ordering::Relaxed);
        let quiet = self.is_quiet();
        if quiet {
            approval.timeout_secs = approval.timeout_secs.max(DND_WAIT_SECS);
            self.log(format!("Do not disturb: queued a request from {} (see Requests)", approval.peer));
        }
        let timeout = approval.timeout_secs;
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(
            id,
            PendingApproval { approval, deadline: now_secs() + timeout, popped: false, reply: Some(tx) },
        );
        self.show_next();
        self.approvals_changed();

        let handle = self.handle.clone();
        Box::pin(async move {
            // Runs however this ends: answered, timed out, or abandoned
            // because the other side gave up (the pop-up must not linger).
            let _cleanup = ApprovalCleanup { handle: handle.clone(), id };
            let answer = tokio::time::timeout(Duration::from_secs(timeout), rx).await;
            matches!(answer, Ok(Ok(true)))
        })
    }

    fn log(&self, text: String) {
        let line = LogLine { time: now_secs(), text: filepigeon::text::display_safe(&text, 500) };
        {
            let mut logs = self.logs.lock().unwrap();
            if logs.len() >= 500 {
                logs.pop_front();
            }
            logs.push_back(line.clone());
        }
        let _ = self.handle.emit("log", line);
    }

    fn transfer(&self, update: TransferUpdate) {
        match &update.state {
            TransferState::Done { message } => self.toast("ok", format!("{}: {} ({message})", update.peer, update.name)),
            TransferState::Failed { message } => self.toast("error", format!("{}: {} ({message})", update.peer, update.name)),
            TransferState::Cancelled { .. } => self.toast("warn", format!("Cancelled: {}", update.name)),
            TransferState::Running => {}
        }
        self.transfers.lock().unwrap().insert(update.id, update.clone());
        let _ = self.handle.emit("transfer", update);
    }

    fn online(&self, online: bool) {
        self.online.store(online, Ordering::Relaxed);
        self.update_tray();
        let _ = self.handle.emit("online", online);
    }
}

// ---------------------------------------------------------------------------
// Background service lifecycle
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize)]
struct ServiceStatus {
    /// "setup" | "starting" | "running" | "stopped" | "error"
    state: String,
    message: String,
}

#[derive(Default)]
struct Service {
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

/// Removes a finished (or abandoned) request and its pop-up.
struct ApprovalCleanup {
    handle: AppHandle,
    id: u64,
}

impl Drop for ApprovalCleanup {
    fn drop(&mut self) {
        let ui = self.handle.state::<Arc<GuiState>>().ui.clone();
        ui.pending.lock().unwrap().remove(&self.id);
        if let Some(w) = self.handle.get_webview_window(&format!("approve-{}", self.id)) {
            let _ = w.destroy();
        }
        {
            let mut open = ui.open_window.lock().unwrap();
            if *open == Some(self.id) {
                *open = None;
            }
        }
        ui.show_next();
        ui.approvals_changed();
    }
}

struct GuiState {
    ui: Arc<GuiUi>,
    service: Mutex<Service>,
    status: Mutex<ServiceStatus>,
    pairing: Mutex<Option<JoinHandle<()>>>,
    /// Sends in progress (peer + files), so one can't be started twice.
    sending: Mutex<std::collections::HashSet<String>>,
    updates: updates::Updates,
    /// An invite link FilePigeon was opened with, until the window asks for it.
    invite_link: Mutex<Option<String>>,
    /// Tray "Do not disturb" check items, kept in sync with the mode.
    dnd_items: Mutex<Vec<(DndMode, CheckMenuItem<tauri::Wry>)>>,
    invisible_item: Mutex<Option<CheckMenuItem<tauri::Wry>>>,
}

impl GuiState {
    /// Nothing the user would notice a restart in the middle of: no
    /// transfers, no requests waiting, no pairing, and not in do-not-disturb.
    fn is_idle(&self) -> bool {
        let transferring = self.ui.transfers.lock().unwrap().values().any(|t| matches!(t.state, TransferState::Running));
        let asking = !self.ui.pending.lock().unwrap().is_empty();
        let pairing = self.pairing.lock().unwrap().as_ref().is_some_and(|h| !h.inner().is_finished());
        let sending = !self.sending.lock().unwrap().is_empty();
        !(transferring || asking || pairing || sending || self.ui.quiet.load(Ordering::Relaxed))
    }

    async fn set_invisible(self: &Arc<Self>, invisible: bool) -> Result<(), String> {
        let paths = Paths::resolve().map_err(err)?;
        let mut cfg: Config = load_json(&paths.config()).map_err(err)?;
        cfg.invisible = invisible;
        save_json(&paths.config(), &cfg).map_err(err)?;
        if let Some(item) = self.invisible_item.lock().unwrap().as_ref() {
            let _ = item.set_checked(invisible);
        }
        let _ = self.ui.handle.emit("invisible", invisible);
        self.restart_service().await;
        Ok(())
    }

    fn set_dnd(&self, mode: DndMode) {
        *self.ui.dnd.lock().unwrap() = mode;
        if let Some(path) = prefs_path() {
            let _ = save_json(&path, &DesktopPrefs { dnd: mode });
        }
        for (m, item) in self.dnd_items.lock().unwrap().iter() {
            let _ = item.set_checked(*m == mode);
        }
        let _ = self.ui.handle.emit("dnd", mode);
        self.ui.refresh_quiet();
    }

    fn set_status(&self, state: &str, message: impl Into<String>) {
        let s = ServiceStatus { state: state.into(), message: message.into() };
        *self.status.lock().unwrap() = s.clone();
        let _ = self.ui.handle.emit("status", s);
    }

    async fn stop_service(&self) {
        let (stop, task) = {
            let mut s = self.service.lock().unwrap();
            (s.stop.take(), s.task.take())
        };
        if let Some(stop) = stop {
            let _ = stop.send(());
        }
        if let Some(task) = task {
            let _ = task.await;
        }
    }

    async fn restart_service(self: &Arc<Self>) {
        self.stop_service().await;
        let app = match App::load() {
            Ok(app) => Arc::new(app),
            Err(e) => {
                let configured = Paths::resolve().map(|p| p.config().exists()).unwrap_or(false);
                let msg = if configured { format!("{e:#}") } else { "Finish setup in Settings to go online.".into() };
                self.set_status(if configured { "error" } else { "setup" }, msg);
                return;
            }
        };
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let ui: Arc<dyn Ui> = self.ui.clone();
        let me = self.clone();
        self.set_status("running", "");
        let task = tauri::async_runtime::spawn(async move {
            let shutdown = async {
                let _ = stop_rx.await;
            };
            match daemon::serve(app, ui, shutdown).await {
                Ok(()) => me.set_status("stopped", "Service stopped."),
                Err(e) => me.set_status("error", format!("{e:#}")),
            }
        });
        let mut s = self.service.lock().unwrap();
        s.stop = Some(stop_tx);
        s.task = Some(task);
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
struct Settings {
    device_name: String,
    rendezvous: String,
    /// Only ever sent *to* the app (to replace the key). The key is never
    /// sent to the window: it sees `has_server_key` instead.
    #[serde(default, skip_serializing)]
    rendezvous_key: String,
    #[serde(default)]
    has_server_key: bool,
    #[serde(default)]
    friend_address: String,
    #[serde(default)]
    invite_page: String,
    #[serde(default = "yes")]
    auto_update: bool,
    download_dir: String,
    upnp: bool,
    prompt_timeout_secs: u64,
    listen_port: u16,
    #[serde(default)]
    invisible: bool,
    #[serde(default)]
    dht: bool,
}

#[derive(Serialize)]
struct Share {
    name: String,
    path: String,
}

#[derive(Serialize)]
struct Snapshot {
    configured: bool,
    device_id: Option<String>,
    /// This PC's public key (not secret): what a server admin adds.
    public_key: Option<String>,
    settings: Settings,
    peers: Vec<Peer>,
    shares: Vec<Share>,
    status: ServiceStatus,
    online: bool,
    logs: Vec<LogLine>,
    transfers: Vec<TransferUpdate>,
    dnd: DndMode,
    quiet: bool,
    approvals: Vec<ApprovalItem>,
    autostart: bool,
    version: String,
    update: updates::UpdateView,
}

#[tauri::command]
fn get_state(window: WebviewWindow, state: State<'_, Arc<GuiState>>) -> CmdResult<Snapshot> {
    main_only(&window)?;
    let paths = Paths::resolve().map_err(err)?;
    let configured = paths.config().exists();
    let cfg: Config = load_json(&paths.config()).map_err(err)?;
    let has_server_key = cfg.has_server_key();
    let identity = paths.identity().exists().then(|| Identity::load_or_create(&paths.identity()).ok()).flatten();
    let device_id = identity.as_ref().map(|i| i.device_id());
    let public_key = identity.as_ref().map(|i| hex::encode(i.public_key()));
    let peers: Vec<Peer> = load_json(&paths.peers()).map_err(err)?;
    let shares: filepigeon::config::Shares = load_json(&paths.shares()).map_err(err)?;
    let mut transfers: Vec<_> = state.ui.transfers.lock().unwrap().values().cloned().collect();
    transfers.sort_by_key(|t| std::cmp::Reverse(t.id));
    Ok(Snapshot {
        configured,
        device_id,
        public_key,
        settings: Settings {
            device_name: cfg.device_name,
            rendezvous: cfg.rendezvous,
            rendezvous_key: String::new(),
            has_server_key,
            friend_address: cfg.friend_address,
            invite_page: cfg.invite_page,
            auto_update: cfg.auto_update,
            download_dir: cfg.download_dir.display().to_string(),
            upnp: cfg.upnp,
            prompt_timeout_secs: cfg.prompt_timeout_secs,
            listen_port: cfg.listen_port,
            invisible: cfg.invisible,
            dht: cfg.dht,
        },
        peers,
        shares: shares.into_iter().map(|(name, p)| Share { name, path: p.display().to_string() }).collect(),
        status: state.status.lock().unwrap().clone(),
        online: state.ui.online.load(Ordering::Relaxed),
        logs: state.ui.logs.lock().unwrap().iter().cloned().collect(),
        transfers,
        dnd: state.ui.dnd_mode(),
        quiet: state.ui.quiet.load(Ordering::Relaxed),
        approvals: state.ui.approvals(),
        autostart: autostart::is_enabled(),
        version: state.ui.handle.package_info().version.to_string(),
        update: state.updates.view(&state.ui.handle),
    })
}

#[tauri::command]
fn set_autostart(window: WebviewWindow, enabled: bool) -> CmdResult<()> {
    main_only(&window)?;
    autostart::set(enabled)
}

#[tauri::command]
async fn set_invisible(window: WebviewWindow, state: State<'_, Arc<GuiState>>, invisible: bool) -> CmdResult<()> {
    main_only(&window)?;
    state.inner().set_invisible(invisible).await
}

#[tauri::command]
async fn set_dnd(window: WebviewWindow, state: State<'_, Arc<GuiState>>, mode: DndMode) -> CmdResult<()> {
    main_only(&window)?;
    state.set_dnd(mode);
    Ok(())
}

#[tauri::command]
async fn save_settings(window: WebviewWindow, state: State<'_, Arc<GuiState>>, settings: Settings) -> CmdResult<()> {
    main_only(&window)?;
    let name = settings.device_name.trim();
    if name.is_empty() || name.len() > 64 {
        return Err("Device name must be 1-64 characters.".into());
    }
    // The rendezvous server is optional (local network only without it),
    // but if either field is filled in, both must be valid.
    // An empty key field keeps the saved key (the window never sees it);
    // clearing the address removes both.
    let key = settings.rendezvous_key.trim().to_lowercase();
    let addr = settings.rendezvous.trim();
    if !key.is_empty() {
        filepigeon::app::parse_server_key(&key).map_err(err)?;
    }
    if addr.is_empty() && !key.is_empty() {
        return Err("Enter the server's address too (host:port, e.g. pigeon.example.com:7400).".into());
    }
    if !addr.is_empty() && !addr.contains(':') {
        return Err("Server address must look like host:port, e.g. pigeon.example.com:7400".into());
    }
    let friend_address = settings.friend_address.trim().to_string();
    if !friend_address.is_empty() {
        filepigeon::invites::check_friend_address(&friend_address).map_err(err)?;
    }
    let invite_page = settings.invite_page.trim().to_string();
    if !invite_page.is_empty() && !invite_page.starts_with("https://") {
        return Err("The invite page must start with https://".into());
    }
    let download = PathBuf::from(settings.download_dir.trim());
    if !download.is_absolute() {
        return Err("Choose a full folder path for received files (use Browse…).".into());
    }
    if !(10..=3600).contains(&settings.prompt_timeout_secs) {
        return Err("Prompt timeout must be between 10 and 3600 seconds.".into());
    }
    let paths = Paths::resolve().map_err(err)?;
    let mut cfg: Config = load_json(&paths.config()).map_err(err)?;
    cfg.device_name = name.to_string();
    cfg.rendezvous = addr.to_string();
    if addr.is_empty() {
        cfg.set_server_key("").map_err(err)?;
    } else if !key.is_empty() {
        cfg.set_server_key(&key).map_err(err)?;
    } else if !cfg.has_server_key() {
        return Err("Enter the server key too (or pair with someone who runs a server: their invite sets it up).".into());
    }
    cfg.friend_address = friend_address;
    cfg.invite_page = invite_page;
    cfg.auto_update = settings.auto_update;
    cfg.download_dir = download;
    cfg.upnp = settings.upnp;
    cfg.prompt_timeout_secs = settings.prompt_timeout_secs;
    cfg.listen_port = settings.listen_port;
    cfg.dht = settings.dht;
    save_json(&paths.config(), &cfg).map_err(err)?;
    Identity::load_or_create(&paths.identity()).map_err(err)?;
    state.inner().restart_service().await;
    Ok(())
}

#[tauri::command]
async fn restart_service(window: WebviewWindow, state: State<'_, Arc<GuiState>>) -> CmdResult<()> {
    main_only(&window)?;
    state.inner().restart_service().await;
    Ok(())
}

#[tauri::command]
async fn pick_folder(window: WebviewWindow, app: AppHandle, title: String) -> CmdResult<Option<String>> {
    main_only(&window)?;
    let picked = app.dialog().file().set_title(title).blocking_pick_folder();
    Ok(picked.and_then(|p| p.into_path().ok()).map(|p| p.display().to_string()))
}

#[derive(Serialize)]
struct PairResult {
    peer: Peer,
    notes: Vec<String>,
}

/// After pairing: if this PC was given a server, reconnect through it.
async fn finish_pairing(state: &Arc<GuiState>, paired: pairing::Paired) -> PairResult {
    if paired.server_changed {
        state.restart_service().await;
    }
    PairResult { peer: paired.peer, notes: paired.notes }
}

#[tauri::command]
fn pair_host(window: WebviewWindow, state: State<'_, Arc<GuiState>>, give_server: bool) -> CmdResult<()> {
    main_only(&window)?;
    let app = App::load().map_err(err)?;
    if give_server {
        filepigeon::invites::friend_address(&app).map_err(err)?;
    }
    let handle = state.ui.handle.clone();
    let gui = state.inner().clone();
    if let Some(old) = state.pairing.lock().unwrap().take() {
        old.abort();
    }
    let task = tauri::async_runtime::spawn(async move {
        let h = handle.clone();
        let result = pairing::host(&app, give_server, move |code| {
            let _ = h.emit("pair", serde_json::json!({ "stage": "code", "code": code }));
        })
        .await;
        let event = match result {
            Ok(paired) => serde_json::json!({ "stage": "done", "result": finish_pairing(&gui, paired).await }),
            Err(e) => serde_json::json!({ "stage": "error", "message": format!("{e:#}") }),
        };
        let _ = handle.emit("pair", event);
    });
    *state.pairing.lock().unwrap() = Some(task);
    Ok(())
}

#[tauri::command]
fn pair_cancel(window: WebviewWindow, state: State<'_, Arc<GuiState>>) {
    if main_only(&window).is_err() {
        return;
    }
    if let Some(task) = state.pairing.lock().unwrap().take() {
        task.abort();
    }
}

#[tauri::command]
async fn pair_join(
    window: WebviewWindow,
    state: State<'_, Arc<GuiState>>,
    code: String,
    give_server: bool,
) -> CmdResult<PairResult> {
    main_only(&window)?;
    let app = App::load().map_err(err)?;
    if give_server {
        filepigeon::invites::friend_address(&app).map_err(err)?;
    }
    let paired = pairing::join_any(&app, &code, give_server, &|_| {}).await.map_err(|e| format!("{e:#}"))?;
    Ok(finish_pairing(state.inner(), paired).await)
}

#[derive(Serialize)]
struct InviteLinkView {
    friend: String,
    slot: String,
    expires: u64,
    message: String,
    link: String,
    code: String,
}

/// Make an invite for a friend; returns the message (and link, and code) to send.
#[tauri::command]
async fn invite_link_create(window: WebviewWindow, name: String) -> CmdResult<filepigeon::invites::InviteMessage> {
    main_only(&window)?;
    let app = App::load().map_err(err)?;
    if app.config.invisible {
        return Err("Turn off Invisible first: your PC has to be online for the invite to work.".into());
    }
    let (invite, _) = filepigeon::invites::create_link(&app, &name).await.map_err(|e| format!("{e:#}"))?;
    Ok(invite)
}

#[tauri::command]
fn invite_links_pending(window: WebviewWindow) -> CmdResult<Vec<InviteLinkView>> {
    main_only(&window)?;
    let app = App::load().map_err(err)?;
    Ok(filepigeon::invites::pending(&app)
        .into_iter()
        .map(|p| {
            let m = filepigeon::invites::invite_message(&app, &p.friend, &p.code());
            InviteLinkView { friend: p.friend, slot: p.slot, expires: p.expires, message: m.message, link: m.link, code: m.code }
        })
        .collect())
}

#[derive(Serialize)]
struct InvitePreview {
    address: String,
    words: String,
}

/// What an entered invite points at (or why it isn't one).
#[tauri::command]
fn invite_preview(window: WebviewWindow, text: String) -> CmdResult<InvitePreview> {
    main_only(&window)?;
    match filepigeon::invites::InviteCode::find(&text) {
        Some(Ok(code)) => Ok(InvitePreview { address: code.address.trim_end_matches(":7400").to_string(), words: code.words }),
        Some(Err(e)) => Err(format!("{e:#}")),
        None => Err("That isn't an invite. It should be a link, or a server name followed by five words.".into()),
    }
}

/// The invite link FilePigeon was opened with, if any (asked once by the window).
#[tauri::command]
fn take_invite_link(window: WebviewWindow, state: State<'_, Arc<GuiState>>) -> Option<String> {
    main_only(&window).ok()?;
    state.invite_link.lock().unwrap().take()
}

/// Join with an invite. On a brand-new install, `device_name` sets this PC up
/// first. Progress arrives as "join" events: connecting, check (the words to
/// compare), done, error.
#[tauri::command]
async fn join_invite(
    window: WebviewWindow,
    state: State<'_, Arc<GuiState>>,
    text: String,
    device_name: Option<String>,
) -> CmdResult<()> {
    main_only(&window)?;
    let code = match filepigeon::invites::InviteCode::find(&text) {
        Some(c) => c.map_err(|e| format!("{e:#}"))?,
        None => return Err("That isn't an invite. It should be a link, or a server name followed by five words.".into()),
    };
    let paths = Paths::resolve().map_err(err)?;
    if !paths.config().exists() {
        let name = device_name.unwrap_or_default();
        let name = name.trim();
        if name.is_empty() || name.len() > 64 {
            return Err("Give this PC a name first (1-64 characters).".into());
        }
        let cfg = Config { device_name: name.to_string(), ..Config::default() };
        save_json(&paths.config(), &cfg).map_err(err)?;
        Identity::load_or_create(&paths.identity()).map_err(err)?;
        let _ = autostart::set(true);
    }
    let app = App::load().map_err(err)?;
    let handle = state.ui.handle.clone();
    let gui = state.inner().clone();
    if let Some(old) = state.pairing.lock().unwrap().take() {
        old.abort();
    }
    let task = tauri::async_runtime::spawn(async move {
        let _ = handle.emit("join", serde_json::json!({ "stage": "connecting" }));
        let h = handle.clone();
        let show = move |words: &str| {
            let _ = h.emit("join", serde_json::json!({ "stage": "check", "words": words }));
        };
        let result = pairing::join_invite(&app, &code, &show).await;
        let event = match result {
            Ok(paired) => serde_json::json!({ "stage": "done", "result": finish_pairing(&gui, paired).await }),
            Err(e) => serde_json::json!({ "stage": "error", "message": format!("{e:#}") }),
        };
        let _ = handle.emit("join", event);
    });
    *state.pairing.lock().unwrap() = Some(task);
    Ok(())
}

#[tauri::command]
async fn invite_link_cancel(window: WebviewWindow, slot: String) -> CmdResult<()> {
    main_only(&window)?;
    let app = App::load().map_err(err)?;
    filepigeon::invites::cancel_link(&app, &slot).await.map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn invites_list(window: WebviewWindow) -> CmdResult<Vec<filepigeon::proto::InviteInfo>> {
    main_only(&window)?;
    let app = App::load().map_err(err)?;
    filepigeon::invites::list(&app).await.map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn invite_revoke(window: WebviewWindow, name: String) -> CmdResult<()> {
    main_only(&window)?;
    let app = App::load().map_err(err)?;
    filepigeon::invites::revoke(&app, &name).await.map_err(|e| format!("{e:#}"))?;
    // An unused invite link's temporary key: forget the link too.
    for p in filepigeon::invites::pending(&app).into_iter().filter(|p| p.temp_invite == name) {
        filepigeon::invites::forget_pending(&app, &p.slot);
    }
    // Forget it on the device it was made for, so unpairing won't try again.
    let mut peers = app.peers().map_err(err)?;
    let mut changed = false;
    for p in peers.iter_mut().filter(|p| p.server_invite.as_deref() == Some(name.as_str())) {
        p.server_invite = None;
        changed = true;
    }
    if changed {
        app.save_peers(&peers).map_err(err)?;
    }
    Ok(())
}

/// A native Windows confirmation: the page can't click it or skip it.
fn native_confirm(app: &AppHandle, title: &str, message: &str, ok: &str) -> bool {
    use tauri_plugin_dialog::{MessageDialogButtons, MessageDialogKind};
    app.dialog()
        .message(message)
        .title(title)
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(ok.into(), "Cancel".into()))
        .blocking_show()
}

#[tauri::command]
async fn peer_update(
    window: WebviewWindow,
    app_handle: AppHandle,
    device_id: String,
    name: String,
    allow_browse: bool,
    auto_accept: bool,
    hidden: bool,
) -> CmdResult<()> {
    main_only(&window)?;
    let app = App::load().map_err(err)?;
    let mut peers = app.peers().map_err(err)?;
    let current = peers.iter().find(|p| p.device_id == device_id).ok_or("No such device.")?.clone();
    if auto_accept && !current.auto_accept {
        let ok = native_confirm(
            &app_handle,
            "Turn on auto-accept?",
            &format!(
                "\"{}\" will be able to send you files and download from your shared folders without asking. Only do this for your own devices.",
                current.name
            ),
            "Turn on",
        );
        if !ok {
            return Err("Auto-accept was not turned on.".into());
        }
    }
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("Name cannot be empty.".into());
    }
    if peers.iter().any(|p| p.device_id != device_id && p.name.eq_ignore_ascii_case(&name)) {
        return Err(format!("Another device is already called \"{name}\"."));
    }
    let p = peers.iter_mut().find(|p| p.device_id == device_id).ok_or("No such device.")?;
    p.name = filepigeon::text::clean_name(&name);
    p.allow_browse = allow_browse;
    p.auto_accept = auto_accept;
    p.hidden = hidden;
    app.save_peers(&peers).map_err(err)
}

/// Unpair; also revokes the server key we gave that device, if any.
/// Returns a warning if that revocation failed.
#[tauri::command]
async fn peer_unpair(window: WebviewWindow, device_id: String) -> CmdResult<Option<String>> {
    main_only(&window)?;
    let app = App::load().map_err(err)?;
    let all = app.peers().map_err(err)?;
    let invite = all.iter().find(|p| p.device_id == device_id).and_then(|p| p.server_invite.clone());
    let peers: Vec<_> = all.into_iter().filter(|p| p.device_id != device_id).collect();
    app.save_peers(&peers).map_err(err)?;
    filepigeon::addrbook::forget(&app, &device_id);
    Ok(match invite {
        Some(name) => filepigeon::invites::revoke(&app, &name)
            .await
            .err()
            .map(|e| format!("Couldn't revoke its key to your server ({e:#}). Revoke \"{name}\" under Settings → Friends' keys.")),
        None => None,
    })
}

/// Folders so broad that sharing them deserves a second, native confirmation.
fn is_broad_folder(path: &std::path::Path) -> bool {
    let home = directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf());
    path.parent().is_none()
        || home.as_ref().is_some_and(|h| path == h.as_path() || h.starts_with(path))
}

#[tauri::command]
async fn share_add(window: WebviewWindow, app_handle: AppHandle, name: String, path: String) -> CmdResult<()> {
    main_only(&window)?;
    let app = App::load().map_err(err)?;
    let name = name.trim().to_string();
    if name.is_empty() || name.contains(['/', '\\']) {
        return Err("Share names cannot be empty or contain slashes.".into());
    }
    let path = simplify_path(PathBuf::from(&path).canonicalize().map_err(|_| "Folder not found.")?);
    if !path.is_dir() {
        return Err("That is not a folder.".into());
    }
    if is_broad_folder(&path)
        && !native_confirm(
            &app_handle,
            "Share this whole folder?",
            &format!(
                "{} contains a large part of your computer. Devices you allow could browse and request anything inside it.",
                path.display()
            ),
            "Share it",
        )
    {
        return Err("Not shared.".into());
    }
    let mut shares = app.shares().map_err(err)?;
    if shares.contains_key(&name) {
        return Err(format!("A share called \"{name}\" already exists."));
    }
    shares.insert(name, path);
    app.save_shares(&shares).map_err(err)
}

#[tauri::command]
fn share_remove(window: WebviewWindow, name: String) -> CmdResult<()> {
    main_only(&window)?;
    let app = App::load().map_err(err)?;
    let mut shares = app.shares().map_err(err)?;
    shares.remove(&name);
    app.save_shares(&shares).map_err(err)
}

/// Start sending in the background; progress and results arrive as events.
fn spawn_send(state: &Arc<GuiState>, peer: String, paths: Vec<PathBuf>) -> CmdResult<()> {
    let app = App::load().map_err(err)?;
    let ui = state.ui.clone();
    // The same files to the same device while that send is still going: a
    // double click, not a second send.
    let mut key: Vec<String> = paths.iter().map(|p| p.display().to_string().to_lowercase()).collect();
    key.sort();
    let key = format!("{}|{}", peer.to_lowercase(), key.join("|"));
    if !state.sending.lock().unwrap().insert(key.clone()) {
        return Err(format!("Already sending those to {peer}: see Transfers."));
    }
    let gui = state.clone();
    tauri::async_runtime::spawn(async move {
        // The transfer card reports progress and the outcome; the log keeps a record.
        match client::send(&app, ui.clone(), &peer, &paths).await {
            Ok(Outcome::Done(c)) => ui.log(format!("{peer} received {} file(s).", c.received)),
            Ok(Outcome::Declined(reason)) => ui.log(format!("{peer} declined your files ({reason}).")),
            Err(e) => ui.log(format!("Sending to {peer} failed: {e:#}")),
        }
        gui.sending.lock().unwrap().remove(&key);
    });
    Ok(())
}

fn yes() -> bool {
    true
}

#[tauri::command]
fn update_status(window: WebviewWindow, state: State<'_, Arc<GuiState>>) -> CmdResult<updates::UpdateView> {
    main_only(&window)?;
    Ok(state.updates.view(&state.ui.handle))
}

/// "Check for updates": checks (and downloads) in the background; progress
/// arrives as "update" events.
#[tauri::command]
fn update_check(window: WebviewWindow, state: State<'_, Arc<GuiState>>) -> CmdResult<()> {
    main_only(&window)?;
    let gui = state.inner().clone();
    tauri::async_runtime::spawn(async move {
        let app = gui.ui.handle.clone();
        gui.updates.check(&app).await;
    });
    Ok(())
}

/// "Restart to update". Refused while something is going on.
#[tauri::command]
fn update_install(window: WebviewWindow, state: State<'_, Arc<GuiState>>) -> CmdResult<()> {
    main_only(&window)?;
    if !state.is_idle() {
        return Err("Finish (or cancel) the transfers and requests in progress first.".into());
    }
    state.updates.install(&state.ui.handle)
}

/// Cancel a transfer (the Cancel button on its card).
#[tauri::command]
fn transfer_cancel(window: WebviewWindow, id: u64) -> CmdResult<()> {
    main_only(&window)?;
    if filepigeon::progress::cancel(id) {
        Ok(())
    } else {
        Err("That transfer has already finished.".into())
    }
}

#[tauri::command]
async fn send_pick(window: WebviewWindow, app_handle: AppHandle, state: State<'_, Arc<GuiState>>, peer: String, folder: bool) -> CmdResult<bool> {
    main_only(&window)?;
    let dialog = app_handle.dialog().file().set_title(format!("Send to {peer}"));
    let picked: Vec<PathBuf> = if folder {
        dialog.blocking_pick_folder().into_iter().collect::<Vec<_>>()
    } else {
        dialog.blocking_pick_files().unwrap_or_default()
    }
    .into_iter()
    .filter_map(|p| p.into_path().ok())
    .collect();
    if picked.is_empty() {
        return Ok(false);
    }
    spawn_send(state.inner(), peer, picked)?;
    Ok(true)
}

#[tauri::command]
fn send_paths(window: WebviewWindow, state: State<'_, Arc<GuiState>>, peer: String, paths: Vec<String>) -> CmdResult<()> {
    main_only(&window)?;
    spawn_send(state.inner(), peer, paths.into_iter().map(PathBuf::from).collect())
}

#[tauri::command]
async fn browse(window: WebviewWindow, peer: String, path: String) -> CmdResult<Vec<DirEntry>> {
    main_only(&window)?;
    let app = App::load().map_err(err)?;
    client::browse(&app, &peer, &path).await.map_err(|e| format!("{e:#}"))
}

#[tauri::command]
fn fetch(window: WebviewWindow, state: State<'_, Arc<GuiState>>, peer: String, path: String) -> CmdResult<()> {
    main_only(&window)?;
    let app = App::load().map_err(err)?;
    let ui = state.ui.clone();
    tauri::async_runtime::spawn(async move {
        let dest = app.config.download_dir.clone();
        match client::get(&app, ui.clone(), &peer, &path, &dest).await {
            Ok(Outcome::Done(c)) => ui.log(format!("Received {} file(s) from {peer} into {}", c.received, dest.display())),
            Ok(Outcome::Declined(reason)) => {
                ui.log(format!("{peer} declined your request for \"{path}\" ({reason})."));
                ui.toast("warn", format!("{peer} declined your request."));
            }
            Err(e) => {
                ui.log(format!("Request to {peer} failed: {e:#}"));
                ui.toast("error", format!("Request to {peer} failed: {e:#}"));
            }
        }
    });
    Ok(())
}

#[derive(Serialize)]
struct ApprovalView {
    approval: Approval,
    seconds_left: u64,
}

#[tauri::command]
fn approval_get(window: WebviewWindow, state: State<'_, Arc<GuiState>>, id: u64) -> CmdResult<ApprovalView> {
    main_or_own_popup(&window, id)?;
    let pending = state.ui.pending.lock().unwrap();
    let p = pending.get(&id).ok_or("This request has expired.")?;
    Ok(ApprovalView { approval: p.approval.clone(), seconds_left: p.deadline.saturating_sub(now_secs()) })
}

#[tauri::command]
fn approval_answer(window: WebviewWindow, state: State<'_, Arc<GuiState>>, id: u64, accept: bool) -> CmdResult<()> {
    main_or_own_popup(&window, id)?;
    answer_approval(&state.ui.pending, id, accept);
    Ok(())
}

#[tauri::command]
fn clear_finished(window: WebviewWindow, state: State<'_, Arc<GuiState>>) {
    if main_only(&window).is_err() {
        return;
    }
    state.ui.transfers.lock().unwrap().retain(|_, t| matches!(t.state, TransferState::Running));
}

#[tauri::command]
fn open_downloads_cmd(window: WebviewWindow) -> CmdResult<()> {
    main_only(&window)?;
    open_downloads()
}

fn open_downloads() -> CmdResult<()> {
    let app = App::load().map_err(err)?;
    let dir = app.config.download_dir;
    std::fs::create_dir_all(&dir).map_err(err)?;
    open_in_file_manager(&dir)
}

fn open_in_file_manager(dir: &std::path::Path) -> CmdResult<()> {
    #[cfg(target_os = "windows")]
    let program = "explorer";
    #[cfg(target_os = "macos")]
    let program = "open";
    #[cfg(all(unix, not(target_os = "macos")))]
    let program = "xdg-open";
    std::process::Command::new(program).arg(dir).spawn().map(|_| ()).map_err(err)
}

// ---------------------------------------------------------------------------
// Tray + app wiring
// ---------------------------------------------------------------------------

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open FilePigeon", true, None::<&str>)?;
    let downloads = MenuItem::with_id(app, "downloads", "Open downloads folder", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit FilePigeon", true, None::<&str>)?;
    let state = app.state::<Arc<GuiState>>();
    let current = state.ui.dnd_mode();
    let modes = [
        (DndMode::Off, "dnd-off", "Off"),
        (DndMode::On, "dnd-on", "On"),
        (DndMode::Auto, "dnd-auto", "Automatic (full-screen apps and games)"),
    ];
    let mut items = Vec::new();
    for (mode, id, label) in modes {
        items.push((mode, CheckMenuItem::with_id(app, id, label, true, mode == current, None::<&str>)?));
    }
    let dnd = Submenu::with_items(app, "Do not disturb", true, &[&items[0].1, &items[1].1, &items[2].1])?;
    *state.dnd_items.lock().unwrap() = items;
    let invisible_now = App::load().map(|a| a.config.invisible).unwrap_or(false);
    let invisible = CheckMenuItem::with_id(app, "invisible", "Invisible", true, invisible_now, None::<&str>)?;
    *state.invisible_item.lock().unwrap() = Some(invisible.clone());
    let menu = Menu::with_items(
        app,
        &[&open, &downloads, &PredefinedMenuItem::separator(app)?, &invisible, &dnd, &PredefinedMenuItem::separator(app)?, &quit],
    )?;
    TrayIconBuilder::with_id("main")
        .icon(app.default_window_icon().cloned().expect("app icon"))
        .tooltip("FilePigeon: starting")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_main(app),
            "downloads" => {
                let _ = open_downloads();
            }
            // Off the main thread: turning DND off may open a queued pop-up,
            // and creating windows from a menu handler can deadlock on Windows.
            id @ ("dnd-off" | "dnd-on" | "dnd-auto") => {
                let mode = match id {
                    "dnd-off" => DndMode::Off,
                    "dnd-on" => DndMode::On,
                    _ => DndMode::Auto,
                };
                let state = app.state::<Arc<GuiState>>().inner().clone();
                tauri::async_runtime::spawn(async move { state.set_dnd(mode) });
            }
            "invisible" => {
                let state = app.state::<Arc<GuiState>>().inner().clone();
                tauri::async_runtime::spawn(async move {
                    let now = App::load().map(|a| a.config.invisible).unwrap_or(false);
                    let _ = state.set_invisible(!now).await;
                });
            }
            "quit" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    // Stop cleanly so any router port mapping is removed.
                    app.state::<Arc<GuiState>>().stop_service().await;
                    app.exit(0);
                });
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                show_main(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

fn main() {
    let (relaunched_hidden, updated_from) = updates::after_update();
    let start_hidden = relaunched_hidden || std::env::args().any(|a| a == "--hidden");
    autostart::refresh();
    linkscheme::register();
    tauri::Builder::default()
        // A second launch (e.g. clicking an invite link while FilePigeon is
        // running) hands its arguments to this one.
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            show_main(app);
            if let Some(link) = linkscheme::find_in_args(args) {
                *app.state::<Arc<GuiState>>().invite_link.lock().unwrap() = Some(link.clone());
                let _ = app.emit("invite-link", link);
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(move |app| {
            let ui = Arc::new(GuiUi::new(app.handle().clone()));
            let state = Arc::new(GuiState {
                ui,
                service: Mutex::new(Service::default()),
                status: Mutex::new(ServiceStatus { state: "starting".into(), message: String::new() }),
                pairing: Mutex::new(None),
                sending: Mutex::new(Default::default()),
                updates: Default::default(),
                invite_link: Mutex::new(linkscheme::find_in_args(std::env::args())),
                dnd_items: Mutex::new(Vec::new()),
                invisible_item: Mutex::new(None),
            });
            app.manage(state.clone());
            build_tray(app)?;
            if start_hidden {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.hide();
                }
            }
            // Watch for quiet time ending so queued requests can pop up.
            let watcher = state.clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    watcher.ui.refresh_quiet();
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            });
            {
                let (app, gui) = (app.handle().clone(), state.clone());
                tauri::async_runtime::spawn(async move { updates::run(app, gui).await });
            }
            if let Some(from) = updated_from {
                let gui = state.clone();
                let now = app.package_info().version.to_string();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    gui.ui.log(format!("FilePigeon was updated from {from} to {now}."));
                    gui.ui.toast("ok", format!("FilePigeon updated to {now}."));
                });
            }
            tauri::async_runtime::spawn(async move { state.restart_service().await });
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the main window keeps FilePigeon running in the tray.
            if window.label() == "main" {
                if let WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_state,
            save_settings,
            restart_service,
            pick_folder,
            pair_host,
            pair_cancel,
            pair_join,
            peer_update,
            peer_unpair,
            invites_list,
            invite_revoke,
            invite_link_create,
            transfer_cancel,
            update_status,
            update_check,
            update_install,
            invite_links_pending,
            invite_preview,
            take_invite_link,
            join_invite,
            invite_link_cancel,
            share_add,
            share_remove,
            send_pick,
            send_paths,
            browse,
            fetch,
            approval_get,
            approval_answer,
            set_dnd,
            set_invisible,
            set_autostart,
            clear_finished,
            open_downloads_cmd,
        ])
        .run(tauri::generate_context!())
        .expect("error while running FilePigeon");
}
