//! Remembered addresses: where each paired device was last reachable, so the
//! next connection can try it directly before asking the rendezvous server.
//! Also remembers this PC's own listening port so it stays stable across
//! restarts (otherwise remembered addresses would go stale on every reboot).

use crate::app::App;
use crate::config::{load_json, save_json};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_PER_PEER: usize = 3;
const MAX_AGE_SECS: u64 = 30 * 24 * 3600;
const MAX_FAILURES: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Known {
    addr: SocketAddr,
    last_ok: u64,
    #[serde(default)]
    failures: u32,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Book {
    #[serde(default)]
    peers: HashMap<String, Vec<Known>>,
    /// This PC's last listening port (used when `listen_port` is 0).
    #[serde(default)]
    own_port: Option<u16>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn path(app: &App) -> std::path::PathBuf {
    app.paths.home.join("addresses.json")
}

fn load(app: &App) -> Book {
    load_json(&path(app)).unwrap_or_default()
}

fn save(app: &App, book: &Book) {
    let _ = save_json(&path(app), book);
}

/// Addresses worth trying for this device, most recent first.
pub fn candidates(app: &App, device_id: &str) -> Vec<SocketAddr> {
    let cutoff = now().saturating_sub(MAX_AGE_SECS);
    load(app)
        .peers
        .get(device_id)
        .map(|v| v.iter().filter(|k| k.last_ok >= cutoff).map(|k| k.addr).collect())
        .unwrap_or_default()
}

/// Record a successful direct connection.
pub fn remember(app: &App, device_id: &str, addr: SocketAddr) {
    let mut book = load(app);
    let list = book.peers.entry(device_id.to_string()).or_default();
    list.retain(|k| k.addr != addr);
    list.insert(0, Known { addr, last_ok: now(), failures: 0 });
    list.truncate(MAX_PER_PEER);
    save(app, &book);
}

/// Record that these remembered addresses didn't answer; forget repeat failures.
pub fn failed(app: &App, device_id: &str, addrs: &[SocketAddr]) {
    let mut book = load(app);
    if let Some(list) = book.peers.get_mut(device_id) {
        for k in list.iter_mut().filter(|k| addrs.contains(&k.addr)) {
            k.failures += 1;
        }
        list.retain(|k| k.failures < MAX_FAILURES);
        save(app, &book);
    }
}

/// Forget everything about a device (on unpair).
pub fn forget(app: &App, device_id: &str) {
    let mut book = load(app);
    if book.peers.remove(device_id).is_some() {
        save(app, &book);
    }
}

pub fn own_port(app: &App) -> Option<u16> {
    load(app).own_port
}

pub fn set_own_port(app: &App, port: u16) {
    let mut book = load(app);
    if book.own_port != Some(port) {
        book.own_port = Some(port);
        save(app, &book);
    }
}
