//! Router port mapping that only exists while it is needed.
//!
//! Most connections get through with hole punching alone, which leaves no
//! standing hole. UPnP is the fallback: when a paired peer asks to connect we
//! map our UDP port with a short lease, renew it while sessions are active, and
//! delete it as soon as things go idle. If we crash, the lease expires on its own.

use crate::netutil::primary_local_ip;
use crate::ui::Ui;
use anyhow::{Context, Result};
use igd_next::aio::tokio::{search_gateway, Tokio};
use igd_next::aio::Gateway;
use igd_next::{PortMappingProtocol, SearchOptions};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const LEASE_SECS: u32 = 120;
const IDLE_CLOSE: Duration = Duration::from_secs(30);
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(300);
/// After a mapping closed without any real session using it, wait this long
/// before opening another for a mere connection request (so a misbehaving
/// server can't keep a router port open by asking over and over).
const UNUSED_COOLDOWN: Duration = Duration::from_secs(600);

pub struct PortGuard {
    ui: Arc<dyn Ui>,
    enabled: bool,
    local_port: u16,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    mapping: Option<Mapping>,
    active_sessions: usize,
    last_use: Option<Instant>,
    last_failure: Option<Instant>,
    used_since_open: bool,
    unused_closed_at: Option<Instant>,
}

struct Mapping {
    gateway: Gateway<Tokio>,
    external: SocketAddr,
    renewed: Instant,
}

impl PortGuard {
    pub fn new(enabled: bool, local_port: u16, ui: Arc<dyn Ui>) -> Arc<Self> {
        let guard = Arc::new(Self { ui, enabled, local_port, state: Mutex::new(State::default()) });
        if enabled {
            let g = guard.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    g.tick().await;
                }
            });
        }
        guard
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// The current mapping's public address, without creating one or waiting.
    pub async fn current(&self) -> Option<SocketAddr> {
        let st = self.state.try_lock().ok()?;
        st.mapping.as_ref().map(|m| m.external)
    }

    /// Ensure a mapping exists; returns our public address if UPnP worked.
    pub async fn open(&self) -> Option<SocketAddr> {
        if !self.enabled {
            return None;
        }
        let mut st = self.state.lock().await;
        // Repeated requests must not keep an existing mapping alive by
        // themselves: only real sessions do (session_started/ended), so nobody
        // can hold the router port open just by asking to connect.
        if let Some(m) = &st.mapping {
            return Some(m.external);
        }
        st.last_use = Some(Instant::now());
        if st.last_failure.is_some_and(|t| t.elapsed() < RETRY_AFTER_FAILURE)
            || st.unused_closed_at.is_some_and(|t| t.elapsed() < UNUSED_COOLDOWN)
        {
            return None;
        }
        st.used_since_open = false;
        match self.map().await {
            Ok(m) => {
                self.ui.log(format!("[upnp] opened UDP {} on router for this session", m.external));
                let ext = m.external;
                st.mapping = Some(m);
                Some(ext)
            }
            Err(e) => {
                self.ui.log(format!("[upnp] not available ({e:#}); using hole punching only"));
                st.last_failure = Some(Instant::now());
                None
            }
        }
    }

    async fn map(&self) -> Result<Mapping> {
        let mut opts = SearchOptions::default();
        opts.timeout = Some(Duration::from_secs(3));
        let gateway = search_gateway(opts).await.context("no UPnP router found")?;
        let local = SocketAddr::new(primary_local_ip().context("no LAN address")?, self.local_port);
        let ext_ip = gateway.get_external_ip().await?;
        gateway
            .add_port(PortMappingProtocol::UDP, self.local_port, local, LEASE_SECS, "FilePigeon (temporary)")
            .await?;
        Ok(Mapping { gateway, external: SocketAddr::new(ext_ip, self.local_port), renewed: Instant::now() })
    }

    pub async fn session_started(&self) {
        let mut st = self.state.lock().await;
        st.active_sessions += 1;
        st.used_since_open = true;
        st.last_use = Some(Instant::now());
    }

    pub async fn session_ended(&self) {
        let mut st = self.state.lock().await;
        st.active_sessions = st.active_sessions.saturating_sub(1);
        st.last_use = Some(Instant::now());
    }

    async fn tick(&self) {
        let mut st = self.state.lock().await;
        let idle = st.active_sessions == 0 && st.last_use.is_none_or(|t| t.elapsed() > IDLE_CLOSE);
        if idle {
            if let Some(m) = st.mapping.take() {
                if !st.used_since_open {
                    st.unused_closed_at = Some(Instant::now());
                }
                self.unmap(m).await;
            }
        } else if let Some(m) = &mut st.mapping {
            if m.renewed.elapsed() > Duration::from_secs(LEASE_SECS as u64 / 2) {
                let local = primary_local_ip().map(|ip| SocketAddr::new(ip, self.local_port));
                if let Some(local) = local {
                    let _ = m
                        .gateway
                        .add_port(PortMappingProtocol::UDP, self.local_port, local, LEASE_SECS, "FilePigeon (temporary)")
                        .await;
                }
                m.renewed = Instant::now();
            }
        }
    }

    async fn unmap(&self, m: Mapping) {
        match m.gateway.remove_port(PortMappingProtocol::UDP, self.local_port).await {
            Ok(()) => self.ui.log(format!("[upnp] closed UDP {} on router", m.external)),
            Err(e) => self.ui.log(format!("[upnp] could not remove mapping ({e}); it expires within {LEASE_SECS}s")),
        }
    }

    /// Remove any mapping now (used on shutdown).
    pub async fn close(&self) {
        if let Some(m) = self.state.lock().await.mapping.take() {
            self.unmap(m).await;
        }
    }
}
