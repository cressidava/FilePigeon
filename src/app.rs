use crate::config::{load_json, save_json, Config, Paths, Peer, Shares};
use crate::identity::Identity;
use anyhow::{anyhow, bail, Context, Result};
use std::net::SocketAddr;

/// Where the rendezvous server is and how to reach it.
pub struct RdvTarget {
    pub addr: SocketAddr,
    /// The server's identity key (connections are pinned to it).
    pub server_key: [u8; 32],
    /// The secret its stealth gate checks knocks against. Never sent anywhere.
    pub knock_secret: [u8; 32],
}

/// A server key is 128 hex characters: identity key then knock secret, exactly
/// as `pigeon-rendezvous --show-key` prints it.
pub fn parse_server_key(text: &str) -> Result<([u8; 32], [u8; 32])> {
    let clean: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() == 64 {
        bail!("this is an old-format server key; get the new one with `pigeon-rendezvous --show-key` on the server");
    }
    let bytes = hex::decode(&clean).ok().filter(|b| b.len() == 64).ok_or_else(|| {
        anyhow!("server key must be the 128 hex characters printed by `pigeon-rendezvous --show-key`")
    })?;
    Ok((bytes[..32].try_into().unwrap(), bytes[32..].try_into().unwrap()))
}

/// Everything a command needs: paths, config and this device's identity.
pub struct App {
    pub paths: Paths,
    pub config: Config,
    pub identity: Identity,
}

impl App {
    pub fn load() -> Result<Self> {
        let paths = Paths::resolve()?;
        if !paths.config().exists() {
            bail!("FilePigeon is not set up on this PC yet. Run `filepigeon init` first.");
        }
        let config: Config = load_json(&paths.config())?;
        // A relative download folder (including the old default "./FilePigeon")
        // would depend on whatever directory the service starts in: replace it
        // with the proper absolute default and save that.
        let mut config = config;
        if !config.download_dir.is_absolute() {
            config.download_dir = crate::config::default_download_dir();
            let _ = save_json(&paths.config(), &config);
        }
        // A server key saved in plain text (older versions, or typed into the
        // file): encrypt it now, where this platform can.
        if !config.rendezvous_key.is_empty() && cfg!(windows) {
            let plain = config.rendezvous_key.clone();
            if config.set_server_key(&plain).is_ok() {
                let _ = save_json(&paths.config(), &config);
            }
        }
        let identity = Identity::load_or_create(&paths.identity())?;
        Ok(Self { paths, config, identity })
    }

    pub fn peers(&self) -> Result<Vec<Peer>> {
        load_json(&self.paths.peers())
    }

    pub fn save_peers(&self, peers: &[Peer]) -> Result<()> {
        save_json(&self.paths.peers(), peers)
    }

    /// Look a peer up by name (case-insensitive) or device-id prefix.
    pub fn find_peer(&self, query: &str) -> Result<Peer> {
        let peers = self.peers()?;
        if let Some(p) = peers.iter().find(|p| p.name.eq_ignore_ascii_case(query)) {
            return Ok(p.clone());
        }
        let q = query.to_lowercase();
        let matches: Vec<_> = peers.iter().filter(|p| p.device_id.starts_with(&q)).collect();
        match matches.as_slice() {
            [one] => Ok((*one).clone()),
            [] => bail!("no paired peer called {query:?} (see `filepigeon peers`)"),
            _ => bail!("{query:?} matches several peers; be more specific"),
        }
    }

    pub fn peer_by_key(&self, key: &[u8; 32]) -> Result<Option<Peer>> {
        Ok(self.peers()?.into_iter().find(|p| p.key().as_ref() == Some(key)))
    }

    pub fn shares(&self) -> Result<Shares> {
        load_json(&self.paths.shares())
    }

    pub fn save_shares(&self, shares: &Shares) -> Result<()> {
        save_json(&self.paths.shares(), shares)
    }

    /// Resolve the rendezvous server address, its pinned key and knock secret.
    pub async fn rendezvous(&self) -> Result<RdvTarget> {
        if self.config.rendezvous.is_empty() || !self.config.has_server_key() {
            bail!("no rendezvous server configured; run `filepigeon init --rendezvous HOST:PORT --rendezvous-key KEY`");
        }
        let (server_key, knock_secret) = parse_server_key(&self.config.server_key()?)?;
        let addr = resolve_server(&self.config.rendezvous).await?;
        Ok(RdvTarget { addr, server_key, knock_secret })
    }
}

/// Look up a rendezvous server's `host:port` (IPv4).
pub async fn resolve_server(address: &str) -> Result<SocketAddr> {
    tokio::net::lookup_host(address)
        .await
        .with_context(|| format!("cannot resolve {address}"))?
        .find(|a| a.is_ipv4())
        .context("rendezvous server has no IPv4 address")
}

