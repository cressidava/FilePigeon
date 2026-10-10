//! The stealth gate on each device's own listener.
//!
//! A device answers nothing at all, not even a TLS handshake, unless the
//! sender first knocks with a key only a currently paired, non-hidden peer can
//! compute: derived from the pair's shared secret (X25519 on their pinned keys)
//! and bound to this device's public key. Strangers, unpaired devices and peers
//! you've hidden from all get exactly what an offline device gives: silence.

use crate::app::App;
use crate::config::{load_json, Peer};
use crate::gate::{make_knock, KnockKeys, KNOCK_LEN};
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Domain-separated knock key for one pair of devices.
fn pair_knock_key(pair_secret: &[u8; 32]) -> [u8; 32] {
    let mut material = b"filepigeon peer knock v1".to_vec();
    material.extend_from_slice(pair_secret);
    blake3::derive_key("filepigeon 2026-10 peer knock", &material)
}

/// What a knock to `target` is bound to.
pub fn knock_context(target_public_key: &[u8; 32]) -> Vec<u8> {
    let mut c = b"filepigeon-peer:".to_vec();
    c.extend_from_slice(target_public_key);
    c
}

/// Makes fresh knocks for reaching `peer` (each knock works only once, so a
/// connection attempt sends a new one every few hundred milliseconds).
pub struct Knocker {
    key: [u8; 32],
    context: Vec<u8>,
}

impl Knocker {
    pub fn new(app: &App, peer: &Peer) -> Result<Self> {
        let their_pk = peer.key().context("invalid peer key")?;
        Ok(Self { key: pair_knock_key(&pair_secret(app, peer)?), context: knock_context(&their_pk) })
    }

    pub fn knock(&self) -> [u8; KNOCK_LEN] {
        make_knock(&self.key, &self.context)
    }
}

/// The keys our own gate accepts: one per paired, non-hidden peer.
pub struct PeerKeys {
    peers_file: PathBuf,
    my_seed: [u8; 32],
    my_pk: [u8; 32],
    cache: Mutex<(Option<Instant>, Arc<Vec<([u8; 32], [u8; 32])>>)>,
}

impl PeerKeys {
    pub fn new(app: &App) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            peers_file: app.paths.peers(),
            my_seed: app.identity.ed25519_seed()?,
            my_pk: app.identity.public_key(),
            cache: Mutex::new((None, Arc::new(Vec::new()))),
        }))
    }

    /// None if peers.json couldn't be read or parsed right now.
    fn compute(&self) -> Option<Vec<([u8; 32], [u8; 32])>> {
        let peers: Vec<Peer> = load_json(&self.peers_file).ok()?;
        let list = peers
            .iter()
            .filter(|p| !p.hidden)
            .filter_map(|p| {
                let pk = p.key()?;
                let secret = crate::dht::pairwise_secret(&self.my_seed, &self.my_pk, &pk).ok()?;
                Some((pk, secret))
            })
            .collect();
        Some(list)
    }

    /// (peer key, pair secret) for every paired, non-hidden peer. Re-read from
    /// peers.json at most once a second, so hiding or unpairing a device takes
    /// effect almost immediately.
    pub fn secrets(&self) -> Arc<Vec<([u8; 32], [u8; 32])>> {
        let mut cache = self.cache.lock().unwrap();
        if cache.0.is_none_or(|t| t.elapsed() > Duration::from_secs(1)) {
            // A momentary read error (antivirus, a half-written edit) must not
            // look like "no trusted peers": keep the last good set.
            if let Some(fresh) = self.compute() {
                cache.1 = Arc::new(fresh);
            }
            cache.0 = Some(Instant::now());
        }
        cache.1.clone()
    }

    pub fn my_public_key(&self) -> [u8; 32] {
        self.my_pk
    }

    /// Is this peer key currently trusted (paired and not hidden)?
    pub fn trusted(&self, owner: &[u8; 32]) -> bool {
        self.secrets().iter().any(|(pk, _)| pk == owner)
    }
}

impl KnockKeys for PeerKeys {
    fn keys(&self) -> Arc<Vec<([u8; 32], [u8; 32])>> {
        Arc::new(self.secrets().iter().map(|(pk, secret)| (*pk, pair_knock_key(secret))).collect())
    }
}

/// Pair secret for one peer, computed from our identity (client side).
pub fn pair_secret(app: &App, peer: &Peer) -> Result<[u8; 32]> {
    let their_pk = peer.key().context("invalid peer key")?;
    crate::dht::pairwise_secret(&app.identity.ed25519_seed()?, &app.identity.public_key(), &their_pk)
}
