//! Internet discovery with no server of your own, over the public BitTorrent
//! "mainline" DHT (experimental, off by default).
//!
//! Each pair of devices shares a secret computed from their existing pairing
//! keys (X25519 Diffie-Hellman on the Ed25519 keys), so nothing new has to be
//! exchanged. From it, for each day and direction, both sides derive:
//!   * a throwaway Ed25519 signing key and salt: where the record lives,
//!   * an encryption key: what the record says.
//! DHT nodes therefore see random keys holding encrypted blobs that change
//! every day and can't be tied to a device, to each other, or to yesterday.
//!
//! Two kinds of record, both from one device to one specific peer:
//!   * `addr`: "you can reach me at ..." (republished every few minutes),
//!   * `knock`: "I'm trying to connect from ..." (so the other side punches
//!     back through its router, since there's no server to tell it).

use crate::app::App;
use crate::config::Peer;
use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use curve25519_dalek::edwards::CompressedEdwardsY;
use mainline::{MutableItem, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Address records older than this are ignored (publishers refresh every 10 min).
pub const ADDR_MAX_AGE: u64 = 30 * 60;
/// Knocks older than this are ignored.
pub const KNOCK_MAX_AGE: u64 = 120;

#[derive(Clone, Copy)]
enum Kind {
    Addr,
    Knock,
}

impl Kind {
    fn label(self) -> &'static [u8] {
        match self {
            Kind::Addr => b"addr",
            Kind::Knock => b"knock",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub addrs: Vec<SocketAddr>,
    pub ts: u64,
    /// Random id so a knock is acted on once.
    #[serde(default)]
    pub id: String,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn today() -> u64 {
    now() / 86_400
}

/// Day number records are keyed by (changes at 00:00 UTC).
pub fn current_day() -> u64 {
    today()
}

/// Shared by exactly two paired devices; computed independently by each.
pub fn pairwise_secret(my_seed: &[u8; 32], my_pk: &[u8; 32], their_pk: &[u8; 32]) -> Result<[u8; 32]> {
    // Ed25519 -> X25519: the secret scalar is the clamped first half of SHA-512(seed)
    // (exactly how Ed25519 derives it), and the public point maps to Montgomery form.
    let h = Sha512::digest(my_seed);
    let scalar: [u8; 32] = h[..32].try_into().unwrap();
    let their_point = CompressedEdwardsY(*their_pk)
        .decompress()
        .context("peer key is not a valid curve point")?
        .to_montgomery();
    let shared = their_point.mul_clamped(scalar).to_bytes();
    if shared == [0u8; 32] {
        bail!("degenerate shared secret");
    }
    let (lo, hi) = if my_pk < their_pk { (my_pk, their_pk) } else { (their_pk, my_pk) };
    let mut material = shared.to_vec();
    material.extend_from_slice(lo);
    material.extend_from_slice(hi);
    Ok(blake3::derive_key("filepigeon 2026-10 dht pairwise secret", &material))
}

struct Slot {
    signer: SigningKey,
    salt: [u8; 16],
    enc: [u8; 32],
}

fn slot(secret: &[u8; 32], kind: Kind, from: &[u8; 32], to: &[u8; 32], day: u64) -> Slot {
    let derive = |purpose: &[u8]| -> [u8; 32] {
        let mut h = blake3::Hasher::new_keyed(secret);
        h.update(purpose);
        h.update(kind.label());
        h.update(from);
        h.update(to);
        h.update(&day.to_le_bytes());
        *h.finalize().as_bytes()
    };
    Slot {
        signer: SigningKey::from_bytes(&derive(b"sign")),
        salt: derive(b"salt")[..16].try_into().unwrap(),
        enc: derive(b"enc"),
    }
}

fn seal(key: &[u8; 32], record: &Record) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    crate::os_random(&mut nonce);
    let ct = ChaCha20Poly1305::new(&Key::from(*key))
        .encrypt(&Nonce::from(nonce), serde_json::to_vec(record)?.as_slice())
        .map_err(|_| anyhow!("encryption failed"))?;
    let mut out = nonce.to_vec();
    out.extend(ct);
    anyhow::ensure!(out.len() <= 1000, "record too large for the DHT");
    Ok(out)
}

fn open(key: &[u8; 32], data: &[u8]) -> Option<Record> {
    if data.len() < 12 {
        return None;
    }
    let pt = ChaCha20Poly1305::new(&Key::from(*key))
        .decrypt(&Nonce::try_from(&data[..12]).ok()?, &data[12..])
        .ok()?;
    serde_json::from_slice(&pt).ok()
}

/// A running DHT client.
pub struct DhtNode {
    dht: mainline::async_dht::AsyncDht,
}

impl DhtNode {
    /// Join the public DHT (or a test network named in `FILEPIGEON_DHT_BOOTSTRAP`).
    pub async fn start() -> Result<Self> {
        let mut builder = mainline::Dht::builder();
        if let Ok(list) = std::env::var("FILEPIGEON_DHT_BOOTSTRAP") {
            let nodes: Vec<String> = list.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            // A local test network only answers clients on loopback.
            if nodes.iter().all(|n| n.starts_with("127.")) {
                builder.bind_address(std::net::Ipv4Addr::LOCALHOST);
            }
            builder.bootstrap(&nodes);
        }
        let dht = builder.build().context("could not start DHT client")?.as_async();
        let node = Self { dht };
        if !tokio::time::timeout(Duration::from_secs(15), node.dht.bootstrapped()).await.unwrap_or(false) {
            bail!("could not join the DHT (no internet, or UDP blocked)");
        }
        Ok(node)
    }

    /// Our public IP as seen by other DHT nodes, if known yet.
    pub async fn public_ip(&self) -> Option<IpAddr> {
        self.dht.info().await.public_address().map(|a| IpAddr::V4(*a.ip()))
    }

    async fn put(&self, app: &App, peer: &Peer, kind: Kind, record: &Record) -> Result<()> {
        let (secret, me, them) = keys(app, peer)?;
        let s = slot(&secret, kind, &me, &them, today());
        let value = seal(&s.enc, record)?;
        let item = MutableItem::new(s.signer, &value, record.ts as i64, Some(&s.salt));
        self.dht.put_mutable(item, None).await.map_err(|e| anyhow!("DHT publish failed: {e}"))?;
        Ok(())
    }

    /// Fetch the freshest record `peer` left for us (checking today and
    /// yesterday, since days roll over at different moments for each side).
    async fn get(&self, app: &App, peer: &Peer, kind: Kind, max_age: u64) -> Option<Record> {
        let (secret, me, them) = keys(app, peer).ok()?;
        let mut best: Option<Record> = None;
        for day in [today(), today().saturating_sub(1)] {
            let s = slot(&secret, kind, &them, &me, day);
            let pk = s.signer.verifying_key().to_bytes();
            if let Some(item) = self.dht.get_mutable_most_recent(&pk, Some(&s.salt)).await {
                if let Some(r) = open(&s.enc, item.value()) {
                    if now().saturating_sub(r.ts) <= max_age && best.as_ref().is_none_or(|b| r.ts > b.ts) {
                        best = Some(r);
                    }
                }
            }
            if best.is_some() {
                break;
            }
        }
        best
    }

    pub async fn publish_addrs(&self, app: &App, peer: &Peer, addrs: &[SocketAddr]) -> Result<()> {
        self.put(app, peer, Kind::Addr, &Record { addrs: addrs.to_vec(), ts: now(), id: String::new() }).await
    }

    pub async fn fetch_addrs(&self, app: &App, peer: &Peer) -> Option<Vec<SocketAddr>> {
        self.get(app, peer, Kind::Addr, ADDR_MAX_AGE).await.map(|r| r.addrs)
    }

    pub async fn knock(&self, app: &App, peer: &Peer, my_addrs: &[SocketAddr]) -> Result<()> {
        let mut id = [0u8; 8];
        crate::os_random(&mut id);
        self.put(app, peer, Kind::Knock, &Record { addrs: my_addrs.to_vec(), ts: now(), id: hex::encode(id) }).await
    }

    pub async fn fetch_knock(&self, app: &App, peer: &Peer) -> Option<Record> {
        self.get(app, peer, Kind::Knock, KNOCK_MAX_AGE).await
    }
}

fn keys(app: &App, peer: &Peer) -> Result<([u8; 32], [u8; 32], [u8; 32])> {
    let me = app.identity.public_key();
    let them = peer.key().context("invalid peer key")?;
    let secret = pairwise_secret(&app.identity.ed25519_seed()?, &me, &them)?;
    Ok((secret, me, them))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        ([seed; 32], sk.verifying_key().to_bytes())
    }

    #[test]
    fn both_sides_derive_the_same_secret() {
        let (a_seed, a_pk) = keypair(1);
        let (b_seed, b_pk) = keypair(2);
        let (_, c_pk) = keypair(3);
        let ab = pairwise_secret(&a_seed, &a_pk, &b_pk).unwrap();
        let ba = pairwise_secret(&b_seed, &b_pk, &a_pk).unwrap();
        assert_eq!(ab, ba);
        assert_ne!(ab, pairwise_secret(&a_seed, &a_pk, &c_pk).unwrap(), "different peer, different secret");
    }

    #[test]
    fn slots_differ_by_day_direction_and_kind() {
        let secret = [7u8; 32];
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let pk = |s: Slot| s.signer.verifying_key().to_bytes();
        let base = pk(slot(&secret, Kind::Addr, &a, &b, 100));
        assert_ne!(base, pk(slot(&secret, Kind::Addr, &a, &b, 101)), "new day, new location");
        assert_ne!(base, pk(slot(&secret, Kind::Addr, &b, &a, 100)), "other direction");
        assert_ne!(base, pk(slot(&secret, Kind::Knock, &a, &b, 100)), "other kind");
        assert_eq!(base, pk(slot(&secret, Kind::Addr, &a, &b, 100)));
    }

    #[test]
    fn records_only_open_with_the_right_key() {
        let r = Record { addrs: vec!["1.2.3.4:5".parse().unwrap()], ts: 9, id: "x".into() };
        let sealed = seal(&[1u8; 32], &r).unwrap();
        assert_eq!(open(&[1u8; 32], &sealed).unwrap().addrs, r.addrs);
        assert!(open(&[2u8; 32], &sealed).is_none());
    }

    #[test]
    fn identity_seed_matches_public_key() {
        let dir = std::env::temp_dir().join(format!("fp-dht-seed-{}", std::process::id()));
        let id = crate::identity::Identity::load_or_create(&dir.join("id.pem")).unwrap();
        let seed = id.ed25519_seed().unwrap();
        assert_eq!(SigningKey::from_bytes(&seed).verifying_key().to_bytes(), id.public_key());
        let _ = std::fs::remove_dir_all(dir);
    }
}
