//! Finding paired devices on the local network, with no server involved.
//!
//! Privacy by design: nobody broadcasts "I'm here". A device looking for a
//! peer sends a lookup carrying a fresh nonce, a timestamp and a MAC keyed by
//! the secret only that pair of devices shares (X25519 on their pinned keys),
//! bound to the device being looked for. To anyone else it is random bytes,
//! never linkable across lookups, and it can't be forged by someone who merely
//! knows a public key. A device answers only if the MAC is valid for one of its
//! paired, non-hidden peers, and only while it is visible. The answer is itself
//! MACed, so a stranger on the network can't redirect the lookup.
//!
//! The same port carries pairing lookups ("who is showing nameplate 42?").
//! Those can't be authenticated yet (that's what pairing is for); SPAKE2 makes
//! an impostor's answer useless.

use crate::app::App;
use crate::config::Peer;
use crate::peergate::PeerKeys;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;

pub const LAN_PORT: u16 = 47400;
/// Lookups older (or newer) than this are ignored, limiting replays.
const MAX_SKEW_SECS: u64 = 300;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "t")]
enum LanMsg {
    Seek { nonce: String, ts: u64, mac: String },
    Here { nonce: String, port: u16, mac: String },
    PairSeek { nonce: String, nameplate: u32 },
    PairHere { nonce: String, port: u16 },
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn lan_key(pair_secret: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("filepigeon 2026-10 lan discovery", pair_secret)
}

fn mac(key: &[u8; 32], parts: &[&[u8]]) -> String {
    let mut h = blake3::Hasher::new_keyed(key);
    for p in parts {
        h.update(&(p.len() as u32).to_le_bytes());
        h.update(p);
    }
    hex::encode(&h.finalize().as_bytes()[..16])
}

fn seek_mac(key: &[u8; 32], nonce: &str, ts: u64, target: &[u8; 32]) -> String {
    mac(key, &[b"seek", nonce.as_bytes(), &ts.to_le_bytes(), target])
}

fn here_mac(key: &[u8; 32], nonce: &str, port: u16, responder: &[u8; 32]) -> String {
    mac(key, &[b"here", nonce.as_bytes(), &port.to_le_bytes(), responder])
}

/// Constant-time comparison of two hex MACs.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn new_nonce() -> String {
    let mut n = [0u8; 16];
    crate::os_random(&mut n);
    hex::encode(n)
}

/// Bind the shared discovery port. Address reuse lets the background service
/// and a pairing session (or several test identities) listen side by side;
/// broadcasts are delivered to all of them.
pub fn bind_shared() -> Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    s.set_broadcast(true)?;
    s.set_nonblocking(true)?;
    s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, LAN_PORT)).into())?;
    Ok(UdpSocket::from_std(s.into())?)
}

async fn ephemeral() -> Result<UdpSocket> {
    let s = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    s.set_broadcast(true)?;
    Ok(s)
}

/// Send to the whole LAN, plus loopback so two identities on one PC work.
async fn broadcast(sock: &UdpSocket, msg: &LanMsg) {
    let bytes = serde_json::to_vec(msg).expect("serializable");
    for target in [Ipv4Addr::BROADCAST, Ipv4Addr::LOCALHOST] {
        let _ = sock.send_to(&bytes, (target, LAN_PORT)).await;
    }
}

/// Ask the local network where `peer` is. Returns its QUIC address once a
/// correctly authenticated answer arrives within `wait`.
pub async fn seek(app: &App, peer: &Peer, wait: Duration) -> Option<SocketAddr> {
    let target = peer.key()?;
    let key = lan_key(&crate::peergate::pair_secret(app, peer).ok()?);
    let sock = ephemeral().await.ok()?;
    let nonce = new_nonce();
    let ts = now();
    let msg = LanMsg::Seek { nonce: nonce.clone(), ts, mac: seek_mac(&key, &nonce, ts, &target) };
    let deadline = Instant::now() + wait;
    let mut buf = [0u8; 2048];
    let mut next_send = Instant::now();
    while Instant::now() < deadline {
        if Instant::now() >= next_send {
            broadcast(&sock, &msg).await;
            next_send = Instant::now() + Duration::from_millis(250);
        }
        let until = next_send.min(deadline);
        if let Ok(Ok((n, src))) = tokio::time::timeout_at(until.into(), sock.recv_from(&mut buf)).await {
            if let Ok(LanMsg::Here { nonce: n2, port, mac }) = serde_json::from_slice(&buf[..n]) {
                // Only the real peer can produce this MAC; ignore anyone else
                // and keep listening.
                if n2 == nonce && port != 0 && same(&mac, &here_mac(&key, &nonce, port, &target)) {
                    return Some(SocketAddr::new(src.ip(), port));
                }
            }
        }
    }
    None
}

/// Answer lookups from paired, non-hidden peers (run by the background service).
/// Lookups meant for other devices (or from strangers) are indistinguishable
/// noise to us and are silently ignored.
pub async fn respond(keys: Arc<PeerKeys>, quic_port: u16) -> Result<()> {
    let sock = bind_shared()?;
    let me = keys.my_public_key();
    let mut seen: HashMap<String, Instant> = HashMap::new();
    let mut buf = [0u8; 2048];
    loop {
        let (n, src) = sock.recv_from(&mut buf).await?;
        let Ok(LanMsg::Seek { nonce, ts, mac }) = serde_json::from_slice(&buf[..n]) else { continue };
        if nonce.len() > 64 || mac.len() != 32 || now().abs_diff(ts) > MAX_SKEW_SECS {
            continue;
        }
        let secrets = keys.secrets();
        let asker = secrets.iter().find(|(_, secret)| same(&mac, &seek_mac(&lan_key(secret), &nonce, ts, &me)));
        let Some((_, secret)) = asker else { continue };
        seen.retain(|_, t| t.elapsed() < Duration::from_secs(MAX_SKEW_SECS * 2));
        if seen.len() > 10_000 || seen.insert(nonce.clone(), Instant::now()).is_some() {
            continue; // already answered, or replayed
        }
        let key = lan_key(secret);
        let reply = LanMsg::Here { mac: here_mac(&key, &nonce, quic_port, &me), nonce, port: quic_port };
        let _ = sock.send_to(&serde_json::to_vec(&reply)?, src).await;
    }
}

/// Pairing host: answer "who has nameplate N?" with our pairing port.
pub async fn answer_pair_seeks(sock: &UdpSocket, nameplate: u32, pair_port: u16) -> Result<()> {
    let mut buf = [0u8; 2048];
    loop {
        let (n, src) = sock.recv_from(&mut buf).await?;
        if let Ok(LanMsg::PairSeek { nonce, nameplate: np }) = serde_json::from_slice(&buf[..n]) {
            if np == nameplate && nonce.len() <= 64 {
                let reply = serde_json::to_vec(&LanMsg::PairHere { nonce, port: pair_port })?;
                let _ = sock.send_to(&reply, src).await;
            }
        }
    }
}

/// Pairing joiner: find a device on the LAN showing `nameplate`.
pub async fn seek_pair(nameplate: u32, wait: Duration) -> Option<SocketAddr> {
    let sock = ephemeral().await.ok()?;
    let nonce = new_nonce();
    let msg = LanMsg::PairSeek { nonce: nonce.clone(), nameplate };
    let deadline = Instant::now() + wait;
    let mut buf = [0u8; 2048];
    let mut next_send = Instant::now();
    while Instant::now() < deadline {
        if Instant::now() >= next_send {
            broadcast(&sock, &msg).await;
            next_send = Instant::now() + Duration::from_millis(250);
        }
        let until = next_send.min(deadline);
        if let Ok(Ok((n, src))) = tokio::time::timeout_at(until.into(), sock.recv_from(&mut buf)).await {
            if let Ok(LanMsg::PairHere { nonce: n2, port }) = serde_json::from_slice(&buf[..n]) {
                if n2 == nonce && port != 0 {
                    return Some(SocketAddr::new(src.ip(), port));
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macs_bind_secret_target_and_time() {
        let (k1, k2) = (lan_key(&[1u8; 32]), lan_key(&[2u8; 32]));
        let (a, b) = ([5u8; 32], [6u8; 32]);
        let m = seek_mac(&k1, "n", 100, &a);
        assert!(same(&m, &seek_mac(&k1, "n", 100, &a)));
        assert!(!same(&m, &seek_mac(&k2, "n", 100, &a)), "different pair secret");
        assert!(!same(&m, &seek_mac(&k1, "n", 101, &a)), "timestamp is authenticated");
        assert!(!same(&m, &seek_mac(&k1, "n", 100, &b)), "bound to the device being looked for");
        assert!(!same(&here_mac(&k1, "n", 7, &a), &here_mac(&k1, "n", 8, &a)), "port is authenticated");
    }
}
