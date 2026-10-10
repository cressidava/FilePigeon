//! FilePigeon: secure, direct PC-to-PC file transfer.
//!
//! Security model in one paragraph: every device has a long-term Ed25519 key.
//! Devices are paired once with a short one-time code (SPAKE2), which swaps their
//! public keys. From then on every connection is QUIC/TLS 1.3 with *mutual*
//! authentication pinned to those exact keys, so only paired devices can ever
//! complete a handshake. A small rendezvous server helps devices find each other
//! and punch through NAT, but it never sees file data or pairing secrets, and it
//! only reveals a device's address to peers that device has approved.

pub mod access;
pub mod addrbook;
pub mod app;
pub mod client;
pub mod config;
pub mod daemon;
pub mod dht;
pub mod gate;
pub mod identity;
pub mod invites;
pub mod lan;
pub mod netutil;
pub mod pairing;
pub mod peergate;
pub mod progress;
pub mod prompt;
pub mod proto;
pub mod rdv_client;
pub mod secret;
pub mod shares;
pub mod text;
pub mod tls;
pub mod transfer;
pub mod ui;
pub mod upnp;
pub mod wire;
pub mod words;

/// Fill `buf` straight from the operating system's secure random source.
/// Used for every key, nonce and token FilePigeon generates.
pub fn os_random(buf: &mut [u8]) {
    use rand::TryRng;
    rand::rngs::SysRng.try_fill_bytes(buf).expect("the operating system's random source failed");
}
