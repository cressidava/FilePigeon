use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

// ---------- device <-> rendezvous server ----------

/// Connection close code: a newer session for the same device replaced this one.
pub const CLOSE_REPLACED: u32 = 2;
/// Connection close code: the invite this connection used was revoked.
pub const CLOSE_REVOKED: u32 = 3;
/// Connection close code: that key is locked to a different device.
pub const CLOSE_WRONG_DEVICE: u32 = 4;
/// Connection close code (between devices): the user cancelled the transfer.
pub const CLOSE_CANCELLED: u32 = 5;

/// Sent by a device on a stream it opens to the rendezvous server.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum RdvRequest {
    /// "I'm online and reachable" (only `serve` does this).
    Register { local_addrs: Vec<SocketAddr> },
    /// "Introduce me to this device."
    Connect { target: String, local_addrs: Vec<SocketAddr> },
    /// Start a pairing session; server returns a nameplate number.
    PairAllocate,
    /// Join a pairing session someone else started.
    PairJoin { nameplate: u32 },
    /// Wait (up to 10 minutes per request) for someone to join this slot: the
    /// inviter's side of an invite link. Repeated until the invite is used.
    PairHold { slot: String },
    /// Join the slot named in an invite link.
    PairJoinSlot { slot: String },
    /// Direct connection failed: forward encrypted packets through the server.
    Relay { target: String },
    /// Admin only: give a friend their own server key (replaces one with the
    /// same name). With `expires_in`, a temporary one (for an invite link).
    InviteCreate {
        name: String,
        #[serde(default)]
        expires_in: Option<u64>,
        /// Hex public key of the only device allowed to use it.
        #[serde(default)]
        device: Option<String>,
        /// Hex knock secret to use (an invite code's), instead of a random one.
        #[serde(default)]
        secret: Option<String>,
    },
    /// Admin only: list friends' invites.
    InviteList,
    /// Admin only: cut a friend off.
    InviteRevoke { name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteInfo {
    pub name: String,
    pub created: u64,
    /// Set for temporary invites (invite links): when it stops working.
    #[serde(default)]
    pub expires: Option<u64>,
    /// Device id of the device it's locked to (None until first used).
    #[serde(default)]
    pub device: Option<String>,
    /// Connections currently using this invite.
    pub connected: usize,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum RdvResponse {
    Ok,
    Nameplate { nameplate: u32 },
    PairMatched,
    PeerCandidates { candidates: Vec<SocketAddr> },
    /// Send the bind token to this port on the server, then connect to it.
    RelayReady { relay_port: u16, token: String },
    /// A friend's server key (128 hex, the same format as `--show-key`).
    Invite { key: String },
    Invites { invites: Vec<InviteInfo> },
    Error { message: String },
}

/// Sent by a device right after it accepts a peer's connection. In TLS 1.3 the
/// connecting side finishes its handshake *before* the other side has checked
/// its certificate, so a connection only counts once this hello arrives;
/// a refusal (unpaired or hidden) then looks exactly like no answer.
pub const PEER_HELLO: &[u8; 3] = b"FP1";

/// First bytes of a relay bind datagram, followed by a 16-byte token.
pub const RELAY_MAGIC: &[u8; 6] = b"FPRLY1";

/// Sent by the server on a stream it opens to a registered device.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum RdvPush {
    Incoming { from: String, candidates: Vec<SocketAddr> },
    /// `from` wants to reach us via the relay on `relay_port`.
    RelayIncoming { from: String, relay_port: u16, token: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum RdvPushReply {
    /// Approved: the server may give our address to the requester.
    Allow { candidates: Vec<SocketAddr> },
    Reject,
}

// ---------- pairing (relayed through the server, end-to-end protected) ----------

#[derive(Debug, Serialize, Deserialize)]
pub struct PairMsg {
    pub data: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PairInfo {
    pub name: String,
    pub public_key: String,
}

/// Sent by each side once pairing is confirmed: access to its rendezvous
/// server, if it chose to give it (a key made just for this device).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PairServerOffer {
    pub server: Option<ServerGift>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerGift {
    /// `host:port` to reach the server from the internet.
    pub address: String,
    /// 128 hex: the server's identity key and this device's own knock secret.
    pub key: String,
}

// ---------- device <-> device ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMeta {
    /// Relative path using `/` separators.
    pub path: String,
    pub size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum PeerRequest {
    /// "I'd like to send you these files."
    Offer { files: Vec<FileMeta> },
    /// List shares (empty path) or a folder within a share.
    Browse { path: String },
    /// "Please send me this file/folder from your shares."
    Fetch { path: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum PeerResponse {
    /// Offer accepted; per-file byte offsets to resume from.
    Accepted { offsets: Vec<u64> },
    Denied { reason: String },
    Listing { entries: Vec<DirEntry> },
    /// Fetch approved; these files will follow once the requester sends `Resume`.
    FetchOffer { files: Vec<FileMeta> },
    Resume { offsets: Vec<u64> },
    Error { message: String },
}

/// Sent after each file's bytes so the receiver can verify integrity.
#[derive(Debug, Serialize, Deserialize)]
pub struct FileDone {
    pub blake3: String,
}

/// Receiver's final report.
#[derive(Debug, Serialize, Deserialize)]
pub struct Complete {
    pub received: usize,
    pub failed: Vec<String>,
}
