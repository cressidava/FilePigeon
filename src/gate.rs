//! Stealth gates (single-packet authorization) for every listening socket.
//!
//! A gated UDP socket silently drops every datagram unless its exact source
//! address (IP *and* port) recently sent a valid "knock": 40 bytes =
//! nonce(16) || timestamp(8) || MAC(16). Nothing is ever sent back to unknown
//! sources, so to a scanner the port looks exactly like one a firewall blocks.
//! Because the filter sits *under* the QUIC stack, unauthenticated packets
//! never reach TLS: no certificate, no alert, nothing that proves the device
//! exists.
//!
//! Two uses:
//!  * the rendezvous server: one knock key, a random secret that is never sent
//!    over the network (distributed with the server address);
//!  * every device's own listener: one knock key per paired, non-hidden peer,
//!    derived from the pair's shared secret and bound to the receiving device,
//!    so only a currently trusted peer can make the device answer at all.
//!
//! Knocks are sent from the same socket QUIC uses, so admission can be per
//! exact address. Every valid knock is consumed exactly once. An admitted
//! address stays admitted while it keeps sending (QUIC keep-alives every 10 s)
//! and is forgotten after 60 s of silence; it also has to knock again at least
//! every few minutes (clients re-knock every 20 s), which keeps sessions alive
//! through NAT port changes and stops junk traffic holding a slot forever.
//! Knock acceptance is budgeted per source IP and per key owner, and a full
//! table evicts the least recently active entry instead of locking everyone out.

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const KNOCK_LEN: usize = 40;
/// Knocks whose timestamp is further than this from our clock are ignored.
const KNOCK_SKEW_SECS: u64 = 120;
/// An admitted address is forgotten after this long without traffic.
const ALLOW_IDLE: Duration = Duration::from_secs(60);
/// Bounds on gate memory; when full, new admissions are refused.
const MAX_ADMITTED: usize = 4096;
const MAX_NONCES: usize = 65_536;
/// An admission must be renewed by a fresh knock within this long.
const ADMISSION_MAX: Duration = Duration::from_secs(300);
/// Valid knocks accepted per source IP, and per key owner, per budget window.
const KNOCKS_PER_IP: u32 = 30;
const KNOCKS_PER_OWNER: u32 = 60;
const BUDGET_WINDOW: Duration = Duration::from_secs(10);
/// Knock context for the rendezvous server.
pub const RDV_CONTEXT: &[u8] = b"filepigeon-rendezvous";
/// Owner id for addresses we contacted ourselves (e.g. the rendezvous server).
pub const OUTBOUND_OWNER: [u8; 32] = [0xff; 32];

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn mac(key: &[u8; 32], context: &[u8], body: &[u8]) -> [u8; 16] {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(&(context.len() as u32).to_le_bytes());
    h.update(context);
    h.update(body);
    h.finalize().as_bytes()[..16].try_into().unwrap()
}

/// Build a fresh knock (random-looking bytes to anyone without the key).
/// `context` binds it to its destination: a knock for one device or server
/// is worthless anywhere else.
pub fn make_knock(key: &[u8; 32], context: &[u8]) -> [u8; KNOCK_LEN] {
    let mut packet = [0u8; KNOCK_LEN];
    crate::os_random(&mut packet[..16]);
    packet[16..24].copy_from_slice(&unix_now().to_le_bytes());
    let tag = mac(key, context, &packet[..24]);
    packet[24..].copy_from_slice(&tag);
    packet
}

/// Returns the nonce if `data` is a valid, fresh knock under `key`.
fn verify_knock(key: &[u8; 32], context: &[u8], data: &[u8]) -> Option<[u8; 16]> {
    if data.len() != KNOCK_LEN {
        return None;
    }
    let expected = mac(key, context, &data[..24]);
    // Constant-time comparison.
    let diff = expected.iter().zip(&data[24..]).fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if diff != 0 {
        return None;
    }
    let ts = u64::from_le_bytes(data[16..24].try_into().unwrap());
    if unix_now().abs_diff(ts) > KNOCK_SKEW_SECS {
        return None;
    }
    Some(data[..16].try_into().unwrap())
}

/// Where a gate gets its currently valid knock keys. Each key comes with an
/// owner id (e.g. the peer's public key) so admissions can be revoked by owner.
pub trait KnockKeys: Send + Sync + 'static {
    fn keys(&self) -> Arc<Vec<([u8; 32], [u8; 32])>>;

    /// Should knocks under this owner's key also be budgeted per owner? True
    /// when the key belongs to one party (a device's peer, a friend's invite);
    /// false for a key several devices share (the server's owner key), where
    /// a per-owner budget would let one sender use up everybody's allowance.
    fn budget_per_owner(&self, _owner: &[u8; 32]) -> bool {
        true
    }
}

/// A fixed single key (the rendezvous server).
pub struct StaticKey(pub Arc<Vec<([u8; 32], [u8; 32])>>);

impl StaticKey {
    pub fn new(secret: [u8; 32]) -> Arc<Self> {
        Arc::new(Self(Arc::new(vec![([0u8; 32], secret)])))
    }
}

impl KnockKeys for StaticKey {
    fn keys(&self) -> Arc<Vec<([u8; 32], [u8; 32])>> {
        self.0.clone()
    }

    fn budget_per_owner(&self, _owner: &[u8; 32]) -> bool {
        self.0.len() > 1
    }
}

struct Admission {
    last: Instant,
    knocked: Instant,
    owner: [u8; 32],
}

impl Admission {
    fn live(&self) -> bool {
        self.last.elapsed() < ALLOW_IDLE && (self.owner == OUTBOUND_OWNER || self.knocked.elapsed() < ADMISSION_MAX)
    }
}

#[derive(Default)]
struct Nonces {
    current: HashSet<[u8; 16]>,
    previous: HashSet<[u8; 16]>,
}

pub struct Gate {
    context: Vec<u8>,
    keys: Arc<dyn KnockKeys>,
    admitted: Mutex<HashMap<SocketAddr, Admission>>,
    nonces: Mutex<Nonces>,
    budgets: Mutex<HashMap<Budget, (Instant, u32)>>,
    pub dropped: AtomicU64,
}

#[derive(Hash, PartialEq, Eq)]
enum Budget {
    Ip(IpAddr),
    Owner([u8; 32]),
}

impl fmt::Debug for Gate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Gate")
    }
}

impl Gate {
    pub fn new(context: &[u8], keys: Arc<dyn KnockKeys>) -> Arc<Self> {
        let gate = Arc::new(Self {
            context: context.to_vec(),
            keys,
            admitted: Default::default(),
            nonces: Default::default(),
            budgets: Default::default(),
            dropped: AtomicU64::new(0),
        });
        // Housekeeping off the packet path: forget idle addresses and old nonces.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let weak = Arc::downgrade(&gate);
            handle.spawn(async move {
                let mut ticks = 0u64;
                loop {
                    tokio::time::sleep(Duration::from_secs(15)).await;
                    let Some(gate) = weak.upgrade() else { break };
                    ticks += 1;
                    gate.prune(ticks % (KNOCK_SKEW_SECS / 15 * 2) == 0);
                }
            });
        }
        gate
    }

    fn prune(&self, rotate_nonces: bool) {
        self.admitted.lock().unwrap().retain(|_, a| a.live());
        self.budgets.lock().unwrap().retain(|_, (t, _)| t.elapsed() < BUDGET_WINDOW);
        if rotate_nonces {
            let mut n = self.nonces.lock().unwrap();
            n.previous = std::mem::take(&mut n.current);
        }
    }

    /// Drop admissions whose key owner is no longer trusted (e.g. a peer that
    /// was just hidden or unpaired).
    pub fn revoke_where(&self, still_trusted: impl Fn(&[u8; 32]) -> bool) {
        self.admitted.lock().unwrap().retain(|_, a| a.owner == OUTBOUND_OWNER || still_trusted(&a.owner));
    }

    /// Let replies in from an address we are contacting ourselves.
    pub fn admit_outbound(&self, to: SocketAddr) {
        let now = Instant::now();
        self.insert_admission(to, Admission { last: now, knocked: now, owner: OUTBOUND_OWNER });
    }

    /// Insert, evicting the least recently active entry if the table is full.
    fn insert_admission(&self, addr: SocketAddr, a: Admission) {
        let mut admitted = self.admitted.lock().unwrap();
        if admitted.len() >= MAX_ADMITTED && !admitted.contains_key(&addr) {
            admitted.retain(|_, a| a.live());
            if admitted.len() >= MAX_ADMITTED {
                if let Some(oldest) = admitted.iter().min_by_key(|(_, a)| a.last).map(|(k, _)| *k) {
                    admitted.remove(&oldest);
                }
            }
        }
        admitted.insert(addr, a);
    }

    /// One more valid knock from this IP and owner, within budget?
    fn within_budget(&self, ip: IpAddr, owner: [u8; 32]) -> bool {
        let mut b = self.budgets.lock().unwrap();
        let mut take = |key: Budget, max: u32| {
            let e = b.entry(key).or_insert((Instant::now(), 0));
            if e.0.elapsed() > BUDGET_WINDOW {
                *e = (Instant::now(), 0);
            }
            e.1 += 1;
            e.1 <= max
        };
        // An over-budget source spends nothing from the owner's allowance.
        if !take(Budget::Ip(ip), KNOCKS_PER_IP) {
            return false;
        }
        !self.keys.budget_per_owner(&owner) || take(Budget::Owner(owner), KNOCKS_PER_OWNER)
    }

    /// Decide whether a datagram may reach the QUIC stack.
    fn admit(&self, from: SocketAddr, data: &[u8]) -> bool {
        // Knocks first, so every valid knock is consumed and never forwarded,
        // even when it comes from an address that's already admitted.
        if data.len() == KNOCK_LEN {
            if let Some((nonce, owner)) =
                self.keys.keys().iter().find_map(|(owner, key)| verify_knock(key, &self.context, data).map(|n| (n, *owner)))
            {
                // A replayed (already used) knock is dropped before it can
                // spend anyone's budget, so replays can't lock others out.
                {
                    let n = self.nonces.lock().unwrap();
                    if n.previous.contains(&nonce) || n.current.contains(&nonce) {
                        return false;
                    }
                }
                if !self.within_budget(from.ip(), owner) {
                    return false;
                }
                let fresh = {
                    let mut n = self.nonces.lock().unwrap();
                    let full = n.current.len() >= MAX_NONCES;
                    !n.previous.contains(&nonce) && !full && n.current.insert(nonce)
                };
                if fresh {
                    let now = Instant::now();
                    self.insert_admission(from, Admission { last: now, knocked: now, owner });
                }
                return false;
            }
        }
        let mut admitted = self.admitted.lock().unwrap();
        match admitted.get_mut(&from) {
            Some(a) if a.live() => {
                a.last = Instant::now();
                true
            }
            Some(_) => {
                admitted.remove(&from);
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
            None => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Whose key admitted this address (None if it isn't admitted).
    pub fn owner_of(&self, addr: SocketAddr) -> Option<[u8; 32]> {
        self.admitted.lock().unwrap().get(&addr).filter(|a| a.live()).map(|a| a.owner)
    }

    pub fn admitted_count(&self) -> usize {
        self.admitted.lock().unwrap().values().filter(|a| a.live()).count()
    }
}

/// A UDP socket that only lets admitted traffic through to QUIC.
#[derive(Debug)]
pub struct GatedSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    gate: Arc<Gate>,
}

impl GatedSocket {
    pub fn new(inner: Arc<dyn AsyncUdpSocket>, gate: Arc<Gate>) -> Arc<Self> {
        Arc::new(Self { inner, gate })
    }
}

impl AsyncUdpSocket for GatedSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            let n = match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(n)) => n,
                other => return other,
            };
            let mut kept = 0;
            for i in 0..n {
                let len = meta[i].len;
                let first = meta[i].stride.clamp(1, len.max(1)).min(len);
                if self.gate.admit(meta[i].addr, &bufs[i][..first]) {
                    if kept != i {
                        let (head, tail) = bufs.split_at_mut(i);
                        head[kept][..len].copy_from_slice(&tail[0][..len]);
                        meta[kept] = meta[i];
                    }
                    kept += 1;
                }
            }
            if kept > 0 {
                return Poll::Ready(Ok(kept));
            }
            // Everything was dropped: poll again (re-registers the waker if idle).
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTX: &[u8] = b"test-context";

    #[test]
    fn knocks_verify_once_per_key_context_and_address() {
        let secret = [9u8; 32];
        let gate = Gate::new(CTX, StaticKey::new(secret));
        let a: SocketAddr = "203.0.113.5:4000".parse().unwrap();
        let a_other_port: SocketAddr = "203.0.113.5:5555".parse().unwrap();
        let b: SocketAddr = "198.51.100.7:4000".parse().unwrap();

        assert!(!gate.admit(a, b"hello"), "strangers are dropped");
        assert!(!gate.admit(a, &make_knock(&[8u8; 32], CTX)), "wrong key");
        assert!(!gate.admit(a, &make_knock(&secret, b"other-context")), "knock meant for someone else");
        assert!(!gate.admit(a, b"quic"), "still not admitted");

        let k = make_knock(&secret, CTX);
        assert!(!gate.admit(a, &k), "the knock itself is never passed on");
        assert!(gate.admit(a, b"quic"), "after knocking, that address passes");
        assert!(!gate.admit(a_other_port, b"quic"), "admission is per exact address, not per IP");
        assert!(!gate.admit(b, &k), "a replayed knock opens nothing");
        assert!(!gate.admit(b, b"quic"));

        // A second, fresh knock from an already-admitted address is consumed too.
        let k2 = make_knock(&secret, CTX);
        assert!(!gate.admit(a, &k2));
        assert!(!gate.admit(b, &k2), "consumed even though it came from an admitted address");
        assert!(!gate.admit(b, b"quic"));
    }

    #[test]
    fn revocation_closes_the_door() {
        let keys = Arc::new(StaticKey(Arc::new(vec![([1u8; 32], [7u8; 32]), ([2u8; 32], [6u8; 32])])));
        let gate = Gate::new(CTX, keys);
        let a: SocketAddr = "203.0.113.5:4000".parse().unwrap();
        let b: SocketAddr = "203.0.113.6:4000".parse().unwrap();
        gate.admit(a, &make_knock(&[7u8; 32], CTX));
        gate.admit(b, &make_knock(&[6u8; 32], CTX));
        assert!(gate.admit(a, b"x") && gate.admit(b, b"x"));
        gate.revoke_where(|owner| owner != &[1u8; 32]);
        assert!(!gate.admit(a, b"x"), "owner 1 was revoked");
        assert!(gate.admit(b, b"x"), "owner 2 is untouched");
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    #[test]
    fn replayed_knocks_spend_no_budget() {
        // One genuine knock, replayed far beyond any budget from many sources,
        // must not stop a fresh knock under the same key from getting in.
        let gate = Gate::new(b"ctx", StaticKey::new([5u8; 32]));
        let knock = make_knock(&[5u8; 32], b"ctx");
        assert!(!gate.admit("10.0.0.1:1000".parse().unwrap(), &knock));
        for i in 0..2000u32 {
            let from = SocketAddr::from(([10, 1, (i >> 8) as u8, i as u8], 2000));
            gate.admit(from, &knock);
        }
        let fresh = make_knock(&[5u8; 32], b"ctx");
        let me: SocketAddr = "10.9.9.9:3000".parse().unwrap();
        gate.admit(me, &fresh);
        assert!(gate.owner_of(me).is_some());
    }

    #[test]
    fn one_source_cannot_exhaust_the_gate() {
        let secret = [3u8; 32];
        let gate = Gate::new(b"ctx", StaticKey::new(secret));
        let flooder: SocketAddr = "203.0.113.9:1000".parse().unwrap();
        for _ in 0..1000 {
            gate.admit(flooder, &make_knock(&secret, b"ctx"));
        }
        // The flooder burned its own budget, not everyone else's.
        assert!(gate.nonces.lock().unwrap().current.len() <= KNOCKS_PER_IP as usize);
        let other: SocketAddr = "198.51.100.1:2000".parse().unwrap();
        gate.admit(other, &make_knock(&secret, b"ctx"));
        assert!(gate.admit(other, b"quic"), "a different source still gets in");
    }
}
