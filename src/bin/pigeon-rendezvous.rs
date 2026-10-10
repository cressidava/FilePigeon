//! The rendezvous server: helps paired devices find each other, relays
//! pairing handshakes, and (as a last resort) forwards encrypted packets when a
//! direct connection is impossible. It never sees file data, file names or
//! pairing codes, and only hands out a device's address when that device approves.

use anyhow::{Context, Result};
use clap::Parser;
use filepigeon::access::{invite_label, Access, OWNER_LABEL};
use filepigeon::gate::{Gate, GatedSocket, RDV_CONTEXT};
use filepigeon::identity::{device_id, Identity};
use filepigeon::proto::{
    InviteInfo, RdvPush, RdvPushReply, RdvRequest, RdvResponse, CLOSE_REPLACED, CLOSE_REVOKED, CLOSE_WRONG_DEVICE,
    RELAY_MAGIC,
};
use filepigeon::tls::{peer_public_key, server_config_with, small_transport, KeyPolicy, ALPN_RDV};
use filepigeon::wire::{read_msg_max, write_msg, MAX_SMALL};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::sync::oneshot;

#[derive(Parser)]
#[command(name = "pigeon-rendezvous", version, about = "FilePigeon rendezvous server")]
struct Args {
    /// UDP address to listen on.
    #[arg(long, default_value = "0.0.0.0:7400")]
    listen: SocketAddr,
    /// Server identity key (created if missing). The knock secret is kept next
    /// to it, with a `.knock` extension.
    #[arg(long, default_value = "rendezvous-key.pem")]
    key: PathBuf,
    /// Print the owner key (for your own devices) and exit.
    #[arg(long)]
    show_key: bool,
    /// Create a key for one friend, print it, and exit. Re-using a name
    /// replaces (and cuts off) that friend's old key.
    #[arg(long, value_name = "NAME")]
    invite: Option<String>,
    /// List friends' invites and exit.
    #[arg(long)]
    invites: bool,
    /// Revoke a friend's invite and exit. Their connections close within seconds.
    #[arg(long, value_name = "NAME")]
    revoke: Option<String>,
    /// Let this device (its public key, from `filepigeon whoami`) create and
    /// revoke invites remotely, then exit. It must also use the owner key.
    #[arg(long, value_name = "PUBLIC_KEY")]
    add_admin: Option<String>,
    /// Stop a device from managing invites, then exit.
    #[arg(long, value_name = "PUBLIC_KEY")]
    remove_admin: Option<String>,
    /// List admin devices and exit.
    #[arg(long)]
    admins: bool,
    /// UDP port range for relay sessions (one port per session). Open these in your firewall.
    #[arg(long, default_value = "7401-7432")]
    relay_ports: String,
    /// Stop a relay session after this many MiB (0 = no limit).
    #[arg(long, default_value_t = 51_200)]
    relay_limit_mb: u64,
    /// Disable relaying entirely (direct connections only).
    #[arg(long)]
    no_relay: bool,
    /// Answer anyone, without requiring the secret knock first (not recommended).
    #[arg(long)]
    no_stealth: bool,
}

const MAX_PENDING_PAIRINGS: usize = 10_000;
const MAX_PAIRINGS_PER_DEVICE: usize = 3;
/// Invite-link slots one device may hold open at once.
const MAX_HELD_PER_DEVICE: usize = 16;
const MAX_HELD_TOTAL: usize = 10_000;
/// One hold request lasts this long; the inviter's PC then asks again.
const HOLD_FOR: Duration = Duration::from_secs(600);
const PAIR_RELAY_LIMIT: u64 = 64 * 1024;
/// Requests per minute, counted per device *and* per IP across connections.
const REQUESTS_PER_MINUTE: u32 = 60;
/// Pairing join attempts per 10 minutes, per device and per IP.
const JOINS_PER_10_MIN: u32 = 10;
/// Generous enough for a household or office sharing one public IP.
const MAX_CONNS_PER_IP: usize = 32;
const MAX_RELAYS_PER_DEVICE: usize = 2;
const MAX_RELAYS_PER_IP: usize = 4;
/// Every refusal of Connect/Relay is sent this long after the request has
/// fully arrived, so "offline", "refused" and "busy" can't be told apart by
/// timing. It must exceed ASK_TIMEOUT, the longest a device may take to answer.
const REFUSAL_AT: Duration = Duration::from_secs(6);
const ASK_TIMEOUT: Duration = Duration::from_secs(5);
const OFFLINE: &str = "peer is offline or not accepting connections from you";

type StreamPair = (quinn::SendStream, quinn::RecvStream);

struct Server {
    /// Our identity key in hex (the first half of every server key).
    identity_hex: String,
    access: Arc<Access>,
    gate: Option<Arc<Gate>>,
    /// Which key each live connection knocked with (stable id -> owner, conn),
    /// so revoking an invite can close its connections.
    conn_owners: Mutex<HashMap<usize, ([u8; 32], quinn::Connection)>>,
    online: Mutex<HashMap<String, Listener>>,
    pending: Mutex<HashMap<u32, (String, oneshot::Sender<StreamPair>)>>,
    /// Invite-link slots: slot id -> (holder, where to hand the joiner).
    held: Mutex<HashMap<String, (String, oneshot::Sender<StreamPair>)>>,
    relay: Option<Arc<Relay>>,
    limits: Mutex<HashMap<String, (Instant, u32)>>,
    conns_per_ip: Mutex<HashMap<IpAddr, usize>>,
}

impl Server {
    /// Count one event under `key`; false once `max` is exceeded within `window`.
    /// (Old entries are pruned by a timer, never on the request path; if the
    /// table is ever huge, unknown keys are refused rather than slowing everyone.)
    fn allow(&self, key: String, max: u32, window: Duration) -> bool {
        let mut l = self.limits.lock().unwrap();
        if l.len() > 200_000 && !l.contains_key(&key) {
            return false;
        }
        let e = l.entry(key).or_insert((Instant::now(), 0));
        if e.0.elapsed() > window {
            *e = (Instant::now(), 0);
        }
        e.1 += 1;
        e.1 <= max
    }
}

// ---------------- relay ----------------
//
// Every relay port is bound for the life of the process, so idle ports stay
// silent instead of answering "port unreachable". A session takes a socket
// from the pool. Both devices first send a bind datagram (magic + their own
// random token) from their QUIC socket; the first bind for each side wins, and
// after that the server blindly forwards datagrams between the two bound
// addresses. The devices run their normal key-pinned QUIC/TLS connection
// *through* it, so the server only ever sees ciphertext.

const RELAY_IDLE: Duration = Duration::from_secs(60);
const RELAY_BIND_WAIT: Duration = Duration::from_secs(30);
const RELAY_MAX_LIFETIME: Duration = Duration::from_secs(12 * 3600);

struct Relay {
    pool: Mutex<Vec<(u16, Arc<tokio::net::UdpSocket>)>>,
    limit_bytes: u64,
    per_device: Mutex<HashMap<String, usize>>,
    per_ip: Mutex<HashMap<IpAddr, usize>>,
    /// Live sessions: port -> (key owner that asked for it, its stop switch),
    /// so revoking a friend also ends their relay sessions.
    sessions: Mutex<HashMap<u16, ([u8; 32], Arc<tokio::sync::Notify>)>>,
}

struct RelaySession {
    port: u16,
    mine: [u8; 16],
    theirs: [u8; 16],
    cancel: Arc<tokio::sync::Notify>,
}

impl Relay {
    /// Take a port for a session requested by `device` from `ip`, using the
    /// key of gate owner `owner`.
    fn create(self: &Arc<Self>, device: &str, ip: IpAddr, owner: [u8; 32]) -> Option<RelaySession> {
        {
            let mut per = self.per_device.lock().unwrap();
            let mut per_ip = self.per_ip.lock().unwrap();
            let n = per.get(device).copied().unwrap_or(0);
            let m = per_ip.get(&ip).copied().unwrap_or(0);
            if n >= MAX_RELAYS_PER_DEVICE || m >= MAX_RELAYS_PER_IP {
                return None;
            }
            per.insert(device.to_string(), n + 1);
            per_ip.insert(ip, m + 1);
        }
        let Some((port, sock)) = self.pool.lock().unwrap().pop() else {
            self.release(device, ip);
            return None;
        };
        // Discard anything that arrived while the port was idle.
        let mut junk = [0u8; 2048];
        while sock.try_recv_from(&mut junk).is_ok() {}
        let (mut mine, mut theirs) = ([0u8; 16], [0u8; 16]);
        filepigeon::os_random(&mut mine);
        filepigeon::os_random(&mut theirs);
        let cancel = Arc::new(tokio::sync::Notify::new());
        let cancelled = cancel.clone();
        self.sessions.lock().unwrap().insert(port, (owner, cancel.clone()));
        let relay = self.clone();
        let device = device.to_string();
        tokio::spawn(async move {
            let forwarded = run_relay(&sock, [mine, theirs], relay.limit_bytes, cancelled).await;
            if forwarded > 0 {
                log(&format!("relay session on port {port} ended ({} forwarded)", human(forwarded)));
            }
            relay.sessions.lock().unwrap().remove(&port);
            relay.pool.lock().unwrap().push((port, sock));
            relay.release(&device, ip);
        });
        Some(RelaySession { port, mine, theirs, cancel })
    }

    fn release(&self, device: &str, ip: IpAddr) {
        let mut per = self.per_device.lock().unwrap();
        if let Some(n) = per.get_mut(device) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                per.remove(device);
            }
        }
        let mut per_ip = self.per_ip.lock().unwrap();
        if let Some(n) = per_ip.get_mut(&ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                per_ip.remove(&ip);
            }
        }
    }
}

async fn run_relay(
    sock: &tokio::net::UdpSocket,
    tokens: [[u8; 16]; 2],
    limit: u64,
    cancelled: Arc<tokio::sync::Notify>,
) -> u64 {
    let mut addrs: [Option<SocketAddr>; 2] = [None, None];
    let mut buf = vec![0u8; 65536];
    let mut forwarded = 0u64;
    let lifetime_end = tokio::time::Instant::now() + RELAY_MAX_LIFETIME;
    let bind_deadline = tokio::time::Instant::now() + RELAY_BIND_WAIT;
    // Only traffic between the two bound addresses counts as activity; junk
    // from anyone else can't keep a session (and its port) alive.
    let mut last_activity = tokio::time::Instant::now();
    loop {
        let both_bound = addrs.iter().all(Option::is_some);
        let deadline = if both_bound { last_activity + RELAY_IDLE } else { bind_deadline }.min(lifetime_end);
        let received = tokio::select! {
            r = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)) => r,
            _ = cancelled.notified() => break,
        };
        let Ok(Ok((n, src))) = received else { break };
        match addrs.iter().position(|a| *a == Some(src)) {
            Some(side) => {
                if let Some(dst) = addrs[1 - side] {
                    last_activity = tokio::time::Instant::now();
                    forwarded += n as u64;
                    if limit > 0 && forwarded > limit {
                        break;
                    }
                    let _ = sock.send_to(&buf[..n], dst).await;
                }
            }
            None => {
                // Unknown sender: only a valid bind for a still-unbound side is
                // accepted (first bind wins, so a seen token can't hijack it).
                if n == RELAY_MAGIC.len() + 16 && buf.starts_with(RELAY_MAGIC) {
                    if let Some(side) = tokens.iter().position(|t| t[..] == buf[RELAY_MAGIC.len()..n]) {
                        if addrs[side].is_none() {
                            addrs[side] = Some(src);
                        }
                    }
                }
            }
        }
    }
    forwarded
}

fn human(n: u64) -> String {
    filepigeon::progress::human(n)
}

fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    let (a, b) = spec.split_once('-').unwrap_or((spec, spec));
    let (a, b): (u16, u16) = (a.trim().parse()?, b.trim().parse()?);
    anyhow::ensure!(a <= b, "bad port range {spec}");
    Ok((a..=b).rev().collect())
}

/// The knock secret: random, created once next to the identity key, readable
/// only by the server. It never appears on the network.
fn load_or_create_knock_secret(key_path: &Path) -> Result<[u8; 32]> {
    let path = key_path.with_extension("knock");
    if path.exists() {
        let bytes = std::fs::read(&path)?;
        return bytes.try_into().map_err(|_| anyhow::anyhow!("{} is corrupt", path.display()));
    }
    let mut secret = [0u8; 32];
    filepigeon::os_random(&mut secret);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    opts.open(&path).with_context(|| format!("cannot create {}", path.display()))?.write_all(&secret)?;
    Ok(secret)
}

#[derive(Clone)]
struct Listener {
    conn: quinn::Connection,
    candidates: Vec<SocketAddr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let managing = args.show_key
        || args.invite.is_some()
        || args.invites
        || args.revoke.is_some()
        || args.add_admin.is_some()
        || args.remove_admin.is_some()
        || args.admins;
    if managing {
        return manage(&args);
    }
    let identity = Identity::load_or_create(&args.key)?;
    let knock_secret = load_or_create_knock_secret(&args.key)?;
    let access = Access::open(&args.key, knock_secret)?;

    let mut cfg = server_config_with(&identity, KeyPolicy::Any, ALPN_RDV, small_transport())?;
    cfg.max_incoming(1024);
    let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
    let raw = runtime.wrap_udp_socket(std::net::UdpSocket::bind(args.listen).context("cannot bind")?)?;
    let gate = (!args.no_stealth).then(|| Gate::new(RDV_CONTEXT, access.clone()));
    let socket: Arc<dyn quinn::AsyncUdpSocket> = match &gate {
        Some(gate) => GatedSocket::new(raw, gate.clone()),
        None => raw,
    };
    let endpoint =
        quinn::Endpoint::new_with_abstract_socket(quinn::EndpointConfig::default(), Some(cfg), socket, runtime)?;
    println!("pigeon-rendezvous listening on UDP {}", args.listen);
    println!("Server id: {}", device_id(&identity.public_key()));
    match &gate {
        Some(gate) => {
            println!("Stealth: on. Only devices with the server key get any answer; to everyone else the port looks closed.");
            let gate = gate.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    let dropped = gate.dropped.swap(0, std::sync::atomic::Ordering::Relaxed);
                    if dropped > 0 {
                        log(&format!("stealth: silently ignored {dropped} packet(s) from unknown sources in the last hour"));
                    }
                }
            });
        }
        None => println!("Stealth: OFF (--no-stealth). The server answers anyone."),
    }
    println!("To configure a device, run this program with --show-key (the key is never written to this log).");

    let relay = if args.no_relay {
        println!("Relay: disabled");
        None
    } else {
        let mut pool = Vec::new();
        for port in parse_ports(&args.relay_ports)? {
            match tokio::net::UdpSocket::bind((args.listen.ip(), port)).await {
                Ok(s) => pool.push((port, Arc::new(s))),
                Err(e) => log(&format!("relay port {port} unavailable: {e}")),
            }
        }
        println!(
            "Relay: UDP {} ({} sessions max{}). Open these ports too.",
            args.relay_ports,
            pool.len(),
            if args.relay_limit_mb > 0 { format!(", {} MiB each", args.relay_limit_mb) } else { String::new() }
        );
        Some(Arc::new(Relay {
            pool: Mutex::new(pool),
            limit_bytes: args.relay_limit_mb * 1024 * 1024,
            per_device: Default::default(),
            per_ip: Default::default(),
            sessions: Default::default(),
        }))
    };
    let invites = access.live_invites().len();
    if invites > 0 {
        println!("Invites: {invites} friend key(s) (list them with --invites).");
    }
    let server = Arc::new(Server {
        identity_hex: hex::encode(identity.public_key()),
        access: access.clone(),
        gate: gate.clone(),
        conn_owners: Default::default(),
        online: Default::default(),
        pending: Default::default(),
        held: Default::default(),
        relay,
        limits: Default::default(),
        conns_per_ip: Default::default(),
    });
    {
        let server = server.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                server.limits.lock().unwrap().retain(|_, (t, _)| t.elapsed() < Duration::from_secs(600));
            }
        });
    }
    // Revocations take effect within seconds: forget the addresses a revoked
    // key admitted and close the connections that used it.
    {
        let server = server.clone();
        tokio::spawn(async move {
            let mut seen = server.access.generation();
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let now = server.access.generation();
                if now == seen {
                    continue;
                }
                seen = now; // (expiries bump the generation too)
                let access = server.access.clone();
                if let Some(gate) = &server.gate {
                    gate.revoke_where(|owner| access.valid_label(owner));
                }
                let revoked: Vec<quinn::Connection> = server
                    .conn_owners
                    .lock()
                    .unwrap()
                    .values()
                    .filter(|(owner, _)| !access.valid_label(owner))
                    .map(|(_, c)| c.clone())
                    .collect();
                for conn in &revoked {
                    conn.close(CLOSE_REVOKED.into(), b"access revoked");
                }
                if let Some(relay) = &server.relay {
                    for (_, (owner, stop)) in relay.sessions.lock().unwrap().iter() {
                        if !access.valid_label(owner) {
                            stop.notify_one();
                        }
                    }
                }
                if !revoked.is_empty() {
                    log(&format!("closed {} connection(s) that used a revoked invite", revoked.len()));
                }
            }
        });
    }
    while let Some(incoming) = endpoint.accept().await {
        let ip = incoming.remote_address().ip();
        let crowded = {
            let mut per_ip = server.conns_per_ip.lock().unwrap();
            let n = per_ip.entry(ip).or_insert(0);
            if *n >= MAX_CONNS_PER_IP {
                true
            } else {
                *n += 1;
                false
            }
        };
        if crowded {
            incoming.ignore();
            continue;
        }
        let server = server.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(server.clone(), incoming).await {
                log(&format!("connection ended: {e:#}"));
            }
            let mut per_ip = server.conns_per_ip.lock().unwrap();
            if let Some(n) = per_ip.get_mut(&ip) {
                *n -= 1;
                if *n == 0 {
                    per_ip.remove(&ip);
                }
            }
        });
    }
    Ok(())
}

/// One-shot management commands (run as root on the server; keys are printed
/// to the terminal, never logged).
fn manage(args: &Args) -> Result<()> {
    // Never create the key files here: if run as root before the service's
    // first start, they'd end up unreadable by the service.
    let knock = args.key.with_extension("knock");
    if !args.key.exists() || !knock.exists() {
        anyhow::bail!("no server key yet: start the service once first, then try again");
    }
    let identity = Identity::load_or_create(&args.key)?;
    let knock_secret = load_or_create_knock_secret(&args.key)?;
    let access = Access::open(&args.key, knock_secret)?;
    let server_pk = hex::encode(identity.public_key());
    if args.show_key {
        // Identity key + owner knock secret: for your own devices.
        println!("{server_pk}{}", hex::encode(knock_secret));
    }
    if let Some(name) = &args.invite {
        let secret = access.create_invite(name, None)?;
        eprintln!("Key for {name:?}. Give it to them directly; it works only for them, and --revoke cuts it off:");
        println!("{server_pk}{}", hex::encode(secret));
    }
    if let Some(name) = &args.revoke {
        if !access.revoke_invite(name)? {
            anyhow::bail!("no invite called {name:?}");
        }
        println!("Revoked {name:?}. The running server closes its connections within a few seconds.");
    }
    if args.invites {
        let invites = access.live_invites();
        if invites.is_empty() {
            println!("No invites.");
        }
        for i in &invites {
            let until = i.expires.map(|e| format!(", temporary until {e}")).unwrap_or_default();
            let device = i
                .device
                .as_ref()
                .and_then(|d| hex::decode(d).ok())
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .map(|k| format!(", locked to device {}", device_id(&k)))
                .unwrap_or_else(|| ", not used yet".into());
            println!("{}  (created {}{until}{device})", filepigeon::text::display_safe(&i.name, 64), i.created);
        }
    }
    if let Some(pk) = &args.add_admin {
        access.add_admin(pk)?;
        println!("Added admin {}.", pk.trim());
    }
    if let Some(pk) = &args.remove_admin {
        if !access.remove_admin(pk)? {
            anyhow::bail!("that device was not an admin");
        }
        println!("Removed admin {}.", pk.trim());
    }
    if args.admins {
        let file = access.file();
        if file.admins.is_empty() {
            println!("No admin devices.");
        }
        for a in &file.admins {
            let id = hex::decode(a).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()).map(|k| device_id(&k));
            println!("{a}  (device {})", id.unwrap_or_default());
        }
    }
    Ok(())
}

fn log(msg: &str) {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    println!("[{t}] {}", filepigeon::text::display_safe(msg, 500));
}

async fn handle_connection(server: Arc<Server>, incoming: quinn::Incoming) -> Result<()> {
    let conn = incoming.await?;
    let pk = peer_public_key(&conn)?;
    let id = device_id(&pk);
    let observed = conn.remote_address();
    // Which key let this connection in. Without stealth there are no knocks,
    // so everyone counts as using the owner key.
    let owner = match &server.gate {
        Some(gate) => gate.owner_of(observed).context("connection without an admission")?,
        None => OWNER_LABEL,
    };
    // A friend's key works only on the device it's locked to.
    match server.access.device_allowed(&owner, &pk) {
        Ok(true) => {}
        Ok(false) => {
            log(&format!("{id}: refused a key that belongs to another device"));
            conn.close(CLOSE_WRONG_DEVICE.into(), b"this key belongs to another device");
            return Ok(());
        }
        Err(e) => {
            conn.close(0u32.into(), b"server error");
            return Err(e);
        }
    }
    server.conn_owners.lock().unwrap().insert(conn.stable_id(), (owner, conn.clone()));
    let result = serve_connection(&server, &conn, &pk, &id, owner, observed).await;
    server.conn_owners.lock().unwrap().remove(&conn.stable_id());
    result
}

async fn serve_connection(
    server: &Arc<Server>,
    conn: &quinn::Connection,
    pk: &[u8; 32],
    id: &str,
    owner: [u8; 32],
    observed: SocketAddr,
) -> Result<()> {
    let id = id.to_string();
    let pk = *pk;

    while let Ok((send, recv)) = conn.accept_bi().await {
        // Rate limits follow the device and the IP, not the connection, so
        // opening more connections doesn't reset them.
        if !server.allow(format!("id:{id}"), REQUESTS_PER_MINUTE, Duration::from_secs(60))
            || !server.allow(format!("ip:{}", observed.ip()), REQUESTS_PER_MINUTE * 2, Duration::from_secs(60))
        {
            conn.close(1u32.into(), b"rate limited");
            break;
        }
        let (server, conn, id) = (server.clone(), conn.clone(), id.clone());
        tokio::spawn(async move {
            if let Err(e) = handle_stream(&server, &conn, &id, &pk, owner, observed, send, recv).await {
                log(&format!("{id}: {e:#}"));
            }
        });
    }

    let mut online = server.online.lock().unwrap();
    if online.get(&id).is_some_and(|l| l.conn.stable_id() == conn.stable_id()) {
        online.remove(&id);
        log(&format!("{id} offline"));
    }
    Ok(())
}

/// Send a refusal no earlier than `REFUSAL_AT` after the request started.
async fn refuse(send: &mut quinn::SendStream, started: Instant, message: &str) -> Result<()> {
    tokio::time::sleep_until((started + REFUSAL_AT).into()).await;
    write_msg(send, &RdvResponse::Error { message: message.into() }).await
}

async fn handle_stream(
    server: &Server,
    conn: &quinn::Connection,
    id: &str,
    pk: &[u8; 32],
    owner: [u8; 32],
    observed: SocketAddr,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<()> {
    let req: RdvRequest = tokio::time::timeout(Duration::from_secs(10), read_msg_max(&mut recv, MAX_SMALL)).await??;
    // Timing starts once the request has fully arrived, so a requester can't
    // shrink the padding by sending its request slowly.
    let started = Instant::now();
    // An invite link's temporary key is for joining the inviter's slot and
    // nothing else: whoever holds a leaked link can't use the server.
    if !matches!(req, RdvRequest::PairJoinSlot { .. } | RdvRequest::Prove { .. }) && server.access.join_only(&owner) {
        let message = "this key only works for joining an invite".to_string();
        return write_msg(&mut send, &RdvResponse::Error { message }).await;
    }
    // Admins manage invites, and only while using the owner key: a friend's
    // invite (or someone replaying a knock made with one) never grants that.
    // Checked per request, so removing an admin takes effect at once.
    let admin_only = matches!(req, RdvRequest::InviteCreate { .. } | RdvRequest::InviteList | RdvRequest::InviteRevoke { .. });
    if admin_only && !(owner == OWNER_LABEL && server.access.is_admin(pk)) {
        let message = "only the server's admin devices can manage invites".to_string();
        return write_msg(&mut send, &RdvResponse::Error { message }).await;
    }
    match req {
        RdvRequest::InviteCreate { name, expires_in, device, secret } => {
            let device = device.and_then(|d| hex::decode(d).ok()).and_then(|b| <[u8; 32]>::try_from(b).ok());
            let secret = secret.and_then(|d| hex::decode(d).ok()).and_then(|b| <[u8; 32]>::try_from(b).ok());
            let made = match secret {
                Some(secret) => server.access.create_invite_with(&name, expires_in, device, secret),
                None => server.access.create_invite_for(&name, expires_in, device),
            };
            let resp = match made {
                Ok(secret) => {
                    log(&format!("{id} created an invite"));
                    RdvResponse::Invite { key: format!("{}{}", server.identity_hex, hex::encode(secret)) }
                }
                Err(e) => RdvResponse::Error { message: format!("{e:#}") },
            };
            write_msg(&mut send, &resp).await?;
        }
        RdvRequest::Prove { nonce } => {
            let resp = match (hex::decode(&nonce), server.access.secret_for(&owner)) {
                (Ok(n), Some(secret)) if n.len() == 16 => {
                    let pk: [u8; 32] = hex::decode(&server.identity_hex)?.try_into().map_err(|_| anyhow::anyhow!("bad key"))?;
                    RdvResponse::Proof { mac: hex::encode(filepigeon::invites::server_proof(&secret, &n, &pk)) }
                }
                _ => RdvResponse::Error { message: "bad proof request".into() },
            };
            write_msg(&mut send, &resp).await?;
        }
        RdvRequest::InviteList => {
            let owners: Vec<[u8; 32]> = server.conn_owners.lock().unwrap().values().map(|(o, _)| *o).collect();
            let invites = server
                .access
                .live_invites()
                .iter()
                .map(|i| {
                    let label = hex::decode(&i.secret)
                        .ok()
                        .and_then(|b| <[u8; 32]>::try_from(b).ok())
                        .map(|s| invite_label(&s));
                    InviteInfo {
                        name: i.name.clone(),
                        created: i.created,
                        expires: i.expires,
                        device: i
                            .device
                            .as_ref()
                            .and_then(|d| hex::decode(d).ok())
                            .and_then(|b| <[u8; 32]>::try_from(b).ok())
                            .map(|k| device_id(&k)),
                        connected: owners.iter().filter(|o| Some(**o) == label).count(),
                    }
                })
                .collect();
            write_msg(&mut send, &RdvResponse::Invites { invites }).await?;
        }
        RdvRequest::InviteRevoke { name } => {
            let resp = match server.access.revoke_invite(&name) {
                Ok(true) => {
                    log(&format!("{id} revoked an invite"));
                    RdvResponse::Ok
                }
                Ok(false) => RdvResponse::Error { message: "no invite by that name".into() },
                Err(e) => RdvResponse::Error { message: format!("{e:#}") },
            };
            write_msg(&mut send, &resp).await?;
        }
        RdvRequest::Register { local_addrs } => {
            let mut candidates = vec![observed];
            candidates.extend(local_addrs.into_iter().take(4));
            let old = server
                .online
                .lock()
                .unwrap()
                .insert(id.to_string(), Listener { conn: conn.clone(), candidates });
            if let Some(old) = old.filter(|o| o.conn.stable_id() != conn.stable_id()) {
                old.conn.close(CLOSE_REPLACED.into(), b"replaced by newer session");
            }
            write_msg(&mut send, &RdvResponse::Ok).await?;
            log(&format!("{id} online"));
        }
        RdvRequest::Connect { target, local_addrs } => {
            // (Asking to be introduced to yourself is never legitimate.)
            let listener = if target == id { None } else { server.online.lock().unwrap().get(&target).cloned() };
            let mut mine = vec![observed];
            mine.extend(local_addrs.into_iter().take(4));
            let approved = match listener {
                Some(l) => ask_target(&l, RdvPush::Incoming { from: id.to_string(), candidates: mine })
                    .await
                    .ok()
                    .flatten()
                    .map(|extra| {
                        let mut all = l.candidates.clone();
                        all.extend(extra.into_iter().take(4));
                        all
                    }),
                None => None,
            };
            match approved {
                Some(candidates) => write_msg(&mut send, &RdvResponse::PeerCandidates { candidates }).await?,
                // Same answer, same timing, for "offline" and "refused".
                None => refuse(&mut send, started, OFFLINE).await?,
            }
        }
        RdvRequest::Relay { target } => {
            // A relay to yourself would just be a free UDP forwarder.
            let listener = if target == id { None } else { server.online.lock().unwrap().get(&target).cloned() };
            let session = match (&server.relay, listener) {
                (Some(relay), Some(listener)) => relay.create(id, observed.ip(), owner).map(|s| (s, listener)),
                _ => None,
            };
            let Some((session, listener)) = session else {
                // Not configured, target offline, or no free port: all look alike.
                return refuse(&mut send, started, OFFLINE).await;
            };
            let push = RdvPush::RelayIncoming {
                from: id.to_string(),
                relay_port: session.port,
                token: hex::encode(session.theirs),
            };
            match ask_target(&listener, push).await {
                Ok(Some(_)) => {
                    log(&format!("relay session on port {} for {id} -> {target}", session.port));
                    write_msg(&mut send, &RdvResponse::RelayReady { relay_port: session.port, token: hex::encode(session.mine) })
                        .await?;
                }
                _ => {
                    // Refused: free the port at once rather than holding it.
                    session.cancel.notify_one();
                    refuse(&mut send, started, OFFLINE).await?;
                }
            }
        }
        RdvRequest::PairAllocate => {
            let (tx, rx) = oneshot::channel();
            let allocated = {
                let mut pending = server.pending.lock().unwrap();
                let mine = pending.values().filter(|(owner, _)| owner == id).count();
                (pending.len() < MAX_PENDING_PAIRINGS && mine < MAX_PAIRINGS_PER_DEVICE).then(|| {
                    let mut n = rand::random_range(1..10_000);
                    while pending.contains_key(&n) {
                        n = rand::random_range(1..1_000_000);
                    }
                    pending.insert(n, (id.to_string(), tx));
                    n
                })
            };
            let Some(nameplate) = allocated else {
                write_msg(&mut send, &RdvResponse::Error { message: "server busy, try again".into() }).await?;
                return Ok(());
            };
            write_msg(&mut send, &RdvResponse::Nameplate { nameplate }).await?;
            let joined = tokio::time::timeout(Duration::from_secs(600), rx).await;
            server.pending.lock().unwrap().remove(&nameplate);
            match_pair(joined, send, recv, "pairing code expired").await?;
        }
        RdvRequest::PairHold { slot } => {
            if slot.len() != 32 || !slot.chars().all(|c| c.is_ascii_hexdigit()) {
                write_msg(&mut send, &RdvResponse::Error { message: "bad invite slot".into() }).await?;
                return Ok(());
            }
            let (tx, rx) = oneshot::channel();
            let held = {
                let mut held = server.held.lock().unwrap();
                // Holding again (after a timeout or reconnect) replaces our own entry.
                let taken_by_other = held.get(&slot).is_some_and(|(owner, _)| owner != id);
                let mine = held.values().filter(|(owner, _)| owner == id).count();
                if taken_by_other || held.len() >= MAX_HELD_TOTAL || (mine >= MAX_HELD_PER_DEVICE && !held.contains_key(&slot)) {
                    false
                } else {
                    held.insert(slot.clone(), (id.to_string(), tx));
                    true
                }
            };
            if !held {
                write_msg(&mut send, &RdvResponse::Error { message: "server busy, try again".into() }).await?;
                return Ok(());
            }
            write_msg(&mut send, &RdvResponse::Ok).await?;
            let joined = tokio::time::timeout(HOLD_FOR, rx).await;
            {
                let mut held = server.held.lock().unwrap();
                if held.get(&slot).is_some_and(|(owner, _)| owner == id) {
                    held.remove(&slot);
                }
            }
            match_pair(joined, send, recv, "nobody joined yet").await?;
        }
        RdvRequest::PairJoinSlot { slot } => {
            if !server.allow(format!("join-id:{id}"), JOINS_PER_10_MIN, Duration::from_secs(600))
                || !server.allow(format!("join-ip:{}", observed.ip()), JOINS_PER_10_MIN, Duration::from_secs(600))
            {
                write_msg(&mut send, &RdvResponse::Error { message: "too many pairing attempts; wait a few minutes".into() })
                    .await?;
                return Ok(());
            }
            let entry = server.held.lock().unwrap().remove(&slot);
            match entry {
                Some((_, tx)) => {
                    let _ = tx.send((send, recv));
                }
                None => {
                    let message = "the person who invited you isn't online right now: FilePigeon must be running on their PC. Try again later.";
                    write_msg(&mut send, &RdvResponse::Error { message: message.into() }).await?;
                }
            }
        }
        RdvRequest::PairJoin { nameplate } => {
            // Sweeping nameplates to snipe other people's pairings is limited
            // per device and per IP, however many connections are used.
            if !server.allow(format!("join-id:{id}"), JOINS_PER_10_MIN, Duration::from_secs(600))
                || !server.allow(format!("join-ip:{}", observed.ip()), JOINS_PER_10_MIN, Duration::from_secs(600))
            {
                write_msg(&mut send, &RdvResponse::Error { message: "too many pairing attempts; wait a few minutes".into() })
                    .await?;
                return Ok(());
            }
            // Removing the entry burns the code: only one join attempt per code.
            let entry = server.pending.lock().unwrap().remove(&nameplate);
            match entry {
                Some((_, tx)) => {
                    let _ = tx.send((send, recv));
                }
                None => {
                    write_msg(&mut send, &RdvResponse::Error { message: "unknown or expired pairing code".into() }).await?;
                }
            }
        }
    }
    Ok(())
}

/// A pairing host's wait is over: connect it to the joiner, or say why not.
async fn match_pair(
    joined: Result<Result<StreamPair, oneshot::error::RecvError>, tokio::time::error::Elapsed>,
    mut send: quinn::SendStream,
    recv: quinn::RecvStream,
    expired: &str,
) -> Result<()> {
    match joined {
        Ok(Ok((mut jsend, jrecv))) => {
            write_msg(&mut send, &RdvResponse::PairMatched).await?;
            write_msg(&mut jsend, &RdvResponse::PairMatched).await?;
            log("pairing session matched");
            relay(recv, jsend, jrecv, send).await;
        }
        _ => {
            let _ = write_msg(&mut send, &RdvResponse::Error { message: expired.into() }).await;
        }
    }
    Ok(())
}

async fn ask_target(l: &Listener, push: RdvPush) -> Result<Option<Vec<SocketAddr>>> {
    let ask = async {
        let (mut send, mut recv) = l.conn.open_bi().await?;
        write_msg(&mut send, &push).await?;
        let _ = send.finish();
        match read_msg_max(&mut recv, MAX_SMALL).await? {
            RdvPushReply::Allow { candidates } => anyhow::Ok(Some(candidates)),
            RdvPushReply::Reject => Ok(None),
        }
    };
    tokio::time::timeout(ASK_TIMEOUT, ask).await?
}

/// Pipe bytes both ways between the two pairing parties (size and time capped).
async fn relay(a_recv: quinn::RecvStream, mut b_send: quinn::SendStream, b_recv: quinn::RecvStream, mut a_send: quinn::SendStream) {
    let a_to_b = async move {
        let _ = tokio::io::copy(&mut a_recv.take(PAIR_RELAY_LIMIT), &mut b_send).await;
        let _ = b_send.finish();
    };
    let b_to_a = async move {
        let _ = tokio::io::copy(&mut b_recv.take(PAIR_RELAY_LIMIT), &mut a_send).await;
        let _ = a_send.finish();
    };
    // Long enough for the inviter to answer an approval pop-up, even one held
    // back by do-not-disturb.
    let _ = tokio::time::timeout(Duration::from_secs(16 * 60), async { tokio::join!(a_to_b, b_to_a) }).await;
}
