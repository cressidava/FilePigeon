//! The background service: stay reachable to paired peers and answer their
//! requests, asking the user to accept or deny anything that moves files.

use crate::app::App;
use crate::config::Peer;
use crate::gate::Gate;
use crate::netutil::{local_candidates, BoundEndpoint};
use crate::peergate::{knock_context, PeerKeys};
use crate::progress::Progress;
use crate::proto::{Complete, PeerRequest, PeerResponse, RdvPush, RdvPushReply, RdvRequest, RdvResponse, CLOSE_REPLACED, CLOSE_REVOKED, CLOSE_WRONG_DEVICE};
use crate::text::display_safe;
use crate::tls::{peer_public_key, server_config, KeyPolicy, ALPN_PEER};
use crate::transfer::{claim_partials, cleanup_stale_partials, recv_files, resume_offsets, send_files, total_size, validate_metas};
use crate::ui::{transfer_name, Approval, ApprovalKind, Direction, TransferState, Ui};
use crate::upnp::PortGuard;
use crate::wire::{read_msg, read_msg_max, write_msg, MAX_REQUEST};
use crate::{rdv_client, shares};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Most simultaneous connections one peer may hold (each send, browse or get
/// uses its own).
const MAX_CONNS_PER_PEER: usize = 8;
/// Every few seconds at most one "[security]" line per peer reaches the log.
const SECURITY_LOG_EVERY: Duration = Duration::from_secs(10);
/// How we close any connection: identical for shutdown and revocation, so a
/// peer can't tell "you were just hidden" from "the device went offline".
const CLOSE_REASON: &[u8] = b"shutdown";
/// Most approvals one peer may have waiting at once (extras are denied).
const MAX_PENDING_PER_PEER: usize = 2;
/// Most approvals waiting in total.
const MAX_PENDING_TOTAL: usize = 16;
/// A peer must send its request within this long after opening a stream.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// At most this many server pushes per peer within `PUSH_WINDOW` (a normal
/// connection uses one or two: direct, then perhaps relay).
const PUSH_BURST: u32 = 4;
const PUSH_WINDOW: Duration = Duration::from_secs(10);
/// Partial files nobody resumed for this long are deleted.
const PARTIAL_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 3600);

struct Ctx {
    app: Arc<App>,
    ep: BoundEndpoint,
    ui: Arc<dyn Ui>,
    ports: Arc<PortGuard>,
    keys: Arc<PeerKeys>,
    gate: Arc<Gate>,
    /// Live connections per peer key, so revocation can close them.
    conns: Mutex<HashMap<[u8; 32], Vec<quinn::Connection>>>,
    /// Approvals currently waiting, per peer key.
    pending: Mutex<HashMap<[u8; 32], usize>>,
    last_push: Mutex<HashMap<String, (Instant, u32)>>,
    last_security_log: Mutex<HashMap<[u8; 32], Instant>>,
}

impl Ctx {
    /// Log a security event, at most once every few seconds per peer.
    fn security_log(&self, key: &[u8; 32], line: String) {
        let mut last = self.last_security_log.lock().unwrap();
        if last.get(key).is_none_or(|t| t.elapsed() > SECURITY_LOG_EVERY) && last.len() < 10_000 {
            last.insert(*key, Instant::now());
            drop(last);
            self.ui.log(line);
        }
    }
}

/// Holds one pending-approval slot; frees it on drop.
struct PendingSlot<'a> {
    ctx: &'a Ctx,
    key: [u8; 32],
}

impl<'a> PendingSlot<'a> {
    fn take(ctx: &'a Ctx, key: [u8; 32]) -> Option<Self> {
        let mut p = ctx.pending.lock().unwrap();
        let total: usize = p.values().sum();
        let mine = p.entry(key).or_insert(0);
        if *mine >= MAX_PENDING_PER_PEER || total >= MAX_PENDING_TOTAL {
            return None;
        }
        *mine += 1;
        Some(Self { ctx, key })
    }
}

impl Drop for PendingSlot<'_> {
    fn drop(&mut self) {
        if let Some(n) = self.ctx.pending.lock().unwrap().get_mut(&self.key) {
            *n = n.saturating_sub(1);
        }
    }
}

/// Run until `shutdown` completes (or this device signs in elsewhere).
pub async fn serve(app: Arc<App>, ui: Arc<dyn Ui>, shutdown: impl Future<Output = ()>) -> Result<()> {
    // One service per identity; two would keep displacing each other.
    let lock = std::fs::File::create(app.paths.home.join("serve.lock"))?;
    if lock.try_lock().is_err() {
        bail!("FilePigeon is already running for this identity (another window or `filepigeon serve`?)");
    }
    // Invisible: bind nothing and announce nothing. Outgoing sends and browsing
    // use their own short-lived sockets, so they keep working.
    if app.config.invisible {
        ui.log("Invisible: nobody can find or connect to this PC, and no ports are open. You can still send files and browse others.".into());
        shutdown.await;
        ui.log("FilePigeon stopped.".into());
        return Ok(());
    }
    // Two layers: the stealth gate drops everything from anyone who isn't a
    // currently trusted peer (so they get no TLS reply at all), and TLS then
    // pins the exact keys.
    let keys = PeerKeys::new(&app)?;
    let gate = Gate::new(&knock_context(&app.identity.public_key()), keys.clone());
    let server = server_config(&app.identity, KeyPolicy::PairedPeers(app.paths.peers()), ALPN_PEER)?;
    // Keep the same port across restarts so remembered addresses stay valid.
    let remembered = crate::addrbook::own_port(&app).filter(|_| app.config.listen_port == 0);
    let ep = match remembered.map(|p| BoundEndpoint::bind_gated(p, Some(server.clone()), Some(gate.clone()))) {
        Some(Ok(ep)) => ep,
        _ => BoundEndpoint::bind_gated(app.config.listen_port, Some(server), Some(gate.clone()))?,
    };
    if app.config.listen_port == 0 {
        crate::addrbook::set_own_port(&app, ep.port());
    }
    let ports = PortGuard::new(app.config.upnp, ep.port(), ui.clone());
    ui.log(format!(
        "FilePigeon is running as \"{}\" ({}) on UDP {}.",
        app.config.device_name,
        app.identity.device_id(),
        ep.port()
    ));
    let removed = cleanup_stale_partials(&app.config.download_dir, PARTIAL_MAX_AGE);
    if removed > 0 {
        ui.log(format!("Removed {removed} unfinished download(s) older than a week."));
    }
    let ctx = Arc::new(Ctx {
        app,
        ep,
        ui,
        ports,
        keys: keys.clone(),
        gate,
        conns: Default::default(),
        pending: Default::default(),
        last_push: Default::default(),
        last_security_log: Default::default(),
    });

    // Fires if the rendezvous server says this device signed in elsewhere.
    let (replaced_tx, mut replaced_rx) = tokio::sync::oneshot::channel::<()>();
    let mut tasks = Vec::new();
    let mut keep_alive = None;
    {
        let ctx = ctx.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = crate::lan::respond(ctx.keys.clone(), ctx.ep.port()).await {
                ctx.ui.log(format!("[lan] local-network discovery unavailable: {e:#}"));
            }
        }));
    }
    {
        let ctx = ctx.clone();
        tasks.push(tokio::spawn(async move { revocation_watch(ctx).await }));
    }
    if ctx.app.config.dht {
        let ctx = ctx.clone();
        tasks.push(tokio::spawn(async move { dht_loop(ctx).await }));
    }
    ctx.ui.log("[lan] paired devices on your local network can find you".into());
    if ctx.app.config.rendezvous.is_empty() {
        ctx.ui.log("No rendezvous server set: reachable on the local network only.".into());
        keep_alive = Some(replaced_tx);
    } else {
        let holders = ctx.clone();
        tasks.push(tokio::spawn(async move { invite_holders(holders).await }));
        let ctx = ctx.clone();
        tasks.push(tokio::spawn(async move {
            rendezvous_loop(ctx).await;
            let _ = replaced_tx.send(());
        }));
    }
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            incoming = ctx.ep.endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(&ctx, incoming).await {
                        ctx.ui.log(format!("[session] {e:#}"));
                    }
                });
            }
            _ = &mut replaced_rx => {
                ctx.ui.log("This device signed in from somewhere else, so this session stopped.".into());
                break;
            }
            _ = &mut shutdown => break,
        }
    }
    drop(keep_alive);
    for t in tasks {
        t.abort();
    }
    ctx.ports.close().await;
    ctx.ep.endpoint.close(0u32.into(), CLOSE_REASON);
    ctx.ui.online(false);
    ctx.ui.log("FilePigeon stopped.".into());
    Ok(())
}

/// Revocation takes effect at once: when a peer is unpaired or hidden, close
/// its open connections and forget the addresses its knocks admitted. Also
/// sweeps old partial files now and then.
async fn revocation_watch(ctx: Arc<Ctx>) {
    let mut last_cleanup = Instant::now();
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        ctx.gate.revoke_where(|owner| ctx.keys.trusted(owner));
        let revoked: Vec<quinn::Connection> = {
            let mut conns = ctx.conns.lock().unwrap();
            let gone: Vec<[u8; 32]> = conns.keys().filter(|k| !ctx.keys.trusted(k)).copied().collect();
            gone.into_iter().flat_map(|k| conns.remove(&k).unwrap_or_default()).collect()
        };
        for c in revoked {
            c.close(0u32.into(), CLOSE_REASON);
        }
        if last_cleanup.elapsed() > Duration::from_secs(6 * 3600) {
            cleanup_stale_partials(&ctx.app.config.download_dir, PARTIAL_MAX_AGE);
            last_cleanup = Instant::now();
        }
    }
}

/// DHT discovery (experimental): keep an encrypted "you can reach me at" record
/// up for every visible paired peer, and watch for their knocks so we can punch
/// back through our router when one of them is trying to connect.
async fn dht_loop(ctx: Arc<Ctx>) {
    let node = match crate::dht::DhtNode::start().await {
        Ok(n) => Arc::new(n),
        Err(e) => {
            ctx.ui.log(format!("[dht] internet discovery unavailable: {e:#}"));
            return;
        }
    };
    ctx.ui.log("[dht] internet discovery on (experimental)".into());
    let mut seen_knocks = std::collections::HashSet::new();
    let mut last_publish: Option<(Instant, u64)> = None;
    loop {
        let peers: Vec<Peer> = ctx.app.peers().unwrap_or_default().into_iter().filter(|p| !p.hidden).collect();
        let day = crate::dht::current_day();
        let due = last_publish.is_none_or(|(at, d)| at.elapsed() > Duration::from_secs(600) || d != day);
        if due {
            let mut addrs = Vec::new();
            if let Some(ip) = node.public_ip().await {
                addrs.push(SocketAddr::new(ip, ctx.ep.port()));
            }
            addrs.extend(local_candidates(ctx.ep.port()));
            let mut set = tokio::task::JoinSet::new();
            for p in peers.clone() {
                let (node, ctx, addrs) = (node.clone(), ctx.clone(), addrs.clone());
                set.spawn(async move { node.publish_addrs(&ctx.app, &p, &addrs).await });
            }
            let mut failures = 0;
            while let Some(r) = set.join_next().await {
                if !matches!(r, Ok(Ok(()))) {
                    failures += 1;
                }
            }
            if failures > 0 {
                ctx.ui.log(format!("[dht] could not publish for {failures} device(s); will retry"));
            }
            last_publish = Some((Instant::now(), day));
        }
        let mut set = tokio::task::JoinSet::new();
        for p in peers {
            let (node, ctx) = (node.clone(), ctx.clone());
            set.spawn(async move { (node.fetch_knock(&ctx.app, &p).await, p) });
        }
        while let Some(Ok((knock, peer))) = set.join_next().await {
            if let Some(k) = knock {
                if seen_knocks.len() < 10_000 && seen_knocks.insert(k.id.clone()) {
                    ctx.ui.log(format!("[{}] knocking via the DHT; opening a path", peer.name));
                    let ctx = ctx.clone();
                    let targets = usable_candidates(k.addrs);
                    tokio::spawn(async move {
                        // Punch for longer than usual: the other side keeps retrying for ~45 s.
                        for _ in 0..4 {
                            ctx.ep.punch(&targets).await;
                        }
                    });
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(20)).await;
    }
}

/// At most 8 addresses, and never broadcast, multicast or unspecified ones:
/// a malicious server or record must not be able to aim our packets anywhere.
pub fn usable_candidates(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let ok = |a: &SocketAddr| match a.ip() {
        std::net::IpAddr::V4(v4) => !(v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast()) && a.port() != 0,
        std::net::IpAddr::V6(v6) => !(v6.is_unspecified() || v6.is_multicast()) && a.port() != 0,
    };
    let mut out: Vec<SocketAddr> = Vec::new();
    for a in addrs.into_iter().filter(ok) {
        if !out.contains(&a) {
            out.push(a);
        }
        if out.len() == 8 {
            break;
        }
    }
    out
}

async fn rendezvous_loop(ctx: Arc<Ctx>) {
    loop {
        if let Err(e) = run_rendezvous(&ctx).await {
            let closed_with = |code: u32| close_code(&e) == Some(code);
            if closed_with(CLOSE_REPLACED) {
                return;
            }
            if closed_with(CLOSE_WRONG_DEVICE) {
                ctx.ui.online(false);
                ctx.ui.log(
                    "[rendezvous] this server key belongs to a different PC, so the server won't accept it here. Keys can't be copied between PCs: pair this PC with the server's owner to get its own."
                        .into(),
                );
                return;
            }
            if closed_with(CLOSE_REVOKED) {
                // Retrying can't help, and would only knock on a closed door.
                ctx.ui.online(false);
                ctx.ui.log(
                    "[rendezvous] the server's owner revoked this PC's key. Local-network transfers still work; ask them for a new key to reach devices over the internet."
                        .into(),
                );
                return;
            }
            ctx.ui.online(false);
            ctx.ui.log(format!("[rendezvous] {e:#}; retrying in 10s"));
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

/// The application close code behind an error, however it surfaced: the
/// connection itself, or a stream read/write that it cut short.
fn close_code(e: &anyhow::Error) -> Option<u32> {
    fn code(ce: &quinn::ConnectionError) -> Option<u32> {
        match ce {
            quinn::ConnectionError::ApplicationClosed(c) => u32::try_from(c.error_code.into_inner()).ok(),
            _ => None,
        }
    }
    e.chain().find_map(|cause| {
        if let Some(ce) = cause.downcast_ref::<quinn::ConnectionError>() {
            return code(ce);
        }
        if let Some(quinn::ReadError::ConnectionLost(ce)) = cause.downcast_ref::<quinn::ReadError>() {
            return code(ce);
        }
        if let Some(quinn::WriteError::ConnectionLost(ce)) = cause.downcast_ref::<quinn::WriteError>() {
            return code(ce);
        }
        if let Some(quinn::ReadExactError::ReadError(quinn::ReadError::ConnectionLost(ce))) =
            cause.downcast_ref::<quinn::ReadExactError>()
        {
            return code(ce);
        }
        // Stream I/O through AsyncRead/AsyncWrite wraps the quinn error.
        let inner = cause.downcast_ref::<std::io::Error>()?.get_ref()?;
        match (inner.downcast_ref::<quinn::ReadError>(), inner.downcast_ref::<quinn::WriteError>()) {
            (Some(quinn::ReadError::ConnectionLost(ce)), _) | (_, Some(quinn::WriteError::ConnectionLost(ce))) => code(ce),
            _ => None,
        }
    })
}

async fn run_rendezvous(ctx: &Arc<Ctx>) -> Result<()> {
    let conn = rdv_client::connect(&ctx.app, &ctx.ep).await?;
    let _reknock = {
        let ctx = ctx.clone();
        AbortOnDrop(tokio::spawn(async move { rdv_client::keep_knocking(&ctx.app, &ctx.ep).await }))
    };
    let req = RdvRequest::Register { local_addrs: local_candidates(ctx.ep.port()) };
    match rdv_client::request(&conn, &req).await?.2 {
        RdvResponse::Ok => {
            ctx.ui.online(true);
            ctx.ui.log("[rendezvous] online; paired devices can reach you".into());
        }
        RdvResponse::Error { message } => bail!(display_safe(&message, 200)),
        other => bail!("unexpected response {:?}", display_safe(&format!("{other:?}"), 200)),
    }
    loop {
        let (send, recv) = conn.accept_bi().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_push(&ctx, send, recv).await {
                ctx.ui.log(format!("[rendezvous] {e:#}"));
            }
        });
    }
}

/// Aborts a background task when dropped.
/// Wait for friends to use our invite links: one task per unused link, each
/// holding its slot on the server until the friend joins or it expires.
async fn invite_holders(ctx: Arc<Ctx>) {
    let mut running: HashMap<String, AbortOnDrop> = HashMap::new();
    loop {
        let pending = crate::invites::pending(&ctx.app);
        running.retain(|slot, task| !task.0.is_finished() && pending.iter().any(|p| &p.slot == slot));
        for invite in pending {
            if running.contains_key(&invite.slot) {
                continue;
            }
            let (ctx, slot) = (ctx.clone(), invite.slot.clone());
            running.insert(slot, AbortOnDrop(tokio::spawn(async move { host_one_invite(ctx, invite).await })));
        }
        // Often, so a link made a moment ago is ready before the friend pastes it.
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn host_one_invite(ctx: Arc<Ctx>, invite: crate::invites::PendingInvite) {
    let result = crate::pairing::host_invite(&ctx.app, &ctx.ui, &invite).await;
    // An invite is used up by one attempt: forget it, and revoke the
    // temporary server key inside it (it would expire within a day anyway).
    crate::invites::forget_pending(&ctx.app, &invite.slot);
    let _ = crate::invites::revoke(&ctx.app, &invite.temp_invite).await;
    match result {
        Ok(paired) => {
            ctx.ui.log(format!(
                "Paired with \"{}\" ({}) using your invite for {}.",
                paired.peer.name, paired.peer.device_id, invite.friend
            ));
            for note in paired.notes {
                ctx.ui.log(format!("[invite] {note}"));
            }
        }
        Err(e) => ctx.ui.log(format!("[invite] invite for {}: {e:#}", invite.friend)),
    }
}

pub struct AbortOnDrop(pub tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The server says someone wants to connect, directly or via the relay.
/// Only reveal our address (or join a relay) for paired, non-hidden peers,
/// and not more often than every few seconds per peer.
async fn handle_push(ctx: &Ctx, mut send: quinn::SendStream, mut recv: quinn::RecvStream) -> Result<()> {
    let push: RdvPush = tokio::time::timeout(Duration::from_secs(10), read_msg_max(&mut recv, crate::wire::MAX_SMALL))
        .await
        .context("server push timed out")??;
    let from = match &push {
        RdvPush::Incoming { from, .. } | RdvPush::RelayIncoming { from, .. } => from.clone(),
    };
    let peer = ctx.app.peers()?.into_iter().find(|p| p.device_id == from && !p.hidden);
    let too_soon = {
        let mut last = ctx.last_push.lock().unwrap();
        if last.len() > 10_000 {
            last.retain(|_, (t, _)| t.elapsed() < PUSH_WINDOW);
        }
        let entry = last.entry(from.clone()).or_insert((Instant::now(), 0));
        if entry.0.elapsed() > PUSH_WINDOW {
            *entry = (Instant::now(), 0);
        }
        entry.1 += 1;
        entry.1 > PUSH_BURST
    };
    let Some(peer) = peer.filter(|_| !too_soon) else {
        // Hidden peers, strangers and floods all get the same answer: "offline".
        write_msg(&mut send, &RdvPushReply::Reject).await?;
        let _ = send.finish();
        return Ok(());
    };
    match push {
        RdvPush::Incoming { candidates, .. } => {
            // Answer at once (the server only waits a few seconds); a router
            // mapping that already exists is included, a new one is made in the
            // background for the next attempt.
            let extra: Vec<_> = ctx.ports.current().await.into_iter().collect();
            write_msg(&mut send, &RdvPushReply::Allow { candidates: extra }).await?;
            let _ = send.finish();
            if ctx.ports.enabled() {
                let ports = ctx.ports.clone();
                tokio::spawn(async move { ports.open().await });
            }
            ctx.ui.log(format!("[{}] connecting...", peer.name));
            ctx.ep.punch(&usable_candidates(candidates)).await;
        }
        RdvPush::RelayIncoming { relay_port, token, .. } => {
            write_msg(&mut send, &RdvPushReply::Allow { candidates: vec![] }).await?;
            let _ = send.finish();
            ctx.ui.log(format!("[{}] connecting through the encrypted relay...", peer.name));
            let server = ctx.app.rendezvous().await?.addr;
            bind_relay(&ctx.ep, SocketAddr::new(server.ip(), relay_port), &token).await?;
        }
    }
    Ok(())
}

/// Tell the relay which address is ours by sending the bind token from our
/// QUIC socket (a few times, in case a datagram is lost).
pub async fn bind_relay(ep: &BoundEndpoint, relay: SocketAddr, token: &str) -> Result<()> {
    let mut packet = crate::proto::RELAY_MAGIC.to_vec();
    packet.extend(hex::decode(token)?);
    for _ in 0..5 {
        ep.send_raw(&packet, relay);
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    Ok(())
}

async fn handle_connection(ctx: &Arc<Ctx>, incoming: quinn::Incoming) -> Result<()> {
    // Anything that reaches here already passed the stealth gate.
    let Ok(conn) = incoming.await else { return Ok(()) };
    let key = peer_public_key(&conn)?;
    if !ctx.keys.trusted(&key) {
        conn.close(0u32.into(), CLOSE_REASON);
        return Ok(());
    }
    {
        let mut conns = ctx.conns.lock().unwrap();
        let list = conns.entry(key).or_default();
        list.retain(|c| c.close_reason().is_none());
        if list.len() >= MAX_CONNS_PER_PEER {
            drop(conns);
            conn.close(0u32.into(), CLOSE_REASON);
            return Ok(());
        }
        list.push(conn.clone());
    }
    // Confirm acceptance so the peer knows the handshake really succeeded.
    let (mut hello, _) = conn.open_bi().await?;
    hello.write_all(crate::proto::PEER_HELLO).await?;
    let _ = hello.finish();
    ctx.ports.session_started().await;
    while let Ok((send, recv)) = conn.accept_bi().await {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_request(&ctx, key, send, recv).await {
                let who = ctx.app.peer_by_key(&key).ok().flatten().map(|p| p.name).unwrap_or_else(|| "peer".into());
                ctx.ui.log(format!("[{who}] {}", display_safe(&format!("{e:#}"), 300)));
            }
        });
    }
    ctx.ports.session_ended().await;
    if let Some(list) = ctx.conns.lock().unwrap().get_mut(&key) {
        list.retain(|c| c.stable_id() != conn.stable_id());
    }
    Ok(())
}

/// The peer as it is configured *right now*: permissions are re-read for
/// every request, so changes apply even to connections that are already open.
fn current_peer(ctx: &Ctx, key: &[u8; 32]) -> Option<Peer> {
    ctx.app.peer_by_key(key).ok().flatten().filter(|p| !p.hidden)
}

async fn deny(send: &mut quinn::SendStream, reason: &str) -> Result<()> {
    write_msg(send, &PeerResponse::Denied { reason: reason.into() }).await?;
    let _ = send.finish();
    Ok(())
}

async fn handle_request(
    ctx: &Ctx,
    key: [u8; 32],
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<()> {
    let req: PeerRequest = tokio::time::timeout(REQUEST_READ_TIMEOUT, read_msg_max(&mut recv, MAX_REQUEST))
        .await
        .context("request timed out")??;
    let Some(peer) = current_peer(ctx, &key) else {
        let _ = send.reset(0u32.into());
        return Ok(());
    };
    let timeout = ctx.app.config.prompt_timeout_secs;
    match req {
        PeerRequest::Offer { files } => {
            let total = match validate_metas(&files) {
                Ok(t) => t,
                Err(e) => {
                    ctx.security_log(&key, format!("[security] rejected an offer from {}: {e}", peer.name));
                    return deny(&mut send, &e.to_string()).await;
                }
            };
            // Reserved before asking, so a duplicate isn't prompted for twice.
            let dest = ctx.app.config.download_dir.clone();
            let Some(claims) = claim_partials(&dest, &peer.device_id, &files) else {
                return deny(&mut send, "this file is already being received from you").await;
            };
            let approved = if peer.auto_accept {
                true
            } else {
                // The slot only covers waiting for a decision, not the transfer.
                let Some(slot) = PendingSlot::take(ctx, key) else {
                    return deny(&mut send, "too many requests waiting; try again later").await;
                };
                let approval = Approval::new(&peer.name, &peer.device_id, ApprovalKind::Offer, None, &files, timeout);
                let answer = ctx.ui.ask(approval).await;
                drop(slot);
                answer
            };
            // Permissions may have changed while the prompt was open.
            if !approved || current_peer(ctx, &key).is_none() {
                ctx.ui.log(format!("Declined {} file(s) from {}", files.len(), peer.name));
                return deny(&mut send, "declined").await;
            }
            let (d, id, f) = (dest.clone(), peer.device_id.clone(), files.clone());
            let offsets = tokio::task::spawn_blocking(move || resume_offsets(&d, &id, &f)).await?;
            write_msg(&mut send, &PeerResponse::Accepted { offsets: offsets.clone() }).await?;
            let progress = Progress::start(ctx.ui.clone(), &peer.name, Direction::Receive, transfer_name(&files), total);
            match recv_files(&mut recv, &dest, &peer.device_id, &files, &offsets, &progress, &claims).await {
                Ok(complete) => {
                    let message = complete_message(&complete, "Received");
                    progress.finish(if complete.failed.is_empty() {
                        TransferState::Done { message: message.clone() }
                    } else {
                        TransferState::Failed { message: message.clone() }
                    });
                    write_msg(&mut send, &complete).await?;
                    let _ = send.finish();
                    ctx.ui.log(format!("{message} from {} into {}", peer.name, dest.display()));
                }
                Err(e) => {
                    progress.finish(TransferState::Failed { message: display_safe(&format!("{e:#}"), 300) });
                    return Err(e);
                }
            }
        }
        PeerRequest::Browse { path } => {
            let resp = if !peer.allow_browse {
                PeerResponse::Denied { reason: "browsing is not enabled for you".into() }
            } else {
                let app_shares = ctx.app.shares();
                let listing =
                    tokio::task::spawn_blocking(move || app_shares.and_then(|s| shares::list(&s, &path))).await?;
                match listing {
                    Ok(entries) => PeerResponse::Listing { entries },
                    Err(e) => PeerResponse::Error { message: e.to_string() },
                }
            };
            write_msg(&mut send, &resp).await?;
            let _ = send.finish();
        }
        PeerRequest::Fetch { path } => {
            if !peer.allow_browse {
                return deny(&mut send, "shared folders are not enabled for you").await;
            }
            let slot = if peer.auto_accept {
                None
            } else {
                match PendingSlot::take(ctx, key) {
                    Some(s) => Some(s),
                    None => return deny(&mut send, "too many requests waiting; try again later").await,
                }
            };
            let app_shares = ctx.app.shares();
            let p = path.clone();
            let collected =
                tokio::task::spawn_blocking(move || app_shares.and_then(|s| shares::collect_for_fetch(&s, &p))).await?;
            let files = match collected {
                Ok(f) => f,
                Err(e) => {
                    write_msg(&mut send, &PeerResponse::Error { message: e.to_string() }).await?;
                    return Ok(());
                }
            };
            let metas: Vec<_> = files.iter().map(|f| f.meta.clone()).collect();
            let approval =
                Approval::new(&peer.name, &peer.device_id, ApprovalKind::Fetch, Some(path.clone()), &metas, timeout);
            let approved = peer.auto_accept || ctx.ui.ask(approval).await;
            drop(slot);
            let still_allowed = current_peer(ctx, &key).is_some_and(|p| p.allow_browse);
            if !approved || !still_allowed {
                ctx.ui.log(format!("Declined {}'s request for \"{}\"", peer.name, display_safe(&path, 100)));
                return deny(&mut send, "declined").await;
            }
            write_msg(&mut send, &PeerResponse::FetchOffer { files: metas.clone() }).await?;
            let offsets = match tokio::time::timeout(REQUEST_READ_TIMEOUT, read_msg_max(&mut recv, MAX_REQUEST))
                .await
                .context("peer did not answer")??
            {
                PeerResponse::Resume { offsets } => offsets,
                _ => bail!("unexpected reply"),
            };
            let progress =
                Progress::start(ctx.ui.clone(), &peer.name, Direction::Send, transfer_name(&metas), total_size(&metas));
            let result = async {
                send_files(&mut send, &files, &offsets, &progress).await?;
                anyhow::Ok(read_msg::<_, Complete>(&mut recv).await?)
            }
            .await;
            match result {
                Ok(complete) => {
                    let message = complete_message(&complete, "Delivered");
                    progress.finish(TransferState::Done { message: message.clone() });
                    ctx.ui.log(format!("{message} to {} from your shares", peer.name));
                }
                Err(e) => {
                    progress.finish(TransferState::Failed { message: display_safe(&format!("{e:#}"), 300) });
                    return Err(e);
                }
            }
        }
    }
    Ok(())
}

pub fn complete_message(c: &Complete, verb: &str) -> String {
    let received = c.received.min(crate::transfer::MAX_FILES);
    let mut m = format!("{verb} {received} file(s)");
    if !c.failed.is_empty() {
        m.push_str(&format!("; {} failed the integrity check and were discarded", c.failed.len()));
    }
    m
}
