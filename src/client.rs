//! Commands that reach out to a peer: send, browse, get.
//! They return results rather than printing, so the CLI and GUI can both use them.

use crate::app::App;
use crate::config::Peer;
use crate::daemon::{complete_message, usable_candidates};
use crate::peergate::Knocker;
use crate::text::display_safe;
use crate::netutil::{local_candidates, BoundEndpoint};
use crate::progress::{Phase, human, Progress};
use crate::proto::{Complete, DirEntry, PeerRequest, PeerResponse, RdvRequest, RdvResponse};
use crate::rdv_client;
use crate::tls::{client_config, KeyPolicy, ALPN_PEER};
use crate::transfer::{claim_partials, collect_for_send, recv_files, resume_offsets, send_files, total_size, validate_metas};
use crate::ui::{transfer_name, Direction, TransferState, Ui};
use crate::wire::{read_msg, write_msg};
use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;

/// How long to wait for the person on the other end to accept.
const DECISION_WAIT: Duration = Duration::from_secs(15 * 60);

pub enum Outcome {
    Done(Complete),
    Declined(String),
}

struct Session {
    ep: BoundEndpoint,
    conn: quinn::Connection,
    peer: Peer,
    route: Route,
    /// Keeps knocking while the session lives (see `keep_knocking`).
    _reknock: Option<crate::daemon::AbortOnDrop>,
}

/// Re-knock every 20 s for the life of a session, from its socket to its
/// current address: the peer's gate needs a fresh knock every few minutes, and
/// a NAT port change mid-transfer gets re-admitted within seconds.
fn keep_knocking(ep: &BoundEndpoint, conn: &quinn::Connection, knocker: Knocker) -> crate::daemon::AbortOnDrop {
    let sock = ep.raw_clone();
    let conn = conn.clone();
    crate::daemon::AbortOnDrop(tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(20)).await;
            if let Some(sock) = &sock {
                let _ = sock.send_to(&knocker.knock(), conn.remote_address());
            }
        }
    }))
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Route {
    Remembered,
    LocalNetwork,
    Direct,
    Dht,
    /// Through the rendezvous server's relay (slower, still end-to-end encrypted).
    Relay,
}

impl Session {
    fn note_route(&self, ui: &Arc<dyn Ui>) {
        let how = match self.route {
            Route::Remembered => "directly (remembered address)",
            Route::LocalNetwork => "directly (local network)",
            Route::Direct => "directly (via rendezvous introduction)",
            Route::Dht => "directly (found via the DHT)",
            Route::Relay => "through the encrypted relay: the server can't read your files, but it may be slower",
        };
        ui.log(format!("Connected to {} {how}.", self.peer.name));
    }
}

/// Testing aid: skip every direct path so the relay gets used.
fn force_relay() -> bool {
    std::env::var_os("FILEPIGEON_FORCE_RELAY").is_some()
}

/// Testing aid: skip remembered addresses and the local network.
fn skip_local() -> bool {
    force_relay() || std::env::var_os("FILEPIGEON_SKIP_LOCAL").is_some()
}

impl Session {
    /// For the transfer card: how the two PCs are connected.
    fn route_label(&self) -> &'static str {
        match self.route {
            Route::Relay => "Relay",
            _ if crate::netutil::is_private(self.conn.remote_address().ip()) => "Local network",
            _ => "Direct",
        }
    }

    async fn close(self) {
        self.conn.close(0u32.into(), b"bye");
        self.ep.endpoint.wait_idle().await;
    }
}

/// Find the peer and connect, pinned to its key. In order:
///   1. remembered addresses and a local-network lookup (no server involved),
///   2. a direct connection arranged by the rendezvous server,
///   3. the rendezvous server's encrypted relay, as a last resort.
/// Every attempt knocks first: the peer's stealth gate answers nothing else.
async fn connect(app: &App, peer_query: &str) -> Result<Session> {
    let peer = app.find_peer(peer_query)?;
    let key = peer.key().context("stored key for this peer is invalid; re-pair")?;
    let knocker = Knocker::new(app, &peer)?;
    let ep = BoundEndpoint::bind(0, None)?;
    let cfg = client_config(&app.identity, KeyPolicy::only(key), ALPN_PEER)?;

    // 1. Server-free attempts, in parallel.
    let known = if skip_local() { vec![] } else { crate::addrbook::candidates(app, &peer.device_id) };
    let lan_wait = Duration::from_millis(if skip_local() { 0 } else { 800 });
    let (lan_addr, known_conn) = tokio::join!(crate::lan::seek(app, &peer, lan_wait), async {
        if known.is_empty() {
            None
        } else {
            race(&ep, &cfg, &knocker, known.clone(), Duration::from_millis(1500)).await.ok()
        }
    });
    if let Some(conn) = known_conn {
        crate::addrbook::remember(app, &peer.device_id, conn.remote_address());
        return {
            let reknock = Some(keep_knocking(&ep, &conn, knocker));
            Ok(Session { ep, conn, peer, route: Route::Remembered, _reknock: reknock })
        };
    }
    if !known.is_empty() {
        crate::addrbook::failed(app, &peer.device_id, &known);
    }
    if let Some(addr) = lan_addr {
        if let Ok(conn) = race(&ep, &cfg, &knocker, vec![addr], Duration::from_secs(5)).await {
            crate::addrbook::remember(app, &peer.device_id, addr);
            return {
            let reknock = Some(keep_knocking(&ep, &conn, knocker));
            Ok(Session { ep, conn, peer, route: Route::LocalNetwork, _reknock: reknock })
        };
        }
    }
    if app.config.rendezvous.is_empty() {
        if app.config.dht {
            let conn = via_dht(app, &ep, &cfg, &knocker, &peer).await?;
            return {
            let reknock = Some(keep_knocking(&ep, &conn, knocker));
            Ok(Session { ep, conn, peer, route: Route::Dht, _reknock: reknock })
        };
        }
        bail!(
            "{} isn't reachable on your local network (it may be offline or invisible). To connect over the internet, set up a rendezvous server or turn on DHT discovery.",
            peer.name
        );
    }

    // 2. Direct connection with the server's help (hole punching).
    let rdv = match rdv_client::connect(app, &ep).await {
        Ok(rdv) => rdv,
        // Server unreachable: fall back to the DHT if it's enabled.
        Err(e) if app.config.dht => {
            let conn = via_dht(app, &ep, &cfg, &knocker, &peer)
                .await
                .with_context(|| format!("rendezvous server unreachable ({e:#}), and DHT discovery failed"))?;
            return {
            let reknock = Some(keep_knocking(&ep, &conn, knocker));
            Ok(Session { ep, conn, peer, route: Route::Dht, _reknock: reknock })
        };
        }
        Err(e) => return Err(e),
    };
    let req = RdvRequest::Connect { target: peer.device_id.clone(), local_addrs: local_candidates(ep.port()) };
    let candidates = match rdv_client::request(&rdv, &req).await?.2 {
        RdvResponse::PeerCandidates { candidates } => usable_candidates(candidates),
        RdvResponse::Error { message } => bail!("{}: {}", peer.name, display_safe(&message, 200)),
        _ => bail!("unexpected response from the rendezvous server"),
    };
    let direct = if force_relay() {
        Err(anyhow!("direct paths disabled by FILEPIGEON_FORCE_RELAY"))
    } else {
        // A few seconds is enough for hole punching when it works at all; if
        // this device needed the relay recently, give direct even less.
        let budget = if crate::addrbook::relayed_recently(app, &peer.device_id) { 1500 } else { 3000 };
        race(&ep, &cfg, &knocker, candidates, Duration::from_millis(budget)).await
    };
    let (conn, route) = match direct {
        Ok(conn) => {
            crate::addrbook::remember(app, &peer.device_id, conn.remote_address());
            (conn, Route::Direct)
        }
        // 3. Relay. Still end-to-end encrypted and pinned to the peer's key.
        Err(direct_err) => match via_relay(app, &ep, &cfg, &knocker, &rdv, &peer).await {
            Ok(conn) => (conn, Route::Relay),
            Err(relay_err) => bail!(
                "could not reach {} directly ({direct_err:#}) or through the relay ({relay_err:#})",
                peer.name
            ),
        },
    };
    rdv.close(0u32.into(), b"done");
    crate::addrbook::note_route(app, &peer.device_id, matches!(route, Route::Relay));
    {
            let reknock = Some(keep_knocking(&ep, &conn, knocker));
            Ok(Session { ep, conn, peer, route, _reknock: reknock })
        }
}

async fn via_relay(
    app: &App,
    ep: &BoundEndpoint,
    cfg: &quinn::ClientConfig,
    knocker: &Knocker,
    rdv: &quinn::Connection,
    peer: &Peer,
) -> Result<quinn::Connection> {
    let (relay_port, token) = match rdv_client::request(rdv, &RdvRequest::Relay { target: peer.device_id.clone() }).await?.2 {
        RdvResponse::RelayReady { relay_port, token } => (relay_port, token),
        RdvResponse::Error { message } => bail!(display_safe(&message, 200)),
        _ => bail!("unexpected response from the rendezvous server"),
    };
    let server = app.rendezvous().await?.addr;
    let relay = std::net::SocketAddr::new(server.ip(), relay_port);
    crate::daemon::bind_relay(ep, relay, &token).await?;
    // The knock travels through the relay too, so the peer's gate admits it.
    race(ep, cfg, knocker, vec![relay], Duration::from_secs(15)).await
}

/// Find the peer's addresses in the DHT, leave a knock so it punches back,
/// and keep trying to connect while it notices (it checks every ~20 s).
async fn via_dht(
    app: &App,
    ep: &BoundEndpoint,
    cfg: &quinn::ClientConfig,
    knocker: &Knocker,
    peer: &Peer,
) -> Result<quinn::Connection> {
    let window = Duration::from_secs(45);
    let deadline = tokio::time::Instant::now() + window;
    let attempt = async {
        let node = crate::dht::DhtNode::start().await?;
        let addrs = usable_candidates(node.fetch_addrs(app, peer).await.unwrap_or_default());
        anyhow::ensure!(!addrs.is_empty(), "no answer");
        let mut mine = local_candidates(ep.port());
        if let Some(ip) = node.public_ip().await {
            mine.insert(0, std::net::SocketAddr::new(ip, ep.port()));
        }
        node.knock(app, peer, &mine).await?;
        // Open our own router towards them while we wait for them to notice.
        let targets = addrs.clone();
        let punching = async {
            loop {
                ep.punch(&targets).await;
            }
        };
        tokio::select! {
            r = race(ep, cfg, knocker, addrs, window) => r,
            _ = punching => unreachable!(),
        }
    };
    let result = attempt.await;
    if result.is_err() {
        // A missing record, a refusal and silence must all look the same.
        tokio::time::sleep_until(deadline).await;
    }
    result.with_context(|| {
        format!("{} didn't answer (it may be offline, or its router may not allow this kind of connection)", peer.name)
    })
}

/// Wait for the peer's hello: proof it accepted us (not just that our side of
/// the TLS handshake finished).
async fn confirmed(conn: quinn::Connection) -> Result<quinn::Connection> {
    let wait = async {
        let (_, mut recv) = conn.accept_bi().await?;
        let mut hello = [0u8; 3];
        recv.read_exact(&mut hello).await?;
        anyhow::ensure!(&hello == crate::proto::PEER_HELLO, "unexpected hello from peer");
        anyhow::Ok(())
    };
    tokio::time::timeout(Duration::from_secs(5), wait).await.map_err(|_| anyhow!("peer did not confirm"))??;
    Ok(conn)
}

/// Race QUIC handshakes to every candidate; the first confirmed one wins.
/// Fresh knocks go to every candidate throughout, from the same socket, so the
/// peer's gate admits us as soon as one arrives (and keeps us through NAT
/// punching delays).
async fn race(
    ep: &BoundEndpoint,
    cfg: &quinn::ClientConfig,
    knocker: &Knocker,
    candidates: Vec<std::net::SocketAddr>,
    timeout: Duration,
) -> Result<quinn::Connection> {
    let deadline = tokio::time::Instant::now() + timeout;
    let candidates = usable_candidates(candidates);
    // Knock before the first handshake packet so it isn't dropped by the gate.
    for addr in &candidates {
        ep.send_raw(&knocker.knock(), *addr);
    }
    let mut attempts = JoinSet::new();
    for &addr in &candidates {
        let (endpoint, cfg) = (ep.endpoint.clone(), cfg.clone());
        attempts.spawn(async move { confirmed(endpoint.connect_with(cfg, addr, "filepigeon")?.await?).await });
    }
    let knocking = async {
        loop {
            tokio::time::sleep(Duration::from_millis(300)).await;
            for addr in &candidates {
                ep.send_raw(&knocker.knock(), *addr);
            }
        }
    };
    let first = async {
        while let Some(res) = attempts.join_next().await {
            if let Ok(Ok(conn)) = res {
                return Some(conn);
            }
        }
        None
    };
    let winner = tokio::select! {
        r = tokio::time::timeout_at(deadline, first) => r.ok().flatten(),
        _ = knocking => None,
    };
    match winner {
        Some(conn) => Ok(conn),
        // Deliberately vague and never early: the other side's reason for
        // refusing (e.g. "you are hidden") must not reach the user, and a
        // refusal must take as long as silence.
        None => {
            tokio::time::sleep_until(deadline).await;
            Err(anyhow!("no answer"))
        }
    }
}

pub async fn send(app: &App, ui: Arc<dyn Ui>, peer_query: &str, paths: &[PathBuf]) -> Result<Outcome> {
    let files = collect_for_send(paths)?;
    if files.is_empty() {
        bail!("nothing to send (empty folder?)");
    }
    let metas: Vec<_> = files.iter().map(|f| f.meta.clone()).collect();
    let total = total_size(&metas);
    let offer = PeerRequest::Offer { files: metas.clone() };
    if serde_json::to_vec(&offer)?.len() > crate::wire::MAX_REQUEST {
        bail!("that's too many files to offer at once ({}); send them in smaller batches", files.len());
    }
    let peer = app.find_peer(peer_query)?;
    // The card appears at once, while still connecting, and can be cancelled
    // at any point.
    let progress = Progress::begin(ui.clone(), &peer.name, Direction::Send, transfer_name(&metas), total, Phase::Connecting);
    let result = tokio::select! {
        r = send_inner(app, &ui, peer_query, &files, offer, &progress) => r,
        _ = progress.cancelled() => Err(anyhow!("cancelled")),
    };
    match &result {
        Ok(Outcome::Done(complete)) => {
            let message = complete_message(complete, "Delivered");
            progress.finish(if complete.failed.is_empty() {
                TransferState::Done { message }
            } else {
                TransferState::Failed { message }
            });
        }
        Ok(Outcome::Declined(reason)) => {
            progress.finish(TransferState::Failed { message: format!("{} declined ({reason})", peer.name) })
        }
        Err(e) => progress.finish(crate::daemon::failure_state(e, &peer.name)),
    }
    result
}

async fn send_inner(
    app: &App,
    ui: &Arc<dyn Ui>,
    peer_query: &str,
    files: &[crate::transfer::LocalFile],
    offer: PeerRequest,
    progress: &Progress,
) -> Result<Outcome> {
    let s = connect(app, peer_query).await?;
    s.note_route(ui);
    progress.set_route(s.route_label());
    progress.attach(&s.conn);
    progress.set_phase(Phase::Waiting);
    let (mut send, mut recv) = s.conn.open_bi().await?;
    write_msg(&mut send, &offer).await?;
    ui.log(format!("Offered {} file(s) to {}. Waiting for them to accept...", files.len(), s.peer.name));

    let resp = tokio::time::timeout(DECISION_WAIT, read_msg(&mut recv)).await.context("no answer")??;
    let outcome = match resp {
        PeerResponse::Accepted { offsets } => {
            progress.set_phase(Phase::Transferring);
            send_files(&mut send, files, &offsets, progress).await?;
            send.finish()?;
            let mut complete: Complete = read_msg(&mut recv).await?;
            // The receiver's report is peer-supplied text.
            complete.failed = complete.failed.iter().take(1000).map(|f| display_safe(f, 200)).collect();
            Outcome::Done(complete)
        }
        PeerResponse::Denied { reason } => Outcome::Declined(display_safe(&reason, 200)),
        _ => bail!("unexpected reply from {}", s.peer.name),
    };
    s.close().await;
    Ok(outcome)
}

pub async fn browse(app: &App, peer_query: &str, path: &str) -> Result<Vec<DirEntry>> {
    let s = connect(app, peer_query).await?;
    let (mut send, mut recv) = s.conn.open_bi().await?;
    write_msg(&mut send, &PeerRequest::Browse { path: path.to_string() }).await?;
    send.finish()?;
    let result = match read_msg(&mut recv).await? {
        // Names come from someone else's disk: make them safe to show.
        PeerResponse::Listing { entries } => Ok(entries
            .into_iter()
            .take(100_000)
            .map(|e| DirEntry { name: display_safe(&e.name, 255), ..e })
            .collect()),
        PeerResponse::Denied { .. } => Err(anyhow!(
            "{} hasn't let you browse their shared folders. They can turn on \"Can browse\" for you on their Devices page.",
            s.peer.name
        )),
        PeerResponse::Error { message } => Err(anyhow!(display_safe(&message, 200))),
        _ => Err(anyhow!("unexpected reply from {}", s.peer.name)),
    };
    s.close().await;
    result
}

pub async fn get(app: &App, ui: Arc<dyn Ui>, peer_query: &str, path: &str, dest: &Path) -> Result<Outcome> {
    let s = connect(app, peer_query).await?;
    s.note_route(&ui);
    let (mut send, mut recv) = s.conn.open_bi().await?;
    write_msg(&mut send, &PeerRequest::Fetch { path: path.to_string() }).await?;
    ui.log(format!("Requested \"{path}\" from {}. Waiting for them to approve...", s.peer.name));

    let resp = tokio::time::timeout(DECISION_WAIT, read_msg(&mut recv)).await.context("no answer")??;
    let outcome = match resp {
        PeerResponse::FetchOffer { files } => {
            let total = validate_metas(&files)?;
            check_matches_request(path, &files)?;
            ui.log(format!("{} is sending {} file(s), {}.", s.peer.name, files.len(), human(total)));
            let claims = claim_partials(dest, &s.peer.device_id, &files)
                .context("this file is already being downloaded")?;
            let offsets = resume_offsets(dest, &s.peer.device_id, &files);
            write_msg(&mut send, &PeerResponse::Resume { offsets: offsets.clone() }).await?;
            let progress = Progress::start(ui.clone(), &s.peer.name, Direction::Receive, transfer_name(&files), total);
            progress.set_route(s.route_label());
            progress.attach(&s.conn);
            match recv_files(&mut recv, dest, &s.peer.device_id, &files, &offsets, &progress, &claims).await {
                Ok(complete) => {
                    let message = complete_message(&complete, "Received");
                    progress.finish(if complete.failed.is_empty() {
                        TransferState::Done { message }
                    } else {
                        TransferState::Failed { message }
                    });
                    write_msg(&mut send, &complete).await?;
                    send.finish()?;
                    let _ = tokio::time::timeout(Duration::from_secs(5), send.stopped()).await;
                    Outcome::Done(complete)
                }
                Err(e) => {
                    progress.finish(crate::daemon::failure_state(&e, &s.peer.name));
                    return Err(e);
                }
            }
        }
        PeerResponse::Denied { reason } => Outcome::Declined(display_safe(&reason, 200)),
        PeerResponse::Error { message } => bail!(display_safe(&message, 200)),
        _ => bail!("unexpected reply from {}", s.peer.name),
    };
    s.close().await;
    Ok(outcome)
}

/// A fetch reply must contain only what was asked for: the requested item (or
/// files inside the requested folder), never unrelated files pushed unasked.
fn check_matches_request(requested: &str, files: &[crate::proto::FileMeta]) -> Result<()> {
    // Compared without regard to case: the owner reports names with their real
    // on-disk casing, which may differ from what was typed.
    let requested = requested.trim_matches('/').to_lowercase();
    // A whole share arrives under the share's own name; an item under its name.
    let base = requested.rsplit_once('/').map(|(_, b)| b.to_string()).unwrap_or(requested.clone());
    let ok = files.iter().all(|f| {
        let p = f.path.to_lowercase();
        p == base || p.starts_with(&format!("{base}/"))
    });
    if !ok {
        bail!("the other device sent files you didn't ask for; refused");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::check_matches_request;
    use crate::proto::FileMeta;

    #[test]
    fn fetch_reply_must_match_request() {
        let f = |p: &str| FileMeta { path: p.into(), size: 1 };
        assert!(check_matches_request("music/Jazz", &[f("Jazz/a.flac"), f("Jazz/b/c.flac")]).is_ok());
        assert!(check_matches_request("music/Jazz/a.flac", &[f("a.flac")]).is_ok());
        assert!(check_matches_request("music/Jazz", &[f("Jazz/a.flac"), f("evil.exe")]).is_err());
        assert!(check_matches_request("music/Jazz/a.flac", &[f("other.exe")]).is_err());
        assert!(check_matches_request("music", &[f("music/a"), f("Music/b/c")]).is_ok());
        assert!(check_matches_request("music", &[f("music/a"), f("Other/b")]).is_err());
        assert!(check_matches_request("music", &[f("invoice.pdf.exe")]).is_err(), "whole share must use its name");
        assert!(check_matches_request("music/jazz", &[f("Jazz/a.flac")]).is_ok(), "case-insensitive");
    }
}
