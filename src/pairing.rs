//! One-time-code pairing using SPAKE2 (a password-authenticated key exchange).
//!
//! The two sides talk directly on the local network, or through the
//! rendezvous server, which only relays opaque messages between them.
//! Knowing the code is what authenticates them: without it, a relay (or
//! attacker) cannot learn the shared key, and a wrong guess just fails.
//! Once a strong shared key exists, each side sends its long-term public key
//! encrypted under it. From then on, connections are pinned to those keys.

use crate::app::{App, RdvTarget};
use crate::invites::{InviteCode, PendingInvite};
use crate::text::display_safe;
use crate::ui::{Approval, ApprovalKind, Ui};
use std::sync::Arc;
use crate::config::Peer;
use crate::identity::{device_id, Identity};
use crate::netutil::BoundEndpoint;
use crate::tls::{client_config, server_config, KeyPolicy, ALPN_PAIR};
use crate::proto::{PairInfo, PairMsg, PairServerOffer, RdvRequest, RdvResponse};
use crate::wire::{read_msg, write_msg};
use crate::{rdv_client, words};
use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use spake2::{Ed25519Group, Identity as SpakeId, Password, Spake2};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CODE_WORDS: usize = 3;
/// How long to wait for the other side's confirmation.
const CONFIRM_WAIT: Duration = Duration::from_secs(60);
/// Joining by invite link: the inviter may take a while to answer the
/// approval pop-up (do-not-disturb can hold it for 14 minutes).
const INVITE_CONFIRM_WAIT: Duration = Duration::from_secs(16 * 60);

struct ServerSlot {
    rdv: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    nameplate: u32,
}

enum Joined {
    Server,
    Lan(quinn::Connection, quinn::SendStream, quinn::RecvStream),
}

async fn allocate(app: &App, ep: &BoundEndpoint) -> Result<ServerSlot> {
    let rdv = rdv_client::connect(app, &ep).await?;
    let (send, recv, resp) = rdv_client::request(&rdv, &RdvRequest::PairAllocate).await?;
    match resp {
        RdvResponse::Nameplate { nameplate } => Ok(ServerSlot { rdv, send, recv, nameplate }),
        RdvResponse::Error { message } => bail!(message),
        other => bail!("unexpected response {other:?}"),
    }
}

async fn accept_lan(ep: &quinn::Endpoint) -> Result<(quinn::Connection, quinn::SendStream, quinn::RecvStream)> {
    // A stray or hostile connection must not end the pairing session: skip it
    // and keep waiting for the real joiner (or for the server path).
    loop {
        let incoming = ep.accept().await.context("pairing endpoint closed")?;
        let Ok(conn) = incoming.await else { continue };
        match tokio::time::timeout(Duration::from_secs(10), conn.accept_bi()).await {
            Ok(Ok((send, recv))) => return Ok((conn, send, recv)),
            _ => continue,
        }
    }
}

/// Create a code (handed to `on_code` for display) and wait up to 10 minutes
/// for the other PC to enter it, either on the local network (no server
/// needed) or through the rendezvous server if one is configured.
/// The result of a pairing.
pub struct Paired {
    pub peer: Peer,
    /// What happened with server access, for the user to read.
    pub notes: Vec<String>,
    /// This PC now uses a server it was given (restart the service to connect).
    pub server_changed: bool,
}

pub async fn host(app: &App, give_server: bool, on_code: impl FnOnce(&str)) -> Result<Paired> {
    let ep = BoundEndpoint::bind(0, None)?;
    let mut server_err = None;
    let mut server = if app.config.rendezvous.is_empty() {
        None
    } else {
        allocate(app, &ep).await.map_err(|e| server_err = Some(e)).ok()
    };
    let lan_sock = crate::lan::bind_shared().ok();
    if server.is_none() && lan_sock.is_none() {
        return Err(server_err.unwrap_or_else(|| anyhow!("local-network pairing is unavailable (port {} busy)", crate::lan::LAN_PORT)));
    }
    let nameplate = server.as_ref().map(|s| s.nameplate).unwrap_or_else(|| rand::random_range(1..10_000));
    // A throwaway certificate: SPAKE2 authenticates, so our real identity key
    // is never shown to whoever happens to connect.
    let lan_ep = BoundEndpoint::bind(0, Some(server_config(&Identity::ephemeral()?, KeyPolicy::Any, ALPN_PAIR)?))?;
    let password = words::pick(CODE_WORDS).join("-");
    on_code(&format!("{nameplate}-{password}"));

    let joined = {
        let via_server = async {
            match server.as_mut() {
                Some(s) => match read_msg(&mut s.recv).await? {
                    RdvResponse::PairMatched => Ok(Joined::Server),
                    RdvResponse::Error { message } => Err(anyhow!(message)),
                    other => Err(anyhow!("unexpected response {other:?}")),
                },
                None => std::future::pending().await,
            }
        };
        let via_lan = async {
            match &lan_sock {
                Some(sock) => tokio::select! {
                    r = accept_lan(&lan_ep.endpoint) => r.map(|(c, s, r)| Joined::Lan(c, s, r)),
                    // If the local listener fails, keep waiting on the server path instead.
                    _ = crate::lan::answer_pair_seeks(sock, nameplate, lan_ep.port()) => std::future::pending().await,
                },
                None => std::future::pending().await,
            }
        };
        let either = async {
            tokio::select! {
                r = via_server => r,
                r = via_lan => r,
            }
        };
        match tokio::time::timeout(Duration::from_secs(600), either).await {
            Ok(r) => r?,
            Err(_) => bail!("nobody entered the code in time"),
        }
    };

    let result = match joined {
        Joined::Server => {
            let s = server.as_mut().expect("server path");
            exchange(app, &mut s.send, &mut s.recv, true, nameplate, &password, give_server, None, CONFIRM_WAIT, None).await
        }
        Joined::Lan(conn, mut send, mut recv) => {
            let r = exchange(app, &mut send, &mut recv, true, nameplate, &password, give_server, None, CONFIRM_WAIT, None).await;
            conn.close(0u32.into(), b"done");
            r
        }
    };
    if let Some(s) = server {
        s.rdv.close(0u32.into(), b"done");
    }
    result
}

/// Enter a code shown on the other PC. With a rendezvous server configured,
/// the server path is tried first (a local-network answer can't be
/// authenticated before SPAKE2, so an impostor there could take a guess);
/// otherwise the local network. A code that has failed once is refused here
/// for a while, so retyping it can't hand an impostor another guess.
pub async fn join(app: &App, code: &str, give_server: bool) -> Result<Paired> {
    let (nameplate, password) = parse_code(code)?;
    if failed_recently(app, nameplate, &password) {
        bail!("this code already failed once and can't be trusted; create a new code on the other PC");
    }
    let result = join_inner(app, nameplate, &password, give_server).await;
    if let Err(e) = &result {
        if e.to_string().contains("did not match") {
            remember_failed(app, nameplate, &password);
        }
    }
    result
}

async fn join_inner(app: &App, nameplate: u32, password: &str, give_server: bool) -> Result<Paired> {
    let ep = BoundEndpoint::bind(0, None)?;
    let server_first = !app.config.rendezvous.is_empty();
    if server_first {
        match join_via_server(app, &ep, nameplate, password, give_server).await {
            Err(e) if e.to_string().contains("unknown or expired") => {} // maybe a local-only code
            other => return other,
        }
    }
    if let Some(addr) = crate::lan::seek_pair(nameplate, Duration::from_millis(1500)).await {
        let cfg = client_config(&Identity::ephemeral()?, KeyPolicy::Any, ALPN_PAIR)?;
        let conn = ep
            .endpoint
            .connect_with(cfg, addr, "filepigeon-pair")?
            .await
            .context("could not reach the other PC on the local network")?;
        let (mut send, mut recv) = conn.open_bi().await?;
        let peer = exchange(app, &mut send, &mut recv, false, nameplate, password, give_server, None, CONFIRM_WAIT, None).await;
        conn.close(0u32.into(), b"done");
        return peer;
    }
    if server_first {
        bail!("unknown or expired pairing code");
    }
    bail!(
        "No PC on your local network is showing that code. Check that both PCs are on the same network and the code is still on screen (or set up a rendezvous server to pair over the internet)."
    );
}

async fn join_via_server(app: &App, ep: &BoundEndpoint, nameplate: u32, password: &str, give_server: bool) -> Result<Paired> {
    let rdv = rdv_client::connect(app, ep).await?;
    let (mut send, mut recv, resp) = rdv_client::request(&rdv, &RdvRequest::PairJoin { nameplate }).await?;
    match resp {
        RdvResponse::PairMatched => {}
        RdvResponse::Error { message } => bail!(crate::text::display_safe(&message, 200)),
        _ => bail!("unexpected response from the rendezvous server"),
    }
    let peer = exchange(app, &mut send, &mut recv, false, nameplate, password, give_server, None, CONFIRM_WAIT, None).await;
    rdv.close(0u32.into(), b"done");
    peer
}

/// Codes that failed, as hashes with a timestamp (kept 15 minutes).
fn failed_codes_path(app: &App) -> std::path::PathBuf {
    app.paths.home.join("failed-codes.json")
}

fn code_hash(nameplate: u32, password: &str) -> String {
    blake3::hash(format!("{nameplate}-{password}").as_bytes()).to_hex()[..32].to_string()
}

fn failed_recently(app: &App, nameplate: u32, password: &str) -> bool {
    let list: Vec<(String, u64)> = crate::config::load_json(&failed_codes_path(app)).unwrap_or_default();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let h = code_hash(nameplate, password);
    list.iter().any(|(c, t)| *c == h && now.saturating_sub(*t) < 900)
}

fn remember_failed(app: &App, nameplate: u32, password: &str) {
    let path = failed_codes_path(app);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut list: Vec<(String, u64)> = crate::config::load_json(&path).unwrap_or_default();
    list.retain(|(_, t)| now.saturating_sub(*t) < 900);
    list.push((code_hash(nameplate, password), now));
    let _ = crate::config::save_json(&path, &list);
}

/// Pair using whatever was entered: an invite (link or code, anywhere in
/// the pasted text) or a nearby pairing code. `on_check` gets the check words
/// to show while the inviter decides.
pub async fn join_any(app: &App, text: &str, give_server: bool, on_check: &CheckFn) -> Result<Paired> {
    match InviteCode::find(text) {
        Some(code) => join_invite(app, &code?, on_check).await,
        None => join(app, text, give_server).await,
    }
}

/// Shows the check words to the user (`|words| ...`).
pub type CheckFn = dyn Fn(&str) + Send + Sync;

/// The invited side: get past the inviter's server's stealth gate with the
/// knock secret derived from the code, join the slot the inviter's PC holds,
/// and pair with the code's password. The inviter approves (comparing check
/// words); we then get our own permanent, device-locked server key.
pub async fn join_invite(app: &App, code: &InviteCode, on_check: &CheckFn) -> Result<Paired> {
    let secrets = {
        let code = code.clone();
        tokio::task::spawn_blocking(move || code.secrets()).await??
    };
    let addr = crate::app::resolve_server(&code.address).await?;
    // (A private address is fine: at the inviter's home, split DNS sends the
    // server's name to its LAN address. The proof below is what matters.)
    // The server's key isn't known yet. Until the server proves it holds this
    // invite's key, we use a throwaway identity and reveal nothing.
    let target = RdvTarget { addr, server_key: [0u8; 32], knock_secret: secrets.knock };
    let ep = BoundEndpoint::bind(0, None)?;
    let rdv = rdv_client::connect_unpinned(&crate::identity::Identity::ephemeral()?, &target, &ep).await.map_err(|_| {
        anyhow!("this invite doesn't work: it was already used, cancelled or expired, or the server can't be reached. Ask for a new one.")
    })?;
    {
        let server_pk = crate::tls::peer_public_key(&rdv)?;
        let mut nonce = [0u8; 16];
        crate::os_random(&mut nonce);
        let proof = tokio::time::timeout(
            Duration::from_secs(10),
            rdv_client::request(&rdv, &RdvRequest::Prove { nonce: hex::encode(nonce) }),
        )
        .await
        .context("the invite's server didn't answer")??
        .2;
        let expected = crate::invites::server_proof(&secrets.knock, &nonce, &server_pk);
        match proof {
            RdvResponse::Proof { mac } if hex::decode(&mac).ok().as_deref() == Some(&expected[..]) => {}
            _ => bail!("the server for this invite couldn't prove it's the right one; not joining"),
        }
    }
    let attempt = async {
        let req = RdvRequest::PairJoinSlot { slot: hex::encode(secrets.slot) };
        // If the inviter's PC isn't holding the slot yet (the invite was made a
        // moment ago, or it's reconnecting), try again for a little while.
        let mut tries = 0;
        let (mut send, mut recv) = loop {
            let (send, recv, resp) = rdv_client::request(&rdv, &req).await?;
            match resp {
                RdvResponse::PairMatched => break (send, recv),
                RdvResponse::Error { message } if message.contains("isn't online right now") && tries < 4 => {
                    tries += 1;
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                RdvResponse::Error { message } => bail!(display_safe(&message, 200)),
                _ => bail!("unexpected response from the rendezvous server"),
            }
        };
        exchange(app, &mut send, &mut recv, false, 0, &secrets.password, false, None, INVITE_CONFIRM_WAIT, Some(on_check))
            .await
    };
    // The wait for the inviter's approval can outlast the server's admission.
    let result = tokio::select! {
        r = attempt => r,
        _ = rdv_client::keep_knocking_to(&target, &ep) => unreachable!(),
    };
    rdv.close(0u32.into(), b"done");
    result
}

/// The inviting side, run by the background service: hold the invite's slot
/// on our server until the friend joins (re-holding every 10 minutes and
/// after any disconnect), then pair, asking `ui` to approve first. An invite
/// is used up by one pairing attempt, approved or not.
pub async fn host_invite(app: &App, ui: &Arc<dyn Ui>, invite: &PendingInvite) -> Result<Paired> {
    let secrets = {
        let code = invite.code();
        tokio::task::spawn_blocking(move || code.secrets()).await??
    };
    let mut last_error = String::new();
    loop {
        if !crate::invites::waiting(app).iter().any(|p| p.slot == invite.slot) {
            bail!("the invite for {} was cancelled or expired", invite.friend);
        }
        let ep = BoundEndpoint::bind(0, None)?;
        let attempt = async {
            let rdv = rdv_client::connect(app, &ep).await?;
            let req = RdvRequest::PairHold { slot: invite.slot.clone() };
            let (mut send, mut recv, resp) = rdv_client::request(&rdv, &req).await?;
            match resp {
                RdvResponse::Ok => {}
                RdvResponse::Error { message } => bail!(display_safe(&message, 200)),
                _ => bail!("unexpected response from the rendezvous server"),
            }
            let outcome = match read_msg(&mut recv).await? {
                RdvResponse::PairMatched => {
                    let approval = Some((ui, app.config.prompt_timeout_secs, invite.friend.as_str()));
                    Some(
                        exchange(app, &mut send, &mut recv, true, 0, &secrets.password, true, approval, CONFIRM_WAIT, None)
                            .await,
                    )
                }
                // Nobody joined in this window: hold again.
                _ => None,
            };
            rdv.close(0u32.into(), b"done");
            anyhow::Ok(outcome)
        };
        let result = tokio::select! {
            r = attempt => r,
            _ = rdv_client::keep_knocking(app, &ep) => unreachable!(),
        };
        match result {
            Ok(Some(paired)) => return paired,
            Ok(None) => {}
            Err(e) => {
                // Say so once (not every retry), e.g. while the server is unreachable.
                let message = format!("{e:#}");
                if message != last_error {
                    ui.log(format!("[invite] can't wait for {} yet: {message}; retrying", invite.friend));
                    last_error = message;
                }
                tokio::time::sleep(Duration::from_secs(20)).await;
            }
        }
    }
}

fn parse_code(code: &str) -> Result<(u32, String)> {
    let code = code.trim().to_lowercase();
    let (num, password) = code.split_once('-').context("code should look like 7-river-falcon-lotus")?;
    let nameplate = num.parse().context("code should start with a number")?;
    let ws: Vec<_> = password.split('-').collect();
    if ws.len() != CODE_WORDS {
        bail!("code should have a number and {CODE_WORDS} words");
    }
    if let Some(bad) = ws.iter().find(|w| !words::is_word(w)) {
        bail!("{bad:?} is not a pairing word; check for typos");
    }
    Ok((nameplate, password.to_string()))
}

async fn exchange(
    app: &App,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    is_host: bool,
    nameplate: u32,
    password: &str,
    give_server: bool,
    approval: Option<(&Arc<dyn Ui>, u64, &str)>,
    confirm_wait: Duration,
    on_check: Option<&CheckFn>,
) -> Result<Paired> {
    let timeout = Duration::from_secs(60);
    let pw = Password::new(password.as_bytes());
    let id_a = SpakeId::new(format!("filepigeon-pair-a:{nameplate}").as_bytes());
    let id_b = SpakeId::new(format!("filepigeon-pair-b:{nameplate}").as_bytes());
    let (state, outbound) = if is_host {
        Spake2::<Ed25519Group>::start_a(&pw, &id_a, &id_b)
    } else {
        Spake2::<Ed25519Group>::start_b(&pw, &id_a, &id_b)
    };
    // Commit, then reveal: the host first sends only a hash of its message,
    // the joiner answers with its own, then the host reveals. Someone in the
    // middle therefore can't try message after message until the two sides'
    // check words happen to match: each side's key is fixed before the other
    // side's contribution is known.
    let inbound = if is_host {
        let commit = blake3::derive_key("filepigeon pairing commitment v1", &outbound);
        write_msg(send, &PairMsg { data: hex::encode(commit) }).await?;
        let theirs: PairMsg = tokio::time::timeout(timeout, read_msg(recv)).await??;
        write_msg(send, &PairMsg { data: hex::encode(&outbound) }).await?;
        hex::decode(theirs.data)?
    } else {
        let commit: PairMsg = tokio::time::timeout(timeout, read_msg(recv)).await??;
        write_msg(send, &PairMsg { data: hex::encode(&outbound) }).await?;
        let reveal: PairMsg = tokio::time::timeout(timeout, read_msg(recv)).await??;
        let reveal = hex::decode(reveal.data)?;
        let expected = blake3::derive_key("filepigeon pairing commitment v1", &reveal);
        if hex::decode(commit.data).ok().as_deref() != Some(&expected[..]) {
            bail!("pairing failed: the other side's messages didn't add up (both PCs need FilePigeon 0.2.2 or newer)");
        }
        reveal
    };
    let shared = state.finish(&inbound).map_err(|e| anyhow!("pairing failed: {e:?}"))?;
    // Both sides derive the same words only if nobody sits in between.
    let check = crate::invites::check_words(&shared);

    // Separate keys per direction.
    let a_to_b = blake3::derive_key("filepigeon 2026-10 pairing a->b", &shared);
    let b_to_a = blake3::derive_key("filepigeon 2026-10 pairing b->a", &shared);
    let (mine, theirs) = if is_host { (a_to_b, b_to_a) } else { (b_to_a, a_to_b) };
    let seal = ChaCha20Poly1305::new(&Key::from(mine));
    let open = ChaCha20Poly1305::new(&Key::from(theirs));
    let mismatch = || {
        anyhow!(
            "pairing code did not match. Nothing was saved. Don't reuse this code: create a new one on the other PC and try again."
        )
    };

    // 1. Swap identities (nonce 0).
    let info = PairInfo {
        name: app.config.device_name.clone(),
        public_key: hex::encode(app.identity.public_key()),
    };
    let sealed = seal
        .encrypt(&Nonce::from([0u8; 12]), serde_json::to_vec(&info)?.as_slice())
        .map_err(|_| anyhow!("encryption failed"))?;
    write_msg(send, &PairMsg { data: hex::encode(sealed) }).await?;
    let reply: PairMsg = tokio::time::timeout(timeout, read_msg(recv)).await??;
    let plain = open
        .decrypt(&Nonce::from([0u8; 12]), hex::decode(reply.data)?.as_slice())
        .map_err(|_| mismatch())?;
    let theirs: PairInfo = serde_json::from_slice(&plain)?;
    let key: [u8; 32] = hex::decode(&theirs.public_key)?
        .try_into()
        .map_err(|_| anyhow!("peer sent an invalid key"))?;
    if key == app.identity.public_key() {
        bail!("cannot pair a device with itself");
    }

    // 2. Key confirmation (nonce 1): only save once both sides agree. For an
    // invite link, the inviter first sees who is pairing and approves it.
    let approved = match approval {
        Some((ui, timeout_secs, invited)) => {
            let mut ask = Approval::new(&theirs.name, &device_id(&key), ApprovalKind::Pair, Some(invited.into()), &[], timeout_secs);
            ask.check = Some(check.clone());
            ui.ask(ask).await
        }
        None => true,
    };
    if let Some(show) = on_check {
        show(&check);
    }
    let word: &[u8] = if approved { b"confirm" } else { b"declined" };
    let confirm = seal.encrypt(&Nonce::from([1u8; 12]), word).map_err(|_| anyhow!("encryption failed"))?;
    write_msg(send, &PairMsg { data: hex::encode(confirm) }).await?;
    if !approved {
        let _ = send.finish();
        let _ = tokio::time::timeout(Duration::from_secs(5), send.stopped()).await;
        bail!("you declined pairing with {}", display_safe(&theirs.name, 64));
    }
    let reply: PairMsg = tokio::time::timeout(confirm_wait, read_msg(recv))
        .await
        .context("the other PC didn't finish pairing in time")??;
    let ok = open
        .decrypt(&Nonce::from([1u8; 12]), hex::decode(reply.data)?.as_slice())
        .map_err(|_| mismatch())?;
    if ok == b"declined" {
        bail!("{} declined the pairing", display_safe(&theirs.name, 64));
    }
    if ok != b"confirm" {
        return Err(mismatch());
    }

    // 3. Server access (nonce 2), now that both sides know who they paired
    // with: each side may hand the other a key for its rendezvous server,
    // made just for this device so it can be revoked on its own.
    let mut notes = Vec::new();
    let mut invite = None;
    let mut offer = PairServerOffer::default();
    if give_server {
        match crate::invites::gift_for(app, &theirs.name, &key).await {
            Ok((gift, name)) => {
                offer.server = Some(gift);
                invite = Some(name);
            }
            Err(e) => notes.push(format!("Couldn't give them access to your server: {e:#}")),
        }
    }
    let sealed = seal
        .encrypt(&Nonce::from([2u8; 12]), serde_json::to_vec(&offer)?.as_slice())
        .map_err(|_| anyhow!("encryption failed"))?;
    write_msg(send, &PairMsg { data: hex::encode(sealed) }).await?;
    // Both sides are paired by now: a missing or broken offer just means none.
    let their_offer: PairServerOffer = match tokio::time::timeout(Duration::from_secs(30), read_msg::<_, PairMsg>(recv)).await {
        Ok(Ok(m)) => hex::decode(m.data)
            .ok()
            .and_then(|c| open.decrypt(&Nonce::from([2u8; 12]), c.as_slice()).ok())
            .and_then(|p| serde_json::from_slice(&p).ok())
            .unwrap_or_default(),
        _ => PairServerOffer::default(),
    };
    // Make sure our messages are delivered before the connection closes.
    let _ = send.finish();
    let _ = tokio::time::timeout(Duration::from_secs(5), send.stopped()).await;

    let peer = save_peer(app, &theirs.name, key, invite.clone())?;
    if let Some(name) = &invite {
        notes.push(format!(
            "Gave {} their own key to your server (invite \"{name}\"). Unpairing them revokes it.",
            peer.name
        ));
    }
    let mut server_changed = false;
    if let Some(gift) = their_offer.server {
        use crate::invites::Adopted;
        let adopted = crate::invites::adopt(app, &gift);
        server_changed = matches!(adopted, Ok(Adopted::Now(_) | Adopted::Refreshed(_)));
        let shown = crate::text::display_safe(&gift.address, 100);
        notes.push(match adopted {
            Ok(Adopted::Now(_)) => format!(
                "Now using {}'s server at {shown} to reach devices over the internet. Restart FilePigeon (or `filepigeon serve`) to connect to it.",
                peer.name
            ),
            Ok(Adopted::Refreshed(_)) => format!("Got a fresh key for the server at {shown} from {}.", peer.name),
            Ok(Adopted::KeptOurs(_)) => format!(
                "{} offered their server at {shown}, but this PC already uses a different one, so nothing changed.",
                peer.name
            ),
            Err(e) => format!("{} offered a server, but it couldn't be used: {e:#}", peer.name),
        });
    }
    Ok(Paired { peer, notes, server_changed })
}

fn save_peer(app: &App, name: &str, key: [u8; 32], server_invite: Option<String>) -> Result<Peer> {
    let mut peers = app.peers()?;
    let id = device_id(&key);
    // Re-pairing the same device replaces its entry (keeping its settings).
    let existing = peers.iter().position(|p| p.device_id == id);
    // The peer picks its own name: strip anything that could disguise it.
    let mut name = crate::text::clean_name(name);
    if name.is_empty() {
        name = format!("peer-{}", &id[..6]);
    }
    if peers.iter().any(|p| p.device_id != id && p.name.eq_ignore_ascii_case(&name)) {
        name = format!("{name}-{}", &id[..4]);
    }
    let paired_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let peer = match existing {
        Some(i) => {
            let p = &mut peers[i];
            p.public_key = hex::encode(key);
            p.paired_at = paired_at;
            if server_invite.is_some() {
                p.server_invite = server_invite;
            }
            p.clone()
        }
        None => {
            let p = Peer {
                name,
                device_id: id,
                public_key: hex::encode(key),
                paired_at,
                // Shares stay private until the user allows this device.
                allow_browse: false,
                auto_accept: false,
                hidden: false,
                server_invite,
            };
            peers.push(p.clone());
            p
        }
    };
    app.save_peers(&peers)?;
    Ok(peer)
}

#[cfg(test)]
mod tests {
    use super::parse_code;

    #[test]
    fn parses_codes() {
        assert_eq!(parse_code(" 42-River-Falcon-lotus ").unwrap(), (42, "river-falcon-lotus".into()));
        assert!(parse_code("42-river-falcon").is_err());
        assert!(parse_code("x-river-falcon-lotus").is_err());
        assert!(parse_code("42-river-falcon-notaword").is_err());
    }
}
