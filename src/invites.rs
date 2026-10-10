//! Managing friends' access to your rendezvous server from an admin device,
//! and handing a friend their own server key while pairing.

use crate::app::{parse_server_key, App};
use crate::netutil::BoundEndpoint;
use crate::proto::{InviteInfo, RdvRequest, RdvResponse, ServerGift};
use crate::rdv_client;
use crate::text::display_safe;
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

/// How long an invite link works.
pub const LINK_TTL: u64 = 24 * 3600;

async fn admin_request(app: &App, req: RdvRequest) -> Result<RdvResponse> {
    let ep = BoundEndpoint::bind(0, None)?;
    let rdv = rdv_client::connect(app, &ep).await?;
    let (_, _, resp) = rdv_client::request(&rdv, &req).await?;
    rdv.close(0u32.into(), b"done");
    match resp {
        RdvResponse::Error { message } => bail!(display_safe(&message, 200)),
        other => Ok(other),
    }
}

/// Create (or replace) a friend's server key. Returns the 128-hex key.
pub async fn create(app: &App, name: &str) -> Result<String> {
    create_with(app, name, None).await
}

async fn create_with(app: &App, name: &str, expires_in: Option<u64>) -> Result<String> {
    create_for(app, name, expires_in, None).await
}

/// `device`: lock the key to this device's public key (otherwise the server
/// locks it to the first device that uses it).
async fn create_for(app: &App, name: &str, expires_in: Option<u64>, device: Option<[u8; 32]>) -> Result<String> {
    let name = crate::access::invite_name_check(name)?;
    let device = device.map(hex::encode);
    match admin_request(app, RdvRequest::InviteCreate { name, expires_in, device, secret: None }).await? {
        RdvResponse::Invite { key } => {
            parse_server_key(&key)?;
            Ok(key)
        }
        _ => bail!("unexpected response from the rendezvous server"),
    }
}

pub async fn list(app: &App) -> Result<Vec<InviteInfo>> {
    match admin_request(app, RdvRequest::InviteList).await? {
        RdvResponse::Invites { invites } => Ok(invites),
        _ => bail!("unexpected response from the rendezvous server"),
    }
}

pub async fn revoke(app: &App, name: &str) -> Result<()> {
    match admin_request(app, RdvRequest::InviteRevoke { name: name.to_string() }).await? {
        RdvResponse::Ok => Ok(()),
        _ => bail!("unexpected response from the rendezvous server"),
    }
}

/// The invite name used for a device paired with "give them my server".
pub fn name_for_device(peer_name: &str, device_id: &str) -> String {
    let short: String = crate::text::clean_name(peer_name).chars().take(40).collect();
    format!("{short} ({device_id})")
}

/// The address friends should use: `friend_address` if set, otherwise the
/// one this PC uses. A private or loopback IP would be useless to someone on
/// another network, so that is refused.
pub fn friend_address(app: &App) -> Result<String> {
    let addr = if app.config.friend_address.trim().is_empty() {
        app.config.rendezvous.trim()
    } else {
        app.config.friend_address.trim()
    };
    if addr.is_empty() {
        bail!("no rendezvous server is set up on this PC");
    }
    check_friend_address(addr)?;
    Ok(addr.to_string())
}

/// `host:port`, where a literal IP must be reachable from other networks.
pub fn check_friend_address(addr: &str) -> Result<()> {
    let Some((host, port)) = addr.rsplit_once(':') else {
        bail!("the server address must look like host:port");
    };
    if port.parse::<u16>().is_err() || host.is_empty() || host.len() > 253 || host.contains(char::is_whitespace) {
        bail!("the server address must look like host:port");
    }
    // Local test setups (a server on this PC) opt out explicitly.
    let testing = std::env::var_os("FILEPIGEON_TEST_LOCAL_SERVER").is_some();
    if let (false, Ok(ip)) = (testing, host.trim_matches(['[', ']']).parse::<IpAddr>()) {
        let local = match ip {
            IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified(),
            IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00,
        };
        if local {
            bail!(
                "{addr} only works inside your own network. Set the address friends should use (a public name or IP) in Settings, or with `filepigeon init --friend-address HOST:PORT`"
            );
        }
    }
    Ok(())
}

/// Make a key for a device we just paired with, ready to send to it.
pub async fn gift_for(app: &App, peer_name: &str, peer_key: &[u8; 32]) -> Result<(ServerGift, String)> {
    let address = friend_address(app)?;
    let name = name_for_device(peer_name, &crate::identity::device_id(peer_key));
    // Only that device can use it: a copy is useless anywhere else.
    let key = create_for(app, &name, None, Some(*peer_key)).await?;
    Ok((ServerGift { address, key }, name))
}

/// What happened with a server offered to us during pairing.
pub enum Adopted {
    /// We had no server: now we use theirs.
    Now(String),
    /// The same key we already have (e.g. after re-pairing): nothing changed.
    Refreshed(String),
    /// We already use a different server: kept ours.
    KeptOurs(String),
}

/// Use a server a just-paired device offered, if this PC has none (or the
/// offer is a new key for the same server). Never replaces a different server.
pub fn adopt(app: &App, gift: &ServerGift) -> Result<Adopted> {
    check_friend_address(&gift.address)?;
    let (server_key, _) = parse_server_key(&gift.key)?;
    let paths = &app.paths;
    let mut cfg: crate::config::Config = crate::config::load_json(&paths.config())?;
    let _ = server_key;
    let current = cfg.server_key().unwrap_or_default();
    // A server key you already have is never replaced by one a peer sends:
    // only a PC with no server takes a gift. (Re-pairing gets back the key it
    // already has, so there's nothing to refresh.)
    if !cfg.rendezvous.trim().is_empty() && !current.is_empty() {
        return Ok(if current.eq_ignore_ascii_case(gift.key.trim()) {
            Adopted::Refreshed(cfg.rendezvous.clone())
        } else {
            Adopted::KeptOurs(gift.address.clone())
        });
    }
    cfg.rendezvous = gift.address.clone();
    cfg.set_server_key(&gift.key)?;
    crate::config::save_json(&paths.config(), &cfg)?;
    Ok(Adopted::Now(gift.address.clone()))
}

// ---------------- invite codes ----------------
//
// An invite is a server address plus five random words, e.g.
// `pigeon.example.com · tiger-maple-lotus-river-cedar`. Everything the friend's
// PC needs is derived from the words with Argon2 (deliberately slow, so the
// words can't be brute-forced offline from an overheard knock):
//
// - a knock secret, registered on our server as a temporary (24 h) key, so
//   the friend's PC can get past its stealth gate before it has a key of its own;
// - a pairing slot id, which our PC holds open on the server;
// - a SPAKE2 password for the pairing itself.
//
// The friend's PC can't pin our server's key yet, and doesn't need to: the
// pairing is end-to-end authenticated by the password, and afterwards it gets
// the pinned server key and its own device-locked knock secret. We approve the
// pairing in a pop-up showing check words that both screens display.

pub const DEFAULT_PORT: u16 = 7400;
const INVITE_WORDS: usize = 5;
const APP_SCHEME: &str = "filepigeon://join/";

/// An invite: which server, and the words.
#[derive(Debug, Clone, PartialEq)]
pub struct InviteCode {
    /// `host:port`.
    pub address: String,
    /// `word-word-word-word-word`.
    pub words: String,
}

/// What the words unlock.
pub struct InviteSecrets {
    pub knock: [u8; 32],
    pub slot: [u8; 16],
    pub password: String,
}

impl InviteCode {
    fn new(address: &str, words: &str) -> Result<Self> {
        let words = words.trim().to_lowercase();
        let parts: Vec<&str> = words.split('-').collect();
        if parts.len() != INVITE_WORDS || parts.iter().any(|w| !crate::words::is_word(w)) {
            bail!("that invite code isn't complete: it should be {INVITE_WORDS} words, like tiger-maple-lotus-river-cedar");
        }
        let mut address = address.trim().trim_end_matches('/').to_lowercase();
        if !address.contains(':') {
            address = format!("{address}:{DEFAULT_PORT}");
        }
        check_friend_address(&address)?;
        Ok(Self { address, words })
    }

    /// Find an invite in whatever was pasted or clicked: an app link
    /// (`filepigeon://join/HOST/WORDS`), a web link (`https://…#HOST/WORDS`),
    /// or the address and words typed out (`HOST WORDS`, `HOST/WORDS`).
    /// `None` if it doesn't look like an invite at all (e.g. a nearby code).
    pub fn find(text: &str) -> Option<Result<Self>> {
        let text = text.trim();
        let rest = if let Some(i) = text.find(APP_SCHEME) {
            &text[i + APP_SCHEME.len()..]
        } else if let Some(i) = text.find('#') {
            &text[i + 1..]
        } else {
            text
        };
        // HOST then WORDS, separated by '/', whitespace or '·'.
        let rest: String = rest.chars().take_while(|c| !c.is_control()).collect();
        let mut parts = rest.split(|c: char| c == '/' || c.is_whitespace() || c == '·').filter(|p| !p.is_empty());
        let host = parts.next()?;
        let words = parts.next()?;
        // A nearby code (`42-river-falcon-lotus`) has no host part.
        if !host.contains('.') && !host.contains(':') {
            return None;
        }
        let words: String = words.chars().take_while(|c| c.is_ascii_alphabetic() || *c == '-').collect();
        Some(Self::new(host, &words))
    }

    /// For people: the address (without the default port) and the words.
    pub fn display(&self) -> String {
        format!("{} · {}", self.short_address(), self.words)
    }

    fn short_address(&self) -> &str {
        self.address.strip_suffix(&format!(":{DEFAULT_PORT}")).unwrap_or(&self.address)
    }

    /// Opens FilePigeon with the invite filled in.
    pub fn app_link(&self) -> String {
        format!("{APP_SCHEME}{}/{}", self.short_address(), self.words)
    }

    /// The invite page link. The invite is in the `#` part, which browsers
    /// never send to the web server.
    pub fn web_link(&self, page: &str) -> String {
        format!("{}#{}/{}", page.trim_end_matches('#'), self.short_address(), self.words)
    }

    /// Derive the secrets (slow on purpose: about a second).
    pub fn secrets(&self) -> Result<InviteSecrets> {
        let params = argon2::Params::new(64 * 1024, 3, 1, Some(32)).map_err(|e| anyhow!("{e}"))?;
        let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut master = [0u8; 32];
        argon
            .hash_password_into(self.words.as_bytes(), format!("filepigeon invite v2 {}", self.address).as_bytes(), &mut master)
            .map_err(|e| anyhow!("{e}"))?;
        let sub = |purpose: &str| blake3::derive_key(&format!("filepigeon invite v1 {purpose}"), &master);
        Ok(InviteSecrets {
            knock: sub("knock"),
            slot: sub("slot")[..16].try_into().expect("16 bytes"),
            password: hex::encode(sub("password")),
        })
    }
}

/// An invite we made that hasn't been used yet (kept on our PC so the
/// background service can wait for the friend).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingInvite {
    /// Who it's for (as typed).
    pub friend: String,
    pub address: String,
    pub words: String,
    /// The pairing slot (hex), also the invite's id.
    pub slot: String,
    /// The temporary server key behind it (revoked once used).
    pub temp_invite: String,
    pub expires: u64,
    /// Used (or cancelled), but its temporary key isn't confirmed revoked
    /// yet: the background service keeps retrying.
    #[serde(default)]
    pub used: bool,
}

impl PendingInvite {
    pub fn code(&self) -> InviteCode {
        InviteCode { address: self.address.clone(), words: self.words.clone() }
    }
}

/// What to send a friend.
#[derive(Debug, Clone, Serialize)]
pub struct InviteMessage {
    /// The whole message, ready to paste into a chat.
    pub message: String,
    /// The link to click (the invite page, or the app link if there's none).
    pub link: String,
    /// `host · words`, for reading out or typing.
    pub code: String,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn pending_path(app: &App) -> std::path::PathBuf {
    app.paths.home.join("pending-invites.json")
}

/// Unused invites that haven't expired.
pub fn pending(app: &App) -> Vec<PendingInvite> {
    let all: Vec<PendingInvite> = crate::config::load_json(&pending_path(app)).unwrap_or_default();
    all.into_iter().filter(|p| p.expires > now()).collect()
}

fn save_pending(app: &App, list: &[PendingInvite]) -> Result<()> {
    crate::config::save_json(&pending_path(app), &list.to_vec())
}

/// Invites still waiting for the friend (not used, not cancelled).
pub fn waiting(app: &App) -> Vec<PendingInvite> {
    pending(app).into_iter().filter(|p| !p.used).collect()
}

/// An invite was used or cancelled: stop waiting for it, and revoke its
/// temporary key. If the server can't be reached, it stays marked for retry
/// (see `retry_revokes`) instead of being forgotten with the key still live.
pub async fn retire(app: &App, slot: &str) -> Result<()> {
    let Some(p) = pending(app).into_iter().find(|p| p.slot == slot) else { return Ok(()) };
    let mut list = pending(app);
    for item in list.iter_mut().filter(|i| i.slot == slot) {
        item.used = true;
    }
    save_pending(app, &list)?;
    match revoke(app, &p.temp_invite).await {
        Ok(()) => {
            forget_pending(app, slot);
            Ok(())
        }
        // Already gone on the server (e.g. revoked by hand): done.
        Err(e) if e.to_string().contains("no invite by that name") => {
            forget_pending(app, slot);
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Retry revoking used invites' temporary keys (they expire by themselves
/// within a day regardless).
pub async fn retry_revokes(app: &App) {
    for p in pending(app).into_iter().filter(|p| p.used) {
        let _ = retire(app, &p.slot).await;
    }
}

/// Forget a pending invite (used, cancelled or expired).
pub fn forget_pending(app: &App, slot: &str) {
    let list: Vec<_> = pending(app).into_iter().filter(|p| p.slot != slot).collect();
    let _ = save_pending(app, &list);
}

/// Invite `friend`: register a temporary key on our server and remember the
/// invite so the background service waits for them. Returns what to send.
pub async fn create_link(app: &App, friend: &str) -> Result<(InviteMessage, PendingInvite)> {
    let friend = crate::text::clean_name(friend);
    if friend.is_empty() || friend.chars().count() > 36 {
        bail!("type who the invite is for (up to 36 characters)");
    }
    let code = InviteCode::new(&friend_address(app)?, &crate::words::pick(INVITE_WORDS).join("-"))?;
    let secrets = {
        let code = code.clone();
        tokio::task::spawn_blocking(move || code.secrets()).await??
    };
    let slot = hex::encode(secrets.slot);
    let temp_invite = format!("invite for {friend} [{}]", &slot[..6]);
    match admin_request(
        app,
        RdvRequest::InviteCreate {
            name: crate::access::invite_name_check(&temp_invite)?,
            expires_in: Some(LINK_TTL),
            device: None,
            secret: Some(hex::encode(secrets.knock)),
        },
    )
    .await?
    {
        RdvResponse::Invite { .. } => {}
        _ => bail!("unexpected response from the rendezvous server"),
    }
    let pending_invite = PendingInvite {
        friend: friend.clone(),
        address: code.address.clone(),
        words: code.words.clone(),
        slot,
        temp_invite,
        expires: now() + LINK_TTL,
        used: false,
    };
    let mut list = pending(app);
    list.push(pending_invite.clone());
    save_pending(app, &list)?;
    Ok((invite_message(app, &friend, &code), pending_invite))
}

/// The message for an invite (also used to show a pending one again).
pub fn invite_message(app: &App, friend: &str, code: &InviteCode) -> InviteMessage {
    let me = crate::text::clean_name(&app.config.device_name);
    let page = app.config.invite_page.trim();
    let (link, how) = if page.is_empty() {
        (code.app_link(), "Install FilePigeon first, then click this link (or paste it into FilePigeon → I have an invite):")
    } else {
        (code.web_link(page), "Click this link. It gets you FilePigeon if you don't have it yet, then opens the invite:")
    };
    let message = format!(
        "{friend}, {me} invited you to FilePigeon, for sending files directly between our PCs.\n\n\
         {how}\n{link}\n\n\
         Or type this into FilePigeon → I have an invite:  {}\n\n\
         It works once, within 24 hours.",
        code.display()
    );
    InviteMessage { message, link, code: code.display() }
}

/// Cancel an unused invite: its temporary server key stops working. If the
/// server can't be reached right now, the revoke is retried in the background.
pub async fn cancel_link(app: &App, slot: &str) -> Result<()> {
    retire(app, slot).await
}

/// The server's answer to `Prove`: only a server holding the invite's knock
/// secret can produce it, and it binds the server's own public key.
pub fn server_proof(knock_secret: &[u8; 32], nonce: &[u8], server_pk: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(&blake3::derive_key("filepigeon server proof v1", knock_secret));
    h.update(nonce);
    h.update(server_pk);
    *h.finalize().as_bytes()
}

/// Three words both sides of a pairing see; they match only if nobody is in
/// between, because they come from the pairing's own secret.
pub fn check_words(shared: &[u8]) -> String {
    let h = blake3::derive_key("filepigeon check words v1", shared);
    (0..3)
        .map(|i| crate::words::WORDS[u16::from_le_bytes([h[2 * i], h[2 * i + 1]]) as usize % crate::words::WORDS.len()])
        .collect::<Vec<_>>()
        .join(" · ")
}

#[cfg(test)]
mod tests {
    use super::check_friend_address;

    #[test]
    fn invite_codes_are_found_in_links_messages_and_typing() {
        use super::InviteCode;
        let want = InviteCode { address: "pigeon.example.com:7400".into(), words: "tiger-maple-lotus-river-cedar".into() };
        for text in [
            "filepigeon://join/pigeon.example.com/tiger-maple-lotus-river-cedar",
            "https://fp.example.com/join#pigeon.example.com/tiger-maple-lotus-river-cedar",
            "Sam, click this:\nhttps://fp.example.com/join#pigeon.example.com/tiger-maple-lotus-river-cedar\n\nOr type…",
            "pigeon.example.com · tiger-maple-lotus-river-cedar",
            "  Pigeon.Example.com:7400 TIGER-maple-lotus-river-cedar ",
        ] {
            assert_eq!(InviteCode::find(text).unwrap().unwrap(), want, "{text}");
        }
        assert_eq!(want.app_link(), "filepigeon://join/pigeon.example.com/tiger-maple-lotus-river-cedar");
        assert_eq!(want.display(), "pigeon.example.com · tiger-maple-lotus-river-cedar");
        // A nearby pairing code is not an invite.
        assert!(InviteCode::find("42-river-falcon-lotus").is_none());
        // Wrong word count, unknown words, or a local address: refused.
        assert!(InviteCode::find("pigeon.example.com tiger-maple-lotus").unwrap().is_err());
        assert!(InviteCode::find("pigeon.example.com tiger-maple-lotus-river-qwerty").unwrap().is_err());
        assert!(InviteCode::find("10.0.0.5 tiger-maple-lotus-river-cedar").unwrap().is_err());
    }

    #[test]
    fn invite_secrets_are_stable_and_distinct() {
        let code = super::InviteCode::find("pigeon.example.com tiger-maple-lotus-river-cedar").unwrap().unwrap();
        let (a, b) = (code.secrets().unwrap(), code.secrets().unwrap());
        assert_eq!((a.knock, a.slot, a.password.clone()), (b.knock, b.slot, b.password.clone()));
        let other = super::InviteCode::find("pigeon.example.com tiger-maple-lotus-river-comet").unwrap().unwrap();
        assert_ne!(other.secrets().unwrap().knock, a.knock);
        assert_ne!(super::check_words(b"one"), super::check_words(b"two"));
        assert_eq!(super::check_words(b"one").split(" · ").count(), 3);
    }

    #[test]
    fn friend_addresses_must_work_from_outside() {
        assert!(check_friend_address("pigeon.example.com:7400").is_ok());
        assert!(check_friend_address("203.0.113.5:7400").is_ok());
        assert!(check_friend_address("10.22.25.30:7400").is_err());
        assert!(check_friend_address("127.0.0.1:7400").is_err());
        assert!(check_friend_address("192.168.1.2:7400").is_err());
        assert!(check_friend_address("pigeon.example.com").is_err());
        assert!(check_friend_address("bad host:7400").is_err());
    }
}
