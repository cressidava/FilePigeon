//! Who may use the rendezvous server. Kept in `<key>.access` next to the
//! server key:
//!
//! - the **owner key** (the knock secret printed by `--show-key`) is for your
//!   own devices;
//! - each friend gets an **invite**: their own random knock secret, so one
//!   friend can be cut off without re-keying everyone else;
//! - **admins** are device public keys allowed to create and revoke invites
//!   remotely (and only when they also knock with the owner key).
//!
//! The server re-reads the file within a couple of seconds of any change, so
//! the command-line tools and the running service can both edit it.

use crate::gate::KnockKeys;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The gate owner id of the owner key's knocks.
pub const OWNER_LABEL: [u8; 32] = [0u8; 32];
const MAX_INVITES: usize = 1000;
/// The longest a temporary invite (for an invite link) may last.
pub const MAX_INVITE_TTL: u64 = 7 * 24 * 3600;
const RECHECK: Duration = Duration::from_secs(2);

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AccessFile {
    /// Hex Ed25519 public keys of devices that may manage invites.
    #[serde(default)]
    pub admins: Vec<String>,
    #[serde(default)]
    pub invites: Vec<Invite>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    pub name: String,
    /// Hex knock secret. Never sent anywhere except inside the invite key.
    pub secret: String,
    pub created: u64,
    /// Temporary invites (inside an invite link) stop working at this time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<u64>,
    /// Hex public key of the only device that may use this invite. Set when
    /// it's made for a known device, otherwise by the first device to use it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
}

impl Invite {
    fn secret_bytes(&self) -> Option<[u8; 32]> {
        hex::decode(&self.secret).ok()?.try_into().ok()
    }

    fn live(&self, now: u64) -> bool {
        self.expires.is_none_or(|e| now < e)
    }
}

/// The gate owner id for an invite's knocks (derived, so the secret itself
/// never has to be kept anywhere else).
pub fn invite_label(secret: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("filepigeon invite owner v1", secret)
}

struct State {
    checked: Option<Instant>,
    modified: Option<SystemTime>,
    file: Arc<AccessFile>,
    keys: Arc<Vec<([u8; 32], [u8; 32])>>,
    generation: u64,
    /// When the next temporary invite runs out (the key set changes then).
    next_expiry: Option<u64>,
}

pub struct Access {
    path: PathBuf,
    /// The key file whose owner new files are given to (see `save`).
    #[cfg_attr(not(unix), allow(dead_code))]
    like: PathBuf,
    owner_secret: [u8; 32],
    state: Mutex<State>,
    /// One read-modify-write at a time within this process.
    edits: Mutex<()>,
}

impl Access {
    /// `key_path` is the server's identity key; the access file sits next to it.
    pub fn open(key_path: &Path, owner_secret: [u8; 32]) -> Result<Arc<Self>> {
        let access = Arc::new(Self {
            path: key_path.with_extension("access"),
            like: key_path.to_path_buf(),
            owner_secret,
            state: Mutex::new(State {
                checked: None,
                modified: None,
                file: Default::default(),
                keys: Arc::new(vec![(OWNER_LABEL, owner_secret)]),
                generation: 0,
                next_expiry: None,
            }),
            edits: Mutex::new(()),
        });
        // A corrupt file at start-up is an error, not "no invites".
        let file = access.read()?;
        access.install(file, modified(&access.path));
        Ok(access)
    }

    fn read(&self) -> Result<AccessFile> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| format!("{} is corrupt", self.path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(AccessFile::default()),
            Err(e) => Err(e).with_context(|| format!("cannot read {}", self.path.display())),
        }
    }

    fn install(&self, file: AccessFile, modified: Option<SystemTime>) {
        let now = now();
        let mut keys = vec![(OWNER_LABEL, self.owner_secret)];
        keys.extend(
            file.invites.iter().filter(|i| i.live(now)).filter_map(Invite::secret_bytes).map(|s| (invite_label(&s), s)),
        );
        let next_expiry = file.invites.iter().filter_map(|i| i.expires).filter(|&e| e > now).min();
        let mut st = self.state.lock().unwrap();
        st.file = Arc::new(file);
        st.keys = Arc::new(keys);
        st.modified = modified;
        st.checked = Some(Instant::now());
        st.generation += 1;
        st.next_expiry = next_expiry;
    }

    /// Pick up edits made by another process (at most every couple of
    /// seconds). A half-written or broken file keeps the last good state.
    fn refresh(&self) {
        {
            let mut st = self.state.lock().unwrap();
            if st.checked.is_some_and(|t| t.elapsed() < RECHECK) {
                return;
            }
            st.checked = Some(Instant::now());
            let expired = st.next_expiry.is_some_and(|e| now() >= e);
            if modified(&self.path) == st.modified {
                if expired {
                    // A temporary invite ran out: same file, fewer keys.
                    let (file, modified) = ((*st.file).clone(), st.modified);
                    drop(st);
                    self.install(file, modified);
                }
                return;
            }
        }
        if let Ok(file) = self.read() {
            self.install(file, modified(&self.path));
        }
    }

    /// Changes whenever the set of valid keys may have changed.
    pub fn generation(&self) -> u64 {
        self.refresh();
        self.state.lock().unwrap().generation
    }

    pub fn file(&self) -> Arc<AccessFile> {
        self.refresh();
        self.state.lock().unwrap().file.clone()
    }

    /// Is this gate owner id still allowed in?
    pub fn valid_label(&self, label: &[u8; 32]) -> bool {
        self.refresh();
        self.state.lock().unwrap().keys.iter().any(|(l, _)| l == label)
    }

    /// The invite name behind a gate owner id (None for the owner key).
    pub fn invite_name(&self, label: &[u8; 32]) -> Option<String> {
        self.file()
            .invites
            .iter()
            .find(|i| i.secret_bytes().is_some_and(|s| invite_label(&s) == *label))
            .map(|i| i.name.clone())
    }

    /// The knock secret behind a gate owner id.
    pub fn secret_for(&self, label: &[u8; 32]) -> Option<[u8; 32]> {
        if *label == OWNER_LABEL {
            return Some(self.owner_secret);
        }
        self.file()
            .invites
            .iter()
            .filter_map(Invite::secret_bytes)
            .find(|s| invite_label(s) == *label)
    }

    /// Is the key behind this gate owner id a temporary one (an invite
    /// link's)? Those may only be used to join the inviter's pairing slot.
    pub fn join_only(&self, label: &[u8; 32]) -> bool {
        *label != OWNER_LABEL
            && self
                .file()
                .invites
                .iter()
                .any(|i| i.expires.is_some() && i.secret_bytes().is_some_and(|s| invite_label(&s) == *label))
    }

    pub fn is_admin(&self, public_key: &[u8; 32]) -> bool {
        let pk = hex::encode(public_key);
        self.file().admins.iter().any(|a| a.eq_ignore_ascii_case(&pk))
    }

    /// Read the current file from disk, change it, save it, and use it. One
    /// edit at a time, across processes too (the service and the root CLI).
    fn edit<T>(&self, change: impl FnOnce(&mut AccessFile) -> Result<T>) -> Result<T> {
        let _one_at_a_time = self.edits.lock().unwrap();
        let _locked = self.lock_file()?;
        let mut file = self.read()?;
        let out = change(&mut file)?;
        self.save(&file)?;
        self.install(file, modified(&self.path));
        Ok(out)
    }

    /// Create (or replace, for the same name) a friend's invite; returns its
    /// knock secret. Replacing cuts off the old one. With `ttl`, the invite is
    /// temporary and stops working after that many seconds.
    pub fn create_invite(&self, name: &str, ttl: Option<u64>) -> Result<[u8; 32]> {
        self.create_invite_for(name, ttl, None)
    }

    /// Like `create_invite`, locked to `device` (a public key) from the start.
    pub fn create_invite_for(&self, name: &str, ttl: Option<u64>, device: Option<[u8; 32]>) -> Result<[u8; 32]> {
        let mut secret = [0u8; 32];
        crate::os_random(&mut secret);
        self.create_invite_with(name, ttl, device, secret)
    }

    /// Like `create_invite_for`, with a given knock secret (derived from an
    /// invite code by the inviting admin device).
    pub fn create_invite_with(
        &self,
        name: &str,
        ttl: Option<u64>,
        device: Option<[u8; 32]>,
        secret: [u8; 32],
    ) -> Result<[u8; 32]> {
        let name = invite_name_check(name)?;
        if secret == self.owner_secret {
            bail!("that secret is already in use");
        }
        let now = now();
        let expires = ttl.map(|t| now + t.clamp(60, MAX_INVITE_TTL));
        let device = device.map(hex::encode);
        self.edit(|f| {
            // Housekeeping: expired temporary invites are dropped for good.
            f.invites.retain(|i| i.live(now));
            if let Some(existing) = f.invites.iter().find(|i| i.name.eq_ignore_ascii_case(&name)) {
                let same_device = existing.device.is_some() && existing.device == device;
                // Re-giving the same device its key (re-pairing): hand back the
                // key it already has rather than cutting it off.
                if same_device && existing.expires.is_none() && expires.is_none() {
                    if let Some(s) = existing.secret_bytes() {
                        return Ok(s);
                    }
                }
                // Never silently take over another device's key.
                if existing.device.is_some() && device.is_some() && !same_device {
                    bail!("an invite called {:?} already belongs to another device", existing.name);
                }
            }
            f.invites.retain(|i| !i.name.eq_ignore_ascii_case(&name));
            if f.invites.len() >= MAX_INVITES {
                bail!("too many invites; revoke some first");
            }
            f.invites.push(Invite { name, secret: hex::encode(secret), created: now, expires, device });
            Ok(secret)
        })
    }

    /// May `device` use the key behind this gate owner id? The owner key is
    /// for any of the owner's devices; an invite only for the device it's
    /// locked to. An invite not locked yet is locked to this device now.
    pub fn device_allowed(&self, label: &[u8; 32], device: &[u8; 32]) -> Result<bool> {
        if *label == OWNER_LABEL {
            return Ok(true);
        }
        let pk = hex::encode(device);
        let matches = |i: &Invite| i.secret_bytes().is_some_and(|s| invite_label(&s) == *label);
        let Some(invite) = self.file().invites.iter().find(|i| matches(i)).cloned() else {
            return Ok(false);
        };
        match invite.device {
            Some(d) => Ok(d.eq_ignore_ascii_case(&pk)),
            None => self.edit(|f| {
                // Re-check under the edit lock: two devices racing for an
                // unlocked key can't both win.
                let Some(i) = f.invites.iter_mut().find(|i| matches(i)) else { return Ok(false) };
                match &i.device {
                    Some(d) => Ok(d.eq_ignore_ascii_case(&pk)),
                    None => {
                        i.device = Some(pk.clone());
                        Ok(true)
                    }
                }
            }),
        }
    }

    /// Invites that still work.
    pub fn live_invites(&self) -> Vec<Invite> {
        let now = now();
        self.file().invites.iter().filter(|i| i.live(now)).cloned().collect()
    }

    /// Revoke a friend's invite; false if there was none by that name.
    pub fn revoke_invite(&self, name: &str) -> Result<bool> {
        self.edit(|f| {
            let before = f.invites.len();
            f.invites.retain(|i| !i.name.eq_ignore_ascii_case(name.trim()));
            Ok(f.invites.len() != before)
        })
    }

    pub fn add_admin(&self, public_key: &str) -> Result<()> {
        let pk = parse_public_key(public_key)?;
        self.edit(|f| {
            if !f.admins.iter().any(|a| a.eq_ignore_ascii_case(&pk)) {
                f.admins.push(pk);
            }
            Ok(())
        })
    }

    pub fn remove_admin(&self, public_key: &str) -> Result<bool> {
        let pk = parse_public_key(public_key)?;
        self.edit(|f| {
            let before = f.admins.len();
            f.admins.retain(|a| !a.eq_ignore_ascii_case(&pk));
            Ok(f.admins.len() != before)
        })
    }

    /// Write atomically, readable only by the file's owner. When run as root
    /// (the command-line tools), the file is handed to whoever owns the server
    /// key, so the sandboxed service can still read it.
    fn save(&self, file: &AccessFile) -> Result<()> {
        let tmp = self.path.with_extension("access.tmp");
        let _ = std::fs::remove_file(&tmp);
        {
            use std::io::Write;
            // create_new never follows a symlink planted at this path.
            let mut f = private_open(&tmp, true)?;
            f.write_all(&serde_json::to_vec_pretty(file)?)?;
            f.sync_all()?;
            self.hand_over(&f)?;
        }
        std::fs::rename(&tmp, &self.path).with_context(|| format!("cannot replace {}", self.path.display()))?;
        Ok(())
    }

    /// When run as root (the CLI), give a file we just opened to the user
    /// that owns the server key, so the sandboxed service can use it. Done on
    /// the open file itself, so nothing can redirect it through a symlink.
    /// The service itself never needs to (and may not) change ownership.
    #[cfg(unix)]
    fn hand_over(&self, f: &std::fs::File) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let want = std::fs::symlink_metadata(&self.like)?;
        if want.file_type().is_symlink() {
            bail!("{} is a symlink; refusing to use it", self.like.display());
        }
        let have = f.metadata()?;
        if (want.uid(), want.gid()) != (have.uid(), have.gid()) {
            std::os::unix::fs::fchown(f, Some(want.uid()), Some(want.gid()))
                .context("cannot hand the file to the service user")?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn hand_over(&self, _f: &std::fs::File) -> Result<()> {
        Ok(())
    }

    /// An exclusive lock on `<key>.access.lock`, held for one edit.
    fn lock_file(&self) -> Result<std::fs::File> {
        let path = self.path.with_extension("access.lock");
        let f = private_open(&path, false)?;
        self.hand_over(&f)?;
        f.lock().with_context(|| format!("cannot lock {}", path.display()))?;
        Ok(f)
    }
}

impl KnockKeys for Access {
    fn keys(&self) -> Arc<Vec<([u8; 32], [u8; 32])>> {
        self.refresh();
        self.state.lock().unwrap().keys.clone()
    }

    /// The owner key is shared by all the owner's devices: no shared budget
    /// that one replaying stranger could exhaust. Each invite is one friend's.
    fn budget_per_owner(&self, owner: &[u8; 32]) -> bool {
        *owner != OWNER_LABEL
    }
}

/// Open a file readable only by its owner, never through a symlink.
/// `new`: it must not exist yet.
fn private_open(path: &Path, new: bool) -> Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true);
    if new {
        opts.create_new(true);
    } else {
        opts.create(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        #[cfg(target_os = "linux")]
        opts.custom_flags(0o400000); // O_NOFOLLOW
    }
    opts.open(path).with_context(|| format!("cannot open {}", path.display()))
}

fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Invite names are labels for people; keep them short and plain.
pub fn invite_name_check(name: &str) -> Result<String> {
    let name = crate::text::clean_name(name);
    if name.is_empty() || name.chars().count() > 64 {
        bail!("an invite name must be 1-64 characters");
    }
    Ok(name)
}

fn parse_public_key(text: &str) -> Result<String> {
    let clean = text.trim().to_lowercase();
    match hex::decode(&clean) {
        Ok(b) if b.len() == 32 => Ok(clean),
        _ => bail!("a device public key is 64 hex characters (`filepigeon whoami` shows it)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("fp-access-{}-{}", std::process::id(), rand::random::<u32>()));
        std::fs::create_dir_all(&d).unwrap();
        d.join("rendezvous-key.pem")
    }

    #[test]
    fn invites_come_and_go() {
        let key = dir();
        std::fs::write(&key, b"x").unwrap();
        let access = Access::open(&key, [7u8; 32]).unwrap();
        assert_eq!(access.keys().len(), 1);
        let bob = access.create_invite("bob", None).unwrap();
        let label = invite_label(&bob);
        assert!(access.valid_label(&label) && access.valid_label(&OWNER_LABEL));
        assert_eq!(access.invite_name(&label).as_deref(), Some("bob"));

        // Another process (or a restart) sees the same file.
        let again = Access::open(&key, [7u8; 32]).unwrap();
        assert!(again.valid_label(&label));

        // Re-inviting the same name replaces the old secret.
        let bob2 = access.create_invite("Bob", None).unwrap();
        assert!(!access.valid_label(&label) && access.valid_label(&invite_label(&bob2)));

        assert!(access.revoke_invite("BOB").unwrap());
        assert!(!access.valid_label(&invite_label(&bob2)));
        assert!(!access.revoke_invite("bob").unwrap());
        assert_eq!(access.keys().len(), 1);
    }

    #[test]
    fn temporary_invites_run_out() {
        let key = dir();
        std::fs::write(&key, b"x").unwrap();
        let access = Access::open(&key, [7u8; 32]).unwrap();
        let temp = access.create_invite("link", Some(3600)).unwrap();
        assert!(access.valid_label(&invite_label(&temp)));
        // Pretend it ran out an hour ago.
        let mut file = (*access.file()).clone();
        file.invites[0].expires = Some(now() - 3600);
        let generation = access.generation();
        access.install(file, None);
        assert!(access.generation() > generation);
        assert!(!access.valid_label(&invite_label(&temp)));
        assert!(access.live_invites().is_empty());
    }

    #[test]
    fn invites_are_locked_to_one_device() {
        let key = dir();
        std::fs::write(&key, b"x").unwrap();
        let access = Access::open(&key, [7u8; 32]).unwrap();
        let (alice, mallory) = ([1u8; 32], [2u8; 32]);
        // Made for a known device.
        let made = invite_label(&access.create_invite_for("a", None, Some(alice)).unwrap());
        assert!(access.device_allowed(&made, &alice).unwrap());
        assert!(!access.device_allowed(&made, &mallory).unwrap());
        // Unlocked: the first device to use it gets it.
        let open = invite_label(&access.create_invite("b", None).unwrap());
        assert!(access.device_allowed(&open, &mallory).unwrap());
        assert!(!access.device_allowed(&open, &alice).unwrap());
        assert!(access.device_allowed(&open, &mallory).unwrap());
        // The owner key works for any device; unknown keys for none.
        assert!(access.device_allowed(&OWNER_LABEL, &alice).unwrap());
        assert!(!access.device_allowed(&[9u8; 32], &alice).unwrap());
    }

    #[test]
    fn link_keys_are_join_only_and_gifts_are_stable() {
        let key = dir();
        std::fs::write(&key, b"x").unwrap();
        let access = Access::open(&key, [7u8; 32]).unwrap();
        let temp = invite_label(&access.create_invite("link", Some(3600)).unwrap());
        let friend = invite_label(&access.create_invite("friend", None).unwrap());
        assert!(access.join_only(&temp) && !access.join_only(&friend) && !access.join_only(&OWNER_LABEL));
        // Re-gifting the same device returns the same key; another device can't take the name.
        let a = access.create_invite_for("sam (1234)", None, Some([1; 32])).unwrap();
        assert_eq!(access.create_invite_for("Sam (1234)", None, Some([1; 32])).unwrap(), a);
        assert!(access.create_invite_for("sam (1234)", None, Some([2; 32])).is_err());
        assert!(access.valid_label(&invite_label(&a)));
    }

    #[test]
    fn admins_are_exact_public_keys() {
        let key = dir();
        std::fs::write(&key, b"x").unwrap();
        let access = Access::open(&key, [7u8; 32]).unwrap();
        assert!(access.add_admin("not a key").is_err());
        access.add_admin(&hex::encode([3u8; 32]).to_uppercase()).unwrap();
        assert!(access.is_admin(&[3u8; 32]) && !access.is_admin(&[4u8; 32]));
        assert!(access.remove_admin(&hex::encode([3u8; 32])).unwrap());
        assert!(!access.is_admin(&[3u8; 32]));
    }
}
