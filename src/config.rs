use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Name shown to peers when pairing.
    pub device_name: String,
    /// `host:port` of the rendezvous server.
    pub rendezvous: String,
    /// The rendezvous server's key (identity key + knock secret, 128 hex), in
    /// plain text. Only used where it can't be encrypted, and for migration:
    /// read it with `server_key()`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub rendezvous_key: String,
    /// The same key, encrypted for this Windows account (DPAPI).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub rendezvous_key_protected: String,
    /// `host:port` friends should use for the server, when it differs from
    /// `rendezvous` (e.g. this PC reaches it by a LAN address).
    pub friend_address: String,
    /// The invite web page (e.g. `https://fp.example.com/join`). Invites link
    /// there so a friend's click also offers the download; empty = app links.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub invite_page: String,
    /// Where received files are written.
    pub download_dir: PathBuf,
    /// UDP port for `serve` (0 = random each start).
    pub listen_port: u16,
    /// Temporarily map a router port via UPnP while a session is active.
    pub upnp: bool,
    /// Unanswered accept/deny prompts are denied after this many seconds.
    pub prompt_timeout_secs: u64,
    /// Invisible: don't announce or listen at all (you can still send/browse).
    pub invisible: bool,
    /// Experimental: find paired devices over the public BitTorrent DHT
    /// when no rendezvous server is configured or reachable.
    pub dht: bool,
    /// Desktop app: install downloaded updates by itself when idle (off =
    /// show a "Restart to update" button instead).
    pub auto_update: bool,
}

impl Default for Config {
    fn default() -> Self {
        let device_name = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "my-pc".into());
        Self {
            device_name,
            rendezvous: String::new(),
            rendezvous_key: String::new(),
            rendezvous_key_protected: String::new(),
            friend_address: String::new(),
            invite_page: String::new(),
            download_dir: default_download_dir(),
            listen_port: 0,
            upnp: true,
            prompt_timeout_secs: 120,
            invisible: false,
            dht: false,
            auto_update: true,
        }
    }
}

impl Config {
    /// The server key (128 hex), decrypted; empty if none is set.
    pub fn server_key(&self) -> Result<String> {
        if !self.rendezvous_key_protected.is_empty() {
            return crate::secret::unprotect(&self.rendezvous_key_protected);
        }
        Ok(self.rendezvous_key.clone())
    }

    pub fn has_server_key(&self) -> bool {
        !self.rendezvous_key_protected.is_empty() || !self.rendezvous_key.trim().is_empty()
    }

    /// Store a server key (encrypted where possible); empty clears it.
    pub fn set_server_key(&mut self, key: &str) -> Result<()> {
        let key = key.trim().to_lowercase();
        self.rendezvous_key.clear();
        self.rendezvous_key_protected.clear();
        if key.is_empty() {
            return Ok(());
        }
        crate::app::parse_server_key(&key)?;
        match crate::secret::protect(&key)? {
            Some(protected) => self.rendezvous_key_protected = protected,
            None => self.rendezvous_key = key,
        }
        Ok(())
    }
}

/// Always an absolute path: never relative to whatever directory the service
/// happens to start in.
pub fn default_download_dir() -> PathBuf {
    directories::UserDirs::new()
        .and_then(|d| d.download_dir().map(Path::to_path_buf))
        .or_else(|| directories::BaseDirs::new().map(|b| b.home_dir().join("Downloads")))
        .or_else(|| directories::ProjectDirs::from("", "", "FilePigeon").map(|p| p.data_dir().to_path_buf()))
        .unwrap_or_else(|| std::env::temp_dir())
        .join("FilePigeon")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub name: String,
    pub device_id: String,
    /// Hex Ed25519 public key, learned during pairing. Connections are pinned to it.
    pub public_key: String,
    pub paired_at: u64,
    /// May this peer list and request from your shared folders? Off until
    /// you turn it on.
    #[serde(default)]
    pub allow_browse: bool,
    /// Skip the accept/deny prompt for this peer's offers and requests.
    #[serde(default)]
    pub auto_accept: bool,
    /// Appear offline to this peer (they can't find or connect to you).
    #[serde(default)]
    pub hidden: bool,
    /// The invite we created on our server for this device, if any (revoked
    /// when you unpair it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_invite: Option<String>,
}

impl Peer {
    pub fn key(&self) -> Option<[u8; 32]> {
        hex::decode(&self.public_key).ok()?.try_into().ok()
    }
}

/// Share name -> absolute folder path.
pub type Shares = BTreeMap<String, PathBuf>;

#[derive(Debug, Clone)]
pub struct Paths {
    pub home: PathBuf,
}

impl Paths {
    /// `FILEPIGEON_HOME` overrides the per-user config dir (handy for running
    /// two identities on one machine).
    pub fn resolve() -> Result<Self> {
        let home = match std::env::var_os("FILEPIGEON_HOME") {
            Some(h) => PathBuf::from(h),
            None => directories::ProjectDirs::from("", "", "FilePigeon")
                .context("cannot determine config directory")?
                .config_dir()
                .to_path_buf(),
        };
        std::fs::create_dir_all(&home)
            .with_context(|| format!("cannot create {}", home.display()))?;
        // Settings reveal paired devices, their addresses and shared folders:
        // keep them readable by this user only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700));
        }
        Ok(Self { home })
    }
    pub fn config(&self) -> PathBuf {
        self.home.join("config.json")
    }
    pub fn peers(&self) -> PathBuf {
        self.home.join("peers.json")
    }
    pub fn shares(&self) -> PathBuf {
        self.home.join("shares.json")
    }
    pub fn identity(&self) -> PathBuf {
        self.home.join("identity.pem")
    }
}

/// `canonicalize` on Windows yields `\\?\C:\...`; drop that prefix for normal
/// drive paths so stored and printed paths look like what users typed.
pub fn simplify_path(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => path,
    }
}

pub fn load_json<T: DeserializeOwned + Default>(path: &Path) -> Result<T> {
    if !path.exists() {
        return Ok(T::default());
    }
    let text = std::fs::read_to_string(path)?;
    serde_json::from_str(&text).with_context(|| format!("{} is corrupt", path.display()))
}

/// Write via a temp file + rename so a crash never leaves a half-written file.
pub fn save_json<T: Serialize + ?Sized>(path: &Path, value: &T) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    opts.open(&tmp)?.write_all(&serde_json::to_vec_pretty(value)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
