use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use filepigeon::app::App;
use filepigeon::config::{load_json, save_json, simplify_path, Config, Paths};
use filepigeon::identity::Identity;
use filepigeon::client::Outcome;
use filepigeon::ui::TerminalUi;
use filepigeon::{client, daemon, pairing};
use filepigeon::progress::human;
use std::sync::Arc;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "filepigeon", version, about = "Secure, direct PC-to-PC file transfer")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Set up this PC (creates its identity key). Re-run to change settings.
    Init {
        /// Name other PCs will see.
        #[arg(long)]
        name: Option<String>,
        /// Rendezvous server, e.g. pigeon.example.com:7400
        #[arg(long)]
        rendezvous: Option<String>,
        /// The server key (128 hex characters) printed by `pigeon-rendezvous --show-key`.
        #[arg(long)]
        rendezvous_key: Option<String>,
        /// The server address friends should use, if this PC reaches it some
        /// other way (e.g. by a LAN address). Empty to clear.
        #[arg(long)]
        friend_address: Option<String>,
        /// Your invite web page (e.g. https://fp.example.com/join), so invites
        /// carry a clickable link that also offers the download. Empty to clear.
        #[arg(long)]
        invite_page: Option<String>,
        /// Where received files go.
        #[arg(long)]
        download_dir: Option<PathBuf>,
        /// Fixed UDP port for `serve` (0 = random).
        #[arg(long)]
        port: Option<u16>,
        /// Allow temporary UPnP router port mappings (true/false).
        #[arg(long)]
        upnp: Option<bool>,
        /// Experimental: find devices over the public BitTorrent DHT when no
        /// rendezvous server is set or reachable (true/false).
        #[arg(long)]
        dht: Option<bool>,
    },
    /// Show this PC's name, device id and settings.
    Whoami,
    /// Pair with another PC. Without a code, shows one; with a code (or an
    /// invite someone sent you), joins.
    Pair {
        code: Option<String>,
        /// Also give that PC its own key to your rendezvous server (you must
        /// be one of the server's admin devices). Unpairing revokes it.
        #[arg(long)]
        give_server: bool,
    },
    /// Manage friends' keys to your rendezvous server (admin devices only).
    #[command(subcommand)]
    Invite(InviteCmd),
    /// List paired PCs.
    Peers,
    /// Forget a paired PC. It can no longer connect to you.
    Unpair { peer: String },
    /// Change what a paired PC is allowed to do.
    Trust {
        peer: String,
        /// Let them browse and request from your shared folders.
        #[arg(long)]
        browse: Option<bool>,
        /// Skip accept/deny prompts for them (use with care).
        #[arg(long)]
        auto_accept: Option<bool>,
        /// Give them a different local name.
        #[arg(long)]
        rename: Option<String>,
        /// Appear offline to them (they can't find or connect to you).
        #[arg(long)]
        hidden: Option<bool>,
    },
    /// Be visible to paired devices, or invisible to everyone.
    Visibility {
        #[arg(value_parser = ["online", "invisible"])]
        mode: String,
    },
    /// Manage folders paired PCs can browse and request files from.
    Share {
        #[command(subcommand)]
        cmd: ShareCmd,
    },
    /// Stay online to receive files and answer requests (prompts appear here).
    Serve,
    /// Offer files or folders to a paired PC.
    Send {
        peer: String,
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// List a paired PC's shares, or a folder inside one (e.g. photos/2024).
    Browse { peer: String, path: Option<String> },
    /// Request a file or folder from a paired PC's shares.
    Get {
        peer: String,
        path: String,
        /// Save here instead of the download folder.
        #[arg(long)]
        to: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum InviteCmd {
    /// Make an invite link for a friend far away: they paste it into
    /// FilePigeon, you approve, and you're paired with their own server key.
    /// Keep FilePigeon running until they use it.
    Link { name: String },
    /// List invite links that haven't been used yet.
    Pending,
    /// Cancel an unused invite link.
    Cancel { name: String },
    /// Make a raw server key for one friend and print it (prefer `link`).
    Create { name: String },
    /// List friends' keys and whether they're connected.
    List,
    /// Cut a friend off. Their connections close within seconds.
    Revoke { name: String },
}

#[derive(Subcommand)]
enum ShareCmd {
    /// Share a folder (read-only) under a name.
    Add { name: String, path: PathBuf },
    /// Stop sharing a folder.
    Remove { name: String },
    /// List your shares.
    List,
}

#[tokio::main]
async fn main() {
    if let Err(e) = run(Cli::parse()).await {
        eprintln!("error: {}", filepigeon::text::display_safe(&format!("{e:#}"), 2000));
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Init { name, rendezvous, rendezvous_key, friend_address, invite_page, download_dir, port, upnp, dht } => {
            let paths = Paths::resolve()?;
            let mut cfg: Config = load_json(&paths.config())?;
            if let Some(v) = name {
                cfg.device_name = v;
            }
            if let Some(v) = rendezvous {
                cfg.rendezvous = v;
            }
            if let Some(v) = rendezvous_key {
                cfg.set_server_key(&v)?;
            }
            if let Some(v) = friend_address {
                let v = v.trim().to_string();
                if !v.is_empty() {
                    filepigeon::invites::check_friend_address(&v)?;
                }
                cfg.friend_address = v;
            }
            if let Some(v) = invite_page {
                let v = v.trim().to_string();
                if !v.is_empty() && !v.starts_with("https://") {
                    bail!("the invite page must be an https:// address");
                }
                cfg.invite_page = v;
            }
            if let Some(v) = download_dir {
                cfg.download_dir = std::path::absolute(v)?;
            }
            if let Some(v) = port {
                cfg.listen_port = v;
            }
            if let Some(v) = upnp {
                cfg.upnp = v;
            }
            if let Some(v) = dht {
                cfg.dht = v;
            }
            save_json(&paths.config(), &cfg)?;
            Identity::load_or_create(&paths.identity())?;
            println!("Saved settings in {}", paths.home.display());
            whoami(&App::load()?);
        }
        Cmd::Whoami => whoami(&App::load()?),
        Cmd::Pair { code, give_server } => {
            let app = App::load()?;
            if give_server {
                // Fail early, before anyone types a code.
                filepigeon::invites::friend_address(&app)?;
            }
            let paired = match code {
                Some(code) => {
                    let show = |words: &str| {
                        println!("Check words: {words}");
                        println!("Ask the person who invited you to confirm they see the same words. Waiting for them to accept...");
                    };
                    pairing::join_any(&app, &code, give_server, &show).await?
                }
                None => {
                    pairing::host(&app, give_server, |code| {
                        println!("Your pairing code is:

    {code}
");
                        println!("On the other PC run:  filepigeon pair {code}");
                        println!("Waiting up to 10 minutes. The code works once.");
                    })
                    .await?
                }
            };
            let peer = &paired.peer;
            println!("\nPaired with \"{}\" (device {}).", peer.name, peer.device_id);
            println!("Check that this matches what the other PC shows.");
            for note in &paired.notes {
                println!("{note}");
            }
            println!("They can't browse or request your shared folders unless you allow it:");
            println!("  filepigeon trust \"{}\" --browse true", peer.name);
        }
        Cmd::Invite(cmd) => {
            let app = App::load()?;
            match cmd {
                InviteCmd::Link { name } => {
                    let (invite, _) = filepigeon::invites::create_link(&app, &name).await?;
                    eprintln!("Send this to {name} (any messenger is fine: it works once, within 24 hours, and you approve who uses it):\n");
                    println!("{}", invite.message);
                    eprintln!("\nKeep FilePigeon running (the desktop app or `filepigeon serve`) until they use it.");
                }
                InviteCmd::Pending => {
                    let list = filepigeon::invites::pending(&app);
                    if list.is_empty() {
                        println!("No unused invite links.");
                    }
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
                    for p in list {
                        println!(
                            "{}  {}  (expires in {} h)",
                            filepigeon::text::display_safe(&p.friend, 40),
                            p.code().display(),
                            p.expires.saturating_sub(now) / 3600
                        );
                    }
                }
                InviteCmd::Cancel { name } => {
                    let found = filepigeon::invites::pending(&app).into_iter().find(|p| p.friend.eq_ignore_ascii_case(name.trim()));
                    let Some(p) = found else { bail!("no unused invite link for {name:?}") };
                    filepigeon::invites::cancel_link(&app, &p.slot).await?;
                    println!("Cancelled the invite for {}.", p.friend);
                }
                InviteCmd::Create { name } => {
                    let key = filepigeon::invites::create(&app, &name).await?;
                    eprintln!("Server key for {name:?}. Give it to them directly (in person, or a disappearing message), never by email or chat history:");
                    println!("{key}");
                    if let Ok(addr) = filepigeon::invites::friend_address(&app) {
                        eprintln!("Server address for them: {addr}");
                    }
                }
                InviteCmd::List => {
                    let invites = filepigeon::invites::list(&app).await?;
                    if invites.is_empty() {
                        println!("No invites.");
                    }
                    for i in invites {
                        let status = if i.connected > 0 { format!("{} connection(s)", i.connected) } else { "not connected".into() };
                        println!("{}  ({status})", filepigeon::text::display_safe(&i.name, 80));
                    }
                }
                InviteCmd::Revoke { name } => {
                    filepigeon::invites::revoke(&app, &name).await?;
                    println!("Revoked {name:?}.");
                }
            }
        }
        Cmd::Peers => {
            let app = App::load()?;
            let peers = app.peers()?;
            if peers.is_empty() {
                println!("No paired PCs yet. Run `filepigeon pair`.");
            }
            for p in peers {
                println!(
                    "{:<20} {}  browse:{}  auto-accept:{}{}",
                    p.name,
                    p.device_id,
                    if p.allow_browse { "yes" } else { "no" },
                    if p.auto_accept { "YES" } else { "no" },
                    if p.hidden { "  (you appear offline to them)" } else { "" }
                );
            }
        }
        Cmd::Unpair { peer } => {
            let app = App::load()?;
            let target = app.find_peer(&peer)?;
            let peers: Vec<_> = app.peers()?.into_iter().filter(|p| p.device_id != target.device_id).collect();
            app.save_peers(&peers)?;
            filepigeon::addrbook::forget(&app, &target.device_id);
            println!("Unpaired {}. Its key is no longer accepted.", target.name);
            if let Some(invite) = &target.server_invite {
                match filepigeon::invites::revoke(&app, invite).await {
                    Ok(()) => println!("Also revoked its key to your server."),
                    Err(e) => println!(
                        "Couldn't revoke its key to your server ({e:#}). Revoke it with: filepigeon invite revoke \"{invite}\""
                    ),
                }
            }
        }
        Cmd::Visibility { mode } => {
            let paths = Paths::resolve()?;
            let mut cfg: Config = load_json(&paths.config())?;
            cfg.invisible = mode == "invisible";
            save_json(&paths.config(), &cfg)?;
            if cfg.invisible {
                println!("Invisible: nobody can find or connect to this PC. You can still send and browse.");
            } else {
                println!("Online: paired devices can find you.");
            }
            println!("Restart `filepigeon serve` (or the desktop app) for this to take effect.");
        }
        Cmd::Trust { peer, browse, auto_accept, rename, hidden } => {
            let app = App::load()?;
            let target = app.find_peer(&peer)?;
            let mut peers = app.peers()?;
            if let Some(new) = &rename {
                if peers.iter().any(|p| p.device_id != target.device_id && p.name.eq_ignore_ascii_case(new)) {
                    bail!("another peer is already called {new:?}");
                }
            }
            let p = peers.iter_mut().find(|p| p.device_id == target.device_id).unwrap();
            if let Some(v) = browse {
                p.allow_browse = v;
            }
            if let Some(v) = auto_accept {
                p.auto_accept = v;
            }
            if let Some(v) = hidden {
                p.hidden = v;
            }
            if let Some(v) = rename {
                p.name = v;
            }
            println!("{}: browse={} auto-accept={} hidden={}", p.name, p.allow_browse, p.auto_accept, p.hidden);
            app.save_peers(&peers)?;
        }
        Cmd::Share { cmd } => {
            let app = App::load()?;
            let mut shares = app.shares()?;
            match cmd {
                ShareCmd::Add { name, path } => {
                    if name.is_empty() || name.contains(['/', '\\']) {
                        bail!("share names cannot contain slashes");
                    }
                    let path = simplify_path(
                        path.canonicalize().with_context(|| format!("{} not found", path.display()))?,
                    );
                    if !path.is_dir() {
                        bail!("{} is not a folder", path.display());
                    }
                    println!("Sharing {} as \"{name}\" (read-only).", path.display());
                    shares.insert(name, path);
                    app.save_shares(&shares)?;
                }
                ShareCmd::Remove { name } => {
                    if shares.remove(&name).is_none() {
                        bail!("no share named {name:?}");
                    }
                    app.save_shares(&shares)?;
                    println!("Stopped sharing \"{name}\".");
                }
                ShareCmd::List => {
                    if shares.is_empty() {
                        println!("No shared folders. Add one with `filepigeon share add NAME PATH`.");
                    }
                    for (name, path) in shares {
                        println!("{name:<16} {}", path.display());
                    }
                }
            }
        }
        Cmd::Serve => {
            println!("Incoming offers and requests will be shown here. Press Ctrl+C to stop.");
            let shutdown = async {
                let _ = tokio::signal::ctrl_c().await;
            };
            daemon::serve(Arc::new(App::load()?), TerminalUi::new(), shutdown).await?
        }
        Cmd::Send { peer, paths } => {
            match client::send(&App::load()?, TerminalUi::new(), &peer, &paths).await? {
                Outcome::Done(c) => {
                    println!("{peer} received {} file(s).", c.received);
                    for f in &c.failed {
                        println!("  FAILED integrity check: {f}");
                    }
                }
                Outcome::Declined(reason) => println!("{peer} declined ({reason})."),
            }
        }
        Cmd::Browse { peer, path } => {
            let path = path.unwrap_or_default();
            let entries = client::browse(&App::load()?, &peer, &path).await?;
            println!("{peer} : {}", if path.trim_matches('/').is_empty() { "shares" } else { &path });
            if entries.is_empty() {
                println!("  (empty)");
            }
            for e in entries {
                if e.is_dir {
                    println!("  [dir]        {}/", e.name);
                } else {
                    println!("  {:>11}  {}", human(e.size), e.name);
                }
            }
        }
        Cmd::Get { peer, path, to } => {
            let app = App::load()?;
            let dest = to.unwrap_or_else(|| app.config.download_dir.clone());
            match client::get(&app, TerminalUi::new(), &peer, &path, &dest).await? {
                Outcome::Done(c) => {
                    println!("Received {} file(s) into {}", c.received, dest.display());
                    for f in &c.failed {
                        println!("  FAILED integrity check (discarded): {f}");
                    }
                }
                Outcome::Declined(reason) => println!("{peer} declined ({reason})."),
            }
        }
    }
    Ok(())
}

fn whoami(app: &App) {
    let c = &app.config;
    println!("Name:          {}", c.device_name);
    println!("Device id:     {}", app.identity.device_id());
    println!("Public key:    {}", hex::encode(app.identity.public_key()));
    println!(
        "Rendezvous:    {}",
        if c.rendezvous.is_empty() { "(none: local network only)" } else { &c.rendezvous }
    );
    if !c.friend_address.is_empty() {
        println!("For friends:   {}", c.friend_address);
    }
    println!("Downloads:     {}", c.download_dir.display());
    println!("UPnP fallback: {}", if c.upnp { "on (temporary mappings)" } else { "off" });
    println!("Visibility:    {}", if c.invisible { "INVISIBLE" } else { "online" });
    println!("DHT discovery: {}", if c.dht { "on (experimental)" } else { "off" });
}
