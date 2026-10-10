//! How the core talks to whoever is using it: the terminal (CLI) or the
//! desktop app. Approvals, log lines and transfer progress all go through `Ui`.

use crate::progress::human;
use crate::prompt::Prompter;
use crate::proto::FileMeta;
use serde::Serialize;
use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    /// The peer wants to send us files.
    Offer,
    /// The peer wants files from our shares.
    Fetch,
    /// Someone used an invite link we made and wants to finish pairing
    /// (`path` holds the name the invite was made for).
    Pair,
}

/// A decision the user has to make. Silence (timeout) means no.
#[derive(Debug, Clone, Serialize)]
pub struct Approval {
    pub peer: String,
    /// First characters of the peer's device id, shown next to its name so a
    /// look-alike name can't impersonate another device.
    pub peer_id: String,
    pub kind: ApprovalKind,
    /// For fetches: the share path requested.
    pub path: Option<String>,
    pub file_count: usize,
    pub total: u64,
    /// The first files, for display.
    pub files: Vec<FileMeta>,
    /// The largest file, always shown even if it isn't among the first ones.
    pub largest: Option<FileMeta>,
    pub timeout_secs: u64,
    /// For pairings: the words the other screen should be showing too.
    pub check: Option<String>,
}

impl Approval {
    pub fn new(
        peer: &str,
        peer_id: &str,
        kind: ApprovalKind,
        path: Option<String>,
        metas: &[FileMeta],
        timeout_secs: u64,
    ) -> Self {
        Self {
            peer: crate::text::display_safe(peer, 64),
            peer_id: peer_id.chars().take(8).collect(),
            kind,
            path: path.map(|p| crate::text::display_safe(&p, 200)),
            file_count: metas.len(),
            total: crate::transfer::total_size(metas),
            files: metas.iter().take(50).cloned().collect(),
            largest: metas.iter().max_by_key(|m| m.size).cloned(),
            timeout_secs,
            check: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Send,
    Receive,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TransferState {
    Running,
    Done { message: String },
    Failed { message: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct TransferUpdate {
    pub id: u64,
    pub peer: String,
    pub direction: Direction,
    pub name: String,
    pub total: u64,
    pub done: u64,
    pub bytes_per_sec: u64,
    #[serde(flatten)]
    pub state: TransferState,
}

pub trait Ui: Send + Sync + 'static {
    fn ask(&self, approval: Approval) -> BoxFuture<bool>;
    fn log(&self, line: String);
    fn transfer(&self, update: TransferUpdate);
    /// Whether the service is currently reachable via the rendezvous server.
    fn online(&self, _online: bool) {}
}

/// Human-readable description of a transfer's contents.
pub fn transfer_name(metas: &[FileMeta]) -> String {
    match metas {
        [one] => one.path.clone(),
        _ => {
            let first = metas.first().map(|m| m.path.split('/').next().unwrap_or("")).unwrap_or("");
            if !first.is_empty() && metas.iter().all(|m| m.path.starts_with(&format!("{first}/"))) {
                format!("{first} ({} files)", metas.len())
            } else {
                format!("{} files", metas.len())
            }
        }
    }
}

pub fn describe(a: &Approval) -> String {
    let head = match a.kind {
        ApprovalKind::Offer => {
            format!("{} [{}] wants to send you {} file(s), {} total:", a.peer, a.peer_id, a.file_count, human(a.total))
        }
        ApprovalKind::Pair => {
            return format!(
                "{} [{}] used your invite for \"{}\" and wants to pair with you.\nCheck words: {}  (they should see the same; only accept if they do)\nAccepting pairs you and gives that PC its own key to your server.",
                a.peer,
                a.peer_id,
                a.path.as_deref().unwrap_or(""),
                a.check.as_deref().unwrap_or("?")
            )
        }
        ApprovalKind::Fetch => format!(
            "{} [{}] is requesting \"{}\" from your shares: {} file(s), {}:",
            a.peer,
            a.peer_id,
            a.path.as_deref().unwrap_or(""),
            a.file_count,
            human(a.total)
        ),
    };
    let mut lines = vec![head];
    lines.extend(a.files.iter().take(8).map(|f| format!("  {}  ({})", f.path, human(f.size))));
    if a.file_count > 8 {
        lines.push(format!("  ...and {} more", a.file_count - 8));
        if let Some(l) = &a.largest {
            lines.push(format!("  largest: {}  ({})", l.path, human(l.size)));
        }
    }
    lines.join("\n")
}

/// The CLI: prompts on stdin, progress as a single updating line.
#[derive(Default)]
pub struct TerminalUi {
    prompter: OnceLock<Arc<Prompter>>,
}

impl TerminalUi {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

impl Ui for TerminalUi {
    fn ask(&self, approval: Approval) -> BoxFuture<bool> {
        let prompter = self.prompter.get_or_init(Prompter::new).clone();
        let question = describe(&approval);
        let timeout = Duration::from_secs(approval.timeout_secs);
        Box::pin(async move { prompter.ask(&question, timeout).await })
    }

    fn log(&self, line: String) {
        println!("{}", crate::text::display_safe(&line, 2000));
    }

    fn transfer(&self, u: TransferUpdate) {
        let pct = if u.total == 0 { 100.0 } else { u.done as f64 * 100.0 / u.total as f64 };
        let arrow = match u.direction {
            Direction::Send => "to",
            Direction::Receive => "from",
        };
        print!(
            "\r{arrow} {}: {:5.1}%  {} / {}  {}/s     ",
            crate::text::display_safe(&u.peer, 64),
            pct,
            human(u.done),
            human(u.total),
            human(u.bytes_per_sec)
        );
        match u.state {
            TransferState::Running => {}
            TransferState::Done { .. } => println!(),
            TransferState::Failed { message } => {
                println!("\n  failed: {}", crate::text::display_safe(&message, 300))
            }
        }
        let _ = std::io::stdout().flush();
    }
}
