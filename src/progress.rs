use crate::ui::{Direction, TransferState, TransferUpdate, Ui};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::{Duration, Instant};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Transfers that can still be cancelled, by id.
static ACTIVE: LazyLock<Mutex<HashMap<u64, Weak<Progress>>>> = LazyLock::new(Default::default);

/// Window for the "current speed" figure.
const SPEED_WINDOW: Duration = Duration::from_secs(5);

/// Where a transfer is: connecting, waiting for the other side to accept,
/// or moving bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Connecting,
    Waiting,
    Transferring,
}

impl Phase {
    fn as_str(self) -> &'static str {
        match self {
            Phase::Connecting => "connecting",
            Phase::Waiting => "waiting",
            Phase::Transferring => "transferring",
        }
    }
}

struct Live {
    phase: Phase,
    route: Option<String>,
    file_index: usize,
    file_count: usize,
    current_file: String,
    /// When bytes started moving (for elapsed time, average speed and ETA).
    moving_since: Option<Instant>,
    /// (time, bytes done) samples for the current speed.
    samples: VecDeque<(Instant, u64)>,
    conn: Option<quinn::Connection>,
}

/// Tracks one transfer, reports it to the `Ui` twice a second, and can be
/// cancelled from the UI (`cancel`).
pub struct Progress {
    ui: Arc<dyn Ui>,
    id: u64,
    peer: String,
    direction: Direction,
    name: String,
    total: u64,
    done: AtomicU64,
    /// Bytes already present from an earlier attempt (excluded from speed).
    resumed: AtomicU64,
    start: Instant,
    finished: AtomicBool,
    cancelled: AtomicBool,
    /// Every byte is out: from here cancelling would only misreport it.
    sealed: AtomicBool,
    cancel_notify: tokio::sync::Notify,
    live: Mutex<Live>,
    report_lock: Mutex<()>,
}

impl Progress {
    /// A transfer that is already moving bytes (the receiving side).
    pub fn start(ui: Arc<dyn Ui>, peer: &str, direction: Direction, name: String, total: u64) -> Arc<Self> {
        Self::begin(ui, peer, direction, name, total, Phase::Transferring)
    }

    /// A transfer that starts in `phase` (the sending side starts while still
    /// connecting, so the user sees it at once).
    pub fn begin(ui: Arc<dyn Ui>, peer: &str, direction: Direction, name: String, total: u64, phase: Phase) -> Arc<Self> {
        let now = Instant::now();
        let p = Arc::new(Self {
            ui,
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            peer: peer.to_string(),
            direction,
            name,
            total,
            done: AtomicU64::new(0),
            resumed: AtomicU64::new(0),
            start: now,
            finished: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
            sealed: AtomicBool::new(false),
            cancel_notify: tokio::sync::Notify::new(),
            live: Mutex::new(Live {
                phase,
                route: None,
                file_index: 0,
                file_count: 0,
                current_file: String::new(),
                moving_since: (phase == Phase::Transferring).then_some(now),
                samples: VecDeque::new(),
                conn: None,
            }),
            report_lock: Mutex::new(()),
        });
        ACTIVE.lock().unwrap().insert(p.id, Arc::downgrade(&p));
        p.report(TransferState::Running);
        let ticker = p.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                let _g = ticker.report_lock.lock().unwrap();
                if ticker.finished.load(Ordering::SeqCst) {
                    break;
                }
                ticker.ui.transfer(ticker.update(TransferState::Running));
            }
        });
        p
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn add(&self, n: u64) {
        self.done.fetch_add(n, Ordering::Relaxed);
    }

    pub fn skip(&self, n: u64) {
        self.done.fetch_add(n, Ordering::Relaxed);
        self.resumed.fetch_add(n, Ordering::Relaxed);
    }

    pub fn set_phase(&self, phase: Phase) {
        let mut live = self.live.lock().unwrap();
        if phase == Phase::Transferring && live.moving_since.is_none() {
            live.moving_since = Some(Instant::now());
        }
        live.phase = phase;
        drop(live);
        self.report(TransferState::Running);
    }

    /// How the two PCs are connected: "Local network", "Direct" or "Relay".
    pub fn set_route(&self, route: &str) {
        self.live.lock().unwrap().route = Some(route.to_string());
    }

    /// Which file is moving now (1-based index).
    pub fn set_file(&self, index: usize, count: usize, name: &str) {
        let mut live = self.live.lock().unwrap();
        live.file_index = index;
        live.file_count = count;
        live.current_file = crate::text::display_safe(name, 200);
    }

    /// The connection this transfer runs over: for connection quality, and so
    /// cancelling can close it.
    pub fn attach(&self, conn: &quinn::Connection) {
        self.live.lock().unwrap().conn = Some(conn.clone());
        if self.is_cancelled() {
            conn.close(crate::proto::CLOSE_CANCELLED.into(), b"cancelled");
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Resolves once the transfer is cancelled.
    pub async fn cancelled(&self) {
        let notified = self.cancel_notify.notified();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }

    /// Stop it: the connection is closed (the other side is told it was
    /// cancelled) and whatever is waiting on it gives up.
    pub fn cancel(&self) {
        if self.finished.load(Ordering::SeqCst)
            || self.sealed.load(Ordering::SeqCst)
            || self.cancelled.swap(true, Ordering::SeqCst)
        {
            return;
        }
        if let Some(conn) = &self.live.lock().unwrap().conn {
            conn.close(crate::proto::CLOSE_CANCELLED.into(), b"cancelled");
        }
        self.cancel_notify.notify_waiters();
    }

    /// All the data has been sent: the transfer can no longer be cancelled
    /// (the other side may already have everything).
    pub fn seal(&self) {
        if !self.is_cancelled() {
            self.sealed.store(true, Ordering::SeqCst);
        }
    }

    /// Report the final state (only the first call counts). A failure after
    /// the user cancelled is reported as cancelled.
    pub fn finish(&self, state: TransferState) {
        let _g = self.report_lock.lock().unwrap();
        if !self.finished.swap(true, Ordering::SeqCst) {
            let state = match state {
                TransferState::Failed { .. } if self.is_cancelled() => TransferState::Cancelled { message: "Cancelled".into() },
                other => other,
            };
            self.ui.transfer(self.update(state));
        }
        ACTIVE.lock().unwrap().remove(&self.id);
    }

    fn report(&self, state: TransferState) {
        let _g = self.report_lock.lock().unwrap();
        self.ui.transfer(self.update(state));
    }

    fn update(&self, state: TransferState) -> TransferUpdate {
        let done = self.done.load(Ordering::Relaxed);
        let fresh = done.saturating_sub(self.resumed.load(Ordering::Relaxed));
        let now = Instant::now();
        let mut live = self.live.lock().unwrap();
        live.samples.push_back((now, done));
        while live.samples.front().is_some_and(|(t, _)| now.duration_since(*t) > SPEED_WINDOW) {
            live.samples.pop_front();
        }
        let current = match (live.samples.front(), live.samples.back()) {
            (Some((t0, b0)), Some((t1, b1))) if t1 > t0 => ((b1 - b0) as f64 / t1.duration_since(*t0).as_secs_f64()) as u64,
            _ => 0,
        };
        let moving = live.moving_since.map(|t| now.duration_since(t).as_secs_f64()).unwrap_or(0.0);
        let average = if moving > 0.5 { (fresh as f64 / moving) as u64 } else { 0 };
        let running = matches!(state, TransferState::Running);
        // Remaining time from the current speed, steadied by the average.
        let speed = if current > 0 && average > 0 { (current + average) / 2 } else { current.max(average) };
        let eta_secs = (running && live.phase == Phase::Transferring && speed > 0)
            .then(|| self.total.saturating_sub(done) / speed.max(1));
        let (rtt_ms, loss_pct) = match &live.conn {
            Some(c) => {
                let s = c.stats();
                let loss = (s.path.sent_packets > 0).then(|| s.path.lost_packets as f32 * 100.0 / s.path.sent_packets as f32);
                (Some(s.path.rtt.as_millis() as u64), loss)
            }
            None => (None, None),
        };
        TransferUpdate {
            id: self.id,
            peer: self.peer.clone(),
            direction: self.direction,
            name: self.name.clone(),
            total: self.total,
            done,
            bytes_per_sec: if running { current } else { average },
            avg_bytes_per_sec: average,
            elapsed_secs: if live.moving_since.is_some() { moving as u64 } else { self.start.elapsed().as_secs() },
            eta_secs,
            phase: live.phase.as_str().into(),
            route: live.route.clone(),
            file_index: live.file_index,
            file_count: live.file_count,
            current_file: live.current_file.clone(),
            rtt_ms,
            loss_pct,
            cancellable: running && !self.sealed.load(Ordering::SeqCst),
            state,
        }
    }
}

/// Cancel a running transfer by id (from the UI). False if it already ended.
pub fn cancel(id: u64) -> bool {
    let found = ACTIVE.lock().unwrap().get(&id).and_then(Weak::upgrade);
    match found {
        Some(p) => {
            p.cancel();
            true
        }
        None => false,
    }
}

pub fn human(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}
