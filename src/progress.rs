use crate::ui::{Direction, TransferState, TransferUpdate, Ui};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Tracks one transfer and reports it to the `Ui` twice a second.
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
    report_lock: Mutex<()>,
}

impl Progress {
    pub fn start(ui: Arc<dyn Ui>, peer: &str, direction: Direction, name: String, total: u64) -> Arc<Self> {
        let p = Arc::new(Self {
            ui,
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            peer: peer.to_string(),
            direction,
            name,
            total,
            done: AtomicU64::new(0),
            resumed: AtomicU64::new(0),
            start: Instant::now(),
            finished: AtomicBool::new(false),
            report_lock: Mutex::new(()),
        });
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

    pub fn add(&self, n: u64) {
        self.done.fetch_add(n, Ordering::Relaxed);
    }

    pub fn skip(&self, n: u64) {
        self.done.fetch_add(n, Ordering::Relaxed);
        self.resumed.fetch_add(n, Ordering::Relaxed);
    }

    /// Report the final state (only the first call counts).
    pub fn finish(&self, state: TransferState) {
        let _g = self.report_lock.lock().unwrap();
        if !self.finished.swap(true, Ordering::SeqCst) {
            self.ui.transfer(self.update(state));
        }
    }

    fn report(&self, state: TransferState) {
        let _g = self.report_lock.lock().unwrap();
        self.ui.transfer(self.update(state));
    }

    fn update(&self, state: TransferState) -> TransferUpdate {
        let done = self.done.load(Ordering::Relaxed);
        let fresh = done - self.resumed.load(Ordering::Relaxed);
        let secs = self.start.elapsed().as_secs_f64().max(0.001);
        TransferUpdate {
            id: self.id,
            peer: self.peer.clone(),
            direction: self.direction,
            name: self.name.clone(),
            total: self.total,
            done,
            bytes_per_sec: (fresh as f64 / secs) as u64,
            state,
        }
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
