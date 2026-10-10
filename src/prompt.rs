use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};

/// Asks the person at the keyboard yes/no questions, one at a time.
/// Silence means no: unanswered prompts are denied after a timeout.
pub struct Prompter {
    lines: Mutex<mpsc::UnboundedReceiver<String>>,
}

impl Prompter {
    pub fn new() -> Arc<Self> {
        let (tx, rx) = mpsc::unbounded_channel();
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            let mut line = String::new();
            while stdin.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                if tx.send(std::mem::take(&mut line)).is_err() {
                    break;
                }
            }
        });
        Arc::new(Self { lines: Mutex::new(rx) })
    }

    pub async fn ask(&self, question: &str, timeout: Duration) -> bool {
        // The timeout covers waiting behind other prompts too: a queued request
        // that never gets shown is denied, not kept forever.
        let started = std::time::Instant::now();
        let Ok(mut rx) = tokio::time::timeout(timeout, self.lines.lock()).await else {
            return false;
        };
        let timeout = timeout.saturating_sub(started.elapsed());
        if timeout.is_zero() {
            return false;
        }
        // Ignore anything typed before the question was shown.
        while rx.try_recv().is_ok() {}
        println!("\n{question}");
        print!("Accept? [y/N] (auto-deny in {}s): ", timeout.as_secs());
        let _ = std::io::stdout().flush();
        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(answer)) => matches!(answer.trim().to_lowercase().as_str(), "y" | "yes"),
            _ => {
                println!("\n-> no answer, denied.");
                false
            }
        }
    }
}
