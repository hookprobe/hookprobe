//! Kill-switch (ADR 0020 D3 contract #4 / condition 5): a sentinel file or a trapped SIGTERM drains
//! and halts every in-flight campaign, fail-closed. Checked cooperatively between every probe frame
//! (cheap: one `Path::exists()` stat) and via a `tokio::signal` trap in the campaign's async runner.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Shared kill-switch state a probe checks between frames. `tripped()` is cheap and safe to call
/// in a tight send loop (a `Path::exists()` syscall + an atomic load).
#[derive(Clone)]
pub struct KillSwitch {
    file: PathBuf,
    signalled: Arc<AtomicBool>,
}

impl KillSwitch {
    pub fn new(file: impl Into<PathBuf>) -> Self {
        Self { file: file.into(), signalled: Arc::new(AtomicBool::new(false)) }
    }

    /// `true` iff the campaign must stop RIGHT NOW: the sentinel file exists, or a trapped signal
    /// already flipped the flag. A probe's send loop must check this before every frame it emits.
    pub fn tripped(&self) -> bool {
        self.signalled.load(Ordering::SeqCst) || self.file.exists()
    }

    /// Called by the signal-handling task when SIGTERM arrives — flips the flag so every probe's
    /// next `tripped()` check (even one that never touches the filesystem sentinel) also halts.
    pub fn trip(&self) {
        self.signalled.store(true, Ordering::SeqCst);
    }

    pub fn sentinel_path(&self) -> &Path {
        &self.file
    }
}

/// Spawns the tokio task that traps SIGTERM and trips `ks` when it arrives. Kept as a free function
/// (not a `KillSwitch` method) so the pure/no-unsafe struct above stays testable without a runtime.
#[cfg(unix)]
pub async fn trap_sigterm(ks: KillSwitch) {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("redteam-engine: kill-switch: could not install SIGTERM trap: {e} (file sentinel still works)");
            return;
        }
    };
    term.recv().await;
    eprintln!("redteam-engine: kill-switch: SIGTERM received -- draining and halting, fail-closed");
    ks.trip();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_tripped_by_default() {
        let ks = KillSwitch::new("/nonexistent/path/that/should/never/exist/for/this/test");
        assert!(!ks.tripped());
    }

    #[test]
    fn tripped_when_sentinel_file_exists() {
        let mut p = std::env::temp_dir();
        p.push(format!("redteam-killswitch-test-{}", std::process::id()));
        std::fs::write(&p, b"stop").unwrap();
        let ks = KillSwitch::new(&p);
        assert!(ks.tripped());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn tripped_after_explicit_trip() {
        let ks = KillSwitch::new("/nonexistent/path/for/trip/test");
        assert!(!ks.tripped());
        ks.trip();
        assert!(ks.tripped());
    }
}
