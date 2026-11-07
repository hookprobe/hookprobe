//! Minimal, zero-dependency `sd_notify(3)` client (backend-audit gap 2 — Architecture.md §4.4's
//! "Type=notify with a watchdog driven from the real work loop").
//!
//! systemd tells "crashed" from "hung" only via this protocol: a service declares
//! `WatchdogSec=N` and must send a `WATCHDOG=1` datagram to `$NOTIFY_SOCKET` at least once every
//! `N` seconds, or systemd kills + restarts it as failed. Without a matching ping, a wedged (not
//! crashed) long-running engine is invisible to systemd between 15-minute selftest passes — this
//! module closes exactly that gap for `hookprobe-supervisor`'s own work loops (`--scan-respond`,
//! and the shared `--run-wasm` streaming host loop every `runtime: wasm` module rides) and
//! `napse-dpi`'s capture loop.
//!
//! Deliberately NOT the `libsystemd`/`sd-notify` crate: avoids a C dependency (`libsystemd`) or a
//! new third-party crate, consistent with this codebase's minimal-dependency posture for
//! long-running/sandboxed engines (see e.g. `hookprobe-mgmt-guard`'s own Cargo.toml doc comment).
//! The wire protocol is trivial — one `KEY=VALUE` datagram to a UNIX socket named by
//! `$NOTIFY_SOCKET` (systemd sets this env var on every unit it manages; either a real
//! filesystem path or, per `sd_notify(3)`, a Linux abstract-namespace name prefixed `@`, both
//! handled below). 100% safe Rust (`std::os::unix::net`, `unix_socket_abstract` stable since
//! Rust 1.70) — no `unsafe` needed even where a crate doesn't `forbid(unsafe_code)`.
//!
//! **Best-effort by design**: every public function here swallows its own errors. Running
//! outside systemd (a dev workstation, `cargo test`, a container with no `NOTIFY_SOCKET`) must
//! never become a hard failure just because nobody is listening — `sd_notify(3)` itself
//! documents exactly this contract ("If the notification socket [...] does not exist, [...] all
//! function calls [...] will fail with -ENXIO, [but this must be ignored]"). A caller that truly
//! needs to observe a send attempt uses `notify_via`/`notify_raw` directly.
use std::env;
use std::ffi::OsStr;
use std::io;
use std::os::unix::net::UnixDatagram;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use std::os::linux::net::SocketAddrExt;
#[cfg(target_os = "linux")]
use std::os::unix::net::SocketAddr as UnixSocketAddr;

/// Send a raw sd_notify state string (e.g. `"READY=1"`, `"WATCHDOG=1"`) to the given notify
/// socket path. `notify_socket = None` (or an empty path) is a silent no-op — "not running under
/// a notifying supervisor" is the common, expected case (dev box, `cargo test`, a unit with no
/// `Type=notify`), never an error. Split out from `notify_raw` so tests can drive the actual
/// socket-write logic deterministically, with no process-global env-var mutation.
pub fn notify_via(notify_socket: Option<&OsStr>, state: &str) -> io::Result<()> {
    let Some(path) = notify_socket else { return Ok(()) };
    if path.is_empty() {
        return Ok(());
    }
    let sock = UnixDatagram::unbound()?;
    let addr = path.to_string_lossy();
    #[cfg(target_os = "linux")]
    {
        // A leading '@' names a Linux abstract-namespace socket (no filesystem inode) rather
        // than a real path -- systemd's own documented convention, used by some container/
        // nested-manager setups. Both forms are handled so this works identically under the
        // host systemd and under any future sandboxed/nested invocation.
        if let Some(abstract_name) = addr.strip_prefix('@') {
            let sockaddr = UnixSocketAddr::from_abstract_name(abstract_name.as_bytes())?;
            sock.send_to_addr(state.as_bytes(), &sockaddr)?;
            return Ok(());
        }
    }
    sock.send_to(state.as_bytes(), addr.as_ref())?;
    Ok(())
}

/// `notify_via` reading the real `$NOTIFY_SOCKET` -- what every production call site uses.
pub fn notify_raw(state: &str) -> io::Result<()> {
    notify_via(env::var_os("NOTIFY_SOCKET").as_deref(), state)
}

/// Tell systemd this process finished starting (`Type=notify` only transitions
/// activating -> running once this arrives, or `TimeoutStartSec` fires and the start is treated
/// as failed) -- call ONCE, right after startup succeeds, before entering the long-running work
/// loop. Best-effort (see module doc): a missing/broken `$NOTIFY_SOCKET` must never abort an
/// otherwise-healthy startup.
pub fn notify_ready() {
    let _ = notify_raw("READY=1");
}

/// Tell systemd this process is alive AND making forward progress. Best-effort, like
/// `notify_ready`. Never call this from an unconditional timer -- see `WatchdogPinger`.
pub fn notify_watchdog() {
    let _ = notify_raw("WATCHDOG=1");
}

/// The systemd watchdog interval for THIS service, halved (the standard "ping at `WATCHDOG_USEC`/2"
/// cadence), or `None` when systemd configured no watchdog (`WATCHDOG_USEC` unset/0). systemd exports
/// `WATCHDOG_USEC` into the service's environment (inherited by children of the `ExecStart` process,
/// e.g. the supervisor inside a `bash -c '… | hookprobe-supervisor …'` pipeline), so a process that is
/// NOT the unit's MainPID can still read it — which, paired with `NotifyAccess=all`, is exactly the
/// `--run-wasm` streaming shape. Deliberately does NOT gate on `WATCHDOG_PID` matching our pid: in the
/// pipeline shape the sender is intentionally not the MainPID, and `NotifyAccess=all` already
/// authorizes it.
///
/// TA2 (2026-07-17 field audit): use this to drive a LIVENESS TIMER thread for the streaming reflex
/// modules (`aegis-guard`, `dnsxai`). Those block on stdin whenever the network is quiet — a
/// perfectly HEALTHY state — but the old `WatchdogPinger`-from-the-epoch-callback design only pinged
/// while the guest was executing wasm, so an idle module sent nothing and systemd SIGABRT'd it every
/// `WatchdogSec` (observed crash-looping on Pi4+CM5). For these modules "blocked on input" is health,
/// not a hang, so a timer heartbeat is the CORRECT signal; a guest genuinely wedged in a compute loop
/// is a separate concern bounded by the epoch/fuel wall, not this liveness ping's job.
pub fn watchdog_interval() -> Option<Duration> {
    watchdog_interval_from(env::var("WATCHDOG_USEC").ok().as_deref())
}

/// Pure core of [`watchdog_interval`] (env-free, so it's testable without racing on process env).
fn watchdog_interval_from(usec: Option<&str>) -> Option<Duration> {
    let usec: u64 = usec?.trim().parse().ok()?;
    if usec == 0 {
        return None;
    }
    Some(Duration::from_micros(usec / 2))
}

/// Rate-limited watchdog pinger: call `tick()` from INSIDE the real work loop, once per unit of
/// actual work done (one packet received+processed, one stdin line handled, one wasm epoch tick
/// that proves the guest executed, ...) -- NEVER from an independent background timer thread
/// that would keep pinging even while the real loop is wedged. That caution is the whole reason
/// this feature is dangerous to half-implement: `WatchdogSec=` paired with a ping NOT tied to
/// genuine progress makes a hang WORSE, not better -- systemd now also can't tell "wedged" from
/// "crashed", because the ping itself is lying about which one it is.
///
/// Internally rate-limited to at most one actual `sd_notify` datagram per `min_interval` --
/// packets/lines typically arrive far more often than the watchdog needs pinging, so sending on
/// every single one would be pure waste on an edge device (SD-card / RTC-limited hardware).
/// `min_interval` must stay comfortably shorter than the pairing unit's own `WatchdogSec=` (this
/// codebase's convention: `WatchdogSec >= 3 * min_interval`, i.e. at least 3 pings would need to
/// be missed in a row before systemd acts -- see each call site's unit for its exact numbers).
pub struct WatchdogPinger {
    min_interval: Duration,
    last: Option<Instant>,
}

impl WatchdogPinger {
    pub fn new(min_interval: Duration) -> Self {
        Self { min_interval, last: None }
    }

    /// Call once per real unit of work. Sends `WATCHDOG=1` only if `min_interval` has elapsed
    /// since the last actual send -- the very first call always sends (so a freshly started
    /// process doesn't sit silent for a full interval before its first proof-of-life).
    pub fn tick(&mut self) {
        let now = Instant::now();
        let due = match self.last {
            None => true,
            Some(last) => now.duration_since(last) >= self.min_interval,
        };
        if due {
            notify_watchdog();
            self.last = Some(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram as TestListener;

    fn tempfile_dir(label: &str) -> std::path::PathBuf {
        let dir = env::temp_dir().join(format!(
            "hookprobe-sd-notify-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn notify_via_none_is_a_silent_noop() {
        // "not running under a notifying supervisor" must never be an error.
        assert!(notify_via(None, "READY=1").is_ok());
    }

    #[test]
    fn watchdog_interval_is_half_the_systemd_budget() {
        // TA2: ping at WATCHDOG_USEC/2. 1800s WatchdogSec (aegis-guard) → 1.8e9 µs → ping every 900s.
        assert_eq!(watchdog_interval_from(Some("1800000000")), Some(Duration::from_secs(900)));
        assert_eq!(watchdog_interval_from(Some("900000000")), Some(Duration::from_secs(450)));
        // No watchdog configured → no heartbeat thread.
        assert_eq!(watchdog_interval_from(None), None);
        assert_eq!(watchdog_interval_from(Some("0")), None);
        assert_eq!(watchdog_interval_from(Some("")), None);
        assert_eq!(watchdog_interval_from(Some("garbage")), None);
        assert_eq!(watchdog_interval_from(Some("  600000000 ")), Some(Duration::from_secs(300)));
    }

    #[test]
    fn notify_via_empty_path_is_a_silent_noop() {
        assert!(notify_via(Some(OsStr::new("")), "READY=1").is_ok());
    }

    #[test]
    fn notify_via_filesystem_socket_delivers_the_exact_datagram() {
        let dir = tempfile_dir("fs-socket");
        let sock_path = dir.join("notify.sock");
        let listener = TestListener::bind(&sock_path).expect("bind test notify listener");

        notify_via(Some(sock_path.as_os_str()), "READY=1").expect("send to a real socket must succeed");

        let mut buf = [0u8; 64];
        let (n, _) = listener.recv_from(&mut buf).expect("recv the datagram");
        assert_eq!(&buf[..n], b"READY=1");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn notify_via_abstract_socket_delivers_the_exact_datagram() {
        // Abstract-namespace sockets need no filesystem path at all -- exercise the '@' branch.
        let name = format!(
            "hookprobe-sd-notify-abstract-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        );
        let sockaddr = UnixSocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let listener = TestListener::bind_addr(&sockaddr).expect("bind abstract test listener");

        let at_name = format!("@{name}");
        notify_via(Some(OsStr::new(&at_name)), "WATCHDOG=1")
            .expect("send to an abstract socket must succeed");

        let mut buf = [0u8; 64];
        let (n, _) = listener.recv_from(&mut buf).expect("recv the datagram");
        assert_eq!(&buf[..n], b"WATCHDOG=1");
    }

    /// Both `WatchdogPinger` behaviors (immediate first ping + rate-limited re-pings) in ONE
    /// test function -- deliberately not split across two `#[test]`s: both mutate the
    /// process-global `NOTIFY_SOCKET` env var (the production `tick()` -> `notify_watchdog()`
    /// -> `notify_raw()` path reads it for real, by design -- that IS what's under test), and
    /// `cargo test` runs `#[test]` functions concurrently on different threads by default, so
    /// two separate env-mutating tests would race each other's `set_var`/`remove_var`. One test
    /// function has no such race with itself.
    #[test]
    fn watchdog_pinger_first_tick_sends_then_rate_limits_then_resumes() {
        let dir = tempfile_dir("pinger");
        let sock_path = dir.join("notify.sock");
        let listener = TestListener::bind(&sock_path).unwrap();
        listener.set_nonblocking(true).unwrap();
        env::set_var("NOTIFY_SOCKET", &sock_path);

        let mut pinger = WatchdogPinger::new(Duration::from_millis(200));
        let mut buf = [0u8; 64];

        // First call always sends, regardless of min_interval (no silent startup gap).
        pinger.tick();
        let (n, _) = listener
            .recv_from(&mut buf)
            .expect("first tick() must send a datagram immediately");
        assert_eq!(&buf[..n], b"WATCHDOG=1");

        // Rapid re-ticks well inside min_interval must NOT send again.
        for _ in 0..50 {
            pinger.tick();
        }
        assert!(
            listener.recv_from(&mut buf).is_err(),
            "ticks inside min_interval must be suppressed, got a second datagram too early"
        );

        // After min_interval elapses, the next tick() sends again.
        std::thread::sleep(Duration::from_millis(250));
        pinger.tick();
        let (n, _) = listener
            .recv_from(&mut buf)
            .expect("a tick() after min_interval has elapsed must send again");
        assert_eq!(&buf[..n], b"WATCHDOG=1");

        env::remove_var("NOTIFY_SOCKET");
    }
}
