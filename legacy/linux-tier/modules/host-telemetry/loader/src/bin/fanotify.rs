//! hookprobe-fanotify — file-access host telemetry via fanotify → ingest_host_event JSON
//! ({"type":"file",…}). The FILE half of the threat-graph host layer (execsnoop is the process half);
//! together: process→file→registry. Needs CAP_SYS_ADMIN. Watches a mount for open/modify/close-write.
//!
//! Volume note: FAN_MARK_MOUNT reports every access on the mount — a real deployment narrows to
//! sensitive subtrees (persistence dirs, executables) or adds FAN_MARK_IGNORE noise filters. Line-flush
//! for the streaming ingest, same contract as the /proc + execsnoop producers.
use std::ffi::CString;
use std::io::Write;

const METADATA_VERSION: u8 = 3; // FANOTIFY_METADATA_VERSION

// High-churn / self-referential subtrees to drop — else a busy rootfs is a firehose (measured 126k
// events/s with FAN_MARK_MOUNT + FAN_OPEN). We watch a MOUNT (kernel granularity) but only emit
// security-relevant writes outside this noise.
const NOISE_PREFIXES: &[&str] = &[
    "/proc/", "/sys/", "/dev/", "/run/", "/tmp/",
    "/var/lib/hookprobe/", // the SOC's own writes → avoid a feedback loop
    "/var/log/", "/var/cache/", "/var/tmp/",
];

fn is_noise(path: &str) -> bool {
    NOISE_PREFIXES.iter().any(|p| path.starts_with(p))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Resolve an fanotify event fd → the file path via /proc/self/fd/<fd>.
fn path_of_fd(fd: i32) -> String {
    let link = format!("/proc/self/fd/{fd}");
    let cl = match CString::new(link) {
        Ok(c) => c,
        Err(_) => return String::new(),
    };
    let mut buf = [0u8; 4096];
    let len = unsafe { libc::readlink(cl.as_ptr(), buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if len > 0 {
        String::from_utf8_lossy(&buf[..len as usize]).into_owned()
    } else {
        String::new()
    }
}

/// The fd's inode — a SPOOF-PROOF identity: the path can be renamed away between the write and our
/// readlink (TOCTOU), but the fd pins the real inode, so the evidence graph can correlate on it.
fn fd_inode(fd: i32) -> u64 {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } == 0 {
        st.st_ino as u64
    } else {
        0
    }
}

/// Max bytes this producer will hash on a single `FAN_CLOSE_WRITE` event (64 MiB) — bounds the
/// worst-case blocking read against a legitimate huge file the [`NOISE_PREFIXES`] filter didn't
/// catch (a VM image, a database dump, …). An oversized file's hash is left unset (see
/// [`hash_fd_content`]'s own doc for why a PARTIAL-content hash would be actively worse than none).
const MAX_HASH_BYTES: i64 = 64 * 1024 * 1024;

/// File-hash IOC wiring (2026-07-09): sha256 the CURRENT content of an ALREADY-OPEN fd — called
/// right before `main`'s event loop closes `meta.fd`, so this reads the SAME bytes the write that
/// triggered `FAN_CLOSE_WRITE` just produced (no TOCTOU window beyond what fanotify's own fd
/// already has — same identity-pinning discipline as [`fd_inode`]'s doc comment).
///
/// Returns `None` (rendered as an EMPTY `sha256` field by the caller — never a fabricated value)
/// when:
///   - the file's size can't be determined (`fstat` failure) or exceeds [`MAX_HASH_BYTES`] — a
///     PARTIAL-content hash would silently mismatch every legitimate full-file IOC in the feed,
///     which is worse than no hash: a false "clean" verdict on a truncated read is a real
///     detection-evasion vector, so this producer refuses to ever emit one;
///   - the seek-to-start or any read syscall fails partway through — same "never partial" rule.
///
/// Never panics — every syscall's return value is checked before use; the read loop is bounded by
/// the file's own EOF (`read` returning `0`), so this can't spin.
fn hash_fd_content(fd: i32) -> Option<String> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return None;
    }
    if st.st_size < 0 || st.st_size > MAX_HASH_BYTES {
        return None;
    }
    if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
        return None;
    }
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            return None; // read error partway through — never emit a hash of only PART of the file
        }
        if n == 0 {
            break; // EOF
        }
        hasher.update(&buf[..n as usize]);
    }
    Some(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "/".to_string());
    let self_ip = std::env::var("HOOKPROBE_DEVICE_IP").unwrap_or_else(|_| "127.0.0.1".to_string());

    let fan_fd = unsafe {
        libc::fanotify_init(libc::FAN_CLOEXEC | libc::FAN_CLASS_NOTIF, libc::O_RDONLY as u32)
    };
    if fan_fd < 0 {
        eprintln!("fanotify_init failed (needs CAP_SYS_ADMIN): {}", std::io::Error::last_os_error());
        std::process::exit(1);
    }
    let cpath = CString::new(path.clone()).expect("path has NUL");
    // FAN_CLOSE_WRITE only: fires ONCE when a written file is closed (a real modification), vs FAN_OPEN
    // (every open) / FAN_MODIFY (every write syscall) which flood. This is the threat-relevant signal —
    // malware dropping/tampering with a file.
    let mask = libc::FAN_CLOSE_WRITE;
    let rc = unsafe {
        libc::fanotify_mark(fan_fd, libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT, mask, libc::AT_FDCWD, cpath.as_ptr())
    };
    if rc < 0 {
        eprintln!("fanotify_mark {path} failed: {}", std::io::Error::last_os_error());
        std::process::exit(1);
    }
    eprintln!("fanotify: watching mount of {path} (open/modify/write) → host-events");

    let mut buf = [0u8; 8192];
    let meta_sz = std::mem::size_of::<libc::fanotify_event_metadata>();
    loop {
        let n = unsafe { libc::read(fan_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue; // interrupted syscall — retry
            }
            eprintln!("fanotify read error: {e}"); // fatal (e.g. EBADF) — don't 100%-CPU spin
            std::process::exit(1);
        }
        if n == 0 {
            continue;
        }
        let mut off = 0usize;
        while off + meta_sz <= n as usize {
            // read_unaligned: `buf` is align-1 but fanotify_event_metadata holds an 8-aligned u64;
            // forming a &reference to a possibly-misaligned address is UB, so copy the value out.
            let meta = unsafe {
                (buf.as_ptr().add(off) as *const libc::fanotify_event_metadata).read_unaligned()
            };
            if meta.vers != METADATA_VERSION || (meta.event_len as usize) < meta_sz {
                break; // version mismatch or truncated — stop (avoids a bad-offset loop)
            }
            if meta.fd >= 0 {
                let raw = path_of_fd(meta.fd);
                // TOCTOU: a race can rename/unlink the file before we readlink → kernel appends
                // " (deleted)". Mark it honestly + carry the fd's inode as a spoof-proof identity.
                let deleted = raw.ends_with(" (deleted)");
                let fpath = raw.strip_suffix(" (deleted)").unwrap_or(&raw);
                if !fpath.is_empty() && !is_noise(fpath) {
                    // File-hash IOC wiring: hash the CLOSED-WRITE content while `meta.fd` is still
                    // open (see `hash_fd_content`'s doc). Empty string (never fabricated) when not
                    // computed — `hookprobe_evidence::EvidenceGraph::ingest_host_event`'s "file"
                    // case already treats an absent/empty `sha256` field this way.
                    let sha256 = hash_fd_content(meta.fd).unwrap_or_default();
                    let ev = serde_json::json!({
                        "type": "file", "ts": now_secs() as f64, "device_ip": self_ip.as_str(),
                        "path": fpath, "action": "write", "pid": meta.pid,
                        "inode": fd_inode(meta.fd), "deleted": deleted, "sha256": sha256,
                    });
                    println!("{ev}");
                    let _ = std::io::stdout().flush();
                }
                unsafe { libc::close(meta.fd) }; // MUST close every event fd or we leak them
            }
            off += meta.event_len as usize;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::unix::io::AsRawFd;

    /// A tiny self-cleaning temp-file helper (no `tempfile` crate — one std::fs::File is all these
    /// tests need, and this workspace prefers a minimal dependency footprint, ADR 0002's own
    /// crypto-agile/small-supply-chain posture generalized to test-only deps too).
    struct TmpFile {
        path: std::path::PathBuf,
        file: File,
    }
    impl TmpFile {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "hookprobe-fanotify-test-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
            ));
            let file = File::options().read(true).write(true).create(true).truncate(true).open(&path).expect("create tmp file");
            Self { path, file }
        }
    }
    impl Drop for TmpFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// A known sha256 vector (`sha256("hello world\n")`) — cross-checked independently (`echo
    /// "hello world" | sha256sum`) — proves [`hash_fd_content`] computes a REAL sha256, not just
    /// "some deterministic string".
    #[test]
    fn hash_fd_content_matches_a_known_sha256_vector() {
        let mut t = TmpFile::new("known-vector");
        t.file.write_all(b"hello world\n").unwrap();
        t.file.flush().unwrap();
        let got = hash_fd_content(t.file.as_raw_fd()).expect("must hash a small real file");
        assert_eq!(got, "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447");
    }

    #[test]
    fn hash_fd_content_of_an_empty_file_matches_sha256_of_empty_input() {
        let t = TmpFile::new("empty");
        let got = hash_fd_content(t.file.as_raw_fd()).expect("must hash a zero-byte file");
        // sha256("") — the well-known empty-input digest.
        assert_eq!(got, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn hash_fd_content_reads_from_the_start_regardless_of_the_fds_current_offset() {
        // fanotify hands us the fd right after the writer's OWN write left the offset at EOF —
        // hash_fd_content must seek back to 0 itself, not assume the caller already did.
        let mut t = TmpFile::new("offset");
        t.file.write_all(b"content").unwrap();
        t.file.flush().unwrap();
        // offset is now at EOF (7) from the write above — do NOT seek back before calling.
        let got = hash_fd_content(t.file.as_raw_fd()).expect("must still hash from the start");
        let expected = {
            use sha2::{Digest, Sha256};
            Sha256::digest(b"content").iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        assert_eq!(got, expected);
    }

    #[test]
    fn hash_fd_content_returns_none_for_an_invalid_fd_never_panics() {
        assert!(hash_fd_content(-1).is_none());
    }

    #[test]
    fn hash_fd_content_over_the_size_cap_returns_none_never_a_partial_hash() {
        // `set_len` (ftruncate) makes this file APPEAR one byte over the cap without writing any
        // real bytes (a sparse file — instant, no disk I/O) — exercises the REAL
        // `st.st_size > MAX_HASH_BYTES` gate in `hash_fd_content`, not a re-derivation of it.
        let t = TmpFile::new("oversized");
        t.file.set_len(MAX_HASH_BYTES as u64 + 1).expect("sparse set_len");
        assert!(hash_fd_content(t.file.as_raw_fd()).is_none(), "an oversized file must never be hashed, even partially");
    }
}
