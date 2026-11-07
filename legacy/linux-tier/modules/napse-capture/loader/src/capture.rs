//! Trigger-to-evidence pcap capture (roadmap D). The one place `bin/napse-dpi.rs` holds a real
//! frame (`let frame = &buf[..n]` at its recv-loop's top) before it is either DPI-parsed into a
//! flow record or discarded — until this module, that discard was total: a detection told an
//! operator "this happened" with no packet ever surfacable as evidence. `FrameCapture` fixes that
//! with a BOUNDED, CHEAP ring: every observed frame is appended to a small per-source rolling
//! buffer; on a network-layer trigger (`FrameCapture::trigger`) the ring is snapshotted and a
//! short, bounded post-trigger tail is collected, then written out as a real libpcap file once its
//! window elapses (`FrameCapture::poll_finalize`).
//!
//! ## What this is NOT (honest scope)
//! HYDRA-IOC / host-EDR triggers fire OUT OF BAND, days after the packet that mattered is long
//! gone from any bounded ring — there is no packet "in hand" to capture for them, and this module
//! makes no attempt to fake one. Only the packet-layer network/L1-L2 detectors in this crate
//! (`portscan`/`beacon`/`lateral`/`l2guard`), which fire from directly inside the recv loop with
//! the triggering frame (or its source's very recent history) still available, are wired to this.
//! `mac_flood` is a further, deliberate exclusion: its own alert (see `l2guard::L2Alert`'s doc)
//! carries NO single attributable source by design — a link-wide flood has no "the" source key to
//! ring on, and inventing one would be dishonest, not a capture.
//!
//! ## Cost discipline (the recv loop is hot — every packet on the mirror passes through it)
//! `observe()` (called on EVERY frame) does no I/O and no allocation beyond one bounded `Vec<u8>`
//! clone into a `VecDeque` slot, with cheap FIFO bound checks. `trigger()` (called only when a
//! detector's OWN cooldown lets an alert through — 10s-900s per detector, see each tracker's
//! module doc) does no I/O either: it clones the already-in-memory ring snapshot. The only real
//! file I/O (`write`, sha256) happens in `poll_finalize()`, invoked once per recv-loop iteration
//! but doing actual work only when a pending capture's bounded window has elapsed — which, because
//! it is downstream of a cooldown-gated `trigger()`, happens at most a few times per cooldown
//! period, never once per packet.
//!
//! ## Bound strategy (two independent ceilings, mirroring this crate's other trackers)
//! 1. **Per-source ring bound** — age (`window_secs`), byte count (`per_source_max_bytes`), AND
//!    frame count (`per_source_max_frames`) — oldest frame evicted first once any bound is
//!    exceeded (see `observe`).
//! 2. **Global byte ceiling** (`global_max_bytes`, across every ring combined) — when exceeded,
//!    the OLDEST-INSERTED SOURCE's entire ring is evicted (never a fine-grained cross-source
//!    time-merge) — the SAME FIFO-oldest-entity-evicted discipline `portscan::PortScanTracker`,
//!    `beacon::BeaconTracker`, and every other bounded tracker in this crate already use
//!    (`evict_if_full`). This keeps eviction O(1) amortized instead of requiring a global
//!    min-heap over every ring's front timestamp.
//!
//! ## Alert-emission timing (why this does NOT delay the events stream)
//! `bin/napse-dpi.rs`'s existing `append_line(&events, &alert.to_json(...))` calls are NOT
//! rerouted through this module — the ORIGINAL alert line is appended immediately, at the same
//! instant it always was, so `hookprobe_manifest::scan_responder`'s enforcement latency is
//! unaffected. `trigger()` additionally schedules a capture keyed to the SAME natural fields
//! (rule_id/src_ip/dst_ip/dst_port/ts) the original alert line already carries. Once
//! `poll_finalize()` finishes writing the pcap file, it hands back a SECOND, later JSON line — a
//! copy of the original alert JSON with `pcap_path`/`pcap_sha256`/`pcap_bytes` appended
//! (`inject_pcap_fields`) — which `bin/napse-dpi.rs` appends to the SAME events stream.
//! `hookprobe_evidence::EvidenceGraph::ingest_detection` computes its stable `det_id` purely from
//! `rule_id:src_ip>dst_ip:dst_port@ts` (see that function), so this second line resolves to the
//! IDENTICAL detection node (`INSERT … ON CONFLICT DO NOTHING`, idempotent) and its `pcap_path`
//! becomes readable at that point — no separate daemon, no ID-matching scheme to keep in sync.

use crate::dpi;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};

// ---------------------------------------------------------------------------------------------
// A hand-rolled, minimal libpcap (classic, "savefile") writer — deliberately no external pcap
// crate (the task's own bias: hand-rolled over a new dependency for a format this small/stable).
// Format: https://wiki.wireshark.org/Development/LibpcapFileFormat — a 24-byte global header
// then N (16-byte record header + payload) records. Written little-endian (both amd64 and arm64,
// this workspace's only targets, are LE — matches what tcpdump/Wireshark themselves emit on LE
// hosts and what every reader auto-detects via the magic number's byte order).
// ---------------------------------------------------------------------------------------------

/// Classic (not nanosecond, not pcapng) libpcap magic — read as a little-endian u32 at byte 0 of
/// a valid capture file. `0xa1b2c3d4` is microsecond-resolution timestamps.
pub const PCAP_MAGIC: u32 = 0xa1b2_c3d4;
pub const PCAP_VERSION_MAJOR: u16 = 2;
pub const PCAP_VERSION_MINOR: u16 = 4;
/// `LINKTYPE_ETHERNET` (DLT_EN10MB) — every frame captured on `hp-mirror` is a raw Ethernet frame.
pub const LINKTYPE_ETHERNET: u32 = 1;
/// Per-record capture length cap. `buf` in `bin/napse-dpi.rs`'s recv loop is itself 65536 bytes,
/// so this never truncates a real captured frame — it exists so `write_pcap_bytes` stays a valid,
/// bounded pcap file even if fed a pathological oversized "frame" from a test/fuzzer.
const SNAPLEN: u32 = 65535;

/// Render `frames` (wall-clock seconds, raw Ethernet bytes) as a complete, valid classic-format
/// libpcap byte stream: one global header, then one record per frame in the given order. Pure —
/// no I/O; the caller decides where these bytes land (`poll_finalize` writes them to
/// `/var/lib/hookprobe/pcap/`). An empty `frames` slice still yields a valid (header-only, zero
/// records) pcap file — a real, honest artifact for "the trigger fired but the ring was empty",
/// never a corrupt/partial one.
pub fn write_pcap_bytes(frames: &[(f64, Vec<u8>)]) -> Vec<u8> {
    let body_len: usize = frames.iter().map(|(_, f)| 16 + f.len().min(SNAPLEN as usize)).sum();
    let mut out = Vec::with_capacity(24 + body_len);
    out.extend_from_slice(&PCAP_MAGIC.to_le_bytes());
    out.extend_from_slice(&PCAP_VERSION_MAJOR.to_le_bytes());
    out.extend_from_slice(&PCAP_VERSION_MINOR.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes()); // thiszone — always UTC, 0 offset
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs — unused by every real reader, 0 is conventional
    out.extend_from_slice(&SNAPLEN.to_le_bytes());
    out.extend_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());
    for (ts, data) in frames {
        let ts = ts.max(0.0);
        let mut ts_sec = ts.trunc() as u32;
        // clamp the microseconds field to a valid [0, 999_999]: fract()*1e6 rounds to 1_000_000 when
        // fract() >= 0.9999995, which is out-of-range for classic pcap — carry it into the second.
        let mut ts_usec = (ts.fract() * 1_000_000.0).round() as u32;
        if ts_usec >= 1_000_000 {
            ts_usec = 0;
            ts_sec = ts_sec.saturating_add(1);
        }
        let incl_len = data.len().min(SNAPLEN as usize);
        let orig_len = data.len() as u32;
        out.extend_from_slice(&ts_sec.to_le_bytes());
        out.extend_from_slice(&ts_usec.to_le_bytes());
        out.extend_from_slice(&(incl_len as u32).to_le_bytes());
        out.extend_from_slice(&orig_len.to_le_bytes());
        out.extend_from_slice(&data[..incl_len]);
    }
    out
}

/// Best-effort per-frame capture-ring key: the frame's own IPv4 source address when it carries
/// one (matches every network-layer alert's `src_ip` — `portscan`/`beacon`/`lateral` all key on
/// exactly this), else its Ethernet source MAC formatted as lowercase hex-colon (matches every
/// L1/L2 alert's `src_mac` — `l2guard::L2Alert`). `None` only for a frame too short to carry even
/// a bare Ethernet header (already rejected upstream by `dpi::eth_addrs`/malformed-frame checks).
pub fn capture_key(frame: &[u8]) -> Option<String> {
    if let Some((ethertype, off)) = dpi::eth_type_and_offset(frame) {
        if ethertype == 0x0800 && frame.len() >= off + 20 {
            let ip = &frame[off..off + 20];
            let version = ip[0] >> 4;
            if version == 4 {
                return Some(format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]));
            }
        }
    }
    dpi::eth_addrs(frame).map(|(_, src)| mac_hex(src))
}

fn mac_hex(m: [u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
}

/// Turn `mac` bytes (as `capture_key` would render them) into a filesystem-safe fragment for a
/// pcap filename — colons and dots become `-`.
fn safe_key_fragment(key: &str) -> String {
    key.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect()
}

/// Insert `"pcap_path":"…","pcap_sha256":"…","pcap_bytes":N,"pcap_first_ts":F,"pcap_last_ts":L`
/// into an already-rendered single-line alert JSON object, right before its closing `}` — every
/// `to_json()` in this crate (`portscan`/`beacon`/`lateral`/`l2guard`) renders exactly one
/// top-level `{...}` object with no trailing whitespace, so `rfind('}')` is a safe, simple splice
/// point. `first_ts`/`last_ts` are the earliest/latest FRAME timestamp actually captured — may be
/// EARLIER than the alert's own `ts` (the pre-trigger ring captures history before the trigger
/// fired). Falls back to returning `line` unchanged (never panics/corrupts) if `line` doesn't end
/// in `}` — defensive, should never trigger against this crate's own alert renderers.
#[allow(clippy::too_many_arguments)]
pub fn inject_pcap_fields(
    line: &str,
    path: &str,
    sha256: &str,
    bytes: u64,
    first_ts: f64,
    last_ts: f64,
) -> String {
    match line.rfind('}') {
        Some(idx) => {
            let mut out = String::with_capacity(line.len() + 128);
            out.push_str(&line[..idx]);
            out.push_str(&format!(
                r#","pcap_path":"{}","pcap_sha256":"{}","pcap_bytes":{},"pcap_first_ts":{:.3},"pcap_last_ts":{:.3}"#,
                jesc(path), sha256, bytes, first_ts, last_ts
            ));
            out.push_str(&line[idx..]);
            out
        }
        None => line.to_string(),
    }
}

fn jesc(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).map(|c| if c == '"' || c == '\\' { '_' } else { c }).collect()
}

/// Tunable knobs — mirrors the `env_num`/`env_or` discipline `bin/napse-dpi.rs` already applies to
/// every other detector's config (a typo'd env var degrades to the documented default).
#[derive(Debug, Clone, Copy)]
pub struct CaptureConfig {
    pub enabled: bool,
    /// BOTH the per-source ring's pre-trigger lookback window AND the post-trigger tail duration
    /// scheduled by `trigger()` — a detection's total captured span is bounded by roughly
    /// `2 * window_secs`.
    pub window_secs: f64,
    pub per_source_max_bytes: usize,
    pub per_source_max_frames: usize,
    /// Ceiling on bytes held across EVERY per-source ring combined (does not count bytes already
    /// handed off to a `PendingCapture` — those are bounded separately by `max_pending`, and are
    /// finalized to disk, not held indefinitely).
    pub global_max_bytes: usize,
    pub max_sources: usize,
    /// Bound on concurrently in-flight (triggered, not yet finalized) captures — protects memory
    /// against a burst of many distinct sources tripping detectors within the same `window_secs`.
    pub max_pending: usize,
    /// WRITER-side on-disk ceiling for the pcap directory (bytes). Enforced at every `finalize_one`
    /// BEFORE writing, independent of the timer-driven `hookprobe-evidence --prune` — so a burst of
    /// triggers from many spoofed sources cannot fill the partition in the gap BETWEEN prune runs
    /// (audit HIGH: writer must self-limit, not rely on eventual cleanup). Matches ADR 0003's 8 GB
    /// pcap tier: the writer refuses to exceed the same bound the prune reclaims down to.
    pub dir_cap_bytes: u64,
}

pub const DEFAULT_CAPTURE_ENABLED: bool = true;
pub const DEFAULT_CAPTURE_WINDOW_SECS: f64 = 10.0;
/// Default in-memory (per napse-dpi PROCESS) global ring ceiling — small and deliberately far
/// below ADR 0003's 8 GB ON-DISK pcap-tier cap (that's `PCAP_DIR_CAP_BYTES` in
/// `crates/hookprobe-evidence`, a completely different, much larger, on-disk-directory bound; see
/// that constant's doc for why the two are not the same number).
pub const DEFAULT_CAPTURE_CAP_MB: usize = 16;
pub const DEFAULT_CAPTURE_PER_SOURCE_MAX_BYTES: usize = 262_144; // 256 KiB
pub const DEFAULT_CAPTURE_PER_SOURCE_MAX_FRAMES: usize = 2000;
pub const DEFAULT_CAPTURE_MAX_SOURCES: usize = 256;
pub const DEFAULT_CAPTURE_MAX_PENDING: usize = 16;
/// Writer-side on-disk pcap-dir ceiling (8 GiB — ADR 0003's pcap tier). The writer refuses to add a
/// pcap once the directory is at/over this, independent of the prune timer.
pub const DEFAULT_CAPTURE_DIR_CAP_BYTES: u64 = 8 * 1024 * 1024 * 1024;

impl Default for CaptureConfig {
    fn default() -> Self {
        CaptureConfig {
            enabled: DEFAULT_CAPTURE_ENABLED,
            window_secs: DEFAULT_CAPTURE_WINDOW_SECS,
            per_source_max_bytes: DEFAULT_CAPTURE_PER_SOURCE_MAX_BYTES,
            per_source_max_frames: DEFAULT_CAPTURE_PER_SOURCE_MAX_FRAMES,
            global_max_bytes: DEFAULT_CAPTURE_CAP_MB * 1024 * 1024,
            max_sources: DEFAULT_CAPTURE_MAX_SOURCES,
            max_pending: DEFAULT_CAPTURE_MAX_PENDING,
            dir_cap_bytes: DEFAULT_CAPTURE_DIR_CAP_BYTES,
        }
    }
}

struct SourceRing {
    frames: VecDeque<(f64, Vec<u8>)>,
    bytes: usize,
}

struct PendingCapture {
    key: String,
    path: String,
    deadline: f64,
    frames: Vec<(f64, Vec<u8>)>,
    /// Running byte total of `frames` — used to bound the post-trigger tail so an attacker who
    /// trips a detector then floods the SAME source cannot grow this capture without limit (audit
    /// CRITICAL). Bounds are `per_source_max_bytes`/`per_source_max_frames`, same as a `SourceRing`.
    bytes: usize,
    per_source_max_bytes: usize,
    per_source_max_frames: usize,
    /// Writer-side dir ceiling copied from cfg at trigger time (finalize_one is a free fn).
    dir_cap_bytes: u64,
    /// The ORIGINAL alert JSON line, captured verbatim at `trigger()` time — `poll_finalize`
    /// splices the finished capture's path/sha256/bytes into a COPY of this and hands it back for
    /// the caller to append as a second events-stream line (see module doc's "Alert-emission
    /// timing" section for why the original line is never delayed).
    alert_json: String,
}

/// A fully-written pcap artifact, ready to fold into a follow-up events-stream line.
#[derive(Debug, Clone)]
pub struct FinalizedCapture {
    pub json_line: String,
}

/// Bounded, per-source rolling frame capture — see the module doc for the full design rationale.
pub struct FrameCapture {
    cfg: CaptureConfig,
    dir: String,
    rings: HashMap<String, SourceRing>,
    /// Insertion-order FIFO of ring keys — global-ceiling and max-sources eviction both pop from
    /// the front (oldest-inserted-source-first), the same discipline `portscan::PortScanTracker`
    /// etc. already use.
    order: VecDeque<String>,
    total_bytes: usize,
    pending: Vec<PendingCapture>,
    seq: u64,
}

impl FrameCapture {
    pub fn new(cfg: CaptureConfig, dir: impl Into<String>) -> Self {
        FrameCapture {
            cfg,
            dir: dir.into(),
            rings: HashMap::new(),
            order: VecDeque::new(),
            total_bytes: 0,
            pending: Vec::new(),
            seq: 0,
        }
    }

    pub fn enabled(&self) -> bool {
        self.cfg.enabled
    }

    /// Record one captured frame. Called on EVERY frame in the hot recv loop — see module doc's
    /// cost-discipline section for why this is safe to do unconditionally (no I/O, bounded work).
    /// `key` is normally `capture_key(frame)`'s result; a `None` key (unparseable frame) is simply
    /// not recorded — the malformed-frame detector already independently flags the frame itself.
    pub fn observe(&mut self, now: f64, key: &str, frame: &[u8]) {
        if !self.cfg.enabled {
            return;
        }
        // Feed any in-flight post-trigger tail whose source matches — bounded by that pending
        // capture's own deadline (checked here so a slow-to-finalize tail can't grow unboundedly
        // between `poll_finalize` calls).
        for p in self.pending.iter_mut() {
            if p.key == key && now < p.deadline {
                // AUDIT CRITICAL fix: bound the post-trigger tail with the SAME per-source caps a
                // SourceRing uses. Without this, an attacker who trips a detector then floods the
                // same src IP/MAC for `window_secs` grows this Vec unboundedly (GBs) → OOM-kills the
                // single-process sensor → the whole SOC datapath fails open. Stop-append when full
                // (keep the first frames after the trigger, which is the forensically useful part);
                // the tail is now ≤ per_source_max_bytes, so `finalize_one`'s write is always small.
                if p.frames.len() < p.per_source_max_frames
                    && p.bytes.saturating_add(frame.len()) <= p.per_source_max_bytes
                {
                    p.bytes += frame.len();
                    p.frames.push((now, frame.to_vec()));
                }
            }
        }

        if !self.rings.contains_key(key) {
            self.evict_source_if_full();
            self.order.push_back(key.to_string());
            self.rings.insert(key.to_string(), SourceRing { frames: VecDeque::new(), bytes: 0 });
        }
        let ring = self.rings.get_mut(key).expect("just inserted above");
        ring.frames.push_back((now, frame.to_vec()));
        ring.bytes += frame.len();
        self.total_bytes += frame.len();

        // Per-source bound: age window, byte cap, AND frame-count cap — oldest evicted first.
        let cutoff = now - self.cfg.window_secs;
        while let Some(&(ts, _)) = ring.frames.front() {
            let over_age = ts < cutoff;
            let over_bytes = ring.bytes > self.cfg.per_source_max_bytes;
            let over_count = ring.frames.len() > self.cfg.per_source_max_frames;
            if !(over_age || over_bytes || over_count) {
                break;
            }
            if let Some((_, old)) = ring.frames.pop_front() {
                ring.bytes -= old.len();
                self.total_bytes -= old.len();
            }
        }

        // Global ceiling: evict the OLDEST-INSERTED SOURCE'S ENTIRE ring — see module doc's "Bound
        // strategy" for why this is deliberately coarse (O(1) amortized) rather than a fine-grained
        // global time-merge across sources.
        while self.total_bytes > self.cfg.global_max_bytes {
            match self.order.pop_front() {
                Some(old_key) => {
                    if let Some(r) = self.rings.remove(&old_key) {
                        self.total_bytes -= r.bytes;
                    }
                }
                None => break,
            }
        }
    }

    fn evict_source_if_full(&mut self) {
        let cap = self.cfg.max_sources.max(1);
        while self.rings.len() >= cap {
            match self.order.pop_front() {
                Some(old) => {
                    if let Some(r) = self.rings.remove(&old) {
                        self.total_bytes -= r.bytes;
                    }
                }
                None => break,
            }
        }
    }

    /// Schedule a capture for `key` (the same `src_ip`/`src_mac` string the firing alert itself
    /// carries): snapshots whatever history `key`'s ring already holds (possibly empty — a source
    /// with no prior traffic still yields a valid, honest, zero-pre-trigger-frame capture) and
    /// arms a bounded post-trigger tail fed by subsequent `observe()` calls for the same `key`
    /// until `now + window_secs`. `alert_json` is the ALREADY-rendered, ALREADY-appended alert
    /// line (see module doc) — stored so `poll_finalize` can hand back an annotated copy once the
    /// file is written; the original line's own emission is never delayed by this call.
    /// No-op (does not even allocate a path) when capture is disabled.
    pub fn trigger(&mut self, now: f64, key: &str, rule_id: u32, alert_json: &str) {
        if !self.cfg.enabled {
            return;
        }
        self.seq += 1;
        let path = format!(
            "{}/{}-{}-{}-{}.pcap",
            self.dir,
            rule_id,
            (now * 1000.0).max(0.0) as u64,
            safe_key_fragment(key),
            self.seq
        );
        let pre: Vec<(f64, Vec<u8>)> =
            self.rings.get(key).map(|r| r.frames.iter().cloned().collect()).unwrap_or_default();
        // The pre-trigger seed is already bounded (it comes from a SourceRing capped at
        // per_source_max_bytes); track its byte total so the post-trigger tail bound in observe()
        // continues from the real starting size, not zero.
        let pre_bytes: usize = pre.iter().map(|(_, d)| d.len()).sum();
        // Bounded concurrent pending — drop-and-finalize-early the oldest one (write whatever it
        // has captured so far) rather than growing unbounded under a burst of many distinct
        // triggering sources within one window.
        if self.pending.len() >= self.cfg.max_pending {
            let evicted = self.pending.remove(0);
            let _ = finalize_one(evicted); // best-effort: never just silently discard a scheduled capture
        }
        self.pending.push(PendingCapture {
            key: key.to_string(),
            path,
            deadline: now + self.cfg.window_secs,
            frames: pre,
            bytes: pre_bytes,
            // tail is allowed to grow to per_source_max on TOP of the seed, so a full capture is at
            // most ~2× per_source_max_bytes (~512 KiB default) — the pre window plus the post tail.
            per_source_max_bytes: self.cfg.per_source_max_bytes.saturating_mul(2),
            per_source_max_frames: self.cfg.per_source_max_frames.saturating_mul(2),
            dir_cap_bytes: self.cfg.dir_cap_bytes,
            alert_json: alert_json.to_string(),
        });
    }

    /// Write every pending capture whose window has elapsed to a real libpcap file on disk, and
    /// return each one's annotated follow-up JSON line for the caller to append to the events
    /// stream. The ONLY place this module performs file I/O (see module doc's cost discipline).
    pub fn poll_finalize(&mut self, now: f64) -> Vec<FinalizedCapture> {
        if self.pending.is_empty() {
            return Vec::new();
        }
        let mut ready = Vec::new();
        let mut still_pending = Vec::with_capacity(self.pending.len());
        for p in self.pending.drain(..) {
            if now >= p.deadline {
                ready.push(p);
            } else {
                still_pending.push(p);
            }
        }
        self.pending = still_pending;
        ready.into_iter().filter_map(finalize_one).collect()
    }
}

fn finalize_one(p: PendingCapture) -> Option<FinalizedCapture> {
    let bytes = write_pcap_bytes(&p.frames);
    // AUDIT HIGH fix — writer-side on-disk guard: before adding a pcap, refuse if the directory is
    // already at/over its cap. Without this, a burst of triggers from many spoofed source IPs (each
    // its own capture_key + file) fills the partition in the window BETWEEN prune-timer runs. The
    // detection itself was already emitted unconditionally, so dropping the pcap here loses only the
    // (bounded) evidence, never the alert — and prune will reclaim space on its next pass.
    if let Some(parent) = std::path::Path::new(&p.path).parent() {
        let dir_bytes: u64 = std::fs::read_dir(parent)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter_map(|e| e.metadata().ok())
                    .filter(|m| m.is_file())
                    .map(|m| m.len())
                    .sum()
            })
            .unwrap_or(0);
        if dir_bytes.saturating_add(bytes.len() as u64) > p.dir_cap_bytes {
            return None;
        }
    }
    if std::fs::write(&p.path, &bytes).is_err() {
        // Best-effort: never lose the underlying detection over a pcap write failure (a full
        // disk / missing directory / permissions issue) — the ORIGINAL alert line was already
        // emitted unconditionally by the caller, so the detection itself is never lost, only its
        // pcap evidence, which is honestly just absent rather than fabricated.
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let sha256 = format!("{:x}", hasher.finalize());
    let first_ts = p.frames.first().map(|(t, _)| *t).unwrap_or(0.0);
    let last_ts = p.frames.last().map(|(t, _)| *t).unwrap_or(0.0);
    let json_line = inject_pcap_fields(&p.alert_json, &p.path, &sha256, bytes.len() as u64, first_ts, last_ts);
    Some(FinalizedCapture { json_line })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_ipv4(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[0..6].copy_from_slice(&[0xaa; 6]);
        f[6..12].copy_from_slice(&[0xbb; 6]);
        f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[9] = 6; // tcp
        ip[12..16].copy_from_slice(&src);
        ip[16..20].copy_from_slice(&dst);
        f.extend_from_slice(&ip);
        f.extend_from_slice(&[0u8; 20]); // bare tcp header, no payload
        f
    }

    // ---- pcap file-format validity ------------------------------------------------------------

    #[test]
    fn write_pcap_bytes_produces_a_valid_global_header() {
        let bytes = write_pcap_bytes(&[]);
        assert_eq!(bytes.len(), 24, "an empty capture is still a valid header-only pcap file");
        let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        assert_eq!(magic, PCAP_MAGIC);
        let vmaj = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
        let vmin = u16::from_le_bytes(bytes[6..8].try_into().unwrap());
        assert_eq!((vmaj, vmin), (PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR));
        let network = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
        assert_eq!(network, LINKTYPE_ETHERNET);
    }

    #[test]
    fn write_pcap_bytes_round_trips_one_record() {
        let payload = vec![0x11u8, 0x22, 0x33, 0x44, 0x55];
        let bytes = write_pcap_bytes(&[(1_782_900_000.5, payload.clone())]);
        assert_eq!(bytes.len(), 24 + 16 + payload.len());
        let rec = &bytes[24..];
        let ts_sec = u32::from_le_bytes(rec[0..4].try_into().unwrap());
        let ts_usec = u32::from_le_bytes(rec[4..8].try_into().unwrap());
        let incl_len = u32::from_le_bytes(rec[8..12].try_into().unwrap());
        let orig_len = u32::from_le_bytes(rec[12..16].try_into().unwrap());
        assert_eq!(ts_sec, 1_782_900_000);
        assert_eq!(ts_usec, 500_000);
        assert_eq!(incl_len, payload.len() as u32);
        assert_eq!(orig_len, payload.len() as u32);
        assert_eq!(&rec[16..16 + payload.len()], payload.as_slice());
    }

    #[test]
    fn write_pcap_bytes_handles_multiple_records_in_order() {
        let frames = vec![
            (100.0, vec![1u8, 2, 3]),
            (100.1, vec![4u8, 5]),
            (100.2, vec![6u8; 10]),
        ];
        let bytes = write_pcap_bytes(&frames);
        // header + 3 records, each 16-byte header + payload
        let expected_len = 24 + (16 + 3) + (16 + 2) + (16 + 10);
        assert_eq!(bytes.len(), expected_len);
        // spot-check the SECOND record's payload lands at the right offset
        let off = 24 + (16 + 3) + 16;
        assert_eq!(&bytes[off..off + 2], &[4u8, 5]);
    }

    #[test]
    fn write_pcap_bytes_truncates_an_oversized_record_to_snaplen_but_reports_true_orig_len() {
        let huge = vec![0xffu8; SNAPLEN as usize + 500];
        let bytes = write_pcap_bytes(&[(1.0, huge.clone())]);
        let rec = &bytes[24..];
        let incl_len = u32::from_le_bytes(rec[8..12].try_into().unwrap());
        let orig_len = u32::from_le_bytes(rec[12..16].try_into().unwrap());
        assert_eq!(incl_len, SNAPLEN);
        assert_eq!(orig_len, huge.len() as u32);
        assert_eq!(bytes.len(), 24 + 16 + SNAPLEN as usize);
    }

    // ---- capture_key ----------------------------------------------------------------------------

    #[test]
    fn capture_key_prefers_ipv4_src_when_present() {
        let f = frame_ipv4([10, 0, 0, 5], [10, 0, 0, 1]);
        assert_eq!(capture_key(&f), Some("10.0.0.5".to_string()));
    }

    #[test]
    fn capture_key_falls_back_to_src_mac_for_a_non_ipv4_frame() {
        let mut f = vec![0u8; 14];
        f[0..6].copy_from_slice(&[0xaa; 6]);
        f[6..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        f[12..14].copy_from_slice(&0x0806u16.to_be_bytes()); // ARP, not IPv4
        assert_eq!(capture_key(&f), Some("11:22:33:44:55:66".to_string()));
    }

    #[test]
    fn capture_key_none_on_a_too_short_frame() {
        assert_eq!(capture_key(&[0u8; 4]), None);
    }

    // ---- inject_pcap_fields -----------------------------------------------------------------------

    #[test]
    fn inject_pcap_fields_splices_before_the_closing_brace_and_stays_valid_json() {
        let line = r#"{"ts":1.0,"rule_id":1000003,"src_ip":"10.0.0.5"}"#;
        let out = inject_pcap_fields(line, "/var/lib/hookprobe/pcap/x.pcap", "abc123", 4096, 0.5, 1.5);
        let v: serde_json::Value = serde_json::from_str(&out).expect("must stay valid json");
        assert_eq!(v["pcap_path"], "/var/lib/hookprobe/pcap/x.pcap");
        assert_eq!(v["pcap_sha256"], "abc123");
        assert_eq!(v["pcap_bytes"], 4096);
        assert_eq!(v["pcap_first_ts"], 0.5);
        assert_eq!(v["pcap_last_ts"], 1.5);
        assert_eq!(v["rule_id"], 1000003, "original fields must survive untouched");
    }

    #[test]
    fn inject_pcap_fields_escapes_a_hostile_path() {
        let line = r#"{"rule_id":1}"#;
        let out = inject_pcap_fields(line, "evil\"; DROP TABLE\\", "sha", 1, 0.0, 0.0);
        let v: serde_json::Value = serde_json::from_str(&out).expect("must stay valid json even with hostile input");
        assert!(v["pcap_path"].as_str().unwrap().contains("DROP TABLE"));
    }

    // ---- FrameCapture ring bounds -----------------------------------------------------------------

    fn small_cfg() -> CaptureConfig {
        CaptureConfig {
            enabled: true,
            window_secs: 5.0,
            per_source_max_bytes: 100,
            per_source_max_frames: 4,
            global_max_bytes: 1000,
            max_sources: 3,
            max_pending: 4,
            dir_cap_bytes: 1_000_000,
        }
    }

    #[test]
    fn ring_never_exceeds_per_source_byte_cap() {
        let mut c = FrameCapture::new(small_cfg(), "/tmp/hp-test-pcap");
        for i in 0..50u8 {
            c.observe(100.0 + i as f64 * 0.01, "10.0.0.1", &[0u8; 20]);
        }
        let ring = c.rings.get("10.0.0.1").expect("source tracked");
        assert!(ring.bytes <= 100, "per-source byte cap must hold, got {}", ring.bytes);
    }

    #[test]
    fn ring_never_exceeds_per_source_frame_count_cap() {
        let mut c = FrameCapture::new(small_cfg(), "/tmp/hp-test-pcap");
        for i in 0..50u8 {
            c.observe(100.0 + i as f64 * 0.01, "10.0.0.2", &[0u8; 1]);
        }
        let ring = c.rings.get("10.0.0.2").expect("source tracked");
        assert!(ring.frames.len() <= 4, "per-source frame-count cap must hold, got {}", ring.frames.len());
    }

    #[test]
    fn ring_drops_oldest_frames_first() {
        let mut c = FrameCapture::new(small_cfg(), "/tmp/hp-test-pcap");
        for i in 0..10u8 {
            c.observe(100.0 + i as f64, "10.0.0.3", &[i]); // 1-byte frames, tag = index
        }
        let ring = c.rings.get("10.0.0.3").unwrap();
        let kept: Vec<u8> = ring.frames.iter().map(|(_, f)| f[0]).collect();
        // frame-count cap is 4 -> only the 4 MOST RECENT (6,7,8,9) survive
        assert_eq!(kept, vec![6, 7, 8, 9]);
    }

    #[test]
    fn global_ceiling_evicts_the_oldest_inserted_source_entirely() {
        let cfg = CaptureConfig {
            enabled: true,
            window_secs: 1000.0,
            per_source_max_bytes: 10_000,
            per_source_max_frames: 10_000,
            global_max_bytes: 250, // small on purpose
            max_sources: 100,
            max_pending: 4,
            dir_cap_bytes: 1_000_000,
        };
        let mut c = FrameCapture::new(cfg, "/tmp/hp-test-pcap");
        c.observe(100.0, "src-a", &[0u8; 100]);
        c.observe(101.0, "src-b", &[0u8; 100]);
        assert!(c.rings.contains_key("src-a"));
        // pushes total past 250 -> src-a (oldest inserted) must be evicted wholesale
        c.observe(102.0, "src-c", &[0u8; 100]);
        assert!(!c.rings.contains_key("src-a"), "oldest-inserted source must be evicted under the global ceiling");
        assert!(c.rings.contains_key("src-b"));
        assert!(c.rings.contains_key("src-c"));
        assert!(c.total_bytes <= 250);
    }

    #[test]
    fn max_sources_bounds_ring_count() {
        let mut c = FrameCapture::new(small_cfg(), "/tmp/hp-test-pcap"); // max_sources=3
        for i in 0..10u8 {
            c.observe(100.0 + i as f64, &format!("10.1.0.{i}"), &[1]);
        }
        assert!(c.rings.len() <= 3, "tracked sources must stay bounded, got {}", c.rings.len());
    }

    #[test]
    fn disabled_capture_never_tracks_anything() {
        let mut cfg = small_cfg();
        cfg.enabled = false;
        let mut c = FrameCapture::new(cfg, "/tmp/hp-test-pcap");
        c.observe(100.0, "10.0.0.9", &[0u8; 50]);
        assert!(c.rings.is_empty());
        c.trigger(100.0, "10.0.0.9", 1_000_003, r#"{"rule_id":1000003}"#);
        assert!(c.pending.is_empty());
    }

    // ---- trigger / poll_finalize end-to-end (real file I/O in a throwaway temp dir) --------------

    fn temp_dir() -> String {
        let d = std::env::temp_dir().join(format!("hp-capture-test-{}-{}", std::process::id(), rand_suffix()));
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().to_string()
    }
    fn rand_suffix() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64
    }

    #[test]
    fn trigger_then_poll_finalize_writes_a_real_pcap_and_annotates_the_alert_json() {
        let dir = temp_dir();
        let mut cfg = small_cfg();
        cfg.window_secs = 1.0;
        let mut c = FrameCapture::new(cfg, dir.clone());
        // pre-trigger history
        c.observe(100.0, "10.5.5.5", &[0xAAu8; 30]);
        c.observe(100.1, "10.5.5.5", &[0xBBu8; 30]);
        let alert = r#"{"ts":100.1,"rule_id":1000003,"src_ip":"10.5.5.5","rule_msg":"NAPSE Port Scan Detected"}"#;
        c.trigger(100.1, "10.5.5.5", 1_000_003, alert);
        // post-trigger tail frame arrives before the deadline
        c.observe(100.5, "10.5.5.5", &[0xCCu8; 30]);
        // not yet due
        assert!(c.poll_finalize(100.5).is_empty());
        // deadline passed -> finalize
        let out = c.poll_finalize(101.2);
        assert_eq!(out.len(), 1);
        let v: serde_json::Value = serde_json::from_str(&out[0].json_line).expect("valid json");
        assert_eq!(v["rule_id"], 1000003);
        assert_eq!(v["src_ip"], "10.5.5.5");
        let path = v["pcap_path"].as_str().expect("pcap_path present");
        assert!(std::path::Path::new(path).exists(), "pcap file must actually exist on disk");
        let bytes_on_disk = std::fs::read(path).unwrap();
        assert_eq!(u32::from_le_bytes(bytes_on_disk[0..4].try_into().unwrap()), PCAP_MAGIC);
        // 2 pre-trigger + 1 post-trigger frame captured
        assert_eq!(bytes_on_disk.len(), 24 + 3 * (16 + 30));
        assert_eq!(v["pcap_bytes"], bytes_on_disk.len() as i64);
        let sha256 = v["pcap_sha256"].as_str().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&bytes_on_disk);
        assert_eq!(sha256, format!("{:x}", hasher.finalize()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn max_pending_bounds_concurrent_in_flight_captures() {
        let dir = temp_dir();
        let cfg = CaptureConfig { max_pending: 2, window_secs: 1000.0, ..small_cfg() };
        let mut c = FrameCapture::new(cfg, dir.clone());
        for i in 0..5u8 {
            let key = format!("10.9.0.{i}");
            c.trigger(100.0 + i as f64, &key, 1, "{}");
        }
        assert!(c.pending.len() <= 2, "pending captures must stay bounded, got {}", c.pending.len());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn post_trigger_tail_is_bounded_under_a_same_source_flood_audit_critical() {
        // AUDIT CRITICAL regression: an attacker trips a detector, then floods the SAME source IP/MAC
        // for the whole window. Before the fix, every mirrored frame was cloned into the pending
        // capture's tail with NO bound → GBs of RAM → OOM-kill of the single-process sensor (SOC goes
        // dark, datapath fails open). The tail must stay bounded regardless of flood volume.
        let dir = temp_dir();
        let cfg = CaptureConfig {
            window_secs: 1000.0,
            per_source_max_bytes: 100,
            per_source_max_frames: 4,
            ..small_cfg()
        };
        let mut c = FrameCapture::new(cfg, dir.clone());
        c.trigger(10.0, "10.7.0.1", 1, "{}");
        for i in 0..100_000u32 {
            c.observe(11.0 + (i as f64) * 1e-6, "10.7.0.1", &[0u8; 64]);
        }
        let p = &c.pending[0];
        // bound = 2× the per-source caps (pre-trigger window + post-trigger tail), NOT 100_000.
        assert!(p.frames.len() <= 8, "post-trigger tail frame count must stay bounded, got {}", p.frames.len());
        assert!(p.bytes <= 200, "post-trigger tail byte total must stay bounded, got {}", p.bytes);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
