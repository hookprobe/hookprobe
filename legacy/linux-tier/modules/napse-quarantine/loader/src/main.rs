//! napse-quarantine — Ring-0 line-rate quarantine enforcement (ADR 0009), the fix for the
//! 2026-07-03 live finding: a port scan outran the reactive detect->nft-drop loop. This process
//! attaches a tiny CO-RE TC-bpf program at clsact INGRESS on `wlan0` (the Wi-Fi/LAN scan path —
//! ADR 0005: brcmfmac/mac80211 has no native XDP) and `end0` (the WAN uplink), and mirrors the
//! scan-responder's persisted quarantine state (`/var/lib/hookprobe/scan-quarantine.json`) into
//! the BPF maps that program enforces from. C9: this binary makes NO quarantine decisions of its
//! own — `crates/hookprobe-manifest/src/scan_responder.rs` already decided; this only enforces,
//! at the earliest kernel point a quarantined source's packets can be stopped.
//!
//! Layering vs the existing nft quarantine (both stay — see docs, not a replacement):
//!   - BPF/TC (this binary) is now the PRIMARY, line-rate enforcement layer: it runs at clsact
//!     ingress, immediately after the driver hands off the skb — before routing, before any
//!     netfilter/nftables hook, and with none of the userspace `tail -F` -> `exec nft` round trip
//!     the reactive path needs to converge.
//!   - `nft` (scan-responder.sh, unchanged) stays as defense-in-depth/fallback: if this loader
//!     fails to load/attach on a given boot (fail-open — see bpf.rs's doc comment), the device is
//!     not left with ZERO enforcement, only a slower one, exactly as it is today.
//!
//! HONEST LIMITS (do not paper over):
//!   - This does NOT prevent the FIRST scan's port disclosure — a source must already be
//!     QUARANTINED (by an earlier detection) before this program's maps have anything to match.
//!     A brand-new, never-before-seen scanner's opening probes still land before enforcement
//!     exists. Closing that needs either faster detection (sub-scan latency) or a default-deny
//!     posture for not-yet-classified devices — flagged as a separate, real follow-up in the
//!     module's README, not solved here.
//!   - `end0` (bcmgenet) is only copy-mode XDP; this program uses TC-bpf on it too (uniform code
//!     path, ADR 0005) rather than a faster native-XDP variant — a documented follow-up, not a gap
//!     in THIS finding's fix (the finding was on the Wi-Fi/LAN path, where TC-bpf is the only
//!     option regardless).

use anyhow::{bail, Context, Result};
#[cfg(feature = "bpf")]
use std::time::Duration;

mod state;
#[cfg(feature = "bpf")]
mod bpf;

/// Self-gate (arch F4 fix — the supervisor never starts `managed` sysext units, so this
/// module must decide for itself; mirrors `modules/ovs/config/ovs-bringup`'s bash
/// `granted() { [[ "$(jq ...)" == "granted" ]]; }` pattern in Rust). Reads the signed
/// Platform Manifest and returns whether `cap` is `capabilities.<cap>.state == "granted"`.
/// A missing/unparseable manifest is treated as NOT granted — fail this module's
/// activation closed rather than attaching a TC-bpf program the platform never called
/// for; `nft` quarantine (scan-responder.sh) stays the fallback enforcement layer
/// regardless (see this file's module doc).
fn granted(cap: &str) -> bool {
    let path = std::env::var("MANIFEST").unwrap_or_else(|_| "/var/lib/hookprobe/manifest.json".to_string());
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("napse-quarantine: cannot read manifest {path} ({e}) — treating '{cap}' as not granted");
            return false;
        }
    };
    let m: hookprobe_manifest::Manifest = match serde_json::from_str(&text) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("napse-quarantine: cannot parse manifest {path} ({e}) — treating '{cap}' as not granted");
            return false;
        }
    };
    m.capabilities
        .get(cap)
        .map(|c| c.state == hookprobe_manifest::types::CapabilityState::Granted)
        .unwrap_or(false)
}

// Every field is read by bpf::run/status (feature = "bpf"); without that feature only
// `state_file` is used (the dry-parse path in `main()` below) — allow the rest to go unread
// rather than feature-gating the struct itself, which would fork the CLI-parsing code in two.
//
// 2026-07-05 threat-model fix (HIGH #3): the generic `--iface` list is replaced by NAMED
// `lan_iface`/`wan_iface` — enforcement now needs to know WHICH plane each attached interface is
// (to resolve the right ifindex for each quarantine entry — see `state::PlaneIfindexes`), the
// exact same LAN/WAN split `scan_responder::IfaceConfig` already uses. Defaults match it too
// (`wlan0`/`end0`, the live Pi 4 topology).
#[cfg_attr(not(feature = "bpf"), allow(dead_code))]
struct Args {
    obj: String,
    lan_iface: String,
    wan_iface: String,
    state_file: String,
    pin_dir: String,
    poll_ms: u64,
    status: bool,
}

/// Does this interface exist right now? (`/sys/class/net/<name>` — the same fact
/// `bpf.rs::sysfs_ifindex` resolves from, checked here first so a fallback decision can be logged
/// BEFORE the attach attempt, not discovered only from its error.)
#[cfg_attr(not(feature = "bpf"), allow(dead_code))]
fn iface_present(name: &str) -> bool {
    std::path::Path::new("/sys/class/net").join(name).exists()
}

/// 2026-07 cross-platform fix: the CONFIGURED interface (from `ifaces.env`/CLI/env — see
/// `aegis::reconcile_network`'s `ifaces.env` artifact, the real source of truth) is normally
/// already correct. This is defense-in-depth for the case it ISN'T (e.g. a device that never ran
/// `hookprobe-network-reconcile.service`, so `ifaces.env` doesn't exist yet, and the unit's own
/// last-resort `Environment=` default — historically the Pi's `wlan0`/`end0` — doesn't match this
/// platform): if `configured` isn't present in sysfs, and the manifest-derived `fallback` IS, use
/// it instead. Pure/testable via the injected `exists` predicate; the real caller passes
/// `iface_present`. Never panics, never fails — if neither resolves, `configured` is kept as-is
/// and `bpf::run`'s own per-iface attach loop logs+skips it without stopping the other interface
/// (fail-open, unchanged).
#[cfg_attr(not(feature = "bpf"), allow(dead_code))]
fn resolve_iface(plane: &str, configured: &str, fallback: Option<&str>, exists: impl Fn(&str) -> bool) -> String {
    if exists(configured) {
        return configured.to_string();
    }
    if let Some(fb) = fallback {
        if fb != configured && exists(fb) {
            eprintln!(
                "napse-quarantine: configured {plane} iface '{configured}' not present — \
                 falling back to the manifest-classified '{fb}'"
            );
            return fb.to_string();
        }
    }
    eprintln!(
        "napse-quarantine: configured {plane} iface '{configured}' not present and no \
         manifest-classified fallback resolved — attach will be attempted anyway (fail-open)"
    );
    configured.to_string()
}

/// Best-effort read of the signed manifest for [`resolve_iface`]'s fallback candidates. Any
/// read/parse error is treated as "no fallback available" (fail-open, same posture as `granted()`
/// above) — this is a LAST-RESORT convenience, not a second copy of the reconciler's fabric plan.
#[cfg_attr(not(feature = "bpf"), allow(dead_code))]
fn manifest_fallback_ifaces() -> (Option<String>, Option<String>) {
    let path = std::env::var("MANIFEST").unwrap_or_else(|_| "/var/lib/hookprobe/manifest.json".to_string());
    match std::fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str::<hookprobe_manifest::Manifest>(&t).ok()) {
        Some(m) => hookprobe_manifest::scan_responder::manifest_iface_fallback(&m),
        None => (None, None),
    }
}

fn parse_args() -> Result<Args> {
    let mut obj = std::env::var("NAPSE_QUARANTINE_OBJ").unwrap_or_else(|_| "/usr/lib/hookprobe/bpf/quarantine.bpf.o".to_string());
    let mut lan_iface = std::env::var("NAPSE_QUARANTINE_LAN_IFACE")
        .or_else(|_| std::env::var("LAN_IFACE"))
        .unwrap_or_else(|_| "wlan0".to_string());
    let mut wan_iface = std::env::var("NAPSE_QUARANTINE_WAN_IFACE")
        .or_else(|_| std::env::var("WAN_IFACE"))
        .unwrap_or_else(|_| "end0".to_string());
    let mut state_file = std::env::var("QUARANTINE_STATE_FILE").unwrap_or_else(|_| "/var/lib/hookprobe/scan-quarantine.json".to_string());
    let mut pin_dir = std::env::var("NAPSE_QUARANTINE_PIN_DIR").unwrap_or_else(|_| "/sys/fs/bpf/napse-quarantine".to_string());
    let mut poll_ms: u64 = std::env::var("NAPSE_QUARANTINE_POLL_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(500);
    let mut status = false;

    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--obj" => obj = it.next().ok_or_else(|| anyhow::anyhow!("--obj needs a value"))?,
            "--lan-iface" => lan_iface = it.next().ok_or_else(|| anyhow::anyhow!("--lan-iface needs a value"))?,
            "--wan-iface" => wan_iface = it.next().ok_or_else(|| anyhow::anyhow!("--wan-iface needs a value"))?,
            "--state-file" => state_file = it.next().ok_or_else(|| anyhow::anyhow!("--state-file needs a value"))?,
            "--pin-dir" => pin_dir = it.next().ok_or_else(|| anyhow::anyhow!("--pin-dir needs a value"))?,
            "--poll-ms" => poll_ms = it.next().ok_or_else(|| anyhow::anyhow!("--poll-ms needs a value"))?.parse()?,
            "--status" => status = true,
            "--help" | "-h" => {
                println!(
                    "napse-quarantine [--obj PATH] [--lan-iface NAME] [--wan-iface NAME] [--state-file PATH] [--pin-dir PATH] [--poll-ms N] [--status]"
                );
                std::process::exit(0);
            }
            other => bail!("unknown argument: {other}"),
        }
    }
    Ok(Args { obj, lan_iface, wan_iface, state_file, pin_dir, poll_ms, status })
}

/// ADR 0016 Fix C (Finding 2, HIGH) — the testable core of the gate. This loader is the
/// highest-privilege native start path this repo owns end-to-end (`bpf(2)` + `CAP_NET_ADMIN`,
/// Ring-0 TC-bpf) — the artifact-hash-signing gate (Findings 1/3) is wasm-only otherwise, so it
/// never covers this binary or the `.bpf.o` it attaches. Parses `module_yaml_path` (THIS module's
/// own, staged read-only alongside every other module's registry mirror —
/// `gen-staging.sh`'s "uniform registry mirror" convention writes it to
/// `/usr/lib/hookprobe/modules/napse-quarantine/module.yaml`) and recomputes+compares every
/// declared artifact's digest (`role: loader` for this binary, `role: bpf-object` for the
/// `.bpf.o`) against the bytes actually on disk. Unlike the wasm `.cwasm` case, both files here
/// live on the immutable rootfs (no writable-partition AOT cache in play), so a fresh
/// read-and-compare against the shipped, RO/dm-verity-covered-where-`enforced` module.yaml is the
/// right-sized check — no TOCTOU window to close the way `wasm_loader::load_module_gated` had to.
/// Returns the parsed `ModuleDef` on success (so a caller/test can assert on it); kept free of
/// `std::process::exit` so it is exercised directly by unit tests — `verify_own_artifacts` below
/// is the fail-closed process-exiting wrapper the real `main()` calls.
#[cfg_attr(not(feature = "bpf"), allow(dead_code))] // only reachable via the bpf-gated main(); tests exercise it directly regardless of feature.
fn verify_own_artifacts_at(
    module_yaml_path: &std::path::Path,
    events_path: Option<&std::path::Path>,
) -> Result<hookprobe_manifest::module_def::ModuleDef> {
    let text = std::fs::read_to_string(module_yaml_path)
        .with_context(|| format!("ADR 0016: cannot read own module.yaml {module_yaml_path:?}"))?;
    let def: hookprobe_manifest::module_def::ModuleDef =
        serde_yaml::from_str(&text).with_context(|| format!("ADR 0016: cannot parse own module.yaml {module_yaml_path:?}"))?;
    let install_dir = module_yaml_path
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("/"));
    hookprobe_manifest::module_sig::verify_artifact_digests(&def, &install_dir, events_path)
        .context("ADR 0016 artifact-digest check failed")?;
    Ok(def)
}

/// ADR 0016 Fix C (Finding 2, HIGH): this loader is the highest-privilege native start path this
/// repo owns end-to-end (`bpf(2)` + `CAP_NET_ADMIN`, Ring-0 TC-bpf) — the artifact-hash-signing
/// gate (Findings 1/3) is wasm-only otherwise, so it never covers this binary or the `.bpf.o` it
/// attaches. Reads THIS module's own `module.yaml` (staged, read-only, alongside every other
/// module's registry mirror — `gen-staging.sh`'s "uniform registry mirror" convention writes it to
/// `/usr/lib/hookprobe/modules/napse-quarantine/module.yaml`) and recomputes+compares every
/// declared artifact's digest (`role: loader` for this binary, `role: bpf-object` for the `.bpf.o`)
/// against the bytes actually on disk — fail-closed, BEFORE `bpf::run`/`bpf::status` ever calls
/// into libbpf. Unlike the wasm `.cwasm` case, both files here live on the immutable rootfs (no
/// writable-partition AOT cache in play), so a fresh read-and-compare against the shipped,
/// RO/dm-verity-covered-where-`enforced` module.yaml is the right-sized check — no TOCTOU window
/// to close the way `wasm_loader::load_module_gated` had to. Exits the process (fail-closed) on
/// any failure; the pure logic lives in `verify_own_artifacts_at` above for testability.
#[cfg(feature = "bpf")]
fn verify_own_artifacts() {
    let module_yaml = std::env::var("NAPSE_QUARANTINE_MODULE_YAML")
        .unwrap_or_else(|_| "/usr/lib/hookprobe/modules/napse-quarantine/module.yaml".to_string());
    let events = std::env::var("HOOKPROBE_EVENTS").ok().map(std::path::PathBuf::from);
    match verify_own_artifacts_at(std::path::Path::new(&module_yaml), events.as_deref()) {
        Ok(_) => eprintln!(
            "napse-quarantine: ADR 0016 artifact-digest check passed (loader + bpf-object) — proceeding to attach."
        ),
        Err(e) => {
            eprintln!("napse-quarantine: refusing to load/attach — {e:#}");
            std::process::exit(1);
        }
    }
}

#[cfg(feature = "bpf")]
fn main() -> Result<()> {
    let args = parse_args()?;
    if !granted("ddos_mitigation") {
        eprintln!(
            "napse-quarantine: capability 'ddos_mitigation' not granted on this platform \
             (module.yaml requires.capabilities) — nothing to enforce here, exiting cleanly. \
             nft quarantine (scan-responder.sh) remains the enforcement layer on this device."
        );
        return Ok(());
    }
    if args.status {
        return bpf::status(&args.pin_dir);
    }
    // ADR 0016 Fix C: verify the loader binary + the .bpf.o against their pinned digests BEFORE
    // ever calling into libbpf to load/attach either.
    verify_own_artifacts();
    // Cross-platform robustness (defense-in-depth alongside `ifaces.env`): if the configured
    // interface isn't present, try the manifest-classified one before ever calling into libbpf.
    let (wan_fb, lan_fb) = manifest_fallback_ifaces();
    let lan_iface = resolve_iface("LAN", &args.lan_iface, lan_fb.as_deref(), iface_present);
    let wan_iface = resolve_iface("WAN", &args.wan_iface, wan_fb.as_deref(), iface_present);
    bpf::run(&args.obj, &lan_iface, &wan_iface, &args.state_file, &args.pin_dir, Duration::from_millis(args.poll_ms))
}

/// Without the `bpf` feature (no libbpf on this build host), the binary still parses args and
/// exercises the pure state-file logic (useful for `--status`-less dry validation / CI without
/// libbpf), but refuses to pretend it attached anything — an honest "not compiled with BPF
/// support" beats a silent no-op that looks like enforcement.
#[cfg(not(feature = "bpf"))]
fn main() -> Result<()> {
    let args = parse_args()?;
    if !granted("ddos_mitigation") {
        eprintln!(
            "napse-quarantine: capability 'ddos_mitigation' not granted on this platform \
             (module.yaml requires.capabilities) — nothing to enforce here, exiting cleanly."
        );
        return Ok(());
    }
    let state = state::load_state(&args.state_file)?;
    // Nothing is actually attached without the `bpf` feature, so the real ifindexes don't matter
    // for this dry-parse summary — placeholders keep the pure `desired_keys` call uniform with
    // the real (feature="bpf") path.
    let desired = state::desired_keys(&state, state::PlaneIfindexes { lan: 0, wan: 0 });
    eprintln!(
        "napse-quarantine: built WITHOUT the `bpf` feature — no libbpf, nothing attached. \
         Parsed {} quarantine entries ({} ip keys, {} mac keys) from {}. \
         Rebuild with `--features bpf` on a host with libbpf to actually enforce.",
        state.len(),
        desired.ips.len(),
        desired.macs.len(),
        args.state_file
    );
    Ok(())
}

#[cfg(test)]
mod iface_fallback_tests {
    use super::*;

    /// Configured interface exists — used as-is, fallback never consulted.
    #[test]
    fn keeps_configured_when_present() {
        let got = resolve_iface("LAN", "enp0s3", Some("wlan0"), |n| n == "enp0s3");
        assert_eq!(got, "enp0s3");
    }

    /// Configured interface absent (e.g. a stale `wlan0` unit default on a non-Pi box), but the
    /// manifest-classified fallback IS present — the cross-platform fix.
    #[test]
    fn falls_back_to_manifest_classified_when_configured_is_absent() {
        let got = resolve_iface("WAN", "end0", Some("enp0s2"), |n| n == "enp0s2");
        assert_eq!(got, "enp0s2");
    }

    /// Neither configured nor fallback present — fail-open: keep the configured name (the
    /// per-iface attach loop logs+skips it without stopping the other interface).
    #[test]
    fn keeps_configured_when_neither_resolves() {
        let got = resolve_iface("LAN", "wlan0", Some("enp9s9"), |_| false);
        assert_eq!(got, "wlan0");
    }

    /// No fallback offered at all (manifest unreadable/absent) — same fail-open behavior.
    #[test]
    fn keeps_configured_when_no_fallback_offered() {
        let got = resolve_iface("WAN", "end0", None, |_| false);
        assert_eq!(got, "end0");
    }

    /// A fallback equal to the (already-absent) configured name must not "match itself" and
    /// short-circuit into a false confidence — `exists` still gates it.
    #[test]
    fn fallback_equal_to_configured_still_requires_existence() {
        let got = resolve_iface("LAN", "wlan0", Some("wlan0"), |_| false);
        assert_eq!(got, "wlan0", "still absent either way — fail-open keeps the configured name");
    }
}

#[cfg(test)]
mod adr0016_tests {
    use super::*;

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("hp-napse-quarantine-adr0016-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Happy path: a module.yaml whose declared digests match the bytes on disk passes, and the
    /// parsed def carries them through.
    #[test]
    fn accepts_matching_loader_and_bpf_object_digests() {
        let dir = tmp_dir("accept");
        let loader_bytes = b"pretend loader ELF bytes";
        let bpf_bytes = b"pretend CO-RE bpf object bytes";
        std::fs::write(dir.join("napse-quarantine"), loader_bytes).unwrap();
        std::fs::write(dir.join("quarantine.bpf.o"), bpf_bytes).unwrap();

        use sha2::{Digest as _, Sha256};
        let yaml = format!(
            r#"id: napse-quarantine
version: "0.1.0"
runtime: sysext
signature: required
artifacts:
  - path: napse-quarantine
    role: loader
    digest: {{ alg: sha256, value: "{}" }}
  - path: quarantine.bpf.o
    role: bpf-object
    digest: {{ alg: sha256, value: "{}" }}
"#,
            hex::encode(Sha256::digest(loader_bytes)),
            hex::encode(Sha256::digest(bpf_bytes)),
        );
        let yaml_path = dir.join("module.yaml");
        std::fs::write(&yaml_path, yaml).unwrap();

        let def = verify_own_artifacts_at(&yaml_path, None).expect("matching digests must be accepted");
        assert_eq!(def.id, "napse-quarantine");
    }

    /// The Fix C regression proof: a tampered `.bpf.o` (the highest-privilege payload this loader
    /// attaches) must be refused, fail-closed, before `bpf::run` would ever be reached.
    #[test]
    fn refuses_a_tampered_bpf_object() {
        let dir = tmp_dir("tamper");
        let loader_bytes = b"pretend loader ELF bytes";
        let original_bpf = b"the real, signed CO-RE bpf object";
        std::fs::write(dir.join("napse-quarantine"), loader_bytes).unwrap();
        // Digest is pinned to `original_bpf`, but a DIFFERENT (tampered) file is on disk.
        std::fs::write(dir.join("quarantine.bpf.o"), b"a swapped-in malicious bpf object").unwrap();

        use sha2::{Digest as _, Sha256};
        let yaml = format!(
            r#"id: napse-quarantine
version: "0.1.0"
runtime: sysext
signature: required
artifacts:
  - path: napse-quarantine
    role: loader
    digest: {{ alg: sha256, value: "{}" }}
  - path: quarantine.bpf.o
    role: bpf-object
    digest: {{ alg: sha256, value: "{}" }}
"#,
            hex::encode(Sha256::digest(loader_bytes)),
            hex::encode(Sha256::digest(original_bpf)),
        );
        let yaml_path = dir.join("module.yaml");
        std::fs::write(&yaml_path, yaml).unwrap();

        let err = verify_own_artifacts_at(&yaml_path, None).unwrap_err();
        assert!(err.to_string().contains("digest check failed") || format!("{err:#}").contains("MISMATCH"), "got: {err:#}");
    }

    #[test]
    fn refuses_when_module_yaml_is_missing() {
        let dir = tmp_dir("missing-yaml");
        let missing = dir.join("does-not-exist.yaml");
        assert!(verify_own_artifacts_at(&missing, None).is_err());
    }
}
