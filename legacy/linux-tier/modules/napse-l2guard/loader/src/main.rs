//! napse-l2guard — Ring-0 line-rate DETERMINISTIC malformed-frame / malformed-ARP drop. This is
//! the real enforcement point `crates/hookprobe-manifest/src/l2_responder.rs`'s doc comment named
//! as still missing when it landed the storm-control half of ADR 0020 Phase-1a: nft cannot express
//! byte-level frame validation or one packet field disagreeing with another, so THIS program
//! re-parses raw frame bytes at TC-bpf clsact INGRESS on `wlan0` and `end0` — the earliest kernel
//! point a malformed frame can be stopped, before routing, before any netfilter/nftables hook —
//! and returns `TC_ACT_SHOT` for exactly the conditions `napse_loader::dpi::frame_anomaly_reason` /
//! `ArpObs::is_malformed` / `ArpObs::eth_mismatch` flag as `l2_responder::L2Verdict::FrameDrop`.
//! See `loader/src/predicates.rs` for the anti-drift proof that this program's C logic and the
//! userspace detector's Rust logic stay in lockstep.
//!
//! SEPARATE from `modules/napse-quarantine` ON PURPOSE (task-mandated, not incidental): quarantine
//! drops a packet because of who (a spoofable MAC/IP) a prior userspace decision already
//! quarantined; this program drops a packet because of WHAT it structurally is, regardless of
//! source. Attaches its OWN TC-bpf program at its OWN priority (see bpf.rs) so the two (and
//! napse-capture's DPI mirror) can never collide/clobber one another's clsact filter.
//!
//! HONEST LIMITS (do not paper over — see the module README for the full accounting):
//!   - Does NOT enforce ARP binding flip-flop or gratuitous-ARP flood — both need cross-packet
//!     HISTORY (stateful), a different problem from "is this ONE frame structurally bad". They
//!     remain handled by `l2_responder`'s existing nft storm-control (gratuitous flood, rate-
//!     limited) or stay alert-only (binding flip-flop).
//!   - Compile-proven (this crate's tests + a clean `clang -target bpf` build + a verifier
//!     smoke-load where root/CAP_BPF permits), NOT yet attach-verified on real hardware in THIS
//!     pass — this dev box has no root/CAP_BPF. Mirrors `modules/napse-quarantine`'s own honesty
//!     posture before its first live Pi test.

use anyhow::{bail, Context, Result};
#[cfg(feature = "bpf")]
use std::time::Duration;

#[cfg(test)]
mod predicates;
#[cfg(feature = "bpf")]
mod bpf;

#[cfg(test)]
mod iface_fallback_tests {
    use super::*;

    #[test]
    fn keeps_configured_when_present() {
        let got = resolve_iface("LAN", "enp0s3", Some("wlan0"), |n| n == "enp0s3");
        assert_eq!(got, "enp0s3");
    }

    #[test]
    fn falls_back_to_manifest_classified_when_configured_is_absent() {
        let got = resolve_iface("WAN", "end0", Some("enp0s2"), |n| n == "enp0s2");
        assert_eq!(got, "enp0s2");
    }

    #[test]
    fn keeps_configured_when_neither_resolves() {
        let got = resolve_iface("LAN", "wlan0", Some("enp9s9"), |_| false);
        assert_eq!(got, "wlan0");
    }

    #[test]
    fn keeps_configured_when_no_fallback_offered() {
        let got = resolve_iface("WAN", "end0", None, |_| false);
        assert_eq!(got, "end0");
    }
}

/// Self-gate (arch F4 fix, same pattern `modules/napse-quarantine/loader/src/main.rs` and
/// `modules/ovs/config/ovs-bringup` use): the supervisor never starts a `managed` sysext unit, so
/// this module decides for itself whether to run. Reuses `ddos_mitigation` — already the
/// platform's edge-vs-cloud gate (policy enabled on rpi4/rpi5/rk3588/n100, disabled on
/// cloud/generic — see `platforms/*.yaml`) — rather than inventing a new capability token for
/// what is, functionally, the same "is this an edge box with a real LAN/WAN to defend" question
/// `napse-quarantine` already answers with this exact token.
fn granted(cap: &str) -> bool {
    let path = std::env::var("MANIFEST").unwrap_or_else(|_| "/var/lib/hookprobe/manifest.json".to_string());
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("napse-l2guard: cannot read manifest {path} ({e}) — treating '{cap}' as not granted");
            return false;
        }
    };
    let m: hookprobe_manifest::Manifest = match serde_json::from_str(&text) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("napse-l2guard: cannot parse manifest {path} ({e}) — treating '{cap}' as not granted");
            return false;
        }
    };
    m.capabilities
        .get(cap)
        .map(|c| c.state == hookprobe_manifest::types::CapabilityState::Granted)
        .unwrap_or(false)
}

// Every field is read by bpf::run/status (feature = "bpf"); the non-bpf build only exercises arg
// parsing — allow the rest to go unread rather than feature-gating the struct itself.
#[cfg_attr(not(feature = "bpf"), allow(dead_code))]
struct Args {
    obj: String,
    lan_iface: String,
    wan_iface: String,
    pin_dir: String,
    stats_interval_secs: u64,
    status: bool,
}

/// Does this interface exist right now? (`/sys/class/net/<name>`.)
#[cfg_attr(not(feature = "bpf"), allow(dead_code))]
fn iface_present(name: &str) -> bool {
    std::path::Path::new("/sys/class/net").join(name).exists()
}

/// 2026-07 cross-platform fix (mirrors `napse-quarantine`'s identically-named function): if the
/// CONFIGURED interface (from `ifaces.env`/CLI/env — see `aegis::reconcile_network`'s `ifaces.env`
/// artifact, the real source of truth) isn't present in sysfs, and the manifest-derived `fallback`
/// IS, use it instead. Pure/testable via the injected `exists` predicate. Never fails — if neither
/// resolves, `configured` is kept as-is (fail-open, unchanged).
#[cfg_attr(not(feature = "bpf"), allow(dead_code))]
fn resolve_iface(plane: &str, configured: &str, fallback: Option<&str>, exists: impl Fn(&str) -> bool) -> String {
    if exists(configured) {
        return configured.to_string();
    }
    if let Some(fb) = fallback {
        if fb != configured && exists(fb) {
            eprintln!(
                "napse-l2guard: configured {plane} iface '{configured}' not present — \
                 falling back to the manifest-classified '{fb}'"
            );
            return fb.to_string();
        }
    }
    eprintln!(
        "napse-l2guard: configured {plane} iface '{configured}' not present and no \
         manifest-classified fallback resolved — attach will be attempted anyway (fail-open)"
    );
    configured.to_string()
}

/// Best-effort read of the signed manifest for [`resolve_iface`]'s fallback candidates — same
/// posture as `granted()` above: any read/parse error means "no fallback available", never a panic.
#[cfg_attr(not(feature = "bpf"), allow(dead_code))]
fn manifest_fallback_ifaces() -> (Option<String>, Option<String>) {
    let path = std::env::var("MANIFEST").unwrap_or_else(|_| "/var/lib/hookprobe/manifest.json".to_string());
    match std::fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str::<hookprobe_manifest::Manifest>(&t).ok()) {
        Some(m) => hookprobe_manifest::scan_responder::manifest_iface_fallback(&m),
        None => (None, None),
    }
}

fn parse_args() -> Result<Args> {
    let mut obj = std::env::var("NAPSE_L2GUARD_OBJ").unwrap_or_else(|_| "/usr/lib/hookprobe/bpf/l2guard.bpf.o".to_string());
    let mut lan_iface = std::env::var("NAPSE_L2GUARD_LAN_IFACE").or_else(|_| std::env::var("LAN_IFACE")).unwrap_or_else(|_| "wlan0".to_string());
    let mut wan_iface = std::env::var("NAPSE_L2GUARD_WAN_IFACE").or_else(|_| std::env::var("WAN_IFACE")).unwrap_or_else(|_| "end0".to_string());
    let mut pin_dir = std::env::var("NAPSE_L2GUARD_PIN_DIR").unwrap_or_else(|_| "/sys/fs/bpf/napse-l2guard".to_string());
    let mut stats_interval_secs: u64 = std::env::var("NAPSE_L2GUARD_STATS_INTERVAL_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(300);
    let mut status = false;

    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--obj" => obj = it.next().ok_or_else(|| anyhow::anyhow!("--obj needs a value"))?,
            "--lan-iface" => lan_iface = it.next().ok_or_else(|| anyhow::anyhow!("--lan-iface needs a value"))?,
            "--wan-iface" => wan_iface = it.next().ok_or_else(|| anyhow::anyhow!("--wan-iface needs a value"))?,
            "--pin-dir" => pin_dir = it.next().ok_or_else(|| anyhow::anyhow!("--pin-dir needs a value"))?,
            "--stats-interval-secs" => stats_interval_secs = it.next().ok_or_else(|| anyhow::anyhow!("--stats-interval-secs needs a value"))?.parse()?,
            "--status" => status = true,
            "--help" | "-h" => {
                println!(
                    "napse-l2guard [--obj PATH] [--lan-iface NAME] [--wan-iface NAME] [--pin-dir PATH] [--stats-interval-secs N] [--status]"
                );
                std::process::exit(0);
            }
            other => bail!("unknown argument: {other}"),
        }
    }
    Ok(Args { obj, lan_iface, wan_iface, pin_dir, stats_interval_secs, status })
}

/// ADR 0016 Fix C (the artifact-hash-signing gate is wasm-only otherwise, so it never covers this
/// loader or the `.bpf.o` it attaches — same rationale as `napse-quarantine`'s identically-named
/// function). Parses THIS module's own staged `module.yaml` and recomputes+compares every
/// declared artifact's digest against the bytes actually on disk. Free of `std::process::exit` so
/// it is exercised directly by unit tests; `verify_own_artifacts` below is the fail-closed,
/// process-exiting wrapper the real `main()` calls.
#[cfg_attr(not(feature = "bpf"), allow(dead_code))]
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

#[cfg(feature = "bpf")]
fn verify_own_artifacts() {
    let module_yaml = std::env::var("NAPSE_L2GUARD_MODULE_YAML")
        .unwrap_or_else(|_| "/usr/lib/hookprobe/modules/napse-l2guard/module.yaml".to_string());
    let events = std::env::var("HOOKPROBE_EVENTS").ok().map(std::path::PathBuf::from);
    match verify_own_artifacts_at(std::path::Path::new(&module_yaml), events.as_deref()) {
        Ok(_) => eprintln!("napse-l2guard: ADR 0016 artifact-digest check passed (loader + bpf-object) — proceeding to attach."),
        Err(e) => {
            eprintln!("napse-l2guard: refusing to load/attach — {e:#}");
            std::process::exit(1);
        }
    }
}

#[cfg(feature = "bpf")]
fn main() -> Result<()> {
    let args = parse_args()?;
    if !granted("ddos_mitigation") {
        eprintln!(
            "napse-l2guard: capability 'ddos_mitigation' not granted on this platform \
             (module.yaml requires.capabilities) — nothing to enforce here, exiting cleanly. \
             malformed-frame findings remain alert-only via l2_responder on this device."
        );
        return Ok(());
    }
    if args.status {
        return bpf::status(&args.pin_dir);
    }
    verify_own_artifacts();
    // Cross-platform robustness (defense-in-depth alongside `ifaces.env`): if the configured
    // interface isn't present, try the manifest-classified one before ever calling into libbpf.
    let (wan_fb, lan_fb) = manifest_fallback_ifaces();
    let lan_iface = resolve_iface("LAN", &args.lan_iface, lan_fb.as_deref(), iface_present);
    let wan_iface = resolve_iface("WAN", &args.wan_iface, wan_fb.as_deref(), iface_present);
    bpf::run(&args.obj, &lan_iface, &wan_iface, &args.pin_dir, Duration::from_secs(args.stats_interval_secs))
}

/// Without the `bpf` feature (no libbpf on this build host), the binary still parses args (useful
/// for CI/dry validation without libbpf) but refuses to pretend it attached anything.
#[cfg(not(feature = "bpf"))]
fn main() -> Result<()> {
    let args = parse_args()?;
    if !granted("ddos_mitigation") {
        eprintln!(
            "napse-l2guard: capability 'ddos_mitigation' not granted on this platform \
             (module.yaml requires.capabilities) — nothing to enforce here, exiting cleanly."
        );
        return Ok(());
    }
    eprintln!(
        "napse-l2guard: built WITHOUT the `bpf` feature — no libbpf, nothing attached. \
         Rebuild with `--features bpf` on a host with libbpf to actually enforce \
         (lan_iface={}, wan_iface={}, obj={}).",
        args.lan_iface, args.wan_iface, args.obj
    );
    Ok(())
}

#[cfg(test)]
mod adr0016_tests {
    use super::*;

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("hp-napse-l2guard-adr0016-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn accepts_matching_loader_and_bpf_object_digests() {
        let dir = tmp_dir("accept");
        let loader_bytes = b"pretend loader ELF bytes";
        let bpf_bytes = b"pretend CO-RE bpf object bytes";
        std::fs::write(dir.join("napse-l2guard"), loader_bytes).unwrap();
        std::fs::write(dir.join("l2guard.bpf.o"), bpf_bytes).unwrap();

        use sha2::{Digest as _, Sha256};
        let yaml = format!(
            r#"id: napse-l2guard
version: "0.1.0"
runtime: sysext
signature: required
artifacts:
  - path: napse-l2guard
    role: loader
    digest: {{ alg: sha256, value: "{}" }}
  - path: l2guard.bpf.o
    role: bpf-object
    digest: {{ alg: sha256, value: "{}" }}
"#,
            hex::encode(Sha256::digest(loader_bytes)),
            hex::encode(Sha256::digest(bpf_bytes)),
        );
        let yaml_path = dir.join("module.yaml");
        std::fs::write(&yaml_path, yaml).unwrap();

        let def = verify_own_artifacts_at(&yaml_path, None).expect("matching digests must be accepted");
        assert_eq!(def.id, "napse-l2guard");
    }

    #[test]
    fn refuses_a_tampered_bpf_object() {
        let dir = tmp_dir("tamper");
        let loader_bytes = b"pretend loader ELF bytes";
        let original_bpf = b"the real, signed CO-RE bpf object";
        std::fs::write(dir.join("napse-l2guard"), loader_bytes).unwrap();
        std::fs::write(dir.join("l2guard.bpf.o"), b"a swapped-in malicious bpf object").unwrap();

        use sha2::{Digest as _, Sha256};
        let yaml = format!(
            r#"id: napse-l2guard
version: "0.1.0"
runtime: sysext
signature: required
artifacts:
  - path: napse-l2guard
    role: loader
    digest: {{ alg: sha256, value: "{}" }}
  - path: l2guard.bpf.o
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
