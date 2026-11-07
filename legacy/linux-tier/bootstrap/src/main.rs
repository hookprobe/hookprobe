//! HookProbe Bootstrap — Platform Manifest generator.
//!
//! Pipeline: scan -> classify -> map capabilities -> allocate resources ->
//! compute retention -> assemble -> (stub) sign -> manifest.json (schema 2).
//!
//! This binary is the SHIPPING implementation (Rust, ADR 0001).
//! The Python script at `bootstrap/reference/generate_manifest.py` is the
//! readable reference; this binary is kept alongside it.
//!
//! Scanner: probes REAL hardware read-only (see `probe.rs`) by default; a
//! probert-style JSON fixture can be passed instead (offline testing / CI).
//!
//! Remaining stub:
//!   - Signer: emits UNSIGNED-REFERENCE-BUILD. TODO: cosign + TPM seal.

mod probe;

use anyhow::{Context, Result};
use clap::Parser;
use std::path::{Path, PathBuf};

use hookprobe_manifest::scan::{HardwareScan, ScanProfile};
use hookprobe_manifest::{build_manifest, classify, load_platforms};

// ---------------------------------------------------------------------------
// Scanner — real hardware probe (probe.rs) or a fixture file.
// ---------------------------------------------------------------------------

/// Reads a probert-style JSON profile from disk (for offline testing / CI).
fn scan_from_fixture(path: &Path) -> Result<HardwareScan> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading fixture {path:?}"))?;
    let profile: ScanProfile =
        serde_json::from_str(&text).with_context(|| format!("parsing fixture {path:?}"))?;
    Ok(profile.scan)
}

// Signing is performed by the device software-PUF identity
// (`hookprobe_manifest::identity`); no TPM required.

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// HookProbe Platform Manifest generator (Rust implementation).
#[derive(Parser)]
#[command(name = "hookprobe-bootstrap", version, about)]
struct Cli {
    /// Probert-style scan profile JSON. Omit to probe REAL hardware (read-only).
    fixture: Option<PathBuf>,

    /// Force the live hardware probe even if a fixture path is given.
    #[arg(long)]
    probe: bool,

    /// Print only the raw hardware scan (`{"scan": …}`) and exit. No classify,
    /// no platforms/ needed — useful for capturing a profile from a device.
    #[arg(long = "scan-only")]
    scan_only: bool,

    /// Print the unified "Get Online" uplink candidates (wired / Wi-Fi-station /
    /// cellular) in failover order, and exit.
    #[arg(long)]
    uplinks: bool,

    /// 2026-07-05 FIX (backend-audit P1 #5 — "first-boot manifest freezes capability
    /// grants"): decide whether the manifest at this path needs a re-probe WITHOUT
    /// probing hardware or writing anything — cheap enough to run on every boot via
    /// `ExecCondition=` (see base/units/hookprobe-bootstrap.service). Exits 0 ("proceed
    /// — re-probe needed") when the file is absent/unreadable/unparseable, or its
    /// recorded `platform.platform_rules_version` is OLDER than this build's own
    /// `hookprobe_manifest::builder::PLATFORM_RULES_VERSION`. Exits 1 ("skip — already
    /// current", systemd's `ExecCondition=` non-zero-but-not-a-failure convention) when
    /// the manifest exists and its rules version is already current. No other flag may
    /// be combined with this one.
    #[arg(long = "check-rules-version")]
    check_rules_version: Option<PathBuf>,

    /// Explicit platforms/ directory (else auto-located from cwd/exe/fixture).
    #[arg(long)]
    platforms: Option<PathBuf>,

    /// Output path. Omit to print to stdout.
    #[arg(short = 'o', long = "out")]
    out: Option<PathBuf>,

    /// Override generated_at timestamp (ISO-8601). Default: now (UTC).
    #[arg(long)]
    now: Option<String>,

    /// OCI image reference for provenance.
    #[arg(long, default_value = "ghcr.io/hookprobe/os:dev")]
    image_ref: String,

    /// OCI image digest for provenance.
    #[arg(long, default_value_t = format!("sha256:{}", "0".repeat(64)))]
    image_digest: String,

    /// First-boot CLAIM: set the local admin password (no account needed). Implies claim.
    #[arg(long = "claim-admin")]
    claim_admin: Option<String>,
    /// Deployment mode for the claim: standalone | cloud-linked | self-hosted.
    #[arg(long, default_value = "standalone")]
    mode: String,
    /// ENROLL into this tenant (cloud-linked / self-hosted). Additive — optional.
    #[arg(long = "enroll-tenant")]
    enroll_tenant: Option<String>,
    /// Enrollment token (paired with --enroll-tenant).
    #[arg(long = "enroll-token")]
    enroll_token: Option<String>,
    /// Write the claim record (admin hash, mode, tenant) to this path.
    #[arg(long = "claim-out")]
    claim_out: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();

    // --- --check-rules-version: cheap, hardware-probe-free "should we regenerate?"
    //     decision (backend-audit P1 #5). Exits BEFORE any scan/probe happens. ---
    if let Some(path) = &cli.check_rules_version {
        std::process::exit(if manifest_needs_reprobe(path) { 0 } else { 1 });
    }

    // --- scan: live probe by default; fixture if one is given (unless --probe).
    let use_fixture = cli.fixture.is_some() && !cli.probe;
    let scan = if use_fixture {
        let p = cli.fixture.as_ref().unwrap();
        scan_from_fixture(p).with_context(|| "fixture scan failed")?
    } else {
        probe::probe().with_context(|| "live hardware probe failed")?
    };

    // --- scan-only: dump the raw profile and exit (portable, no platforms/).
    if cli.scan_only {
        let doc = serde_json::json!({ "scan": scan });
        let json = serde_json::to_string_pretty(&doc)?;
        match &cli.out {
            Some(path) => {
                std::fs::write(path, format!("{json}\n"))?;
                eprintln!("wrote scan profile {path:?}");
            }
            None => println!("{json}"),
        }
        return Ok(());
    }

    // --- uplinks: the unified "Get Online" candidate list (wired/Wi-Fi-sta/cellular) ---
    if cli.uplinks {
        println!("Get Online — uplink candidates (failover order, lower = preferred):");
        for u in hookprobe_manifest::net_roles::enumerate_uplinks(&scan.interfaces, scan.lte.present) {
            println!("  [{:>2}] {:<14} {}", u.priority, u.name, u.kind.as_str());
        }
        return Ok(());
    }

    // Surface present-but-undriven hardware as a deploy PREREQUISITE — the immutable
    // image can't ship every driver/firmware, so this must be visible, never silent.
    if !scan.unbound.is_empty() {
        eprintln!(
            "WARNING: {} device(s) PRESENT but with NO driver (image lacks the kernel module/firmware):",
            scan.unbound.len()
        );
        for u in &scan.unbound {
            eprintln!(
                "  {} {} [{}] @ {} — bake its driver/firmware into the image, add a driver sysext, or build a profile variant",
                u.bus, u.id, u.class, u.path
            );
        }
    }

    // --- classify: needs platforms/.
    let platforms_dir = locate_platforms(cli.platforms.as_deref(), cli.fixture.as_deref())
        .context("could not locate platforms/ — pass --platforms <dir>")?;
    let platforms = load_platforms(&platforms_dir)?;
    let (platform, match_info) = classify(&scan, &platforms)?;

    let now_iso = cli.now.unwrap_or_else(utc_now);

    let mut manifest = build_manifest(
        &scan,
        platform,
        &match_info,
        &now_iso,
        &cli.image_ref,
        &cli.image_digest,
    )?;

    // Sign with the device's software-PUF identity (no TPM required). On a device
    // WITH a TPM this is the tier a future hardware-seal step upgrades.
    let identity =
        hookprobe_manifest::identity::DeviceIdentity::derive(manifest.hardware.tpm.present);
    if hookprobe_manifest::identity::weak_entropy() {
        eprintln!(
            "WARNING: NO device-unique PUF material (no board serial / machine-id / storage \
             serial / MAC) — the derived identity key is NOT unique or secret. Provision \
             /etc/machine-id or add a hardware root before trusting this device identity."
        );
    }
    identity.sign_manifest(&mut manifest);

    // Informational: name the strongest sealing tier this device could use. The
    // current build holds a software-PUF key; TPM/DICE hardware sealing is a drop-in.
    let tier = hookprobe_manifest::identity::recommended_tier(manifest.hardware.tpm.present, false);
    if tier != hookprobe_manifest::identity::SealTier::SoftwarePuf {
        eprintln!(
            "note: {} available (TPM/DICE present) — this build uses a software-PUF key; hardware sealing is a drop-in upgrade.",
            tier.as_str()
        );
    }

    // --- optional first-boot claim (local admin, no account) + enroll (additive) ---
    if let Some(pw) = &cli.claim_admin {
        use hookprobe_manifest::claim;
        let mode = claim::Mode::parse(&cli.mode).unwrap_or(claim::Mode::Standalone);
        let rec = claim::claim(&mut manifest, pw, mode, &now_iso);
        if let Some(tenant) = &cli.enroll_tenant {
            claim::enroll(&mut manifest, tenant, cli.enroll_token.as_deref().unwrap_or(""));
        }
        identity.sign_manifest(&mut manifest); // re-sign: identity.claim_state/tenant changed
        if let Some(p) = &cli.claim_out {
            std::fs::write(p, serde_json::to_string_pretty(&rec)? + "\n")
                .with_context(|| format!("writing claim record to {p:?}"))?;
        }
        eprintln!(
            "claimed: state={:?} mode={} tenant={:?}",
            manifest.identity.claim_state, rec.mode, manifest.identity.tenant
        );
    }

    let json = serde_json::to_string_pretty(&manifest)?;
    let class = serde_json::to_value(&manifest.platform.class).unwrap_or_default();
    let method = serde_json::to_value(&manifest.platform.match_info.method).unwrap_or_default();
    let summary = format!(
        "class={}, profile={}, match={}:{}",
        class.as_str().unwrap_or_default(),
        manifest.platform.profile,
        method.as_str().unwrap_or_default(),
        manifest.platform.match_info.key,
    );
    match &cli.out {
        Some(path) => {
            std::fs::write(path, format!("{json}\n"))
                .with_context(|| format!("writing output to {path:?}"))?;
            eprintln!("wrote {path:?}  ({summary})");
            eprintln!(
                "signed: software-PUF {} (tpm_available={})",
                manifest.identity.idevid.pubkey_fpr, identity.tpm_available
            );
        }
        None => println!("{json}"),
    }

    Ok(())
}

/// 2026-07-05 FIX (backend-audit P1 #5): true when the manifest at `path` should be
/// regenerated — absent, unreadable, unparseable (all treated as "stale": safer to
/// re-probe than to trust a corrupt/foreign file), OR its recorded
/// `platform.platform_rules_version` is older than this build's own
/// `PLATFORM_RULES_VERSION`. Never touches hardware — reads (at most) one JSON file.
fn manifest_needs_reprobe(path: &Path) -> bool {
    use hookprobe_manifest::builder::PLATFORM_RULES_VERSION;
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return true, // absent (or unreadable) -- first boot / wiped data partition
    };
    let manifest: hookprobe_manifest::types::Manifest = match serde_json::from_str(&text) {
        Ok(m) => m,
        Err(_) => return true, // present but corrupt/foreign -- safer to regenerate than trust it
    };
    manifest.platform.platform_rules_version < PLATFORM_RULES_VERSION
}

/// Locate `platforms/` by checking, in order: an explicit dir, then ancestors
/// of the fixture / cwd / exe, then standard install paths.
fn locate_platforms(explicit: Option<&Path>, fixture: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        if p.is_dir() {
            return Some(p.to_path_buf());
        }
    }
    if let Some(f) = fixture {
        if let Ok(c) = f.canonicalize() {
            if let Some(d) = ancestors_platforms(&c) {
                return Some(d);
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        if let Some(d) = ancestors_platforms(&cwd) {
            return Some(d);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(d) = ancestors_platforms(&exe) {
            return Some(d);
        }
    }
    for p in [
        "/usr/share/hookprobe/platforms",
        "/etc/hookprobe/platforms",
        "/var/lib/hookprobe/platforms",
    ] {
        let pb = PathBuf::from(p);
        if pb.is_dir() {
            return Some(pb);
        }
    }
    None
}

/// Return the nearest `<ancestor>/platforms` directory at or above `start`.
fn ancestors_platforms(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .map(|d| d.join("platforms"))
        .find(|c| c.is_dir())
}

/// Current UTC timestamp in ISO-8601 (seconds precision, +00:00 suffix).
fn utc_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let secs_in_day = secs % 86400;
    let days = secs / 86400;
    let (h, m, s) = (secs_in_day / 3600, (secs_in_day % 3600) / 60, secs_in_day % 60);
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}+00:00")
}

/// Convert days-since-epoch to (year, month, day). Howard Hinnant's algorithm.
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod rules_version_reprobe_tests {
    //! backend-audit P1 #5 — "first-boot manifest freezes capability grants". Regression
    //! coverage for `manifest_needs_reprobe`: absent/corrupt/pre-this-fix manifests must
    //! trigger a re-probe; a manifest already carrying the current
    //! `PLATFORM_RULES_VERSION` must NOT (the "detect once" floor stays true once caught up).
    use super::manifest_needs_reprobe;
    use hookprobe_manifest::builder::PLATFORM_RULES_VERSION;
    use std::path::PathBuf;

    /// A real, checked-in example manifest (manifest/examples/generic.manifest.json) --
    /// predates this fix, so it has NO `platform.platform_rules_version` key at all: the
    /// exact "pre-this-fix, frozen manifest" shape a fielded device would actually have.
    fn example_manifest_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../manifest/examples/generic.manifest.json")
    }

    fn scratch_path(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "hookprobe-bootstrap-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("manifest.json")
    }

    #[test]
    fn absent_manifest_needs_reprobe() {
        let path = scratch_path("absent").parent().unwrap().join("does-not-exist.json");
        assert!(!path.exists());
        assert!(manifest_needs_reprobe(&path), "an absent manifest must trigger a re-probe");
    }

    #[test]
    fn malformed_manifest_needs_reprobe() {
        let path = scratch_path("malformed");
        std::fs::write(&path, "{ not valid json").unwrap();
        assert!(manifest_needs_reprobe(&path), "a corrupt manifest must trigger a re-probe, not be trusted as-is");
    }

    #[test]
    fn pre_fix_manifest_with_no_rules_version_field_needs_reprobe() {
        // A REAL checked-in fixture predating this field -- proves the #[serde(default)]
        // floor (0) is genuinely "older than any real PLATFORM_RULES_VERSION >= 1", not just
        // in a hand-crafted test document.
        let example = example_manifest_path();
        assert!(example.is_file(), "fixture missing: {example:?}");
        assert!(
            manifest_needs_reprobe(&example),
            "a pre-fix manifest (no platform_rules_version field) must trigger exactly one re-probe"
        );
    }

    #[test]
    fn manifest_already_at_current_rules_version_does_not_need_reprobe() {
        let example = example_manifest_path();
        let text = std::fs::read_to_string(&example).unwrap();
        let mut doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        doc["platform"]["platform_rules_version"] = serde_json::json!(PLATFORM_RULES_VERSION);
        let path = scratch_path("current");
        std::fs::write(&path, serde_json::to_string(&doc).unwrap()).unwrap();

        assert!(
            !manifest_needs_reprobe(&path),
            "a manifest already at PLATFORM_RULES_VERSION must NOT trigger a re-probe (detect-once floor)"
        );
    }

    #[test]
    fn manifest_at_a_future_rules_version_does_not_need_reprobe() {
        // A newer device/manifest (rules_version > this build's own) must never be treated
        // as stale -- only STRICTLY OLDER triggers a re-probe.
        let example = example_manifest_path();
        let text = std::fs::read_to_string(&example).unwrap();
        let mut doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        doc["platform"]["platform_rules_version"] = serde_json::json!(PLATFORM_RULES_VERSION + 1);
        let path = scratch_path("future");
        std::fs::write(&path, serde_json::to_string(&doc).unwrap()).unwrap();

        assert!(!manifest_needs_reprobe(&path));
    }
}
