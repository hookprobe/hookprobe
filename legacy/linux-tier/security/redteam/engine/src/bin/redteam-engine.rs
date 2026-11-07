//! redteam-engine CLI — the campaign runner (ADR 0020). Loads + enforces the ROE (D3), stands up a
//! `TargetGuard` (netlink-verified topology + limits + kill-switch), writes the pre-fire
//! `attack_run` audit, fires exactly ONE requested probe (Phase-1b: `mac-flood` | `syn-scan` |
//! `state-exhaust`), determines verify-fired by reading the DUT's own `events` telemetry stream
//! (never merely "the attacker failed"), and writes the finding(s) + final verdict. This binary
//! NEVER ships in an image (ADR 0020 D2) and is NEVER run outside the declared DUT netns/segment.
use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use redteam_engine::campaign::{now_iso8601, Campaign};
use redteam_engine::findings::{Cadence as FCadence, Finding, Layer, Outcome, Severity};
use redteam_engine::kill_switch::KillSwitch;
use redteam_engine::l2_link::mac_flood;
use redteam_engine::l34_net::syn_scan;
use redteam_engine::limiter::Limiter;
use redteam_engine::roe::Roe;
use redteam_engine::sockets::{iface_mac, parse_mac};
use redteam_engine::target_guard::TargetGuard;
use redteam_engine::topology::IpCommandTopology;
use std::path::PathBuf;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ProbeKind {
    MacFlood,
    SynScan,
    StateExhaust,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum CadenceArg {
    Smoke,
    Full,
}

#[derive(Parser)]
#[command(name = "redteam-engine", version, about = "HookProbe OS ADR 0020 adversarial-resilience harness -- DUT-only, ROE-gated. NEVER run against a production/WAN target.")]
struct Cli {
    /// Path to rules-of-engagement.yaml -- default-deny, enforced (D3).
    #[arg(long, default_value = "security/redteam/rules-of-engagement.yaml")]
    roe: PathBuf,
    /// Output directory for attack_run.json / findings.jsonl.
    #[arg(long)]
    out: PathBuf,
    /// Which probe to fire this run.
    #[arg(long, value_enum)]
    probe: ProbeKind,
    /// smoke (post-build, per-image) | full (pre-release Gate R) -- ADR 0020 D5.
    #[arg(long, value_enum, default_value = "smoke")]
    cadence: CadenceArg,
    /// The image/build under test (recorded on the attack_run node).
    #[arg(long, default_value = "dev")]
    image_version: String,
    /// Who/what ran this campaign (operator or CI identity).
    #[arg(long, default_value = "ci")]
    operator: String,
    /// The DUT-side veth interface this probe transmits on (must be a ROE-declared interface).
    #[arg(long)]
    iface: String,
    /// The DUT netns (required for --probe mac-flood, condition 2).
    #[arg(long)]
    netns: Option<String>,
    /// Numeric IP/CIDR-literal target (never a hostname -- condition 3 rejects anything else).
    #[arg(long)]
    target: Option<String>,
    /// Destination MAC for a crafted frame (default: broadcast).
    #[arg(long, default_value = "ff:ff:ff:ff:ff:ff")]
    dst_mac: String,
    /// Number of frames to send (mac-flood) / distinct forged sources (state-exhaust).
    #[arg(long, default_value_t = 200)]
    count: u32,
    /// Comma-separated destination ports for --probe syn-scan (fan-out). The default list is a
    /// realistic top-N common-service scan (60 ports) -- napse_loader::portscan's default
    /// distinct-port threshold is 50 (DEFAULT_THRESHOLD), so a default-args run actually crosses
    /// it; pass a shorter --ports list deliberately to exercise an under-threshold non-trigger.
    #[arg(long, default_value = "20,21,22,23,25,53,80,88,110,111,123,135,137,138,139,143,161,179,389,443,445,465,514,515,587,631,636,993,995,1080,1194,1433,1521,1723,2049,2082,2083,2181,2375,3000,3128,3268,3306,3389,4444,4789,5000,5432,5601,5900,5985,5986,6379,7001,8000,8080,8443,8888,9000,9090,9200,9300,11211,27017")]
    ports: String,
    /// Destination port for --probe state-exhaust.
    #[arg(long, default_value_t = 22)]
    dst_port: u16,
    /// The DUT's own events/telemetry JSONL stream -- read AFTER the probe fires to determine
    /// verify-fired (the loop-closing principle: an attack is only "withstood" if the defense's own
    /// output shows it fired). Omit to honestly record `inconclusive` (never fabricate a pass).
    #[arg(long)]
    events: Option<PathBuf>,
    /// Substring the DUT's events stream must contain for this campaign to count as "verified
    /// fired" (e.g. "l2_mac_flood" or "port scan detected").
    #[arg(long, default_value = "")]
    verify_substr: String,
    /// Deterministic reproduction seed, recorded on the finding.
    #[arg(long, default_value_t = 1)]
    seed: u64,
    /// Explicit campaign id, so several probes fired as SEPARATE process invocations (the normal
    /// shape of a real campaign -- one probe per invocation) share ONE `attack_run` record instead
    /// of each minting its own. Defaults to a value derived from the ROE hash + cadence + image
    /// version (no wall-clock component), so repeated invocations against the SAME ROE/cadence/
    /// image naturally continue the same campaign without the caller having to compute anything.
    #[arg(long)]
    campaign_id: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let roe_text = std::fs::read_to_string(&cli.roe)
        .with_context(|| format!("ROE file not found: {}", cli.roe.display()))?;
    let roe = Roe::parse(&roe_text)?; // fail-closed: any ROE problem aborts before anything fires
    let roe_hash = Roe::hash_of(&roe_text);
    let limits = roe.limits.clone();
    let guard = TargetGuard::new(roe, Box::new(IpCommandTopology))?;
    let limiter = Limiter::new(limits);
    let kill_switch: KillSwitch = guard.kill_switch().clone();
    // Contract #4 / condition 5: a trapped SIGTERM must halt an in-flight campaign, not just the
    // file sentinel. Runs concurrently on the multi-thread runtime while the (synchronous, blocking)
    // probe send loop below occupies its own worker thread -- both share the SAME `KillSwitch`
    // (cheap `Arc<AtomicBool>` clone), so the probe's per-frame `tripped()` check sees the flip.
    #[cfg(unix)]
    tokio::spawn(redteam_engine::kill_switch::trap_sigterm(kill_switch.clone()));

    let campaign = Campaign::new(&cli.out);
    let cadence = match cli.cadence {
        CadenceArg::Smoke => FCadence::Smoke,
        CadenceArg::Full => FCadence::Full,
    };
    let cadence_str = match cli.cadence {
        CadenceArg::Smoke => "smoke",
        CadenceArg::Full => "full",
    };
    let run_id = cli
        .campaign_id
        .clone()
        .unwrap_or_else(|| format!("ar:{roe_hash}:{cadence_str}:{}", cli.image_version));
    let dut_targets = vec![cli.iface.clone()];
    // Contract #5: the attack_run audit is written BEFORE the first probe fires.
    let run = campaign.start(run_id.clone(), roe_hash.clone(), cadence, cli.image_version.clone(), dut_targets, cli.operator.clone())?;
    println!("redteam-engine: attack_run {} recorded (pre-fire audit) -> {}", run.id, campaign.attack_run_path().display());

    let dst_mac = parse_mac(&cli.dst_mac).context("--dst-mac")?;

    let (layer, probe_name, target_component, severity, frames_sent, aborted): (Layer, &str, &str, Severity, u32, Option<String>) =
        match cli.probe {
            ProbeKind::MacFlood => {
                let netns = cli.netns.clone().context("--probe mac-flood requires --netns")?;
                let scope = guard.validate_l2(&cli.iface, &netns)?;
                let stats = mac_flood::run(&scope, &limiter, &kill_switch, cli.count, dst_mac, cli.seed as u32)?;
                (Layer::L2, "mac-flood", "napse-dpi", Severity::Amber, stats.frames_sent, stats.aborted_reason)
            }
            ProbeKind::SynScan => {
                let target_lit = cli.target.clone().context("--probe syn-scan requires --target")?;
                let target = guard.validate_l3_literal(&target_lit, &cli.iface)?;
                let src_mac = iface_mac(&cli.iface)?;
                let ports: Vec<u16> = cli
                    .ports
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.parse::<u16>().context("--ports"))
                    .collect::<Result<_>>()?;
                // Source IP: this engine's own veth address (a real, un-spoofed source -- the
                // fan-out probe's whole point is volume/pattern, not spoofing). Read from the
                // kernel rather than guessed, so the crafted frame's IP header is not a lie.
                let src_ip = first_ipv4_of_iface(&cli.iface)?;
                let stats = syn_scan::run_fan_out_scan(&target, &limiter, &kill_switch, src_mac, src_ip, dst_mac, &ports)?;
                (Layer::L4, "syn-scan-fanout", "napse-dpi", Severity::Amber, stats.frames_sent, stats.aborted_reason)
            }
            ProbeKind::StateExhaust => {
                let target_lit = cli.target.clone().context("--probe state-exhaust requires --target")?;
                let target = guard.validate_l3_literal(&target_lit, &cli.iface)?;
                let src_mac = iface_mac(&cli.iface)?;
                let stats = syn_scan::run_state_exhaustion(&target, &limiter, &kill_switch, src_mac, dst_mac, cli.count, cli.dst_port)?;
                (Layer::L4, "syn-flood-state-exhaustion", "napse-quarantine", Severity::Red, stats.frames_sent, stats.aborted_reason)
            }
        };

    if let Some(reason) = &aborted {
        eprintln!("redteam-engine: probe aborted mid-campaign (fail-closed): {reason}");
    }
    println!("redteam-engine: probe {probe_name} sent {frames_sent} frame(s) on {}", cli.iface);

    // Verify-fired: read the DUT's OWN telemetry. Never assume; an unreadable/missing events file
    // is honestly `inconclusive`, never a fabricated withstand (D6).
    let (verified_fired, claimed_outcome, evidence_ref) = match &cli.events {
        Some(p) => match std::fs::read_to_string(p) {
            Ok(text) => {
                let matched = if cli.verify_substr.is_empty() {
                    None
                } else {
                    text.lines().rfind(|l| l.contains(cli.verify_substr.as_str())).map(|l| l.to_string())
                };
                match matched {
                    Some(line) => (true, Outcome::Withstood, line.chars().take(120).collect::<String>()),
                    None => (true, Outcome::Breached, format!("no line containing {:?} found in {}", cli.verify_substr, p.display())),
                }
            }
            Err(e) => (false, Outcome::Inconclusive, format!("could not read {}: {e}", p.display())),
        },
        None => (false, Outcome::Inconclusive, "no --events path supplied -- cannot verify defense fired".to_string()),
    };

    let finding = Finding::new(
        format!("finding:{}:{}", run.id, probe_name),
        run.id.clone(),
        now_iso8601(),
        layer,
        probe_name.to_string(),
        target_component.to_string(),
        claimed_outcome,
        severity,
        verified_fired,
        evidence_ref,
        None,
        cli.seed,
        None,
    );
    campaign.record_finding(&finding)?;
    let final_run = campaign.finish(run, std::slice::from_ref(&finding))?;

    println!(
        "redteam-engine: finding outcome={:?} severity={:?} verified_fired={} -> attack_run verdict={:?}",
        finding.outcome, finding.severity, finding.verified_fired, final_run.verdict
    );
    if finding.blocks_gate_r() {
        eprintln!("redteam-engine: RED -- this finding would block Gate R");
        std::process::exit(1);
    }
    Ok(())
}

/// The interface's own IPv4 address (from `ip -4 -j addr show`), so a crafted frame's source IP is
/// a real address this box actually owns on this interface, never a guess.
fn first_ipv4_of_iface(iface: &str) -> Result<[u8; 4]> {
    let out = std::process::Command::new("ip")
        .args(["-4", "-j", "addr", "show", "dev", iface])
        .output()
        .with_context(|| format!("exec `ip -4 -j addr show dev {iface}`"))?;
    if !out.status.success() {
        bail!("`ip addr show dev {iface}` failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let addr = v[0]["addr_info"][0]["local"].as_str().with_context(|| format!("no IPv4 address on {iface}"))?;
    let parts: Vec<u8> = addr.split('.').map(|s| s.parse().unwrap_or(0)).collect();
    if parts.len() != 4 {
        bail!("unexpected address shape {addr:?} on {iface}");
    }
    Ok([parts[0], parts[1], parts[2], parts[3]])
}
