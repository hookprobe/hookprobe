//! `hookprobe-dns-sinkhole` CLI — regenerate the DNS sinkhole/RPZ artifacts from dnsxai's
//! `BLOCK_INSTANT` verdicts + HYDRA's bundled domain IOCs, and record each newly-sinkholed (and
//! newly-released) domain into the evidence graph's `/var/lib/hookprobe/responses` stream.
//!
//! Driven by `hookprobe-dns-sinkhole.timer` (mirrors `hookprobe-hydra.timer`'s cadence pattern).
//! Every input is read best-effort: a missing/malformed file degrades to "no signal from that
//! source this pass," never a hard failure — this binary must never crash the timer it runs
//! under (same "fail toward not sinkholing" discipline the library crate documents).
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

use hookprobe_dns_sinkhole::{
    build_sinkhole_set, diff_state, hydra_domain_indicators, render_response_json, render_revert_json,
    render::{render_dnsmasq_conf, render_rpz},
    Allowlist, AllowlistConfig,
};
use hookprobe_hydra::feed::IocFeed;

#[derive(Parser, Debug)]
#[command(
    name = "hookprobe-dns-sinkhole",
    about = "DNS sinkhole / RPZ enforcement (roadmap A1) — dnsxai BLOCK_INSTANT + HYDRA domain IOCs, allowlist-guarded"
)]
struct Args {
    /// dnsxai's DNS/DGA verdict stream (JSON lines, `modules/dnsxai`'s stdout).
    #[arg(long, default_value = "/var/lib/hookprobe/dns-verdicts")]
    verdicts: PathBuf,
    /// The bundled HYDRA IOC feed (`hookprobe-ioc-v1`) — the same file `hookprobe-hydra` reads.
    #[arg(long, default_value = "/usr/share/hookprobe/threat-intel/ioc-feed.json")]
    hydra_feed: PathBuf,
    /// Operator-owned allowlist (never generated/overwritten by this binary).
    #[arg(long, default_value = "/etc/hookprobe/dns-sinkhole-allowlist.yaml")]
    allowlist: PathBuf,
    /// Directory the RPZ zone + dnsmasq conf + this generator's own state are written to.
    #[arg(long, default_value = "/var/lib/hookprobe/dns-sinkhole")]
    out_dir: PathBuf,
    /// Evidence-graph response stream (`hookprobe-evidence --responses` already tails this).
    #[arg(long, default_value = "/var/lib/hookprobe/responses")]
    responses: PathBuf,
    /// TTL recorded on each ACTIVE sinkhole response record (informational — the RPZ/dnsmasq
    /// artifacts themselves are regenerated fresh every pass, so the real enforcement window is
    /// "until this domain drops out of the merged signal set," not this value; it documents the
    /// evidence record's own claimed window, matching `scan_responder`'s TTL field discipline).
    #[arg(long, default_value_t = 3600)]
    ttl_secs: u64,
    /// Print a JSON summary to stdout (counts only — the artifacts themselves are the files).
    #[arg(long)]
    print: bool,
}

fn now_ts() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Load the previous pass's `domain -> first_sinkholed_ts` state. Any failure (missing file,
/// corrupt JSON) degrades to "no prior state" — every currently-sinkholed domain is then treated
/// as newly-added this pass (one extra evidence record, never a crash or a lost enforcement).
fn load_state(path: &std::path::Path) -> BTreeMap<String, f64> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
        Err(_) => BTreeMap::new(),
    }
}

fn save_state(path: &std::path::Path, state: &BTreeMap<String, f64>) -> Result<()> {
    let json = serde_json::to_string_pretty(state)?;
    std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))
}

fn main() -> Result<()> {
    let args = Args::parse();

    // ---- inputs, every one degrading gracefully ----------------------------------------------
    let verdict_text = match std::fs::read_to_string(&args.verdicts) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "hookprobe-dns-sinkhole: {} unreadable ({e}) — sinkholing from HYDRA signal only this pass",
                args.verdicts.display()
            );
            String::new()
        }
    };

    let hydra_domains = match IocFeed::load(&args.hydra_feed) {
        Ok(feed) => hydra_domain_indicators(&feed),
        Err(e) => {
            eprintln!(
                "hookprobe-dns-sinkhole: HYDRA feed {} unavailable ({e}) — sinkholing from dnsxai signal only this pass",
                args.hydra_feed.display()
            );
            Vec::new()
        }
    };

    let allow_cfg = match std::fs::read_to_string(&args.allowlist) {
        Ok(text) => AllowlistConfig::parse(&text).unwrap_or_else(|e| {
            eprintln!(
                "hookprobe-dns-sinkhole: allowlist {} malformed ({e}) — falling back to the BUILT-IN safety net only \
                 (never to an empty/wide-open allowlist)",
                args.allowlist.display()
            );
            AllowlistConfig::default()
        }),
        Err(_) => AllowlistConfig::default(), // no operator file yet — builtin floor still applies
    };
    let allowlist = Allowlist::new(&allow_cfg.domains);

    // ---- merge + filter ------------------------------------------------------------------------
    let entries = build_sinkhole_set(verdict_text.lines(), &hydra_domains, &allowlist);

    // ---- render + write the resolver-facing artifacts (always, even if empty) ------------------
    std::fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("creating {}", args.out_dir.display()))?;
    let now = now_ts();
    let rpz = render_rpz(&entries, now as u64);
    std::fs::write(args.out_dir.join("hookprobe-sinkhole.rpz"), &rpz)
        .with_context(|| "writing hookprobe-sinkhole.rpz".to_string())?;
    let dnsmasq = render_dnsmasq_conf(&entries);
    std::fs::write(args.out_dir.join("hookprobe-sinkhole.dnsmasq.conf"), &dnsmasq)
        .with_context(|| "writing hookprobe-sinkhole.dnsmasq.conf".to_string())?;

    // ---- evidence-graph track & trace: only NEW/REVERTED domains get a fresh record ------------
    let state_path = args.out_dir.join("state.json");
    let prev_state = load_state(&state_path);
    let diff = diff_state(&entries, &prev_state, now);

    if !diff.newly_added.is_empty() || !diff.reverted_domains.is_empty() {
        let mut resp_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&args.responses)
            .with_context(|| format!("opening {}", args.responses.display()))?;
        for e in &diff.newly_added {
            writeln!(resp_file, "{}", render_response_json(e, args.ttl_secs, now))?;
        }
        for d in &diff.reverted_domains {
            writeln!(resp_file, "{}", render_revert_json(d, now))?;
        }
    }
    save_state(&state_path, &diff.next_state)?;

    eprintln!(
        "hookprobe-dns-sinkhole: {} domain(s) sinkholed ({} dnsxai signal(s), {} HYDRA domain IOC(s) before merge/allowlist) \
         — {} newly added, {} reverted this pass",
        entries.len(),
        verdict_text.lines().filter(|l| hookprobe_dns_sinkhole::parse_dnsxai_block_instant(l).is_some()).count(),
        hydra_domains.len(),
        diff.newly_added.len(),
        diff.reverted_domains.len(),
    );
    if args.print {
        println!(
            "{}",
            serde_json::json!({
                "sinkholed": entries.len(),
                "newly_added": diff.newly_added.len(),
                "reverted": diff.reverted_domains.len(),
            })
        );
    }
    Ok(())
}
