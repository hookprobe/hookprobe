//! HookProbe Supervisor — level-triggered, idempotent module reconciler.
//!
//! Reads a signed Platform Manifest + module definitions and reconciles desired
//! modules against the device's granted capabilities and resource budget
//! (Architecture.md C9-C11).
//!
//! `runtime: wasm` modules load for real (Wasmtime, epoch + StoreLimits, capability-sandboxed —
//! `wasm_loader.rs`, built with `--features wasm`; ADR 0009 build step 1). `runtime: container`
//! modules still have no loader (Podman/Quadlet is a future build step) — reconcile resolves their
//! desired state but nothing executes them yet.
//! TODO: Podman/Quadlet for `runtime: container`; enforce budgets at the cgroup layer.

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;

#[cfg(feature = "wasm")]
mod wasm_loader;

use hookprobe_manifest::fleet;
use hookprobe_manifest::module_def::ModuleDef;
use hookprobe_manifest::module_sig;
use hookprobe_manifest::health::{run_health, HealthPolicy, HealthProbe, HealthState};
use hookprobe_manifest::supervisor::reconcile;
use hookprobe_manifest::Manifest;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// HookProbe supervisor/reconciler (Rust implementation).
///
/// Mirrors `supervisor/reference/supervisor.py` CLI.
#[derive(Parser)]
#[command(name = "hookprobe-supervisor", version, about)]
struct Cli {
    /// Signed Platform Manifest JSON path. Optional only for `--run-wasm`.
    manifest: Option<PathBuf>,

    /// Modules directory (default: auto-locate modules/ from manifest path).
    #[arg(long)]
    modules: Option<PathBuf>,

    /// Write reconciled manifest to this path.
    #[arg(long)]
    write: Option<PathBuf>,

    /// PRODUCTION: run module <id> as the live sandboxed SOC datapath (streaming stdin→stdout, WASI
    /// preopens from its grants). E.g. `tail -F flows | hookprobe-supervisor --run-wasm napse >> events`.
    #[cfg(feature = "wasm")]
    #[arg(long)]
    run_wasm: Option<String>,

    /// AOT precompile mode (ADR 0009 build step 1): `<id>` or `all` — write `.cwasm` next to the
    /// resolved `.wasm` (or under --precompile-out) for ~1-5ms cold start on later loads. Exits
    /// after precompiling; no manifest required.
    #[cfg(feature = "wasm")]
    #[arg(long)]
    precompile: Option<String>,

    /// With --precompile: write the `.cwasm` (+ sha256 sidecar) under this dir instead of next to
    /// the source `.wasm`. Use this on-device (e.g. `/var/lib/hookprobe/modules-cache`) since the
    /// `.wasm`'s directory may be the read-only rootfs (`/usr/lib/hookprobe/modules/`).
    #[cfg(feature = "wasm")]
    #[arg(long = "precompile-out")]
    precompile_out: Option<PathBuf>,

    /// Demo: module(s) whose self-test always fails (→ shed). Repeatable.
    #[arg(long)]
    fail: Vec<String>,

    /// Demo: module(s) that fail self-test once then pass (→ heal). Repeatable.
    #[arg(long)]
    flaky: Vec<String>,

    /// Demo: data-plane module(s) that lose the management path (→ revert). Repeatable.
    #[arg(long = "cut-net")]
    cut_net: Vec<String>,

    /// Demo: module(s) whose resource budget is always breached (simulated cgroup OOM-kill /
    /// wasm fuel exhaustion) → bounded restart-with-backoff, then graceful shed + a
    /// `ResourceBudget` evidence event (resource-budgets feature). Repeatable.
    #[arg(long = "oom")]
    oom: Vec<String>,

    /// DEV: simulate off-device release signing — sign all modules with the release
    /// key at this path (created if absent) and write its pubkey to the trust store.
    #[arg(long = "sign-modules")]
    sign_modules: Option<PathBuf>,

    /// Trusted public-key dir (*.pub) for module verification. Default: <modules>/.trust
    #[arg(long)]
    trust: Option<PathBuf>,

    /// Fleet GitOps: diff this desired-state hookprobe.yaml against the live device.
    #[arg(long)]
    fleet: Option<PathBuf>,

    /// Fleet rollout state (ADR 0012 D2/build-step-3): `fleet/rollout.yaml`-shaped
    /// file naming which rings a promoted digest has reached, per channel. Only
    /// meaningful with `--fleet`. Absent = legacy behavior (every channel mismatch
    /// is actionable, no ring window enforced) — see `fleet::diff_ring_gated`.
    #[arg(long)]
    rollout: Option<PathBuf>,

    /// Boot-health gate (greenboot): print a verdict and exit non-zero if the
    /// baseline SOC isn't healthy, so a bad image is rolled back (`bootc rollback`).
    #[arg(long = "health-gate")]
    health_gate: bool,

    /// Modules that MUST be running+healthy for a healthy boot (default: napse, hydra). Repeatable.
    #[arg(long = "require")]
    require: Vec<String>,

    /// Reconcile the multi-WAN failover plan from `network.uplinks` + intent, print the
    /// generated networkd drop-ins, and exit. (Config is a generated artifact.)
    #[arg(long = "wan-plan")]
    wan_plan: bool,

    /// Operator WAN intent YAML (disable/prefer uplinks). Optional; default = manifest order.
    #[arg(long = "wan-intent")]
    wan_intent: Option<PathBuf>,

    /// With --wan-plan: write the generated drop-ins under this networkd root instead of printing.
    #[arg(long = "wan-write")]
    wan_write: Option<PathBuf>,

    /// Decide where the persistent data partition goes (enforces removable-media policy)
    /// from `hardware.storage`, print the decision, and exit.
    #[arg(long = "data-plan")]
    data_plan: bool,

    /// Boot disk bare name for --data-plan (e.g. nvme0n1). Default: auto-detect from `/`.
    #[arg(long = "boot-dev")]
    boot_dev: Option<String>,

    /// Reconcile the Wi-Fi radio config (station→wpa_supplicant, AP→hostapd) from
    /// `network.wifi_radios` + intent, print the generated config, and exit.
    #[arg(long = "wifi-plan")]
    wifi_plan: bool,

    /// Operator Wi-Fi intent YAML (station/ap SSIDs, channel, band, country). Optional.
    #[arg(long = "wifi-intent")]
    wifi_intent: Option<PathBuf>,

    /// With --wifi-plan: write the generated config files under this dir instead of printing.
    #[arg(long = "wifi-write")]
    wifi_write: Option<PathBuf>,

    /// Reconcile the network fabric (OVS LAN bridge / segments / MAC-binding flows /
    /// mirror, or cloud VRF segments) from the manifest + intent, print it, and exit.
    #[arg(long = "fabric-plan")]
    fabric_plan: bool,

    /// Operator fabric intent YAML (kind, bridge, segments, mac_bindings, mirror_to).
    #[arg(long = "fabric-intent")]
    fabric_intent: Option<PathBuf>,

    /// With --fabric-plan: write the generated plan files under this dir instead of printing.
    #[arg(long = "fabric-write")]
    fabric_write: Option<PathBuf>,

    /// Classify observed devices (JSON array of observations: mac/hostname/vendor_class/
    /// dhcp_opt55/mdns_services) into device class + suggested segment, and exit. This is
    /// MAC-independent identity — the "who has what" that MAC filtering can't see.
    #[arg(long = "classify")]
    classify: Option<PathBuf>,

    /// AEGIS auto-segmentation: read a dnsmasq leases file, identify each device, and
    /// emit the segment DECISION (segment + enforcement mechanism) + a ready fabric
    /// mac_bindings fragment. The live identity→AEGIS→fabric loop.
    #[arg(long = "auto-segment")]
    auto_segment: Option<PathBuf>,

    /// Enrich --auto-segment with mDNS (`avahi-browse -p -r` output file).
    #[arg(long = "mdns")]
    mdns: Option<PathBuf>,

    /// Enrich --auto-segment with a dnsmasq DHCP log (`log-dhcp`) for vendor-class (opt 60).
    #[arg(long = "dhcp-log")]
    dhcp_log: Option<PathBuf>,

    /// Reconcile microsegmentation (east-west isolation inside a segment) from
    /// --fabric-intent (segments) + --microseg-intent (policies); print and exit.
    #[arg(long = "microseg-plan")]
    microseg_plan: bool,

    /// Operator microsegmentation intent YAML (gateway + per-segment policies).
    #[arg(long = "microseg-intent")]
    microseg_intent: Option<PathBuf>,

    /// Continuous trust: evaluate live posture signals (JSON array: mac/current_segment/
    /// risk/threat from QSECBIT/HYDRA) and emit dynamic quarantine override flows.
    #[arg(long = "trust-eval")]
    trust_eval: Option<PathBuf>,

    /// Continuous-trust policy YAML (risk thresholds + quarantine segment/vlan). Optional.
    #[arg(long = "trust-policy")]
    trust_policy: Option<PathBuf>,

    /// Build trust posture from the LIVE detection plane: `arp-status.json` (presence).
    /// Triggers trust mode; combine with --blocked / --prev-quarantined.
    #[arg(long = "arp")]
    arp: Option<PathBuf>,

    /// Threat list for the live feed (`blocked_macs.json`-style JSON array of MACs).
    #[arg(long = "blocked")]
    blocked: Option<PathBuf>,

    /// ADR 0023 task #19 / ADR 0027 Layer-1: HYDRA's corroboration-gated per-device intel
    /// verdicts (`hookprobe-hydra --verdicts-out`, JSON lines — device_ip/threat/risk/enforce/
    /// reasons). Folded into the live posture as `IntelOnly` signals; a single/uncorroborated hit
    /// can never quarantine on its own (see `trust::evaluate`'s `intel_requires_corroboration`).
    /// Optional — omit for zero HYDRA intel input (unchanged prior behavior).
    #[arg(long = "hydra-verdicts")]
    hydra_verdicts: Option<PathBuf>,

    /// Previously-quarantined MACs (JSON array) → emit a convergent add/remove reconcile.
    #[arg(long = "prev-quarantined")]
    prev_quarantined: Option<PathBuf>,

    /// Quarantine STATE file (JSON array): read as the previous set AND rewritten with the
    /// new set — the self-contained continuous loop. Takes precedence over --prev-quarantined.
    #[arg(long = "quarantine-state")]
    quarantine_state: Option<PathBuf>,

    /// Bridge name substituted into the generated `ovs-ofctl` reconcile commands.
    #[arg(long = "bridge", default_value = "hp-br0")]
    bridge: String,

    /// AEGIS: reconcile the WHOLE network intent (hookprobe.yaml `network:` — WAN + Wi-Fi
    /// + fabric + microseg + trust) into all artifacts in one pass; print the plan-as-diff.
    #[arg(long = "reconcile-network")]
    reconcile_network: Option<PathBuf>,

    /// With --reconcile-network: write every generated artifact under this dir (else print).
    #[arg(long = "network-write")]
    network_write: Option<PathBuf>,

    /// DEV ONLY: proceed even if the manifest is UNSIGNED. By default an unsigned manifest
    /// is REFUSED (an attacker stripping the signature must not be a silent downgrade).
    #[arg(long = "allow-unsigned")]
    allow_unsigned: bool,

    /// ADR 0002 crypto-agility DISPATCH for module signing on the manifest-less `--run-wasm` path
    /// (the reconcile path instead reads the loaded manifest's own `crypto.module_signing` — see
    /// `main()`). Named suite from `hookprobe_manifest::crypto::crypto_suite`; its
    /// `module_signing` legs are the ones a `signature: required` module must satisfy — e.g. the
    /// default hybrid suite requires BOTH ml-dsa-65 AND ed25519 (fail-closed, no downgrade), while
    /// `hookprobe-ed25519-only-legacy` requires only ed25519. This is a POLICY switch, never a
    /// code change (ADR 0002 §"crypto-agility mechanism").
    #[arg(long = "crypto-suite", default_value = "hookprobe-pqc-hybrid-2026")]
    crypto_suite: String,

    /// ADR 0016: populate/refresh each declared `artifacts[].digest.value` IN PLACE in
    /// `modules/<id>/module.yaml` (the module author declares `path`+`role` by hand once; this
    /// tool only ever recomputes `value` from the bytes actually on disk). `<id>` or `all`. Run
    /// BEFORE `--sign-modules` (builder/sign-release.sh enforces the order) so the signature
    /// covers the FINAL bytes. Exits before requiring a manifest, like `--precompile`.
    #[arg(long = "write-artifact-digests")]
    write_artifact_digests: Option<String>,

    /// ADR 0016/0017 release gate: recompute + compare every declared (non-`aot`) artifact
    /// digest against the bytes actually resolvable in THIS environment — `<id>` or `all` — and
    /// exit non-zero iff at least one is a genuine MISMATCH (tamper) or a `signature: required`
    /// module declares NO executing-payload (`role: executable`/`loader`) digest at all (D5,
    /// unprotected payload). A digest that is a recognized placeholder (`PENDING`/`TODO`/
    /// `DEADBEEF`/empty) or whose source cannot be resolved/read in this environment (e.g. a
    /// cross-arch native binary with no cross-toolchain here) is reported LOUDLY but is NOT a
    /// failure — it is the honest "populated at the real per-arch release build" tracked state
    /// `builder/release-pass.sh`/`builder/verify-staging.sh` consume instead of hard-aborting.
    /// `status: stub` modules and `signature: unsigned` modules are exempt. Exits before
    /// requiring a manifest, like `--write-artifact-digests`.
    #[arg(long = "check-artifact-digests")]
    check_artifact_digests: Option<String>,

    /// Events file an ADR 0016 `ArtifactTamper` evidence event is appended to on a payload-digest
    /// mismatch (JSON lines — the same stream `hookprobe-evidence --events` ingests). Falls back
    /// to env `HOOKPROBE_EVENTS`, then `/var/lib/hookprobe/events`.
    #[arg(long = "events")]
    events: Option<PathBuf>,

    /// Conntrack flow stream (JSONL, `type:conn` records) for --scan-respond's F4 fallback
    /// confirmation: a source with an ESTABLISHED conntrack flow to this DUT is confirmed even if
    /// the mirror-fed handshake tracker missed it — so a mirror failure (F1 class) can no longer
    /// disable ALL enforcement. Default `/var/lib/hookprobe/flows`.
    #[arg(long = "flows")]
    flows: Option<PathBuf>,

    // --- AEGIS reflex: scan-responder (ENRICH / DROP / DOCUMENT a NAPSE port-scan) ---------

    /// AEGIS reflex: read NAPSE port-scan alert lines from stdin (one JSON event per line —
    /// `tail -F /var/lib/hookprobe/events`), ENRICH the scanner (host intel), DROP it via a
    /// deterministic nft quarantine (TTL auto-revert, mgmt-path allowlisted, idempotent), and
    /// print one response JSON line per alert to stdout for `hookprobe-evidence --responses`.
    /// Long-running, like `--run-wasm`'s stdin loop.
    #[arg(long = "scan-respond")]
    scan_respond: bool,

    /// One-shot: TTL-sweep the quarantine state (release any scanner quiet for
    /// `--quarantine-ttl-secs`) — run from a timer so quarantine auto-reverts even with no new
    /// scans. Shares the exact same expiry logic as `--scan-respond`'s per-alert reconcile.
    #[arg(long = "scan-respond-sweep")]
    scan_respond_sweep: bool,

    /// Quarantine TTL (auto-revert window), seconds. Falls back to env `QUARANTINE_TTL_SECS`,
    /// then 300.
    #[arg(long = "quarantine-ttl-secs")]
    quarantine_ttl_secs: Option<u64>,

    /// Quarantine state file (JSON), persisted across invocations for TTL auto-revert AND
    /// idempotent re-quarantine (a scanner still actively probing refreshes, not re-adds).
    #[arg(long = "quarantine-state-file")]
    quarantine_state_file: Option<PathBuf>,

    /// Host-intel output dir: one JSON per scanner (MAC, OUI vendor, hostname, class, scan facts).
    #[arg(long = "host-intel-dir")]
    host_intel_dir: Option<PathBuf>,

    /// dnsmasq leases file, for hostname-by-IP enrichment (same format as --auto-segment).
    #[arg(long = "dnsmasq-leases")]
    dnsmasq_leases: Option<PathBuf>,

    /// Management/self CIDR that must NEVER be quarantined (repeatable). Default: 10.200.0.0/28.
    #[arg(long = "protect-cidr")]
    protect_cidr: Vec<String>,

    /// Exact management/gateway/WAN IP that must NEVER be quarantined (repeatable). Default:
    /// 10.66.0.1 (the LAN gateway); the WAN default gateway and configured DNS resolver(s) are
    /// added automatically at startup (2026-07-05 threat-model fix HIGH #4 — a WAN attacker
    /// spoofing exactly those addresses to trigger self-quarantine of this device's own upstream
    /// is the concrete DoS this closes) unless `--no-auto-protect-upstream` is passed.
    #[arg(long = "protect-ip")]
    protect_ip: Vec<String>,

    /// 2026-07-05 threat-model fix (HIGH #5): known-good MAC(s) (lowercase colon-hex, repeatable)
    /// for the LAN-side addresses in `--protect-ip`/`--protect-cidr` (typically the real LAN
    /// gateway's MAC). Once ANY are configured, a LAN-classified source claiming a protected IP
    /// from a DIFFERENT mac is NOT exempted from quarantine — see
    /// `scan_responder::ProtectPolicy::lan_macs`. Left empty by default (permissive, IP-only
    /// matching — today's behavior) until an operator configures the real binding.
    #[arg(long = "protect-mac")]
    protect_mac: Vec<String>,

    /// Skip auto-adding the resolved WAN default gateway + `/etc/resolv.conf` nameservers to the
    /// protect-ip set. Off by default — auto-protecting the live upstream is the safe default.
    #[arg(long = "no-auto-protect-upstream")]
    no_auto_protect_upstream: bool,

    /// `ip route show default` output file (else the live command is run). Dev/test fixture.
    #[arg(long = "gateway-route-file")]
    gateway_route_file: Option<PathBuf>,

    /// `/etc/resolv.conf` path override (dev/test fixture / non-standard resolver config location).
    #[arg(long = "resolv-conf")]
    resolv_conf: Option<PathBuf>,

    /// LAN/AP interface the LAN-side quarantine (ip+mac) is scoped to. Falls back to env
    /// `LAN_IFACE`, then `wlan0` (the routed AP on this Pi 4 — `hp-br0` is down).
    #[arg(long = "lan-iface")]
    lan_iface: Option<String>,

    /// WAN uplink interface the WAN-side quarantine (ip-only) is scoped to. Falls back to env
    /// `WAN_IFACE`, then `end0`.
    #[arg(long = "wan-iface")]
    wan_iface: Option<String>,

    /// D12 fix (2026-07-07 enforcement-separation audit): the `hookprobe_manifest::l2_responder::
    /// PortRole` of `--lan-iface` — `"access"` (a genuine single-client port; keeps the strict
    /// mac-flood storm-control meter) or `"uplink"` (an AP/LAN-bridge serving many legitimate
    /// clients; the mac-flood meter is not installed at all — see `l2_responder::render_storm_
    /// control`'s doc). Falls back to env `LAN_PORT_ROLE`, then the manifest-derived default via
    /// `l2_responder::PortRole::default()` (`uplink` — matches `--lan-iface`'s own default `wlan0`,
    /// an AP radio).
    #[arg(long = "lan-port-role")]
    lan_port_role: Option<String>,

    /// 2026-07-05 VERIFY-pass re-audit (Q5 fix): exact override for this device's OWN WAN-side
    /// address(es) (repeatable) — used ONLY for `scan_responder::is_wan_ingress_martian`'s
    /// `wan_self_ips`, a DEDICATED list, never `--protect-ip` (the mgmt/gateway/resolver
    /// allowlist). Conflating the two previously let a LAN attacker scanning the gateway/resolver
    /// itself evade enforcement (see ADR 0018's Q5 correction). When empty (the default), the
    /// live address is auto-resolved from `ip -4 -o addr show dev <wan-iface>`.
    #[arg(long = "wan-self-ip")]
    wan_self_ip: Vec<String>,

    /// `ip -4 -o addr show dev <wan-iface>` output file (else the live command is run). Dev/test
    /// fixture, mirrors `--gateway-route-file`.
    #[arg(long = "wan-addr-file")]
    wan_addr_file: Option<PathBuf>,

    /// HYDRA threat-intel feeds dir (the SAME CIDR feeds `hydra-feedsync` parses into the BPF
    /// blocklist, ADR 0005) — used for WAN-scanner reputation lookup. Falls back to env
    /// `FEEDS_DIR`, then `/var/lib/hookprobe/feeds`.
    #[arg(long = "feeds-dir")]
    feeds_dir: Option<PathBuf>,

    /// Actually execute the generated `nft` commands. Without this, --scan-respond/--sweep only
    /// PRINT the plan to stderr — a safe default mirroring `trust-reconcile.sh`'s never-`eval`,
    /// print-first discipline.
    #[arg(long = "apply")]
    apply: bool,

    // --- AEGIS RESOURCE-SHED reflex (2026-07-07) — resource-REALITY enforcement, never identity.
    // See `hookprobe_manifest::scan_responder`'s "RESOURCE-REALITY ENFORCEMENT" section doc for
    // the full design: Layer 1 (blanket per-source new-conn-rate cap, always-on), Layer 2
    // (conntrack-saturation-triggered per-top-talker cap), Layer 3 (sustained-PSI-triggered
    // per-top-talker cap) — Layers 2/3 share one dynamic `shed_ips` nft set/state file. One-shot,
    // timer-driven (like `--scan-respond-sweep`) rather than a stdin tail-loop: there is no alert
    // STREAM to tail here, only live resource facts to re-sample each cycle.
    /// One-shot: re-sample conntrack fill + PSI pressure, decide this cycle's Layer-2/3 shed
    /// triggers, reconcile the dynamic `shed_ips` nft set (add/refresh/TTL-revert), and (re-)apply
    /// Layer 1's blanket per-source new-connection-rate cap bootstrap (idempotent — safe to
    /// re-apply every cycle). Run from a timer (`hookprobe-resource-shed.timer`).
    #[arg(long = "resource-shed-reconcile")]
    resource_shed_reconcile: bool,

    /// Resource-shed state file (JSON) — Layer 2/3's persisted `ShedEntry` list, for TTL
    /// self-revert and idempotent refresh (mirrors `--quarantine-state-file`'s role).
    #[arg(long = "resource-shed-state-file")]
    resource_shed_state_file: Option<PathBuf>,

    /// Layer 2/3 shed TTL (self-revert window), seconds. Falls back to env
    /// `RESOURCE_SHED_TTL_SECS`, then [`hookprobe_manifest::scan_responder::DEFAULT_SHED_TTL_SECS`].
    #[arg(long = "resource-shed-ttl-secs")]
    resource_shed_ttl_secs: Option<u64>,

    /// Layer 1's blanket per-source new-connection ceiling, packets/second (any protocol). Falls
    /// back to env `RESOURCE_SHED_NEW_CONN_PPS`, then `DEFAULT_NEW_CONN_PPS` (400 — see that
    /// constant's doc for the "err toward not dropping" rationale).
    #[arg(long = "new-conn-pps")]
    new_conn_pps: Option<u32>,

    /// Layer 2/3's stricter per-source cap once a source is in the `shed_ips` set, packets/second.
    /// Falls back to env `RESOURCE_SHED_CAP_PPS`, then `DEFAULT_SHED_CAP_PPS` (50).
    #[arg(long = "shed-cap-pps")]
    shed_cap_pps: Option<u32>,

    /// Conntrack table fill percentage (0..100) at/above which Layer 2 considers the box under a
    /// real resource wall. Falls back to env `RESOURCE_SHED_CONNTRACK_SATURATION_PCT`, then
    /// `DEFAULT_CONNTRACK_SATURATION_PCT` (80.0).
    #[arg(long = "conntrack-saturation-pct")]
    conntrack_saturation_pct: Option<f64>,

    /// Minimum CONCURRENT conntrack entries a source must hold to be considered a top-talker
    /// candidate during saturation (the "many small fish" guard). Falls back to env
    /// `RESOURCE_SHED_TOP_TALKER_MIN_ENTRIES`, then `DEFAULT_TOP_TALKER_MIN_ENTRIES` (200).
    #[arg(long = "top-talker-min-entries")]
    top_talker_min_entries: Option<u64>,

    /// Sustained (`avg60`) CPU `some`-line PSI percentage at/above which Layer 3 considers the box
    /// genuinely CPU-pressured. Falls back to env `RESOURCE_SHED_CPU_AVG60_PCT`, then
    /// `DEFAULT_CPU_SOME_AVG60_PCT` (40.0).
    #[arg(long = "cpu-pressure-avg60-pct")]
    cpu_pressure_avg60_pct: Option<f64>,

    /// Sustained (`avg60`) memory `full`-line PSI percentage at/above which Layer 3 considers the
    /// box genuinely, fully memory-pressured ("maxing out RAM"). Falls back to env
    /// `RESOURCE_SHED_MEM_AVG60_PCT`, then `DEFAULT_MEM_FULL_AVG60_PCT` (15.0).
    #[arg(long = "mem-pressure-avg60-pct")]
    mem_pressure_avg60_pct: Option<f64>,

    /// `/proc/pressure/cpu` path override (dev/test fixture; else the live file is read).
    #[arg(long = "psi-cpu-file")]
    psi_cpu_file: Option<PathBuf>,

    /// `/proc/pressure/memory` path override (dev/test fixture; else the live file is read).
    #[arg(long = "psi-mem-file")]
    psi_mem_file: Option<PathBuf>,

    /// `/proc/sys/net/netfilter/nf_conntrack_count` path override (dev/test fixture).
    #[arg(long = "conntrack-count-file")]
    conntrack_count_file: Option<PathBuf>,

    /// `/proc/sys/net/netfilter/nf_conntrack_max` path override (dev/test fixture).
    #[arg(long = "conntrack-max-file")]
    conntrack_max_file: Option<PathBuf>,

    /// A conntrack table dump text file (`conntrack -L`/`/proc/net/nf_conntrack`-style, one entry
    /// per line) for top-talker identification — dev/test fixture. Without this, the live
    /// `/proc/net/nf_conntrack` is read (best-effort — absent/unreadable degrades to "no
    /// visibility", never a fabricated source, per `evaluate_resource_reality`'s doc).
    #[arg(long = "conntrack-dump-file")]
    conntrack_dump_file: Option<PathBuf>,
}

/// Health probe driven by the demo flags. The shipping supervisor probes the live
/// module (Wasmtime/Podman) and queries the actual management path instead.
struct DemoProbe {
    fail: Vec<String>,
    flaky: Vec<String>,
    cut_net: Vec<String>,
    oom: Vec<String>,
    seen: std::collections::HashMap<String, u32>,
}
impl HealthProbe for DemoProbe {
    fn self_test(&mut self, id: &str, _rt: &hookprobe_manifest::types::Runtime) -> Result<(), String> {
        let n = self.seen.entry(id.to_string()).or_insert(0);
        *n += 1;
        if self.fail.iter().any(|x| x == id) {
            return Err("simulated persistent self-test failure".to_string());
        }
        if self.flaky.iter().any(|x| x == id) && *n == 1 {
            return Err("simulated transient failure".to_string());
        }
        Ok(())
    }
    fn verify_connectivity(&mut self, after_id: &str) -> Result<(), String> {
        if self.cut_net.iter().any(|x| x == after_id) {
            Err("management path unreachable".to_string())
        } else {
            Ok(())
        }
    }
    // Resource-budgets feature: --oom <id> simulates a persistent budget breach (cgroup
    // OOM-kill / wasm fuel exhaustion) the same way --fail simulates a persistent self-test
    // failure — the shipping supervisor instead queries the real enforcement layer (systemd
    // unit `Result=oom-kill`, or a `ResourceBudget` event this module's own run already emitted).
    fn check_resource_budget(&mut self, id: &str, _rt: &hookprobe_manifest::types::Runtime) -> Result<(), String> {
        if self.oom.iter().any(|x| x == id) {
            Err("simulated cgroup MemoryMax exceeded (oom-kill)".to_string())
        } else {
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();

    // PRODUCTION streaming run — the sandboxed engine as the live SOC datapath. Runs before (and
    // without needing) the manifest, so it drops into a `tail -F flows | ... >> events` systemd pipe.
    #[cfg(feature = "wasm")]
    if let Some(id) = cli.run_wasm.clone() {
        let modules_dir = cli.modules.clone().unwrap_or_else(|| PathBuf::from("modules"));
        let module_dir = modules_dir.join(&id);
        let ypath = module_dir.join("module.yaml");
        let ytext = std::fs::read_to_string(&ypath)
            .with_context(|| format!("reading {}", ypath.display()))?;
        let mut def: ModuleDef = serde_yaml::from_str(&ytext).context("parse module.yaml")?;

        // Verify-before-run (the security fix this gap closes): the production streaming
        // datapath must not execute an unverified module. Mirror EXACTLY the cosign-style gate
        // reconcile already applies before loading (module_sig::verify_module_for_suite →
        // resolve_sig_verified → supervisor::verify_signature) — same trust store, same
        // fail-closed rule, same `--allow-unsigned` escape hatch, so the two run paths can never
        // silently diverge. Part A: dispatched through the ACTIVE crypto suite's
        // `module_signing` legs (`--crypto-suite`, default hybrid ML-DSA-65 + Ed25519) — a
        // MISSING or INVALID required leg refuses, never a silent downgrade to Ed25519-only.
        let trust_dir = cli.trust.clone().unwrap_or_else(|| modules_dir.join(".trust"));
        let suite = hookprobe_manifest::crypto::crypto_suite(&cli.crypto_suite)
            .with_context(|| format!("--crypto-suite '{}'", cli.crypto_suite))?;
        let sig_state = module_sig::verify_module_for_suite(&module_dir, &trust_dir, &suite.module_signing);
        def.sig_verified = module_sig::resolve_sig_verified(&sig_state, &def.signature);
        eprintln!(
            "run-wasm: {id} module signature: {} ({})",
            sig_state.as_str(),
            if def.signature == "required" { "required" } else { "unsigned-ok" }
        );
        if def.signature == "required" && !hookprobe_manifest::supervisor::verify_signature(&def) {
            if cli.allow_unsigned {
                eprintln!(
                    "run-wasm: {id} signature {} — proceeding (--allow-unsigned, DEV ONLY)",
                    sig_state.as_str()
                );
            } else {
                anyhow::bail!(
                    "refusing to run {id}: signature {} and module.yaml declares `signature: required`. \
                     Sign the module into the trust store ({trust_dir:?} — see --sign-modules), \
                     or pass --allow-unsigned for a dev/reference run.",
                    sig_state.as_str()
                );
            }
        }

        // Prefer a precompiled `.cwasm` bound (sha256 sidecar) to the exact `.wasm` on disk —
        // ADR 0009's AOT cold-start target; falls back to the `.wasm` source (JIT) transparently.
        // NOTE (ADR 0016 Fix A): for a `signature: required` module, `wasm_loader` NEVER actually
        // trusts this `.cwasm` — it reads the pinned `.wasm` bytes once, verifies THEM (Findings
        // 1+3), and compiles straight from those verified bytes. `Executable::Precompiled` here
        // only feeds `exec.source_wasm()` to that gate; the `.cwasm` field is inert on that path.
        let exec = wasm_loader::locate_executable(&id, &modules_dir)
            .with_context(|| format!("no .wasm for {id}"))?;

        // Bind the digest check to wherever `exec` TRULY resolved (dev workspace target/,
        // on-device /usr/lib/hookprobe/modules/<id>/, or a co-located layout) by treating its own
        // parent dir as the install dir, so `artifacts[].path: <id>.wasm` matches regardless of
        // which of locate_wasm's three candidate layouts this run picked.
        let digest_install_dir = exec.source_wasm().parent().unwrap_or(&module_dir).to_path_buf();
        let events = cli.events.clone()
            .or_else(|| std::env::var("HOOKPROBE_EVENTS").ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("/var/lib/hookprobe/events"));

        let preopens: Vec<(String, String)> = def
            .read_grants()
            .iter()
            .filter(|p| std::path::Path::new(p).is_dir())
            .map(|p| (p.to_string(), p.to_string()))
            .collect();
        let mem = def.resources.as_ref().map(|b| b.memory_mb).unwrap_or(256);
        let epoch_ms = def.resources.as_ref().and_then(|b| b.epoch_ms).unwrap_or(50);
        // Resource-budgets feature: the wasm CPU-metering wall, refilled every `epoch_ms` tick
        // (see `wasm_loader::run_wasi_module_streaming`'s doc for the rate-wall design). Per-
        // runtime default (`resource_budget::WASM_DEFAULT_FUEL`) when module.yaml doesn't declare
        // one — a `Budget::default()` still resolves a sensible fuel number via `effective_fuel`.
        let fuel_budget = def
            .resources
            .clone()
            .unwrap_or_default()
            .effective_fuel(&def.runtime);
        eprintln!(
            "run-wasm: {id} [{}] ({}) sandboxed · {mem} MiB cap · epoch {epoch_ms}ms · fuel {fuel_budget}/tick · {} preopen(s)",
            exec.describe_gated(&def),
            exec.display_path_gated(&def).display(),
            preopens.len()
        );
        // Manual kill-switch — no signal handler is registered (kept zero-new-dependency); tests
        // set this directly. Production unit stop is systemd's normal SIGTERM → TimeoutStopSec →
        // SIGKILL sequence (see the module units' Restart=/RestartSec=, same as sibling services).
        let kill = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        // ADR 0021 A76 AOT selection: read the CPU microarch tier from the signed Platform
        // Manifest (best-effort — this streaming path is otherwise manifest-less). Absent/
        // unreadable → None → the always-safe A72 baseline AOT/JIT (never an A76 blob on an A72).
        let cpu_tier = manifest_cpu_tier(cli.manifest.as_deref());
        if let Some(t) = cpu_tier.as_deref() {
            eprintln!("run-wasm: {id} CPU microarch tier '{t}' (from signed manifest) — A76-tier AOT eligible");
        }
        // ADR 0016 Fix A/Fix B (Findings 1+3): the digest+path-binding gate now runs INSIDE the
        // load path itself (`wasm_loader::load_module_gated`), on the exact bytes about to be
        // compiled — never a re-opened path, never a trusted `.cwasm` for a signed module.
        return wasm_loader::run_wasi_module_streaming(
            &exec,
            &def,
            &digest_install_dir,
            Some(&events),
            &preopens,
            mem,
            epoch_ms,
            fuel_budget,
            kill,
            cpu_tier.as_deref(),
        );
    }

    // AOT precompile mode (ADR 0009 build step 1, gap 2): produce a `.cwasm` next to whichever
    // `.wasm` `locate_wasm` resolves for each id — which is naturally the on-device
    // `/usr/lib/hookprobe/modules/<id>.wasm` convention when run there, and the dev workspace
    // `target/wasm32-wasip1/release/` tree otherwise. `all` precompiles every discovered
    // `runtime: wasm` module. Exits before requiring a manifest (like --run-wasm).
    #[cfg(feature = "wasm")]
    if let Some(target) = cli.precompile.clone() {
        let modules_dir = cli.modules.clone().unwrap_or_else(|| PathBuf::from("modules"));
        let out_override = cli.precompile_out.clone();
        let ids: Vec<String> = if target == "all" {
            if modules_dir.is_dir() {
                discover_modules(&modules_dir)?
                    .into_iter()
                    .filter(|(_, d)| matches!(d.runtime, hookprobe_manifest::types::Runtime::Wasm))
                    .map(|(_, d)| d.id)
                    .collect()
            } else {
                Vec::new()
            }
        } else {
            vec![target]
        };
        if ids.is_empty() {
            eprintln!("precompile: no wasm modules discovered under {modules_dir:?}");
        }
        for id in ids {
            match wasm_loader::locate_wasm(&id, &modules_dir) {
                None => eprintln!("precompile: {id} — no .wasm found, skip"),
                Some(wasm) => {
                    let out_dir = out_override
                        .clone()
                        .unwrap_or_else(|| wasm.parent().unwrap_or(&modules_dir).to_path_buf());
                    match wasm_loader::precompile(&wasm, &out_dir, &id) {
                        Ok(r) => println!(
                            "precompile: {id} -> {} ({} bytes, compiled in {:?})",
                            r.cwasm.display(),
                            r.cwasm_bytes,
                            r.compile_elapsed
                        ),
                        Err(e) => eprintln!("precompile: {id} FAILED: {e:#}"),
                    }
                }
            }
        }
        return Ok(());
    }

    // ADR 0016 D3: populate/refresh each declared artifact's digest VALUE in place in module.yaml.
    // Runs before requiring a manifest (like --run-wasm/--precompile/--sign-modules) — this is a
    // registry-tree operation, not a reconcile. `builder/sign-release.sh` calls this BEFORE
    // `--sign-modules` so the signature covers the final bytes (D3's build -> digest -> sign order).
    if let Some(target) = cli.write_artifact_digests.clone() {
        let modules_dir = cli.modules.clone().unwrap_or_else(|| PathBuf::from("modules"));
        // Repo root, for resolving `staging.artifacts[].src` (ADR 0016/0017 sysext gap fix) the
        // SAME way `gen-staging.sh`/`stage-apply.sh` do — every `modules/<id>/` lives directly
        // under `<repo>/modules`, so the parent of `modules_dir` IS the repo root by the same
        // construction `builder/sign-release.sh` (cd's to REPO, passes `--modules "$REPO/modules"`)
        // already assumes.
        let repo_root = modules_dir
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let ids: Vec<String> = if target == "all" {
            discover_modules(&modules_dir)?.into_iter().map(|(_, d)| d.id).collect()
        } else {
            vec![target]
        };
        let mut total = 0usize;
        for id in &ids {
            let dir = modules_dir.join(id);
            let ypath = dir.join("module.yaml");
            let text = match std::fs::read_to_string(&ypath) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("write-artifact-digests: {id}: cannot read {ypath:?}: {e}");
                    continue;
                }
            };
            let def: ModuleDef = match serde_yaml::from_str(&text) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("write-artifact-digests: {id}: cannot parse {ypath:?}: {e}");
                    continue;
                }
            };
            if def.artifacts.is_empty() {
                eprintln!(
                    "write-artifact-digests: {id} — no `artifacts:` block declared in module.yaml \
                     (declare `path`+`role` by hand once; this tool only refreshes `value`), skipping"
                );
                continue;
            }
            // ADR 0017/0021: this build can only honestly produce/hash ITS OWN arch's bytes (the
            // `build` stage runs AS the target arch — no cross-arch codegen, no cross-AOT). An
            // entry qualified with an explicit `arch:` for some OTHER arch is left completely
            // untouched here — it was (or will be) written by that arch's own run of this same
            // tool over the same module.yaml (the D3 collect-then-sign ordering ADR 0017
            // established for `role: aot`, generalized by ADR 0021 to `role: executable`/
            // `loader`/`bpf-object` too — e.g. napse-quarantine/host-telemetry/evidence/api
            // declaring one entry per built arch for the SAME on-device path).
            let current_arch = hookprobe_manifest::module_sig::running_arch();
            let mut new_text = text.clone();
            let mut n = 0usize;
            for a in &def.artifacts {
                let is_aot = a.role == hookprobe_manifest::module_def::ArtifactRole::Aot;
                match a.arch.as_deref() {
                    Some(arch) if arch.eq_ignore_ascii_case(current_arch) => {}
                    Some(other_arch) => {
                        eprintln!(
                            "write-artifact-digests: {id}: artifact '{}' (role: {:?}, arch: {other_arch}) \
                             — not this build's arch ({current_arch}), leaving untouched (ADR 0016/0017/0021 D3)",
                            a.path, a.role
                        );
                        continue;
                    }
                    None if is_aot => {
                        eprintln!(
                            "write-artifact-digests: {id}: artifact '{}' has role: aot but no `arch:` — \
                             malformed (ADR 0017 D1 requires it), skipping",
                            a.path
                        );
                        continue;
                    }
                    // ADR 0021: an arch-less entry on a native role (executable/loader/
                    // bpf-object) is the single-arch-canonical convention (unchanged) — this
                    // build's own bytes are written into it regardless of `current_arch`, exactly
                    // as before this generalization existed.
                    None => {}
                }
                // ADR 0016/0017 sysext-artifact-digest gap fix: for a module whose payload is
                // declared by staged/on-device path (`staging.artifacts[].src -> dest`, the
                // sysext/native-loader convention — `host-telemetry`, `napse-quarantine`, …),
                // resolve the BUILD-TREE source `gen-staging.sh`/`stage-apply.sh` would stage
                // FROM, not the on-device `dest` itself (which never exists in this checkout).
                // Falls back to the unchanged co-located `resolve_artifact_path` when no staging
                // entry names this `dest` (every wasm module: identical behavior to before).
                let file = match hookprobe_manifest::module_sig::resolve_artifact_source(
                    &def, &a.path, &dir, &repo_root, current_arch,
                ) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("write-artifact-digests: {id}: artifact '{}': {e:#}", a.path);
                        continue;
                    }
                };
                let bytes = match std::fs::read(&file) {
                    Ok(b) => b,
                    Err(e) => {
                        if is_aot {
                            // ADR 0017 D3: a missing AOT blob for the built arch is a WARNING, not
                            // a failure — the module simply falls back to verified JIT at runtime.
                            eprintln!(
                                "write-artifact-digests: {id}: artifact '{}' (role: aot, arch: {current_arch}) \
                                 not found ({file:?}): {e} — WARNING only (no AOT for this arch; falls back \
                                 to verified JIT, ADR 0017 D3), skipping",
                                a.path
                            );
                        } else if def.staging.is_some() {
                            // A sysext/native-loader module whose staged source genuinely can't be
                            // produced in THIS build environment (e.g. no cross-toolchain for this
                            // arch on this box) — tracked, honest "populated at the real per-arch
                            // release build" state, NOT a hand-faked digest. Never hard-fails this
                            // tool; `builder/release-pass.sh`/`verify-staging.sh`'s three-case gate
                            // (PASS/FAIL-tamper/PENDING-tracked) is what enforces this must become a
                            // real digest before a release ships.
                            eprintln!(
                                "write-artifact-digests: {id}: artifact '{}' — staged source not built in \
                                 this environment ({file:?}: {e}); leaving its digest as-is (populated at \
                                 the real per-arch release build, ADR 0016/0017 tracked-pending state), skipping",
                                a.path
                            );
                        } else {
                            eprintln!("write-artifact-digests: {id}: artifact '{}' not found ({file:?}): {e} — skipping", a.path);
                        }
                        continue;
                    }
                };
                let hex_digest = match hookprobe_manifest::module_sig::digest_hex(&a.digest.alg, &bytes) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("write-artifact-digests: {id}: artifact '{}': {e}", a.path);
                        continue;
                    }
                };
                // ADR 0021: `want_arch` is whatever THIS entry's own `arch:` field says (`Some`
                // for any arch-qualified role — aot, or a native executable/loader/bpf-object
                // that repeats its `path` once per built arch), `None` for the arch-independent
                // single-arch-canonical convention every other artifact still uses.
                let want_arch = a.arch.as_deref();
                match hookprobe_manifest::module_sig::write_digest_value_matching(&new_text, &a.path, want_arch, &hex_digest) {
                    Ok(t) => {
                        new_text = t;
                        n += 1;
                        eprintln!("write-artifact-digests: {id}: {} ({} bytes) -> {}", a.path, bytes.len(), hex_digest);
                    }
                    Err(e) => eprintln!("write-artifact-digests: {id}: artifact '{}': {e}", a.path),
                }
            }
            if n > 0 {
                std::fs::write(&ypath, &new_text).with_context(|| format!("writing {ypath:?}"))?;
                total += n;
            }
        }
        eprintln!("write-artifact-digests: {total} digest(s) written across {} module(s)", ids.len());
        return Ok(());
    }

    // ADR 0016/0017 release-gate three-case check: PASS (digest present + recomputed match) /
    // FAIL (digest present + recomputed mismatch — tamper, hard) / PENDING|UNVERIFIED (digest
    // absent-in-spirit — a placeholder token, or its source can't be read in this environment —
    // tracked, LOUD, non-fatal). This is the ONE place `builder/release-pass.sh`/
    // `builder/verify-staging.sh` now call for a real byte-level artifact-digest verdict instead
    // of each re-implementing a presence-only (or hard-fail-on-placeholder) check in shell/python.
    if let Some(target) = cli.check_artifact_digests.clone() {
        let modules_dir = cli.modules.clone().unwrap_or_else(|| PathBuf::from("modules"));
        let repo_root = modules_dir
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let arch = hookprobe_manifest::module_sig::running_arch();
        let ids: Vec<String> = if target == "all" {
            discover_modules(&modules_dir)?.into_iter().map(|(_, d)| d.id).collect()
        } else {
            vec![target]
        };
        let mut hard_fail = false;
        let mut n_pass = 0usize;
        let mut n_pending = 0usize;
        for id in &ids {
            let dir = modules_dir.join(id);
            let ypath = dir.join("module.yaml");
            let text = match std::fs::read_to_string(&ypath) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("check-artifact-digests: {id}: cannot read {ypath:?}: {e}");
                    continue;
                }
            };
            let def: ModuleDef = match serde_yaml::from_str(&text) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("check-artifact-digests: {id}: cannot parse {ypath:?}: {e}");
                    continue;
                }
            };
            if def.status.as_deref() == Some("stub") {
                eprintln!("check-artifact-digests: {id}: status=stub, exempted (shipped: no)");
                continue;
            }
            if def.signature != "required" {
                eprintln!("check-artifact-digests: {id}: signature={:?}, not subject to this gate", def.signature);
                continue;
            }
            // ADR 0021: a `role: executable`/`loader` entry counts toward `has_executing` only if
            // it APPLIES to the arch this gate is running as — arch-less (single-arch-canonical,
            // unchanged) or explicitly `arch:`-qualified to THIS `arch`. A module that pins
            // executing-payload digests ONLY for a different arch is, on THIS arch's tree,
            // exactly as unprotected as if it pinned none at all (same rule
            // `module_sig::verify_artifact_digests`/`verify_executable_binding` enforce at
            // load-time — this gate must not be laxer than the runtime check it exists to catch
            // regressions ahead of).
            let has_executing = def.artifacts.iter().any(|a| {
                matches!(
                    a.role,
                    hookprobe_manifest::module_def::ArtifactRole::Executable
                        | hookprobe_manifest::module_def::ArtifactRole::Loader
                ) && a.arch.as_deref().map(|ar| ar.eq_ignore_ascii_case(arch)).unwrap_or(true)
            });
            if !has_executing {
                eprintln!(
                    "check-artifact-digests: FAIL {id}: signature: required but no executing-payload \
                     (role: executable|loader) artifact digest pinned for THIS arch ({arch}) at all \
                     (ADR 0016/0021 D5 — run `hookprobe-supervisor --write-artifact-digests {id}` \
                     [on an {arch} build] then re-sign)"
                );
                hard_fail = true;
                continue;
            }
            for a in &def.artifacts {
                if a.role == hookprobe_manifest::module_def::ArtifactRole::Aot {
                    // ADR 0017's own arch-aware AOT checks (verify-staging.sh #7 / release-pass.sh)
                    // own this role — never duplicated/hard-failed here.
                    continue;
                }
                // ADR 0021: an entry `arch:`-qualified to a DIFFERENT arch than the one this gate
                // is running as is inert metadata for another platform's tree — never resolved,
                // never opened, never checked here (that arch's own run of this gate covers it).
                if let Some(a_arch) = a.arch.as_deref() {
                    if !a_arch.eq_ignore_ascii_case(arch) {
                        eprintln!(
                            "check-artifact-digests: {id}: artifact '{}' (role {:?}, arch: {a_arch}) \
                             — not this gate's arch ({arch}), skipping (checked by that arch's own run)",
                            a.path, a.role
                        );
                        continue;
                    }
                }
                if hookprobe_manifest::module_sig::is_placeholder_digest(&a.digest.value) {
                    eprintln!(
                        "check-artifact-digests: PENDING {id}: artifact '{}' (role {:?}) not yet \
                         populated — tracked, populated at the real per-arch release build (must \
                         become PASS before shipping)",
                        a.path, a.role
                    );
                    n_pending += 1;
                    continue;
                }
                let file = match hookprobe_manifest::module_sig::resolve_artifact_source(
                    &def, &a.path, &dir, &repo_root, arch,
                ) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!(
                            "check-artifact-digests: UNVERIFIED {id}: artifact '{}' — cannot resolve \
                             its source in this environment ({e:#}); cannot verify locally",
                            a.path
                        );
                        n_pending += 1;
                        continue;
                    }
                };
                let bytes = match std::fs::read(&file) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!(
                            "check-artifact-digests: UNVERIFIED {id}: artifact '{}' — source not \
                             available in this environment ({file:?}: {e}); the real per-arch release \
                             build populates + re-verifies this before shipping",
                            a.path
                        );
                        n_pending += 1;
                        continue;
                    }
                };
                let actual = match hookprobe_manifest::module_sig::digest_hex(&a.digest.alg, &bytes) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("check-artifact-digests: FAIL {id}: artifact '{}': {e}", a.path);
                        hard_fail = true;
                        continue;
                    }
                };
                if actual.eq_ignore_ascii_case(a.digest.value.trim()) {
                    eprintln!(
                        "check-artifact-digests: PASS {id}: artifact '{}' digest matches ({} bytes)",
                        a.path,
                        bytes.len()
                    );
                    n_pass += 1;
                } else {
                    eprintln!(
                        "check-artifact-digests: FAIL {id}: artifact '{}' digest MISMATCH (expected {}, \
                         got {}) — ADR 0016 fail-closed, this is tamper evidence, not a build artifact",
                        a.path, a.digest.value, actual
                    );
                    hard_fail = true;
                }
            }
        }
        eprintln!(
            "check-artifact-digests: {n_pass} PASS, {n_pending} PENDING/UNVERIFIED (tracked, non-fatal), \
             hard_fail={hard_fail} across {} module(s)",
            ids.len()
        );
        if hard_fail {
            anyhow::bail!("check-artifact-digests: FAILED — at least one hard failure above (digest MISMATCH-tamper, or an entirely unprotected signature:required module)");
        }
        return Ok(());
    }

    // Load manifest.
    let manifest_path_ref = cli
        .manifest
        .as_ref()
        .context("a manifest path is required (positional), or use --run-wasm <id>")?;
    let manifest_text = std::fs::read_to_string(manifest_path_ref)
        .with_context(|| format!("reading manifest {:?}", manifest_path_ref))?;
    let mut manifest: Manifest = serde_json::from_str(&manifest_text)
        .with_context(|| "parsing manifest JSON")?;

    // Verify the manifest's self-signature before trusting it (software-PUF).
    match hookprobe_manifest::identity::verify_manifest(&manifest) {
        Ok(hookprobe_manifest::identity::Verify::Valid) => {
            eprintln!("manifest signature: VERIFIED ({})", manifest.identity.idevid.pubkey_fpr)
        }
        Ok(hookprobe_manifest::identity::Verify::Unsigned) => {
            if cli.allow_unsigned {
                eprintln!("manifest signature: UNSIGNED — proceeding (--allow-unsigned, DEV ONLY)")
            } else {
                anyhow::bail!(
                    "refusing to reconcile an UNSIGNED manifest (signature stripped or never signed). \
                     Sign the manifest, or pass --allow-unsigned for a dev/reference build."
                )
            }
        }
        Err(e) => {
            return Err(e.context("refusing to reconcile a manifest that fails signature verification"))
        }
    }

    // --- multi-WAN: reconcile the failover plan from network.uplinks + intent ---
    if cli.wan_plan {
        use hookprobe_manifest::multi_wan;
        let intent = match &cli.wan_intent {
            Some(p) => multi_wan::WanIntent::parse(
                &std::fs::read_to_string(p).with_context(|| format!("reading wan-intent {p:?}"))?,
            )
            .with_context(|| "parsing wan-intent YAML")?,
            None => multi_wan::WanIntent::default(),
        };
        let wp = multi_wan::plan(&manifest.network.uplinks, &intent);
        println!("Multi-WAN failover plan (from signed manifest · {} uplink(s)):", wp.routes.len());
        println!("  {}", wp.summary());
        for r in &wp.routes {
            println!("    metric {:>3}  {:<14} {}", r.metric, r.iface, r.kind);
        }
        let files = multi_wan::render_networkd(&wp);
        match &cli.wan_write {
            Some(root) => {
                for f in &files {
                    let dst = root.join(&f.path);
                    if let Some(parent) = dst.parent() {
                        std::fs::create_dir_all(parent)
                            .with_context(|| format!("mkdir {parent:?}"))?;
                    }
                    std::fs::write(&dst, &f.content)
                        .with_context(|| format!("writing {dst:?}"))?;
                    eprintln!("wrote {dst:?}");
                }
            }
            None => {
                println!("{}", "-".repeat(78));
                for f in &files {
                    println!("# --- {} ---", f.path);
                    print!("{}", f.content);
                }
            }
        }
        return Ok(());
    }

    // --- storage: decide where the persistent data partition goes (removable policy) ---
    if cli.data_plan {
        use hookprobe_manifest::storage as st;
        let boot_dev = cli.boot_dev.clone().unwrap_or_else(detect_boot_dev);
        // Match the boot disk's serial from the manifest if its name is known.
        let boot_serial = manifest
            .hardware
            .storage
            .iter()
            .find(|d| d.dev == boot_dev)
            .and_then(|d| d.serial.clone());
        let plan = st::select_data_target(&manifest.hardware.storage, &boot_dev, boot_serial.as_deref());
        println!("Data-partition plan (from signed manifest · boot disk '{boot_dev}'):");
        println!("  → {}", plan.summary());
        if let Some(rec) = &plan.recommend_dedicated {
            println!("  recommend: dedicate fixed spare '{rec}' for durable data (operator action — not auto-claimed)");
        }
        if let Some(w) = &plan.warning {
            println!("  WARNING: {w}");
        }
        for (dev, reason) in &plan.excluded {
            println!("  excluded {dev}: {reason}");
        }
        return Ok(());
    }

    // --- Wi-Fi: reconcile station/AP radio config from network.wifi_radios + intent ---
    if cli.wifi_plan {
        use hookprobe_manifest::wifi_cfg;
        let mut intent = match &cli.wifi_intent {
            Some(p) => wifi_cfg::WifiIntent::parse(
                &std::fs::read_to_string(p).with_context(|| format!("reading wifi-intent {p:?}"))?,
            )
            .with_context(|| "parsing wifi-intent YAML")?,
            None => wifi_cfg::WifiIntent::default(),
        };
        // ADR 0034 (c): resolve `country: auto`/absent → the boot-detected CC (never emit `auto`).
        resolve_wifi_country(&mut intent);
        let radios = &manifest.network.wifi_radios;
        let device_id = &manifest.identity.device_id;
        let wp = wifi_cfg::plan(radios, &intent, device_id);
        println!("Wi-Fi plan (from signed manifest · {} radio(s)):", radios.len());
        println!("  {}", wp.summary());
        for a in &wp.assignments {
            println!("    {:<14} {:<8} {}", a.iface, a.role, a.note);
        }
        let files = wifi_cfg::render(radios, &intent, device_id);
        match &cli.wifi_write {
            Some(root) => {
                for f in &files {
                    let dst = root.join(&f.path);
                    if let Some(parent) = dst.parent() {
                        std::fs::create_dir_all(parent).with_context(|| format!("mkdir {parent:?}"))?;
                    }
                    std::fs::write(&dst, &f.content).with_context(|| format!("writing {dst:?}"))?;
                    eprintln!("wrote {dst:?}");
                }
            }
            None => {
                println!("{}", "-".repeat(78));
                for f in &files {
                    println!("# --- {} ---", f.path);
                    print!("{}", f.content);
                }
                if files.is_empty() {
                    println!("(no config emitted — declare station/ap intent with --wifi-intent)");
                }
            }
        }
        return Ok(());
    }

    // --- fabric: reconcile the L2/L3 data plane (OVS LAN / cloud VRF) from intent ---
    if cli.fabric_plan {
        use hookprobe_manifest::fabric;
        let intent = match &cli.fabric_intent {
            Some(p) => fabric::FabricIntent::parse(
                &std::fs::read_to_string(p).with_context(|| format!("reading fabric-intent {p:?}"))?,
            )
            .with_context(|| "parsing fabric-intent YAML")?,
            None => fabric::FabricIntent::default(),
        };
        // The WAN uplink (kept off the LAN bridge) = the top wired uplink in the manifest.
        let wan = manifest
            .network
            .uplinks
            .iter()
            .find(|u| u.kind == "wired")
            .map(|u| u.name.clone());
        // OVS is capability-gated; without it the L2 plane falls back to a Linux bridge.
        let ovs_granted = manifest.capabilities.get("openvswitch").is_some_and(|c| {
            matches!(c.state, hookprobe_manifest::types::CapabilityState::Granted)
        });
        let fp = fabric::plan(&manifest.network.interfaces, wan.as_deref(), &intent, ovs_granted);
        println!("Fabric plan (from signed manifest):");
        println!("  resolved: {} — {}", fp.resolved, fp.why);
        println!("  {}", fp.summary());
        println!("  topology: {} LAN carrier(s), can_switch={}", fp.topology.lan_carriers.len(), fp.topology.can_switch);
        if let Some(w) = &wan {
            println!("  WAN uplink (off-bridge): {w}");
        }
        if !ovs_granted && fp.l2.is_some() {
            println!("  note: 'openvswitch' capability NOT granted → Linux-bridge fallback (no OpenFlow MAC binding)");
        }
        let files = fabric::render(&fp);
        match &cli.fabric_write {
            Some(root) => {
                for f in &files {
                    let dst = root.join(&f.path);
                    if let Some(parent) = dst.parent() {
                        std::fs::create_dir_all(parent).with_context(|| format!("mkdir {parent:?}"))?;
                    }
                    std::fs::write(&dst, &f.content).with_context(|| format!("writing {dst:?}"))?;
                    eprintln!("wrote {dst:?}");
                }
            }
            None => {
                println!("{}", "-".repeat(78));
                for f in &files {
                    println!("# === {} ===", f.path);
                    print!("{}", f.content);
                }
            }
        }
        return Ok(());
    }

    // --- classify: MAC-independent device identity from observed signals ---
    if let Some(path) = &cli.classify {
        use hookprobe_manifest::fingerprint;
        let text = std::fs::read_to_string(path).with_context(|| format!("reading observations {path:?}"))?;
        let obs: Vec<fingerprint::DeviceObservation> =
            serde_json::from_str(&text).with_context(|| "parsing observations JSON")?;
        let profiles = fingerprint::classify_all(&obs);
        println!("Device identity (MAC-independent fingerprint → suggested segment):");
        println!("  {:<18} {:<16} {:<10} {:<12} rand?", "MAC", "class", "conf", "segment");
        for p in &profiles {
            println!(
                "  {:<18} {:<16} {:<10} {:<12} {}",
                p.mac, p.class.as_str(), p.confidence.as_str(), p.suggested_segment,
                if p.mac_randomized { "RANDOMIZED" } else { "-" }
            );
        }
        println!("{}", "-".repeat(78));
        for p in &profiles {
            println!("{} ({}):", p.mac, p.class.as_str());
            for sig in &p.signals {
                println!("    · {sig}");
            }
        }
        return Ok(());
    }

    // --- auto-segment: live identity → AEGIS segment decision → fabric bindings ---
    if let Some(path) = &cli.auto_segment {
        use hookprobe_manifest::fingerprint::{self, Mechanism};
        let text = std::fs::read_to_string(path).with_context(|| format!("reading leases {path:?}"))?;
        let mut obs = fingerprint::observations_from_dnsmasq_leases(&text);
        // Enrich with richer live signals so fewer devices fall to 'unknown'.
        let mdns = match &cli.mdns {
            Some(p) => fingerprint::parse_avahi_browse(&std::fs::read_to_string(p).with_context(|| format!("reading mdns {p:?}"))?),
            None => Vec::new(),
        };
        let dhcp = match &cli.dhcp_log {
            Some(p) => fingerprint::parse_dnsmasq_dhcp_log(&std::fs::read_to_string(p).with_context(|| format!("reading dhcp-log {p:?}"))?),
            None => Vec::new(),
        };
        if !mdns.is_empty() || !dhcp.is_empty() {
            fingerprint::enrich(&mut obs, &mdns, &dhcp);
            eprintln!("enriched: {} mDNS host(s), {} DHCP vendor-class pair(s)", mdns.len(), dhcp.len());
        }
        let profiles = fingerprint::classify_all(&obs);
        let decisions = fingerprint::recommend_all(&profiles);
        println!("AEGIS auto-segmentation ({} device(s) — identity → segment → enforcement):", decisions.len());
        println!("  {:<18} {:<14} {:<12} {:<10} why", "MAC", "class", "segment", "enforce");
        for d in &decisions {
            println!("  {:<18} {:<14} {:<12} {:<10} {}", d.mac, d.class.as_str(), d.segment, d.mechanism.as_str(), d.reason);
        }
        // Emit the fabric mac_bindings fragment the operator can paste into fabric-intent.
        println!("{}", "-".repeat(78));
        println!("# fabric-intent.yaml fragment (AEGIS plan — review before applying):");
        println!("mac_bindings:");
        for d in &decisions {
            match d.mechanism {
                Mechanism::MacFlow => println!("  - {{ mac: \"{}\", segment: {} }}", d.mac, d.segment),
                Mechanism::Dot1x => println!("  - {{ mac: \"{}\", segment: {}, via: dot1x }}   # randomized MAC → enroll in 802.1X", d.mac, d.segment),
                Mechanism::Observe => println!("  # {} → onboarding (observe; no MAC/identity binding yet)", d.mac),
            }
        }
        return Ok(());
    }

    // --- microseg: east-west isolation inside segments (stateful conntrack) ---
    if cli.microseg_plan {
        use hookprobe_manifest::{fabric, microseg};
        // Segments come from the fabric intent (the VLAN map); policies from microseg intent.
        let segments = match &cli.fabric_intent {
            Some(p) => fabric::FabricIntent::parse(&std::fs::read_to_string(p).with_context(|| format!("reading fabric-intent {p:?}"))?)?.segments,
            None => Vec::new(),
        };
        let intent = match &cli.microseg_intent {
            Some(p) => microseg::MicrosegIntent::parse(&std::fs::read_to_string(p).with_context(|| format!("reading microseg-intent {p:?}"))?)?,
            None => microseg::MicrosegIntent::default(),
        };
        let mp = microseg::plan(&segments, &intent);
        println!("Microsegmentation plan (east-west isolation):");
        println!("  {}", mp.summary());
        for u in &mp.unresolved {
            println!("  WARNING: unresolved segment reference '{u}'");
        }
        println!("{}", "-".repeat(78));
        for f in [microseg::render_ovs_conntrack(&mp), microseg::render_nft(&mp)] {
            println!("# === {} ===", f.path);
            print!("{}", f.content);
        }
        return Ok(());
    }

    // --- continuous trust: posture signals → dynamic re-segmentation (quarantine) ---
    if cli.trust_eval.is_some() || cli.arp.is_some() {
        use hookprobe_manifest::trust;
        let policy = match &cli.trust_policy {
            Some(p) => trust::TrustPolicy::parse(&std::fs::read_to_string(p).with_context(|| format!("reading trust-policy {p:?}"))?)?,
            None => trust::TrustPolicy::default(),
        };
        // Posture source: explicit JSON, OR built from the LIVE detection plane (arp + blocked).
        let signals: Vec<trust::PostureSignal> = if let Some(arp_path) = &cli.arp {
            let arp = trust::parse_arp_status(&std::fs::read_to_string(arp_path).with_context(|| format!("reading arp {arp_path:?}"))?);
            let blocked: Vec<String> = match &cli.blocked {
                Some(p) => serde_json::from_str(&std::fs::read_to_string(p).with_context(|| format!("reading blocked {p:?}"))?).unwrap_or_default(),
                None => Vec::new(),
            };
            // ADR 0023 task #19 / ADR 0027 Layer-1 (2026-07-16): fold in HYDRA's corroboration-gated
            // intel verdicts (module-computed via `hookprobe-hydra`'s `verdict::assess` — see that
            // binary's main.rs — into `/var/lib/hookprobe/hydra-verdicts`, JSON lines) as `IntelOnly`
            // posture signals, resolved to a MAC via this SAME live ARP snapshot. Optional/absent
            // file → zero intel signals (unchanged prior behavior) — this is a live-plane ADDITION,
            // never a hard dependency. The corroboration/enforcement gate itself is untouched: it
            // still lives ENTIRELY in `trust::evaluate`'s `intel_requires_corroboration` check.
            //
            // 2026-07-16 security-auditor AMBER-1 fix: a missing/unreadable verdicts file (e.g.
            // first boot, before HYDRA has ever run once) must NEVER abort this whole continuous-
            // trust cycle with `?` — that would also disable the CONFIRMED `Direct` blocked_macs
            // quarantine + recovered-device release below, which have nothing to do with HYDRA.
            // Mirrors `--blocked` just above: missing/malformed → treated as zero intel, never a
            // hard error (malformed individual lines were already skipped via `filter_map`).
            let hydra_verdicts: Vec<trust::HydraDeviceVerdict> = match &cli.hydra_verdicts {
                Some(p) => std::fs::read_to_string(p)
                    .ok()
                    .map(|text| text.lines().filter_map(|l| serde_json::from_str(l).ok()).collect())
                    .unwrap_or_default(),
                None => Vec::new(),
            };
            let intel = trust::intel_signals_from_hydra(&hydra_verdicts, &arp, &[], "byod");
            eprintln!(
                "live posture: {} ARP entries, {} blocked, {} HYDRA intel signal(s)",
                arp.len(), blocked.len(), intel.len()
            );
            trust::build_posture(&arp, &blocked, &intel, &[], "byod")
        } else {
            let path = cli.trust_eval.as_ref().unwrap();
            serde_json::from_str(&std::fs::read_to_string(path).with_context(|| format!("reading posture {path:?}"))?)
                .with_context(|| "parsing posture signals JSON")?
        };
        let decisions = trust::evaluate_all(&signals, &policy);
        println!("Continuous trust ({} device(s) — live posture → action):", decisions.len());
        println!("  {:<18} {:<10} {:<12} why", "MAC", "action", "→ segment");
        for d in &decisions {
            println!("  {:<18} {:<10} {:<12} {}", d.mac, d.action.as_str(), d.to_segment, d.reason);
        }
        println!("{}", "-".repeat(78));
        // Reverting reconcile when a previous quarantined set is supplied (continuous loop);
        // otherwise the one-shot quarantine flows. --quarantine-state makes it self-contained:
        // it is the prev source AND is rewritten with the new set after.
        let state_path = cli.quarantine_state.as_ref().or(cli.prev_quarantined.as_ref());
        if let Some(p) = state_path {
            let prev: Vec<String> = std::fs::read_to_string(p)
                .ok()
                .and_then(|t| serde_json::from_str(&t).ok())
                .unwrap_or_default();
            let rec = trust::reconcile(&decisions, &prev);
            eprintln!("reconcile: +{} quarantined, -{} released, {} current", rec.newly_quarantined.len(), rec.recovered.len(), rec.current.len());
            print!("{}", trust::render_reconcile(&rec, &policy, &cli.bridge).content);
            // Persist the new quarantined set for the next cycle (only for the state file).
            if let Some(sp) = &cli.quarantine_state {
                std::fs::write(sp, serde_json::to_string(&rec.current)? + "\n")
                    .with_context(|| format!("writing quarantine state {sp:?}"))?;
            }
        } else {
            print!("{}", trust::render_quarantine_flows(&decisions, &policy).content);
        }
        return Ok(());
    }

    // --- AEGIS reflex: scan-responder — ENRICH / DROP (nft, TTL auto-revert) / DOCUMENT ------
    if cli.scan_respond || cli.scan_respond_sweep {
        use hookprobe_manifest::scan_responder as sr;

        let ttl_secs = cli
            .quarantine_ttl_secs
            .or_else(|| std::env::var("QUARANTINE_TTL_SECS").ok().and_then(|v| v.parse().ok()))
            .unwrap_or(300);
        let state_path = cli
            .quarantine_state_file
            .clone()
            .unwrap_or_else(|| PathBuf::from("/var/lib/hookprobe/scan-quarantine.json"));
        let host_intel_dir = cli
            .host_intel_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("/var/lib/hookprobe/host-intel"));

        // 2026-07-05 threat-model fix (HIGH #4): resolve the LIVE WAN default gateway + configured
        // DNS resolver(s) and fold them into the protect-ip set — this is the concrete fix for "a
        // WAN attacker spoofs the device's own gateway/resolver to trigger self-quarantine of its
        // own upstream". One-time, at startup (NOT re-resolved per alert — an untrusted per-alert
        // trigger re-reading routing state would reopen a TOCTOU angle for no benefit).
        let mut protect_ips = if cli.protect_ip.is_empty() { vec!["10.66.0.1".to_string()] } else { cli.protect_ip.clone() };
        if !cli.no_auto_protect_upstream {
            let route_text = match &cli.gateway_route_file {
                Some(p) => std::fs::read_to_string(p).ok(),
                None => std::process::Command::new("ip")
                    .args(["route", "show", "default"])
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .and_then(|o| String::from_utf8(o.stdout).ok()),
            };
            if let Some(gw) = route_text.as_deref().and_then(sr::parse_default_gateway) {
                eprintln!("scan-respond: auto-protecting the resolved WAN default gateway {gw}");
                protect_ips.push(gw);
            }
            let resolv_path = cli.resolv_conf.clone().unwrap_or_else(|| PathBuf::from("/etc/resolv.conf"));
            let resolvers = std::fs::read_to_string(&resolv_path)
                .ok()
                .map(|t| sr::parse_resolv_conf_nameservers(&t))
                .unwrap_or_default();
            for r in &resolvers {
                eprintln!("scan-respond: auto-protecting the configured DNS resolver {r}");
            }
            protect_ips.extend(resolvers);
        }
        let protect = sr::ProtectPolicy {
            cidrs: if cli.protect_cidr.is_empty() { vec!["10.200.0.0/28".to_string()] } else { cli.protect_cidr.clone() },
            ips: protect_ips,
            lan_macs: cli.protect_mac.iter().map(|m| m.to_ascii_lowercase()).collect(),
        };
        // LAN/WAN iface scoping (the key requirement: handle BOTH a LAN and a WAN scanner).
        // Defaults match the live Pi 4 topology (hp-br0 down; the AP is wlan0 + nft).
        let ifaces = sr::IfaceConfig {
            lan: cli.lan_iface.clone().or_else(|| std::env::var("LAN_IFACE").ok()).unwrap_or_else(|| "wlan0".to_string()),
            wan: cli.wan_iface.clone().or_else(|| std::env::var("WAN_IFACE").ok()).unwrap_or_else(|| "end0".to_string()),
        };
        // 2026-07-05 VERIFY-pass re-audit (Q5 fix): resolve this device's OWN WAN-side address(es)
        // into a DEDICATED list — NEVER `protect.ips` (the mgmt/gateway/resolver allowlist). The
        // original code passed `protect.ips` as `is_wan_ingress_martian`'s `wan_self_ips`, which
        // meant a LAN attacker scanning the gateway or a configured DNS resolver (both legitimately
        // in `protect.ips`) got misclassified as an "impossible WAN ingress" and evaded enforcement
        // (see ADR 0018's Q5 correction, `scan_responder::decide`'s doc comment). One-time, at
        // startup (same "resolve once, never per-alert" discipline as the gateway/resolver
        // auto-protect above).
        let wan_self_ips: Vec<String> = if !cli.wan_self_ip.is_empty() {
            cli.wan_self_ip.clone()
        } else {
            let addr_text = match &cli.wan_addr_file {
                Some(p) => std::fs::read_to_string(p).ok(),
                None => std::process::Command::new("ip")
                    .args(["-4", "-o", "addr", "show", "dev", &ifaces.wan])
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .and_then(|o| String::from_utf8(o.stdout).ok()),
            };
            let resolved = addr_text.as_deref().map(sr::parse_wan_self_ips).unwrap_or_default();
            for ip in &resolved {
                eprintln!("scan-respond: resolved this device's own WAN address {ip} on {} (wan_self_ips, Q5 fix)", ifaces.wan);
            }
            resolved
        };
        let flows_path = cli
            .flows
            .clone()
            .unwrap_or_else(|| PathBuf::from("/var/lib/hookprobe/flows"));
        let feeds_dir = cli
            .feeds_dir
            .clone()
            .or_else(|| std::env::var("FEEDS_DIR").ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("/var/lib/hookprobe/feeds"));
        // Read every already-fetched HYDRA threat-intel feed once per run (they refresh hourly;
        // re-reading per-alert would be wasteful and these files are small). The WAN reputation
        // seam: `Some(feed_name)` on a match, honest `None` ("unknown, needs feed") otherwise —
        // never fabricated. Reuses the SAME on-disk files `hydra-feedsync` parses (ADR 0005)
        // without depending on (or touching) `modules/napse-capture/loader`.
        let feed_bodies: Vec<(String, String)> = std::fs::read_dir(&feeds_dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("txt"))
                    .filter_map(|e| {
                        let name = e.path().file_stem()?.to_str()?.to_string();
                        std::fs::read_to_string(e.path()).ok().map(|body| (name, body))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let feed_refs: Vec<(&str, &str)> = feed_bodies.iter().map(|(n, b)| (n.as_str(), b.as_str())).collect();

        // Reverse-DNS (PTR) for a WAN scanner via `getent hosts` (NSS; no extra package needed).
        // Best-effort: NXDOMAIN/timeout/absent binary all fall back to `None` (never fabricated).
        fn resolve_ptr(ip: &str) -> Option<String> {
            let out = std::process::Command::new("getent").args(["hosts", ip]).output().ok()?;
            if !out.status.success() {
                return None;
            }
            hookprobe_manifest::scan_responder::parse_getent_hosts(&String::from_utf8_lossy(&out.stdout))
        }

        fn load_state(p: &std::path::Path) -> Vec<hookprobe_manifest::scan_responder::QuarantineEntry> {
            std::fs::read_to_string(p).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
        }
        fn save_state(p: &std::path::Path, s: &[hookprobe_manifest::scan_responder::QuarantineEntry]) -> Result<()> {
            let json = serde_json::to_string(s)?;
            std::fs::write(p, json + "\n").with_context(|| format!("writing quarantine state {p:?}"))
        }
        fn now_secs() -> f64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0)
        }
        // Apply a plan's non-comment lines via `nft`, one argv per line (no shell involved —
        // mirrors trust-reconcile.sh's never-`eval` discipline). Without --apply, PRINT only.
        fn apply_or_print(plan: &str, apply: bool) {
            if plan.lines().all(|l| l.trim().is_empty() || l.starts_with('#')) {
                return;
            }
            if !apply {
                eprintln!("scan-respond: PLAN (pass --apply to execute):\n{plan}");
                return;
            }
            for line in plan.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let argv: Vec<&str> = line.split_whitespace().collect();
                match std::process::Command::new("nft").args(&argv).status() {
                    Ok(st) if st.success() => eprintln!("scan-respond: nft {} -> ok", argv.join(" ")),
                    Ok(st) => eprintln!("scan-respond: nft {} -> FAILED ({st})", argv.join(" ")),
                    Err(e) => eprintln!("scan-respond: nft {} -> exec error: {e}", argv.join(" ")),
                }
            }
        }

        // --scan-respond-sweep: one-shot TTL sweep, independent of any new alert (timer-driven).
        if cli.scan_respond_sweep {
            let state = load_state(&state_path);
            let ts = now_secs();
            let diff = sr::sweep_quarantine(state, ts, ttl_secs);
            if !diff.to_remove.is_empty() {
                apply_or_print(&sr::render_element_ops(&diff, ttl_secs).content, cli.apply);
                for e in &diff.to_remove {
                    let iface = ifaces.for_kind(sr::classify_source(&e.ip));
                    println!("{}", sr::render_revert_json(e, ttl_secs, ts, iface));
                }
            }
            save_state(&state_path, &diff.state)?;
            return Ok(());
        }

        // --scan-respond: the tail-loop — one NAPSE event JSON line per stdin line.
        // Apply the nft quarantine bootstrap (table/sets/chains/drop-rules) ON START when --apply,
        // so a fresh boot has the enforcement scaffold BEFORE the first alert (the per-event element
        // adds target these sets). Idempotent — safe to re-run every start. Without --apply, print only.
        eprintln!("scan-respond: nft bootstrap (idempotent; applied on start when --apply):");
        apply_or_print(&sr::render_bootstrap(ttl_secs, &ifaces).content, cli.apply);
        std::fs::create_dir_all(&host_intel_dir).ok();

        // ADR 0020 Phase-1a defensive: the L1/L2 storm-control bootstrap (mac-flood / broadcast-
        // multicast / ARP-flood rate caps). A SEPARATE nft table (`hookprobe_l2guard`) from the
        // one above — self-managing `meter`s, no per-alert element diff loop needed (see
        // `l2_responder`'s module doc for why that's the anti-spoof property for this path).
        use hookprobe_manifest::l2_responder as l2r;
        // D12 fix: resolve the LAN port role from --lan-port-role / LAN_PORT_ROLE, else the safer
        // manifest-aligned default (`PortRole::default()` == UplinkBridge) — an unrecognized value
        // warns and falls back to the default rather than silently misclassifying the port.
        let lan_port_role = cli
            .lan_port_role
            .clone()
            .or_else(|| std::env::var("LAN_PORT_ROLE").ok())
            .and_then(|v| match v.to_ascii_lowercase().as_str() {
                "access" => Some(l2r::PortRole::Access),
                "uplink" | "uplink_bridge" | "uplink-bridge" => Some(l2r::PortRole::UplinkBridge),
                other => {
                    eprintln!("scan-respond: lan-port-role {other:?} not recognized, using the default");
                    None
                }
            })
            .unwrap_or_default();
        let l2_cfg = l2r::L2GuardConfig {
            lan_iface: ifaces.lan.clone(),
            wan_iface: ifaces.wan.clone(),
            lan_port_role,
            ..Default::default()
        };
        eprintln!("scan-respond: l2guard storm-control bootstrap (idempotent; applied on start when --apply):");
        apply_or_print(&l2r::render_storm_control(&l2_cfg).content, cli.apply);

        // Resource-shed bootstrap ON START (Finding-2, 2026-07-10): the `hookprobe_resource_shed`
        // table is otherwise only (re-)applied by the 10s `hookprobe-resource-shed.timer` (its first
        // fire is `OnBootSec=10s`), leaving a ~10s boot window with NO always-on management-plane
        // flood cap. Applying the SAME idempotent bootstrap here on start makes the mgmt-port cap
        // (and Layer 1's blanket cap) present from the first boot second. Built from this path's
        // resolved ifaces + mgmt-allowlist (`protect`) with the crate defaults for the rate knobs;
        // the resource-shed timer re-applies it every 10s with the operator's live env tunables
        // (RESOURCE_SHED_MGMT_CONN_PPS etc.), which is authoritative in steady state — this on-start
        // apply only closes the initial window with the safe defaults.
        let rs_bootstrap_cfg = sr::ConnRateCapConfig {
            lan_iface: ifaces.lan.clone(),
            wan_iface: ifaces.wan.clone(),
            protect_cidrs: protect.cidrs.clone(),
            protect_ips: protect.ips.clone(),
            ..Default::default()
        };
        eprintln!("scan-respond: resource-shed bootstrap (idempotent; applied on start when --apply):");
        apply_or_print(&sr::render_conn_rate_cap(&rs_bootstrap_cfg).content, cli.apply);

        // sd_notify watchdog (backend-audit gap 2 — Architecture.md §4.4): READY=1 once startup
        // (the nft bootstrap above) has actually run, BEFORE blocking on the stdin tail-loop below
        // (Type=notify's contract). WATCHDOG=1 is rate-limited (WatchdogPinger) and pinged ONLY
        // from inside the loop body below, once per REAL line this process reads off stdin — never
        // from an independent timer — so the ping proves this specific tail-loop is still reading
        // and processing `events`, not merely that the process exists. Honest tradeoff: on a truly
        // quiet network (no NAPSE alert of ANY kind — port-scan, L1/L2, …) for longer than the
        // pairing unit's `WatchdogSec=`, this process will NOT ping and systemd will restart it —
        // safe (Restart=on-failure + the same `tail -n0 -F` re-attaches at current EOF, so no
        // alert is lost), just spurious; `hookprobe-scan-responder.service`'s `WatchdogSec=` is
        // sized generously to make that rare rather than routine.
        hookprobe_manifest::sd_notify::notify_ready();
        let mut watchdog = hookprobe_manifest::sd_notify::WatchdogPinger::new(std::time::Duration::from_secs(20));

        use std::io::BufRead;
        for line in std::io::stdin().lock().lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("scan-respond: stdin read error: {e}");
                    break;
                }
            };
            // A real line was read off stdin — the tail-loop is alive and making progress.
            watchdog.tick();
            let Some(alert) = sr::parse_scan_alert(&line) else {
                // Not a port-scan alert — try the L1/L2 defensive detectors (ADR 0020 Phase-1a).
                // Decision-only here: RateLimit is already enforced by the storm-control bootstrap
                // above (nft meters act on every matching packet with no per-alert plumbing
                // needed); FrameDrop is now ALSO really enforced, by a SEPARATE Ring-0 program —
                // modules/napse-l2guard's TC-bpf clsact-ingress hook, attached independently of
                // this process (see `l2_responder::render_frame_drop_status`). Either way we only
                // DOCUMENT the finding here — never call `reconcile_quarantine` (the persistent,
                // identity-keyed quarantine state) for an L1/L2 finding, by construction
                // (`L2Verdict` cannot express one).
                if let Some(l2_alert) = l2r::parse_l2_alert(&line) {
                    let verdict = l2r::decide_l2(&l2_alert, l2_cfg.lan_port_role);
                    println!("{}", l2r::render_l2_response_json(&l2_alert, &verdict, now_secs()));
                }
                continue;
            };
            let ts = now_secs();

            // BRANCH ON SOURCE — a key requirement: a LAN scanner and a WAN scanner get
            // different enrichment AND a different quarantine placement.
            let kind = sr::classify_source(&alert.src_ip);
            let iface = ifaces.for_kind(kind);
            let scan_port_count;
            let intel_path;

            // 2026-07-05 threat-model fix (CRITICAL #2): the MAC bound to LAN quarantine is the
            // OBSERVED frame source MAC the packet-layer sensor captured AT DETECTION TIME
            // (`napse_loader::portscan::PortScanTracker`), carried in the alert's `src_mac` field
            // — NEVER an ARP/`ip neigh` lookup keyed on the CLAIMED `src_ip` (that lookup
            // faithfully resolves whatever the REAL owner of a spoofed claimed IP has, e.g. this
            // device's own gateway, poisoning the quarantine key against an address the attacker
            // never touched). No `ip neigh`/`/proc/net/arp` shell-out happens here at all anymore
            // — zero per-alert I/O cost for MAC resolution, on top of being the correct value.
            let mac: Option<String> = if kind == sr::SourceKind::Lan { alert.src_mac.clone() } else { None };

            match kind {
                sr::SourceKind::Lan => {
                    // ENRICH (LAN) — MAC already resolved above → MAC-independent fingerprint identity.
                    let leases_text = cli.dnsmasq_leases.as_ref().and_then(|p| std::fs::read_to_string(p).ok());
                    let hostname = leases_text.as_deref().and_then(|t| {
                        hookprobe_manifest::fingerprint::observations_from_dnsmasq_leases(t)
                            .into_iter()
                            .find(|o| o.ip.as_deref() == Some(alert.src_ip.as_str()))
                            .and_then(|o| o.hostname)
                    });
                    let dhcp_pairs = cli
                        .dhcp_log
                        .as_ref()
                        .and_then(|p| std::fs::read_to_string(p).ok())
                        .map(|t| hookprobe_manifest::fingerprint::parse_dnsmasq_dhcp_log(&t))
                        .unwrap_or_default();
                    let vendor_class = hostname
                        .as_deref()
                        .and_then(|h| dhcp_pairs.iter().find(|(n, _)| n.eq_ignore_ascii_case(h)).map(|(_, v)| v.clone()));
                    let mdns_hosts = cli
                        .mdns
                        .as_ref()
                        .and_then(|p| std::fs::read_to_string(p).ok())
                        .map(|t| hookprobe_manifest::fingerprint::parse_avahi_browse(&t))
                        .unwrap_or_default();
                    let mdns_host = mdns_hosts.into_iter().find(|h| h.ip == alert.src_ip);

                    let key = mac.clone().unwrap_or_else(|| alert.src_ip.clone()).replace(':', "-");
                    let path = host_intel_dir.join(format!("{key}.json"));
                    let prev_intel: Option<sr::HostIntel> =
                        std::fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str(&t).ok());
                    let sig = sr::EnrichSignals {
                        mac: mac.as_deref(),
                        hostname: hostname.as_deref(),
                        vendor_class: vendor_class.as_deref(),
                        dhcp_opt55: None,
                        mdns: mdns_host.as_ref(),
                    };
                    let intel = sr::enrich_host(prev_intel.as_ref(), &alert, sig, ts);
                    if let Ok(j) = serde_json::to_string_pretty(&intel) {
                        if let Err(e) = std::fs::write(&path, j) {
                            eprintln!("scan-respond: writing host-intel {path:?}: {e}");
                        }
                    }
                    scan_port_count = intel.scan_ports.len();
                    intel_path = path;
                }
                sr::SourceKind::Wan => {
                    // ENRICH (WAN) — no DHCP/mDNS off-link: PTR + coarse network group + bogon
                    // flag + reputation against HYDRA's already-fetched feeds. Honest "unknown,
                    // needs feed" (never fabricated) when the feed dir hasn't synced yet.
                    let ptr = resolve_ptr(&alert.src_ip);
                    let reputation = sr::wan_reputation(&alert.src_ip, &feed_refs);

                    let path = host_intel_dir.join(format!("{}.json", alert.src_ip.replace(':', "-")));
                    let prev_intel: Option<sr::WanIntel> =
                        std::fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str(&t).ok());
                    let intel = sr::enrich_wan(prev_intel.as_ref(), &alert, ptr.as_deref(), reputation.as_deref(), ts);
                    if intel.is_bogon {
                        eprintln!("scan-respond: WARNING {} is a bogon/reserved address arriving on the WAN path (spoofed or misrouted?)", alert.src_ip);
                    }
                    if let Ok(j) = serde_json::to_string_pretty(&intel) {
                        if let Err(e) = std::fs::write(&path, j) {
                            eprintln!("scan-respond: writing host-intel {path:?}: {e}");
                        }
                    }
                    scan_port_count = intel.scan_ports.len();
                    intel_path = path;
                }
            }
            let _ = &intel_path; // enrichment artifact path (logged above on write failure only)

            // DROP — deterministic quarantine (nft), TTL auto-revert, mgmt-path allowlist. Same
            // reflex verdict (trust::evaluate) for both kinds; only the RENDERING (iface/sets)
            // differs, via render_element_ops's own classify_source routing.
            //
            // 2026-07-05 threat-model fix (CRITICAL #1): `decide` now gates on `alert.confirmed`
            // (stamped by the INDEPENDENT `napse_loader::confirm::HandshakeTracker`, never a
            // self-reported field this crate trusts) and on WAN-ingress-martian shape. Its
            // `Observed` verdict means "detected and documented, never enforced" — the persisted
            // quarantine state (and therefore the nft sets / BPF maps mirroring it) is NEVER
            // touched for it: no add, no TTL refresh, no nft op at all. This is what makes a
            // single-packet, spoofable claimed source structurally unable to populate the
            // enforced map, closing the reflected-DoS the audit found.
            // F4 (2026-07-06): if the mirror-fed handshake tracker didn't confirm this source, it
            // can STILL be confirmed by an independent, un-spoofable signal — an ESTABLISHED
            // conntrack flow to this DUT (the kernel already saw the full 3-way). This makes
            // enforcement robust to a mirror failure (F1 class): one dead mirror can no longer
            // disable ALL quarantine. Read the flows tail ONLY on the unconfirmed path — the common
            // confirmed-handshake path pays nothing. Anti-spoof invariant preserved: neither signal
            // true → still unconfirmed → never quarantined (see sr::is_confirmed_any).
            let confirmed = if alert.confirmed {
                true
            } else {
                sr::conntrack_established(&read_flows_tail(&flows_path, 512 * 1024), &alert.src_ip)
            };
            let verdict =
                sr::decide(&alert.src_ip, &alert.dst_ip, scan_port_count, confirmed, mac.as_deref(), &protect, &wan_self_ips);
            if !matches!(verdict, sr::ReflexVerdict::Observed { .. }) {
                let allowlisted = matches!(verdict, sr::ReflexVerdict::Allowlisted { .. });
                let state = load_state(&state_path);
                let diff = sr::reconcile_quarantine(
                    state,
                    &alert.src_ip,
                    mac.as_deref(),
                    ts,
                    ttl_secs,
                    allowlisted,
                    sr::DEFAULT_MAX_QUARANTINE_ENTRIES,
                );
                apply_or_print(&sr::render_element_ops(&diff, ttl_secs).content, cli.apply);
                if let Err(e) = save_state(&state_path, &diff.state) {
                    eprintln!("scan-respond: {e:#}");
                }
                for e in &diff.to_remove {
                    // A revert can happen ON THE SAME cycle as a fresh alert (e.g. the allowlisted
                    // force-release path) — always documented, same as a sweep-triggered revert.
                    let revert_iface = ifaces.for_kind(sr::classify_source(&e.ip));
                    println!("{}", sr::render_revert_json(e, ttl_secs, ts, revert_iface));
                }
            }

            // DOCUMENT — one response line for `hookprobe-evidence --responses` to link to
            // this detection (by rule_id/src_ip/dst_ip/dst_port, the same natural-key match
            // `ingest_detection` already uses for its triggering flows). Emitted for EVERY
            // verdict, including `Observed` — detection is never silenced, only enforcement is
            // gated.
            println!("{}", sr::render_response_json(&alert, &verdict, ttl_secs, ts, iface));
        }
        return Ok(());
    }

    // --- AEGIS reflex: resource-shed (2026-07-07) — RESOURCE-REALITY enforcement, never identity.
    // One-shot, timer-driven (`hookprobe-resource-shed.timer`): re-sample conntrack fill + PSI
    // pressure, decide this cycle's Layer-2/3 triggers, reconcile the shared `shed_ips` set, and
    // (re-)apply Layer 1's always-on blanket cap. See `hookprobe_manifest::scan_responder`'s
    // "RESOURCE-REALITY ENFORCEMENT" module-doc section for the full design/invariants.
    if cli.resource_shed_reconcile {
        use hookprobe_manifest::scan_responder as sr;

        let ttl_secs = cli
            .resource_shed_ttl_secs
            .or_else(|| std::env::var("RESOURCE_SHED_TTL_SECS").ok().and_then(|v| v.parse().ok()))
            .unwrap_or(sr::DEFAULT_SHED_TTL_SECS);
        let state_path = cli
            .resource_shed_state_file
            .clone()
            .unwrap_or_else(|| PathBuf::from("/var/lib/hookprobe/resource-shed.json"));
        let ifaces = sr::ConnRateCapConfig {
            lan_iface: cli.lan_iface.clone().or_else(|| std::env::var("LAN_IFACE").ok()).unwrap_or_else(|| "wlan0".to_string()),
            wan_iface: cli.wan_iface.clone().or_else(|| std::env::var("WAN_IFACE").ok()).unwrap_or_else(|| "end0".to_string()),
            new_conn_pps: cli
                .new_conn_pps
                .or_else(|| std::env::var("RESOURCE_SHED_NEW_CONN_PPS").ok().and_then(|v| v.parse().ok()))
                .unwrap_or(sr::DEFAULT_NEW_CONN_PPS),
            meter_timeout_secs: sr::DEFAULT_CONN_RATE_METER_TIMEOUT_SECS,
            shed_cap_pps: cli
                .shed_cap_pps
                .or_else(|| std::env::var("RESOURCE_SHED_CAP_PPS").ok().and_then(|v| v.parse().ok()))
                .unwrap_or(sr::DEFAULT_SHED_CAP_PPS),
            // Customer-separation floor (2026-07-09 on-metal finding): the mgmt subnet + LAN gateway
            // + configured DNS resolvers get a first-match `accept` so resource-shed never throttles
            // the operator's own segment or the LAN's own NAT/DNS path. Same allowlist the
            // scan-responder path uses (default mgmt subnet 10.200.0.0/28 + LAN gateway 10.66.0.1).
            protect_cidrs: if cli.protect_cidr.is_empty() { vec!["10.200.0.0/28".to_string()] } else { cli.protect_cidr.clone() },
            protect_ips: {
                let mut ips = cli.protect_ip.clone();
                if let Some(gw) = std::env::var("PROTECT_IPS").ok().filter(|v| !v.is_empty()) {
                    ips.extend(gw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
                }
                ips
            },
            max_conns_per_src: std::env::var("RESOURCE_SHED_MAX_CONNS_PER_SRC")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(sr::DEFAULT_MAX_CONNS_PER_SRC),
            // Finding-2 (2026-07-10): the always-on management-plane flood cap. Ports are a
            // comma-list (e.g. "22,2222"); an empty/unset list falls back to the default (sshd :22
            // only). Keyed on a measured per-source new-conn RATE, never identity — see
            // `ConnRateCapConfig::mgmt_ports`.
            mgmt_ports: std::env::var("RESOURCE_SHED_MGMT_PORTS")
                .ok()
                .map(|v| v.split(',').filter_map(|p| p.trim().parse::<u16>().ok()).collect::<Vec<u16>>())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| sr::DEFAULT_MGMT_PORTS.to_vec()),
            mgmt_conn_pps: std::env::var("RESOURCE_SHED_MGMT_CONN_PPS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(sr::DEFAULT_MGMT_CONN_PPS),
        };
        let rr_cfg = sr::ResourceRealityConfig {
            conntrack_saturation_pct: cli
                .conntrack_saturation_pct
                .or_else(|| std::env::var("RESOURCE_SHED_CONNTRACK_SATURATION_PCT").ok().and_then(|v| v.parse().ok()))
                .unwrap_or(sr::DEFAULT_CONNTRACK_SATURATION_PCT),
            top_talker_min_entries: cli
                .top_talker_min_entries
                .or_else(|| std::env::var("RESOURCE_SHED_TOP_TALKER_MIN_ENTRIES").ok().and_then(|v| v.parse().ok()))
                .unwrap_or(sr::DEFAULT_TOP_TALKER_MIN_ENTRIES),
            top_n: sr::DEFAULT_SHED_TOP_N,
            psi: sr::PsiThresholds {
                cpu_some_avg60_pct: cli
                    .cpu_pressure_avg60_pct
                    .or_else(|| std::env::var("RESOURCE_SHED_CPU_AVG60_PCT").ok().and_then(|v| v.parse().ok()))
                    .unwrap_or(sr::DEFAULT_CPU_SOME_AVG60_PCT),
                mem_full_avg60_pct: cli
                    .mem_pressure_avg60_pct
                    .or_else(|| std::env::var("RESOURCE_SHED_MEM_AVG60_PCT").ok().and_then(|v| v.parse().ok()))
                    .unwrap_or(sr::DEFAULT_MEM_FULL_AVG60_PCT),
            },
        };

        // Re-sample every real-world fact THIS cycle (fresh each invocation — a timer-driven
        // oneshot, not a long-running process with cached state) — every read degrades gracefully
        // to "no signal" on any failure (fail toward "don't shed", never toward guessing).
        let read_or = |p: &Option<PathBuf>, default: &str| -> Option<String> {
            std::fs::read_to_string(p.clone().unwrap_or_else(|| PathBuf::from(default))).ok()
        };
        let psi_cpu = read_or(&cli.psi_cpu_file, "/proc/pressure/cpu").map(|t| sr::parse_psi_file(&t)).unwrap_or_default();
        let psi_mem =
            read_or(&cli.psi_mem_file, "/proc/pressure/memory").map(|t| sr::parse_psi_file(&t)).unwrap_or_default();
        let conntrack_count =
            read_or(&cli.conntrack_count_file, "/proc/sys/net/netfilter/nf_conntrack_count").and_then(|t| sr::parse_conntrack_scalar(&t));
        let conntrack_max =
            read_or(&cli.conntrack_max_file, "/proc/sys/net/netfilter/nf_conntrack_max").and_then(|t| sr::parse_conntrack_scalar(&t));
        // Live conntrack dump: prefer a fixture file (tests/dev); else try `conntrack -L` (needs
        // CAP_NET_ADMIN — this unit's systemd file grants it), which is far more complete/portable
        // across kernels than parsing `/proc/net/nf_conntrack` by hand. Best-effort: an empty/
        // unreadable result degrades to "no top-talker visibility this cycle" (see
        // `evaluate_resource_reality`'s doc on why that must never guess a source).
        let conntrack_dump_text = match &cli.conntrack_dump_file {
            Some(p) => std::fs::read_to_string(p).unwrap_or_default(),
            None => std::process::Command::new("conntrack")
                .args(["-L"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                .unwrap_or_default(),
        };
        let inputs = sr::ResourceRealityInputs {
            conntrack_count,
            conntrack_max,
            conntrack_src_ips: sr::parse_conntrack_src_ips(&conntrack_dump_text),
            psi_cpu,
            psi_mem,
        };

        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0);
        let triggers = sr::evaluate_resource_reality(&inputs, &rr_cfg);

        let state: Vec<sr::ShedEntry> =
            std::fs::read_to_string(&state_path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
        let diff = sr::reconcile_resource_shed(state, &triggers, now, ttl_secs, sr::DEFAULT_MAX_SHED_ENTRIES);

        // Layer 1's blanket bootstrap is (re-)applied EVERY cycle (idempotent — add/delete/add) so
        // it is always present without needing a separate unit/dependency; Layer 2/3's per-cycle
        // `shed_ips` element diff rides in the same nft invocation batch.
        let bootstrap_plan = sr::render_conn_rate_cap(&ifaces).content;
        let element_plan = sr::render_shed_element_ops(&diff, ttl_secs).content;
        if !cli.apply {
            eprintln!("resource-shed: PLAN (pass --apply to execute):\n{bootstrap_plan}{element_plan}");
        } else {
            for plan in [&bootstrap_plan, &element_plan] {
                for line in plan.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let argv: Vec<&str> = line.split_whitespace().collect();
                    match std::process::Command::new("nft").args(&argv).status() {
                        Ok(st) if st.success() => eprintln!("resource-shed: nft {} -> ok", argv.join(" ")),
                        Ok(st) => eprintln!("resource-shed: nft {} -> FAILED ({st})", argv.join(" ")),
                        Err(e) => eprintln!("resource-shed: nft {} -> exec error: {e}", argv.join(" ")),
                    }
                }
            }
        }

        let json = serde_json::to_string(&diff.state)?;
        std::fs::write(&state_path, json + "\n").with_context(|| format!("writing resource-shed state {state_path:?}"))?;

        // DOCUMENT — a first-class response record for every shed action (added/refreshed) and
        // every revert this cycle, appended to RESPONSES for `hookprobe-evidence --responses` to
        // ingest exactly like `scan_responder`'s own records.
        for e in &diff.to_add {
            let iface = ifaces.lan_iface.as_str(); // shed_ips is enforced on BOTH ifaces; log the lan one as representative
            println!("{}", sr::render_shed_response_json(e, ifaces.shed_cap_pps, ttl_secs, now, iface));
        }
        for e in &diff.to_remove {
            let iface = ifaces.lan_iface.as_str();
            println!("{}", sr::render_shed_revert_json(e, ttl_secs, now, iface));
        }
        return Ok(());
    }

    // --- AEGIS: one intent → reconcile the whole network in a single pass ---
    if let Some(path) = &cli.reconcile_network {
        use hookprobe_manifest::aegis;
        let mut intent = load_network_intent(path)?;
        // ADR 0034 (c): resolve `wifi.country: auto`/absent → the boot-detected CC the
        // hookprobe-regdomain oneshot wrote (already `iw reg set` before hostapd) — so the
        // generated hostapd `country_code` matches the kernel regdomain and is never `auto`.
        // Ensure a WifiIntent exists even when the operator OMITTED the whole `wifi:` block (the
        // standalone default), so a box in RO still renders `country_code=RO`, not the world floor.
        resolve_wifi_country(intent.wifi.get_or_insert_with(Default::default));
        let ovs_granted = manifest.capabilities.get("openvswitch").is_some_and(|c| {
            matches!(c.state, hookprobe_manifest::types::CapabilityState::Granted)
        });
        let result = aegis::reconcile_network(&manifest, &intent, ovs_granted);
        println!("AEGIS network reconcile — plan (intent → artifacts):");
        for line in &result.plan {
            println!("  {line}");
        }
        for w in &result.warnings {
            println!("  ⚠ {w}");
        }
        match &cli.network_write {
            Some(root) => {
                for f in &result.artifacts {
                    let dst = root.join(&f.path);
                    if let Some(parent) = dst.parent() {
                        std::fs::create_dir_all(parent).with_context(|| format!("mkdir {parent:?}"))?;
                    }
                    std::fs::write(&dst, &f.content).with_context(|| format!("writing {dst:?}"))?;
                }
                eprintln!("wrote {} artifact(s) under {:?}", result.artifacts.len(), root);
            }
            None => {
                println!("{}", "-".repeat(78));
                for f in &result.artifacts {
                    println!("# ===== {} =====", f.path);
                    print!("{}", f.content);
                }
            }
        }
        return Ok(());
    }

    // Locate modules/ directory.
    let manifest_path = manifest_path_ref.canonicalize()
        .with_context(|| format!("resolving manifest path {:?}", manifest_path_ref))?;
    let modules_dir = match cli.modules {
        Some(p) => p,
        None => find_modules_dir(&manifest_path)
            .with_context(|| "could not locate modules/ directory")?,
    };

    // Discover modules. A device with NO modules installed yet (e.g. a fresh data
    // partition whose modules/ dir doesn't exist) is valid — treat it as zero modules
    // rather than erroring, so the supervisor still verifies the manifest + reconciles.
    let discovered = if modules_dir.is_dir() {
        discover_modules(&modules_dir)?
    } else {
        eprintln!("note: modules dir {modules_dir:?} absent — reconciling 0 modules");
        Vec::new()
    };

    // Supply-chain trust store (baked-in release public keys).
    let trust_dir = cli.trust.clone().unwrap_or_else(|| modules_dir.join(".trust"));

    // DEV: simulate the off-device release-signing step (production signs in the HSM).
    if let Some(keyfile) = &cli.sign_modules {
        let dirs: Vec<PathBuf> = discovered.iter().map(|(d, _)| d.clone()).collect();
        let n = module_sig::dev_sign_all(&dirs, keyfile, &trust_dir)?;
        eprintln!("DEV: release-signed {n} modules (key {keyfile:?}) -> trust {trust_dir:?}. Production signs OFF-device.");
    }

    // Verify each module's signature against the trust store BEFORE load (cosign-style). Part A /
    // ADR 0002 agility dispatch: driven by THIS DEVICE's own manifest `crypto.module_signing` —
    // the same suite the CBOM was generated from (`gen-cbom.py` reads the identical policy) — so
    // the on-device enforcement and the shipped CBOM's "implemented" claim can never drift apart.
    // A hybrid suite (the default) requires BOTH ml-dsa-65 AND ed25519; a missing/invalid leg
    // refuses fail-closed, never a silent downgrade to whichever leg happens to still verify.
    let ed_trust_count = module_sig::load_trust(&trust_dir).len();
    let mldsa_trust_count = module_sig::load_trust_mldsa(&trust_dir).len();
    let mut modules: Vec<ModuleDef> = Vec::new();
    println!(
        "Supply chain (cosign-style verify · suite {} · {} ed25519 + {} ml-dsa-65 trusted key(s)):",
        manifest.crypto.suite_id, ed_trust_count, mldsa_trust_count
    );
    for (dir, mut def) in discovered {
        let st = module_sig::verify_module_for_suite(&dir, &trust_dir, &manifest.crypto.module_signing);
        def.sig_verified = module_sig::resolve_sig_verified(&st, &def.signature);
        println!(
            "  {:<18} {:<9} {}",
            def.id,
            st.as_str(),
            if def.signature == "required" { "(required)" } else { "(unsigned-ok)" }
        );
        modules.push(def);
    }
    println!("{}", "-".repeat(78));

    // Reconcile.
    let report = reconcile(&mut manifest, &modules);

    // Print results (mirrors Python reference output format).
    let plat = &manifest.platform;
    println!(
        "Reconcile  device={}  class={}  modules discovered={}",
        plat.profile,
        serde_json::to_value(&plat.class)
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default(),
        modules.len()
    );
    println!("{:<20} {:<10} DETAIL", "MODULE", "STATE");
    println!("{}", "-".repeat(78));

    for r in &report {
        println!("{:<20} {:<10} {}", r.id, r.state.as_str(), r.detail);
    }

    // Real Wasm load (Wasmtime) for every module reconciled to `running` — replaces MockLoader.
    // Load-checks under the module's exact grants + memory budget (execution proven in wasm_loader tests).
    #[cfg(feature = "wasm")]
    {
        use hookprobe_manifest::types::Runtime;
        let wasm_running: Vec<&ModuleDef> = report
            .iter()
            .filter(|r| r.state.as_str() == "running")
            .filter_map(|r| modules.iter().find(|m| m.id == r.id))
            .filter(|m| matches!(m.runtime, Runtime::Wasm))
            .collect();
        if !wasm_running.is_empty() {
            println!("{}", "-".repeat(78));
            println!("Wasm load (Wasmtime · capability-sandboxed):");
            let events = cli.events.clone()
                .or_else(|| std::env::var("HOOKPROBE_EVENTS").ok().map(PathBuf::from))
                .unwrap_or_else(|| PathBuf::from("/var/lib/hookprobe/events"));
            // ADR 0021 A76 AOT selection: this path already has the SIGNED manifest in hand —
            // read the CPU microarch tier straight from it (no re-probe). `None` = A72 baseline.
            let cpu_tier = manifest.hardware.cpu.tier.clone();
            for def in wasm_running {
                match wasm_loader::locate_executable(&def.id, &modules_dir) {
                    None => println!("  {:<18} — no local .wasm (registry pull / not built)", def.id),
                    Some(exec) => {
                        // ADR 0016 Fix A/B: the IDENTICAL gated load path the `--run-wasm` path
                        // applies (digest + path-binding on the exact bytes about to be compiled,
                        // never a re-opened path, never a trusted `.cwasm` for a signed module),
                        // so the two run paths can never diverge. Refuse (skip) just THIS module
                        // on a mismatch/missing-block-in-release — the rest of the reconcile
                        // still proceeds ("Refused" outcome in reconcile vs. non-zero exit on
                        // the single-module `--run-wasm` invocation, per ADR 0016 D2).
                        let digest_install_dir = exec.source_wasm().parent().unwrap_or(&modules_dir).to_path_buf();
                        let preopens: Vec<(String, String)> = def
                            .read_grants()
                            .iter()
                            .filter(|p| std::path::Path::new(p).is_dir())
                            .map(|p| (p.to_string(), p.to_string()))
                            .collect();
                        let mem = def.resources.as_ref().map(|b| b.memory_mb).unwrap_or(256);
                        match wasm_loader::load_check_gated(&exec, def, &digest_install_dir, Some(&events), &preopens, mem, cpu_tier.as_deref()) {
                            Ok(cold_start) => println!(
                                "  {:<18} LOADED  ({} MiB cap · {} preopen · sig {} · {} · cold-start {:?})",
                                def.id,
                                mem,
                                preopens.len(),
                                def.sig_verified.map(|v| if v { "ok" } else { "FAIL" }).unwrap_or("n/a"),
                                exec.describe_gated(def),
                                cold_start
                            ),
                            Err(e) => eprintln!("  {:<18} LOAD FAILED  {e:#}", def.id),
                        }
                    }
                }
            }
            // ADR 0017 residual-risk #1: boot-time telemetry — how many `signature: required`
            // module loads THIS reconcile fell back from the verified-AOT fast path to the
            // verified-JIT floor, for ANY reason. 0 is healthy for every module this image ships
            // an AOT blob for; nonzero surfaces exactly the "silent 1000x regression" drift the
            // ADR's Blocker warns about, as data instead of a mystery slow boot.
            println!(
                "ADR 0017 AOT->JIT fallback count this run: {}",
                wasm_loader::aot_fallback_count()
            );
        }
    }

    println!("{}", "-".repeat(78));

    // Budget summary.
    let alloc = &manifest.resources.allocatable;
    let used_cpu: u64 = manifest.modules.iter().map(|m| m.budget.cpu_pct).sum();
    let used_mem: u64 = manifest.modules.iter().map(|m| m.budget.memory_mb).sum();
    let free_cpu = alloc.cpu_pct.saturating_sub(used_cpu);
    let free_mem = alloc.memory_mb.saturating_sub(used_mem);
    println!(
        "Budget: allocatable cpu={} mem={}MB  |  free after load cpu={} mem={}MB  |  running={}",
        alloc.cpu_pct,
        alloc.memory_mb,
        free_cpu,
        free_mem,
        manifest.modules.len()
    );

    // --- Health phase: self-test → bounded heal → graceful shed; commit-confirmed
    //     (verify-after-apply) for data-plane modules so a reconcile can't self-lockout.
    let mut probe = DemoProbe {
        fail: cli.fail.clone(),
        flaky: cli.flaky.clone(),
        cut_net: cli.cut_net.clone(),
        oom: cli.oom.clone(),
        seen: std::collections::HashMap::new(),
    };
    let health_events = cli.events.clone()
        .or_else(|| std::env::var("HOOKPROBE_EVENTS").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/var/lib/hookprobe/events"));
    let health = run_health(&mut manifest, &modules, HealthPolicy::default(), &mut probe, Some(&health_events));
    if !health.is_empty() {
        println!("\nHealth (self-test → heal → shed · commit-confirmed for data-plane):");
        for h in &health {
            println!("  {:<18} {:<9} {}", h.id, h.state.as_str(), h.detail);
        }
        let shed = health
            .iter()
            .filter(|h| matches!(h.state, HealthState::Failed | HealthState::Reverted))
            .count();
        println!(
            "  running after health = {} ({} shed)",
            manifest.modules.len(),
            shed
        );
    }

    // --- Fleet GitOps: diff the pulled desired state against the live device ---
    if let Some(fp) = &cli.fleet {
        let yaml = std::fs::read_to_string(fp)
            .with_context(|| format!("reading desired-state {fp:?}"))?;
        let desired = fleet::DesiredState::parse(&yaml)?;
        let running: Vec<String> = manifest.modules.iter().map(|m| m.id.clone()).collect();
        let channel = manifest.provenance.image_ref.rsplit(':').next().unwrap_or("dev").to_string();

        // Ring-window enforcement (ADR 0012 D2/build-step-3): `--rollout` is
        // optional — its absence is the documented legacy path (every channel
        // mismatch stays actionable), not an error.
        let rollout = match &cli.rollout {
            Some(rp) => {
                let ry = std::fs::read_to_string(rp)
                    .with_context(|| format!("reading rollout state {rp:?}"))?;
                Some(fleet::RolloutState::parse(&ry)?)
            }
            None => None,
        };
        let drift = fleet::diff_ring_gated(&desired, &running, &channel, rollout.as_ref());

        println!("\nFleet GitOps (desired vs live · channel={channel}):");
        if drift.is_empty() {
            println!("  in sync — no drift");
        } else {
            // Print actionable and pending drift in DISTINCT sections — a node
            // outside its promoted ring window must never read as "in sync" (it
            // isn't) nor be confused with something the agent will act on now.
            let (actionable, pending): (Vec<_>, Vec<_>) =
                drift.iter().partition(|d| d.is_actionable());
            for d in &actionable {
                println!("  drift (actionable): {}", d.describe());
            }
            for d in &pending {
                println!("  drift (pending, ring not promoted — no upgrade): {}", d.describe());
            }
        }
    }

    // --- Boot-health gate (greenboot): one healthy/unhealthy verdict for this boot.
    //     Unhealthy → exit non-zero. WHAT HAPPENS NEXT DEPENDS ON THE TIER (ADR 0019
    //     D2/D3 — the bootc/Debian substrate split), and the old unconditional
    //     "greenboot rolls the image back" comment here was the exact overclaim ADR
    //     0019 F2/F3 flagged: on rpi-native (today's shipping mkosi/Pi image) there is
    //     no second deployment slot and no bootc — a FAIL is NOT auto-rolled-back, it
    //     is a reflash-required event. On a real bootc-managed UEFI deployment (ADR
    //     0019 D2, Phase 1+), a FAIL verdict IS the trigger greenboot's retry-exhaustion
    //     path uses to invoke a REAL `bootc rollback`. Report honestly which applies —
    //     never assert the rollback happened when there was nothing to roll back to.
    //     (Manifest-signature tampering already exits non-zero at load, above.) ---
    if cli.health_gate {
        // Default required set = the always-staged baseline SOC engines. NOT `hydra`:
        // hydra is `status: stub` (ADR 0015 D3), so gen-staging stages nothing for it and
        // it can NEVER appear in manifest.modules — requiring it made every boot UNHEALTHY
        // and, once greenboot is active, would roll back the image on every boot. napse +
        // qsecbit are the two core wasm engines present on every image of every class.
        let required: Vec<String> = if cli.require.is_empty() {
            vec!["napse".to_string(), "qsecbit".to_string()]
        } else {
            cli.require.clone()
        };
        let missing: Vec<&String> = required
            .iter()
            .filter(|r| !manifest.modules.iter().any(|m| &m.id == *r))
            .collect();

        // 2026-07-05 FIX (backend-audit P0 #2 — "health verdict decoupled from unit
        // liveness"): `missing` above only asks whether THIS reconcile invocation's own
        // in-process module load+self-test succeeded (`manifest.modules`, health.rs's
        // survivor set) — it says NOTHING about whether the SEPARATE systemd-managed unit
        // that is supposed to be continuously driving live traffic (e.g. `napse.service`
        // tailing `/var/lib/hookprobe/flows`) is actually still alive. A crashed/dead SOC
        // engine unit could coexist with a perfectly healthy `--health-gate` verdict before
        // this fix (the exact gap that would have hidden a live napse-capture-inactive
        // class regression). Cross-check `systemctl is-active` for each required module's
        // staged unit, BEST-EFFORT: on an environment with no real systemd/units (a dev box,
        // a gate-ladder rehearsal, a container test) `systemctl` is either absent or every
        // query fails uniformly — that is treated as "liveness cross-check unavailable here"
        // and reported honestly, NEVER silently treated as healthy AND never used to
        // fail-close an environment that was never expected to run these units for real.
        let mut dead_units: Vec<String> = Vec::new();
        let mut systemctl_checked_any = false;
        for r in &required {
            if missing.contains(&r) {
                continue; // already unhealthy per the model; no need to also probe systemd
            }
            let unit = module_unit_name(r);
            match systemctl_is_active(&unit) {
                Some(true) => systemctl_checked_any = true,
                Some(false) => {
                    systemctl_checked_any = true;
                    dead_units.push(unit);
                }
                None => {} // systemctl unusable for this unit in this environment — skip honestly
            }
        }

        if missing.is_empty() && dead_units.is_empty() {
            println!(
                "\nBOOT HEALTHY — manifest verified + baseline SOC running ({}).",
                required.join(", ")
            );
            if !systemctl_checked_any {
                println!(
                    "note: systemctl liveness cross-check unavailable in this environment (no systemd/units to query) — verdict is model-only (manifest.modules), same as before this fix."
                );
            }
        } else {
            let mut problems: Vec<String> = missing.iter().map(|s| (*s).clone()).collect();
            problems.extend(dead_units.iter().cloned());
            let bootc_managed = bootc_manages_this_deployment();
            let detail = if dead_units.is_empty() {
                format!("required modules not running: {problems:?}")
            } else if missing.is_empty() {
                format!(
                    "required modules present in the reconcile model but their systemd unit is NOT active: {dead_units:?} (the dataplane engine is dead even though it loaded/self-tested earlier this run)"
                )
            } else {
                format!("required modules unhealthy: {problems:?} (missing-from-model and/or dead systemd unit)")
            };
            if bootc_managed {
                eprintln!(
                    "\nBOOT UNHEALTHY — {detail}. This deployment is bootc-managed: a real `bootc rollback` to the last-good deployment is the expected recovery once greenboot's retry budget is exhausted (ADR 0019 D2)."
                );
            } else {
                eprintln!(
                    "\nBOOT UNHEALTHY — {detail}. NO ROLLBACK SLOT AVAILABLE on this image (single-slot rpi-native/mkosi build, no bootc-managed deployment detected) — this boot is marked FAILED but nothing will automatically revert it. A/B image-sync (ADR 0019 Phase 3) is pending; recovery today is a manual reflash from a known-good image."
                );
            }
            std::process::exit(1);
        }
    }

    // Optionally write reconciled manifest.
    if let Some(out_path) = &cli.write {
        let json = serde_json::to_string_pretty(&manifest)?;
        std::fs::write(out_path, format!("{json}\n"))
            .with_context(|| format!("writing reconciled manifest to {out_path:?}"))?;
        eprintln!("\nwrote reconciled manifest -> {out_path:?}");
        eprintln!("WARNING: modules[] mutated -> signature marked STALE (shipping supervisor re-signs).");
    }

    Ok(())
}

/// Read the last `max_bytes` of a JSONL file (the recent tail — enough to catch currently-
/// ESTABLISHED conntrack flows without reading a multi-GB history). Used by --scan-respond's F4
/// conntrack-confirmation fallback. Returns `""` if the file is absent/unreadable so the caller
/// degrades to "not conntrack-confirmed" — fail-safe toward the anti-spoof default (never toward
/// trusting an unconfirmed source). Drops a possibly-partial first line when we seek mid-file so no
/// half-record reaches the JSONL parser.
fn read_flows_tail(path: &std::path::Path, max_bytes: u64) -> String {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return String::new(),
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(max_bytes);
    if start > 0 && f.seek(SeekFrom::Start(start)).is_err() {
        return String::new();
    }
    // Read raw bytes then lossily decode — seeking into the middle of a multi-byte char (rare for
    // ASCII JSON, but never trust it) must not error the whole read to empty.
    let mut bytes = Vec::new();
    if f.read_to_end(&mut bytes).is_err() {
        return String::new();
    }
    let mut buf = String::from_utf8_lossy(&bytes).into_owned();
    if start > 0 {
        if let Some(nl) = buf.find('\n') {
            buf.drain(..=nl);
        }
    }
    buf
}

/// Discover module definitions from `modules/*/module.yaml`.
fn discover_modules(modules_dir: &std::path::Path) -> Result<Vec<(PathBuf, ModuleDef)>> {
    let mut mods = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(modules_dir)?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.path());

    for entry in entries {
        let dir = entry.path();
        let module_yaml = dir.join("module.yaml");
        if !module_yaml.exists() {
            continue;
        }
        let text = std::fs::read_to_string(&module_yaml)
            .with_context(|| format!("reading {module_yaml:?}"))?;
        let m: ModuleDef = serde_yaml::from_str(&text)
            .with_context(|| format!("parsing {module_yaml:?}"))?;
        mods.push((dir, m));
    }
    Ok(mods)
}

/// The staged systemd unit name for a module id (P0 #2 liveness cross-check). Mirrors the
/// SAME id->unit mapping `builder/gen-staging.sh` actually stages (every `units/*.service`
/// glob is named after the module directory, one exception: `napse-capture`'s staged unit is
/// `napse-dpi.service`, not `napse-capture.service` — see `modules/napse-capture/module.yaml`'s
/// `staging.units`). Not a second inclusion list (ADR 0015 D0 stays the registry): this is
/// purely a display/lookup mapping for a module id the CALLER already decided is required.
fn module_unit_name(module_id: &str) -> String {
    match module_id {
        "napse-capture" => "napse-dpi.service".to_string(),
        other => format!("{other}.service"),
    }
}

/// Best-effort `systemctl is-active --quiet <unit>` — `Some(true)`/`Some(false)` when the
/// query genuinely ran (systemd IS present and answered), `None` when it could not be asked
/// at all (no `systemctl` binary, or the call itself errored — a dev box / container
/// rehearsal with no real systemd, not a verdict about the unit). Callers MUST treat `None`
/// as "skip honestly", never as healthy or unhealthy — the same fail-closed-but-never-
/// fabricated-green discipline `bootc_manages_this_deployment` already uses below.
fn systemctl_is_active(unit: &str) -> Option<bool> {
    match std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .status()
    {
        Ok(status) => Some(status.success()),
        Err(_) => None,
    }
}

/// Auto-detect the boot disk's bare name (e.g. `nvme0n1`) from the real root
/// filesystem: `findmnt -no SOURCE /sysroot|/` → `lsblk -no PKNAME`. Returns ""
/// if it can't be determined (the picker then reports an explicit None).
/// Honesty check for the boot-health gate (ADR 0019 D2/D3): is `bootc` actually
/// managing THIS running deployment (a real second slot to roll back to), or is
/// `bootc` merely absent / present-but-inert (rpi-native mkosi image, dev box,
/// container test run)? `bootc status` only succeeds against a real bootc-managed
/// root — a bare `command -v bootc` is not enough, since a future UEFI-tier image
/// could ship the binary without yet being deployed via bootc install. Never assume
/// the optimistic case: absence of evidence (no binary, non-zero exit, no output)
/// means "not bootc-managed" here, on purpose.
fn bootc_manages_this_deployment() -> bool {
    match std::process::Command::new("bootc").arg("status").output() {
        Ok(out) => out.status.success() && !out.stdout.is_empty(),
        Err(_) => false,
    }
}

/// The signed Platform Manifest's on-device path (schema 2) — the single source of truth for
/// capabilities AND crypto posture (`docs/architecture/Readme.md` "detect once, query forever").
#[cfg(feature = "wasm")]
const DEFAULT_MANIFEST_PATH: &str = "/var/lib/hookprobe/manifest.json";

/// ADR 0017/0021 — read the CPU microarch tier (`hardware.cpu.tier`) from the signed Platform
/// Manifest, for the otherwise-manifest-less `--run-wasm` streaming datapath. Best-effort: uses the
/// caller-supplied manifest path, else the on-device default; on ANY error (absent, unreadable,
/// unparseable, or no tier field) returns `None` — the always-safe A72 baseline (never an A76 blob
/// on an A72). This only READS a field to ADD a candidate AOT tier; it can never make a load LESS
/// safe than baseline. Residual (documented, ADR 0021): a tampered manifest that falsely claims a
/// higher tier could, on that arch, make the loader attempt a legit-but-higher-tier blob whose
/// illegal instructions would trap on the real (lower) CPU — a self-inflicted DoS, not RCE (the
/// blob bytes are still digest-bound to the SIGNED module.yaml, unforgeable), and it requires write
/// access to the persistent partition; production verifies the manifest signature at provision time
/// and the manifest is frozen thereafter.
#[cfg(feature = "wasm")]
fn manifest_cpu_tier(manifest_path: Option<&std::path::Path>) -> Option<String> {
    let path = manifest_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_MANIFEST_PATH));
    let text = std::fs::read_to_string(&path).ok()?;
    let manifest: Manifest = serde_json::from_str(&text).ok()?;
    manifest.hardware.cpu.tier
}

fn detect_boot_dev() -> String {
    let run = |args: &[&str]| -> Option<String> {
        let out = std::process::Command::new(args[0]).args(&args[1..]).output().ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    };
    let src = run(&["findmnt", "-no", "SOURCE", "/sysroot"])
        .or_else(|| run(&["findmnt", "-no", "SOURCE", "/"]))
        .unwrap_or_default();
    if src.is_empty() {
        return String::new();
    }
    // Direct-partition root (SBC / bootc norm): PKNAME is the whole disk.
    if let Some(pk) = run(&["lsblk", "-no", "PKNAME", &src]) {
        if let Some(n) = pk.lines().next().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            return n.to_string();
        }
    }
    // LVM / dm root: PKNAME is empty — walk the dependency tree down to the physical
    // disk (`lsblk -s` lists leaf→root; the last TYPE=disk row is the boot disk).
    if let Some(tree) = run(&["lsblk", "-sno", "NAME,TYPE", &src]) {
        if let Some(disk) = tree
            .lines()
            .filter_map(|l| {
                let mut it = l.split_whitespace();
                let name = it.next()?;
                let ty = it.next()?;
                (ty == "disk").then(|| name.trim_start_matches(['`', '|', '-', ' ', '\u{2514}', '\u{2500}']).to_string())
            })
            .next_back()
        {
            return disk;
        }
    }
    String::new()
}

/// Resolve the `network:` intent for `--reconcile-network <path>`. 2026-07-05 FIX
/// (backend-audit P1 #4 — "network.yaml single-point-of-failure"): an ABSENT intent file
/// is "omit the whole document" — exactly the same safe-defaults case `NetworkIntent`'s
/// `#[serde(default)]` + every sub-intent's own `Option<...>` already handles for "omit one
/// section" (`aegis::reconcile_network` already `.unwrap_or_default()`s each section, e.g.
/// `intent.wan.clone().unwrap_or_default()`). Before this fix, the CALLER
/// (`hookprobe-network-reconcile.service`'s `ConditionPathExists=/etc/hookprobe/network.yaml`)
/// gated the ENTIRE reconcile — including the mirror/fabric bring-up that has nothing to do
/// with operator overrides — on that one file's mere existence, so a device that never
/// wrote/shipped a network.yaml got NO network reconcile at all (not even the manifest-
/// derived safe defaults) instead of the intended "defaults everywhere" behavior. A file
/// that DOES exist but fails to PARSE is still a hard error (real corruption, not absence)
/// — only ENOENT falls back to defaults, so a typo'd network.yaml is never silently ignored.
fn load_network_intent(path: &std::path::Path) -> Result<hookprobe_manifest::aegis::NetworkIntent> {
    use hookprobe_manifest::aegis;
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(aegis::HookprobeIntent::parse(&text)
            .with_context(|| "parsing hookprobe.yaml intent")?
            .network),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "note: network intent {path:?} not found -- reconciling with NetworkIntent::default() (safe defaults: auto fabric, idle Wi-Fi, manifest WAN order, ...)"
            );
            Ok(aegis::NetworkIntent::default())
        }
        Err(e) => Err(e).with_context(|| format!("reading intent {path:?}")),
    }
}

/// Read the boot-detected regulatory country the `hookprobe-regdomain.service` oneshot wrote to
/// `/run/hookprobe/wifi-country` (the output of `wifi_calibrate::decide_country`, already applied
/// via `iw reg set` BEFORE hostapd starts — ADR 0034). Returns the trimmed contents, or `None`.
fn read_boot_detected_country() -> Option<String> {
    let p = std::env::var("WIFI_COUNTRY_FILE")
        .unwrap_or_else(|_| "/run/hookprobe/wifi-country".to_string());
    std::fs::read_to_string(&p).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Resolve a Wi-Fi intent's `country` in place so a generated hostapd `country_code` is ALWAYS a
/// valid regdomain token, never `auto` (ADR 0034 (c)). Precedence (via
/// `wifi_calibrate::resolved_country_for_render`): a real operator-intent 2-letter code wins;
/// else the boot-detected CC from `/run/hookprobe/wifi-country`; else world `00`. Mutates the
/// intent's `country` to the resolved value so BOTH `wifi_cfg::render` and the plan see it.
fn resolve_wifi_country(intent: &mut hookprobe_manifest::wifi_cfg::WifiIntent) {
    use hookprobe_manifest::wifi_calibrate::resolved_country_for_render;
    let run_file = read_boot_detected_country();
    let resolved = resolved_country_for_render(intent.country.as_deref(), run_file.as_deref());
    intent.country = Some(resolved);
}

/// Locate a `modules/` directory by walking upward from the manifest path, then
/// (fallback) from the current working directory. The manifest commonly lives on
/// a data partition (e.g. /var/lib/hookprobe) with no `modules/` above it, so the
/// cwd fallback makes the default work when run from the repo / install root.
fn find_modules_dir(start: &std::path::Path) -> Option<PathBuf> {
    fn walk_up(mut dir: &std::path::Path) -> Option<PathBuf> {
        loop {
            let candidate = dir.join("modules");
            if candidate.is_dir() {
                return Some(candidate);
            }
            dir = dir.parent()?;
        }
    }
    start
        .parent()
        .and_then(walk_up)
        .or_else(|| std::env::current_dir().ok().and_then(|cwd| walk_up(&cwd)))
}

#[cfg(test)]
mod network_intent_fallback_tests {
    //! backend-audit P1 #4 — "network.yaml single-point-of-failure". Regression coverage
    //! for `load_network_intent`: an absent file must reconcile with safe defaults (never
    //! error, never require the caller to gate on the file's existence first), a malformed
    //! file must still hard-fail (absence != corruption), and a present, valid file must
    //! parse exactly as before.
    use super::load_network_intent;

    #[test]
    fn absent_file_falls_back_to_network_intent_default() {
        let dir = tempfile_dir("absent");
        let path = dir.join("does-not-exist.yaml");
        assert!(!path.exists());

        let intent = load_network_intent(&path).expect("an absent network.yaml must NOT be an error");
        let default_intent = hookprobe_manifest::aegis::NetworkIntent::default();
        // NetworkIntent has no PartialEq — compare via Debug (every field is None in both,
        // so this is exact, not approximate).
        assert_eq!(format!("{intent:?}"), format!("{default_intent:?}"));
    }

    #[test]
    fn present_valid_file_parses_the_declared_section() {
        let dir = tempfile_dir("present-valid");
        let path = dir.join("network.yaml");
        std::fs::write(&path, "network:\n  wan: {}\n").unwrap();

        let intent = load_network_intent(&path).expect("a present, valid file must parse");
        // `wan: {}` decodes to Some(WanIntent::default()) -- proves the FILE was actually
        // read (not silently treated as absent) while still resolving to a safe default.
        assert!(intent.wan.is_some(), "expected the declared `wan:` section to be Some(_)");
    }

    #[test]
    fn present_but_malformed_file_is_a_hard_error_not_a_silent_default() {
        let dir = tempfile_dir("malformed");
        let path = dir.join("network.yaml");
        // Invalid YAML (unterminated mapping) -- must fail to parse, not be treated as
        // "absent" and silently default (absence != corruption).
        std::fs::write(&path, "network: [this is not a mapping\n").unwrap();

        let err = load_network_intent(&path).expect_err("malformed YAML must be a hard error");
        assert!(
            format!("{err:#}").contains("parsing hookprobe.yaml intent"),
            "got: {err:#}"
        );
    }

    /// Minimal per-test scratch dir under the target dir (no extra dev-dependency needed).
    fn tempfile_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "hookprobe-supervisor-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
