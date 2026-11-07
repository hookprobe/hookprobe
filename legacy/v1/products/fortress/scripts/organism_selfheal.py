#!/usr/bin/env python3
"""HookProbe Fortress — Organism Self-Heal watchdog.

The single restart authority for the Fortress node. Periodically (systemd
timer, ~5 min) it checks that everything that was built is actually running
and producing data, auto-heals what it safely can, and escalates the rest.

Mirrors the canonical hookprobe-com scripts/organism_selfheal.py contract:
  - HealthReport with exit codes: 0 = healthy, 1 = healed (action taken),
    2 = critical (needs a human).
  - Restart-storm protection: a crash-looping unit is restarted at most
    MAX_RESTARTS_PER_HOUR before we stop and escalate to CRITICAL.
  - Atomic JSON health report for dashboards.

Fortress-specific scope (vs the MSSP/website canon): the fts-* container
stack, fts-* host services, and the ClickHouse data-freshness signals that
matter here (CNO heartbeat, NSM capture). Website checks (blog/social/SEO/
VIRE/SSL) are intentionally omitted.

Run: organism_selfheal.py [--json]   (root; uses rootful podman + systemctl)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# Containers that SHOULD be running (managed by fortress.service /
# fortress-ids.service / aiochi.service). If one is not running we restart it.
EXPECTED_CONTAINERS = [
    # core (fortress.service)
    "fts-postgres", "fts-redis", "fts-web", "fts-qsecbit", "fts-dnsxai", "fts-dfs",
    # IDS (fortress-ids.service)
    "fts-hydra-feed", "fts-hydra-consumer", "fts-hydra-enricher",
    "fts-hydra-features", "fts-hydra-anomaly", "fts-hydra-lifecycle",
    "fts-hydra-temporal", "fts-hydra-sentinel", "fts-qsecbit-ids",
    # AIOCHI (aiochi.service)
    "aiochi-clickhouse", "aiochi-bubble", "aiochi-identity",
    "aiochi-logshipper", "aiochi-suricata", "aiochi-zeek",
]

# Host systemd services that should be active.
HOST_SERVICES = [
    "fts-cno", "fts-slaai", "fts-htp-vpn", "fts-wan-failover",
    "fts-device-lifecycle", "fts-fingerprint-engine", "fts-presence-sensor",
    "fts-host-agent",
    # Datapath: NAPSE flow inspector + XDP attach on FTS-mirror. fts-xdp is a
    # oneshot (RemainAfterExit), so is-active reports the attach state.
    "fts-napse", "fts-xdp",
]

# ClickHouse data-freshness signals: table -> (database, ts_column, max_age_s,
# producer). If the newest row is older than max_age_s we restart the producer
# (a container name or systemd:<svc>). Storm-protected; escalates to CRITICAL
# once the restart budget is exhausted.
DATA_FRESHNESS = {
    "cno_emotion_log": ("hookprobe_ids", "timestamp", 600, "systemd:fts-cno"),  # CNO heartbeat ~60s
    "zeek_connections": ("aiochi", "ts", 1200, "aiochi-logshipper"),            # continuous NSM capture
    # NAPSE flows land on flow expiry (~300s) — newest row routinely 300-330s
    # old; 900s tolerates quiet gaps with no expiring flows before flagging.
    "napse_flows": ("hookprobe_ids", "timestamp", 900, "systemd:fts-napse"),
    # XDP stats flush ~10s. Stale-despite-consumer-up means the program
    # detached from FTS-mirror, so re-attach (fts-xdp is idempotent).
    "xdp_stats": ("hookprobe_ids", "timestamp", 300, "systemd:fts-xdp"),
}

# HTTP health endpoints (warn-only; container/service checks do the healing).
HEALTH_ENDPOINTS = {
    "cno": "http://127.0.0.1:8900/healthz",
}

CH_HOST = os.environ.get("CLICKHOUSE_HOST", "127.0.0.1")
CH_PORT = os.environ.get("CLICKHOUSE_PORT", "8123")
CH_USER = os.environ.get("SELFHEAL_CH_USER", "aiochi")
CH_PASSWORD = os.environ.get("SELFHEAL_CH_PASSWORD", "aiochi_secure_password")

HEALTH_REPORT = os.environ.get(
    "SELFHEAL_REPORT", "/var/lib/fortress/health/selfheal.json")
DISCORD_WEBHOOK = os.environ.get("DISCORD_WEBHOOK_URL", "")

# Don't escalate transient post-boot churn: within this window a not-yet-up
# unit is a WARNING, not CRITICAL.
BOOT_GRACE_SEC = int(os.environ.get("SELFHEAL_BOOT_GRACE_SEC", "600"))

RESTART_LIMIT_FILE = "/tmp/fortress-selfheal-restarts"
MAX_RESTARTS_PER_HOUR = 3
DISK_MIN_FREE_GB = 3


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 20) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except Exception as e:
        return 1, str(e)


def _ch_query(sql: str, database: str) -> Optional[str]:
    try:
        req = urllib.request.Request(
            f"http://{CH_HOST}:{CH_PORT}/?database={database}",
            data=sql.encode("utf-8"),
        )
        req.add_header("X-ClickHouse-User", CH_USER)
        req.add_header("X-ClickHouse-Key", CH_PASSWORD)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.read().decode("utf-8").strip()
    except Exception:
        return None


def _post_discord(message: str) -> None:
    if not DISCORD_WEBHOOK:
        return
    try:
        data = json.dumps({"content": message[:1900]}).encode("utf-8")
        req = urllib.request.Request(
            DISCORD_WEBHOOK, data=data, method="POST",
            headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


def _system_uptime_sec() -> float:
    try:
        return float(Path("/proc/uptime").read_text().split()[0])
    except Exception:
        return 1e9


# Restart-storm protection — the single restart authority. A crash-looping
# unit is restarted at most MAX_RESTARTS_PER_HOUR before escalating to a human.

def _restart_recent() -> list[str]:
    cutoff = int(time.time()) - 3600
    try:
        lines = Path(RESTART_LIMIT_FILE).read_text().splitlines()
    except OSError:
        return []
    keep = []
    for ln in lines:
        parts = ln.split()
        if len(parts) == 2:
            try:
                if int(parts[1]) > cutoff:
                    keep.append(ln)
            except ValueError:
                pass
    return keep


def _can_restart(name: str) -> bool:
    return sum(1 for ln in _restart_recent()
               if ln.split()[0] == name) < MAX_RESTARTS_PER_HOUR


def _record_restart(name: str) -> None:
    try:
        keep = _restart_recent()
        keep.append(f"{name} {int(time.time())}")
        Path(RESTART_LIMIT_FILE).write_text("\n".join(keep) + "\n")
    except OSError:
        pass


@dataclass
class HealthReport:
    timestamp: str = ""
    checks_run: int = 0
    checks_ok: int = 0
    checks_warn: int = 0
    checks_crit: int = 0
    healed: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    criticals: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)

    @property
    def exit_code(self) -> int:
        if self.criticals:
            return 2
        if self.healed:
            return 1
        return 0

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "checks_run": self.checks_run,
            "checks_ok": self.checks_ok,
            "checks_warn": self.checks_warn,
            "checks_crit": self.checks_crit,
            "healed": self.healed,
            "warnings": self.warnings,
            "criticals": self.criticals,
            "details": self.details,
        }


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def _container_running(name: str) -> Optional[bool]:
    """True/False if known, None if the container doesn't exist."""
    rc, out = _run(["podman", "inspect", "-f", "{{.State.Status}}", name])
    if rc != 0:
        return None
    return out == "running"


def check_containers(report: HealthReport) -> None:
    booting = _system_uptime_sec() < BOOT_GRACE_SEC
    for name in EXPECTED_CONTAINERS:
        report.checks_run += 1
        state = _container_running(name)
        if state is True:
            report.checks_ok += 1
            continue
        # Not running (or missing) — try to heal.
        if not _can_restart(name):
            report.checks_crit += 1
            report.criticals.append(
                f"container {name} not running and restart budget exhausted "
                f"({MAX_RESTARTS_PER_HOUR}/hr) — needs a human")
            continue
        _record_restart(name)
        if state is None:
            # Missing entirely — boot units own creation; just flag (warn
            # during boot grace, else critical).
            report.checks_crit += 1
            (report.warnings if booting else report.criticals).append(
                f"container {name} does not exist (boot unit should create it)")
            continue
        rc, _ = _run(["podman", "restart", name], timeout=60)
        time.sleep(2)
        if _container_running(name) is True:
            report.checks_warn += 1
            report.healed.append(f"restarted container {name}")
        else:
            report.checks_crit += 1
            (report.warnings if booting else report.criticals).append(
                f"container {name} failed to restart (rc={rc})")


def check_host_services(report: HealthReport) -> None:
    booting = _system_uptime_sec() < BOOT_GRACE_SEC
    for svc in HOST_SERVICES:
        report.checks_run += 1
        rc, out = _run(["systemctl", "is-active", svc])
        if out == "active":
            report.checks_ok += 1
            continue
        if out in ("inactive", "") and not _run(["systemctl", "is-enabled", svc])[1].startswith("enabled"):
            # not enabled / not installed here — skip silently
            report.checks_ok += 1
            continue
        if not _can_restart(svc):
            report.checks_crit += 1
            report.criticals.append(
                f"service {svc} {out} and restart budget exhausted — needs a human")
            continue
        _record_restart(svc)
        _run(["systemctl", "restart", svc], timeout=60)
        time.sleep(2)
        if _run(["systemctl", "is-active", svc])[1] == "active":
            report.checks_warn += 1
            report.healed.append(f"restarted service {svc}")
        else:
            report.checks_crit += 1
            (report.warnings if booting else report.criticals).append(
                f"service {svc} failed to restart (was {out})")


def _restart_producer(producer: str) -> tuple[bool, str]:
    """Restart a freshness producer (container or systemd:<svc>)."""
    if producer.startswith("systemd:"):
        svc = producer.split(":", 1)[1]
        _run(["systemctl", "restart", svc], timeout=60)
        time.sleep(2)
        return _run(["systemctl", "is-active", svc])[1] == "active", svc
    _run(["podman", "restart", producer], timeout=60)
    time.sleep(2)
    return _container_running(producer) is True, producer


def check_data_freshness(report: HealthReport) -> None:
    if _system_uptime_sec() < BOOT_GRACE_SEC:
        return  # let producers warm up after boot
    for table, (db, ts_col, max_age_s, producer) in DATA_FRESHNESS.items():
        report.checks_run += 1
        out = _ch_query(
            f"SELECT toUnixTimestamp(now()) - toUnixTimestamp(max({ts_col})) "
            f"FROM {table}", db)
        if out is None or out == "" or out.lower().startswith("code"):
            report.checks_warn += 1
            report.warnings.append(f"freshness: cannot query {db}.{table}")
            continue
        try:
            age = int(float(out))
        except ValueError:
            report.checks_warn += 1
            report.warnings.append(f"freshness: bad value for {table}: {out!r}")
            continue
        report.details[f"freshness_{table}_s"] = age
        if age <= max_age_s:
            report.checks_ok += 1
            continue
        # Stale — heal the producer (storm-protected).
        if not _can_restart(producer):
            report.checks_crit += 1
            report.criticals.append(
                f"{db}.{table} stale ({age}s > {max_age_s}s); producer "
                f"{producer} restart budget exhausted — needs a human")
            continue
        _record_restart(producer)
        ok, who = _restart_producer(producer)
        if ok:
            report.checks_warn += 1
            report.healed.append(
                f"restarted {who} ({table} stale {age}s > {max_age_s}s)")
        else:
            report.checks_crit += 1
            report.criticals.append(
                f"{table} stale and producer {producer} failed to restart")


def check_health_endpoints(report: HealthReport) -> None:
    for name, url in HEALTH_ENDPOINTS.items():
        report.checks_run += 1
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                ok = resp.status == 200
        except Exception:
            ok = False
        if ok:
            report.checks_ok += 1
        else:
            report.checks_warn += 1
            report.warnings.append(f"health endpoint {name} ({url}) not responding")


def check_disk_space(report: HealthReport) -> None:
    report.checks_run += 1
    try:
        st = os.statvfs("/")
        free_gb = (st.f_bavail * st.f_frsize) / (1024 ** 3)
        report.details["disk_free_gb"] = round(free_gb, 1)
        if free_gb < DISK_MIN_FREE_GB:
            report.checks_crit += 1
            report.criticals.append(f"disk space low: {free_gb:.1f} GB free")
        else:
            report.checks_ok += 1
    except Exception as e:
        report.checks_warn += 1
        report.warnings.append(f"disk check failed: {e}")


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def run_selfheal() -> HealthReport:
    report = HealthReport(timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    check_containers(report)
    check_host_services(report)
    check_data_freshness(report)
    check_health_endpoints(report)
    check_disk_space(report)
    return report


def main() -> int:
    report = run_selfheal()
    try:
        p = Path(HEALTH_REPORT)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        os.replace(tmp, p)
    except OSError:
        pass

    if "--json" in sys.argv:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"=== Fortress Self-Heal — {report.timestamp} ===")
        print(f"checks: {report.checks_ok}OK {report.checks_warn}WARN "
              f"{report.checks_crit}CRIT / {report.checks_run} total")
        for h in report.healed:
            print(f"  + healed: {h}")
        for w in report.warnings:
            print(f"  ! warn:   {w}")
        for c in report.criticals:
            print(f"  x CRIT:   {c}")
        if not (report.healed or report.warnings or report.criticals):
            print("  all systems nominal")

    if report.criticals:
        _post_discord(
            "HookProbe Fortress Self-Heal CRITICAL\n"
            + "\n".join(f"- {c}" for c in report.criticals))
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
