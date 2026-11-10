"""End-of-line self-test. Quick and safe only: no soaks, no traffic attacks, nothing that mutates policy.

Checks (each -> {name, ok, detail}):
  * boot contract on the post-claim boot log: the same markers tools/diagnostics/cm5-metal-loop.sh waits for
    (secure boot PASS, HBoot-AB PASS, P10-B PASS, P11-AP2 PASS) and none of its failure markers
  * owner CLAIMED, HTTPS ready (the MCTLS.CRT patch took effect)
  * setup credential is IDENTICAL to the first boot's (the label value is stable across a reboot; ADR 0054 D1)
  * the AP's PSK source is "the per-device setup credential" (never WIFI.TXT/build env on a factory unit)
  * BSSID (if printed) equals the per-device Wi-Fi MAC
  * optional --mc-url: owner sign-in works with the token, a wrong token and the unauthenticated API are refused
  * optional --run-mc-e2e: os/kernel/tools/mc-e2e-metal.sh --no-browser (heavier; includes its own attack probes)
"""
import http.client
import re
import secrets as _secrets
import subprocess
import urllib.parse

from . import serialparse as sp

FAIL_RE = [re.compile(p) for p in (r"secure boot: FAIL", r"\[P10-B\] SILENT", r"PANIC", r"panicked", r"halting;",
                                   r"AP will NOT start")]            # cm5-metal-loop.sh:41


def check_boot(first, second):
    """first: identity.json; second: parse() of the post-claim boot + `setup_same` / `fail_markers` computed by the
    caller (the passphrase itself never enters these dicts)."""
    res = []

    def add(name, ok, detail=""):
        res.append({"name": name, "ok": bool(ok), "detail": detail})
    add("secure boot PASS", second.get("secure_boot") == "PASS", second.get("secure_boot", "marker absent"))
    add("HBoot-AB PASS", second.get("hboot_ab"))
    add("Wi-Fi firmware up (P10-B PASS)", second.get("p10b"))
    add("WPA2 AP up (P11-AP2 PASS)", "ap2_ssid" in second, second.get("ap2_ssid", "marker absent"))
    bad = second.get("fail_markers", ["fail_markers not computed"])
    add("no failure markers", not bad, ", ".join(bad))
    add("owner CLAIMED after patch", second.get("owner") == "CLAIMED", second.get("owner", "marker absent"))
    add("HTTPS ready (MCTLS.CRT accepted)", second.get("tls_ready"),
        "rejected" if second.get("tls_rejected") else "no certificate" if second.get("tls_nocert") else "")
    add("setup credential identical across reboot", second.get("setup_same"))
    add("TLS key identical across reboot", second.get("tls_pub") is not None and second.get("tls_pub") == first.get("tls_pub"))
    add("PSK source is the per-device setup credential", second.get("psk_source") == "the per-device setup credential",
        second.get("psk_source", "marker absent"))
    if "ap_bssid" in second:
        add("BSSID equals per-device Wi-Fi MAC", second["ap_bssid"] == first.get("wifi_mac"), "")
    return res


def _req(host, port, method, path, body=None, timeout=8):
    c = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        h = {"Content-Type": "application/x-www-form-urlencoded"} if body is not None else {}
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        r.read()
        return r.status, r.getheader("Set-Cookie") or ""
    finally:
        c.close()


def check_http(mc_url, token):
    """Owner auth behaves (tools/mc-e2e.sh:76-82): wrong token = no session, right token = HttpOnly cookie, and the
    protected API is 401 without one. The token goes in the POST body only, never in a URL or argv."""
    u = urllib.parse.urlparse(mc_url)
    host, port = u.hostname, u.port or 80
    res = []

    def add(name, ok, detail=""):
        res.append({"name": name, "ok": bool(ok), "detail": detail})
    try:
        st, _ = _req(host, port, "GET", "/api/dns")
        add("protected API refuses without a session", st == 401, f"HTTP {st}")
        wrong = "WRONG-" + _secrets.token_hex(8)
        st, ck = _req(host, port, "POST", "/api/login", "token=" + urllib.parse.quote(wrong))
        add("wrong owner key gets no session", "hq_session" not in ck, f"HTTP {st}")
        st, ck = _req(host, port, "POST", "/api/login", "token=" + urllib.parse.quote(token))
        add("owner key signs in (HttpOnly cookie)", "hq_session" in ck and "HttpOnly" in ck, f"HTTP {st}")
    except OSError as e:
        add("Mission Control reachable", False, f"{type(e).__name__}: {e}")
    return res


def run_mc_e2e(script, ip, key_file, timeout=900):
    r = subprocess.run([script, "--ip", ip, "--key-file", key_file, "--no-browser"],
                       capture_output=True, text=True, timeout=timeout)
    tail = "\n".join((r.stdout + r.stderr).strip().splitlines()[-5:])
    return [{"name": "mc-e2e-metal.sh --no-browser", "ok": r.returncode == 0, "detail": tail}]
