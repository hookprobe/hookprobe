"""Parse the heqk boot log into a unit identity and the per-device setup credential.

Every pattern below mirrors a real `kprint!`/`puts` format in the kernel; the file:line is cited next to it
(os/kernel at the time of writing; if a marker moves or changes wording, the tests' fixtures AND this table
are the places to update). Nothing is invented: a marker that is absent is reported as absent, never guessed.

The host can never compute the credential (no SRK off-device, ADR 0054 D1): it only reads what the device prints.
"""
import re

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

CROCKFORD = "0123456789abcdefghjkmnpqrstvwxyz"           # apcred.rs:13 (lowercase, no i l o u)
_G = "[0-9a-hjkmnp-tv-z]{4}"
PSK_RE = re.compile(rf"^{_G}(?:-{_G}){{3}}$")             # apcred.rs: 4 groups of 4, '-' joined, 19 chars
SSID_RE = re.compile(r"^HookProbe-Setup-[0-9A-HJKMNP-TV-Z]{4}$")   # apcred.rs:88-90 (ALPHA uppercased, 20 chars)
MAC = r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}"

# name -> (regex, citation)
MARKERS = {
    # main.rs:2840  " [WIFI] per-device MAC {:02x}:..:{:02x} (locally administered, derived from the device secret)"
    "wifi_mac": (re.compile(rf"\[WIFI\] per-device MAC ({MAC}) "), "kernel/src/main.rs:2840"),
    # main.rs:3027  " [WIFI] setup AP \"{ssid}\" — per-device passphrase {psk} (label / QR: {WIFI:T:WPA;S:..;P:..;;})"
    "setup_ap": (re.compile(r'\[WIFI\] setup AP "([^"]+)"\s*\S+\s*per-device passphrase (\S+) \(label / QR: (WIFI:[^)]*;;)\)'),
                 "kernel/src/main.rs:3027"),
    # main.rs:3034  " [WIFI] no WIFI.TXT, no build-time PSK and no device-unique key — the AP will NOT start ..."
    "no_ap": (re.compile(r"\[WIFI\] no WIFI\.TXT, no build-time PSK and no device-unique key"), "kernel/src/main.rs:3034"),
    # tlshost.rs:421-425  " [MC-TLS] device TLS key (P-256, SRK-derived) pub=" + 65 bytes hex (4 kprint! calls) + "\n"
    "tls_pub": (re.compile(r"\[MC-TLS\] device TLS key \(P-256, SRK-derived\) pub=([0-9a-f]{130})\b"), "kernel/src/tlshost.rs:421"),
    # tlshost.rs:410 " [MC-TLS] OFF — no device root key (SRK): refusing a guessable TLS key"
    "tls_off_nosrk": (re.compile(r"\[MC-TLS\] OFF — no device root key"), "kernel/src/tlshost.rs:410"),
    # tlshost.rs:427  " [MC-TLS] HTTPS ready on :443 — certificate chain of {} from MCTLS.CRT, ..."
    "tls_ready": (re.compile(r"\[MC-TLS\] HTTPS ready on :443"), "kernel/src/tlshost.rs:427"),
    # tlshost.rs:429-431  "HTTPS OFF — MCTLS.CRT present but rejected" / "HTTPS OFF — no certificate provisioned"
    "tls_rejected": (re.compile(r"\[MC-TLS\] HTTPS OFF — MCTLS\.CRT present but rejected"), "kernel/src/tlshost.rs:429"),
    "tls_nocert": (re.compile(r"\[MC-TLS\] HTTPS OFF — no certificate provisioned"), "kernel/src/tlshost.rs:431"),
    # main.rs:1674-1678 " [NETCP] device identity (SRK-derived) pk=<hex> fp[0..8]=<16 hex> — register this pk ..."
    # (printed ONLY when a provisioned MSSP blob exists: not guaranteed on a factory image)
    "netcp_id": (re.compile(r"\[NETCP\] device identity \(SRK-derived\) pk=([0-9a-f]+) fp\[0\.\.8\]=([0-9a-f]{16})"),
                 "kernel/src/main.rs:1674"),
    # main.rs:3610 / 1873 / mcserve.rs:557  " [AP-MC] owner: CLAIMED — ..." | "UNCLAIMED — ..." (also "[MC] owner:")
    "owner": (re.compile(r"\[(?:AP-MC|MC)\] owner: (CLAIMED|UNCLAIMED)"), "kernel/src/main.rs:3610"),
    # main.rs:3338  " [P11-AP2] PASS(ap-config-wpa2) — WPA2 BSS up (try N); join \"{ssid}\" (PSK from {src}); ..."
    "ap2_pass": (re.compile(r'\[P11-AP2\] PASS\(ap-config-wpa2\)[^"]*"([^"]*)" \(PSK from ([^)]*)\)'), "kernel/src/main.rs:3338"),
    # main.rs:3325  "... | get_ap={} bssid xx:xx:xx:xx:xx:xx mac_set=..."
    "ap2_bssid": (re.compile(rf"get_ap=\S+ bssid ({MAC})"), "kernel/src/main.rs:3325"),
    # hboot/src/main.rs:280  " secure boot: PASS (ed25519 AND SLH-DSA, svn OK)"
    "secure_boot": (re.compile(r"secure boot: (PASS|FAIL)"), "os/kernel/hboot/src/main.rs:280"),
    # main.rs:737-762 " [HBoot-AB] PASS — ..."
    "hboot_ab": (re.compile(r"\[HBoot-AB\] PASS"), "kernel/src/main.rs:737"),
    # main.rs:2858 " [P10-B] PASS — firmware (N B) + NVRAM uploaded; F2 ..."
    "p10b": (re.compile(r"\[P10-B\] PASS"), "kernel/src/main.rs:2858"),
    # main.rs:3669 " [AP-MC] Mission Control on http://10.99.0.1/ for Wi-Fi clients (served by heqk)"
    "mc_url": (re.compile(r"\[AP-MC\] Mission Control on (http://[0-9.]+/)"), "kernel/src/main.rs:3669"),
}


class ParseError(Exception):
    pass


def clean(text):
    """Strip ANSI + CR so a raw capture matches line patterns."""
    return ANSI.sub("", text).replace("\r", "")


def parse(text):
    """Return a dict of what the log says. Missing markers are simply absent from the dict.

    Raises ParseError on markers that are present but malformed or mutually inconsistent.
    """
    t = clean(text)
    out = {}
    for name, (rx, _cite) in MARKERS.items():
        ms = list(rx.finditer(t))
        if ms:
            out[name] = [m.groups() if m.groups() else (m.group(0),) for m in ms]
    r = {"markers_seen": sorted(out)}
    if "wifi_mac" in out:
        mac = out["wifi_mac"][-1][0]
        if int(mac[:2], 16) & 0x03 != 0x02:       # apcred.rs wifi_mac(): locally administered + unicast
            raise ParseError(f"Wi-Fi MAC {mac} is not locally-administered unicast: not a per-device derived MAC")
        r["wifi_mac"] = mac
    if "setup_ap" in out:
        creds = set(out["setup_ap"])
        if len(creds) > 1:
            raise ParseError("the log contains more than one distinct setup credential (two units captured together?)")
        ssid, psk, qr = out["setup_ap"][-1]
        if not SSID_RE.match(ssid):
            raise ParseError(f"setup SSID {ssid!r} does not match HookProbe-Setup-XXXX")
        if not PSK_RE.match(psk):
            raise ParseError("setup passphrase is not the 16-char Crockford base32 xxxx-xxxx-xxxx-xxxx form")
        want = f"WIFI:T:WPA;S:{ssid};P:{psk};;"
        if qr != want:
            raise ParseError("the device's QR payload does not match its own SSID/passphrase")
        r["setup_ssid"], r["setup_psk"], r["qr_payload"] = ssid, psk, qr
    if "tls_pub" in out:
        pubs = set(g[0] for g in out["tls_pub"])
        if len(pubs) > 1:
            raise ParseError("more than one distinct MC TLS public key in the log")
        pub = out["tls_pub"][-1][0]
        if not pub.startswith("04"):
            raise ParseError("MC TLS pub is not an uncompressed SEC1 P-256 point (04...)")
        r["tls_pub"] = pub
    if "netcp_id" in out:
        r["netcp_pk"], r["netcp_fp8"] = out["netcp_id"][-1]
    if "owner" in out:
        r["owner"] = out["owner"][-1][0]
    if "ap2_pass" in out:
        r["ap2_ssid"], r["psk_source"] = out["ap2_pass"][-1]
    if "ap2_bssid" in out:
        r["ap_bssid"] = out["ap2_bssid"][-1][0]
    if "mc_url" in out:
        r["mc_url"] = out["mc_url"][-1][0]
    for flag in ("no_ap", "tls_off_nosrk", "tls_ready", "tls_rejected", "tls_nocert", "hboot_ab", "p10b"):
        r[flag] = flag in out
    if "secure_boot" in out:
        r["secure_boot"] = out["secure_boot"][-1][0]
    return r


def require_identity(p):
    """The factory contract for the FIRST boot of a unit: a real SRK, a setup credential, a TLS key."""
    if p.get("no_ap"):
        raise ParseError("device printed 'the AP will NOT start': no OTP-backed SRK (unprovisioned board) or a "
                         "WIFI.TXT/HEQK_AP_PSK-less image on a shared key; the OTP secret must be provisioned first")
    if p.get("tls_off_nosrk"):
        raise ParseError("device printed '[MC-TLS] OFF — no device root key': no real SRK on this unit")
    missing = [k for k in ("setup_ssid", "setup_psk", "wifi_mac", "tls_pub") if k not in p]
    if missing:
        hint = ""
        if "setup_psk" in missing:
            hint = (" (the setup line is printed only when there is no signed WIFI.TXT and no HEQK_AP_PSK in the image: "
                    "a factory image must have neither, ADR 0054 D3)")
        raise ParseError(f"serial log is missing: {', '.join(missing)}{hint}")
    return p


def unit_id(p):
    """The per-unit directory name: the SRK-derived Wi-Fi MAC (no separate serial number is printed)."""
    if "wifi_mac" in p:
        return p["wifi_mac"].replace(":", "")
    raise ParseError("no per-device MAC in the log")


def redact(text, secrets):
    """Replace every secret string (and the QR payload form) so the log can be stored."""
    for s in sorted({x for x in secrets if x}, key=len, reverse=True):
        text = text.replace(s, "<redacted>")
    return text
