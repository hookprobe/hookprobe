#!/usr/bin/env bash
# cm5-wifiheal-check — audit A7 (docs/design/heqk-audit-2026-11-10.md §4.1, "Metal must still prove") on a BENCH image
# built with the `wifiheal-bench` feature (never shipped; tools/ci/shipping_guard.py forbids it). The trigger
# `wifi heal-test freeze|freeze-once|fwhalt|clear` (web console POST /api/hsh, each change carried by an owner-signed
# HQMGMT1 envelope) shapes the self-heal classifier's INPUT; the real kick / BSS bounce / firmware reload / reboot /
# degrade code acts. Timings are taken from the kernel's own clock (`[WIFI-HEAL] step=… t_ms=…` lines), not the host's.
#
#   1  fresh boot, persistent `freeze`: kick (100 ms, every 500 ms) -> bounce 10 s -> reload 25 s -> reload #2 after the
#      60-s backoff -> exactly ONE reboot, a `[WIFI-HEAL] diagnostics` line before each heavy step; every reload brings
#      the BSS back serve-ready with `PMKID correction Some(true)` (REL-08)
#   2  the boot after it prints the previous recovery record; `fwhalt` goes straight to the reload branch
#      (firmware-crash, no kick / bounce first); the bench Pi re-joins (lease + gateway ping)
#   3  `freeze-once`: kick -> bounce -> reload -> cleared by the reload; BSS serve-ready + PMKID Some(true); the Pi re-joins
#   4  `freeze` again within 30 min of the Wi-Fi reboot: Degrade — Wi-Fi off, /api/health wifi_heal.state degraded,
#      NO further reset, Mission Control on the management VLAN still answers
#   5  `clear` + a normal reboot: Wi-Fi back, the Pi re-joins, wifi_heal.state ok
#
#   tools/diagnostics/cm5-wifiheal-check.sh <owner-key-file> <serial-log> [mc] [pi]
#   SIGN_KEY (default ~/heqk-owner-ca/bench-owner.key) = the enrolled bench owner key that signs the envelopes;
#   PI_SUDO_FILE (optional) lets a re-join nudge the Pi's NetworkManager (tools/diagnostics/pi-ensure-ap.sh).
# Exit 0 = every check ok, 1 = a check failed, 2 = not runnable (not a bench image, or not a fresh boot).
set -u -o pipefail
KEY="${1:?owner key file}"; LOG="${2:?serial log}"
MC="${3:-https://192.168.200.146}"; PI="${4:-claude@10.200.0.4}"
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd)
SIGN="${SIGN_KEY:-$HOME/heqk-owner-ca/bench-owner.key}"
UP="python3 -I $ROOT/os/kernel/tools/hq-upload.py --mc $MC --owner-key-file $KEY --insecure --sign-key $SIGN"
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; return "$1"; }
pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
T=$(mktemp -d); chmod 700 "$T"; trap 'rm -rf "$T"' EXIT
mark=$(stat -c %s "$LOG")
since() { tail -c +$((mark + 1)) "$LOG" | tr -d '\r\000'; }
waitlog() { for _ in $(seq 1 "$2"); do since | grep -aq "$1" && return 0; sleep 2; done; return 1; }
api() { python3 -I - "$MC" "$KEY" "$1" <<'PY'
import ssl, sys, urllib.parse, urllib.request, http.cookiejar
mc, key, path = sys.argv[1], open(sys.argv[2]).read().strip(), sys.argv[3]
c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
o = urllib.request.build_opener(urllib.request.HTTPSHandler(context=c), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
o.open(mc + "/api/login", urllib.parse.urlencode({"token": key}).encode(), timeout=10).read()
print(o.open(mc + path, timeout=10).read().decode())
PY
}
heal() { api /api/health | python3 -c "import json,sys; d=json.load(sys.stdin); h=d.get('wifi_heal',{}); b=d.get('wifi_heal_bench',{}); print($1)"; }
hsh() { $UP --hsh "wifi heal-test $1" 2>&1 | tee "$T/hsh.out"; }
mc_up() { for _ in $(seq 1 80); do curl -sk -o /dev/null -m 5 "$MC/" && return 0; sleep 3; done; return 1; }
mgmt200() { [ "$(curl -sk -o /dev/null -w '%{http_code}' -m 8 "$MC/api/health")" = 200 ]; }
# joined = the Pi holds an AP lease (10.99.0.x) and the AP gateway answers (the probe of cm5-wifi-live-spike.sh)
apup() { pi "a=\$(ip -4 -o addr | awk '\$4 ~ /^10\\.99\\.0\\./ {print \$2; exit}'); [ -n \"\$a\" ] && ping -c1 -W2 -I \$a 10.99.0.1 >/dev/null" 2>/dev/null; }
rejoin() { for _ in $(seq 1 "${1:-30}"); do apup && return 0
  [ -n "${PI_SUDO_FILE:-}" ] && PI_SUDO_FILE="$PI_SUDO_FILE" "$HERE/pi-ensure-ap.sh" "$PI" >/dev/null 2>&1; sleep 3; done; return 1; }
ensure_owner() { local e; e=$(api /api/config | python3 -c 'import json,sys; print(bool(json.load(sys.stdin).get("envelope", {}).get("owner_enrolled")))')
  [ "$e" = True ] && return 0
  python3 -I "$ROOT/os/kernel/tools/policy-sign.py" enroll-proof "$SIGN" > "$T/enroll.txt" && $UP --enroll "$T/enroll.txt" > "$T/enroll.out" 2>&1
  local rc=$?; echo "     owner key enrolled for the envelopes (rc=$rc: $(cut -c1-100 "$T/enroll.out"))"; return $rc; }
# ladder <persist|once|fwhalt|degrade> — reads the serial text since `mark` and prints "<rc>|<check>" lines
ladder() { since > "$T/s.txt"; python3 -I - "$1" "$T/s.txt" <<'PY'
import re, sys
mode, text = sys.argv[1], open(sys.argv[2], errors="replace").read().splitlines()
INJ = re.compile(r"\[WIFI-HEAL\] bench injection applied: mode=(\S+) injected_fwhalts=(\d+) t_ms=(\d+)")
STEP = re.compile(r"\[WIFI-HEAL\] step=(\w+) class=(\S+) t_ms=(\d+) stall_ms=(\d+)")
RELOAD = re.compile(r"\[WIFI-HEAL\] firmware reload: bring-up step (\d+) \(0 = ready\), PMKID correction (.+?), BSS serve-ready=(\w+)")
BOUNCE = re.compile(r"\[WIFI-HEAL\] BSS bounce on chanspec \S+: serve-ready=(\w+)")
out = []
def chk(c, what): out.append(f"{0 if c else 1}|{what}")
inj = next(((i, int(m.group(3))) for i, l in enumerate(text) for m in [INJ.search(l)] if m), None)
if inj is None:
    print("1|the bench injection reached the AP loop ([WIFI-HEAL] bench injection applied)"); sys.exit()
i0, t0 = inj
steps = [(i, m.group(1), m.group(2), int(m.group(3))) for i, l in enumerate(text) if i > i0 for m in [STEP.search(l)] if m]
heavy = [s for s in steps if s[1] != "kick"]
kicks = [s for s in steps if s[1] == "kick"]
tag = [(i, l) for i, l in enumerate(text) if "[WIFI-HEAL]" in l or "[SELF-HEAL]" in l]
def diag_before(i):  # the nearest [WIFI-HEAL]/[SELF-HEAL] line before the step line is the diagnostics capture
    prev = [l for j, l in tag if j < i]
    return bool(prev) and "diagnostics before recovery" in prev[-1]
def first(name, k=0):
    xs = [s for s in heavy if s[1] == name]
    return xs[k] if len(xs) > k else None
def within(a, b, lo, hi):
    return a is not None and b is not None and lo <= b[3] - a[3] <= hi
reloads = [(int(m.group(1)), m.group(2), m.group(3)) for l in text[i0:] for m in [RELOAD.search(l)] if m]
bounces = [m.group(1) for l in text[i0:] for m in [BOUNCE.search(l)] if m]
reboots = sum("[SELF-HEAL] Wi-Fi recovery exhausted" in l for l in text[i0:])
names = [s[1] for s in heavy]
fmt = lambda s: f"{s[3] - t0} ms" if s else "absent"
if mode in ("persist", "once"):
    k0 = kicks[0] if kicks else None
    chk(k0 is not None and steps[0][1] == "kick" and 0 <= k0[3] - t0 <= 1500, f"first step is a kick, {fmt(k0)} after the injection (<= 1.5 s: KICK_MS 100 + engage)")
    pre = [s[3] for s in kicks if not heavy or s[0] < heavy[0][0]]
    gaps = [b - a for a, b in zip(pre, pre[1:])]
    chk(len(pre) >= 10 and all(450 <= g <= 1500 for g in gaps), f"kicks repeat every ~500 ms until the bounce ({len(pre)} kicks, gaps {min(gaps or [0])}..{max(gaps or [0])} ms)")
    b, r1 = first("bounce"), first("reload")
    chk(within(k0, b, 9000, 11500), f"BSS bounce at stall + 10 s ({fmt(b)} after the injection, {b[3] - k0[3] if b and k0 else '?'} ms after the first kick)")
    chk(within(b, r1, 14500, 18000), f"firmware reload 15 s after the bounce (settle 5 s + 10 s): {r1[3] - b[3] if b and r1 else '?'} ms")
    chk(all(diag_before(s[0]) for s in heavy) and heavy != [], f"a [WIFI-HEAL] diagnostics line precedes every heavy step ({', '.join(names)})")
    chk(bool(bounces) and bounces[0] == "true", f"the bounce re-started the BSS serve-ready ({bounces[:1]})")
    chk(bool(reloads) and all(r == (0, "Some(true)", "true") for r in reloads),
        f"every reload: bring-up step 0, PMKID correction Some(true), BSS serve-ready ({reloads})")
    if mode == "persist":
        r2, rb = first("reload", 1), first("reboot")
        chk(names[:4] == ["bounce", "reload", "reload", "reboot"], f"ladder order bounce -> reload -> reload -> reboot ({names})")
        chk(within(r1, r2, 59500, 64000), f"reload #2 only after the 60-s backoff: {r2[3] - r1[3] if r1 and r2 else '?'} ms")
        chk(within(r2, rb, 14500, 18000), f"the reboot 15 s after reload #2 (budget spent): {rb[3] - r2[3] if r2 and rb else '?'} ms")
        chk(reboots == 1 and names.count("reboot") == 1, f"exactly ONE reboot ({reboots} [SELF-HEAL] line(s))")
    else:
        cleared = any("bench freeze-once cleared by the firmware reload" in l for l in text[i0:])
        chk(names == ["bounce", "reload"] and cleared and reboots == 0, f"freeze-once: bounce -> reload, cleared by the reload, nothing after it ({names}, cleared={cleared})")
elif mode == "fwhalt":
    s0 = steps[0] if steps else None
    chk(s0 is not None and s0[1] == "reload" and s0[2] == "firmware-crash", f"first step after the FWHALT is the reload, class firmware-crash ({s0[1:3] if s0 else None}) — no kick / bounce first")
    chk(s0 is not None and 0 <= s0[3] - t0 <= 1500, f"reload at once: {s0[3] - t0 if s0 else '?'} ms after the injection")
    chk(s0 is not None and diag_before(s0[0]), "a [WIFI-HEAL] diagnostics line precedes the reload")
    chk(bool(reloads) and reloads[0] == (0, "Some(true)", "true"), f"reload: bring-up step 0, PMKID correction Some(true), BSS serve-ready ({reloads[:1]})")
    chk(reboots == 0, "no reset")
elif mode == "degrade":
    d = first("degraded")
    degraded = any("[WIFI-HEAL] DEGRADED" in l for l in text[i0:])
    chk(d is not None and diag_before(d[0]) and degraded, f"Degrade after the failed recovery ({names}), diagnostics before it, [WIFI-HEAL] DEGRADED")
    chk(d is not None and d[3] - t0 <= 120000, f"degraded {fmt(d)} after the recurrence")
    chk(reboots == 0 and "reboot" not in names, "NO reset in the boot after the Wi-Fi reboot")
print("\n".join(out))
PY
}
run_ladder() { local l; while IFS= read -r l; do [ -n "$l" ] && chk "${l%%|*}" "$2: ${l#*|}"; done < <(ladder "$1"); }

# ---- 0. preflight ----
mc_up || { echo "WIFIHEAL: Mission Control not reachable at $MC"; exit 2; }
ensure_owner || { echo "WIFIHEAL: the bench owner key is not enrolled"; exit 2; }
hsh status >/dev/null; grep -q "injection mode=" "$T/hsh.out" || { echo "WIFIHEAL: not a wifiheal-bench image ($(head -c 200 "$T/hsh.out"))"; exit 2; }
[ "$(heal 'h.get("after_wifi_reboot")')" = False ] || { echo "WIFIHEAL: this boot follows a Wi-Fi reboot — do a normal reboot first (phase 1 needs a fresh boot)"; exit 2; }
[ "$(heal 'h.get("reloads", 0) + h.get("bounces", 0)')" = 0 ] || { echo "WIFIHEAL: this boot already bounced / reloaded the radio (its reload budget is not fresh) — do a normal reboot first"; exit 2; }
[ "$(heal 'h.get("state")')" = ok ] && [ "$(heal 'b.get("mode")')" = off ]; chk $? "0.1 bench image, self-heal state ok, no injection, fresh reload budget"
rejoin 20; chk $? "0.2 the bench Pi is on the AP (lease + gateway ping)"

# ---- 1. persistent freeze: the whole ladder to the ONE reboot ----
mark=$(stat -c %s "$LOG")
hsh freeze >/dev/null; grep -q "accepted" "$T/hsh.out"; chk $? "1.0 'wifi heal-test freeze' accepted with an owner-signed envelope ($(head -1 "$T/hsh.out" | cut -c1-90))"
waitlog "\[SELF-HEAL\] Wi-Fi recovery exhausted" 90; chk $? "1.1 the ladder ran to its end within 180 s"
sleep 3; run_ladder persist "1"
m1=$mark

# ---- 2. the boot after the reboot: record printed, FWHALT -> reload ----
mc_up; chk $? "2.0 Mission Control back after the Wi-Fi reboot"
mark=$m1; waitlog "previous boot's recovery record: flags=1 class=tx-freeze action=4" 60; chk $? "2.1 the next boot printed the previous recovery record (flags=1 rebooted, tx-freeze, RebootOnce)"
[ "$(heal 'h.get("after_wifi_reboot")')" = True ]; chk $? "2.2 /api/health wifi_heal.after_wifi_reboot = true"
rejoin 40; chk $? "2.3 the Pi re-joined after the reboot"
mark=$(stat -c %s "$LOG")
hsh fwhalt >/dev/null; grep -q "accepted" "$T/hsh.out"; chk $? "2.4 'wifi heal-test fwhalt' accepted"
waitlog "\[WIFI-HEAL\] firmware reload:" 30; t_fw=$(date +%s); run_ladder fwhalt "2"
rejoin 30; chk $? "2.9 the Pi re-joined after the firmware reload (lease + gateway ping)"

# ---- 3. freeze-once: kick -> bounce -> reload, cleared; stations re-join ----
# wait out RECUR_MS (120 s) since that reload, so the freeze escalates to a bounce first (a freeze within 120 s of a
# reload goes straight to the reload stage)
w=$(( 115 - ($(date +%s) - t_fw) )); [ "$w" -gt 0 ] && sleep "$w"
mark=$(stat -c %s "$LOG")
hsh freeze-once >/dev/null; grep -q "accepted" "$T/hsh.out"; chk $? "3.0 'wifi heal-test freeze-once' accepted"
waitlog "bench freeze-once cleared by the firmware reload" 40; chk $? "3.1 the reload cleared the freeze"
sleep 10; run_ladder once "3"
rejoin 30; chk $? "3.9 the Pi re-joined the reloaded firmware's BSS (lease + gateway ping)"
[ "$(heal 'h.get("state")')" = ok ] && [ "$(heal 'b.get("mode")')" = off ]; chk $? "3.10 /api/health: state ok, injection off ($(heal 'h'))"

# ---- 4. recurrence within 30 min of the Wi-Fi reboot: Degrade, no reset ----
mark=$(stat -c %s "$LOG")
hsh freeze >/dev/null; grep -q "accepted" "$T/hsh.out"; chk $? "4.0 'wifi heal-test freeze' (the recurrence) accepted"
waitlog "\[WIFI-HEAL\] DEGRADED" 75; chk $? "4.1 Wi-Fi degraded"
sleep 30; run_ladder degrade "4"
heal 'h.get("state","")' | grep -q '^degraded'; chk $? "4.5 /api/health wifi_heal.state = degraded ($(heal 'h.get("state","")' | cut -c1-60))"
mgmt200 && sleep 20 && mgmt200; chk $? "4.6 management VLAN $MC/api/health still 200 (twice, 20 s apart)"
! apup; chk $? "4.7 Wi-Fi is off: the Pi has no AP lease + gateway"
since | grep -aq "\[SELF-HEAL\]\|\[CRASH\]"; [ $? = 1 ]; chk $? "4.8 no reset since the recurrence"

# ---- 5. clear + a normal reboot: Wi-Fi back ----
hsh clear >/dev/null; grep -q "injection mode=off" "$T/hsh.out"; chk $? "5.0 'wifi heal-test clear'"
mark=$(stat -c %s "$LOG"); $UP --reboot "wifiheal check: restore Wi-Fi" >/dev/null 2>&1; sleep 25; mc_up; chk $? "5.1 device back after a normal reboot"
rejoin 40; chk $? "5.2 the Pi re-joined: Wi-Fi restored (lease + gateway ping)"
[ "$(heal 'h.get("state")')" = ok ] && [ "$(heal 'b.get("mode")')" = off ]; chk $? "5.3 /api/health: wifi_heal.state ok, no injection"
fh=$(since | grep -ac "FWHALT")
echo "    FWHALT lines since the restore reboot: $fh"
[ "$ok" -eq "$n" ] && { echo "WIFIHEAL: PASS ($ok/$n)"; exit 0; } || { echo "WIFIHEAL: FAIL ($ok/$n)"; exit 1; }
