# Pre-soak finding 3 on CM5: a station that vanishes without a deauth (2026-11-22)

**Tool:** `tools/diagnostics/cm5-ghost-station-check.sh` (`PI_SUDO_FILE`). **Image:** `am35B-78cb7095` (main with #1468).

**Method.**
1. The bench Pi is joined to the AP over WPA3.
2. Its Wi-Fi driver is unloaded (`modprobe -r brcmfmac_cyw brcmfmac`), so the radio disappears.
3. The script checks that `wlan0` is gone; a run where it is not is **INVALID** and is not counted.
4. For 10 minutes it watches the AP's heartbeat `stations=` count and its Leave lines.
5. At the end the driver is reloaded and the Pi rejoins.

**Result: not reproduced. The AP cleans up.**
- `stations=1` at t = 30 s, then `stations=0` from t = 60 s.
- One `[P11-AP3] station dc:a6:32:a4:b6:88 left (deauth/disassoc)`: the kernel's Leave path ran (StaSet, key abort,
  SAE forget, SAVI).
- The delay of about 30–60 s, rather than immediate, shows it was the firmware's inactivity ageing, not a deauth sent
  by the client. That ageing arrives as an event `ap_poll` already maps to Leave (`*_IND`).
- The Pi rejoined afterwards (SAE accepted, DHCP lease 10.99.0.10).

**Earlier invalid run.** The first attempt's `modprobe -r brcmfmac` failed ("module in use"), so the Pi never left, and
its "ghost" verdict was discarded. The script now refuses to report unless the radio is actually gone.

**Status of finding 3:** downgraded from *plausible* to *not reproduced* for the common case (a client leaving range or
powering off). The firmware's own `WLC_E_DEAUTH` / `WLC_E_DISASSOC` (not `_IND`) is still not mapped to Leave. It was
seen once, in the SAE watch window (reason 6 to an unauthenticated association). It stays a low-priority open item,
with no change before the soak.
