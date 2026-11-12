# onboarding/wifi — Wi-Fi on first boot

heqk drives the CM5's CYW43455 directly, with no Linux and no wpa_supplicant:

- **Access point** (metal-proven): beaconing, association, the WPA2 4-way handshake run by heqk as
  authenticator, DHCP, and SNAT to the `end0` uplink. Build with `--features apmode`, or `apmc` for
  Mission Control on the AP. No build-time PSK is needed. The AP credential comes from, in order
  (ADR 0054 D3):
  1. an operator-signed **`WIFI.TXT`** on the boot partition (SSID, PSK, channel, guest; parity gap
     G20) — the client AP;
  2. `HEQK_AP_PSK` in the build environment — **bench images only**;
  3. the **per-device setup credential** (`apcred.rs`, ADR 0054): `HKDF(SRK, "HQ-AP-SETUP")` gives SSID
     `HookProbe-Setup-XXXX` and a 16-character passphrase, unique per device, read off at end-of-line
     for the label/QR;
  4. otherwise no AP (it never runs open, and never with a shared default).
- **Station-to-station relay** (G10, metal-proven): the AP keeps `ap_isolate` on, and heqk itself
  relays traffic between Wi-Fi clients after the lease and IDS gates — unicast, mDNS/SSDP/LLMNR
  discovery, and IPv6 (`lanrelay.rs`; check: `tools/diagnostics/cm5-intrabss-check.sh`).
- **Client (STA)** (metal-proven): scan, association, host WPA2 supplicant, DHCP, internet.

| What | Where |
|---|---|
| Driver + supplicant / authenticator | [`cyw43.rs`](../../os/kernel/arch-aarch64/src/cyw43.rs), [`wpa.rs`](../../os/kernel/arch-aarch64/src/wpa.rs), [`aes.rs`](../../os/kernel/arch-aarch64/src/aes.rs) |
| Firmware | [`os/drivers/firmware/`](../../os/drivers/firmware/) |
| Bring-up notes | [`P9_P10_BRINGUP.md`](../../os/kernel/P9_P10_BRINGUP.md), [`P9_WIFI_INVESTIGATION.md`](../../os/kernel/P9_WIFI_INVESTIGATION.md) |
| Credentials + relay | [`apcred.rs`](../../os/kernel/kernel/src/apcred.rs), [`lanrelay.rs`](../../os/kernel/kernel/src/lanrelay.rs) |
| Decisions | ADR 0049 D1 (signed files, WIFI.TXT), ADR 0054 (per-device setup credential), ADR 0034 (regdomain), ADR 0042 (retired 2026-11-12, no successor) (Wi-Fi security surface) |
