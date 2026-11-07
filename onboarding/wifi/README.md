# onboarding/wifi — Wi-Fi on first boot

heqk drives the CM5's CYW43455 directly, with no Linux and no wpa_supplicant:

- **Access point** (metal-proven): beaconing, association, the WPA2 4-way handshake run by heqk as
  authenticator, DHCP, and SNAT to the `end0` uplink. Build with `--features apmode`, or `apmc` for
  Mission Control on the AP, and set `HEQK_AP_PSK` (8–63 chars) in the build environment.
- **Client (STA)** (metal-proven): scan, association, host WPA2 supplicant, DHCP, internet.

| What | Where |
|---|---|
| Driver + supplicant / authenticator | [`cyw43.rs`](../../os/kernel/arch-aarch64/src/cyw43.rs), [`wpa.rs`](../../os/kernel/arch-aarch64/src/wpa.rs), [`aes.rs`](../../os/kernel/arch-aarch64/src/aes.rs) |
| Firmware | [`os/drivers/firmware/`](../../os/drivers/firmware/) |
| Bring-up notes | [`P9_P10_BRINGUP.md`](../../os/kernel/P9_P10_BRINGUP.md), [`P9_WIFI_INVESTIGATION.md`](../../os/kernel/P9_WIFI_INVESTIGATION.md) |
| Decisions | ADR 0034 (regdomain), ADR 0042 (Wi-Fi security surface) |
