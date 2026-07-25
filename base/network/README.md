# base/network/ — stable wifi naming (station vs AP) across reboots

## The problem (validated on a real Pi 4)

The kernel names wifi interfaces `wlan0`, `wlan1`, … by **enumeration order**, which
varies across reboots (USB vs SDIO timing). On the Pi 4 `guardian` the **onboard
radio was `wlan1`** (`brcmfmac`/SDIO, Pi MAC OUI `dc:a6:32`) and the **USB dongle was
`wlan0`** (`rtl88XXau`/USB). A reboot can swap them — putting `hostapd` (AP) on the
uplink radio or `wpa_supplicant` (station) on the AP radio. V1 keyed off `wlan1`,
which is exactly this latent bug.

## The fix — two layers

**1. Stable identity (no name dependence).** The bootstrap prober records, per
interface, the `driver`, `bus` (`sdio`/`usb`/`pci`/`platform`) and an **`onboard`**
flag (`brcmfmac` ∨ SDIO/MMC bus ∨ a Pi MAC OUI). `crate::net_roles::assign_wifi_roles`
then assigns roles from that, **never from `wlanN`**:

> **onboard radio → STATION (uplink/client); every additional radio → AP.**

Holds for Pi 4 / Pi 5 / **CM5** (all onboard = `brcmfmac`). Unit-tested with the exact
Pi 4 case (onboard `wlan1` → station, USB `wlan0` → AP).

**2. Stable names (so daemons bind correctly).** These `systemd.link` files rename by
driver, so the names are reboot-stable:

| File | Match | Name | Bind |
|---|---|---|---|
| `10-hookprobe-wlan-station.link` | `Driver=brcmfmac` (onboard) | **`wlan-sta`** | `wpa_supplicant` (station) |
| `20-hookprobe-wlan-ap.link` | add-on AP drivers (rtl88XXau, …) | **`wlan-ap`** | `hostapd` (AP) |

The Containerfile bakes them: `COPY base/network/*.link /etc/systemd/network/`.
Config (`hostapd.conf`, `wpa_supplicant`) references `wlan-ap` / `wlan-sta`, never
`wlanN`. Add your dongle's driver to `20-…link` if it isn't listed.

## Net effect

- **Onboard Pi/CM5 radio is ALWAYS the station** (the device's own uplink) — by
  identity, not name, and pinned to `wlan-sta`.
- **Any add-on radio is the AP**, pinned to `wlan-ap`.
- Survives reboots, USB re-plugs, and SD→NVMe moves. No per-board code.

## Ethernet WAN/LAN roles (CM5 2×LAN, N100 4×LAN)

Same principle for wired ports — don't bind WAN/LAN to `ethN`/`enpXsY` names:
- **Onboard/PCIe NIC ports are name-stable** (predictable names come from the fixed
  PCI path) — the N100's `enp1s0..enp4s0` and a CM5 carrier's ports don't reorder.
- **USB Ethernet adapters DO reorder** — pin them by MAC with a `.link` if used.
- **WAN vs LAN is a POLICY choice, not auto-detectable** (you can't know which port
  is wired to the modem). The prober records `mac` + `bus` + `driver` + PCI path per
  interface, so the assignment is reboot-stable; assign it in Network/Gateway config.
  Convention: lowest-numbered onboard port = WAN unless the operator overrides.

So: wired ports → role by stable identity (convention, operator-overridable); wifi →
onboard=station / add-on=AP by the `onboard` flag. And see `docs/driver-strategy.md`
for the firmware/driver prerequisite (an interface only exists if its driver is in
the image).

See `crates/hookprobe-manifest/src/net_roles.rs` + the prober's `onboard` flag
(`bootstrap/src/probe.rs`), `docs/OS-platform-report.md`.
