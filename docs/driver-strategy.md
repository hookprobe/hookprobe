# Driver & firmware strategy — for an immutable, signed OS

**The constraint (operator, validated):** the OS ships as **one signed, immutable
bootc image**. It **cannot carry every driver/firmware** — external components vary
endlessly (USB Wi-Fi dongles, PCIe radios like the N100's `ath12k`, 5G/LTE modems).
If a component's driver/firmware isn't in the image, the kernel never creates its
interface and it **fails silently**. So driver availability is a real **deploy
prerequisite**, not something the running image can fix by itself.

## 1. Make it visible (built)

The bootstrap prober scans `/sys/bus/pci` + `/sys/bus/usb` for **network-class
devices that are PRESENT but have no driver bound** and records them in
`scan.unbound`; bootstrap prints a loud `WARNING` per device. So instead of "the
Wi-Fi just doesn't work", the operator/installer gets:

```
WARNING: 1 network device(s) PRESENT but with NO driver (image lacks the kernel module/firmware):
  pci 17cb:1107 [network-other] @ 0000:06:00.0 — bake its driver/firmware into the image, add a driver sysext, or build a profile variant
```

(Validated: the scan correctly identifies the N100's PCIe Wi-Fi `ath12k_pci`
(`0x028000`) and the 4 NICs; with the driver present it reports 0 unbound — remove
the firmware and that card flags as unbound.)

## 2. Satisfy the prerequisite — three ways (cheapest → heaviest)

| Way | What | When |
|---|---|---|
| **a. Base firmware bundle** | Ship `linux-firmware` / Debian `firmware-*` packages + in-tree modules in the image (now in the **edge profiles**: `firmware-{brcm80211,iwlwifi,atheros,realtek,misc-nonfree}`, `modemmanager`, `libqmi/mbim-utils`). | Covers the **common case** — most ath/iwlwifi/mt76/brcm Wi-Fi + CDC modems work out of the box. |
| **b. Baked out-of-tree .ko (build-time)** | The popular out-of-tree USB-Wi-Fi drivers (`rtl8812au`/`8814au`, `8821au`/`8821cu`, `8188eu`/`8192eu`, `8852au`/`8832bu`) are **cross-compiled against the image's exact kernel at build time** and installed to `/usr/lib/modules/<ver>/updates/hookprobe/` — **no on-device compiler/DKMS**. arm64: `builder/mkosi-arm64/build-dongle-drivers.sh`. | Dongles whose driver isn't in mainline but is known/common — **this is the default for the chipsets we ship** (incl. the lab's own `rtl88XXau`). |
| **b′. Driver sysext** | A **signed systemd-sysext extension image** carrying an out-of-tree driver + firmware, merged into `/usr` at boot. Added per-deployment **without rebuilding/re-signing the base** image. | A dongle we *didn't* pre-bake, added in the field. The bootc-native way to extend an immutable image post-ship. |
| **c. Custom profile variant** | A profile with the exact driver/firmware packages baked in (`base/profiles/<x>.yaml` `packages.include` → `builder/build.sh`). | Known fleets / a specific SKU where you control the hardware. |

## 3. Per-component guidance

- **PCIe Wi-Fi (e.g. N100 `ath12k` / WiFi-7):** in-tree driver; needs the `ath12k`
  firmware blob → covered by the firmware bundle (recent `linux-firmware`). Verify
  the blob version matches the card.
- **USB Wi-Fi dongles (`rtl88XXau`, `8814au`, `mt76x2u`):** usually **out-of-tree** →
  **driver sysext** (or DKMS baked into a variant). Then `20-hookprobe-wlan-ap.link`
  pins it to `wlan-ap` (see `base/network/`).
- **5G/LTE modems (N100 `cdc_mbim`/`qmi_wwan`):** in-tree drivers + **ModemManager**
  + `libmbim/libqmi` (in the edge profiles) + often a **modem firmware** blob and
  `usb-modeswitch`. Carrier APN/profile is runtime config, not a driver.

## 4. The flow

```
build image (profile firmware bundle)
   → first boot → prober reports `scan.unbound`
       → empty  → all hardware driven → proceed
       → non-empty → PREREQUISITE: add a driver sysext (b) or rebuild a variant (c)
           → reboot → device fully sees the hardware
```

The boot-health gate (`base/greenboot/`) can also fail a boot whose *required* radio
is unbound, so a fleet rollout won't silently ship blind nodes.

## 5. One model for every edge add-on ("single plane of glass")

The point of HookProbe OS: **every external addition is absorbed by the SAME pipeline**
— detect → driver → capability → module → one console. No per-device special-casing,
no separate product per accelerator/modem. Concretely, on a CM5:

| Add-on | Prober detects | Driver source | Capability | Module / surface |
|---|---|---|---|---|
| **USB 5G modem** | interface (`cdc_mbim`/`qmi`) — or `unbound` `comm/modem` if undriven | base `modemmanager`+firmware, or sysext | WAN / `secure_tunnel` | `cellular-connect.sh` → **Get Online** |
| **PCIe AI chip** (Hailo/Coral/Helio) | `npu` (present, `driver_ready`) — or `unbound` `ai-accelerator` if undriven | base firmware, or driver sysext | `edge_ai` (`npu.driver_ready`) | `edge-ai-detector` (WASI-NN) → **Detect** |
| **USB Wi-Fi dongle** | wifi interface (`onboard=false`) — or `unbound` `wireless` | sysext | `wifi_ap` | `hostapd` on `wlan-ap` → **Network/Gateway** |
| **2nd LAN port** | ethernet interface (≥2) | in-tree | `openvswitch` / `multi_wan` | OVS / PBR → **Network/Gateway** |

Every one follows the same rule: **driver present → the capability grants and the
module runs; driver absent → the prober flags it (`unbound`) as an explicit
prerequisite** (add a driver sysext or rebuild a variant) — never a silent failure.
One OS, one capability model, one console — for every edge.

## 6. Supported Wi-Fi hardware — out of the box (what we ship)

> **What "out of the box" means here:** the image carries the driver **and** firmware, so the
> radio enumerates and can run an AP/client with **no field steps**. Generated from the arm64/
> Pi 4 image package set + the baked Tier-2 modules. ✅ = out-of-box · 🅱 = baked .ko (build-time)
> · ⚠ = needs a sysext/variant.

| Chipset / module | Bus | Tier | Driver source | Out-of-box | Typical hardware |
|---|---|---|---|---|---|
| **brcmfmac** | onboard | 1 | in-kernel + `firmware-brcm80211` | ✅ | Pi 4 / Pi 5 / CM5 onboard Wi-Fi |
| **ath9k / ath9k_htc** | PCIe / USB | 1 | in-kernel + `firmware-atheros` | ✅ | Atheros cards & older USB dongles |
| **ath10k / ath11k / ath12k** | PCIe | 1 | in-kernel + `firmware-atheros`/`linux-firmware` | ✅ | N100 PCIe Wi-Fi (ath12k / Wi-Fi 7) |
| **rtl8xxxu** | USB | 1 | in-kernel + `firmware-realtek` | ✅ | Many Realtek b/g/n dongles (8188/8192/8723) |
| **rt2800usb** | USB | 1 | in-kernel + `firmware-misc-nonfree` | ✅ | Ralink b/g/n dongles |
| **mt76 (mt7601u/7610u/7612u/7921u)** | USB | 1 | in-kernel + `firmware-misc-nonfree` | ✅ | MediaTek b/g/n/ac/ax dongles |
| **rtl8812au / rtl8814au** | USB | 2 | baked (`aircrack-ng/rtl8812au`) | 🅱 | **Alfa AWUS036ACH, the lab's `rtl88XXau` dongle**, most cheap AC sticks |
| **rtl8821au / rtl8821cu** | USB | 2 | baked (`morrownr/8821au`,`8821cu`) | 🅱 | Single-stream AC / travel dongles (AWUS036ACS) |
| **rtl88x2bu** | USB | 2 | baked (`morrownr/88x2bu`) | 🅱 | RTL8822BU AC1200 dongles |
| **rtl8188eu / rtl8192eu** | USB | 2 | baked (`aircrack-ng/rtl8188eus`,`clnhub/rtl8192eu`) | 🅱 | Older Realtek b/g/n sticks (better AP-mode than in-tree) |
| **rtl8852au / rtl8832bu** | USB | 2 | baked (`lwfinger/rtl8852au`) | 🅱 | Newer Realtek Wi-Fi 6 (ax) dongles |
| anything else | — | 3 | prober flags `unbound` | ⚠ | Add a sysext (b′) or rebuild a variant (c) |

The bootstrap prober (§1) makes the boundary honest: a present-but-undriven radio is a loud
`unbound` warning, never a silent miss. Tier-2 chipsets are operator-selectable in
`build-dongle-drivers.sh`; rebuild the image to change the set.

## 7. Boot substrate — one rootfs, two loaders (arm64)

The **same** arm64 rootfs (systemd-boot / UEFI) is proven two ways:
- **qemu `-M virt` + AAVMF** (`builder/mkosi-arm64/boot-arm64.sh`) — fast CI proof of the arm64
  userspace + the first-boot self-provision chain (mirrors the amd64 Gate 1).
- **real Pi 4** — the Pi's on-board bootloader loads the **rpi UEFI firmware** on the ESP, which
  then boots the identical systemd-boot image. UEFI everywhere keeps one boot model across
  amd64 / arm64-virt / Pi 4 and aligns with the eventual bootc/composefs layer. (Alternative:
  the Debian `raspi-firmware` native path — `config.txt` loads the kernel directly, no UEFI —
  kept as a fallback if pftf UEFI proves flaky on a given board.)

See `bootstrap/src/probe.rs` (`unbound_devices`, `pci_accelerator`), `base/profiles/*.yaml`
(firmware bundle), `builder/mkosi-arm64/` (arm64/Pi 4 image + baked drivers), `base/network/`
(stable naming), `base/scripts/` (first-boot data + cellular), `docs/OS-platform-report.md` §8.x.
