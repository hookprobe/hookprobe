# heqk radio drivers — QCN9274 Wi-Fi 7 + EM9293 5G (plan)

**Status:** Proposed (2026-11-23). Plan only. A companion to
`heqk-x86-fortress-delinux-plan-2026-11-23.md` (F4's two long poles).
**Scope:** the two radios the production N100 runs today, which ADR 0064 also chose for the
HookProbe RK3588 board. Every driver below is **arch-neutral** (PCI/USB + DMA), so one
implementation serves the N100 (x86), the RK3588 board and, for xHCI, CM5 (RP1).
**Constraints:** x86 is out of the MVP; nothing here touches the soak, `kernel/src` or MVP gates
until X0. Wireless work stays within the receive-only assessment rule. The AP transmits only as
an AP on our own SSID, on legal channels, with the correct regulatory domain, and never injects frames.

## 1. Ground truth (live N100, read-only, 2026-11-23)

| | Wi-Fi | 5G |
|---|---|---|
| Part | Qualcomm QCN9274 (PCIe `17cb:1109`); one card provides both AP radios (2.4 + 5 GHz) | Sierra EM9293 (USB `1199:90e3`), USB 3.2 at 10 Gb/s, on M.2/USB |
| Linux driver | `ath12k` + `mhi` + `qmi_helpers` | `cdc_mbim` (+ `cdc_ncm` framing), `option` (serial), driven by ModemManager |
| Device interface | PCIe → MHI → QRTR/QMI (WLFW) for boot; copy engines → HTC → WMI for control; SRNG rings → HTT/DP for data | if0 MBIM control (CDC class 2/14), if1 CDC-Data (proto 2, NTB), if3/if4 vendor serial (diag/AT) |
| Firmware | `firmware-2.bin`, `board-2.bin`, `regdb.bin` under `~/ath12k-firmware/QCN9274/hw2.0` (the board file was edited: `.bak*` copies exist) | modem-resident; there is no host blob |
| Isolation | own IOMMU group | behind xHCI `00:14.0`, whose group also holds PCH SRAM `00:14.2` and which carries the bench USB-serial consoles. **Not passable.** The USB-C xHCI `00:0d.0` is alone in its group. |

**Licences** (from `modinfo`) decide how each layer may be written for AGPL-3.0-only heqk:

| Linux source | Licence | Use in heqk |
|---|---|---|
| `ath12k` (WMI/HTT/DP/CE, the **WLFW QMI message tables**) | Dual BSD/GPL (BSD-3-Clause-Clear) | may port, keeping the notice |
| `cdc_ncm` (NTB framing) | Dual BSD/GPL | may port |
| `mhi`, `qmi_helpers`, `mhi_wwan_mbim`, `option` | GPL-2.0-only | **clean-room**: behaviour, traces and specs only; GPLv2-only is incompatible with AGPLv3 |
| `cdc_mbim` | GPL | **clean-room** from the public USB-IF MBIM 1.0 spec (libmbim LGPL-2.1+ as a behaviour reference) |
| `xhci-hcd` | GPL | **clean-room** from the public Intel xHCI 1.2 spec |
| Qualcomm firmware blobs | `LICENSE.qca_firmware` (redistributable) | shipped through the firmware-staging path, listed in the SBOM as vendor blobs (as CYW43455 is) |

Before any clean-room layer starts, record who reads the GPL sources (behaviour notes only) and
who writes the code. Check for permissive references (BSD ports of MHI/QRTR) first; none is
assumed here.

## 2. Shared foundation (lands first; both radios need it)

1. **VT-d (DMAR) remapping in the x86 kernel.** It parses DMAR (F0 fixtures), sets up a per-device
   context and second-level tables, and handles fault reporting. This is what lets an EL0 driver own a
   DMA-capable device without being able to DMA into the kernel. On x86 we get real DMA confinement
   for the ADR 0065 resident-EL0 driver model. **No radio driver runs before this.**
2. **MSI-X** delivery, with notifications into a resident EL0 server.
3. **An EL0 DMA ABI:** IOVA-mapped coherent buffers and descriptor rings, granted per device. It is an
   extension of `hal::wifisrvabi`'s frame rings, and must be arch-neutral so that RK3588 can implement it too.
4. **The firmware-blob path** (signed manifest + SBOM entry). It already exists for CYW43455.
5. **Host-testable codec crates.** They are pure `no_std` and have no device access:
   MBIM messages, NTB16/NTB32, the QMI TLV encoder, WLFW messages, HTC/WMI encoders and
   802.11 IE builders. They are unit-tested against fixtures captured from the live box.
   **These can start today** as detached crates (like `arch-x86_64`, with their own lockfile) and join
   the workspace after the soak/X0.

Placement follows ADR 0065/0050: each radio is a **resident EL0 server** (it parses untrusted
radio/USB input, so a fault costs the server, never the kernel). MLME and the WPA
authenticator stay in their own EL0 component (the `el0-wpa` pattern). Keys stay where they live today.

## 3. 5G modem (EM9293) — first: smaller, public specs, wide reuse

| Layer | Work | Source basis | Rough size |
|---|---|---|---|
| **M1 xHCI** | host controller: command/event/transfer rings, slot/endpoint contexts, control + bulk + interrupt; SuperSpeed; root-port devices only (no hubs, no isochronous) at first | xHCI 1.2 spec, clean-room | L (several kLOC) |
| **M2 USB core** | enumeration, descriptors, SET_CONFIGURATION, CDC functional descriptors (MBIM: max control message size, NTB parameters) | USB 3.2 + CDC specs | S |
| **M3 MBIM control** | OPEN/CLOSE; DEVICE_CAPS; SUBSCRIBER_READY; PIN; RADIO_STATE; REGISTER_STATE; PACKET_SERVICE; CONNECT (APN from intent config); IP_CONFIGURATION; SIGNAL_STATE notifications. MBIMEx 5G info and QMI-over-MBIM come later. | USB-IF MBIM 1.0, clean-room | M |
| **M4 data path** | NTB16/32 + NDP `IPS0` session framing over bulk, giving raw IPv4/IPv6 (no L2). The modem appears as an **L3 point-to-point WAN**, like `ppp0`. | `cdc_ncm` (BSD) + spec | M |
| **M5 integration** | WAN failover in the existing `uplink` logic (the V1 `fts-wan-failover` behaviour is the spec); IPv6 from IP_CONFIGURATION + SLAAC on the link; SIM PIN sealed; manifest capability `cellular`; Mission Control signal/registration views | existing heqk logic | M |

Leverage: M1/M2 give heqk **USB on every platform**. That includes CM5 (RP1's xHCI), RK3588, USB
serial consoles and USB Ethernet. Modem firmware updates stay an off-device operator procedure for now.

**Development path** (evidence class in brackets):
1. **[fixture]** On the live box, read-only: `lsusb -v`, the MBIM functional descriptor,
   `mmcli -m 0` state dumps, and a root `usbmon` capture of one MBIM bring-up. Codec tests replay it.
   Read queries only: never reset or reconfigure the production modem.
2. **[E1]** The xHCI driver against QEMU `qemu-xhci`, under KVM on the dev host.
3. **[E2]** A **second EM9293 + SIM** on the twin N100, passed **at USB level** (`-device usb-host`)
   into a heqk guest on QEMU's emulated xHCI. MBIM/NTB run against the real modem before the real xHCI exists.
4. **[E3-lite]** The real Intel xHCI. Plug the modem (in an M.2-to-USB-C carrier) into the twin's
   USB-C controller `00:0d.0`, which is alone in its IOMMU group, and pass it by VFIO. That covers real
   controller + real modem.
5. **[E3]** Twin metal boot (X3), then failover parity against the F0 baselines.

## 4. Wi-Fi 7 (QCN9274) — the long pole

The CYW43455 is FullMAC: its firmware does the MLME, and heqk does the WPA authenticator.
QCN9274 under `ath12k` is closer to SoftMAC for control: **the host owns the AP MLME**
(auth/assoc/deauth, beacon contents, peer and key install). The firmware owns the radio and runs
a data path the host must drive. The arch-neutral WPA pieces carry over unchanged (`hal::wpaauth`,
`wpakeyer`, `rsnassoc`, `saewire`, `sae` crate).

| Layer | Work | Source basis | Rough size |
|---|---|---|---|
| **W1 MHI host** | PCIe BAR/MHI registers, state machine to M0, BHI/BHIe firmware download, channel/event rings | **clean-room** (GPL-2.0 in Linux) | M–L |
| **W2 QRTR + QMI WLFW** | IPC router over the MHI IPCR channel; WLFW: host cap, board-data (BDF) selection + download from `board-2.bin`, M3 download, mode-on, CE pipe config | QRTR/TLV clean-room; WLFW messages port from `ath12k` (BSD) | M |
| **W3 CE + HTC + WMI** | copy-engine rings; HTC services; WMI init/service-ready; pdev/vdev; channel; regulatory (`regdb.bin`, country); beacon template; peer assoc; key install; mgmt TX/RX | `ath12k` (BSD) | L |
| **W4 data path** | HTT setup; SRNG rings TCL (tx) / WBM (completions) / REO (rx) / RXDMA; one pdev, no MLO, no advanced offloads | `ath12k` (BSD) | **L–XL** (performance-critical) |
| **W5 AP MLME** | probe response, auth (open, SAE), assoc/reassoc, deauth, inactivity; IE builders HT/VHT/HE/EHT; BSS bridging into the heqk LAN | net-new (the hostapd/mac80211 *behaviour* is the reference) | M–L |
| **W6 breadth** | both bands (two pdevs on one card), WPA3-SAE default, DFS (off at first, as on CM5's `allow_dfs=false`), 6 GHz/EHT, MLO last | — | L |

`ath12k` is tens of kLOC. heqk takes the **single-link AP subset**: no STA mode, no mesh, no
monitor-TX, no MLO until W6.

**Development path:**
1. **[fixture]** On the live box, read-only: firmware/BDF versions and board/chip IDs (boot log),
   the WMI service bitmap and capabilities (debugfs, root), and the current AP config (channels, country,
   ciphers). Throughput/latency/client-count baselines become the parity target.
2. **[E1]** Codec crates (WLFW, HTC/WMI, IEs) host-tested against the fixtures.
3. **[E3-lite]** A **second QCN9274 card** (the Fortress module class, Compex WLE7002E25 per ADR 0064 §open)
   in the twin N100, with **VFIO passthrough** into a heqk KVM guest. The twin runs Linux as the VFIO host
   while it is not production. Milestones, in order: MHI M0 + firmware loaded → WLFW ready + BDF accepted
   → WMI service-ready → beacon on a non-DFS 5 GHz channel (shielded/low power) → one WPA2 client associates
   → DHCP from the heqk LAN → throughput against Linux on the same card.
4. **[E3]** Twin metal (X3), then shadow run, then cutover.

The production card is **never** passed through. It serves the live APs until the swap.

## 5. Order, parallelism, interim

```
now ─ F0 fixtures ─ codec crates (MBIM, NTB, QMI-TLV, WLFW, WMI, IEs) ── host tests
       │
       ├─ x86 foundation: VT-d ─ MSI-X ─ EL0 DMA ABI          (detached crate, QEMU)
       │
       ├─ 5G:   xHCI(QEMU) ─ USB core ─ MBIM/NTB vs real modem (usb-host) ─ VFIO 00:0d.0 ─ metal
       │
       └─ WiFi: MHI ─ WLFW/BDF ─ WMI ─ beacon ─ assoc ─ DP ─ perf ─ both bands ─ metal
post-soak X0 ─ drivers join the workspace; uplink/LAN integration through hal traits
```

- **5G first.** It is smaller, its specs are public, and xHCI pays off on every platform. It also delivers
  WAN-failover parity early.
- **Wi-Fi starts in parallel** once the VT-d + EL0 DMA ABI exist. It is the critical path of the whole cutover.
- **Interim (decision D-D):** if Wi-Fi is not at parity when the rest is, cut over with an Ethernet-attached
  AP on a LAN port. heqk still sees all traffic at L2/L3.
- **Alternative worth an operator look (decision D-F):** a FullMAC Wi-Fi 6E PCIe module from the Infineon
  family heqk already drives, where the firmware does the MLME. It would reuse the existing BCDC/iovar/WPA
  work behind a new PCIe message-ring transport. The trade: 6E instead of 7, and a divergence from the ADR 0064
  choice. *Module availability and the PCIe FullMAC protocol must be verified before this is weighed.*

## 5a. No-purchase test strategy (operator, 2026-11-23) — supersedes the twin/second-card steps above

**Operator rule:** no new hardware; test on what we have. The "twin N100", "second QCN9274" and
"second EM9293" steps in §3/§4 are replaced by the following. Read-only facts checked on the live box:

| Asset we own | Fact | What it tests |
|---|---|---|
| Live box, **USB-C xHCI `00:0d.0`** | IOMMU group alone; **2 hotplug SuperSpeed ports, nothing plugged in**; no PCI reset method (xHCI HCRST suffices) | **real Intel xHCI silicon** through VFIO into a heqk KVM guest, **no window needed**. Devices: anything USB we own (a USB stick; a phone, whose USB tethering is an RNDIS/NCM cellular stand-in, to be verified per phone; and NCM framing is shared with MBIM data) |
| Live box, **EM9293** (production 5G failover; PPPoE stays primary) | on xHCI `00:14.0` with the bench consoles, so not VFIO-able | **the real modem through QEMU `usb-host`** (libusb, device-level) into a heqk guest on emulated `qemu-xhci`, in a **maintenance window**: ModemManager releases the device, the guest drives MBIM/NTB, then exits; the kernel driver and MM re-probe. Cost: no 5G failover during the window. The host controller is never touched. |
| Live box, **QCN9274** (production APs) | IOMMU group alone; reset method `bus` (SBR) | **the real card through VFIO** into a heqk guest, in a **maintenance window**: APs down (wired LAN/WAN stay up). It is gated on a rehearsal (below). |
| Live box, **spare I226** | IOMMU group alone; `flr` + `bus` | igc on real silicon (main plan F2); also the guest's LAN uplink for Wi-Fi/5G tests |
| **CM5 bench** (after the soak) | RP1 carries standard xHCI host controllers; heqk already drives RP1 | **xHCI on a second, real, non-production silicon**, the same arch-neutral driver on aarch64 metal. heqk CM5 is also a proven **WPA2 STA (P10)**, so it serves as a **test client** for the heqk-x86 AP. |
| Phones/laptops we own | — | Wi-Fi clients (WPA2/WPA3) for association, DHCP and throughput tests |

**Wi-Fi window prerequisite (rehearsal, Linux only, no heqk):** in one short window, stop
`fts-hostapd-*`, unbind `ath12k`, rebind it, restart hostapd, and confirm the APs come back **with no
reboot**. Repeat it with an SBR in between (the reset VFIO will perform). If either cycle needs a reboot
to recover, the VFIO window carries a "Wi-Fi down until reboot" risk, and the operator decides whether
to accept it. In the same window, capture `ath12k` WMI/HTT tracepoints during the driver restart. That
gives the full boot-time host↔firmware exchange as an offline fixture for a **replay simulator**, so the
MHI→WLFW→WMI layers can be exercised offline (E1) before any VFIO window.

**Window discipline:**
- Each window is announced and time-boxed, with a written rollback.
- One radio per window.
- The guest gets only its device and a vfio-bound I226 (it never shares the production bridge).
- The guest runs observe-only toward production traffic.
- Windows follow the bench time-share pattern (a lock and a log).

**The metal step without a twin:** the only x86 metal we own is the production box. The first heqk metal
boot there (X3) can be made **low-risk but not zero-risk**:
- The heqk image goes on the existing ESP (777 MB free): a file copy, with no repartitioning.
- It is booted with a one-shot `BootNext` (the next reset returns to Linux by default).
- heqk arms the **iTCO watchdog** (present) first thing, so a hang self-resets back to Linux.
- A `metal-readonly` profile: no NVMe writes, no TPM NV/PCR-policy writes, no Secure Boot key
  enrolment, and Setup Mode is left untouched.
- The whole site (WAN, LAN, Wi-Fi, and every dev session on the box) is down for the boot's duration.

This conflicts with the earlier "no boot/EFI tests on production" rule, so it needs **an explicit
operator decision (D-G)**, and it comes only after every VFIO stage is green.

## 6. Decisions + hardware asks

- **D-F** — QCN9274 native (recommended: it matches ADR 0064, and the board needs it anyway), or a FullMAC 6E
  module as the first on-device AP.
- **No hardware purchase** (operator 2026-11-23). Tools only: `swtpm` (apt) on the live box.
- **D-G** — whether, and when, the one-shot `BootNext` + watchdog metal boot on the production box is allowed.
- **D-H** — approval for the maintenance windows: the Wi-Fi rehearsal, the Wi-Fi VFIO window and the
  modem `usb-host` window.
- **Clean-room protocol** for MHI, QRTR/QMI-TLV, xHCI and MBIM: who reads the GPL behaviour, and who writes the code.
- **ADR:** the EL0 DMA ABI + VT-d confinement is a security boundary. It needs a short ADR (an ADR 0065
  extension) and a `security-auditor` pass before the first DMA-capable EL0 driver.

## 7. Exit criteria (per radio, before the cutover counts it as parity)

- **5G:** cold boot to registered + connected without an operator; failover WAN→5G→WAN inside the V1 bound;
  IPv4 + IPv6; survives modem reset and SIM removal (fails closed to "no cellular", never wedges the WAN);
  a sustained-throughput soak.
- **Wi-Fi:** both bands up from cold boot; WPA2 + WPA3-SAE clients; the separation-matrix rows that touch
  Wi-Fi clients pass; throughput and client count within an agreed fraction of the Linux baseline;
  a firmware crash is recovered by the EL0 server restart + firmware reload (the ADR 0065 4e pattern) without a
  kernel fault.
