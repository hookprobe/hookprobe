# Post-soak bench batch on the CM5, 2026-11-28

Bench CM5 (Cortex-A76 r4p1), fortress port-4 VLAN bench, bench Pi as the Wi-Fi client. This batch closes the post-soak
plan of 2026-11-25: the R0 readout, the /setup safety path (G48 / GF-H4), and the radar check after the fix. Bench
gaps W-04 and MT-J5 are closed too.

## 1. rpiboot entry (bench rig reference)

The operator's sequence on the Nano relays, sent as plain `cm5-relay.py` subcommands:
1. all off (`on`, `in2-off`);
2. rest **15 s**;
3. `off` (IN1 energised, board off);
4. 1 s later, `in2-on`;
5. 9 s later (both held, 10 s in total), `on` (IN1 released);
6. the boot ROM `0a5c:2712` enumerates within 1 s;
7. `in2-off`.

Result: **5/5** entries, 17:36:26–17:38:11, plus one more for the restore flash.

Sequences run back to back failed: the Nano answered "no reply" to `P1` or `B0` right after the coils switched. So did
holding IN2 only 5 s before the release. Rest before each sequence. A reboot after a flash is: all off, 15 s rest, IN1
on 5 s, IN1 off.

## 2. R0: FP/SIMD and trap state at boot (t0inv HBoot)

Image `r0t0inv-917f74359`, clean rpiboot flash: **VERIFIED** (eMMC sha256 `6d81d80e…`). The boot printed secure boot
PASS (ed25519 AND SLH-DSA, svn OK) and then:

| Readout | Value |
|---|---|
| `r0.cptr_el2` | `0x33ff`, **TFP = 0** (EL2 does not trap FP/SIMD) |
| `r0.cpacr_el1` | `0x0`, **FPEN = 0** (FP/SIMD trapped at EL1/EL0: softfloat contract holds) |
| `r0.sctlr_el1` | `0x30d00800`, **A = 0** |
| `r0.hcr_el2.e2h` | **0** (no VHE) |
| ID registers | FP = 1, AdvSIMD = 1, **SVE = 0**, DotProd = 1 |

Input for ADR 0072 (KR-1). An FP/SIMD grant only needs CPACR_EL1.FPEN, because EL2 already passes FP through. SVE is
absent, so only NEON/DotProd is available.

## 3. Restore and radar (Infineon fix #1625) on the shipping-path image

Image `lansvcfix-07fdef234` (main with #1625 radar + #1635 lansvc fix), clean rpiboot flash: **VERIFIED** (sha256
`31d0db59…`). It booted with secure boot PASS and `[ID] image=lansvcfix-07fdef234`.

Serial log, same boot:

```
[P11-AP] 802.11h spect=1 set ok=true read back Some(1); radar=1 set ok=true read back 1 — radar detection ON
[P11-ACS] 6 neighbours scanned -> channel 36 @ 80 MHz (chanspec 0xe02a ...)
[P11-ACS] operating chanspec readback 0xe02a vs requested 0xe02a => ON THE CHOSEN CHANNEL
```

As Infineon advised (radar = 1 must be set explicitly for a DFS AP), both values read back as 1. The AP chose
non-DFS channel 36.

## 4. G48 / GF-H4: /setup safety path, `cm5-cfgd-live-check.sh`: **PASS 20/20**

A first-run /setup sends one HQCFG1 bundle. On the bench check, a bundle that breaks the WAN must revert by itself, and
Mission Control must stay reachable on the AP.

| | Result |
|---|---|
| A1–A5 | Policy bundle applies live, no reboot, commits by itself. Rule 7 (MC on the AP) answers |
| B1–B5 | Static WAN bundle applies live, LAN client reaches the WAN, rule 7 during the trial, owner confirm commits |
| **C1–C5** | **Dead-gateway bundle, never confirmed: not usable within the window → reverted live to the last-known-good WAN. That WAN works again, no reboot, rule 7 after the revert** |
| E1–E4 | DHCP WAN live, confirmed once leased. Still in force after a reboot. `/api/config` at rest: sealed, secrets protected |

The bench baseline was restored before and after (generation 7, bench policy only).

Not covered: the browser wizard screens themselves. They belong to the UI session; this run tests the backend path
they call. A full first-run that ends in success needs a bench port with untagged DHCP.

## 5. MT-J5: WAN RX ring 512 (`cm5-throughput-check.sh`, 5 runs)

Wi-Fi client download through NAT + IDS + Shield: 88.5 / 97.0 / 96.1 / 91.3 / 97.2 Mbps, **median 96.1** (floor 30).

GEM counters after the runs: 221,700 frames received, **`res_err=0`, `overrun=0`**, fcs/len errors 0. With the old
128-entry ring the same path gave ~6 Mbps at 64 % `res_err`.

## 6. W-04: beacon IEs of the CM5 AP

Read from the bench Pi's `wpa_supplicant` (D-Bus `BSS.IEs`, the associated BSS):

| IE | Value |
|---|---|
| SSID | `HookProbe-Setup-R3Q1` (first-run setup network) |
| RSN | group CCMP, pairwise CCMP, AKM PSK + SAE (WPA3 transition), caps `0x008c`: MFPC = 1, MFPR = 0 |
| RSNX | `0x20`: SAE hash-to-element advertised |
| Beacon protection | not advertised (Extended Capabilities is 8 octets, so bit 84 is absent). It is optional in WPA3; recorded, not a defect |
| WPS | **no WPS IE**. The vendor IEs are WMM (`0050f202`) and Broadcom (`00101802`) |
| Country | `RO`, channels 36–64 and 100–140. W-03 was ruled not-a-defect, and radar detection is now on (§3) |

## Not done in this batch

- **MT-J6 (IPv6 re-probe):** needs kea stopped on fortress during a boot, which takes sudo on fortress. It waits for
  the operator.
- **Flash stub M1** (Chrome WebUSB): needs the operator at the browser.
- **P-256 timing on CM5:** the host ctgrind review stands (20261108-p256-ct.md). A metal run would need a new bench
  feature.
