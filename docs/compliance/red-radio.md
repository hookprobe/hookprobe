# RED art. 3(1)(a), 3(1)(b), 3(2): radio, EMC, safety (gate G2)

Draft. **Every row here is a laboratory item.** No test report exists in this repository. Statuses are
defined in [`README.md`](README.md). Engineering facts below are inputs for the lab, not evidence of
conformity.

## 1. Essential requirements

| Article | Scope | Typical harmonised standards (for the lab to confirm and select) | Evidence in repo | Status |
|---|---|---|---|---|
| 3(1)(a) | Health and safety (electrical safety, RF exposure) | EN IEC 62368-1 (safety); EN 62311 / EN 62479 or EN 50665/50385 family (RF exposure) | None | LAB / GAP |
| 3(1)(b) | EMC | EN 301 489-1 + EN 301 489-17 (radio equipment EMC); EN 55032 / EN 55035 for the host | None | LAB / GAP |
| 3(2) | Efficient use of spectrum | EN 300 328 (2.4 GHz wideband); EN 301 893 (5 GHz RLAN); EN 300 440 only if applicable | None | LAB / GAP |
| 3(2) | Bluetooth (same CYW43455) | EN 300 328 if Bluetooth can transmit in the shipped product | BT driver exists but feature `p10bt` is not in shipped flavours (`os/kernel/kernel/Cargo.toml`) | LAB: confirm radio stays off, or test |
| RED art. 10(2) | Combination of radio + software: information on intended software | Firmware/driver are not the module vendor's Linux driver (see §3) | `firmware-provenance.md` | LEGAL / LAB |
| RED art. 10(8), 10(9), 17 | Instructions, safety information, DoC, CE marking, conformity procedure (Annex II module A, or III/IV) | n/a | None | GAP |

The enclosure, antenna (type, gain, cable) and power supply are part of the finished product. **GAP**: no
enclosure / antenna / PSU specification is recorded in the repository. Release gate REL-06 (thermal in the
enclosure) is still `blocked:not run` (`tools/release-gate/items.txt`).

## 2. CM5 module approvals (verify only; nothing asserted here)

`os/kernel/PRODUCTION_READINESS.md` §5 states "the CM5 module is pre-certified; antenna / enclosure are
not". **This package does not rely on that sentence.** Obtain from the module vendor and file in the
technical documentation:

| Item to obtain | Why |
|---|---|
| The module's RED test reports / DoC and the exact module variant (wireless SKU) they cover | Determines which 3(2) tests can be referenced vs repeated |
| The antenna(s) and maximum gain covered, and conditions for external-antenna use | Host antenna choice may invalidate reliance |
| Integration conditions on firmware, NVRAM (RF calibration / power tables) and CLM blob | heqk loads its own firmware/NVRAM/CLM (§3); conducted power and channel behaviour depend on them |
| Whether reliance is permitted with a non-vendor host OS / driver | heqk replaces the vendor's Linux `brcmfmac` driver |

## 3. Radio-configuration facts from the repo that the lab must see

| Fact | Source | Compliance relevance |
|---|---|---|
| The CYW43455 firmware + CLM blob are the regulatory authority; heqk uploads the NVRAM verbatim and sets the country itself | `os/kernel/arch-aarch64/src/cyw43.rs` lines ~571-583; `os/kernel/cm5-boot/stage-wifi-firmware.sh` header | Channel/power limits come from the firmware CLM, not from a host regdb |
| **Country is hard-coded to `RO` (Romania)**: `ccode=RO` baked into NVRAM by default (`REGDOMAIN="${REGDOMAIN:-RO}"`), and `wifi_regulatory(b"RO", 0)` / `set_regdomain(b"RO", 0)` in code | `stage-wifi-firmware.sh`; `cyw43.rs` ~line 2614; `os/kernel/kernel/src/main.rs` ~line 2995 | **GAP**: per-market country configuration and its control (who can change it) are undefined. EU-wide ETSI parameters vs country-specific rules must be confirmed by the lab; a non-EU SKU must not ship `RO` (see `fcc-gate.md`) |
| Firmware ≥ 7.45.265 required: 7.45.234 silently ignores the country (stays world/99) | `stage-wifi-firmware.sh` (`MIN_FW`), metal-proven 2026-07-23 per header | Test the exact pinned firmware (`firmware-provenance.md`); any firmware bump is a radio change |
| **DFS channels unusable**: 5 GHz AP limited to UNII-1 (36/40/44/48); DFS channels 52-144 excluded everywhere; channel 52 refused by config parser | `os/kernel/kernel/src/wificfg.rs` header + tests (`channel=52` → `BadChannel`); ADR 0034 D4; ADR 0042 (retired 2026-11-12, no successor) ("UNII-1 36–48 only, VHT80"); `os/kernel/P9_WIFI_INVESTIGATION.md` line ~109 | No radar detection / CAC needed for AP mode if the lab confirms the firmware cannot be driven onto DFS channels. **STA mode** (heqk also associates as a client) on DFS channels relies on firmware passive-scan behaviour: lab to verify |
| 2.4 GHz channels 1-13 accepted by the config parser | `wificfg.rs` | Correct for ETSI; wrong for FCC (see `fcc-gate.md`) |
| **AP is limited to one BSS**: firmware reports `mbss` 0, cannot be enabled (BCME -23) | `docs/design/metal-evidence/20261110-batch52-53.md` "Guest SSID: this firmware cannot run a second AP" | Test configuration = single BSS |
| WPA3-SAE / PMF host implementation | `docs/design/metal-evidence/20261110-batch38-47.md` | Not a 3(2) item; listed so test modes match shipped modes |
| Bandwidths / throughput: VHT80 on UNII-1 used | ADR 0042 (retired 2026-11-12, no successor); memory notes on brcmfmac caps | Test VHT20/40/80 modes as shipped |
| `max_clients` 1..64 (`maxassoc`) | `wificfg.rs` | Test-mode definition |
| **The in-repo NVRAM files for Pi 4, CM5 and the generic name are byte-identical** (sha256 `57cba1b4…`) | `os/drivers/firmware/brcm-firmware-rpt/*.txt` (see `firmware-provenance.md`) | **Verify with the module vendor that this NVRAM (RF calibration, power tables) is the one approved for the CM5 module.** A wrong NVRAM can change conducted power |

## 4. Required before G2 can close

1. Accredited lab test plan built from §1, using the shipped image (sha256 + git from
   `<image>.json`), the pinned firmware hashes, the final enclosure, antenna and PSU.
2. Module-vendor documentation per §2.
3. Decision on per-market regulatory-domain control (replace the hard-coded `RO`).
4. Test reports, risk assessment, user instructions, DoC.
5. Operator sign-off (`certification`, release gate CMP-01) referencing the reports.
