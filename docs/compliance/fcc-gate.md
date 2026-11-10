# FCC: separate market-entry gate (G4)

Draft. **Separate from the EU gates**: an EU result never closes an FCC item and vice versa. Every item is
a lab / TCB / legal item; nothing is closed. KDB numbers are listed as items **to verify** (current
revision and applicability) on the FCC KDB site by the TCB or lab; they were not re-read for this draft.

## 1. Rule parts to assess

| Area | Rule (47 CFR) | Product relevance | Evidence in repo | Status |
|---|---|---|---|---|
| 2.4 GHz Wi-Fi (and BT if enabled) | Part 15 subpart C, §15.247 | AP + STA on 2.4 GHz | None | LAB |
| 5 GHz U-NII | Part 15 subpart E, §15.407 | AP on UNII-1 (36-48) only per repo; STA scan/association behaviour on other bands set by firmware | `wificfg.rs`, ADR 0034 D4, ADR 0042 | LAB |
| DFS | §15.407(h) | AP excludes DFS channels (52-144) per repo; STA on DFS must be passive/slave only | `wificfg.rs` (channel 52 refused), `os/kernel/P9_WIFI_INVESTIGATION.md` | LAB: verify firmware cannot initiate on DFS |
| Host unintentional emissions | Part 15 subpart B (§15.107, §15.109), SDoC (Part 2 subpart J) | Digital device (CM5 + carrier + Ethernet) | None | LAB |
| Modular transmitter | §15.212 | Reliance on the CM5 module's grant, if one exists for the variant used | None | TCB / module vendor |
| RF exposure | §1.1310, §2.1091 (mobile) | Fixed/mobile installation distance | None | LAB |
| Labelling and user information | §2.925, §15.19, §15.21, §15.105 | FCC ID ("Contains FCC ID: …") and statements | None | GAP |
| Software configuration control | §15.407(i) (U-NII software security) | heqk is a non-vendor driver that loads its own firmware, NVRAM and CLM | `firmware-provenance.md` | TCB / LEGAL |
| Equipment authorization eligibility | Part 2 (incl. covered-equipment restrictions) | Supply-chain of radio module | None | LEGAL |

## 2. KDBs to verify (list, not conclusions)

| KDB | Topic | Why |
|---|---|---|
| 996369 (D01-D04) | Modular transmitter integration guide for host manufacturers | Conditions for relying on the module grant; when host testing / C2PC is needed |
| 594280 (D01, D02) | Configuration control; U-NII software security description | Country/channel/power must not be user-changeable outside the grant; heqk's own driver and the `RO` default are directly in scope |
| 905462 | U-NII DFS compliance | Confirm "no DFS operation" claim incl. STA mode |
| 789033 | U-NII measurement guidance | Test method |
| 558074 | DTS (§15.247) measurement guidance | Test method |
| 447498 | RF exposure procedures | Exposure evaluation |
| 784748 | Labelling | Label |
| E-labelling guidance (KDB number to verify) | E-labelling, if planned | Device has a web UI |

Rule citations in §1 (including §15.407(i) for U-NII device security) are to be verified against the
current eCFR text by the lab/TCB.

## 3. Host-integration responsibilities (items for the TCB, from repo facts)

| Item | Repo fact | Open question / action |
|---|---|---|
| Driver and firmware differ from the module vendor's reference | heqk embeds the CYW43455 firmware + CLM + NVRAM via `include_bytes!` (`os/kernel/arch-aarch64/src/cyw43.rs` lines 590-592) and talks to the firmware directly | Is the module grant valid with this software? Does the grantee's integration guide allow a third-party driver? Possibly a permissive change or a new grant (TCB to decide) |
| **Regulatory domain is hard-coded `RO`** | `stage-wifi-firmware.sh` (`REGDOMAIN` default `RO`, NVRAM `ccode=RO`), `cyw43.rs` `wifi_regulatory(b"RO", 0)`, `main.rs` `set_regdomain(b"RO", 0)` | **GAP (blocking for US)**: a US SKU must lock the US domain at build/factory time with no end-user path to change it (KDB 594280). `RO` would permit 2.4 GHz channels 12/13 and ETSI power limits |
| 2.4 GHz channels 1-13 accepted by `WIFI.TXT` parser | `os/kernel/kernel/src/wificfg.rs` | US SKU must reject 12/13 (firmware CLM is the authority; parser should also refuse) |
| `WIFI.TXT` / owner-signed config can set channel | ADR 0058, `wificfg.rs` | Confirm no country/power field is exposed (none found in `wificfg.rs`; keep it that way) |
| NVRAM modified at staging (placeholder `macaddr`, `ccode`/`regrev` appended) | `stage-wifi-firmware.sh` | Confirm with module vendor/TCB that these edits are permitted; NVRAM power tables untouched |
| Firmware upgrade path | Firmware is inside the signed OS image; an OS update can change it (`otaimg.rs`) | Change-control procedure: a firmware/CLM/NVRAM change triggers radio re-assessment |
| Bluetooth | Not in shipped flavours (`p10bt` opt-in) | Lab confirms BT is not transmitting, or tests it |
| Antenna | Not specified in repo | GAP |

## 4. Required before G4 can close

1. Module grant documentation (FCC ID, grant conditions, integration guide) for the exact CM5 variant.
2. TCB decision on reliance vs new grant / permissive change, considering heqk's own driver, firmware and
   regulatory-domain handling.
3. US-specific build/factory configuration with locked domain; software security description.
4. Lab reports (§15.247, §15.407, subpart B, RF exposure), labels, user manual statements.
5. Operator sign-off referencing the grant and reports (recommend a dedicated release-gate item, separate
   from CMP-01's EU scope).
