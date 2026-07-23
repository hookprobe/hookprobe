# P10 WiFi (CYW43455 SDIO) — Status Tracker

Updated 2026-07-23. Legend: ✅ done (metal-proven) · ⚠️ partial · ❌ blocked · 🔲 written/not reached.
Full context: `HEQK_REMEDIATION_PLAN.md`, `HEQK_KERNEL_DOSSIER.md` (Part 3 = the bring-up sequence).

## Stage A — SDIO link + chip ID  ✅ DONE (metal-proven)
| Step | Status | Evidence / Notes |
|---|---|---|
| WL_ON power + pinmux (gio GPIO28, pinctrl D0-stepping) | ✅ | now with reset PULSE (low→high) |
| VC mailbox → clk_emmc2 = 100 MHz | ✅ | mailbox validated |
| SDHCI host init + **INT_ENABLE 0x34** | ✅ | *the* fix that cracked CMD5 (status bits never latched) |
| CMD5/CMD3/CMD7 enum + CMD52 F1 enable | ✅ | CAPS=0x15eac832 matches Linux |
| ALP clock + backplane window | ✅ | needed before chipcommon read |
| Chip ID read → **0x4345** | ✅ | `[P10-A] PASS` (via CMD52 bytes) |

## Stage B — firmware upload + ARMCR4 boot  ⚠️ 90% — ONE blocker
| Step | Status | Evidence / What's needed |
|---|---|---|
| EROM walk → CR4 (0x18002000 / wrap 0x18102000) | ✅ | |
| bp_w32 via 32-bit CMD53 (AI regs need atomic writes) | ✅ | the fix that let the CR4 halt |
| CR4 halt (cr4_set_passive) | ✅ | halted=true, IOCTL=0x21 |
| Func block size 64 + block-mode CMD53 | ✅ | fixed DATA framing |
| Firmware (609 KB) + NVRAM upload → 0x198000 | ✅ | fail_stage=0 |
| CR4 activate (vector→addr0, release) | ✅ | IOCTL=0x01, CPUHALT cleared → CR4 running |
| F2 pre-seq (FORCE_HT, F2 blksz 512, SDPCM ver, hostintmask) | ✅ | code applied; FORCE_HT confirmed (CHIPCLKCSR bit 0x02) |
| **HT PLL locks (HT_AVAIL 0x80)** | ❌ **BLOCKED** | CHIPCLKCSR=0x52 → HT never available (even after full power-off + WL_ON reset) |
| **F2 ready (firmware alive)** | ❌ blocked | F2_IOR=0x00, stuck at step 7 — gated on HT |

## Stage C — SDPCM/BCDC + regdomain  🔲 not reached (blocked by B), code written
| Step | Status | What's needed |
|---|---|---|
| SDPCM/BCDC framing (bcdc_dcmd) | 🔲 buggy | doffset in byte 3 not byte 6 (=12) — fix |
| TX credit tracking (txmax) | 🔲 missing | read txmax (byte 5); TX only while tx_seq != txmax |
| CMD53 >512 B truncation (D3) | 🔲 bug | loop BCDC/CLM in ≤512 B chunks |
| clmload + country iovar encoders | ✅ written | correct off-metal |
| **Regdomain = RO** | ✅ done (baked) | ccode=RO in NVRAM + fw ≥ 7.45.265 |

## ACTIVE BLOCKER + next diagnostic
**HT PLL won't lock → F2 never ready.** CR4 released+running, FORCE_HT set, firmware uploaded,
but HT_AVAIL never sets; NOT the reset trap (full power-off didn't help). → the firmware likely
isn't truly executing (it's what brings up the PMU/HT PLL). **Next:** read back TCM 0x198000 words
after upload vs FW_BIN; verify the CR4 reset-vector address (4345 may boot CR4 from its own vector,
not backplane 0). `f2_diag()`/`cr4_halt_diag()`/`fw_last_step()` are the instrumentation.

## Non-blocking known issues (audit)
- Bus width: 4-bit CMD53 timed out on D1–D3 → running 1-bit (D0). Revisit D1–D3 pinmux/routing.
- WiFi driver not restartable (wedge needs power-cycle) → MINIX-pattern restart = future.
- Firmware blob unverified → measure into a PCR before upload (security TODO).
