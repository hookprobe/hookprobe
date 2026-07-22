# HEQK — Build, Flash & Validate Plan (CM5) + Gap Ledger + "Ahead-of-Linux" Roadmap

_As of 2026-07-22. Purpose: one place to build the image, flash the CM5, validate
every phase on metal, and track the remaining gaps (with the deep-investigation
findings that resolved them) — plus the research-backed roadmap that keeps HEQK's
BPF/JIT detection plane ahead of Linux eBPF, seL4, QNX, and FreeBSD._

---

## 1. Build the image

```bash
cd ~/heqk && . "$HOME/.cargo/env"
# Host-side verifier soundness gate (P16, Agni-style) — must pass before flashing.
rustc --edition 2021 -O tools/verifier-harness.rs -o /tmp/vh && /tmp/vh   # [P16-verifier] PASS

cargo build -p hboot  --release                       # EL2 boot manager
cargo build -p kernel --features hboot --release      # EL1 kernel (cm5)
llvm-objcopy -O binary \
  target/aarch64-unknown-none-softfloat/release/kernel /tmp/kernel.bin
SVN=1 ./cm5-boot/mkimage-hboot.sh \
  target/aarch64-unknown-none-softfloat/release/hboot /tmp/kernel.bin \
  cm5-boot/heqk8.img            # hybrid-signed (ed25519 + SLH-DSA), svn 1
```
QEMU pre-flight (no hardware): `./validate.sh` — all implemented phases must be GREEN
(P0–P6b, DRV, P8/P8p/P8n/P8l/P8t/P8s/P8ss/P8b, and the host `[P16]` harness).

## 2. Flash (rpiboot)

```bash
sudo cm5-boot/flash-now.sh        # runs rpiboot mass-storage-gadget, writes eMMC
```
1. **Fit the nRPIBOOT jumper**, power-cycle → rpiboot flashes automatically.
2. **Remove the jumper** (BOOT → eMMC), power-cycle → HEQK boots.
3. Watch the FTDI @115200 (`/dev/ttyUSB2`). Restore Linux later:
   `config.txt.heqk-backup → config.txt`.

## 3. Validation checklist (FTDI markers, in boot order)

| Marker | Proves |
|---|---|
| `[CM5-BOOT] PASS` | boot chain EL2→EL1, MMU, console on real silicon |
| `measure: PCR0 CRTM-anchored to OTP device id=0x0102…5a31` | B-7 measured-boot root |
| `svn … floor …` (no `WARN … unreadable`) | P7d-c fail-closed anti-rollback |
| `[P7d-B1]` HW-bound AK + `[P7d-B2] PASS` | B-1/B-2 hardware attestation |
| `[P7b] W^X PASS` | kernel .text RO+X, data RW+PXN |
| `[P7c-4c] PASS … counter=~1.3e9 … not wedged` | EL0 driver = preemptible scheduled TCB in own ASID |
| `[P8] rule plane: 11 rules verified, 9 JIT-compiled to native ARM64 on metal` | 4-tier detection plane on silicon |
| `[P8-JIT] PASS … EL1 RO+X … matches interpreter` | native BPF codegen on metal |
| **`[P8-WX] PASS … alias sealed RO`** | **B-9 (JIT half): no writable alias of exec code** |
| `[P8] PASS — inline IPS … forward :53 / drop :4444` | inline enforcement |
| `[P8] 3 real frame(s) … IDS verdict` | real GEM RX → verdict |
| **`[P14] … iommu2/8/5 … present/enabled/bypass`** | **IOMMU containment recon (DMA-window fix seed)** |
| `[P9] RC1 status … link …` | 2nd-interface probe (see §5.3) |
| `[P7c] EL0 driver SERVER processed 5 frames + survived 1 crash-restart` | continuous restartable isolated driver (4d) |
| `halting` + **0 `UNEXPECTED KERNEL FAULT`** | clean run, no regressions |

A green run = the whole spine (P0–P7e) + the detection plane + the verifier + the
capability rights model, metal-validated with zero unexpected faults.

---

## 4. Gap ledger — status after the deep investigation

| Gap | Status | Resolution |
|---|---|---|
| **JIT code-frame RW alias (W^X)** | ✅ **FIXED (CM5)**, flash-validate `[P8-WX]` | Dedicated L3-mapped JIT pool; `jit_seal` flips the GB0 identity page RO after emit → no writable alias. (QEMU coarse-block path still rides block-splitting; metal is the product.) |
| **OOM / unwrap kernel-fatal** | ✅ **RESOLVED** | Adversary-reachable paths already fail closed (Err/None/fail-safe DROP); one runtime cap `unwrap` tidied. Remaining unwraps are test-code (panic = correct fail) or boot invariants (panic = intended fail-closed EL2 reboot). |
| **Capability rights unenforced** | ✅ **FIXED** | `mint` (monotonic rights diminution, Grant-gated) + `has_rights`/`as_frame_rights` enforcement point; `[P2]` proves RO-frame write DENIED, amplification REFUSED. |
| **Recursive revoke stack depth** | ✅ **FIXED** | `caps::revoke` iterative (fixpoint over the flat parent-linked array). |
| **Verifier soundness (attack surface)** | ✅ **HARDENED** | `absdom.rs` modular operators + `[P16]` Agni-style soundness harness (injected-unsound operator caught). Roadmap in §6 for a *proof*. |
| **64 GiB no-IOMMU DMA window** | ◐ **SEED FIXED** (probe on metal), fence staged | `iommu.rs` driver + `[P14]` probe. BCM2712 IOMMU confirmed: whole-block containment via `ADDR_CAP` fence (no requester-IDs). See §5.1. |
| **GEM RX-IRQ for adaptive NAPI** | ◐ **CODE DONE**, on-metal enable staged | Delivery path fully reversed (RP1 src 6 → MSI-X → mip0 → GIC INTID 166). Scaffolding built; §5.2. |
| **P9 second interface (RTL8111H)** | ⏸ **HARDWARE-GATED** (verdict), last software tries staged | Schematic proves NO board reset/power GPIO. §5.3. |

---

## 5. Staged metal experiments (separate, careful flashes)

### 5.1 IOMMU fence — close the 64 GiB DMA window
`iommu::probe()` (already in boot, `[P14]`) confirms which block is live + whether
firmware left it enabled/bypass. **Next flash:** call `iommu::fence(base, granted_top)`
on the block gating the target RC — read back `ADDR_CAP`/`CTRL` to confirm the
`ADDR_CAP_SHIFT=12` assumption, then drive an out-of-window DMA and observe the
abort. Apply to **iommu2** (pcie1/RTL — safe while the RTL link is down) first;
**iommu5** (RP1/GEM) needs a ceiling above the live ring/buffer PAs or the datapath
breaks. Full windowed (2-level page-table) containment needs the PTE bit-layout
from `bcm2712_iommu_map` — the one remaining unknown.

### 5.2 GEM RX-IRQ (retire the RX poll wakeup)
Path: `gem::rx_irq_enable()` (IER RCOMP) + `Gic::enable_spi(166)` + the `handle_irq`
INTID-166 branch (all built). **Must mask the timer PPI first** (or the scheduler-
torn-down timer fires) — add a `Gic` disable + a self-contained probe that enables
only SPI 166, waits for real RX frames, and reports `GEM_RX_IRQS`:
- **fires** → firmware pre-programmed the RP1 `MSIX_CFG_6` + inbound window; done.
- **silent** → program `MSIX_CFG_6` at RP1 `0x108000 + 0x08 + 6*4` (ENABLE + addr
  `0xFF_FFFF_F000` + data 6), and if still silent add the RC2 inbound window
  `0xFF_FFFF_F000 → 0x10_0013_0000`. Keep `poll_rx` as the drain routine + fallback.

### 5.3 P9 — the definitive disambiguation
Schematic verdict: **no GPIO to drive.** Two remaining steps before calling it a
hardware fault:
1. This build's config knobs (`pciex1_gen=2`, `pcie_tperst_clk_ms=100`) — reflash + re-read `[P9]` RC1 status.
2. **Run `cm5-boot/linux-observe/`** to record an actual `rc1dump.txt` (never captured yet):
   - Linux's `pcie-brcmstb` **also** can't set `STATUS & 0x30` → **hardware/board fault** (RMA / reseat CM5 / reflow / try a second board).
   - Linux **does** train → diff its trained registers vs `rtl8111::rc1_train()` and mirror the deltas (likely the CLKREQ/HARD_DEBUG mask + refclk MDIO, Track-B steps 8–9).

---

## 6. Research-backed roadmap — stay ahead of Linux / seL4 / QNX / FreeBSD

**Thesis (defensible, cited):** no system has a *verified verifier* **and** a
*verified JIT* **and** a *tiny owned TCB* together. seL4 has the kernel proof but
**no in-kernel detection/extension plane**; Linux eBPF (20k-LOC C verifier, CVE
history — CVE-2020-8835 / 2021-3490 / 2021-31440) and Windows (PREVAIL verifier,
**unverified uBPF JIT, no tnum**) have the plane but not the assurance; FreeBSD
eBPF (`ubpf`/`generic-ebpf`) has **no verifier at all**; QNX is certified-not-proven
with no BPF. HEQK can occupy the empty quadrant.

Ranked (leverage-per-effort). **✅ = landed 2026-07-22.**

- ✅ **tnum domain (item 2) — LANDED** (`absdom.rs`): sound-and-optimal tnum
  and/or/xor/lshift/add (CGO'22), Agni-checked in the harness (all SOUND; injected
  unsound tnum_and caught). HEQK now has the bitwise precision PREVAIL/Windows lack.
  _Staged next:_ wire tnum into `verify_prevail`'s per-register state to tighten
  AND_K/OR/LSH on the live datapath.
- ✅ **Mandatory JIT constant blinding (item 5) — LANDED** (`bpf_jit.rs`): every
  MOV64_K immediate XOR-split with a per-compile key — attacker-chosen gadget
  constants never appear verbatim; JIT still == interpreter.

1. **Agni-style SMT soundness CI** (replace the sampling harness). Encode each
   `absdom.rs` operator's γ-soundness as a bit-vector SMT query, run Z3 in CI —
   *exhaustive* over all inputs, not sampled. _Agni, CAV'23 (github.com/bpfverif/agni)._ Effort: medium.
2. **Add a tnum (tristate) domain** alongside intervals — bit-level known/unknown,
   strictly more precise than PREVAIL/Windows on bitwise/mask/CIDR ops (which our
   rules do constantly). Use the CGO'22 *proven* add/sub/mul and CEGIS-*synthesize*
   the rest; keep each operator sound-in-isolation (SAS'24 lesson). _arXiv:2105.05398._ Effort: medium.
3. **Jitterbug/Serval-style per-instruction JIT proof** — the headline
   differentiator (only Linux RV32 has it). Spec = our own interpreter; prove each
   emitted AArch64 sequence semantically equals `interp(op)`, closing the
   verifier→JIT **bounds-elision** loop end-to-end. _Jitterbug OSDI'20; Serval SOSP'19._ Effort: medium-high.
4. **Kani-prove the core operators** — `kani::proof` harnesses; sound+complete at
   fixed u64 width ⇒ "bounded" = "total." A machine-checked artifact Linux can't
   claim for its live verifier. Effort: medium.
5. **Mandatory JIT hardening now** (low effort): constant blinding (defeat
   JIT-spray), no interpreter fallback, Spectre-v1 index masking in the verifier.
   We own the stack ⇒ make these non-optional, not configs.
6. **(Later) K2-style verified superoptimizer** for detection rules — safe-by-
   construction rule optimization; reuse its BPF-in-FOL equivalence spec. _SIGCOMM'21._

Landing items **1–4** lets HEQK claim, with citations, **a provably-sound verifier
driving a formally-verified JIT with tnum-grade precision in a tiny owned TCB** —
a combination Linux, Windows, FreeBSD, seL4, and QNX each individually lack.
