# HEQK Core — Security Audit & Fixes (2026-07-20)

A deep vulnerability audit of the kernel source (a parallel adversarial review of every file, plus targeted fixes). Five findings; four fixed, one partially mitigated with the full fix deferred to a named larger effort. Each fix is validated (`./validate.sh` green, P0–P6b + DRV).

| # | Sev | Defect | Disposition |
|---|---|---|---|
| 1 | **HIGH** | **virtio RX: device-controlled `id`/`len` used to index buffers unchecked** (`virtio.rs`) — a hostile/buggy NIC sets `id` huge → OOB read of kernel RAM into the packet buffer (info-leak) or a data abort. | **FIXED** — `if id >= QSZ \|\| len <= NET_HDR \|\| len > BUF_SZ { return None }` before use. Untrusted device input is now bounded. |
| 2 | **HIGH** | **User pages had no UXN/PXN** (`mmu.rs`) — the EL0 **stack was executable** (classic exec-stack → shellcode), and every EL0-writable page was **executable at EL1** (priv-esc if the kernel ever branches into user memory). | **FIXED** — split into `map_user_code_page` (EL0 RO+exec, **W^X**), `map_user_data_page` (EL0 RW, **UXN+PXN**), `map_user_device_page` (Device, UXN+PXN). Kernel data pages get UXN+PXN too. |
| 3 | MED | **JIT "W^X" defeated by a writable identity alias; GB1 RAM is RWX at EL1** (`bpf_jit.rs`/`mmu.rs`) — JIT code is RO+exec at its VA but still **writable via its identity mapping**; and the 1 GiB kernel RAM block has no PXN, so heap/stacks/JIT frames are executable at EL1. | **PARTIALLY MITIGATED / DEFERRED** — JIT code is RO+exec via its exec alias and EL0-non-exec; user/kernel *data* pages now carry PXN. The full fix (remove the RW identity alias of code frames + PXN kernel *data* while keeping kernel *text* executable) requires **kernel-page block-splitting** — the already-named deferred W^X gap (`buildPlan.md`). Documented, not hidden. |
| 4 | MED | **Unexpected EL1 (kernel) fault exited with code 0 (success)** (`exception.rs`) — a real kernel crash (e.g. from #1) terminated QEMU with status 0, which the harness read as PASS, laundering crashes into "green." | **FIXED** — `rust_exception` now `exit(1)`; only the deliberate all-tests-passed path exits 0. Kernel crashes can no longer masquerade as success. |
| 5 | LOW | **`verify()` off-by-one and not enforced** (`bpf.rs`) — accepted a jump to `== prog.len()`; and `verify()` gated nothing (only a self-test), so a future third-party BPF path would be fail-open. | **FIXED** — bound corrected to `>= prog.len()`; the signed threat rule is now **verified before the datapath runs it** (verify-then-run), establishing the discipline for future untrusted rules. |

## Confirmed sound (audited, no change needed)
- BPF interpreter runtime checks — LDX bounds, register-index (`>= 11`), and step-limit (termination) are correct; `wrapping_*` prevents overflow UB.
- Syscall boundary dereferences **no** EL0-supplied pointer; `SYS_CAP_IDENTIFY`'s CPtr goes through bounds-checked `slots.get()`.
- `caps::revoke` recursion is bounded by the CNode slot count.
- Kernel RAM identity map is correctly `AP_RW_EL1` (EL0 no-access); IPC critical sections mask IRQs; the trap-frame save/restore is symmetric.

## The one honest residual
**Full W^X for kernel code and the JIT (#3) needs kernel-page block-splitting** — replacing the coarse 1 GiB identity blocks with per-page mappings so kernel *text* is RX, kernel *data* is RW+PXN, and JIT frames have no writable alias. That is the same deferred item that also blocks per-address-space ASIDs, tracked in `buildPlan.md`. It is a real limitation, not a claimed-green gate.

*Method: adversarial source review of all of `kernel/src` + `arch-aarch64/src`, ranked by exploitability, each fix re-validated against the full P0–P6b + DRV gate ladder.*

---

# HEQK Core — Round 2: Deep End-to-End Audit (2026-07-21)

Trigger: after the RP1 GEM datapath reached metal (real Ethernet frame → IDS
verdict on the microkernel), a **four-agent parallel adversarial review** of the
whole system — (1) networking/DMA, (2) core kernel primitives, (3) crypto/boot
chain, (4) MMU/EL2–EL1. Scope now includes the new attack surface: the GEM
driver, the packet parser facing hostile wire frames, the PCIe inbound DMA
window, and the quantum-safe boot/attestation chain on metal.

## Fixed this round (QEMU-validated P0–P6b + DRV green; in the metal image)
| # | Sev | Defect | Fix |
|---|-----|--------|-----|
| R2-1 | **MEDIUM** | **IDS evasion** — `net.rs` parsed only single-VLAN IPv4, so IPv6 / QinQ / 802.1ad traffic to a blocked L4 port fell through to `PASS` **without running the threat rule** (`packet.rs` `Some(m) => PASS`). An attacker reached port 4444 simply over IPv6. | `parse()` now unwraps up to 3 stacked VLAN tags and parses IPv6 via a bounded (8) extension-header walk to locate the real L4 header; over-long chains fail closed. Closes the bypass; still `.get()`-safe. |
| R2-2 | LOW | **OOB read** — `attest_replay` looped `events.add(i)` over a log-supplied `count` with no upper bound; a corrupted count walks off the page. | Clamp `count` to what fits in the 64 KiB log region before iterating. |
| R2-3 | LOW | **Footgun length** — `gem::poll_rx` returned a device-controlled `desc_len` (up to 16383) that could exceed bytes actually copied; a caller slicing `out[..len]` would read OOB. | Return `desc_len.min(copy_n)`. |
| R2-4 | MEDIUM | **IPC TOCTOU** — one global `MSG`; a second sender (no-receiver branch, after the first delivery cleared `RECV_WAITER`) overwrote the word a woken receiver had not read → wrong/lost message. | Split into `SEND_MSG` (parked by a waiting sender) and `DELIVERED` (private handoff to a woken receiver). |

## Verified SOUND (adversarially, not merely unreviewed)
- **Secure-boot enforcement:** hybrid ed25519 **AND** SLH-DSA (no downgrade), verify binds the *recomputed* hash not the header's, SVN bound into the signed message with a correct unsigned floor compare, **geometry pinned** (load_pa/entry_off/size) so a malicious image cannot redirect the payload over HBoot's EL2 code or into unsigned bytes, `mkimage` signs exactly what runs.
- **Datapath memory-safety vs. hostile input:** `net.rs` parser, `bpf.rs` VM (LDX bounds + register-range + step-limit termination), `packet.rs` SPSC ring, and both DMA RX paths (`gem`, `virtio`) — all bounds-checked, fail-closed, no OOB from a hostile NIC/frame.
- **EL0→EL1 boundary:** no EL0-supplied pointer is ever dereferenced; registers scrubbed on `eret` to EL0; CPtrs resolve through bounds-checked `slots.get`; capabilities unforgeable (CSpace is kernel-private, EL0 passes only an integer index).
- **MMU mechanics:** MAIR↔attr-index match, TCR 39-bit sizing, correct barrier/TLBI ordering at enable (CM5 + HBoot regimes), device MMIO is Device-nGnRnE+PXN|UXN, no RAM mapped Device / no MMIO mapped Normal.

## Prioritized backlog — NOT fixed this round (named, not hidden)
These are either hardware-gated or require the block-splitting epic; bundling them
into a metal flash carries silent-hang risk that cannot be QEMU-validated, so they
are deferred to dedicated, individually-validated passes.

| # | Sev | Gap | Why deferred / fix path |
|---|-----|-----|------------------------|
| B-1 | ~~CRITICAL~~ **CLOSED (P7d-b1, 2026-07-21, validated on CM5 metal)** | The AK is no longer a software constant in the world-readable image. HBoot generates a 256-bit secret from the on-device TRNG, burns it into **customer OTP (block 1)** once (`hboot/src/ak_derive.rs`, `mailbox::set_customer_otp`), and derives the **per-device AK** — ed25519 + SLH-DSA-128f (deterministic keygen) — from the read-back OTP contents; it publishes the per-device AK pubkeys and the kernel verifies the cert chain against them. Metal proof: boot 1 burned (`OTP burn OK`), boot 2 was idempotent (`already provisioned`) and derived the **same** `ak_ed_pk=0x03699d2a`; kernel `AK=HARDWARE-BOUND … VERIFIED`. The AK now lives only in fuses — per-device, not in the image. Identity `device_id` (serial) is also bound into the cert; AK sk scrubbed from RAM after signing. | **Honest limit:** OTP is readable by on-device supervisor code (documented Pi property) → not HSM-grade; closes B-1 *as written* (not-in-image, per-device). The AK is now permanent (OTP can't be rewritten → no rotation). Off-device verifier must enroll the published per-device pubkey (TOFU). |
| B-2 | ~~CRITICAL~~ **CLOSED (P7d-a + P7d-b2, 2026-07-21)** | (a) The boot nonce is now hardware-TRNG per boot (P7d-a, `hboot/src/rng.rs`). (b) The kernel runs a **runtime attestation service** (`kernel/src/attest_svc.rs`): HBoot mints a per-boot **ephemeral ed25519 key**, hybrid-AK-certifies it (`eph_pk‖svn‖device_id‖PCRs`, quantum-safe), and scrubs the AK; the kernel signs **verifier-supplied challenge nonces** with the ephemeral key on demand. A response to one nonce does not satisfy another → replay defeated. QEMU: `[P7d-B2] PASS` (distinct nonces → distinct valid sigs; cross-replay rejected). The device AK never enters the kernel and no SLH-DSA signing lives there. | Transport (deliver the verifier nonce over the network) is P8 packet-plane integration; the freshness *mechanism* is closed. |
| B-3 | ~~HIGH~~ **CLOSED (P7e, 2026-07-21, validated on CM5 metal)** | HBoot now enables **stage-2 translation** before `eret` (`hboot/src/stage2.rs`, `VTCR_EL2=0x8002_3559`, single 4KB L1 table) that carves its own footprint `0x200000..0x800000` (code+vectors+page-tables+EL2 stack) out of the EL1 IPA space as **invalid** — an EL1 access there takes a stage-2 fault straight to EL2 (`el1_blocked`). Metal proof: the kernel boots normally under stage-2 (EL1 memory intact) and an EL1 read of `0x200000` is trapped to EL2 (`X`) then recovered. The AK is already scrubbed (B-1), so no key material persists there anyway. | Residual: uses 2 MiB hole granularity (over-blocks `0..0x200000` and `0x280000..0x800000`, both unused by EL1). Stage-2 is CM5/HBoot only (QEMU boots the kernel standalone). |
| B-4 | **HIGH** | **GEM descriptor cache-line false sharing** — 4×16 B descriptors share a 64 B line; `dc_cvac` on recycle writes back a stale cached neighbor over the device's fresh `USED`/length → silent RX loss **at line rate** (not hit by the sequential-poll demo). | Place the descriptor ring in **Non-cacheable** memory (standard for DMA rings) and drop the per-descriptor clean/invalidate. Requires page-granular mapping of the ring page → the block-splitting epic. |
| B-5 | ~~MEDIUM~~ **FIXED (P7b, 2026-07-21)** | No W^X at EL1 — all RAM was RWX. | **DONE on QEMU + CM5 metal:** the coarse blocks are split (mmu/mmu_cm5), kernel `.text` is RO+X, all other RAM RW+PXN, and `SCTLR.WXN` is set. Verified: `.text` AP=0b10 PXN=0, data AP=0b0 PXN=1; datapath unaffected. |
| B-6 | ~~MEDIUM~~ **FIXED (P7c, 2026-07-21)** | EL0 ran with IRQs masked (SPSR 0x80) — an uncooperative EL0 task could wedge the CPU. | **DONE (QEMU):** EL0 tasks are now preemptible scheduler TCBs — `make_el0_thread` enters EL0 with IRQs on; the lower-EL IRQ vector reschedules; trap frame carries SP_EL0. Verified: an infinite-loop EL0 task is preempted (300 ticks, box not wedged). CM5-metal side of the shared change is dormant (no EL0 tasks on CM5 yet). |
| B-7 | MEDIUM | Measured-boot has **no hardware root of trust** (PCRs in plain DRAM, HBoot self-measures unanchored). | OTP CRTM anchor — same hardware dependency as B-1. |
| B-8 | **MEDIUM → PARTIAL (P7d-c, 2026-07-21, read/gate validated on CM5 metal)** | The floor is now backed by a **hardware monotonic store**: `OtpCounter` reads a popcount-thermometer from BCM2712 OTP block 3 (fuses one-way → monotonic), and the boot gate enforces `svn ≥ max(compile, hardware)`. Metal: `floor=1 (BCM2712 OTP block3 (hardware monotonic thermometer))`. Block 3 is blank so the effective floor still equals the compile floor — the hardware floor only rises once **`advance_floor` is deliberately invoked** (an explicit operator action, never on the boot path; IRREVERSIBLE, built but gated). | **Residual:** actually *advancing* the floor consumes fuse bits irreversibly — a deliberate per-release operator decision. Also uses block 3 (the RPi device-key region), since block 1 now holds the B-1 AK secret. RPMB is the alternative if 512 bits is outgrown. |
| B-9 | LOW | JIT/user code-page W^X bypassable via the RW identity alias (QEMU path); `SYS_CAP_IDENTIFY` uses a global CSpace + `rights` unenforced; OOM/`unwrap` are kernel-fatal; recursive `revoke` stack depth; 64 GiB oversized no-IOMMU DMA window. | Assorted; several ride the block-splitting epic or the multi-EL0-task milestone. |

**Read of the whole system:** the enforcement spine (secure-boot AND-gate + geometry pin, memory-safe datapath, EL0 isolation, cap unforgeability) is sound. The concentrated residual risk is (a) attestation is **demo-grade** until the AK is hardware-bound (B-1/B-2), (b) three real hardening items ride the **block-splitting epic** (B-4/B-5, plus the earlier W^X residual), and (c) EL1↔EL2 isolation (B-3). These are the top of the next hardening milestone, in that order.

*Method: 4 parallel adversarial subagents over the full tree; findings ranked by exploitability; the tractable, QEMU-validatable fixes landed and re-gated (P0–P6b + DRV green); the rest triaged with an explicit fix path rather than silently deferred.*
