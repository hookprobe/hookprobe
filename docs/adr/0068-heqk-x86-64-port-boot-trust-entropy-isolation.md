# ADR 0068: heqk on x86_64 — boot chain, trust root, entropy and isolation

**Status:** 🟡 Proposed (2026-11-22). Needs operator review; nothing in X1 merges before this ADR is accepted.

**Scope:** a new `os/kernel/arch-x86_64` crate, os/kernel (HAL decoupling), the UEFI loader (`os/kernel/efiboot`),
os/build (x86 images), and the G19 super-PoP host plan.

**Builds on:**
- ADR 0047 D1, which ratified heqk on every platform, "N100/x86_64 and cloud" included. This ADR decides how,
  not whether.
- ADR 0062 (multi-tenant microarchitectural isolation): x86 rows still to be verified.
- ADR 0050 D4 / operator decision 2026-11-11: the identity key and Noise stay in EL1 (ring 0 here).

## Context

**The operator wants heqk on x86_64 because Arm hosting is hard to find** (G19 super-PoP, 2026-11-22). Measured on
`main` 4ae76988 by the G19 PoP session:
- there is no x86 arch crate;
- `kernel/src` makes 827 direct `arch_aarch64::` references and has 83 `asm!` sites across 24 files;
- portable network logic (nat, ip6, ip6lan, pppoe, dhcpd, uplink, wanparse, mgmtproto, apparse, reject,
  virtio_*) lives inside `arch-aarch64`.

**The CM5's trust and isolation chain does not exist on x86:**
- hboot at EL2 with a stage-2 carve-out (SEC-2);
- an SRK derived from OTP;
- the BCM2712 TRNG.

Each needs an explicit x86 decision, or the port silently weakens the guarantees.

## Decision

### D1. Sequencing: X0 → X1 → X2 → X3

| Step | What | Owner | Gate |
|---|---|---|---|
| **X0** | Move the portable network logic into a no_std crate. kernel → arch calls go through `hal` traits only. Pure moves plus trait plumbing, one module family per PR, no behaviour change | HomePods | validate.sh + mc-e2e green, the AP payload under the HBoot window, the CM5 bench WPA3 / NAT / loop-gap checks unchanged. **Starts after the REL-05 soak candidate is frozen**; never inside the candidate |
| **X1** | `arch-x86_64` minimum for QEMU q35 + KVM: UEFI entry (efiboot), long-mode 4-level paging, IDT + LAPIC timer (x2APIC where present), ring 3 as the EL0 equivalent with SMEP/SMAP on, serial console, virtio-pci net/blk (reusing `pci.rs` / `virtio_transport.rs`), BPF **interpreter** (no x86 JIT) | G19 PoP session (crate) + HomePods (kernel wiring after X0) | `[ALL] GREEN` from validate.sh under `qemu-system-x86_64 -M q35 -enable-kvm` |
| **X2** | G19 client, then the heqk-native PoP on x86 KVM (on-host QEMU, then a real x86 cloud VM) | HomePods | `[P-g19]` over a real internet path |
| **X3** | N100 metal: igc, NVMe, TPM 2.0 | HomePods | its own metal gate (ADR 0047: no "zero-Linux" claim before it) |

### D2. Boot chain: UEFI → `efiboot` → heqk, with no hypervisor layer of our own

On x86 there is no hboot/EL2 equivalent in the first port:
- the kernel runs in ring 0 with paging, SMEP, SMAP and NX;
- EL0 servers run in ring 3.

The SEC-2 carve-out has no x86 counterpart and is **not claimed**:
- on a cloud VM, the cloud hypervisor is in the TCB, and that is stated in the device's capabilities;
- a later VMX-root shim, the x86 analogue of hboot, is out of scope for this ADR.

### D3. Trust root

| Platform | Root | Device identity / SRK |
|---|---|---|
| N100 metal | UEFI Secure Boot with our own keys enrolled, plus TPM 2.0 measured boot (PCR 0/2/4/7 + a heqk PCR) | SRK = a TPM-sealed secret, bound to the PCR policy (replaces the CM5 OTP-derived SRK). `rpmb`-style anti-rollback through a TPM NV counter |
| Cloud VM with vTPM (shielded instance) | same as metal, against the vTPM | vTPM-sealed |
| Cloud VM without vTPM (e.g. OCI A1) | **none** beyond the image signature checked by efiboot | a key bound to the cloud's instance-identity attestation, or provisioned per instance. **Weaker, and labelled as such**: never "hardware-rooted" |

- The image signature (hybrid Ed25519 + SLH-DSA) and the SVN rules are unchanged; `efiboot` verifies them before it
  jumps to the kernel.
- Key custody (who holds pop.key, the release keys) stays as decided elsewhere (ADR 0050 step 4).

### D4. Entropy

- **x86:** RDSEED, with RDRAND as a fallback, behind the existing `HwTrng` contract: a startup health check,
  continuous tests, and **fail-closed**. No timer jitter, never zeros. On KVM this makes S1 / X2 possible without a
  virtio-rng device.
- **aarch64 QEMU / cloud without SMCCC TRNG:** a virtio-rng source is a separate decision, recorded under G19. It is
  never in a CM5 image.

### D5. Isolation claims

- Single-tenant first.
- Multi-tenant on x86 stays **blocked by ADR 0062** until its x86 rows are verified: Spectre v1/v2/BHI, MDS/TAA,
  L1TF, Retbleed/SRSO, IBRS/eIBRS/STIBP and RSB stuffing on ring transitions, SMT policy, and cache-partitioning
  limits.
- On a shared cloud host, cross-VM side channels are outside heqk's control and are stated as such.

### D6. What stays architecture-independent

The capability model, the supervisor and autoheal, the EL0 server ABI (`hal::*abi`), the signed artifact formats,
evidence, Mission Control, and the Neuro ABI. The x86 arch crate implements traits; it does not fork logic.

## Consequences

- X0 is a large, mechanical refactor of the AP datapath's hottest code. It is done in slices, after the soak
  candidate freeze, and proven on the CM5 bench before each next slice.
- An x86 cloud PoP without a vTPM has a software-only identity. The PoP's enrollment and Mission Control must show
  that, and not imply hardware rooting.
- Until X3, x86 is a cloud / QEMU target only. No product claim on x86 metal.

## Open questions for the operator

1. Which x86 cloud first (a shielded instance with vTPM preferred), and does the PoP accept a software-only identity
   on a no-vTPM host for the MVP?
2. N100 Secure Boot: enroll our own PK/KEK (owner-controlled), or ship with the vendor keys plus a shim (not
   recommended)?
3. Is a VMX-root shim (the x86 hboot) ever wanted on metal, or is ring-0 heqk plus the TPM enough for the product?
