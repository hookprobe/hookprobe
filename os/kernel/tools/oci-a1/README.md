# heqk on the arm64 cloud — OCI Ampere A1 target

ADR 0047 port item 10 ("VM/cloud: virtio-pci, UEFI boot … arm64 cloud is closest";
the heqk-everywhere report dated 2026-10-09, in the REPO-ROOT design docs folder — not
`os/kernel`'s local canon, which validate.sh checks). First cloud: Oracle OCI `VM.Standard.A1.Flex`
(the instance that runs hookprobe.com today).

## Why there is no `/dev/kvm` on the A1 — and why heqk doesn't need it

The A1 is a Neoverse-N1 (ARMv8.2). Nested virtualization on Arm needs FEAT_NV (v8.3/v8.4), so
the hypervisor cannot give the guest EL2 and the guest can never offer `/dev/kvm`. No OCI
setting changes that; only bare-metal shapes expose EL2. heqk does **not** need KVM: it boots
**as the guest kernel** at EL1, replacing Ubuntu in the VM.

## Device model (measured on the real instance, 2026-11-09)

| | OCI A1 guest |
|---|---|
| CPU / EL | Neoverse-N1 (MIDR part 0xd0c), **EL1** only |
| Firmware | UEFI 2.7 (edk2) + **ACPI only**: FACP APIC PPTT GTDT MCFG SPCR DBG2 IORT BGRT (+DSDT), no DTB |
| IRQ | **GICv3** (+ITS), virtual timer PPI 27 |
| Console | **PL011** (SPCR), ttyAMA0 |
| PCI | QEMU gpex host bridge 1b36:0008, ECAM via MCFG, PCIe root ports |
| NIC | **virtio-net 1af4:1041**, modern-only virtio 1.0, MSI-X |
| Boot volume | **virtio-scsi 1af4:1048** behind a root port (not virtio-blk) |
| Other | virtio-gpu 1af4:1050, qemu-xhci |

`run-oci-a1.sh` reproduces this in QEMU (`virt,gic-version=3,virtualization=off,acpi=on`,
`-cpu neoverse-n1`, AAVMF, modern-only virtio-pci). The efiboot probe checks it: **18/18 match.**

## Files

| | |
|---|---|
| `run-oci-a1.sh <disk.img>` | boot a disk on the OCI A1 QEMU model |
| `mkdisk.sh <out> <BOOTAA64.EFI>` | GPT + FAT32 ESP disk; `MKDISK_QCOW2=1` also writes the OCI-importable `.qcow2` |
| `boot-heqk.sh [outdir]` | build heqk `--features cloud` → embed in efiboot → disk → boot. `PROBE_ONLY=1` = probe disk only, `BOOT=0` = build only |
| `oneshot-probe.sh <user@host>` | live test WITHOUT an image import: on a **throwaway** Oracle Linux/Ubuntu A1, put the probe on the ESP, arm a one-shot GRUB chainload, reboot. The probe prints `[OCI-A1-model]` on the serial console and powers off; starting the instance again returns the normal OS. Refuses the production host (by name and by its running containers) |
| `../../efiboot/` | the UEFI entry: read-only hardware probe (`[OCI-A1-model] PASS/FAIL`), plus with `HEQK_IMAGE=` a bounds-checked ELF loader → ExitBootServices → MMU off → heqk at EL1 |

## Port status (QEMU OCI model)

| Step | State |
|---|---|
| 0. QEMU target matching the real A1 | ✅ probe 18/18 |
| 1. UEFI boot (efiboot loader) | ✅ heqk unmodified boots P0–P3 (EL1, MMU, W^X, caps, EL0) |
| 2. GICv3 (`kernel --features cloud`) | ✅ timer IRQs live. Review fixes (2026-11-09, verified on the real A1 by the hookprobe-com agent): 24-bit INTID ack (LPIs ≥ 8192), per-SPI trigger (level for PL011/INTx; edge kept for the CM5-parity `enable_spi`), correct GICD_IROUTER Aff3[39:32], GICv4 VLPIS stride, loud (not silent) RWP/redistributor failures |
| 3. virtio **PCI** transport | ✅ `virtio_transport` (mmio + pci-modern) under both virtio-net drivers; `pci.rs` ECAM; `Mmu::map_mmio` (ECAM 0x40_1000_0000 identity, 64-bit BARs at 0x80_0000_0000+ via translated high L1 slots); enables MEM+bus-master (firmware leaves the NIC off). `[P5b]` PASS over virtio-pci, `[DRV]` grants the NIC's PCI config page to the EL0 driver. **Full default sequence `[ALL] … GREEN` on the OCI model.** |
| 4. ACPI hand-off (efiboot passes RSDP; GIC/UART/ECAM from MADT/SPCR/MCFG, not constants) | ❌ not blocking on OCI A1 — the real A1's ACPI was checked and every constant matches; needed for other clouds |
| 5. virtio-scsi (boot/data volume) | ❌ |
| 5b. PSCI power + SMCCC TRNG (`smccc.rs`, in `cloud`) | ✅ on the model. Exits/faults use PSCI SYSTEM_OFF/RESET instead of semihosting (`hlt #0xf000` is undefined on a real VM → the first exit/fault would have re-faulted). `HwTrng` cloud leaf = hypervisor SMCCC TRNG (TRNG_RND64), strict/fail-closed; non-PSCI ids only after `PSCI_FEATURES(SMCCC_VERSION)` says SMCCC ≥ 1.1 (an HVC with a non-PSCI id is UNDEFINED without EL2). Model: `PSCI 1.1, TRNG ABSENT → fails closed`. Real A1 (Linux `smccc_trng` live, per the hookprobe-com agent) should show `TRNG v1.x two-sample OK` — **unverified until the live test** |
| 6. Cloud identity root | ❌ — the A1 has **no vTPM** and Secure Boot is off (measured by the hookprobe-com agent). Options: OCI Shielded instance if offered for A1, or a key bound to OCI instance-identity attestation |

Measured A1 CPU features (hookprobe-com agent): AES, SHA-1/SHA-2, CRC32, LSE atomics; **no** SHA-3/SHA-512, pointer-auth or RNDR — crypto must not assume those.

## Live test on real OCI

**Never on the production instance.** It serves hookprobe.com / MSSP. Use a separate instance:
import `disk.qcow2` as a custom image (UEFI firmware, paravirtualized launch mode), launch a
small A1.Flex from it, and watch the **serial console connection**. Start with the probe-only
image (`PROBE_ONLY=1 BOOT=0 MKDISK_QCOW2=1 boot-heqk.sh`): if it prints `[OCI-A1-model] PASS`,
the QEMU model matches the real A1 and every later step can be developed locally. The tenancy's
free A1 allowance (4 OCPU / 24 GB) is fully used by production, so the test instance needs
credits or a resize.
