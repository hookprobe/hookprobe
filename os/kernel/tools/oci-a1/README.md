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
| `../../efiboot/` | the UEFI entry: read-only hardware probe (`[OCI-A1-model] PASS/FAIL`), plus with `HEQK_IMAGE=` a bounds-checked ELF loader → ExitBootServices → MMU off → heqk at EL1 |

## Port status (QEMU OCI model)

| Step | State |
|---|---|
| 0. QEMU target matching the real A1 | ✅ probe 18/18 |
| 1. UEFI boot (efiboot loader) | ✅ heqk unmodified boots P0–P3 (EL1, MMU, W^X, caps, EL0) |
| 2. GICv3 (`kernel --features cloud`) | ✅ timer IRQs live; runs on to P5 (rules, scan, DNS sink, packet engine) |
| 3. virtio **PCI** transport (ECAM from MCFG; high ECAM needs an MMU window) | ❌ next — `[P5b] wire: FAIL` (heqk only knows virtio-mmio) |
| 4. ACPI hand-off (efiboot passes RSDP; GIC/UART/ECAM from MADT/SPCR/MCFG, not constants) | ❌ |
| 5. virtio-scsi (boot/data volume) | ❌ |
| 6. Cloud identity root (no OTP; vTPM availability on A1 unverified) + PSCI reset/off | ❌ |

## Live test on real OCI

**Never on the production instance.** It serves hookprobe.com / MSSP. Use a separate instance:
import `disk.qcow2` as a custom image (UEFI firmware, paravirtualized launch mode), launch a
small A1.Flex from it, and watch the **serial console connection**. Start with the probe-only
image (`PROBE_ONLY=1 BOOT=0 MKDISK_QCOW2=1 boot-heqk.sh`): if it prints `[OCI-A1-model] PASS`,
the QEMU model matches the real A1 and every later step can be developed locally. The tenancy's
free A1 allowance (4 OCPU / 24 GB) is fully used by production, so the test instance needs
credits or a resize.
