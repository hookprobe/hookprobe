# appliance/cm5 — Raspberry Pi Compute Module 5

| What | Where |
|---|---|
| Boot config: `config.txt` (`kernel=heqk8.img`), no-devicetree variant, A/B `tryboot.txt` | [`os/kernel/cm5-boot/`](../../os/kernel/cm5-boot/) |
| CM5 notes, serial console, rpiboot | [`README-CM5.md`](../../os/kernel/cm5-boot/README-CM5.md) |
| Build plan from QEMU to metal | [`BUILD_FLASH_PLAN.md`](../../os/kernel/BUILD_FLASH_PLAN.md) |
| CM5 MMU / boot entry | `os/kernel/arch-aarch64/src/mmu_cm5.rs`, `boot_cm5.s` |
| Build a signed image | [`os/build/`](../../os/build/) |
| Flash | [`tools/flash/`](../../tools/flash/) |
| Bench acceptance runbook | [`bench-runbook-prod-mc-2026-11.md`](../../docs/design/bench-runbook-prod-mc-2026-11.md) |

The boot files stay next to the kernel because the build and flash scripts find them by relative
path. This page is the hardware view of them.
