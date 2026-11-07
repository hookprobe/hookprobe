# appliance/ — hardware profiles

One folder per supported board or carrier. Code never asks "is this a Pi?". It asks whether a
capability is granted, so a new piece of hardware should need only a profile here.

| Profile | Status |
|---|---|
| [`cm5/`](cm5/) | Raspberry Pi Compute Module 5 (BCM2712). **Primary target, metal-proven.** |
| [`waveshare-dual-eth/`](waveshare-dual-eth/) | Waveshare CM5-DUAL-ETH-MINI carrier: the bench board (GEM `end0` + RTL8111H `eth1`) |
| QEMU `virt` (cortex-a72) | The virtual target. Used by `os/kernel/validate.sh` and `os/kernel/tools/mc-e2e.sh`. |
| RK3588 · N100 · cloud | Planned on heqk (ADR 0047). The old Linux-tier profiles are in [`legacy/linux-tier/platforms/`](../legacy/linux-tier/platforms/). |
