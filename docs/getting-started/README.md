# Getting started

## 1. Toolchain

heqk pins its own nightly toolchain ([`os/kernel/rust-toolchain.toml`](../../os/kernel/rust-toolchain.toml)).
You also need `qemu-system-aarch64`. For the UI and browser tests you need Node, plus Playwright
Chromium under `os/kernel/tools/mc-e2e/`. Full setup: [`HACKING.md`](../../os/kernel/HACKING.md).

## 2. Validate in QEMU (no hardware)

```sh
os/kernel/validate.sh          # boots every phase gate under QEMU and prints the lifecycle report
os/kernel/tools/mc-e2e.sh      # end to end: attack → heqk IPS → evidence → Mission Control in a real browser
```

## 3. Build a signed CM5 image

```sh
os/build/gen-heqk-dev-keys.sh                              # bench keys, once
HEQK_KEYDIR=os/build/.heqk-dev-keys FEATURES=prod-mc \
  os/build/make-cm5-heqk-disk.sh --zero-linux --owner-token auto
```

## 4. Flash and accept on metal

See [`tools/flash/`](../../tools/flash/) and the
[bench runbook](../design/bench-runbook-prod-mc-2026-11.md). Flashing erases the whole eMMC.

## 5. Optional: enroll with a control plane

See [`onboarding/enrollment/`](../../onboarding/enrollment/).
