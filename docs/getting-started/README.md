# Getting started

## For everyone: flash, plug in, sign in

You don't need Linux or any commands. You need:
- a Raspberry Pi **Compute Module 5** with eMMC on a carrier board (tested: Waveshare CM5-DUAL-ETH-MINI)
- a USB-C cable
- any Windows, macOS or Linux computer

1. **Get the image** and its `.owner-key` file (your device's sign-in key; keep it safe, it's the only copy).
   The first public signed image is coming soon on [Releases](https://github.com/hookprobe/hookprobe/releases).
2. **Flash it** with Raspberry Pi's free tools:
   - Set the carrier's **nRPIBOOT / "disable eMMC boot"** switch and connect the board over USB.
   - Run **rpiboot** ([raspberrypi/usbboot](https://github.com/raspberrypi/usbboot), a current release; older ones can't flash a CM5). The eMMC appears as a drive.
   - In **[Raspberry Pi Imager](https://www.raspberrypi.com/software/)**: *Choose OS* → *Use custom* → the HookProbe OS image → that drive → *Write*. Skip OS customization.
3. **Plug it in.** Turn the nRPIBOOT switch off, connect the Ethernet port **furthest from USB-C** to your router, and power the board.
4. **Open Mission Control.** Find the device in your router's list of connected devices, browse to `http://<its address>/`, and sign in with the key from the `.owner-key` file.

**Coming next:** flashing from the browser (WebUSB), with nothing to install. See [`tools/flash/`](../../tools/flash/).
**Enrolling with a control plane** is optional: see [`onboarding/enrollment/`](../../onboarding/enrollment/).

---

## For developers: build and test

### Toolchain

heqk pins its own nightly toolchain and targets ([`os/kernel/rust-toolchain.toml`](../../os/kernel/rust-toolchain.toml));
rustup installs them on first use. You also need `qemu-system-aarch64`. For the UI and browser tests you need
Node, plus Playwright Chromium under `os/kernel/tools/mc-e2e/`. Full setup: [`HACKING.md`](../../os/kernel/HACKING.md).

### Validate in QEMU (no hardware)

```sh
os/kernel/validate.sh          # boots every phase gate under QEMU and prints the lifecycle report
os/kernel/tools/mc-e2e.sh      # end to end: attack → heqk IPS → evidence → Mission Control in a real browser
```

### Build a signed CM5 factory image

```sh
os/build/gen-heqk-dev-keys.sh                              # bench keys, once
HEQK_KEYDIR=os/build/.heqk-dev-keys FEATURES=prod-mc \
  os/build/make-cm5-heqk-disk.sh --zero-linux --owner-token auto
# → os/build/generated/cm5-heqk/<image>.img  +  .owner-key, .sha256, .json
```

Flash it as above, or with the guarded developer script `os/kernel/cm5-boot/flash-image.sh`
(see [`tools/flash/`](../../tools/flash/) and the [bench runbook](../design/bench-runbook-prod-mc-2026-11.md)).
