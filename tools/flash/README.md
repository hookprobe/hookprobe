# tools/flash — writing an image to a CM5

**Users:** no scripts needed. Flash with Raspberry Pi's own tools (rpiboot, then Raspberry Pi Imager →
*Use custom*), as described in [Getting started](../../docs/getting-started/).

**Developers** can use the guarded scripts below instead.

The flash scripts live with the CM5 boot files in
[`os/kernel/cm5-boot/`](../../os/kernel/cm5-boot/) because they locate those files and the
bundled `usbboot` (`os/kernel/tools/usbboot/`) by relative path.

| Script | Use |
|---|---|
| `flash-image.sh <img> --backup <file>` | **Recommended.** Guarded whole-eMMC write of a factory image, with read-back verification |
| `flash-now.sh` | Copy only the boot set (`config.txt`, `heqk8.img`, `tryboot.txt`) onto the boot partition |
| `flash-clean.sh` | Archive the existing Linux partitions, then install heqk |
| `ab-update.sh` | Stage slot B and set up a tryboot |

All of them erase or modify the device, so the operator runs them (`sudo`). Serial console:
see [`tools/diagnostics/`](../diagnostics/).
## Browser flasher (WebUSB) — in progress, not usable yet

Design: [ADR 0070](../../docs/adr/0070-webusb-flasher-heqk-flash-stub.md) (proposed; operator decision 2026-11-24:
a heqk flash stub, no Linux). It replaces the write path of the retired ADR 0037.

**What exists** (`web/`, browser side only, tested offline, **not metal-verified**):

| File | What |
|---|---|
| `web/src/rpiboot.mjs` | rpiboot for BCM2712 (`0a5c:2712`): boot message + `bootcode5.bin`, the file server (GetFileSize / ReadFile / Done, metadata), stage detection |
| `web/src/reenum.mjs` | finding the device again after each reset: `getDevices()`, `connect`, and a Reconnect click when Chrome needs a new permission |
| `web/src/bootfiles.mjs` | reads Raspberry Pi's `bootfiles.bin` (ustar) and lays `config.txt` / `boot.img` over it |
| `web/src/stubproto.mjs` | host side of HQFL, the stub's vendor protocol: HELLO, VERIFY, WRITE with per-chunk ack and resume, FINISH read-back |
| `web/src/flasher.mjs` | the three steps end to end |
| `web/index.html`, `web/app.mjs` | a plain development page (modes: rpiboot only, verify only, full write) |
| `web/test/` | `node --test` with mock devices: boot ROM, file server, re-enumeration, stub, faults |

Run the tests: `node --test tools/flash/web/test/*.test.mjs` (CI gate g1). Serve the page on localhost
(`python3 -m http.server -d tools/flash/web 8000`), Chrome or Edge.

**The stub** (`os/kernel/flashstub/`, ADR 0070 D3–D6, host-tested, **not metal-verified**): the BCM2712 DWC2
OTG core in device mode (polled, FIFO mode), the HQFL v1 server (verify with `boot_abi::verify` + SVN floor +
HBoot prefix before any write; MBR written last; full read-back; both slot files re-verified through FAT), and
the stub image, an HBoot payload built with `cargo build --release --features flashstub`. Host tests:
`cd os/kernel/flashstub && cargo +stable test --release --target x86_64-unknown-linux-gnu` (CI gate g1).

**What is missing** before a CM5 can be flashed from the page:

1. The stub on metal: packing it into `boot.img` (HBoot + the signed stub payload) and the metal test plan
   M1–M6 in ADR 0070. Step M1 (rpiboot only) can run before the stub is packed.
2. A USB ID for the stub (Q2; both sides use a pid.codes test ID as a placeholder).
