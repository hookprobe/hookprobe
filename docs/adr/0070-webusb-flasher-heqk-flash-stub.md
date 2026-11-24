<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# ADR 0070 — Browser flasher: WebUSB rpiboot and a heqk flash stub that verifies, then writes the eMMC

**Status:** proposed. Operator decision 2026-11-24: option (a), a heqk-native flash stub (no Linux).
The rest of this record (protocol, security contract, metal plan) is awaiting review. It replaces the write path
of the retired [ADR 0037](0037-zero-touch-onboarding-flasher-provisioning.md) (Decision 1, "CM5/CM4 are
browser-flashable via WebUSB + rpiboot (eMMC as USB mass storage)"); the rest of 0037 stays retired.

**Built so far (2026-11-24):** the browser side: `tools/flash/web/` holds the rpiboot protocol, the
re-enumeration handling, the host side of the HQFL protocol and a development page, tested offline against mock
devices (`node --test`, CI g1). The first stub implementation: `os/kernel/flashstub/` (a detached crate) holds the
DWC2 device-mode driver, the HQFL server and the stub image (`--features flashstub`), tested on the host against
a register-level DWC2 model and the real verifier (`cargo test`, CI g1). **Nothing here has run on a CM5.**

**Relates to:** [0047](0047-heqk-everywhere-on-device-mission-control.md) (no Linux on the device), [0056](0056-device-upload-interface.md)
(the OTA upload path whose checks the stub repeats), [0067](0067-heqk-efficiency-programme-and-ip-hygiene.md)
D11 (driver provenance, no GPL-2 transcription), `os/build/heqk-boot-key-check.sh` (the dev-key release gate).

## Context

A CM5 boots from its eMMC. To write that eMMC from another computer, the board is held in USB boot mode
(nRPIBOOT asserted at power-on). Its BCM2712 boot ROM then enumerates as USB device `0a5c:2712` and waits for a
host to send a second stage. Today the host is Raspberry Pi's `rpiboot` (vendored in
`os/kernel/tools/usbboot/`). It loads `mass-storage-gadget64/boot.img`: a Linux kernel and initramfs that expose
the eMMC as a USB mass-storage device. The operator then writes it with `dd`
(`os/kernel/cm5-boot/flash-image.sh`) or Raspberry Pi Imager.

ADR 0037 wanted the same from a web page with nothing installed. Doing that with the mass-storage gadget fails
for three reasons:

1. **Chrome does not let a page claim a mass-storage interface.** WebUSB refuses `claimInterface` on protected
   interface classes, and mass storage (class 0x08) is one of them. The page could run rpiboot, but it could not
   write a single byte to the gadget. File System Access cannot open a raw block device either.
2. **ADR 0047.** The gadget is a Linux kernel with a root shell on the UART (empty password, per its README). A
   HookProbe flasher would boot Linux on every device it flashes.
3. **Licensing.** Serving a GPL-2 kernel binary from a public page carries source-offer duties for that binary,
   separate from our own code.

## Decision

### D1 — The flow

```
browser (WebUSB)                         CM5
  requestDevice 0a5c:2712  ───────────►  boot ROM (iSerialNumber index 0/3)
  boot message + bootcode5.bin ───────►  second stage starts, USB resets
  (re-enumeration: getDevices / connect / Reconnect click)
  file server: GetFileSize/ReadFile ◄──  second stage asks for bootmain, memsys*, config.txt, boot.img ...
  Done                               ◄──  firmware boots boot.img = HBoot + the heqk flash stub
  (re-enumeration: new VID/PID, Reconnect click)
  HQFL over the stub's vendor interface:
    HELLO → VERIFY (signed slot image) → WRITE (whole disk image) → FINISH (read-back)
```

- **Stage 1 (boot ROM).** A vendor control OUT carries the length in wValue/wIndex, then the bytes follow on bulk
  OUT in ≤ 16 KiB transfers, with no zero-length packet. The boot message is 24 bytes {LE32 length, 20-byte
  signature, zero when unsigned}, followed by `bootcode5.bin`. The host then reads a LE32 return code with a
  vendor control IN (0 = accepted).
- **Stage 2 (file server).** The host reads a 260-byte message {LE32 command, 256-byte name}.
  - GetFileSize: the host answers with the size in a control transfer alone.
  - ReadFile: the host sends the file.
  - An unknown file gets an empty write.
  - `*name` is board metadata: the host acknowledges it with an empty write.
  - Done, or an empty name, ends the server.

  The files come from Raspberry Pi's `bootfiles.bin` (`2712/` entries), with our `config.txt` (`boot_ramdisk=1`)
  and `boot.img` laid on top.
- **Re-enumeration.** The stale `USBDevice` is never reused. The page waits on `navigator.usb.getDevices()`, the
  `connect` event and polling. Chrome keeps a permission across a reset only for a device with a serial number,
  and the stub has a new VID/PID. So the page falls back to a **Reconnect** button: `requestDevice` needs a user
  gesture.
- **The stub** is delivered the way the mass-storage gadget is: a FAT ramdisk `boot.img` holding `config.txt`
  and the stub image (HBoot + a `flashstub` heqk payload). Whether the 2712 firmware also fetches a bare `kernel=`
  file over the file server is to be seen on metal (step M1). The JS file server works either way.

### D2 — Why not mass storage

See Context 1–3. In short, mass storage is the one USB class a page can never write through, and it would mean
booting Linux on the device. A vendor-class interface (0xff) is claimable from WebUSB on every desktop OS.
Windows needs the WinUSB driver bound, and the stub will provide that through MS OS 2.0 descriptors (Q4).

### D3 — The stub's security contract

The stub is a separate heqk build (cargo feature `flashstub`). It does one thing: verify an image, then write it.
**It verifies before it writes, refuses everything else, and has no code path to OTP or RPMB.**

1. **Same verifier as OTA and boot.** VERIFY receives the signed A/B slot file (`heqk8-a.img`, at most 5 MiB).
   The stub runs exactly the OTA pre-flight checks of `kernel/src/otaimg.rs`:
   - the length and header bound;
   - `boot_abi::verify::verify_digest`, meaning both Ed25519 and SLH-DSA-SHA2-128s signatures over the
     SVN-bound digest;
   - an SVN at or above the stub's compiled-in floor.

   It uses the same trust root (`TRUSTED_*_PUBKEY` in `boot-abi/src/verify.rs`). There is no second verifier
   and no second key set. The verifier's comment currently says it has "two call sites, only two"; the stub
   becomes the third, and that comment and the security review must record it.
2. **The HBoot prefix must match.** Like OTA rule 4, the HBoot bytes in front of the signed payload are not
   covered by the payload signature. The stub refuses a slot whose HBoot prefix is not byte-identical to the
   HBoot it was itself booted with. So a release stub writes only a release HBoot.
3. **The dev-key release gate applies.** The stub is built through `heqk-boot-key-check.sh`. A release stub
   carries the release trust root, so an image signed with development keys never verifies on it. A debug stub
   reports `release=0` in INFO, and the page refuses to use it unless "Accept a DEBUG stub" is ticked (bench only).
4. **No write before a positive verdict.** WBEGIN and WRITE before an OK verdict are answered NOT_VERIFIED, and
   nothing reaches the eMMC. A refusal is final for that session.
5. **Write, then prove it.** FINISH carries the SHA-256 of everything the host sent. The stub compares three
   hashes:
   - the host's;
   - its own running hash of what it received;
   - a full read-back of the written range from the eMMC.

   It then finds `HEQK8-A.IMG` and `HEQK8-B.IMG` through FAT on the written medium itself, the same `fat.rs` and
   `hal::abslot` code OTA uses (it never trusts the manifest offset). Each slot must hold the verified payload,
   or a payload that also verifies. On any mismatch, or on ABORT or USB disconnect after a write, the stub
   zeroes LBA 0 (the MBR), so the board never boots a half-written or substituted image.
6. **No OTP, no RPMB, no boot partitions.**
   - The stub makes no OTP mailbox calls, not even reads. HBoot still enforces the OTP floor at every boot.
   - It has no RPMB access.
   - Its eMMC driver keeps the property it has today: no CMD6 (SWITCH), CMD38 (ERASE), CMD42 (LOCK), and no
     partition switch. It writes the user area only.

   A full write does overwrite the reserved keystore window (LBA 2016..2047) with the image's zeros. Like
   `flash-image.sh` today, a reflash gives the device a new identity.
7. **Not signed today, honestly.** The disk image as a whole is not signed. `config.txt` and `OWNER.TXT` are
   patched per device. The signed config files (`*.SIG`) and the Wi-Fi firmware hashes are checked by the kernel
   at boot, not by the stub.

   Until secure boot is enabled (release items TC-0x), the boot ROM runs any `boot.img` a host sends. So the stub
   protects an honest page from a corrupt or substituted download, not a device from a malicious host. The
   authoritative check is still HBoot's verify at every boot.

### D4 — The HQFL vendor protocol (v1)

Interface class 0xff, subclass 0x48 ('H'), protocol 0x01, with one bulk OUT and one bulk IN endpoint (512 B
max packet, high speed). **One message is one bulk transfer, one request gets one response.**

A frame is a 16-byte little-endian header, then the payload:
- magic `HQFL`;
- version u8 = 1;
- type u8;
- status u8 (in responses);
- reserved u8;
- seq u32 (echoed in the response);
- payload length u32.

**No frame length is ever a multiple of 512.** The encoder enforces this, so every transfer ends in a short
packet and neither side needs a zero-length packet. Maximum frame: 16 + 16 + 64 KiB.

| Request | Payload | Response |
|---|---|---|
| 0x01 HELLO | u32 host version | 0x81 INFO (64 B): u32 version, u32 max chunk, u64 eMMC sectors, u64 SVN floor, u8 release, u8 cache on, u8 wear A/B, 32 B stub build hash |
| 0x02 VBEGIN | u32 slot image length (≤ 5 MiB) | 0x82 ACK u64 next |
| 0x03 VDATA | u32 offset, u32 0, data (≤ 64 KiB) | ACK u64 next |
| 0x04 VEND | — | 0x84 VERDICT: u64 svn, 32 B payload hash; status ≠ 0 = refused |
| 0x05 WBEGIN | u64 disk length (multiple of 512, ≤ eMMC) | ACK u64 0 (NOT_VERIFIED without a verdict) |
| 0x06 WRITE | u64 offset, u32 CRC-32 of data, u32 0, data (n × 512 B, ≤ 64 KiB) | ACK u64 next = offset + n (the write-chunk ack) |
| 0x07 FINISH | 32 B SHA-256 of all data sent | 0x87 RESULT: 32 B read-back SHA-256, u8 slot flags (bit 0 A, bit 1 B) |
| 0x08 ABORT | — | ACK (clears LBA 0 if anything was written) |
| any | — | 0xEE ERROR: u64 next |

Status codes:

| Code | Name | Code | Name | Code | Name |
|---|---|---|---|---|---|
| 0 | OK | 5 | BAD_HEADER | 10 | IO |
| 1 | BAD_FRAME | 6 | SIG_FAIL | 11 | RANGE |
| 2 | BAD_VERSION | 7 | ROLLBACK | 12 | READBACK_MISMATCH |
| 3 | BAD_STATE | 8 | BAD_OFFSET | 13 | SLOT_MISMATCH |
| 4 | TOO_BIG | 9 | BAD_CRC | 14 | NOT_VERIFIED |

**Writes are strictly sequential.** The stub accepts only `offset == next`.
- After a short transfer (BAD_FRAME), a CRC error or IO, the response carries `next`, and the host resends from
  there. It allows at most 4 retries in a row.
- Any other status ends the session with the stub's `next` in the error.
- There is no resume across a stub restart: the verdict and the running hash live in RAM, so the host starts
  over.

### D5 — What the stub reuses from the kernel

| Need | Reused | New |
|---|---|---|
| Signature + SVN | `boot_abi::verify` (unchanged), `otaimg::check` header/length logic | the third call site; HBoot-prefix compare against the running HBoot |
| eMMC | `arch-aarch64/src/emmc.rs` + `sdhci.rs` (probe, CMD17/18 read, CMD24 write behind `p15-write`) | one gate, `admit_full_medium()`, compiled only with `flashstub`. It admits LBA 0..SEC_COUNT for this one session, after a positive verdict. The existing Gate 1 allowlist stays as it is for every other build |
| Slot location | `fat.rs`, `hal::abslot` | — |
| Hash | `boot_abi::sha256` | — |
| USB device | — | the DWC2 device-mode driver (D6) and the HQFL server |
| Build guard | `tools/ci/shipping_guard.py` | `flashstub` is listed as a feature the shipping flavour must never contain (added with this ADR, before the feature exists) |

Writing uses CMD24, one block at a time, which is metal-proven but slow. CMD25 multi-block writes are a measured
follow-up (M6), not a precondition.

### D6 — Open hardware question Q1: the USB device controller

The BCM2712 has its own USB 2.0 OTG controller, separate from RP1's xHCI host ports. Raspberry Pi's devicetree
names it `usb@480000`, compatible `brcm,bcm2835-usb` (the Synopsys DesignWare HS OTG "DWC2" binding):
- `reg <0x10 0x00480000 0x0 0x10000>`, so the base address is **0x10_0048_0000**;
- interrupt GIC SPI 73;
- `status = "disabled"` by default.

**Assumption to prove:** this is the controller behind the CM5's USB boot pins, the one the boot ROM and second
stage use for rpiboot. If so, it is powered and clocked when the stub starts, because the stub arrived through it.

**First metal read (no write):** the stub prints GSNPSID (offset 0x40, a DWC2 core reads `0x4F54_xxxx`) and
GHWCFG1–4 (0x44–0x50) on the UART. Those give the FIFO depth, the endpoint count and the UTMI width.

Driver plan: device mode only.
- One configuration: EP0 control, plus one bulk OUT and one bulk IN, high speed.
- Slave (PIO) FIFO mode before internal DMA, and polling instead of interrupts, like HBoot.
- Soft-disconnect first (DCTL.SftDiscon), so the host sees a fresh enumeration after the firmware's own use of
  the core.

It will be written from the USB 2.0 specification (chapter 9) and the register facts read on the part. The only
code reference allowed is permissively licensed: TinyUSB's `portable/synopsys/dwc2` (MIT), class B in
`docs/security/driver-provenance.md`. Linux `dwc2` (GPL-2) is not transcribed (ADR 0067 D11). Every new driver
file gets its register row before merge.

### D7 — Other open questions

- **Q2. USB ID for the stub.** The code uses pid.codes test ID `1209:0001` as a placeholder only. Before anything
  ships, the stub needs a pid.codes allocation or a vendor ID.
- **Q3. Raspberry Pi firmware.** `bootfiles.bin` holds Raspberry Pi's redistributable boot firmware. The page
  takes it as a file today. Whether HookProbe serves it, and under which notice, is a licensing decision
  (ADR 0067 D13).
- **Q4. Host setup.**
  - Windows: WinUSB through MS OS 2.0 descriptors in the stub. The boot ROM itself needs Raspberry Pi's
    installer driver.
  - Linux: a udev rule for `0a5c:2712` and the stub ID.
- **Q5. Secure boot.** With customer-key secure boot enabled, the ROM checks `boot.img`'s signature, and the
  stub's contract becomes a device-side guarantee. That is out of scope here (OTP is a production blocker, never
  provisioned by this work).

## Alternatives

- **(b) Hand the raw write to a native tool.** The browser runs rpiboot, then Raspberry Pi Imager or `dd` writes
  the mass-storage gadget. This works today with no stub, but it boots Linux on the device (ADR 0047), still
  needs an install, and no HookProbe code checks the signature before the write. Rejected by the operator
  2026-11-24.
- **(c) A native flasher app** (libusb). It avoids Chrome's class rules and permission prompts, but it is an
  install, per-OS packaging and signing, and it still needs a stub or the Linux gadget on the device. Rejected
  by the operator 2026-11-24.
- **WebUSB to the mass-storage gadget.** Not possible: Chrome protects class 0x08.

## Consequences

- **+** No Linux on the device at any point. The image is verified by the same code as OTA before a byte is
  written, and is proved by read-back after.
- **+** The browser side is transport-agnostic and fully testable offline.
- **−** A new USB device driver, which QEMU cannot test: QEMU models DWC2 in host mode only. Its proof is metal.
- **−** The verifier gets a third call site and the eMMC driver a whole-medium write gate. Both need security
  review, and the gate must stay out of every non-stub build (the shipping guard enforces that).
- **−** One or two Reconnect clicks per flash (Chrome permission model).

## Metal test plan (operator: relay rig, Chrome on the bench host; nothing below has run)

Preconditions:
- the operator's relay sequence for rpiboot entry (see the bench memory and runbook);
- a udev rule on the bench host for `0a5c:2712` and the stub ID;
- the page served on `http://localhost`;
- the UART capture running;
- an eMMC backup taken before M4 (`flash-image.sh --backup`).

| Step | What | Pass |
|---|---|---|
| M1 | rpiboot only, no stub. Tick "rpiboot only". Serve `mass-storage-gadget64/bootfiles.bin` + its `config.txt` + `boot.img`. No write is possible: the page cannot claim mass storage. | Log shows `0a5c:2712 iSerialNumber=0 -> boot ROM`, `second stage accepted (return code 0)`, `iSerialNumber=N -> file server` (N ≠ 0/3), `GetFileSize …` lines, `RPIBOOT DONE: file server done`. The host then sees the gadget enumerate (`lsblk` shows the eMMC); power-cycle without nRPIBOOT. This proves stages 1–2 and re-enumeration in Chrome. |
| M2 | Stub up, verify only (the default). | UART shows `GSNPSID=0x4F54…`. Log shows `stub: HQFL v1, release build …` and `signature OK (svn N …)`, then `VERIFIED … nothing written`. The eMMC hash is unchanged. |
| M3 | Refusals. A tampered slot (one byte), an image with SVN below the floor, a dev-signed image on a release stub. | `Refused: SIG_FAIL` / `ROLLBACK` / `SIG_FAIL`. The stub's UART shows no write. The eMMC hash is unchanged. |
| M4 | Full write of a bench image. | `wrote … bytes`, `read-back matches; slot flags 0x3`. A cold boot without nRPIBOOT boots heqk, and the banner's slot hash equals the manifest `slot_sha256`. |
| M5 | Fault: USB unplugged mid-write, then a re-run. | The page shows the error with the stub's offset. The board does not boot (LBA 0 cleared). The re-run completes as in M4. |
| M6 | Throughput. | Time a 512 MiB write. CMD24 vs CMD25 decides whether the multi-block write is needed. |
