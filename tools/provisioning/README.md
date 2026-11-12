# tools/provisioning — per-unit factory provisioning station (heqk "Phase 7")

Takes one freshly flashed CM5 to a **labelled, self-tested, shippable** state. Runs on a Linux bench station,
Python 3 standard library only (`openssl` CLI required for the TLS step; `qrencode` optional, a built-in QR
encoder is used otherwise; `rsvg-convert`/`inkscape`/ImageMagick `convert` optional for PNG labels).

Decisions it implements: ADR 0054 (per-device setup credential, read once off the serial console, printed on the
label with a Wi-Fi QR), ADR 0037 D3 (retired 2026-11-12; see in part 0051 / 0054 / 0058 / 0059) (owner key = physical possession), ADR 0051 (MC TLS certificate from the owner CA).

```
provision-unit.py run           provision one unit (resumable)
provision-unit.py reset-verify  after a factory reset: the setup credential must equal the label value
provision-unit.py otp           OTP programming GATE (irreversible, separately approved) -- refusal path only
```

## What the station does, per unit

| # | Step | How |
|---|---|---|
| 1 | flash | `os/kernel/cm5-boot/flash-image.sh` (guarded, sha256 read-back); `--skip-flash` if already flashed |
| 2 | capture boot 1 | serial console (115200) or a recorded log; relay power-cycle if `--relay` |
| 3 | identity | parse the SRK-derived Wi-Fi MAC, the setup SSID + passphrase (+ QR payload), the MC TLS public key |
| 4 | owner key | mint a 120-bit owner token; stage the salted-verifier `OWNER.TXT` (same format as `make-cm5-heqk-disk.sh`) |
| 5 | TLS cert | `os/kernel/tools/mctls-provision.py` certifies the device's printed P-256 key with the owner CA |
| 6 | patch | write `OWNER.TXT` (128 B) + `MCTLS.CRT` (4096 B) in place on the unit's eMMC at the offsets in `<image>.json`, read-back verified |
| 7 | verify boot | capture boot 2: owner CLAIMED, HTTPS ready, setup credential **identical** to boot 1 |
| 8 | label | `label.svg`/`.png` (model, ID, SSID, passphrase, Wi-Fi QR) + `owner-card.svg`/`.png` |
| 9 | self-test | boot contract (same markers as `tools/diagnostics/cm5-metal-loop.sh`), credential/TLS stability, optional network sign-in check, optional `mc-e2e-metal.sh --no-browser` |
| 10 | record | `record.json` (+ detached signature with `--sign-key`) |

The host **never computes** the setup credential (the SRK exists only on the device; ADR 0054 D1): it parses what
the device prints. The unit has no separate serial number in its output, so the **unit ID is the SRK-derived Wi-Fi MAC**
(`02:4b:...` -> `024b...`), also the work-dir name.

The owner key is on a **separate card**, not on the Wi-Fi label (ADR 0054 D4: joining the Wi-Fi must not grant
Mission Control access; the label is visible on the outside of the unit).

## Prerequisites

* A factory image from `os/build/make-cm5-heqk-disk.sh` with its `<image>.json` manifest, built **without**
  `--wifi-file` and without `HEQK_AP_PSK` (otherwise the device never prints a setup credential: ADR 0054 D3) and
  **without** an owner token / MCTLS file (left as the unclaimed placeholder / empty).
* The unit's **OTP secret must already be provisioned** (a unit with no OTP-backed SRK prints
  `the AP will NOT start` and the tool rejects it; see the OTP gate below).
* Bench: serial console (FTDI, 115200 8N1), optionally the relay rig (`tools/diagnostics/cm5-relay.py`),
  `sudo` for the flasher / rpiboot.
* An owner CA directory (`--ca-dir`); created on first use by `mctls-provision.py` (name-constrained, key mode 600).
  Decide whose CA signs factory units (per-customer vs a factory CA) before volume production -- the tool takes
  whichever directory you give it.
* The station should be **offline** from the internet and used by one operator at a time.

## One-unit walkthrough (bench with relays)

```bash
IMG=os/build/generated/cm5-heqk/<image>.img
tools/provisioning/provision-unit.py run \
    --image "$IMG" --out ~/factory-out --ca-dir ~/factory-ca \
    --console /dev/serial/by-id/usb-FTDI_FT232R_USB_UART_...-if00-port0 \
    --relay "--backend nano --dev auto" --confirm-erase \
    --operator "$USER" --sign-key ~/factory-keys/record-ed25519.pem
```

Without `--relay` the tool stops and asks the operator to fit/remove the nRPIBOOT jumper and power-cycle (not with
`--non-interactive`, which fails instead). The tool prints progress; at the end `RESULT: SHIPPABLE` or
`NOT SHIPPABLE`. Then print `label.png` onto the unit's label stock and `owner-card.png` onto the sealed insert card
(both are in `~/factory-out/<unit-id>/`, mode 0600).

To also test sign-in over the network, join the unit's setup Wi-Fi with the station and add
`--mc-url http://10.99.0.1/` (and `--run-mc-e2e` for the heavier metal acceptance run).

### Replay / offline

`--serial-log boot1.log --verify-serial-log boot2.log --patch-target some.img` runs the whole flow with no hardware
(this is what the unit tests do). Raw serial captures **contain the passphrase**; pass `--delete-input-logs` to have
the tool unlink them after use, or shred them yourself.

## Outputs, `<out>/<unit-id>/` (directory mode 0700)

| File | Contains secrets? |
|---|---|
| `secrets.json` (0600) | **yes**: setup passphrase, QR payload, owner token, staged `OWNER.TXT` bytes |
| `label.svg/.png`, `owner-card.svg/.png` (0600) | **yes** (that is their purpose) |
| `state.json`, `identity.json`, `boot2.json`, `selftest.json`, `reset-verify.json`, `MCTLS.CRT` | no |
| `provision.log`, `boot-*.redacted.log` | no: every line passes a redactor that replaces the passphrase/QR/token |
| `record.json` (+ `record.json.sig`) | no: timestamps, operator, tool git commit, image sha256, identity (MAC, setup SSID, TLS pub), per-step results, `shippable` |

The passphrase and owner token never go to stdout, the general log, or the record (tests assert this over every
non-secret file). Keep `secrets.json` on an encrypted station disk and destroy it once the label/card are printed
and the unit is shipped; nothing else in the pipeline needs it (re-provisioning/reset-verify do, see below).

## Failure handling

| Symptom | Meaning / action |
|---|---|
| `first boot rejected: ... AP will NOT start` or `[MC-TLS] OFF — no device root key` | no OTP-backed SRK on this unit. Not shippable; OTP secret not provisioned. No work dir is created. |
| `serial log is missing: setup_psk ... factory image must have neither` | the image has a signed `WIFI.TXT` or `HEQK_AP_PSK`: rebuild the factory image without them |
| `the log contains more than one distinct setup credential` | two units' output in one capture: re-capture one unit |
| `patch refused: OWNER.TXT ... not the unclaimed placeholder` | the unit was already claimed: re-flash the factory image (never overwritten silently) |
| `refusing block device` | the patch target is not the CM5 in rpiboot mode (`/dev/disk/by-id/usb-*Raspberry_Pi*`) |
| step failed midway | the work dir keeps every completed step. Fix the cause and continue with `run ... --resume-unit <unit-id>` (steps already `ok` are skipped; the owner key is not re-minted, the patch is not repeated) |
| selftest FAIL | `selftest.json` lists the check; `record.json` says `shippable: false`. Do not ship. |

## Factory reset (ADR 0054 D1/D5)

heqk has no on-device reset button yet (see "Open items"); today a factory reset is operational:

1. Re-flash the factory image (`flash-image.sh`, or this tool with `run`), which restores the unclaimed
   `OWNER.TXT`, an empty `MCTLS.CRT`, and an empty DataVolume. The setup credential is **not stored anywhere on the
   card**; it is re-derived from the SRK (OTP), so it comes back **identical to the label** and never as a universal
   password. The owner key is gone with the claim: the unit needs a new owner key (`run`, which re-claims it; a new
   owner card is printed).
2. Verify: boot the unit with the console attached and run

   ```bash
   tools/provisioning/provision-unit.py reset-verify --out ~/factory-out --resume-unit <unit-id> \
       --console /dev/serial/by-id/usb-FTDI_... --relay "--backend nano --dev auto"
   ```
   It checks: the setup line is present; the credential equals the label value in `secrets.json`; the per-device MAC is
   unchanged; the PSK source is the per-device derivation (not `WIFI.TXT`/build env); the passphrase matches the
   Crockford `xxxx-xxxx-xxxx-xxxx` form and no default string; no other unit in `<out>` shares it. Exit 0 = pass.

## OTP programming (not part of `run`)

Provisioning the per-device OTP secret is **irreversible** and approved separately. `provision-unit.py otp` is a gate
only: it refuses unless `--i-understand-otp-is-irreversible` **and** `--otp-approval-file` (JSON with `approved_by`,
`approval_ref`, `approved_at`, `valid_until` in the future; regular file, not world-writable) are present, and even
then **no programming backend is wired** (`OtpBackendNotWired`). `run` has no OTP flag and never calls it.

## Tests

```bash
python3 -m unittest discover tools/provisioning/tests
```
No hardware: recorded (synthesised) serial logs in `tests/fixtures/` (formats cited to `os/kernel` file:line in
`fixtures/README.md` and `hqprov/serialparse.py`); QR encoder known-answer + decode round trip; secret-handling;
resume/idempotence; patch safety; OTP refusal.

## Open items / unverified without hardware

* Serial capture, relay cycling, rpiboot disk discovery, `flash-image.sh` invocation, and patching a real eMMC have
  **not** been run on metal (only against image files and replayed logs).
* `qrencode` output parsing is untested here (not installed on the dev host); the built-in encoder is what is tested
  (round-trip decoded through our own reader, plus the ISO RS/format-info known answers). Scan a printed label with a
  phone once on the first real unit.
* The device does not print a serial number, an image/version string, or an SRK fingerprint; unit ID = Wi-Fi MAC.
* The setup line prints only on the AP image path and only once per boot (no way to ask again), so the capture window
  must include power-on.
