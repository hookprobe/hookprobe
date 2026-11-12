# heqk CM5 bench flash runbook (2026-11-12)

Why: on 2026-11-12 five flash attempts in a row failed at the first step (the CM5 never showed its boot ROM on USB)
and an automated batch nearly ran its checks against the old image. Operator: no flashing without concrete steps.
Rule: **a flash is one deliberate, operator-approved action with a stop rule — not a retry loop.**

## 0. Before (no board action)

1. Build the image, keep `disk.img`, `heqk8.img` and the factory log together; record both sha256 prefixes.
2. Run `tools/diagnostics/cm5-flash-preflight.sh <image-dir>` (read-only). **Any BAD = do not flash.**
3. Tell the operator: image, hashes, what the batch will test, how long, and what the board runs now. Wait for GO.

## 1. Enter rpiboot (one attempt)

Use `tools/diagnostics/cm5-rpiboot-check.sh` (add `--msd` to also expose the eMMC as USB mass storage, read-only)
to prove the path without flashing. **Root cause of the 2026-11-12 failures:** the operator heard a single relay click —
the board was not power-cycled while nRPIBOOT was held, so the ROM never saw the boot mode. **Operator procedure (2026-11-12, LEDs IN1/IN2):** rpiboot = energise IN1 (power OFF) + IN2 (nRPIBOOT) together →
wait ~5 s → release BOTH (IN1 first, so nRPIBOOT is held at the instant power returns) → boot ROM `0a5c:2712` on USB.
After flashing, a normal boot = reset IN1 only (off → on). **Always run the paper test first:**
`tools/diagnostics/cm5-relay.py --backend nano --dev auto --dry-run rpiboot` (and `… --dry-run boot`) prints the exact
relay commands in order without touching anything. Asserting nRPIBOOT FIRST and cycling
power after it left IN1 unswitched (one click). `cm5-relay.py rpiboot` now uses the proven order and reads the relay
state back after every step. The read-back says what the controller drove, NOT that a contact moved — the operator's
LEDs / clicks are the ground truth when in doubt.
Verified after the fix: boot ROM `0a5c:2712` enumerated within 7 s.


`python3 tools/diagnostics/cm5-relay.py --backend nano --dev auto rpiboot`
- Pass: `0a5c:2712` appears on USB within 15 s.
- **Fail: stop.** Do not retry in a loop. Put the board back (`… boot`), confirm it serves its old image, report. The
  likely causes are physical and need the operator:
  - the USB-C data cable to the CM5 (the device port, not power-only), or a hub port that dropped it;
  - the nRPIBOOT relay contact / jumper wiring;
  - the board not actually power-cycling (relay 1 contact).
  One second attempt is allowed only after a physical check, and only with the operator's go.

## 2. Flash + read-back verify

`sudo os/kernel/cm5-boot/flash-image.sh <disk.img> --confirm-erase` — pass = `VERIFIED` (read-back equals the image).
Fail: stop; the board is in rpiboot with a partial image — re-flash the previous known-good image (keep its path in the
batch record) before anything else.

## 3. Boot and confirm the RIGHT image is running

`python3 tools/diagnostics/cm5-relay.py --backend nano --dev auto boot`, then on serial (from the mark taken before boot):
`secure boot: PASS`, `[P11-AP2] PASS`, and the build id of the image just flashed. **The batch starts only if the build
id matches** — a batch must never test whatever happened to be on the board.

## 4. Run the batch

`cm5-metal-loop.sh` does steps 1–3 in one go; batch scripts must call it once and abort on a non-zero exit (no retry
loop). After the batch: shred the temporary sudo copy, record results + serial offsets, and say plainly what ran and
what did not.

## Known-good fallback

Keep the last image that passed metal (path + hashes) in every batch record; it is what step 2's failure path restores.
