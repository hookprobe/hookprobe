<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# ADR 0069 — G19: replay protection for the first handshake message

**Status:** accepted (operator, 2026-11-24): option A, the monotonic counter. Implemented in `g19ctr.rs` / `controlplane.rs` (device) and `superpop` `pop.rs` (`CtrState`, `--ctr-state`).

## Context

G19's handshake is Noise IK: the device sends msg1 (ephemeral keys, its encrypted static identity and a payload),
the super-PoP answers with msg2. Today msg1's payload is only the device fingerprint, which the PoP checks against
its allowlist.

Nothing in msg1 is fresh from the PoP's point of view. Anyone who records one msg1 off the wire can send it again
later. The replay gains no keys (the attacker cannot complete the handshake), but on a **new** msg1 the PoP replaces
the device's live session (`pop.rs`: one live session per device), so a replay **tears down the real device's
tunnel**. It is a denial-of-service lever available to anyone on the path.

What has been done (#1498, deployed):
- A byte-identical msg1 within 30 s is answered from cache and does not replace the session.
- After 30 s it is treated as a replay and ignored, remembered for 24 h, up to 4,096 entries.

This closes the cheap version of the attack. It does not survive a PoP restart (the replay set is in RAM), and an
attacker holding many recorded msg1s can outlast the 4,096-entry window.

## Decision

Add a **monotonic initiator counter** to msg1's payload. The PoP refuses any msg1 whose counter is not higher than
the highest it has accepted for that device, and keeps that high-water mark on disk.

- **Payload:** `fp (32 B, sha256 of the device pk) ‖ ctr (8 B, LE u64)`. The counter is inside the encrypted, authenticated part of msg1, so it
  cannot be altered.
- **Device:** a 64-bit counter in the sealed store (one record, written before each new msg1). Retransmits of the same
  msg1 keep the same counter. Each new handshake (a fresh ephemeral) takes counter + 1. Cost: one sealed eMMC write per
  handshake, about one a day with the 24 h rekey. Negligible wear.
- **PoP:** per device, `last_ctr` in the devices state on disk (fsync before msg2 is sent). Accept iff
  `ctr > last_ctr`, or the msg1 is byte-identical to the cached one (#1498's retransmit rule stays). Refusals are
  counted (`hs_stale_ctr`).
- **Migration:** the PoP accepts the old 8-byte payload from a device until that device has once sent a counter. From
  then on that device's counter is required (no downgrade). Old images keep working. Each device upgrades itself the
  first time it runs the new image.

## Alternatives

| | Option | For | Against |
|---|---|---|---|
| A | **Counter in the sealed store (recommended)** | No clock needed. Works before SNTP and on a cold boot without RTC. Strictly monotonic. Small change | A device whose disk is restored from an old backup sends a lower counter and is refused until its counter passes the PoP's mark (recovery: the operator resets `last_ctr` for that device) |
| B | Wall-clock timestamp (WireGuard's TAI64N idea) | No device state to keep | The tunnel would need a trusted clock before it starts. At first boot the clock often comes after the WAN, and the RTC may be unset. A wrong clock locks the device out |
| C | PoP challenge (cookie round trip) | Fully stateless on both ends | Changes the handshake pattern (3 messages, IK no longer sufficient); a bigger change to the verified Noise code |
| D | Keep #1498 only | No change | Replays work again after a PoP restart; a large recording outlasts the window |

## Consequences

- One more sealed record on the device and one durable field per device on the PoP.
- The PoP restart no longer re-opens the replay window.
- A device restored from an old disk image needs an operator action on the PoP (documented, audited).
- Both sides change: device (`controlplane.rs` / `g19.rs`, sealed store) and `superpop`. Ship order: PoP first (accepts
  both forms), then device images.

## Evidence plan

- QEMU (E1): replay of a recorded msg1 after a PoP restart → refused; a fresh handshake → accepted; old-format device
  → accepted until it sends a counter, then the old format is refused for it.
- S1 / E2 (QEMU → real PoP) and CM5 (E3) with the existing harnesses.

## Implementation notes (2026-11-24)

- **Device:** the counter lives in its own DataVolume region `G19Ctr` (sectors 2056..2058 of the partition), two
  records `HQG19C1\0 | ctr | sha256` written alternately (slot = ctr % 2). The newest valid one wins, so a torn write
  leaves the previous value. `g19ctr::next()` writes ctr + 1 and reads it back before the msg1 is built; if that
  fails, no msg1 is sent and the control plane retries with its usual backoff. Retransmits reuse the pre-built msg1
  datagrams, so they carry the same counter. The MSSP enrollment control plane (no counter source) keeps the old
  payload. Self-tests: `[P-g19ctr]` (record layer) and `[P19-controlplane]` (the real initiator carries `fp ‖ ctr`
  and sends nothing when the counter is not durable).
- **PoP:** marks are keyed by fingerprint. The check comes after authentication and before msg2. The mark is raised
  and made durable after msg2 is built and before it is sent. If it can't be saved, the handshake is refused and the
  RAM mark is rolled back. New stats: `hs_stale_ctr`, `hs_legacy`, `hs_ctr_unsaved`.
- **Downgrade note:** once a device has sent a counter, an image without this change (an OTA rollback to an older
  build) can no longer bring the tunnel up with that PoP. That is the intended no-downgrade rule; recovery is the
  documented PoP-side mark reset.
- **Ship order:** PoP first (it accepts both forms), then device images.

