# ADR 0053 — Operator write actions in on-device Mission Control (parity gap G14)

**Status:** 🟡 Proposed (2026-11-08) — **needs an operator decision** (D1). Nothing is built until accepted.
**Related:** ADR 0037 D3 (owner auth), ADR 0049 D1 (operator-signed files), ADR 0051 (HTTPS), ADR 0023
(enforcement separation), ADR 0052 (Shield). Parity source: V1 Fortress/Guardian web write routes.

## Context

heqk's Mission Control is read-only: every non-GET request returns 405. All configuration is an
operator-signed file on the boot partition (POLICY / BLOCK / ALLOW / IOC / DEVICES / WIFI), which is strong
(an attacker with the card cannot forge it) but slow: changing one device's policy means re-signing and
re-flashing. V1 had many write routes — and its failures are the lesson: Guardian had no CSRF protection
and a shell `/execute` route; Fortress quarantine flows were not persistent; actions were not audited.

## Options for the authority of a write

| | Authority | Strength | Cost |
|---|---|---|---|
| A | The owner **session** (owner key → HttpOnly+Secure cookie, HTTPS) | anyone holding the owner key or a live session | simplest; matches every consumer router |
| B | Session **plus a per-action operator signature** (the browser signs with an operator key held in WebCrypto / a hardware key) | possession of the operator key | strongest; heavier UX, key management in the browser |
| C | Session for **reversible, self-expiring** actions only; signed files for durable configuration | session for minutes-scale actions, signature for anything persistent | balanced |

## Decision (proposed): C

**D1.** A signed-in owner session may perform only actions that are (a) reversible, (b) bounded in time
(they expire on their own, default ≤ 24 h, maximum 7 days), and (c) never able to weaken the management
floor or a signed policy: acknowledge/close an incident; quarantine a device or release one *that a session
quarantined*; pause Shield for one device for ≤ 1 h; temporarily allow one domain for ≤ 24 h; log out (incl.
"log out everywhere"). Durable configuration stays in operator-signed files (unchanged trust model).
*Operator to decide: C (recommended), A, or B.*

**D2.** Every write: POST only, `Origin`/`Host` must match the device (plus SameSite=Strict, already set),
a per-session CSRF token in a header, JSON body ≤ 1 KiB, strict schema, rate-limited per session.

**D3.** Every write is appended to a RAM audit ring (who = session id, what, target, expiry, result) shown in
Mission Control and exported with detections (ADR 0052-style ring + the G15 syslog path). No shell, no
generic "execute" — each action is a typed handler.

**D4.** Session-made actions do not survive a reboot unless persistence (G12) is in the image; the UI says
so ("expires at … / until reboot").

## Consequences

Closes V1 parity for day-to-day operations without making a stolen session able to change durable policy.
Requires: CSRF token plumbing in `http.rs`/`mcauth.rs`, a typed action table, the audit ring, UI buttons.
