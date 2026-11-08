# ADR 0053 — Operator write actions in on-device Mission Control (parity gap G14)

**Status:** 🟢 Accepted with modifications (operator, 2026-11-08) — built: `actions.rs`, `actionapi.rs`, `[P-actions]`, mc-e2e checks.
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

## Operator modifications (2026-11-08) and how they are met

| # | Safeguard | Implementation |
|---|---|---|
| S1 | Maximum TTL enforced by the kernel, not the UI | `actions::MIN_TTL_S..MAX_TTL_S` (60 s..24 h); out-of-range is **refused**, not clamped |
| S2 | Quarantine expires automatically, including after a reboot | actions live in RAM on the monotonic clock; a reboot clears them; nothing is persisted |
| S3 | Authenticated, authorized, CSRF- and replay-protected | owner session + `Origin` must equal `Host` + per-session CSRF token (`X-HQ-CSRF`, derived from the session) + strictly increasing per-session `seq` |
| S4 | Who, when, which device, why | audit ring: session tag, time, kind, target, TTL, mandatory reason, result — refusals included |
| S5 | Re-authentication for high-impact operations | `isolate` and `shield_allow` require the owner key again (shared login throttle) |
| S6 | Emergency recovery independent of Mission Control | power cycle clears every session action; signed files remain the authority |
| S7 | A temporary exception never silently becomes permanent | no action kind writes a file or changes WAN / firewall / trust; there is no "make permanent" path; no kind disables enforcement |
| S8 | (ADR 0023) the management path always passes | `hold_ip` on an address inside the management floor is refused at submit and ignored by the hook (`[P-actions]` sub-check) |

Kinds built: `ack`, `hold_ip` (TTL), `isolate` (TTL, re-auth → quarantine policy, DHCP/DNS still work), `shield_allow`
(TTL, re-auth, never overrides DDR/canary/relay/DoH controls). UI: Investigate (Acknowledge, Hold source 1 h),
Shield (Hold 1 h per client, Allow 1 h per blocked name, active actions with "End now", audit log).
