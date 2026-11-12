# hsh R6 — production management transport: options for decision (2026-11-12)

Status: **DECIDED 2026-11-12 — option D** (owner-key-signed command envelopes; the web console is the first carrier; the carrier carries no authority). Input: the hsh spec (R6), ADR 0059 D9, the reviewer's principles.

## Principles (reviewer, 2026-11-12)

1. Replace `hsh-dev` with a production transport, not a production build of the development protocol.
2. The management plane stays separate from the packet dataplane.
3. Authenticate the owner; authorise **each** privileged operation through HEQK capabilities.
4. Diagnostics are read-only by default; changes use an explicit elevated transaction.
5. Confirmation is bound to the staged change, with a timeout, a connectivity check and automatic rollback.
6. The transport is never a trust anchor: the signed kernel and the owner identity stay authoritative.
7. Mission Control, the CLI and a future AI Copilot use **one** management API. No separate privileged paths.

## The common core (the same whichever carrier is selected)

The carrier only moves bytes. Authority comes from the management ABI (`mgmtabi`, EL1), which every client uses.

| Element | Today | Needed for the principles |
|---|---|---|
| One management API | `mgmtabi` messages; Mission Control's confirm / rollback / stage already route through it; hsh uses it | Keep. Every new carrier is a thin client of `mgmtabi` (7) |
| Roles | view / operate / config / owner / recovery; cfgd enforces them (R10) | Keep |
| Read-only default | the hsh session starts at `view` | Keep (4) |
| Elevation | `owner challenge` → signature by K_own → `owner elevate` (`mgmtabi::elevate`); the device never holds K_own | Make it the **only** way to reach operate/config/owner from any carrier (3, 6) |
| Confirm bound to the change | **Gap:** `/api/config/confirm` is authorised by re-entering the owner token (`ownerapi.rs:623`) and commits **whatever is on trial** (`dispatch(…, 0, &[], …)`, `ownerapi.rs:630`) | Confirm carries the staged **generation + bundle digest** and a fresh challenge, signed by K_own; cfgd refuses if anything else is on trial (5) |
| Timeout / connectivity / rollback | cfgd live trial: confirm window 300 s (auto 120 s), health = WAN usable, live revert; a crash → last-known-good | Keep; add the management-path re-probe after a WAN apply (live-apply follow-up) (5) |
| Dataplane separation | hsh runs as an EL0 excursion; `mgmtabi` in EL1; nothing on the packet path | Keep (2); a new carrier must not add per-packet work |

The confirm-binding gap should be fixed **whatever is selected**.

## Options

| | A. Web console only | B. Web + UART at view role | C. No production shell | D. Signed command envelopes, any carrier | E. USB device serial (CDC-ACM) |
|---|---|---|---|---|---|
| **Carrier** | `POST` over the owner's authenticated TLS session (Mission Control) | A + the board's UART console, RX on in production | none; Mission Control pages only | each privileged request is a K_own-signed envelope (device id, nonce, msg, args, staged digest); carried by web, UART, USB or a file | the CM5 USB-C port in device mode |
| **Exposure** | anyone who reaches Mission Control (LAN / AP / mgmt VLAN) **and** holds the owner session | A + physical access to the UART pins | smallest | the carrier is untrusted by design; a signature is needed for any change | physical (USB-C) |
| **Authentication** | owner session (token login) + per-op K_own challenge | web: same; UART: none needed for view, K_own challenge to elevate | — | the signature over the envelope **is** the authorisation; no session state is trusted | like B |
| **Elevation** | challenge → K_own signature (a browser / CLI holding the key signs) | same; on UART the operator pastes the signature hex | — | built in: every privileged envelope is signed | like B |
| **Recovery** (network or Mission Control down) | none: the shell needs the network | **yes**: view diagnostics on site; changes still need K_own | none | **yes**, if a physical carrier is enabled | yes |
| **Provisioning** | nothing new | nothing new (cable / pins) | — | an owner-side signing tool (CLI) | a USB device-mode driver: **not built** (DWC2/RP1 device stack) |
| **Image cost** | ≈ +100 KB (el0-hsh ELF) | ≈ +100 KB + a small UART line reader | 0 | ≈ +100 KB + an envelope verifier (small, Ed25519 already linked) | ≈ +100 KB + a USB device stack (large) |
| **Build effort** | small: a production gate on the existing endpoint | small + UART RX reader | none | medium: envelope format, nonce store, CLI signer | large |
| **Fits principles** | 1–7, if the confirm gap is fixed | 1–7, if the confirm gap is fixed; UART is view-only, so it is not a trust anchor | 1–6; (7) only through MC pages | 1–7 most strictly: the carrier carries no authority | as B, at much higher cost |

## Recommendation (engineering)

**D's authorisation model on A's carrier now, with B's UART as an optional second carrier.**

- Every privileged operation (confirm, rollback, stage, owner ops) is a K_own-signed envelope bound to the device
  id, a fresh nonce and, for confirm, the staged generation + digest. `mgmtabi` verifies it; the session alone never
  authorises a change.
- The production carrier is the web console over the owner session (A). It is small and already built behind
  `hsh-dev`.
- The UART carrier (B) can be added later as view-only plus envelope paste. It changes nothing in the trust model,
  because the carrier carries no authority.
- C stays the fallback if image budget or audit scope forces it. E is not worth a USB device stack now.

## Test criteria (for whichever option is selected)

1. View commands answer on the carrier; every privileged command is refused without a valid K_own signature.
2. A confirm signed for generation N is refused while N+1 is on trial; a replayed envelope (old nonce) is refused;
   an envelope for another device id is refused.
3. An unconfirmed change reverts live after the window; a change that breaks the management path reverts (re-probe).
4. A carrier fault (malformed / oversized input, EL0 fault) never changes configuration and never blocks the
   dataplane loop (bounded per call).
5. No secret is ever printed on the carrier or journaled; the journal records every privileged request with its
   outcome.
6. Mission Control, the shell and the test client produce the same journal record for the same operation.
7. Image ≤ 5,242,880 B with the selected carrier(s).
