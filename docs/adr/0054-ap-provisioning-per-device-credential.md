# ADR 0054 — Wi-Fi AP production provisioning: per-device setup credential (parity gap G12)

**Status:** 🟢 Accepted (operator decision register, 2026-11-08) — increment 1 built (`apcred.rs`, `[P-apcred]`);
Mission Control QR view and setup→client hand-off are later increments.
**Related:** ADR 0037 D3 (owner key = physical possession), ADR 0049 D1 (operator-signed files, WIFI.TXT = G20),
ADR 0023 (management floor), decision register `docs/design/heqk-decisions-2026-11-08.md`.

## Context

heqk can ship as a WPA2 access point. Today the AP credential comes from an operator-signed WIFI.TXT or, on
bench images, a build-time `HEQK_AP_PSK`; with neither, the AP does not start (it never runs open). That is
safe but not a product: a customer device needs a working Wi-Fi credential out of the box, and the operator
required (2026-11-08): a unique per-device credential, no universal default, QR / secure onboarding, owner
authentication separate from Wi-Fi authentication, management isolation, no WPS, a reset that never
restores a universal password, and a visible difference between the setup AP and the client AP.

## Decision

**D1 — the setup credential is derived per device from the sealing root.**
`HKDF(SRK, "HQ-AP-SETUP")` → SSID `HookProbe-Setup-XXXX` and a 16-character passphrase from an unambiguous
alphabet (Crockford base32, grouped `xxxx-xxxx-xxxx-xxxx`, 80 bits). The SRK is derived by HBoot from the
per-device OTP secret, which was generated at provisioning by a CSPRNG, and EL1 cannot read the OTP back
(SEC-2). Consequences: unique per device, nothing stored on the card, survives re-flashing, and a factory
reset re-derives the same device-unique value (never a universal one). It is read off once at end-of-line
(serial console) and printed on the device label with the matching Wi-Fi QR code.

*Alternative considered:* draw a random passphrase from the TRNG on first boot and keep it in the sealed
store. Rejected for increment 1: it cannot be printed on a label before the customer first powers the device,
and a reset would change it (support burden). It remains an option for re-keying (D5).

**D2 — no real SRK, no AP.** On a device without an OTP-backed SRK (QEMU, an unprovisioned board) the kernel
only has a synthetic key that is the same everywhere; `apcred::derive` refuses any constant-fill key, so the
AP stays off instead of using a shared password.

**D3 — precedence.** Operator-signed WIFI.TXT (the **client AP**: the operator's SSID/passphrase) > bench
build env (`HEQK_AP_PSK`, bench images only) > the per-device **setup AP** credential > no AP. The setup AP
is visibly different (SSID prefix `HookProbe-Setup-`).

**D4 — owner auth stays separate.** Joining the Wi-Fi gives network access only; Mission Control still needs
the owner key (ADR 0037 D3) and runs on the management path. Client isolation (`ap_isolate`, G10) is on.
There is no WPS code in heqk.

**D5 — later increments.** (a) Mission Control "Wi-Fi" panel showing the setup credential + QR behind owner
re-authentication (ADR 0053 guards); (b) setup → client hand-off: once a signed WIFI.TXT is present the setup
SSID is no longer broadcast (already true by precedence); (c) optional re-key from the TRNG into the sealed
store, with "reset" returning to the label value.

## Consequences

Production units need the OTP secret provisioned at manufacturing (an irreversible, separately approved
step — same class as RPMB, not done by development sessions). The bench CM5 already has one.
