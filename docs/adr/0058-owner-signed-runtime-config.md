# ADR 0058 — Owner-signed configuration on a running device (WAN, Wi-Fi, policy)

**Status:** 🟢 Accepted (operator, 2026-11-10 — the configuration journey and its eight rules approved; was 🟡 Proposed 2026-11-10). Amendments to D2 / D3 / Consequences are proposed by ADR 0059 (still Proposed). Records the operator decision of 10 Nov 2026 ("the owner signs in the
browser", requirements doc §Configuration journey) and turns it into a device contract. Device-side items
are for the heqk session (they touch `os/kernel`); the Mission Control half is built against this contract.
Answers ADR 0056 open item 2 ("whether WIFI.TXT updates belong here").

**Status reconciled 2026-11-12:** evidence for "Accepted": `docs/design/adr0058-implementation.md` (line 3, "ADR 0058
… is accepted", and its table of the operator's eight configuration rules of 2026-11-10); built and metal-proven —
config journey 20/20 on CM5 (`docs/design/metal-evidence/20261111-batch59-63.md`). Shipping still needs the G46
security review of enrollment / rotation (release gate SEC-05, `signoff:g46-security-review`).

## Context

Internet mode, PPPoE login, ISP and management VLANs, Wi-Fi name / password / security, prefix lists, ACLs,
routes and the SASE tunnel all live in operator-signed files on the boot partition (WAN.TXT, WIFI.TXT,
POLICY.TXT). They are read at boot only, and the upload interface (ADR 0056) refuses them, so a home user cannot
switch to PPPoE or rename their Wi-Fi without re-flashing. ADR 0055 D1 rightly keeps them out of the owner
journal: they are signed configuration, not owner rules.

The signatures are plain Ed25519 over a short tagged message (`HQWAN1` / `HQWIF1` / `HQPOL1` · generation · length ·
sha256), so a browser can produce them byte-for-byte with WebCrypto. What is missing is (a) a way to deliver
them to a running device and (b) a way for the OWNER's key to be the key the device trusts.

## D1 — Three new upload types (extends ADR 0056 D2)

| Type | File + signature | Cap | Activation |
|---|---|---|---|
| `wan` | WAN.TXT + HQNSIG1 | 512 B | next boot |
| `wifi` | WIFI.TXT + HQWSIG1 | 1 KiB | next boot |
| `policy` | POLICY.TXT + HQPSIG1 (4096 B, `\n`-padded) | 4 KiB | next boot (ADR 0056 D2 row, now phase 1) |

Same container (`cat X.SIG X.TXT`), same begin / chunk / finish / activate flow and owner re-authentication.
"Activate" stages the file in the A/B artifact store; the boot loaders read the store slot before the boot
partition (as the live-reload packs already do), verify again, and on refusal keep the previous generation.
A generation must be strictly greater than the active one (anti-rollback per type, persisted like the policy
floor in the trust anchor).

## D2 — Rollback and recovery

The previous generation stays in the other slot. `POST /api/upload/rollback {type}` (owner re-auth) re-activates
it for the next boot. If the new WAN / Wi-Fi settings leave the device unreachable, the AP setup network
(ADR 0054, per-device credential) and the boot-partition files remain the recovery path; a failed boot of new
settings falls back to the previous slot automatically (tryboot-style, mirroring the OS-image path).

## D3 — The owner's key becomes the trust anchor

Today the anchor pins the image's compiled key on first use. Add enrollment and rotation:
- **Enroll** (first boot or an unpinned device): `POST /api/anchor/enroll {pubkey}` with the owner key
  re-authentication and the setup network (or physical presence) as the gate; pins the owner's Ed25519
  public key in place of the image key.
- **Rotate**: a new public key signed by the currently pinned key (`HQROT1` · new key · generation).
- A factory reflash still resets the pin (physical access = the owner's own action), unchanged.
The private key never reaches the device; the device stores only the public half (ADR 0051 spirit).

## D4 — Where the owner's key lives

Mission Control signs with an Ed25519 key held in the owner's browser (WebCrypto, stored in IndexedDB), with a
PKCS#8 PEM backup the owner downloads — the same format `os/kernel/tools/policy-sign.py` uses, so an existing
operator key can be imported and the CLI keeps working. **Passkeys / hardware security keys are not possible
with the current verifier**: WebAuthn signs `authenticatorData ‖ sha256(clientDataJSON)`, never the raw `HQ…`
message. Supporting them needs a WebAuthn-aware verifier on the device (open item 1).

## D5 — Mission Control flow

Advanced → build the change in a form (only options the device supports) → see the exact file as a draft →
review the diff against what the device reports → sign in the browser → upload → "applies at next reboot" with
the generation and a rollback. Until D1 is served, the upload is refused by the device and Mission Control offers
the two signed files for the boot card instead (still no build machine needed).

## Consequences

- Closes the re-flash gap for WAN / Wi-Fi / policy (gap register G43–G45); answers ADR 0056 open item 2.
- New parser surface (already fuzzed for WAN / Wi-Fi / policy at boot); no new trust: the signature stays the
  authority, the session only decides whether to try.
- The PSK travels in a signed file over the owner's HTTPS session and rests on the device as today.

## Open items

1. WebAuthn-aware verifier (passkey / security key signing) — size and whether worth it.
2. Who may enroll the anchor on an already-pinned device (only rotation signed by the pinned key, proposed).
3. A reboot endpoint (`POST /api/reboot`, owner re-auth) so "Apply now" does not need a power cycle.
