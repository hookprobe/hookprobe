# ADR 0056 — Device-side upload interface (signed artifacts over Mission Control HTTPS)

**Status:** 🟡 Proposed contract (2026-11-09) — direction approved by the operator 2026-11-09 ("take the upload
half of item 3, with an explicit boundary against the other session's flasher work"). **Countersign needed
from the flasher owner (task #20)** on the boundary in D1 and the open items before implementation of D6+.
Compatible with ADR 0037 (static client-side browser flasher — "no backend" is a security property) and
ADR 0051 (owner CA / Mission Control HTTPS): this interface never receives, generates or stores an owner
private key.

## Context

Signed data packs (Shield lists, IOC pack, rule pack, OUI registry, device policy) and OS images reach a device
only by re-flashing its storage. Protection goes stale from day one, and G22 list refresh, live rule updates
and OTA delivery all wait on a channel (gap register; legacy parity #2, #17). The A/B tryboot mechanism, the
SVN floor and every artifact's signature format already exist; what is missing is a safe way to put a signed
artifact onto a running device.

## D1 — Ownership boundary

| This ADR (device side, this session) | Flasher (task #20, other session) |
|---|---|
| The HTTPS upload API on the device, its authorization, validation, staging, activation, rollback, audit | Browser flasher UX, platform selection, first-flash |
| Which artifact types a running device accepts, and how each is verified | WebUSB / rpiboot transport |
| Live reload of data packs; hand-off of OS images to the existing A/B tryboot commit | Owner CA generation and private-key custody (ADR 0051), MCTLS issuance |
| | Secure-boot provisioning — and SEC-3 fuses are out of scope for everyone (operator 2026-11-09) |

The flasher may *use* this API after first boot (e.g. "update this device"), as a client like any browser.

## D2 — Artifacts (closed list; the client never chooses a path)

| Type | File + signature | Cap | Activation |
|---|---|---|---|
| `shield_block` / `shield_allow` | BLOCK.TXT / ALLOW.TXT + HQBSIG1 / HQASIG1 | 16 MiB | live reload |
| `ioc` | IOC.TXT + HQISIG1 | 16 MiB | live reload |
| `rules` | RULES.BIN + HQRSIG1 (+ the DET-2 per-rule gate) | 64 KiB | live reload (verifier + JIT) |
| `oui` | OUI.TXT + HQOSIG1 | 4 MiB | live reload |
| `devices` | DEVICES.TXT + HQDSIG1 | 16 KiB | live reload |
| `policy` | POLICY.TXT + HQPSIG1 | 4 KiB | next boot (it carries WAN/ACL/mgmt) |
| `os_image` (phase 2) | heqk8.img (Ed25519 + SLH-DSA, SVN) | slot size | A/B tryboot + commit (existing M3.4 path) |

Not accepted: OWNER.TXT / owner keys, Wi-Fi credentials (WIFI.TXT holds a PSK — later, owner-journal kind
or flasher), MCTLS material (flasher / ADR 0051), anything unsigned.

## D3 — Transport and authorization

Owner session + `Origin` = `Host` + CSRF + per-session `seq` (ADR 0053 S3) **and owner re-authentication
for every upload** (S5). Chunked, because the HTTP body is bounded:
`POST /api/upload/begin {type, size, sha256}` → upload id; `PUT /api/upload/<id>?off=` chunks ≤ 16 KiB in
order; `POST /api/upload/<id>/finish` → verify; `POST /api/upload/<id>/activate` (separate step, re-auth);
`POST /api/upload/<id>/abort`. One upload in flight; idle uploads expire after 10 min.

## D4 — Validation (all before activation; any failure aborts and is audited)

Declared type in the D2 list; `size` ≤ the type cap; chunks contiguous; SHA-256 of the received bytes = the
declared digest; the signature verified by **the same verifier and signature domain the boot-time loader
uses** (no second verifier); the signed generation ≥ the active generation for that type (anti-rollback per
artifact); for `os_image` the existing hboot verification + SVN floor; and a dry-run parse (skipped /
truncated counts returned to the client).

## D5 — Staging and activation

Uploads land in a dedicated staging region (region registry, item #54) — never over the active copy. Active
data packs live in an artifact store with A/B slots per type plus a manifest record (type, slot, generation,
digest); activation writes the inactive slot, verifies it by reading it back through the real loader, then
commits the manifest record (atomic single-sector write). Power loss before the commit leaves the old slot
active. Boot-time loaders prefer the artifact store's committed slot when its generation is ≥ the boot-FAT
copy; otherwise the FAT copy (a reflash always wins back). `os_image` is handed to the existing A/B tryboot
flow (`otaflip` / `abcommit`), which already rolls back an unhealthy trial boot.

## D6 — Audit

Every begin / finish / activate / abort / refusal is a record in the ADR 0055 journal's audit trail (actor,
time, type, size, digest, generation before/after, result, reason).

## Consequences

- Fresh intel, lists and rules without re-flashing; OTA delivery becomes possible; G22 list refresh closes.
- New attack surface (upload parser, staging) — fuzzed (ADR 0050 D3); nothing new to trust: the signature is
  still the authority, the session only decides *whether to try*.
- Depends on #54 (region registry) and G12 (the AP image carries persistence).

## Open items (flasher owner + operator)

1. Confirm the D1 boundary and that the flasher uses this API (not a second device-side path) after first boot.
2. Whether WIFI.TXT updates belong here (signed, contains a PSK) or in the flasher / an owner-journal kind.
3. MCTLS certificate renewal: stays entirely in the flasher / ADR 0051 flow (proposed), or a later D2 row.
