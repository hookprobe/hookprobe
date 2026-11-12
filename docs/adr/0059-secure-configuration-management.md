# ADR 0059: Secure configuration management for heqk

**Status:** 🟡 Proposed (2026-11-10). Needs operator review.

**Scope:** os/kernel (cfgd, anchor, verifiers), os/mission-control (bundle producer), os/build (release gate).

**Evidence:** `docs/design/secure-config-assessment-2026-11-10.md`. That document holds the inventory, the
threat model, the roadmap and the test plan; every statement of fact there carries a file and line reference.

**Related ADRs:**
- **Extends** ADR 0049 D1 (operator-signed POLICY), ADR 0056 (upload interface) and ADR 0058 (owner-signed
  runtime config).
- **Amends** ADR 0058 in three places: D2 (rollback becomes a health-checked trial), D3 (factory reset may no
  longer clear the owner key on the token alone) and the Consequences section ("the PSK … rests on the device as
  today" is replaced by D6 below).
- **Supersedes** the clause in ADR 0049 D1 that reads "standalone: an unsigned POLICY.TXT is accepted", but only
  for production images (D8 below).
- **Supersedes** `mgmt_floor` in WAN.TXT (D7 below).

## Context

The operator found that editing WAN.TXT or POLICY.TXT on the boot partition can take a device offline. Inspection
confirmed this and found more (assessment §A):

- **C1.** On `main`, the WAN mode, static addressing, PPPoE credentials and VLAN/QinQ settings are applied without
  any signature check. A failed WAN.SIG only suppresses `mgmt_floor`.
- **C2.** WAN.SIG signs only `body[..len]`, but the parsers read the whole sector. Lines appended after the
  signed text therefore override the signed settings while the signature stays valid. This was reproduced with a
  host proof of concept against the real parser.
- **C3.** WAN.TXT is verified before the device-pinned key has been loaded.
- **C4.** Images built without an operator key accept every configuration file unsigned.
- **WAN and WIFI have no persisted anti-rollback.**
- **No health-checked rollback exists.**
- **Secrets are stored in plaintext.**
- **The trust anchor is protected only by an unkeyed hash.**
- **Pi secure boot (SEC-3) is not enabled.** Anyone who can write the eMMC can therefore replace HBoot itself.

ADR 0058, as built on branch `feat/heqk-prod-phases` (PR #950), fixes C1 and C3. C2 is being fixed on the same
branch.

What is missing is one principle that every configuration path must obey, plus the structure around it: the
object format, the lifecycle, the key hierarchy, the management interface and the recovery path.

## Decision

### D1: The rule

A configuration byte takes effect only if all of the following hold:
- it lies inside a region whose exact bytes were signed;
- the signing key is authorized for that configuration section by the device anchor;
- the signed generation is at or above that section's persisted floor;
- after that, it passed strict parsing and semantic validation.

On a device that has a key, nothing else may become configuration. That includes text that happens to be present
on the FAT partition, a Mission Control session, a CLI command, or a suggestion from the AI assistant. Device-side
authentication (a session or token) decides only whether the device will *try* an operation. It never grants
authority over configuration.

### D2: The text files stay, but only as signed content or as import/export

The line grammar (WAN.TXT, WIFI.TXT, POLICY.TXT) is kept as the canonical **body** format. It is deterministic,
already fuzzed, auditable by a person, and producible byte for byte in a browser.

These files are never trusted because they are present. Their roles are:
1. **Factory baseline.** The FAT copy signed with the vendor key (or later the owner key). It is read only at
   boot, never written at runtime, and used only as a fallback below the store.
2. **Legacy form.** Per-file `.SIG` uploads under ADR 0058. They are accepted with the C2 fix: the parser sees
   exactly the signed bytes, duplicate keys are rejected, and any bytes after the signed length must be zero.
3. **Export and diagnostic view.** Comments are allowed here; they are stripped before signing.

The **HQCFG1 bundle** (assessment §B.4) becomes the native form:
- a fixed binary envelope containing the schema version, generation, a device binding, the signer's key id and a
  table of sections;
- canonical text sections inside it;
- a signature over the exact envelope bytes, so the whole configuration is one atomic, consistent unit;
- canonical-text rules: printable ASCII and LF only, a closed set of keys, each key at most once, and no bytes
  outside the signed length.

### D3: Kernel capability, authorized configuration and runtime state are separate

- Protocol engines and enforcement live in the signed kernel. The existing VLAN, QinQ, PPPoE, ACL, prefix-list and
  route engines are kept unchanged; inspection found no defect in them.
- Customer settings are never compiled into the kernel image.
- Authorized configuration lives in DataVolume A/B halves: the active half plus the last known good half. The FAT
  partition holds only the factory baseline.
- Runtime state (leases, sessions, counters) is never written back as configuration.

### D4: Key hierarchy (assessment §B.3)

| Key | Role |
|---|---|
| K_boot (Ed25519 + SLH-DSA) | Signs HBoot and the kernel. Anchored in HBoot, and in Pi OTP once SEC-3 lands. |
| K_vend (TOFU-pinned) | Signs content packs and the factory baseline configuration. |
| K_own | Enrolled by the owner and held off-device. Signs configuration, delegations, rotations and transfers. |
| K_adm,i | Delegated administrators. Each holds a certificate signed by K_own that lists the sections it may sign. All certificates are revoked at once by bumping an owner-signed epoch. The table is bounded to 8 entries. |
| K_dev_enc (X25519) | Derived as HKDF(SRK). Used only to protect secrets at rest. |

Encryption never substitutes for a signature.

### D5: Lifecycle (assessment §B.5)

A configuration change goes through these steps in order:
1. Authenticate the session and authorize the operation.
2. Verify the signature, key scope, device binding and generation.
3. Validate the grammar and semantics, and check the requested capabilities against the Platform Manifest.
4. Write the inactive half and read it back.
5. Commit the manifest atomically with the state PENDING and a deadline.
6. Activate.
7. Run the health window. It passes when the WAN is usable, management is reachable, and (for a remote change)
   the owner has confirmed.
8. Then either COMMIT and raise the floor, or revert automatically to the last known good half.

Recovery rules:
- A reboot while still PENDING counts as one trial. A second such boot reverts.
- The floor is raised only on COMMIT.
- Boot falls back in this order: store active → store last known good → FAT baseline → safe default. The safe
  default is DHCP on the WAN, LAN and setup AP up, management locked down on the management VLAN, and a reason
  shown in Mission Control.
- On a device that has a key, unsigned configuration is never used at any step.

### D6: Secrets at rest

The PPPoE password and the Wi-Fi PSK travel in a `secrets` section. It is encrypted to K_dev_enc and bound to the
device id and the generation, and the encrypted section is itself covered by the signature.

Units without provisioned OTP have no SRK. They report "secrets not protected at rest" and are never presented as
protected.

### D7: Management-plane authority belongs to policy

`mgmt_floor` moves into the `mgmt` section, signed under the policy scope. In a legacy WAN.TXT it is honoured
only when the file is signed and the floor lies inside the management sub-interface's subnet.

Before staging, a bundle must keep at least one management path reachable: LAN, setup AP, or the management VLAN
with an ACL that admits the floor. A bundle that leaves none is refused.

### D8: No unprotected production images

A production build without a configuration key fails the release gate. Keyless images (bench and development)
announce `CONFIG UNPROTECTED` at boot, in `GET /api/anchor` and in Mission Control.

Standalone operation stays first-class. The owner key is generated in the browser at first setup and needs no
account or cloud.

### D9: One management ABI; hsh runs at EL0

The implementation specification is `docs/design/hsh-native-management-shell.md` (operator, 2026-11-10). Its §0
reconciles that specification with the repository. Its R6 asks the operator to decide which transport `hsh` uses
in production.

The configuration manager (cfgd, in EL1) is the only component that writes configuration. It exposes a bounded
set of messages: state, stage, confirm, rollback, enroll, rotate, delegate, revoke, challenge, recovery. Mission
Control handlers, `hsh` and the AI assistant tool layer are thin clients of this ABI.

`hsh` is an EL0 component, per ADR 0050's placement rules: it parses untrusted input, and an EL0 fault cannot
corrupt kernel state. Consequences:
- The device never holds K_own. hsh can therefore only stage bundles that are already signed, or show the digest
  of a draft for the owner to sign off-device.
- UART input is compiled out of production images. Where it is enabled, elevated rights need a challenge-response
  signed by K_own.
- Every operation, accepted or refused, is recorded in the HMAC-chained owner journal.

**Decision note, 2026-11-12 (operator): R6 = D.** Privileged management operations are authorised only by command
envelopes (HQMGMT1) signed off-device by K_own and verified by the management ABI in EL1; the carrier (web console,
Mission Control, any later carrier) carries no authority, and the owner session alone never authorises a change.
Confirm and rollback envelopes bind the generation and digest of the bundle in force. Status and format:
`docs/design/adr0059-implementation.md` step 4. Same day, also converted: upload activate / rollback (every type),
factory reset and owner-key rotation. Known deviation for this round: reboot, owner rules, operator actions and the
alert hook still use owner-token re-authentication. Accepted consequence: with no owner key enrolled, no client can
confirm or roll back by hand (a trial that needs a confirm reverts at the end of its window).

### D10: Recovery, ownership transfer, and honesty about anti-rollback

- **Clearing K_own** requires either a signature from K_own or physical presence: a 10-minute window opened by
  holding the setup button at power-on. The owner token alone is not enough; this amends ADR 0058 D3.
- **Ownership transfer** is a rotation signed by the old owner. Without the old owner it goes through the
  physical-presence window.
- **Anti-rollback today** consists of software floors in the DataVolume. An attacker who can write the raw eMMC
  can restore an older anchor sector, and with it lower floors or an older pin.
- **Planned hardening:** a keyed MAC over the anchor using HKDF(SRK), and RPMB-backed floors whose key is written
  once as a separate manufacturing step.
- **Against an attacker with physical write access, none of this is a guarantee until SEC-3 (Pi secure boot) is
  enabled.** Documentation and the UI must not claim otherwise.

## Consequences

- The operator's attack (editing a text file to take the device offline) is closed on keyed devices by ADR 0058
  together with the C2 fix. After this ADR, a correctly signed but harmful configuration also reverts by itself.
- One configuration authority and one lifecycle replace separate per-file loaders. ADR 0058 upload types continue
  as legacy forms.
- The verifier and parser together cost about 16 KiB of static buffer and a few KiB of code. The only new
  cryptography is X25519 and ChaCha20-Poly1305, which are already in the tree. There is no heap and no new
  framework.
- The owner must protect the owner key. Losing it means physical-presence recovery.
- Residual risks are listed in the assessment's threat model (§C). The largest is SEC-3.

## Rollout

**MVP build order, confirmed by the operator on 2026-11-10:**
1. Close the Phase 0 security defects (C1–C4, H1, H2, M1).
2. Build HQCFG1 verification (assessment Phase 1).
3. Build cfgd: stage, trial, commit and automatic revert (assessment Phase 2).
4. Build the management ABI and the native `hsh` at EL0 (assessment Phase 5).

Each step starts only after the previous one passes its gates.

**Not ordered by the operator:** secrets at rest (Phase 3), delegation, revocation and the `mgmt_floor` move
(Phase 4), and hardware anchoring (Phase 6). Their place in the schedule is not part of the confirmed order.
**RPMB is already under a direct operator instruction to the heqk session:** build it, with the key write as a
separate manufacturing operation. That instruction stands, and this ADR does not defer it. Where these phases and
SEC-01 (ADR 0050 D4) sit relative to steps 2–4 is the operator's call. Until secrets at rest land, the MVP bundle carries the PPPoE password and PSK the
way ADR 0058 does today, inside the signed region, and the UI keeps saying they are not protected at rest.

Phase details are in assessment §E.

Phase 6, the hardware anchoring work (SEC-3, RPMB, OTP), is made of manufacturing operations: Red-gated and never
autonomous.

## Open items

1. Physical-presence signal on boards without a setup button: a power-cycle pattern or a GPIO strap.
2. WebAuthn verifier (ADR 0058 open item 1). It would let K_own live on a passkey or hardware security key.
3. ML-DSA as a second configuration-signature algorithm (the envelope reserves `alg = 2`). Crypto agility per
   ADR 0002.
4. ~~Zero-tail rule for length-prefixed packs.~~ **Not adopted (heqk session, 2026-11-10).** Verifying and
   parsing one buffer already means nothing reads past the signed length. Store slots are not guaranteed to be
   zero-filled after a shorter upload, so the rule could refuse legitimate files. HQCFG1 makes the question moot:
   its envelope carries `total_len`, and nothing outside the signed length is ever parsed. D2 rule 2 therefore
   reads "the parser sees exactly the signed bytes; duplicate keys are rejected".
