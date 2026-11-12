# ADR 0059: implementation status (heqk side, 2026-11-10)

This note records what was built and what was tested. It does not change ADR 0059. Statuses:

- **built**: the code exists.
- **QEMU**: `validate.sh` and/or `mc-e2e` passed.
- **metal**: a CM5 bench run passed, with the evidence file named.

## Phase 0 — defects

| Step | What | Status |
|---|---|---|
| 0.1 | Fail-closed WAN path: the anchor is pinned first; an unverified WAN.TXT ignores the whole file (ADR 0058) | built, QEMU (713950a4). Metal: batch 58 boots with `WAN.TXT signature OK` |
| 0.2 (C2) | Verify and parse one buffer: `wan_signed` keeps exactly `[..len]`, duplicate keys are refused, `[P-wansig]` vectors added. The zero-tail rule was **not adopted** (ADR 0059 open item 4) | built, QEMU (a1486fe6). Metal: config-journey batch 58 |
| 0.3 (H1) | WAN/WIFI generation floors in anchor record v3 (`HQANCH3`). The first accepted generation becomes its own floor; accepting a newer one moves the floor to the previous one. The store path keeps a one-step rollback window; a file on the card must be ≥ the generation in force | built, QEMU (`[P-anchor]`) |
| 0.4 (H2) | `artstore::fallback_step`: active half, then the other (previous) half, then the boot partition, then the default. Applies to WAN, WIFI, POLICY and the content packs | built, QEMU (`[P-artstore]`) |
| 0.5 (C4) | `make-cm5-heqk-image.sh` refuses a release build of a device profile without `HEQK_POLICY_PUBKEY`. The boot banner says `CONFIG UNPROTECTED`; `/api/anchor` gains `config_protected`, `state` and `floors` | built, QEMU (mc-e2e) |
| 0.6 (M1) | A factory reset with the owner token alone keeps the enrolled owner key; a reflash removes it | built, QEMU (a1486fe6). Metal: config-journey D1 |

## Step 2: HQCFG1 bundle (`kernel/src/cfgbundle.rs`)

Pure verification with no heap. The byte layout matches `os/kernel/tools/hqcfg.py` and the browser builder through the shared vectors (`os/kernel/tools/vectors/hqcfg-vectors.json`, 24 cases). Run `tools/vectors/hqcfg-vectors-rs.py` to regenerate `kernel/src/testdata/hqcfg_vectors.rs`. Schema 1.0 accepts only kinds 1 (wan), 4 (wifi) and 5 (policy).

Status: built, QEMU (`[P-cfgbundle]` 24/24).

## Step 3: cfgd (`kernel/src/cfgd.rs`), the single configuration writer

- Upload type `config` (artifact-store type 9, staged) is committed as **PENDING**.
- At boot the bundle becomes a **TRIAL**, and the WAN, Wi-Fi and POLICY loaders read its sections first.
- **Commit:** the trial commits when the WAN is usable, which raises the bundle floor (anchor `cfg_floor`).
- **Revert:** the trial reverts after 300 s, or on a second boot while PENDING.
- **Owner confirm required:** a bundle that touches the management plane (`mgmt*`/`vlan*`/`pcp` keys, `interface mgmt`, `route … via mgmt`) is never auto-committed and needs `POST /api/config/confirm`.
- **Refusal at stage:** a bundle with no management path is refused at upload. This is checked against the device's real addressing.
- **Refused committed bundle:** a committed bundle that no longer verifies tries the other half first.
- **API:**
  - `GET /api/config` — additive (R6 = D): `envelope: {format: "HQMGMT1", device_id, epoch, next_seq, generation, digest, owner_enrolled}` (hex strings; `digest` = SHA-256 of the HQCFG1 bundle in force, zeros = none). This is what a confirm / rollback envelope must bind.
  - `POST /api/config/confirm`, `POST /api/config/rollback` — **hard switch (R6 = D, operator 2026-11-12):** authorised only by a required `envelope` field (312 hex = the HQMGMT1 envelope signed by the enrolled owner key); the `owner_key` re-authentication no longer authorises a change and is ignored. `reason`, `permanent=true`, `seq`, Origin + `X-HQ-CSRF` stay as the transport gate. Refusals with an envelope problem are `403 {"ok":false,"refused":"refused: …"}`. Full request format, signing and error table for the UI: `docs/design/mgmt-envelope-api.md`.

**Bundle semantics:** a bundle is complete for the sections it carries. For a missing section, the per-file source applies.

**While a bundle is in force** (committed or on trial), per-file `wan` / `wifi` / `policy` uploads are refused at `begin`. The refusal says: "a configuration bundle is in force: change this with a new bundle (type config), or roll the bundle back first". Without this, the bundle's section would silently win over the upload (metal batch 60). Rolling back with no older verified half clears the bundle.

**Factory reset** (token-only) erases the store and resets the WAN / Wi-Fi / bundle generation floors, so the shipped boot-card baseline applies again. Before this, a kept WAN floor refused the shipped gen-2 WAN.TXT, and the device came up on DHCP without its management VLAN. The owner key and the POLICY floor (ADR 0049 D1) stay. **This needs your review:** replaying an older card file still requires physical card access, which is equivalent to a reflash.

**Boot self-tests never change live configuration state.** `cfgd::set_selftest` makes confirm and rollback refuse during the `[P-hsh]` / `[P-mgmtabi]` boot tests. In metal batch 60, a boot self-test committed a live trial.

Status: built, QEMU (`[P-cfgd]`). Metal: pending (trial, commit and revert on the bench).

## Step 4: management ABI + `hsh` (docs/design/hsh-native-management-shell.md)

- **4a — built, QEMU, metal (batch 59: `[P-hsh]` + `[P-mgmtabi]` PASS on CM5).**
  - `hal::mgmtabi` is a versioned set of read messages with fixed records, roles and result codes.
  - `kernel/src/mgmtabi.rs` serves them from the same producers as `GET /api/*`, with a role check.
  - `el0-hsh` is an EL0 excursion shell: a bounded parser per spec §9, a static registry, and a two-phase flow (line → request → reply → text). It has no heap and no state.
  - The read commands are `info`, `version`, `uptime`, `wan status` / `interface show wan`, `qsecbit status`, `config status`, `owner status` and `security posture`.
  - Transport (R6 = D, operator 2026-11-12): the web carrier `POST /api/hsh` (feature `hsh`, carried by the AP product `apmc`; `hsh-dev` stays development-only and refused in release builds). Guards: the owner session, Origin, CSRF; each request journaled (command words only). Body: line 1 = the command line; optional line 2 = an HQMGMT1 envelope (312 hex) for a privileged command. The envelope goes from the carrier straight to the EL1 verifier; the EL0 parser never sees it. There is no UART RX code.
- **4b — built, QEMU.**
  - `CFG_CONFIRM` / `CFG_ROLLBACK` and `CFG_STAGE <upload-id>` (the caller's verified `config` upload).
  - The dispatcher journals each operation, allowed or refused. Mission Control's `/api/config/confirm|rollback` call the same dispatch after their guards, so all clients get one authorisation decision and write one journal record.
- **4c — R6 = D, built, QEMU (`[P-hsh-web]`, `[P-mgmtabi]`).** Every message above view is authorised ONLY by an HQMGMT1 envelope signed by the enrolled owner key `K_own`; the session's role never authorises a change, and session elevation (`HQCHAL1`, `owner elevate`) is retired. `owner challenge` (view) shows what to bind.
  - Envelope (156 B, little-endian): `"HQMGMT1\0"` | version u16 = 1 | msg u16 (20 confirm, 21 rollback, 22 stage) | device_id[16] | epoch[8] | seq u64 | arg u64 (stage: upload id) | generation u64 | digest[32] | Ed25519(K_own, `"HQMGMT1-SIG"` ‖ bytes 0..92).
  - Verified in `mgmtabi` (EL1) before dispatch: the owner key's signature, this device id, this boot's epoch, seq above the floor (then consumed), the operation and argument, and for confirm / rollback the generation + digest of the bundle in force (else "something else is on trial / in force").
  - Replay: a RAM sequence floor under a per-boot epoch drawn from the hardware TRNG (CM5). A reboot draws a new epoch, so envelopes signed for an earlier boot no longer match; nothing is written to the eMMC per operation. No TRNG word = no epoch = every privileged operation refused.
  - Owner side: `os/kernel/tools/policy-sign.py mgmt-sign` builds an envelope; `hq-upload.py --sign-key … --config-confirm|--config-rollback|--hsh` signs locally and sends it. The private key never reaches the device.
  - Consequence: with no owner key enrolled, nothing can confirm or roll back by hand (the trial still auto-commits when healthy or reverts after its window).

## Not done here
- **UART carrier:** not built (R6 = D keeps the carrier free of authority; a UART carrier would be view + envelope paste).
- **RPMB:** deferred until after the MVP.
- **Owner-signed reset (`HQRST1`):** ADR 0059 Phase 2.
