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
  - `GET /api/config`
  - `POST /api/config/confirm`
  - `POST /api/config/rollback`

**Bundle semantics:** a bundle is complete for the sections it carries. For a missing section, the per-file source applies.

Status: built, QEMU (`[P-cfgd]`). Metal: pending (trial, commit and revert on the bench).

## Not done here

- **Step 4:** the management ABI and `hsh` (4a in progress).
- **Production transport (R6):** awaiting the operator's decision.
- **RPMB:** deferred until after the MVP.
- **Owner-signed reset (`HQRST1`):** ADR 0059 Phase 2.
