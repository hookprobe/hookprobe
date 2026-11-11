# heqk: configuration sealed at rest + live apply without reboot (design, 2026-11-11)

Status: **design, awaiting operator answers Q1–Q7**. Architect review (Plan agent) of the `wt-p5` tree, spot-checked by
the implementer. Operator principle: *"once you enter the house and close the door you can move chairs as you wish"* —
after a verified boot the device holds its keys, its configuration is encrypted at rest and survives reboot, and
settings change **live**, never requiring a reboot.

## 0. Defects found while designing (confirmed in code)

| # | Defect | Evidence |
|---|---|---|
| F-a | **Encrypting only the data file is not enough.** Three plaintext copies of the plaintext digest let an attacker test PPPoE-password / PSK guesses offline from a raw eMMC image: (1) the signature sector holds `sha256(plaintext)` plus a publicly verifiable signature; (2) the manifest digest repeats it; (3) the audit records repeat it. | `policysig.rs:46-57,114-132`; `artstore.rs:150`; `upload.rs:470-482` |
| F-b | **Uploads write plaintext to the eMMC Staging region**, including WAN / Wi-Fi / config uploads with secrets, and nothing scrubs it. | `upload.rs:285-296` (confirmed) |
| F-c | **A bundle's Wi-Fi section is ignored at boot.** Wi-Fi loads before cfgd starts the bundle trial. | `main.rs:3055` vs `main.rs:3134` (confirmed) |
| F-d | **The in-loop PPPoE retry can trip the watchdog.** It blocks for up to 30 s; the watchdog maximum is about 16 s. | `main.rs:4403,4446`; `uplink.rs:697`; `rtwdog.rs:7-9` |
| F-e | **The D7 management-path check does not test the owner's own address**, so a `/32` block of the owner's client passes. | `cfgd.rs:74-90` |
| F-f | **Rule 7 lists eth1 as a management path, but Mission Control is not served on eth1.** | `main.rs:3528`; `cfgd.rs:28` |

## 1. The model (the "house")

- **The door:** a verified boot. HBoot hands over the per-device SRK, and the kernel derives
  `K_cfg,ty = HKDF(SRK, "HQ-cfg-at-rest-v1" ‖ ty)`. This key never leaves EL1.
- **At rest:** every stored config artifact (WAN, Wi-Fi, policy, HQCFG1 bundle) is sealed under `K_cfg`. The owner's
  signature stays inside the seal, still covering the plaintext.
- **Changes:** cfgd, the single writer, applies a new signed bundle **live**: policy swap, Wi-Fi BSS re-key, WAN
  re-bring-up. It runs a trial while the management path stays reachable. It commits when healthy or when the owner
  confirms, and otherwise reverts **live** to the last-known-good.
- **Reboots:** a reboot or crash during a trial means "last-known-good" (the existing PENDING semantics).
- **Outside the house:** the factory FAT baseline. It is signed and plaintext, and by rule it carries no secrets.

## 2. Feature 1: sealed at rest

- **Format:** reuse HQKSEAL1 (`seal.rs`) with in-place seal/unseal for 16 KiB bundles.
  - Seal policy: `mask 0, svn_floor 0`, so the configuration survives OTA updates.
  - The generation goes in the MAC-covered reserved header bytes.
- **On disk:** `[HQKSEAL1 128 B][ct(sig ‖ data)]` in the existing slot, so no layout change.
  - Every signature format fits in 128 B.
  - The manifest's unused byte becomes `sealed`.
  - The digest becomes the hash of the **sealed** image, which closes F-a.
- **Read order:** raw → seal bounds → **HMAC first** (nothing decrypted on failure) → decrypt in RAM → **the type's own
  signature verifier** → parse → apply.
  - The signature is still verified before any parse; the seal is an extra outer gate.
  - A read-only `artstore::Plain` block-device view serves decrypted slots to all existing loaders unchanged.
  - A MAC failure feeds the existing fallback (other half → FAT → default).
  - A plaintext pack where `sealed=1` is refused, which blocks a downgrade.
- **Write:**
  - Staged uploads are kept in RAM, never on disk (closes F-b).
  - `activate_sealed` seals, writes, reads back and commits the manifest.
- **Migration:** a one-time, crash-safe boot step.
  - Seal the active plaintext half into the inactive half, commit the manifest, then zero the old half and the
    Staging sectors.
  - Cost: the previous generation is dropped once (Q7).
- **No SRK (blank OTP):** never seal under a synthetic key.
  - Secret-bearing config (a PPPoE password, any Wi-Fi config) applies live **RAM-only**, not persisted (Q3).
  - Non-secret config is stored signed and plaintext.
  - Both cases are reported (`at_rest`, `secrets_protected`).
- **Baseline lint:** the release build refuses a FAT baseline that contains `pppoe_pass=` or a `WIFI.TXT`.
- **Relation to ADR 0059 D6** (an owner-encrypted secrets section): this device-side seal is simpler and covers more.
  It amends D6 (Q2).

## 3. Feature 2: live apply

- **Scope:** HQCFG1 bundles apply live. Per-file wan/wifi/policy uploads stay next-boot, as legacy (Q1).
- **State machine (cfgd):** Idle → Queued → Applying → Trial → Committing | Reverting.
  - **Applying:** the trial counter is persisted first. Executors run in the order Policy → WAN → Wi-Fi, and only
    for changed subsystems (per-section digest).
  - **Reverting:** flip the manifest first, then re-run the executors with the last-known-good.
  - **Reboot only if the revert itself fails.** `Tick::RevertReboot` becomes `Tick::Reverted`.
  - **One change in flight at a time;** the HTTP reply goes out before the apply starts.
- **Confirm rule:** a management-plane **or Wi-Fi** change needs the owner's confirm, because the AP is a management
  path. The health check (WAN usable + post-apply management-path re-probe incl. the owner's own address) closes F-e.
  - Trial window: 120 s for auto-commit changes, 300 s for confirm changes.
- **Policy executor:**
  - Parse into scratch. On error, keep the old policy; never lockdown live.
  - Swap with one struct copy.
  - `POLICY_GEN` is the hook for future SMP publication.
  - Established NAT flows are kept (Q4).
- **WAN executor:**
  - Build and verify first.
  - Tear down: PPPoE PADT, DORA/RENEW/WAN6 state, the MSS default, and `nat::flush_wan` keyed by (VRF 0, WAN address).
  - Link configure, then a **non-blocking** `wan_start` (static / DHCP / PPPoE, which also closes F-d).
  - Re-probe the management path.
  - It never touches the AP or eth1.
- **Wi-Fi executor:**
  - Load and verify first, then derive the PMK and a TRNG GTK. If anything fails, the AP is untouched.
  - Bounce the BSS: `ap_stop` → forget stations → `ap_set_security` → `ap_start` on the current channel →
    `ap_install_gtk`.
  - Require serve-ready plus the GTK set; otherwise revert. Stations re-join.
- **Crash semantics** use the existing PENDING/trials rules: any crash during apply or trial boots the last-known-good.
- **API:** `applies:"live"`, `applied_live`, `reboot_required:false`, `persisted`, `at_rest`, and `trial{phase,
  generation, window_s, needs_confirm, changes}`; `/api/config` adds `phase`, `remaining_s`, `health{…}`, `last{…}`,
  `at_rest{…}` and `policy_generation`.

## 4. Still reboot-only

- The OS image and compiled features, HBoot, the Wi-Fi firmware and CLM, and the regulatory domain.
- Manufacturing steps (OTP/SRK, the RPMB key) and the factory-reset erase.
- The fixed LAN/AP addressing.
- A fresh automatic channel scan.

**Live but with a short outage:** Wi-Fi changes (stations re-join) and WAN mode / VLAN changes.

## 5. Implementation steps (each one QEMU self-test, then metal)

0. Fix F-c (cfgd before the Wi-Fi load) and F-d (the watchdog in the PPPoE retry).
1. `seal.rs` in-place seal/unseal plus `cfg_key`; `[P15-seal]` extended.
2. artstore: the `sealed` byte, the `Plain` view, `activate_sealed`. `[P-artstore]` must show no secret string and no
   plaintext digest on disk.
3. upload: RAM staging; the audit records the ciphertext digest.
4. Wire `Plain` into the loaders and cfgd; `[P-cfgd]` runs on a sealed store.
5. Migration, staging scrub, the no-SRK rules, the `at_rest` fields; new `[P-cfgseal]` with crash injection.
6. The cfgd live engine with mock executors; new `[P-cfgd-live]`.
7. The policy executor plus `Ctx.peer` and the owner-address probe.
8. The activation hook (`take_apply` in the AP loop).
9. The WAN executor (non-blocking `wan_start`, `nat::flush_wan`). Metal: DHCP → static → PPPoE → DHCP live.
10. The Wi-Fi executor. **Metal spike early:** repeated `ap_stop`/`ap_start` on the CYW43455.
11. Management-VLAN changes under confirm.

## 6. Open questions (operator)

- **Q1.** Make per-file uploads legacy next-boot (recommended), or extend live apply to them?
- **Q2.** Amend ADR 0059 D6 to "device-side seal of every stored config artifact; owner-encrypted secrets optional
  later"?
- **Q3.** No SRK: secret-bearing config RAM-only (recommended), or plaintext only with an explicit, journaled owner
  acknowledgement?
- **Q4.** Should a policy that tightens access flush established flows, or keep them?
- **Q5.** On a definitive PPPoE authentication reject, revert early or wait out the window?
- **Q6.** eth1 and rule 7: should Mission Control be served on eth1?
- **Q7.** Is dropping the previous generation once during migration acceptable?

**Risks:**
- **R1. eMMC wear levelling can keep old pages.** Zeroing is not erasure. Use secure-trim where possible and call it
  "best effort".
- **R2. A CYW43455 AP down/up cycle is unproven.** That is why the step 10 spike comes early.
- **R3. A Wi-Fi change drops the owner's session** while the phone re-joins. Sessions are RAM-held, so they should
  survive.
- **R4. Image size:** about +10–15 KiB.
- **R5. SMP later:** the policy swap must become generation-published (ADR 0060 D7).
