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
   - **Status (2026-11-12, built, QEMU `[P-cfgd-wan]`, metal pending):** `kernel/src/wanlive.rs` (verify + parse
     first, teardown, link, start) + `uplink::wan_teardown` / `wan_start` / `mgmt_current`, `nat::flush_wan` (each NAT
     mapping now records its WAN address), `CH_WAN` in `LIVE_CAPABLE`.
   - DHCP and static start **non-blocking** (the in-loop DORA; static resolves its gateway in the loop). PPPoE kept
     the bounded blocking dial at first; since the follow-ups below it is non-blocking too (`pppoe::Dial`).
   - Q5: a PAP/CHAP reject fails the apply at once (live revert, no window). A change of the management
     sub-interface or floor is applied only when it differs, and then needs the owner's confirm.
   - Metal must prove: DHCP → static → PPPoE → DHCP live (Mission Control on the AP reachable throughout), and a
     wrong-PPPoE-password bundle reverting live early.
10. The Wi-Fi executor. **Metal spike early:** repeated `ap_stop`/`ap_start` on the CYW43455.
   - **Status (2026-11-12, built, QEMU `[P-cfgd-wifi]`, metal pending):** `kernel/src/wifilive.rs` (resolve, derive
     first, bounce) + the `apply_wifi_live` glue in `main.rs`, run from the step-8 hook after policy and WAN. `CH_WIFI`
     is in `LIVE_CAPABLE`; a Wi-Fi change still always waits for the owner's confirm (300 s), else cfgd reverts live.
   - Resolve as boot does: the bundle's wifi section (one that does not parse is refused live), else `WIFI.TXT`, else
     the default (build PSK or the SRK setup credential). Before the radio is touched: the PMK (PBKDF2 or raw hex),
     a TRNG GTK and the SAE password element (`cyw43::ap_security_prepare`). Any failure leaves the AP untouched.
   - Bounce: `ap_stop` (`WLC_DOWN`) → forget every station's SAE state + the PMKSA → install the security mode →
     `max_clients` (before `ap_start`: the firmware applies `maxassoc` in the bring-up; a removed cap restores the
     firmware's own value) → `ap_start` on the current chanspec → `ap_install_gtk`. It must come up serve-ready and
     keyed, else it returns false and cfgd reverts live. On success the AP loop's PMK / GTK are replaced; the
     passphrase and scratch keys are wiped with volatile writes. DHCP leases are kept (MAC-bound).
   - The firmware is **not** re-downloaded, so the REL-08 in-RAM PMKID correction stays in place. A new `channel=`
     takes effect at the next boot. The AP addressing, the WAN and eth1 are not touched. Mission Control's
     Wi-Fi/management-VLAN serving choice (G12-M) is re-evaluated after every live Wi-Fi or WAN apply / revert
     (`mcmgmt::serve_on_wifi` from the credential in force and the running management sub-interface; the node's
     management address follows the live sub-interface) — follow-up 2026-11-12, `[P-cfgd-wifi-after]`.
   - **IPv6 at an AP restart (follow-up 2026-11-12, `[P-cfgd-wifi-after]`):** every bounce of the BSS calls
     `clear_station_v6_state()` (main.rs): all SAVI bindings, neighbour entries and IPv6 pinholes of the old BSS are
     dropped, the LAN numbering is kept and the RA burst restarts. The Wi-Fi self-heal bounce must call it too when
     it lands.
   - Metal must prove (R2): repeated live bounces on the CYW43455 (≥ 10 back to back) with no FWHALT and no SDIO
     wedge. Stations re-join after an SSID change, a passphrase change and a `max_clients` change. This covers WPA2,
     WPA3-SAE and transition, both ways (WPA2 ↔ WPA3), with a WPA3 phone and a WPA2-only client. Mission Control
     must be reachable after the re-join, and the owner's confirm must commit (R3: the session survives). With no
     confirm, the 300 s window must revert live to the old SSID and stations must re-join it. A bundle whose
     passphrase cannot derive must leave the BSS beaconing untouched. The `wifi-pmkid-fix` RAM correction must
     still be in place after bounces. The boot log line only repeats the boot-time result, so this needs a chip-RAM
     read-back of the patch site, or a WPA3 soak across bounces with no FWHALT.
   - **Follow-ups (2026-11-12, release-plan Workstream 6, built, QEMU, metal pending):**
     - **Non-blocking PPPoE dial** (`[P-cfgd-pppoe]`). `pppoe::Dial` wraps the unchanged engine (its parsers are
       untouched): a budget per stage (Discovery 10 s, Requesting 6 s, LCP / auth / IPCP 10 s each), a fresh re-dial on
       a stage timeout (a half-open session is PADT'd first), at most 3 attempts, an overall bound (60 s from the loop,
       30 s at boot). `uplink::pppoe_dial_begin` / `pppoe_dial_poll` step it from the AP loop (at most 8 frames per
       poll), for the live WAN apply AND the in-loop retry, so forwarding and Mission Control keep running (closes
       F-d). The boot dial is the same machine stepped in a loop with the watchdog petted, then its pings and the
       bounded IPv6 probe as before. After a loop dial, IPV6CP runs in the engine and RS / DHCPv6-PD in `pppoe_poll`
       (`v6acq_*`, shared with the boot probe), so the loop never waits for IPv6 either.
     - **Q5 from the loop** (`[P-cfgd-mgmt]`). A definitive reject (PAP/CHAP rejected, no protocol in common) now
       arrives after the executor returned; the loop calls `cfgd::wan_auth_rejected` and the live trial reverts at once.
       A timeout-only dial is not definitive: the in-loop retry and the window decide.
     - **Management re-probe after a WAN change** (`[P-cfgd-mgmt]`). `wanlive::mgmt_reprobe`, fed once a second while a
       trial runs: the management sub-interface must have its address and a resolved gateway, and the owner's own
       client (F-e) must still have a path (on the AP; on-link on the management VLAN and resolved; or routed over the
       resolved management gateway). A lost path makes the trial unhealthy even when the WAN is usable: it never
       auto-commits and reverts at the window. `/api/config` reports `live.mgmt_ok` / `live.mgmt_probe` (null outside a
       trial). The policy dimension stays the stage-time D7 check (a WAN-only change does not change the policy).
     - **Q3 RAM-only apply** (`[P-cfgd-volatile]`, `[P-upload]`). With no device key, a secret-bearing HQCFG1 bundle
       whose changes are all live-capable is verified by cfgd (signature, device, generation above the floor) and
       applied live from RAM; its commit stays in RAM (no manifest write, no floor rise, nothing on disk). The activate
       reply says `at_rest:"volatile_ram_only"`; `/api/config` `at_rest` adds `volatile_ram_only` and `persisted`, and
       never reports a volatile configuration as sealed or protected. A live rollback / window revert re-loads the
       persisted last-known-good (no manifest flip). A reboot returns to the persisted configuration. A later persisted
       bundle's revert goes back to the persisted last-known-good, never to a volatile one. The journal records the
       activation without a digest (F-a). Per-file uploads with a secret stay refused (next-boot only).
   - **Metal must prove (follow-ups 2026-11-12):**
     - Live WAN DHCP → PPPoE → DHCP with a Wi-Fi client streaming and Mission Control open: no forwarding stall during
       the dial (the loop keeps serving), the `[M-NAT0] … PPPoE dialled in the loop` line, IPv6 PD re-acquired in the
       loop (`[V6LAN]` renumbers).
     - A bundle with a **wrong PPPoE password**: `[WAN] PPPoE dial REJECTED (authentication)` then `[CFGD] … reverting
       LIVE` within seconds (not the window), management (AP + management VLAN) reachable throughout, the old WAN back.
     - A PPPoE AC that does not answer: bounded re-dials (`gave up`), the watchdog never fires, the window reverts.
     - A WAN bundle that keeps the WAN but breaks the management path (e.g. a management gateway that does not
       answer): `/api/config` `live.mgmt_ok:false`, no auto-commit, live revert at 120 s.
     - Wi-Fi + management-VLAN change with clients: Mission Control moves to / from the management VLAN as G12-M
       says (`[AP-MC] … after the live change`), the owner's confirm commits.
     - AP restart IPv6: a station with a SLAAC address and an open IPv6 flow, then a live SSID change; the station
       re-joins (also with a new private MAC) and gets IPv6 again (no SAVI refusal, RA seen at once).
     - No device key (blank OTP unit): a bundle with a PPPoE password activates `at_rest:"volatile_ram_only"`, applies
       live, commits; nothing in the Store region (raw read); a **reboot** returns to the persisted configuration.
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
