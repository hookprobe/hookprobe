# Secure configuration management for heqk: assessment, architecture, threat model, roadmap

**Date:** 2026-11-10 · **Decision record:** [ADR 0059](../adr/0059-secure-configuration-management.md) ·
**Builds on:** ADR 0049 (operator-signed POLICY), ADR 0056 (upload interface), ADR 0058 (owner-signed runtime
config) and its implementation note `docs/design/adr0058-implementation.md` (branch `feat/heqk-prod-phases`, PR #950).

**Trigger:** the operator reported that tampering with the plaintext configuration files on the boot partition
(`WAN.TXT`, `POLICY.TXT`) can take a device offline.

**Labels used throughout:**
- **[VERIFIED]** means read in code, with `file:line`, or reproduced.
- **[DESIGN]** means a recommendation.
- **[ASSUMPTION]** means not yet proven.

Line numbers refer to `main` @ `3713ce89` unless marked **(p1e)**. **(p1e)** is the heqk session's uncommitted
ADR 0058 tree, which is being landed as PR #950.

---

## A. Current-state assessment

### A.1 Critical defects

| # | Defect | Where | Status |
|---|---|---|---|
| **C1** | **WAN.TXT fails open.** The WAN mode is parsed and applied with no signature check: DHCP, static IP/gateway/DNS, PPPoE user and password. The link keys (VLAN, QinQ, PCP, management sub-interface) are applied even when `WAN.SIG` fails. A failed signature only suppresses `mgmt_floor`. Anyone who can write the boot partition sets a wrong VLAN, static address or PPPoE login and the device drops off the WAN. | `kernel/src/main.rs:3098-3109` (`load_wan_cfg`, no signature), `:3119-3140` (the comment says "Connectivity settings apply either way"), `:14202` | **[VERIFIED] on main.** Fixed in (p1e): a WAN.TXT that fails verification is ignored as a whole (main.rs (p1e) `:3121-3135`). |
| **C2** | **WAN.SIG signed-prefix bypass.** `verify_wan` hashes `body[..len]`, and `len` comes from the signature file. `policy-sign.py` and the UI set it to the unpadded text length (`os/kernel/tools/policy-sign.py:67-70`). `parse_wan_cfg` and `parse_wan_link` parse the whole 512-B sector up to the first NUL, and duplicate keys are last-wins. Lines appended after the signed text therefore override the signed values while the signature still verifies. | `kernel/src/policysig.rs` `verify_wan`. `main.rs:14103-14113` and `:14202-14212` re-read the sector and parse all of it. `hal/src/lib.rs:454-455` and `:554-555` (`end = first NUL`). | **[VERIFIED] by host PoC against the real `hal` parser.** Signed `mode=dhcp` plus appended `mode=static ip=203.0.113.9/30 … vlan=4000` parses as Static on VLAN 4000, and the signed bytes are byte-identical. **Fixed on `feat/heqk-prod-phases` (QEMU PASS 2026-11-10, metal pending).** WIFI (`wificfg.rs:192` (p1e)) and DEVICES (`devpolicy.rs` `load_text(&buf[..body_len])`) are not affected. |
| **C3** | **WAN.TXT is consumed before the trust anchor is pinned.** On main, `wan_signed` runs at `main.rs:3133` and `anchor::boot` at about `:3170`. WAN therefore verifies against the compiled key, not the device-pinned key. WIFI.TXT verifies only against the compiled `POLICY_PUBKEY` (`wificfg.rs:169-191`). | main.rs | **[VERIFIED] on main.** Fixed in (p1e): the anchor is pinned first, and `config_keys` chooses the key by source. |
| **C4** | **Keyless images accept every config file unsigned.** If no operator key is compiled in or pinned, WAN.TXT, POLICY.TXT and WIFI.TXT are trusted as-is (`main.rs:14171-14174`, `policysig.rs:10-13`). There is no release gate that keeps a keyless image out of production. | policysig, main.rs | **[VERIFIED]. Open in (p1e)** (its implementation note lists it as open). |

### A.2 High / medium gaps

| # | Gap | Evidence |
|---|---|---|
| H1 | **No persisted anti-rollback for WAN or WIFI.** POLICY has a floor in the anchor (`anchor.rs` `policy_floor`). WAN and WIFI are checked only against the active generation at upload time (`artstore.rs:267` (p1e)). `verify_wan` takes no floor. An older signed WAN.TXT, for example with old ISP credentials or an old VLAN, can be replayed from the card. | [VERIFIED] |
| H2 | **A refused WAN falls back to DHCP on an untagged link, not to the last known good config.** That fails safe, but it is still a denial of service at any site that needs a VLAN or PPPoE. In (p1e), a refused store copy falls back to the boot-partition file, never to the previous verified store half. | main.rs (p1e) `:3138`, `artstore.rs:351` `boot_fallback` |
| H3 | **No health-checked trial or commit for configuration.** ADR 0058 D2 promises "a failed boot of new settings falls back automatically". The store rolls back only when the loader refuses a copy (signature or parse error). A validly signed WAN with wrong PPPoE credentials stays active until the owner rolls back by hand over LAN or Wi-Fi. | `artstore.rs:373-418` (p1e); the implementation note says rule 7 is "metal test pending" |
| H4 | **Plaintext secrets at rest.** The PPPoE password (`WAN.TXT pppoe_pass=`) and the Wi-Fi PSK (`WIFI.TXT`) are stored in clear on the FAT partition and in the artifact store. Anyone with read access to the eMMC gets the ISP login and the Wi-Fi key. | `hal/src/lib.rs:443-452`, ADR 0058 Consequences ("rests on the device as today") |
| H5 | **Software floors and pins are not keyed.** The anchor (pinned key, POLICY floor, owner key) is protected only by an unkeyed SHA-256 in two alternating sectors (`anchor.rs:80-86`). An attacker with raw eMMC access can rewrite the pin or lower a floor. | [VERIFIED] (Explore sweep) |
| H6 | **No hardware root of trust for HBoot. SEC-3 is not done.** The Pi EEPROM bootloader loads `heqk8-*.img` without verifying it (`docs/design/heqk-svn-and-sec3-plan.md:42-46`). An attacker who can write the eMMC (CM5 rpiboot USB mode) replaces HBoot, reads customer OTP and derives the SRK. **Against a physical attacker, every software control below is advisory until SEC-3 lands.** | [VERIFIED] code and plan; [ASSUMPTION] that shipped units have no `SIGNED_BOOT` set |
| M1 | **Factory reset clears the owner config key and needs only the owner token.** It is guarded by the token, re-authentication and `confirm=ERASE` (`http.rs:314`, `ownerapi.rs:454` (p1e), `factoryreset.rs:66` (p1e)). Re-enrolling afterwards needs the label key. So a stolen owner token is enough to destroy the configuration authority, and the token plus the label key is enough to take it over. | [VERIFIED] (p1e) |
| M2 | **`OWNER.TXT` is unauthenticated by design.** Writing it on the FAT replaces the Mission Control owner verifier (`mcauth.rs:89-93`). Combined with M1, a card writer can take over the config authority without touching the kernel. This is subsumed by H6 until SEC-3. | [VERIFIED] |
| M3 | **A signed WAN.TXT can widen `mgmt_floor` to /8.** That is the subnet that is never enforced against. Management-plane authority sits in the connectivity file. | implementation note §6 (p1e) |
| M4 | **Verify, then re-read.** The WAN code verifies one read of the sector and parses another read (`wan_signed` vs `load_wan_cfg`/`load_wan_link`). This is the structural cause of C2 and a latent time-of-check/time-of-use bug. | [VERIFIED] |
| M5 | **Fixing a bad cold-boot slot may loop resets.** HBoot halts on a bad signature, and the watchdog resets the SoC. On a tryboot attempt the system falls back to the `config.txt` slot. If the `config.txt` slot itself is bad, no third fallback was found. | [ASSUMPTION] (Explore sweep; not tested) |

### A.3 Implementation inventory

**1. Implemented and operational (proven on metal or in the QEMU gates)**
- HBoot verifies the kernel with hybrid Ed25519 + SLH-DSA-SHA2-128s and an SVN floor. The keys are compiled in (`boot-abi/src/verify.rs:35-45, 158-171`). A failure halts the boot (`hboot/src/main.rs:273-276`). The release gate rejects dev keys (`os/build/make-cm5-heqk-image.sh:48-69`).
- A/B kernel slots with a tryboot commit (`abboot.rs`). The eMMC write window is restricted to the boot-config sector, the inactive slot, the keystore and the DataVolume (`emmc.rs:490-520`, `store.rs:84-96`).
- POLICY.TXT is verified before it is parsed, against the operator key, with a persisted generation floor (`main.rs:14134-14177`, `policysig.rs`, `anchor.rs`). A refused policy leads to a management-sub-interface LOCKDOWN only (`main.rs:3221-3224`).
- The POLICY engine uses bounded fixed tables (8 ACLs × 32 entries, 16 prefix lists × 16, 16 routes, 16 bindings, a 4 KiB file). The whole file is rejected with a line number on any error, with no heap (`hal/src/policy.rs:35-44, 302-311`). **No defect was found. Keep it.**
- Signed content packs (BLOCK, ALLOW, IOC, OUI, DEVICES, RULES) go through `artstore` A/B halves with an atomic one-sector manifest commit and readback (`artstore.rs`).
- The device-pinned operator key (TOFU) refuses a conflicting key in a newer image (`anchor.rs` `decide`).
- SEC-2: stage-2 hides the VC mailbox, so OTP is not readable by a running signed kernel (`hboot/src/stage2.rs`, `mailbox.rs:140-187`).
- The owner journal is HMAC-chained with `HKDF(SRK)`. Sealed blobs are encrypt-then-MAC (`ownerjournal.rs:363`, `seal.rs`).
- Mission Control requires an owner session with CSRF and Origin checks. Every write needs re-authentication. TLS terminates in EL0 (`el0-tlshost`).

**2. Implemented but incomplete or not yet validated**
- ADR 0058 (p1e): the fail-closed WAN check, the anchor pinned first, the wan/wifi/policy upload types, the per-type A/B store, `/api/upload/rollback`, and owner-key enroll and rotate. All of it passes QEMU only, is not committed, and the metal journey check (`tools/diagnostics/cm5-config-journey-check.sh`) has not been run. **It still contains C2.**
- Anti-rollback for WAN and WIFI exists only at upload time (H1).
- The SRK-derived keys are absent on units where OTP was not provisioned (`hboot/src/main.rs:416,436`). On those units the journal and seal guarantees degrade, and the code says so.
- The HBoot SVN floor reads an OTP bit count, but `advance_floor` is never called from the boot path (`hboot/src/rollback.rs:120-126`). The effective floor is the compile-time `1`.

**3. Specified in an ADR but not implemented**
- ADR 0058 D2: automatic fallback after a failed boot with new settings (H3).
- ADR 0058 open item 1: a WebAuthn-aware verifier.
- ADR 0049 D1 rotation of the operator key (`anchor.rs` header: "Rotation … is not built"). The owner key rotation in (p1e) is separate.
- SEC-3 (Pi secure boot: signed `boot.img`, OTP key hash): plan only (`docs/design/heqk-svn-and-sec3-plan.md:51-89`).
- RPMB-backed floors: called "pending" (`hboot/src/rollback.rs:16-19`).

**4. Entirely missing**
- A canonical, versioned configuration object covering WAN, link, LAN, Wi-Fi and policy as one signed unit.
- Protection at rest for secrets (H4).
- Delegated administrator keys and a revocation mechanism.
- A configuration manager acting as the single writer, with stage, trial, health check, commit and auto-revert.
- A native CLI (`hsh`). The UART is output-only: the only `getc` sits inside driver code and the kernel never calls it.
- A management API ABI shared by CLI and UI.
- Any authentication for local, physical-presence management.
- A release gate that refuses keyless production images (C4).

### A.4 Hardware assumptions that need verification

| Claim | Status |
|---|---|
| CM5 has no TPM or secure element | [VERIFIED] in code: none used. Board-level: none on CM5. |
| CM5 eMMC exposes RPMB | [ASSUMPTION]: the driver logs the RPMB size (`emmc.rs:237-242`) but never uses it. The authentication-key write is a one-time manufacturing operation that cannot be undone. |
| BCM2712 customer OTP: block 1 holds the 256-bit secret, block 3 the SVN bits | [ASSUMPTION]: the tag `0x00030024` mapping has not been verified on metal (`mailbox.rs:283-287`). |
| The Pi EEPROM signed-boot flow (`SIGNED_BOOT`, `program_pubkey`) works on CM5 with heqk's `boot.img` | [ASSUMPTION]: plan only, not exercised. |
| The tryboot fallback covers a bad tryboot slot but not a bad committed slot | [ASSUMPTION] (M5). |
| The eMMC can be written by anyone with physical access (nRPIBOOT plus USB) | [ASSUMPTION], strongly expected. Treat it as true. |

---

## B. Target architecture

### B.1 Component diagram and trust boundaries

```
          OFF-DEVICE (owner custody)                              ON-DEVICE
 ┌───────────────────────────────────┐        ┌──────────────────────────────────────────────────────┐
 │ Owner key  K_own (Ed25519)        │        │ Pi EEPROM ──(SEC-3: verifies)──▶ HBoot (EL2)          │
 │  browser WebCrypto / hqcfg CLI /  │        │   trust root: K_boot (Ed25519+SLH-DSA), compiled      │
 │  later passkey (WebAuthn)         │        │   ──verifies──▶ heqk kernel image (EL1)               │
 │ Delegated admin keys K_adm        │        │                                                       │
 │ Config authoring: MC UI, hqcfg,   │  TB-1  │ ┌──── EL1 kernel ──────────────────────────────────┐  │
 │ AI Copilot (proposes, never signs)│───────▶│ │ cfgd (config manager, single writer)              │  │
 └───────────────────────────────────┘ signed │ │  verify(HQCFG bundle) → validate → stage → trial  │  │
             ▲  HTTPS (EL0 TLS)        bundle │ │  → health → commit / auto-revert → journal        │  │
             │                                │ │  reads anchor + floors (DataVolume, MAC'd)        │  │
 ┌───────────┴───────────┐  TB-2 mgmt ABI     │ │ protocol engines (unchanged): uplink, pppoe,      │  │
 │ Mission Control (UI)  │◀──────────────────▶│ │  VLAN/QinQ, policy ACL/prefix/route, wificfg      │  │
 │ hsh (EL0 component)   │  narrow messages   │ └───────────────────────────────────────────────────┘  │
 └───────────────────────┘                    │ EL0: el0-tlshost (HTTP parse), hsh, wasmhost          │
                                              │ Storage: FAT p1 = factory BASELINE only (read-only     │
                                              │   at runtime) · DataVolume: anchor/floors, cfg A/B,   │
                                              │   journal · [RPMB: floors, when provisioned]          │
                                              └──────────────────────────────────────────────────────┘
```

Trust boundaries:
- **TB-0, physical.** The eMMC and FAT are untrusted storage. Anything read from them is data until a signature verifies. Without SEC-3, TB-0 does not even protect HBoot (H6).
- **TB-1, owner authority.** A configuration takes effect only if it carries a signature from a key the anchor authorizes for that scope. Device-side authentication (a session or token) decides *whether to try* an operation. It never replaces the signature.
- **TB-2, the management ABI.** UI, hsh and Copilot reach cfgd only through a small fixed message set. Nothing above TB-2 writes kernel networking structures.
- **TB-3, EL0/EL1.** Parsers of untrusted network input (HTTP, TLS, DNS) and the CLI line editor run in EL0 (ADR 0050). The config grammar parser runs in EL1, but only on bytes that already verified. It is bounded, fuzzed and allocation-free.

### B.2 Separation of what the system *can* do, what the owner *authorized*, and runtime state

| Layer | Content | Storage | Authority |
|---|---|---|---|
| Kernel capabilities | Protocol engines, limits, crypto, verifiers, trust roots | Signed kernel image | K_boot |
| Authorized configuration | The HQCFG bundle: WAN, link, LAN, Wi-Fi, policy, management, tunnel | DataVolume config A/B (active plus last known good); the FAT holds only the factory baseline | K_own / K_adm (scoped); K_vend for the baseline only |
| Runtime state | DHCP leases, PPPoE session, link state, counters, neighbour tables | RAM (and the sealed evidence log) | none: derived, never fed back as configuration |

### B.3 Key hierarchy

| Key | Holder | Signs / does | Anchored by | Rotation / revocation |
|---|---|---|---|---|
| **K_boot** (Ed25519 + SLH-DSA) | HookProbe release (offline, HSM later) | HBoot and kernel images | Compiled into HBoot. **After SEC-3:** the hash of the RSA key that signs `boot.img` is in Pi OTP. | New image plus SVN. Revocation through the SVN floor (OTP bits). |
| **K_vend** (Ed25519, today's `HEQK_POLICY_PUBKEY`) | HookProbe or the MSSP operator | Content packs; the **factory baseline** config | Compiled into the kernel, then pinned on first use in the anchor | Existing anchor rule: a different key in a new image is refused. Rotation needs a handover signed by the pinned key (not built). |
| **K_own** (Ed25519; WebAuthn later) | Owner, off-device | Configuration bundles, delegations, rotation, transfer | Enrolled into the anchor (ADR 0058 D3) | `HQROT1` signed by the old key (strictly increasing generation). Loss requires physical-presence recovery (§E). |
| **K_adm,i** (Ed25519) | Delegated administrators | Bundles **limited to the scopes** in their certificate | A delegation certificate signed by K_own: `HQDEL1 ‖ adm_pk ‖ scope_bits ‖ epoch ‖ max_gen` | Bump the anchor's `delegation_epoch` (an owner-signed op), which revokes every certificate at once. Bounded table of 8. |
| **K_dev_enc** (X25519) | Device, derived as `HKDF(SRK,"HQCFG-ENC1")` | Decrypts secrets (PPPoE password, PSK) sealed to it | The public half is published at `GET /api/device` and in the factory record | Re-derived on every boot. It changes only if the OTP secret changes. |
| **K_dev_id** (existing, HKDF(SRK)) | Device | Device identity, TLS, journal MAC | OTP secret | — |

Two things are deliberately separate:
- **Encryption protects confidentiality and gives no authenticity.** The device publishes `K_dev_enc`, so anyone can encrypt to it. A sealed secret is accepted only inside a bundle signed with a key that is authorized for its scope.
- **The signature does not depend on the device secret.** A unit whose OTP was never provisioned (no SRK) still verifies configuration. It only loses at-rest secret protection, and the UI shows that state.

### B.4 The canonical configuration object (HQCFG1)

**The options considered:**
- **Deterministic CBOR.** It needs a new parser in EL1, and canonical-form rules differ between libraries, which invites parser differentials. Browsers have no built-in CBOR.
- **Pure binary TLV.** Smallest, but it means a second grammar next to the fuzzed text grammar, and humans cannot audit it.
- **The existing text grammar.** Already fuzzed (`main.rs:14711, 14980`), already producible byte-for-byte in a browser (the UI tests assert parity with `policy-sign.py`), and human-auditable.

**Recommendation [DESIGN]: canonical text sections inside a fixed binary envelope, with the signature over the exact envelope bytes.**

```
HQCFG1 bundle (≤ 16 KiB, one contiguous buffer)
 0  magic "HQCFG1\0\0"          8
 8  schema_version u16 LE          (refuse unknown major)
10  flags u16                      (bit0 device-bound)
12  generation u64 LE              (strictly increasing per device, anti-rollback)
20  device_id [16]                 (sha256(K_dev_id pub)[..16], all-zero = any device; refused if bound and ≠)
36  signer_key_id [8]              (sha256(signer pk)[..8], selects K_own / K_adm,i)
44  section_count u8, reserved [3]
48  section table: count × { kind u8, rsv u8, len u16 LE }   kinds: 1 wan 2 link 3 lan 4 wifi 5 policy 6 mgmt 7 tunnel 8 secrets
..  section bodies, concatenated, exactly len bytes each, no padding between
..  zero padding to the end of the buffer is NOT part of the bundle
sig: separate 512 B: "HQCSIG1\0" | alg u8 (1=Ed25519, 2=Ed25519+ML-DSA reserved) | total_len u32 | sha256(bundle[..total_len]) | sig over "HQCFG1-SIG" ‖ sha256
```

**Canonical text rules for section bodies (reject anything else):**
- ASCII 0x20-0x7E plus LF only. No CR, NUL, tab or trailing whitespace.
- One `key=value` per line. Keys come from a closed per-section set, and **each key may appear at most once**. Repeatable keys (ACL entries, routes) use indexed forms, as POLICY lines already do.
- Every line ends in LF. No blank lines and no comments inside the signed form. Comments are an export-only decoration and are stripped before signing.
- No byte before the header and none after `total_len`. **Every byte of the bundle that cfgd parses is a byte that was signed.**
- **Length comes only from the section table, never from padding.** The legacy POLICY.TXT is padded with `\n` to exactly 4096 bytes (`POLICY_FILE_LEN`, required by the device and `make-cm5-heqk-disk.sh`). That padding belongs to the legacy per-file form only. Inside HQCFG1 the `policy` section is unpadded, and its `len` is the exact statement text. When cfgd hands the section to `hal::policy`, it copies it into the engine's 4096-byte buffer and pads with `\n` itself, after verification, so no padding is ever signed or parsed as content.
- **Semantic duplicates** are refused as well as duplicate keys: the same list plus seq, a second `default` for one ACL, a duplicate interface binding, or a duplicate route `dst`+`from`. This matches the Mission Control builders, which enforce it in `assertCanonical()` (PR #967).

**Secrets section (kind 8):** `X25519(eph) ‖ ChaCha20-Poly1305(K = HKDF(ECDH, "HQCFG-SEC1" ‖ device_id ‖ generation), nonce 0, aad = header)`. It carries the `pppoe_pass` and `psk` values that the wan and wifi sections reference as `pppoe_pass=@secret:0`. These primitives are already in the tree for `securechannel` (`x25519`, `chacha20poly1305`). A secret encrypted for one generation cannot be cut and pasted into another bundle.

**Transition:** the per-file formats (WAN.SIG, WIFI.SIG, POLICY.SIG) remain accepted as *factory baseline* and *legacy upload* forms, with the C2 fix applied (parse exactly the signed bytes, zero tail). An HQCFG1 bundle is wire-compatible with the browser signer: it is one more fixed-layout message.

### B.5 Configuration lifecycle (cfgd)

```
 authenticate session ─▶ authorize op (role/scope) ─▶ receive bundle (≤16 KiB, staging area)
   ─▶ verify signature (key from anchor by key_id; scope ⊇ sections; device_id; generation > floor)
   ─▶ validate: strict grammar → semantic (subnet/gw sanity, VLAN 1..4094, PPPoE fields, ACL/route limits,
      capability check against the Platform Manifest, management-reachability invariant §B.6)
   ─▶ write INACTIVE half + readback ─▶ commit manifest (state = PENDING{gen, deadline}, atomic sector)
   ─▶ activate (next boot, or live for live-safe sections)
   ─▶ health window (default 5 min): WAN usable (lease / IPCP up + gateway answers) AND management reachable
      AND (if remote) owner CONFIRM received
   ─▶ COMMIT: manifest state = ACTIVE, raise floor(gen) ─▶ journal
   └▶ timeout / failure / reboot while PENDING ─▶ REVERT to last-known-good half ─▶ journal + alert
```

The design mirrors OTA tryboot and Junos-style `commit confirmed`.

**Crash consistency:**
- Only the manifest sector commit is atomic, and each step is idempotent.
- After power loss at any point, the device boots either the previous ACTIVE half or a PENDING half with a deadline. A PENDING half found at boot counts one trial. A second boot while still PENDING reverts.
- The floor is raised only on COMMIT. A reverted generation therefore never burns the floor.

### B.6 Invariants cfgd enforces (semantic validation)

1. **Management reachability.** A bundle must not remove every management path. At least one of these must remain: LAN, Wi-Fi setup network, or the management sub-interface, with a `mgmt in` ACL that admits the management floor. If not, the bundle is refused before staging.
2. **`mgmt_floor` lives in the `mgmt` section** (the policy authority), not in `wan`. Legacy WAN.TXT `mgmt_floor` is honoured only when it is signed **and** is a subset of the management sub-interface subnet (M3).
3. Resource limits: the existing `hal::policy` caps. Bundle ≤ 16 KiB. Section count ≤ 8.
4. Capabilities: a section that requests something the manifest does not grant (for example `wifi` on a unit without Wi-Fi) is refused. It is never silently ignored.

### B.7 Boot and recovery flow

```
HBoot verifies kernel (halt on fail; tryboot falls back to the committed slot)
 └▶ kernel: anchor::boot (pin/keep K_vend; load K_own, delegations, floors; verify anchor MAC if SRK)
     └▶ cfgd: candidate = store ACTIVE (or PENDING trial) ─verify+validate─▶ apply
          fail ─▶ store LAST-KNOWN-GOOD half ─verify+validate─▶ apply (alert "config reverted")
          fail ─▶ FAT factory baseline (K_vend or K_own signed, ≥ baseline floor) ─▶ apply
          fail ─▶ SAFE DEFAULT: WAN DHCP untagged, LAN + setup AP up, mgmt LOCKDOWN on the mgmt VLAN,
                  POLICY = built-in default; Mission Control on the LAN shows "configuration refused: <reason>"
     never: an unsigned or unverified byte as configuration (on a keyed device)
```

**Recovery path:** the LAN and setup-AP management network (ADR 0054 per-device credential) is always available, because it does not depend on any WAN setting. The physical-presence recovery (§E.6) is the last resort, and it never needs vendor involvement.

### B.8 Management environment

- **One ABI (TB-2).** cfgd exposes about ten messages:
  - `state()`
  - `stage(bundle, sig)`
  - `confirm(gen)`
  - `rollback()`
  - `enroll(pk, pop)`
  - `rotate(msg, sig)`
  - `delegate(cert)`
  - `revoke_epoch(msg, sig)`
  - `challenge()`
  - `recovery(...)`

  The Mission Control HTTP handlers, hsh and the Copilot tool layer are thin clients of this ABI.
- **hsh runs as an EL0 component, not in the kernel.** The reasons:
  - the line editor and command parser handle untrusted input (ADR 0050 placement rules);
  - an EL0 fault cannot corrupt kernel networking state;
  - the existing EL0 host pattern (`el0-tlshost`, `el0-lansvc`) already gives isolation at a few KiB of code.

  The cost is one more EL0 image and a syscall-style message path, both of which exist.
- **The device never holds K_own,** so hsh cannot sign. hsh can do three things:
  - read state and diagnostics (view role);
  - stage a **pre-signed** bundle, pasted or read from USB;
  - build an **unsigned draft** and print its sha256 as hex or QR. The owner signs that digest off-device (phone or laptop `hqcfg sign-digest`) and pastes the signature back.
- **Authentication:**
  - UART input is **disabled in production images** (compile feature).
  - When it is enabled, a session starts at the view role and needs a challenge-response to elevate: the device prints a nonce, and the owner key signs `HQCHAL1 ‖ device_id ‖ nonce`.
  - The owner token is accepted as a second factor, never as the only factor for key operations.
- **Roles:**
  - `view`: read-only.
  - `operate`: confirm or rollback to an already-signed generation.
  - `config:<scopes>`: carries a signed bundle within its delegated scopes.
  - `owner`: enroll, rotate, delegate, revoke, transfer.
  - `recovery`: physical presence only.
- **Audit:** every ABI call (accepted or refused) is a record in the HMAC-chained owner journal (`ownerjournal.rs`): op, key_id, generation, bundle sha256, result, reason. Mission Control and hsh display the same log.
- **AI Copilot** produces a draft bundle and a diff (the "plan as a diff" UX rule). It never holds a key, and the owner signs.

---

## C. Threat model

**Assets:** WAN connectivity (availability); management reachability; ACL and policy integrity (the network's security posture); ISP credentials and Wi-Fi PSK (confidentiality); configuration authority (the anchor: K_own, delegations, floors); audit-log integrity.

| Attacker | Capability | Main attacks | Mitigation | Residual risk |
|---|---|---|---|---|
| **A1 remote WAN** | Packets to the WAN | Reach management; malformed input | Mission Control not served on the WAN; mgmt LOCKDOWN on refused policy; EL0 parsers | Engine bugs in PPPoE, DHCP or IPv6 (fuzzed; separate scope) |
| **A2 LAN / Wi-Fi client** | On the management network | Brute-force the owner token; CSRF; upload a config | Session plus CSRF and Origin checks; re-authentication; **a config needs an off-device signature** (a session alone is not enough) | Can trigger already-signed rollbacks only if it holds the owner token |
| **A3 owner-token thief** | Mission Control session | Factory reset that wipes K_own (M1); stage a malicious config | A signature is required for config. **Fix M1:** clearing K_own needs a K_own signature or physical presence | Can roll back within the signed history (bounded by floors) and erase owner data (visible, journaled) |
| **A4 physical, card-write** (rpiboot or eMMC access, minutes) | Read and write all storage while the device is off | Edit WAN.TXT (C1, C2); replay older signed files (H1); delete files (DoS); read secrets (H4); rewrite anchor and floors (H5); replace OWNER.TXT (M2); **replace HBoot (H6)** | C1-C2 fixes; per-type floors; fallback to last-known-good; secrets sealed to K_dev_enc; anchor MAC'd with HKDF(SRK); **SEC-3 secure boot**; RPMB floors | **Until SEC-3: full compromise.** After SEC-3: DoS by wiping the DataVolume (the device falls back to the baseline or safe default) and rollback of floors via a raw-eMMC snapshot unless RPMB is used. |
| **A5 next-image builder** (compromised vendor pipeline or MSSP) | Ships a validly signed kernel | Swap the config key; disable verification | TOFU pin of K_vend (exists); K_own enrolled outside the image; reproducible builds and SBOM | A malicious signed kernel can do anything at EL1. This is the vendor trust root, same as every OS. |
| **A6 delegated admin** | K_adm with scopes | Exceed scope (for example touch `mgmt`) | Scope bits checked per section; epoch revocation; journal | Abuse within scope until revoked |
| **A7 insider at the factory** | Provisioning station | Pre-enroll their own K_own | Enrollment happens at the customer (ADR 0058 D3), never at the factory; the anchor state is visible in Mission Control | — |

**Trust assumptions:** Ed25519 and SHA-256 are sound. HBoot and the kernel are what K_boot signed. After SEC-3, the Pi ROM and EEPROM verify HBoot. The owner protects K_own. The BCM2712 OTP is not readable by EL1 after SEC-2 [VERIFIED in code; metal-proven per memory].

---

## D. ADR

See [ADR 0059](../adr/0059-secure-configuration-management.md).

---

## E. Implementation roadmap

**MVP order (operator, 2026-11-10):** Phase 0 → Phase 1 (HQCFG1) → Phase 2 (cfgd) → Phase 5 (management ABI + `hsh` at EL0).

**Not in the confirmed order:** Phase 3 (secrets), Phase 4 (delegation), Phase 6 (hardware). RPMB (6c) is already under a direct operator instruction to the heqk session and is not deferred. The operator decides how these and SEC-01 (ADR 0050 D4) interleave with steps 2–4.

**Ownership:**
- **Kernel phases:** the heqk session.
- **Bundle producer (`configBuild.ts`/`signing.ts`) and `os/kernel/tools/hqcfg.py` byte parity:** the Mission Control UI session.
- **Spec and review:** ADR 0059.

Security defects come first. Every phase is independently shippable and gated by `validate.sh` (QEMU), `mc-e2e.sh` and, where noted, metal.

### Phase 0: close the defects (in progress or small)

| Step | Change | Files | Tests | Acceptance |
|---|---|---|---|---|
| **0.1** | Land ADR 0058's fail-closed WAN path, with the anchor pinned first (C1, C3) | heqk session, PR #950: `main.rs`, `policysig.rs`, `artstore.rs`, `upload.rs`, `anchor.rs` | its `[P-anchor]`, `[P-artstore]`, `[P-upload]`, mc-e2e | On a keyed device, an unsigned or failed WAN.TXT means DHCP, untagged, no mgmt sub-interface |
| **0.2** *(heqk session: **done, QEMU PASS 2026-11-10**: one verified buffer, `WanCfgErr::Duplicate`, `[P-wansig]` covers the PoC. The zero-tail rule was **not adopted**; see ADR 0059 open item 4)* | **C2 / M4:** verify and parse **one buffer**: `wan_signed` returns the verified `&[u8]`, and both WAN parsers take `&sec[..len]`. Require `sec[len..]` to be all zero. Add `WanCfgErr::Duplicate` and reject repeated keys in `parse_wan_cfg` and `parse_wan_link`. Apply the same zero-tail rule to every len-prefixed pack verifier. | `kernel/src/main.rs` (`wan_signed`, `load_wan_cfg`, `load_wan_link`), `hal/src/lib.rs` (parsers), `policysig.rs` (`verify_wan` returns len), `artstore.rs` | `[P-wansig]` new vectors: appended-after-len refused; nonzero tail refused; duplicate `mode`/`vlan` refused. `[P-wancfg]` duplicate vectors. Fuzz corpus entry. Host PoC (§F) turned into a hal unit test. | The PoC fails, and all existing WAN vectors pass |
| **0.3** *(heqk session, next)* | **H1:** per-type generation floors for WAN and WIFI in the anchor (record v3: `wan_floor`, `wifi_floor`), raised on accept and enforced on **both** the FAT and store paths | `anchor.rs`, `policysig.rs` (`verify_wan(.., floor)`), `wificfg.rs`, `artstore.rs` | `[P-anchor]` v2 to v3 migration; replaying an older WAN.SIG is refused after a newer one was accepted; reboot persistence | An older signed WAN.TXT dropped on the card is refused |
| **0.4** *(heqk session, next)* | **H2:** if the active WAN or WIFI fails to load, fall back to the **other store half** when it verifies, then to the FAT baseline, then to DHCP | `artstore.rs` (`boot_fallback` tries the other half), `main.rs` WAN block | QEMU: corrupt the active half, and the boot uses the previous generation | A tampered active half never forces DHCP when a good previous half exists |
| **0.5** *(heqk session, next)* | **C4:** release gate. A `prod` image without `HEQK_POLICY_PUBKEY` fails the build. Keyless images print `CONFIG UNPROTECTED` at boot and in `GET /api/anchor`, and Mission Control shows a red banner. | `os/build/make-cm5-heqk-image.sh`, `tools/ci/gates.sh`, `kernel/build.rs`, `http.rs` | gate test: a keyless prod build fails | No production artifact can accept unsigned config |
| **0.6** *(heqk session: **done, QEMU** 2026-11-10. A token reset keeps K_own; only a reflash clears it. The HQRST1 and physical-presence path stays in Phase 4/E.6)* | **M1:** clearing K_own in a factory reset needs an owner-key signature (`HQRST1 ‖ device_id ‖ nonce`) or physical presence (§E.6). A token-only reset keeps K_own. | `ownerapi.rs`, `factoryreset.rs`, Mission Control reset dialog | `[P-ownerapi]`: a token-only reset keeps the owner key | Owner token alone cannot remove the config authority |

### Phase 1: canonical grammar and HQCFG1 verifier (pure, no I/O)
- **Files:**
  - new `kernel/src/cfgbundle.rs`: envelope parse plus verification. No heap. One 16 KiB static buffer.
  - `hal/src/lib.rs`: a strict-canonical mode for the WAN and link parsers.
  - `os/kernel/tools/hqcfg.py`: successor to `policy-sign.py`, which stays.
  - `os/mission-control/src/store/configBuild.ts` and `signing.ts`: emit a bundle.
- **Interfaces:**
  - `cfgbundle::verify(buf, sig, anchor) -> Result<Verified<'_>, CfgErr>`
  - `Verified::sections() -> impl Iterator<(Kind, &[u8])>`
- **Tests:**
  - `[P-cfgbundle]`: valid; a byte flipped anywhere in the header, table or body; truncation; trailing bytes; section overlap; len overflow; unknown kind; unknown major schema; wrong device_id; unknown key_id; a scope violation; an older generation.
  - Byte parity between UI, `hqcfg.py` and the kernel vectors.
- **Accept:** fuzz 10⁶ iterations clean, and verification takes under 5 ms on CM5.
- **Risk:** the grammar freezes. Mitigation: `schema_version`, where a minor version adds keys and a major version is refused.

### Phase 2: cfgd lifecycle (stage, trial, commit, revert)
- **Files:**
  - new `kernel/src/cfgd.rs`;
  - `artstore.rs`: manifest state PENDING or ACTIVE, deadline, trial count;
  - `main.rs`: boot candidate selection §B.7, health window hooks reusing OTA trial health (`main.rs` `[OTA] trial` around `:3878-3953`);
  - `http.rs`: `/api/config/{stage,confirm,rollback,state}`.
- **Tests:**
  - QEMU: a bad-PPPoE bundle reverts after the deadline; a reboot while PENDING reverts on the second boot; confirm commits and raises the floor; a revert does not raise the floor.
  - Power-loss injection at each write (§F).
- **Accept:** metal journey: a signed bad WAN reverts by itself within 5 min, with Mission Control reachable on the LAN throughout.
- **Depends on:** Phase 1, and 0.3 for the floors.

### Phase 3: secrets at rest
- **Files:** `kernel/src/cfgsecret.rs` (X25519 + ChaCha20-Poly1305 from existing crates); `GET /api/device` publishes `enc_pk`; the UI encrypts in the browser (WebCrypto X25519 where available, else a vendored TweetNaCl-equivalent).
- **Tests:** decrypt OK; a wrong device fails; a cross-generation paste fails; a tampered ciphertext fails; a unit without OTP reports "secrets not protected at rest".
- **Accept:** `strings` on a DataVolume dump shows no PSK or PPPoE password.

### Phase 4: delegation, revocation, mgmt_floor move
- **Files:** `anchor.rs` (delegation table of 8, `delegation_epoch`), `cfgbundle.rs` (scope check), POLICY and `mgmt` grammar (`mgmt_floor`).
- **Tests:** an in-scope admin bundle is accepted; out of scope is refused; an epoch bump revokes; legacy WAN `mgmt_floor` outside the mgmt subnet is refused.

### Phase 5: management ABI and hsh (EL0)
- **Files:** new `os/kernel/el0-hsh/`; `kernel/src/mgmtabi.rs` (message enum, bounded); `rp1_uartp` RX path behind feature `console-in` (off in prod); HTTP handlers rewired as ABI clients.
- **Tests:**
  - `[P-mgmtabi]`: every message, with authorization per role;
  - hsh: a challenge-response elevates, a replayed challenge is refused;
  - UART disabled in a prod build (symbol absent).
- **Accept:** Mission Control and hsh produce identical journal records for the same operation.

### Phase 6: hardware anchoring (manufacturing operations, which are Red and never autonomous)
- **6a, SEC-3:** Pi EEPROM signed boot (`boot.img` + `boot.sig`, `program_pubkey`). This is a precondition for any claim against attacker A4. Files: `os/build/`, `docs/design/heqk-svn-and-sec3-plan.md`.
- **6b, anchor MAC:** `HMAC(HKDF(SRK,"HQANCH-MAC"), record)`. Units without OTP stay on the unkeyed hash, reported honestly.
- **6c, RPMB:** the floors (POLICY, WAN, WIFI, CFG, the kernel SVN) are mirrored into RPMB with its write counter. The authentication key is derived from SRK and written once as a separate manufacturing step.
- **6d:** wire `advance_floor` for the HBoot SVN (OTP bits), used sparingly because it cannot be undone.

### E.6 Physical-presence recovery (used by 0.6 and lost-key recovery)
- Physical presence means proof that someone at the device can act: holding the setup button during power-on (or, on boards without a button, three power cycles within 60 s) puts the device into a 10-minute recovery window.
- In that window, the LAN or setup AP accepts `recovery` operations:
  - clear K_own (the delegations follow);
  - re-enroll;
  - reset the configuration to the factory baseline.
- Each use is journaled and is shown permanently in Mission Control ("ownership reset on <date> by physical presence").
- **Ownership transfer:** the old owner signs `HQXFER1 ‖ new_pk ‖ gen`, which is the same operation as a rotation. Without the old owner, use physical-presence recovery.

---

## F. Test strategy

| Category | Tests | Where |
|---|---|---|
| Signature verification | Valid; wrong key; another tag (cross-pack); key_id unknown; key revoked (epoch); scope exceeded | `[P-policy-sig]`, `[P-wansig]`, new `[P-cfgbundle]` (QEMU selftests in `validate.sh`) |
| Tampering | A byte flip anywhere; **appended after the signed length (C2 PoC)**; nonzero tail; duplicate key; CRLF or NUL injection in canonical mode; edits to the section table | hal unit tests, `[P-wansig]`, fuzz harness (`main.rs:14711`) |
| Replay / rollback | An older generation from the FAT, from the store and over the upload; the floor persists across reboot; anchor sector rollback (raw write of an old anchor), which is detected once 6b or 6c lands and is documented as residual until then | `[P-anchor]`, QEMU disk-image manipulation script |
| Malformed configuration | Bad VLAN (0, 4095); gateway outside the subnet; /31 and /32 rules; PPPoE without a user; an over-long field; ACL table full; unknown key; unknown schema major | `[P-wancfg]`, `[P-policy]`, fuzz |
| Semantic invariants | A bundle that removes every management path is refused; a `mgmt_floor` wider than the management subnet is refused; a capability not granted is refused | `[P-cfgd]` |
| Privilege escalation | Token-only factory reset keeps K_own; an admin key outside its scope; a session without a signature cannot stage; the vendor key cannot sign a store copy after enrollment (`config_keys`); UART RX absent in prod | `[P-ownerapi]`, `[P-anchor]`, mc-e2e negative cases, a symbol check in the gate |
| Interrupted writes / power loss | A `BlockDev` fault injector in the QEMU harness: fail or tear the write *k* for every *k* during stage, commit and floor raise. Assert after reboot that the device runs the ACTIVE or the last-known-good config and that the floor is never ahead of an applied generation. | new `tools/diagnostics/cfg-powercut.sh` (QEMU), then metal with a relay-switched supply |
| Failed activation | A signed bundle with bad PPPoE credentials or a wrong VLAN reverts within the deadline; a reboot during PENDING reverts on the second boot | QEMU with a simulated AC; metal `cm5-config-journey-check.sh` |
| Recovery | Management loss on the WAN keeps the LAN and setup AP up; the physical-presence window works; lost-key recovery; corrupt store means baseline then safe default | metal checklist |
| Regression | The existing WAN, VLAN, QinQ, PPPoE and policy selftests unchanged; CM5 metal acceptance (prod-mc) | `validate.sh`, `mc-e2e.sh`, metal |

**PoC reproduction (C2), host-only:** a scratch crate that depends on `os/kernel/hal` calls `hal::parse_wan_cfg` and `hal::parse_wan_link` on a sector holding `"HQWAN1\nmode=dhcp\n"` followed by `"mode=static\nip=203.0.113.9/30\ngw=203.0.113.10\nvlan=4000\n"`. The result is `Static{203.0.113.9/30}`, VLAN 4000, while `sector[..17]` equals the signed bytes. Run it from outside `os/kernel` so that the kernel's `.cargo/config.toml` (build-std) does not apply. Phase 0.2 must turn this into a failing-then-passing hal test.

---

## Status log

### 2026-11-10: build progress (heqk session)

**Pushed: `a1486fe6` on `feat/heqk-prod-phases`.** Validate GREEN and mc-e2e PASS. Metal is pending
(`cm5-config-journey-check.sh`). It contains:
- the C2 fix (one verified buffer; duplicate keys refused);
- 0.6 (a token-authorised factory reset keeps K_own).

**Being validated on `wip/next2`:**
- 0.3 (WAN/WIFI floors, anchor v3)
- 0.4 (`artstore::fallback_step`: active half, then the other half, then FAT)
- 0.5 (release gate; "CONFIG UNPROTECTED"; `/api/anchor` reports `config_protected`)
- step 2 (`cfgbundle.rs`, checked against the UI's 24 shared vectors)
- step 3 (`cfgd.rs`, `/api/config{,/confirm,/rollback}`)

**Review findings sent to the heqk session (open):**
1. **cfgd commits on "WAN usable" alone.** §B.5 also needs management reachable, plus an owner confirm for
   remote changes. Otherwise a bundle that breaks the management VLAN auto-commits and locks out remote
   management.
2. **No D7 management-reachability check before staging.**
3. **A committed bundle that fails verification at boot skips the last-known-good half.**

**Residual risk accepted for now:** `anchor::accept_gen` keeps a one-generation rollback window. A card writer
can therefore replay the immediately previous signed WAN/WIFI file from the FAT partition. This is subsumed by
H6 (SEC-3 is open). The proposed hardening is to allow the window only on the owner-authenticated store path.
