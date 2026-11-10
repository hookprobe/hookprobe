# Decision record — customer OTP provisioning and eMMC RPMB key programming (2026-11-10)

**Status: AWAITING OWNER APPROVAL.** Nothing in this record has been executed. No OTP or RPMB write was made
during the autonomous work, and none will be made without the owner's explicit, separate authorisation.

| Decision | Classification | Treatment until decided |
|---|---|---|
| D-OTP — customer OTP provisioning | **Production blocker** | Production readiness = **BLOCKED**. Normal images never write OTP (`otp-provision` is a separate HBoot build). |
| D-RPMB — eMMC RPMB key programming | **Owner decision required** | No RPMB access exists in the code (the eMMC driver has no partition-switch path). Evidence (RPMB size) collected read-only. |
| WPA3 on the AP | **Evidence in (batch 30): no alternative firmware needed** | `[WIFI-CAP] sae=false sae_ext=true mfp=true fwsup=false` — the host runs SAE (external SAE) and PMF is supported. WPA3-SAE + PMF is now a build item (Phase 6). |

---

## D-OTP — customer OTP provisioning

### What it is
HBoot built with `--features otp-provision` reads customer OTP block 1 (8 × 32-bit words). If it is blank,
it generates 256 bits from the hardware TRNG **on the device** (refusing if any of the 8 words came from a
non-live RNG), burns them with `SET_USER_OTP` block 1, reads them back, and uses them only if the read-back
equals what was written and has enough set bits (`hboot/src/ak_derive.rs`, `hboot/src/mailbox.rs`). The
burn is constrained to the customer block — it cannot reach the serial, bootloader or device-key rows. From
the OTP secret HBoot derives:
- the per-device **attestation key** (Ed25519 + SLH-DSA), and
- the **sealing root key** `SRK = SHA-256("HEQK-SEAL-SRK-v1" ‖ OTP)`, handed to the kernel once and scrubbed.

### Why it blocks production
With blank OTP, HBoot hands over **no SRK**, and every SRK consumer fails closed:
- no HTTPS key for Mission Control (`[MC-TLS] OFF`);
- owner policy journal RAM-only (owner rules lost at reboot);
- no sealed evidence log (detections lost at reboot);
- no per-device setup-AP credential;
- attestation uses the **software** AK, whose private half is tracked in `hboot/src/attest_keys.rs` — its
  quotes prove nothing.

The unit is secure (it fails closed), but it is not a sellable product.

### Irreversible implications
- OTP bits only go 0 → 1. A burned secret can never be changed, rotated or erased; the unit's AK and SRK are
  fixed for life.
- A burn with weak entropy would weaken that unit permanently. Mitigations already in code: TRNG liveness
  required for all 8 words, read-back equality, minimum popcount; any failure → no burn / software AK.
- A partial burn (power cut mid-write) leaves a unit that can never be provisioned correctly; it falls back
  to the software AK and must be treated as scrap for production (detectable: `low-entropy (partial burn)`).

### Recovery implications
- No recovery of a burned secret is possible or needed: it never leaves the device; derived keys are
  re-derived every boot.
- Data sealed under the SRK (journal, evidence log, TLS key) is unreadable on any other unit and after any
  change of the derivation constants — a new derivation label is a data-loss event for every field unit.
- The EL2 stage-2 carve (SEC-2, metal-proven) keeps a compromised EL1 kernel from reading OTP; on-device
  supervisor code (HBoot) can. This is the documented ceiling — not HSM-grade.

### Dependencies
- Signing-key custody (register item 1): the factory image that carries `otp-provision` must itself be
  signed by the production key.
- The verifier side (MSSP / enrolment) must reject `otp_provisioned=0` quotes in production.
- D-RPMB depends on D-OTP if the RPMB key is derived from the SRK (recommended below).

### Recommended implementation (for approval)
1. A **factory provisioning station**, not a field action: a dedicated, signed HBoot build with
   `otp-provision`, run once per unit on the line, followed by flashing the product image (which never
   writes OTP).
2. The station records the unit's public AK (and serial) in the manufacturing database and keeps the boot
   log (`ak : … provisioned`, read-back equality) as the unit's provisioning evidence.
3. A post-provisioning self-test on the station: `[MC-TLS]` ON, sealed journal and evidence log mount,
   attestation quote with `otp_provisioned=1` verified against the recorded AK.
4. Units that report `partial burn` / `low-entropy` / `TRNG not fully live` are quarantined, never shipped.
5. Release builds exclude the software AK private keys (audit §2.1 #8), so a blank unit cannot attest at all.

**Approval requested:** authorise (a) the factory-station approach above and (b) a first provisioning of
**one designated test unit** (not the bench CM5 used for development unless you choose it). Until then:
production readiness = BLOCKED.

---

## D-RPMB — eMMC RPMB key programming

### What it is
RPMB is a small authenticated partition inside the eMMC. Writes need an HMAC-SHA256 under a 256-bit key that
is programmed **once** into the eMMC and can never be read back or changed; every authenticated write
increments a monotonic write counter that cannot be rolled back. Reads are unauthenticated but come back with
a MAC the host verifies.

### Why it matters (the security benefit)
Today the owner journal, the sealed evidence log and the pack/POLICY generation floors live in the eMMC user
area. Someone holding the card (or a full-disk image from earlier) can restore an **older consistent copy**:
an owner's later block or revoke disappears, an older signed pack comes back. Every copy is validly
MAC'd, so nothing on the same medium can tell old from new. An RPMB-anchored high-water mark can.

### The important distinction
Programming the key **does not by itself protect anything**. The protection exists only when:
1. the journal's rollback state (its epoch, last sequence number and head MAC) is written to RPMB with each
   committed change, **and**
2. recovery (journal replay at boot) **checks** the replayed head against that RPMB record and treats a
   mismatch as a rollback.
Both must be implemented and demonstrated; until then RPMB adds nothing.

### Irreversible implications
- The key is write-once: a wrong or lost key means RPMB can never be written again on that unit (reads still
  work, but no new high-water marks → rollback detection stops; the unit stays functional).
- The write counter is finite (2³²) — RPMB must hold a compact high-water record updated per owner change
  (rare), never per detection.
- Programming needs the first partition-switch code in the eMMC driver (CMD6 to `PARTITION_ACCESS`).
  The current driver deliberately has **no** switch path (one wrong EXT_CSD index can brick the boot
  area). That code needs its own review, a fixed switch-back-to-user-area discipline and fault tests.

### Recovery implications
- Factory reset: RPMB contents cannot be deleted, only overwritten (authenticated). A factory reset must
  write a fresh "empty journal, epoch E+1" record — no special recovery path.
- eMMC replacement (board rework): a new eMMC has an unprogrammed RPMB → provisioned on first boot like a new
  unit; the old journal is unreadable anyway (SRK-sealed, same unit) — the owner re-applies settings.
- If the key is derived from the SRK, it can always be recomputed on that unit; nothing to back up.
- A detected rollback must not brick the unit: proposed behaviour = owner rules from the rolled-back journal
  are **not** applied, an alert is raised, Mission Control asks the owner to re-authenticate and re-apply.
  Forwarding, IPS and the signed baseline are unaffected (ADR 0023 fail-open for customers).

### Dependencies
- **D-OTP first** (recommended key = `HKDF(SRK, "HQ-rpmb-key-v1")`: no key storage, unit-unique, no
  extra secret in any image). Without OTP there is no SRK, hence no RPMB key.
- Evidence (batch 30, read-only probe): `[EMMC-RPMB] RPMB_SIZE_MULT=32 (RPMB partition 4096 KiB) REL_WR_SEC_C=1 EXT_CSD_REV=8` —
  an eMMC 5.1 part with a 4 MiB RPMB partition: ample for the high-water record. Nothing was accessed.

### Recommended implementation (for approval)
1. eMMC driver: a reviewed RPMB module — switch to the RPMB partition, authenticated read / write-counter
   read / authenticated write, **always** switch back to the user area; never touches boot partitions.
   Key programming is a separate, explicitly-gated function (like `otp-provision`), never reached by a
   normal image.
2. One RPMB record `{magic, version, journal epoch, last seq, head MAC, POLICY floor, per-pack floors}`.
3. Journal append: write the journal record, then the RPMB record (crash between the two = journal one
   ahead of RPMB → accepted, RPMB caught up on boot; journal behind RPMB → rollback).
4. Replay: compare; a rollback → owner rules not applied + alert + owner re-auth flow.
5. QEMU model of RPMB (counter + MAC) for the gate; metal on one designated unit after approval.

**Approval requested:** (a) whether to use RPMB at all; (b) if yes, the SRK-derived key and the gating
above; (c) which unit may be programmed first. Until then: the rollback gap is documented in SECURITY.md
and the human register.

---

## WPA3 on the AP — evidence in (batch 30, 2026-11-10)
Verbatim from the CM5 serial console (`docs/design/metal-evidence/20261110-batch30.md`):
`[WIFI-CAP] sae=false sae_ext=true mfp=true fwsup=false idsup=false | ap sta wme … mfp sae_ext fbt …`

- `sae_ext` — the firmware supports **external SAE**: the host performs the SAE (dragonfly) commit/confirm
  exchange and hands the PMK to the firmware, exactly as heqk already runs the WPA2 4-way handshake on the host.
- `mfp` — 802.11w protected management frames (needed for WPA3, optional for WPA2).
- `fwsup` / `idsup` absent — no in-firmware supplicant/authenticator (known; heqk does it on the host).

**Conclusion: no alternative vendor firmware is required.** WPA3-SAE (with PMF, WPA2/WPA3 transition mode) is
a host-side build item in Phase 6: SAE over P-256 (hash-to-element), the auth-frame exchange through the
firmware's external-auth path, PMF/IGTK in the authenticator, then metal tests with WPA3 phones.
