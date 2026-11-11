# ADR 0058: implementation notes (2026-11-10)

ADR 0058 (owner-signed runtime configuration) is accepted and is not changed here. This note covers how it was built and checks it against the operator's eight configuration rules (2026-11-10). It also lists the choices that need a security review.

## Checked against the operator's rules

| # | Rule | Where it holds | Evidence |
|---|---|---|---|
| 1 | No customer WAN settings in the kernel image | WAN.TXT is a file on the boot partition (or the staged store), never compiled in | `os/build/make-cm5-heqk-disk.sh` |
| 2 | Default DHCP at first boot | No WAN.TXT means DHCP. An unverified WAN.TXT, when an operator key exists, also means DHCP | `main.rs` WAN block |
| 3 | Owner public key enrolled at initial provisioning | `POST /api/anchor/enroll`: one-shot, owner re-authentication, proof of possession | `[P-anchor]`, mc-e2e |
| 4 | Owner signs and uploads WAN / Wi-Fi / policy from Mission Control | Upload types `wan`, `wifi`, `policy` (staged, applied at next boot) | `[P-artstore]`, `[P-upload]`, mc-e2e |
| 5 | A/B store, generation tracking, rollback | Artifact store halves per type; a second manifest group (sectors 2/3) for the staged types; `POST /api/upload/rollback` re-verifies the other half | `[P-artstore]` |
| 6a | WAN.TXT parse = exactly the signed bytes | Fixed after peer review (ADR 0059 finding C2): appended lines after the signed length used to override it; duplicate keys are refused | `[P-wansig]` |
| 6 | Verify the signature before parsing or applying | Every loader verifies first. **Fixed in this change:** WAN.TXT connectivity settings used to apply even when the signature failed (only the management floor was skipped). The trust anchor is now also pinned before WAN.TXT is read | code review; metal pending |
| 7 | Management recovery network stays up if a WAN change disconnects | The LAN and Wi-Fi management network does not depend on the WAN. Rollback is served on it | **metal test pending:** a signed WAN.TXT with bad PPPoE credentials, then Mission Control over LAN/Wi-Fi, then rollback |
| 8 | A WAN file never overrides the signed baseline or weakens management access | WAN.TXT cannot touch POLICY (ACLs / management `in` policy). See the open point on `mgmt_floor` below | code review |

## Choices that need a security review (G46)

1. **Key scope.** The owner key verifies only the *configuration* files: WAN.TXT, WIFI.TXT, POLICY.TXT. Vendor content packs (blocklist, allowlist, IOC, rules, OUI, devices) keep the vendor/pinned key. Without this split, enrollment would immediately orphan every factory-signed threat pack.
2. **Enrollment gate.** Requires an owner session, re-authentication of the owner token, a proof of possession (the new key signs `HQENR1 ‖ key`), and no owner key already enrolled. The request context has no ingress interface, so it does not check "setup network / physical presence". Mission Control is not served on the WAN.
3. **Rotation.** Signed by the enrolled key over `HQROT1 ‖ new key ‖ generation (u64 LE)`, with the generation strictly increasing. The new key also proves possession.
4. **Factory reset keeps the owner key** (ADR 0059 Phase 0.6, 2026-11-10). Holding the owner token alone must not be enough to swap the owner key. A full reflash (physical access) resets it. An owner-signed reset (`HQRST1`) is ADR 0059 Phase 2.
5. **Key choice by source (no lock-out).** A configuration file read from the artifact store (an upload) verifies only with the owner key. The factory baseline on the boot partition also verifies with the vendor key until the owner replaces it. Without this, enrolling would turn the shipped POLICY.TXT into a management LOCKDOWN. Nothing remote writes the boot partition: OTA writes only the kernel slots, and anyone who can edit the card has physical access, which counts as the owner. `policysig::config_keys`, `[P-anchor]` key scope.
6. **Open point on `mgmt_floor` (rule 8).** A *signed* WAN.TXT may set `mgmt_floor` (`/8`..`/32`), the subnet that is never enforced against. A wide floor weakens enforcement. Options:
   - move the floor into POLICY;
   - clamp it to the management sub-interface subnet.

   Not changed without a decision.

## Not autonomous

The RPMB authentication-key write and OTP fuses stay behind separate manufacturing operations (operator, 2026-11-10).
