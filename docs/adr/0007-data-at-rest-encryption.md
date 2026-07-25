# ADR 0007 — Signed releases + data-at-rest encryption (open OS, encrypted crown jewels)

**Status:** ✅ Accepted (2026-07-02) — phased. Executes on top of the validated `/usr`-verity (ADR 0006
H3, done + reboot-proof). Supersedes the earlier draft; folds in the operator's refined plan.
**Deciders:** operator (plan below), os-architect.
**Relates to:** [ADR 0006](0006-os-hardening.md) (verity/integrity), [ADR 0002](0002-crypto-agility-pqc.md)
(PQC/crypto-agility), `security/crypt/README.md`.

## The decision that resolves open-vs-closed

**The OS stays OPEN (GitHub, Apache-2.0); the proprietary crown jewels are ENCRYPTED.** Open source is a
*trust* feature for a security product (auditability) — and dm-verity proves the public code is genuine
("code-signing"). Confidentiality is reserved for what's actually secret: **AI models, threat intel,
TLS certs, API tokens, credentials, and customer operational/capture data.** This gives commercial-grade
IP + data protection *without* closing the platform.

| Asset | Location | Mechanism | Why |
|---|---|---|---|
| Code / OS | `/usr` (public → GitHub) | **dm-verity** (integrity) | genuine + untampered; no secrecy |
| Boot | `/boot` (FAT) | plaintext + **signed** | firmware reads it before any key exists |
| **Models · intel · certs · tokens · secrets · data · logs** | **encrypted data volume** | **plain dm-crypt (no header)** | the real IP + customer confidentiality |

## Platform strategy (this shapes the root of trust)

| Platform | Role | Root of trust for factory key | Storage |
|---|---|---|---|
| **CM5** | ✅ **Supported / primary** | **OTP secure-boot key** (device-bound, soldered) | **eMMC = OS+firmware+key · SD = customer data (encrypt + enlarge)** |
| **N100 / x86 appliance** | ✅ Supported | **TPM 2.0** (seal to PCRs) | NVMe/SSD |
| **Pi 4** | Community (cheaper) | none strong → **documented limitation** | single SD (OS+data together → weaker factory key) |
| **Future HookProbe silicon** | 🎯 Endgame | built-in secure element | — |

**The CM5 split is the model:** OS + factory key on **eMMC** (soldered, hard to clone) · customer data
on **SD** (removable, dm-crypt, customer can encrypt + resize). Clone/steal the SD → encrypted, and the
key isn't on it. Pi 4 (single SD) gets the same software but a weaker anchor — a community limitation.

## Unlock model (no TPM on Pi/CM5-without-OTP → tiered)

Zero-touch by default, hardening opt-in — matching the operator's setup-wizard flow:

- **Factory key (default, zero-touch):** master key auto-unlocked at boot, wrapped by the platform
  anchor (CM5 OTP / N100 TPM / Pi4 device-salt[weak]). **Protects: SD removed/cloned.** Does NOT protect
  a stolen whole appliance (be honest in docs).
- **Customer-managed passphrase (opt-in, strong):** re-wraps the master key under a passphrase set in the
  wizard → protects against physical appliance theft too. Needs entry (or a management-channel prompt).
- **Recovery key** + **key rotation** — offered on the wizard's advanced-security page.
- **Network-bound (Clevis/Tang, fleet):** key wrapped by the PoP; additive, never required (air-gap
  falls back to a local pin). See `security/crypt/`.

Plain dm-crypt (no header): `--type plain --cipher aes-xts-plain64 --key-size 512 --hash sha256`; the
cipher recipe lives in the initramfs, the key is externally supplied (never plaintext on the SD). AES-256
is already **quantum-safe** (Grover only halves → 128-bit) — no PQC needed on the disk; PQC belongs on
the *key delivery / tunnel / signatures* (ADR 0002).

## Zero-touch first boot (no keyboard/monitor/serial)

```
Power on → factory-key auto-unlock → HookProbe starts → Wi-Fi AP "HookProbe" @ 192.168.4.1
        → user connects → Web dashboard → Setup Wizard
Wizard: hostname · admin account · Wi-Fi/Ethernet · static/DHCP · timezone · NTP · cloud (opt)
        · Advanced Security: [factory key ▸ customer passphrase ▸ recovery key ▸ rotate]
```
Reuses the SASE-edge built-in AP. Operators later get **dashboard RBAC only — no shell/SSH/OS account**
(admin holds root + the disk key).

## Signed releases (installation aborts if unsigned)

Every HookProbe GitHub release is **cosign-signed** (image + SBOM/CBOM). Self-built images are unsigned
and allowed (a build-from-source flag skips the gate). Enforcement:
1. **`hookprobe verify <image>`** flashing/verify tool — checks the cosign signature before `dd`.
2. **CM5/Pi EEPROM secure boot** — the EEPROM verifies a signed `boot.img`; combined with our signed
   UKI/kernel = a real firmware→userspace chain. **CM5 OTP** makes this strong (stretch on Pi 4).
3. Unsigned official-channel image → **abort**.

## Phases (build in order; validate each on hardware before the next)

- **E0 — `/usr`-verity** ✅ DONE (enforced, reboot-proof, ADR 0006 H3).
- **E1 — Encrypt the DATA volume** (plain dm-crypt): models, intel, certs, tokens, secrets, `/var/lib/
  hookprobe`, logs. LOWEST risk (off the boot path — unlocks post-boot). Factory keyfile for now (E3
  hardens the anchor). **← STARTING NOW** (on the Pi 4; identical on CM5-SD / N100).
- **E2 — Move remaining secrets** off the plaintext root into the encrypted volume (`/etc` creds, keys),
  bind-mount them back → "closer to full disk" without encrypting the public OS.
- **E3 — Platform-bound unlock anchors:** CM5 OTP · N100 TPM-seal · Pi4 device-salt · customer passphrase
  · Clevis/Tang. Per-capability (manifest-gated). Reuse `seal-luks-tpm.sh` + `enroll-clevis.sh`.
- **E4 — Admin/operator RBAC + signed-release gate + setup wizard:** operators = dashboard-only; the
  `hookprobe verify` tool; the AP→wizard first-boot with the advanced-security encryption page.

## Consequences

- Encryption (confidentiality) and verity (integrity) are orthogonal and coexist — no self-poisoning
  (dm-crypt is read-write-native).
- On CM5, the eMMC/SD split is the reference; the manifest capability-gates the anchor per platform.
- Boot partition stays plaintext (integrity-anchored by the signed image + verity root hash, not secret).
- Retention/offload/QSECBIT operate on the decrypted runtime view — unchanged.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: HARD.** dm-crypt/dm-verity/initramfs key delivery are replaced by heqk-native block encryption + a heqk unlock path anchored in the OTP/attestation chain `hboot` already establishes. The "open code, encrypted crown-jewels" intent survives. → **Phase M3**.
