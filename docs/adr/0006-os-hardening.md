# ADR 0006 — OS hardening posture + roadmap (immutable bootc security appliance)

**Status:** ✅ Accepted (2026-07-01) — phased. H1 (branding + KSPP sysctls) + H1b (splash/banner) +
H2 core (secure-boot UKI signing + measured-boot PCR attestation) landed. H2 follow-on (key
enrollment, PCR-sealed secrets, remote attestation) + H3–H5 open.
**Date:** 2026-07-01
**Deciders:** os-architect (author), security, code-developer
**Relates to:** [`Readme.md`](../architecture/Readme.md) (supply chain / PQC invariants), [ADR 0002](0002-crypto-agility-pqc.md)
(crypto posture), [ADR 0003](0003-platform-manifest-schema.md) (capability model), [ADR 0005](0005-unified-ebpf-detection.md)
(eBPF dataplane — the hardening must not break it). Grounded in a 2026-07-01 deep-research pass
(competition teardown + Linux-hardening survey; sources at the end). Verification was rate-limited
mid-run, so claims are trusted from PRIMARY sources (bootc.dev, Bottlerocket, KSPP, NIST, vendor docs).

## Context

We are an *OS product*, so trust + hardening are the product, not a feature. The competition survey
settles the strategic question: **almost every modern network/security OS is Linux under the hood** —
Cisco IOS-XE (Linux + IOSd as a process), NX-OS (Wind River Linux 5), Palo Alto PAN-OS (Linux),
Arista EOS (Linux + SysDB), Aruba CX (Linux microservices), Cumulus/SONiC (Debian) — with **FortiOS
(proprietary + FortiASIC) and Junos (FreeBSD) the outliers**. They brand it via a custom `os-release`,
a custom CLI, signed images, and an ASIC/NPU fast path. **HookProbe's Debian-bootc + branded Mission
Control + Wasm modules + (future) silicon is the mainstream modern pattern, just more immutable.**

The reference implementation to copy is **AWS Bottlerocket** (an immutable security OS): dm-verity
rootfs (fail-closed), SELinux enforcing-by-default, kernel Lockdown "integrity" — and it explicitly
sets `lockdown=none` on the NVIDIA variant that must load unsigned modules, i.e. **the exact
hardening-vs-functionality tradeoff we have with eBPF**. bootc's own **composefs** backend gives us
the native path: sealed images signed with OUR Secure Boot keys, the composefs digest embedded in the
UKI kernel cmdline, fs-verity — a firmware-to-userspace chain of trust.

## Decision — principles

1. **Harden without breaking our own dataplane.** We use eBPF/XDP + Wasm heavily. `unprivileged_bpf_disabled=1`
   is SAFE (our loader is privileged, `CAP_BPF`). Kernel Lockdown must be **integrity** mode (not
   confidentiality) and must still permit privileged BPF prog load + signed module load. `rp_filter`
   is NOT forced globally (breaks multi-WAN failover + the routed AP) — RPF is done selectively in the
   eBPF engine via `bpf_fib_lookup` on the WAN role.
2. **Brand the OS.** `os-release` presents `ID=hookprobe` (+ `ID_LIKE=debian` for tooling
   compatibility). This is both product identity AND a hardening/packaging necessity (systemd-sysext
   extension-release match, compliance scanners).
3. **Trust is measured + signed end-to-end.** Secure Boot with our keys → signed UKI → measured boot
   (TPM PCRs) → composefs-sealed rootfs (fs-verity) → cosign-signed modules/sysexts → SBOM/CBOM/SLSA.
4. **Self-audit, and show it.** Run OpenSCAP against CIS/STIG/ANSSI profiles in CI + on-device; render
   the result as a hardening score the operator sees (feed the QSECBIT / Security-Score orb).
5. **PQC-first for long-lived trust.** FIPS 140-3 + PQC coexist (AWS-LC FIPS 3.0 ships ML-KEM). Boot/
   firmware signing uses LMS/XMSS (NIST SP 800-208, CNSA 2.0) — field firmware outlives classical RSA.

## The phased roadmap (most security-per-effort first)

- **H1 — cheap wins, NO new subsystems (LANDED with this ADR):**
  - `os-release` branding (`ID=hookprobe`, `ID_LIKE=debian`, `SYSEXT_LEVEL`).
  - KSPP hardened sysctls: `kptr_restrict=2`, `dmesg_restrict=1`, `yama.ptrace_scope=1`,
    `kexec_load_disabled=1`, `perf_event_paranoid=2`, no-redirects, `log_martians` (already had
    `unprivileged_bpf_disabled=1`, `ip_forward=0`-by-default).
  - TODO H1b: finish systemd sandboxing on the 7 remaining privileged units (add `NoNewPrivileges` +
    scoped `ReadWritePaths` where they don't already need broad access); strip setuid binaries; the
    Plymouth boot splash + first-boot banner (ships with the branding).
- **H2 — measured + secure boot (CORE LANDED):**
  - ✅ **Secure Boot signing** — `security/secureboot/generate-keys.sh` mints the PK→KEK→db hierarchy;
    `sign-uki.sh` signs the mkosi UKI with `db` + verifies (sbsign/sbverify). Tested: signs the real
    157 MB arm64 UKI, verifies against our db, correctly REJECTS a foreign cert. Keys gitignored →
    KMS/HSM in prod. Capability-gated: UEFI targets enforce it; the Pi (GPU/u-boot boot, no UEFI-SB)
    relies on H3 integrity instead — the UKI is still signed (harmless, enforced where checked).
  - ✅ **Measured-boot attestation** — `measured-boot-report.sh` + `hookprobe-measured-boot.service`
    read the TPM 2.0 PCRs from **sysfs** (0/4/7/11 — no tpm2-tools dep) → `boot-attestation.json`
    {tpm, secure_boot, uki_measured, posture, integrity_score}. Runs everywhere; reports honest
    `software` posture where there's no TPM (Pi). Feeds the QSECBIT score. Tested on real TPM hardware.
  - ⏳ Follow-on: enroll PK/KEK/db per platform (mokutil / `efi-updatevar`); `systemd-pcrphase` +
    PCR-seal a device secret / the data-partition LUKS key to PCR 7+11; remote-attestation quote to the
    PoP (fits the TPM-bound identity we already have).
- **H3 — rootfs integrity (CORE LANDED for the Pi):**
  - ✅ **dm-verity mechanism + tooling** — `security/verity/build-verity.sh` formats a hash tree +
    root hash over the rootfs; `rootfs-integrity-check.sh` + `hookprobe-rootfs-integrity.service`
    report the posture (enforced / verified / tampered / none) → QSECBIT. Tested: pristine rootfs
    verifies, flipping ONE 512 B block makes `veritysetup verify` FAIL (fail-closed) — a rootkit can't
    hide. This is the Pi's primary boot-integrity mechanism (no TPM / no UEFI-SB), and matches our
    immutable design (RO root, writable state on /var/lib/hookprobe). Mirrors Bottlerocket's dm-verity.
  - ⏳ **H3a wired opt-in** in `make-pi4-image.sh` (`HOOKPROBE_VERITY=1`): computes + stores the verity
    anchor on p1, off by default until Pi-boot-validated (keeps the proven build intact).
  - 🧪 **H3b (full RO verity-boot) — BUILT, validating on the Pi:** initramfs-tools hooks
    (`base/initramfs/`): `local-top/hookprobe-verity` runs `veritysetup open` → `/dev/mapper/hpverity`
    (root hash + hash-tree location from cmdline; hash tree stored on the FAT boot partition);
    `local-premount/hookprobe-overlay` lays a writable **tmpfs overlay** over the RO verified root so
    services can still write /etc,/var (persistent SOC state is on its own /var/lib/hookprobe mount).
    **FALLBACK-SAFE**: any failure (missing hash tree, tamper, wrong hash) → a dm-linear passthrough so
    the Pi still boots unverified rather than bricking. `make-pi4-image.sh HOOKPROBE_VERITY=1` seals the
    rootfs post-populate + repoints `cmdline` to `root=/dev/mapper/hpverity ro`. Pi has no TPM/UEFI-SB,
    so the root hash isn't hardware-anchored (an attacker with physical SD write could re-verity) —
    this gives immutability + remote-tamper/corruption fail-closed detection; hardware anchoring waits
    on a TPM/secure-element (HookProbe silicon).
  - For the **bootc/UEFI path**, prefer native **composefs** sealed images (fs-verity + composefs
    digest in the UKI cmdline) — same guarantee, no custom pipeline.
  - **Follow-up (ADR 0016 D4):** artifact-hash signing (per-module payload digest, pinned inside
    the signed `module.yaml`, recomputed and compared before the supervisor executes it) is now the
    platform-independent floor that holds even where verity is `none` (cloud/N100/VM). The two are
    complementary, not redundant — verity can't tell a legitimate OTA payload update from tampering
    across a delta, and artifact-hash signing can't protect files outside the registry it enumerates.
    Recommendation carried forward here: extend verity from `verified`/`none` to `enforced` on the
    non-Pi image paths (cloud/N100/edge-pro/VM) as a follow-up H3 revision — not done by ADR 0016,
    which only records the dependency and ships the module-level floor.
- **H3c — data-at-rest confidentiality (LANDED: policy + tooling):** encrypt ONLY the data partition
  (LUKS2 + dm-integrity), not the public rootfs. Auto-unlock via **capability-driven Clevis**
  (`security/crypt/enroll-clevis.sh`): `tpm2` pin (local, standalone-safe) / `tang` (network, fleet) /
  `sss t=1 {tpm2,tang}` (both). **Network (Tang) unlock is ADDITIVE, never required** — the
  standalone-by-default invariant applied to disk: a local pin or a mandatory recovery keyslot always
  keeps an air-gapped device bootable. TPM-sealed unlock reuses H2's `seal-luks-tpm.sh`. Honest
  trilemma for a bare, TPM-less, headless, air-gapped Pi (auto-unlock + confidentiality + no-local-
  secret can't all hold) → default **integrity-only** (dm-verity); confidentiality needs a TPM/secure-
  element (or HookProbe silicon). Full matrix + rationale in `security/crypt/README.md`.
- **H4 — MAC:** confine services default-deny. **AppArmor first** (native to Debian, far lower effort
  than authoring SELinux policy on a Debian base); revisit SELinux-enforcing (Bottlerocket model) if a
  market demands it. Profile the privileged units (ovs, bootstrap, the eBPF loader).
- **H5 — compliance + PQC + FIPS:** OpenSCAP + SCAP-security-guide self-audit (CIS Level 1/2, DISA
  STIG, ANSSI) → QSECBIT hardening score in Mission Control; kernel FIPS mode + AWS-LC/OpenSSL FIPS for
  regulated markets; CNSA 2.0 LMS/XMSS boot-signing; keep the ML-KEM/ML-DSA hybrid (ADR 0002).
- **Cross-cutting supply chain:** SLSA build provenance (incremental — per-build, no transitive
  requirement), in-toto, Syft/Trivy SBOM + CVE scan of the image in CI (gate on criticals), reproducible
  builds, CBOM per image.

## Consequences

- H1 landed: `base/config/os-release` + expanded `base/config/sysctl.d/90-hookprobe.conf`, staged by
  `builder/mkosi-arm64/build-arm64.sh`. Presents as HookProbe OS; KSPP sysctls applied at boot.
- The eBPF dataplane constrains the boot-lockdown + module-signing choices (H2/H4) — validate every
  hardening flag against `napse-capture` load on real target kernels before shipping (the Bottlerocket
  NVIDIA-variant precedent is our template for documenting the tradeoff).
- Nothing here blocks Phase C (HTP/SASE tunnel); H1/H2 should land alongside it.

## Sources (deep research 2026-07-01; verification rate-limited → trusted from primary sources)

- Competition: developer.cisco.com (Open NX-OS = Wind River Linux 5, RPM/yum); en.wikipedia
  (IOS-XE = Linux + IOSd process); juniper.net (Junos = FreeBSD); nvidia.com (Cumulus = Linux/Debian).
- Hardening: github.com/bottlerocket-os SECURITY_FEATURES.md (dm-verity fail-closed, SELinux enforcing,
  Lockdown integrity + the NVIDIA lockdown=none tradeoff); bootc.dev experimental-composefs (sealed
  images, UKI digest, fs-verity); kspp.github.io (kptr_restrict=2, dmesg_restrict=1, ptrace_scope,
  LOCKDOWN_LSM_EARLY / STRICT_KERNEL_RWX / STACKPROTECTOR_STRONG / INIT_ON_ALLOC_DEFAULT_ON).
- PQC/FIPS: aws.amazon.com (AWS-LC FIPS 3.0 = first FIPS-140-3 module with ML-KEM; X25519MLKEM768
  hybrid); csrc.nist.gov + uefi.org + thalestct.com (SP 800-208 LMS/XMSS + HSS/XMSS_MT approved for
  firmware signing; CNSA 2.0 wants them for code/firmware; UEFI spec being genericized for PQC).
- Compliance/supply-chain: docs.redhat.com (OpenSCAP + SCAP Security Guide profiles: DISA STIG, CIS,
  ANSSI, PCI DSS); slsa.dev (build levels incremental, no transitive requirement).

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: HARD.** bootc/composefs/dm-verity/UKI/LSM/KSPP are all Linux and are removed on the rpi-native tier. heqk provides measured boot + RO integrity + W^X + capability isolation **natively** (arguably simpler and stronger); the hardening *intent* survives, every named mechanism is re-decided. → **Phase M3**.
