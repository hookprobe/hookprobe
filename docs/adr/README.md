# Architecture Decision Records

Numbered, never renumbered. The current product is heqk everywhere (**ADR 0047**); ADRs written for the
bootc/Debian Linux tier remain as dated records and apply only to `legacy/linux-tier/` (path map:
[`docs/PATHS.md`](../PATHS.md)). Each ADR's own **Status** line is authoritative; this index is a summary
(as of 2026-11-09). Current gap/decision status: [`heqk-parity-gaps.md`](../design/heqk-parity-gaps.md),
[`heqk-decisions-2026-11-08.md`](../design/heqk-decisions-2026-11-08.md).

| # | Title | Status | Superseded by |
|---|---|---|---|
| [0001](0001-mission-control-stack.md) | Mission Control technology stack (Astro + SolidJS) | Accepted, locked | backend hosting: 0047 D2 |
| [0002](0002-crypto-agility-pqc.md) | Crypto-agility & post-quantum (PQC) layer | Accepted (amended 2026-11-09) | — |
| [0003](0003-platform-manifest-schema.md) | The Platform Manifest schema | Accepted | — |
| [0004](0004-secure-edge-transport.md) | Secure edge-to-edge transport: evolve HTP / NEURO / DSM | Accepted (amended 2026-11-09) | — |
| [0005](0005-unified-ebpf-detection.md) | Unified eBPF detection across the fleet | Accepted (Linux tier) | — |
| [0006](0006-os-hardening.md) | OS hardening posture + roadmap (immutable bootc appliance) | Accepted (Linux tier) | — |
| [0007](0007-data-at-rest-encryption.md) | Signed releases + data-at-rest encryption | Accepted (Linux tier) | — |
| [0008](0008-rbac-admin-operator.md) | Admin/operator RBAC | Accepted | — |
| [0009](0009-soc-brain-edge-cloud.md) | The SOC brain: two-tier detect→track→trace→display | Accepted | — |
| [0010](0010-zero-touch-provisioning.md) | Zero-touch provisioning: the captive portal | Accepted (portal not built; 2026-07-17 amendment Proposed) | — |
| [0011](0011-product-cortex.md) | Product Cortex: agentic PLM on the evidence graph | Accepted | — |
| [0012](0012-release-definition-cortex-pass.md) | What a release is: versioning, channels, rings | Accepted | — |
| [0013](0013-cortex-evolution-apis.md) | Product Cortex evolution | Accepted | — |
| [0014](0014-continuous-improvement-detection-lifecycle.md) | Continuous-improvement detection lifecycle | Accepted (2026-07-15 amendment Proposed) | — |
| [0015](0015-registry-driven-module-inclusion.md) | Registry-driven module inclusion | Accepted (Linux tier) | — |
| [0016](0016-artifact-hash-signing.md) | Artifact-hash signing | Accepted (Linux tier) | — |
| [0017](0017-authenticated-aot-cache.md) | Authenticated AOT cache | Accepted (Linux tier) | — |
| [0018](0018-inline-quarantine-safety.md) | Inline quarantine safety: confirm before you drop | Accepted | — |
| [0019](0019-bootc-debian-substrate.md) | The bootc/Debian substrate | Accepted (Linux tier) | in part by 0047 |
| [0020](0020-adversarial-resilience-harness.md) | Adversarial resilience harness | Accepted with conditions | — |
| [0021](0021-multiarch-native-artifact-digests.md) | Multi-arch native-artifact digests | Accepted (Linux tier) | — |
| [0022](0022-behavioral-quarantine-vs-static-allowlists.md) | Dynamic behavioral quarantine replaces static allowlists | Accepted | — |
| [0023](0023-enforcement-separation.md) | Enforcement separation | Accepted | — |
| [0024](0024-exploitability-vex-pipeline.md) | Exploitability & VEX pipeline | Accepted | — |
| [0025](0025-aegis-byo-llm-planner.md) | AEGIS BYO-LLM planner | Accepted | — |
| [0026](0026-sigma-yara-detection.md) | Sigma + YARA rule ingestion | Accepted | — |
| [0027](0027-hydra-ioc-threat-intel-enrichment.md) | HYDRA's IOC/threat-intel lens | Accepted | — |
| [0028](0028-rbac-enforcement.md) | RBAC enforcement | Accepted | — |
| [0029](0029-unified-pi-fatboot-dual-kernel.md) | Unified Raspberry Pi fat-boot image | Superseded | 0043 / 0047 |
| [0030](0030-single-kernel-convergence-bridge.md) | Fat-boot improvements + single-kernel convergence bridge | Superseded | 0043 / 0047 |
| [0031](0031-dataplane-performance-strategy.md) | Data-plane performance strategy | Accepted (Linux tier) | — |
| [0032](0032-custom-edge-kernel-btf-mainline-rp1.md) | BTF-enabled edge kernel | Superseded | 0043 / 0047 |
| [0033](0033-dns-sinkhole-rpz.md) | DNS sinkhole / RPZ enforcement | Accepted (Linux tier) | — (heqk counterpart: 0052) |
| [0034](0034-adaptive-wifi-regdomain-and-calibration.md) | Adaptive Wi-Fi: regdomain + calibration | Accepted (Linux tier) | — |
| [0035](0035-substrate-ownership-underlay-overlay.md) | HookProbe Linux: substrate ownership & underlay/overlay | Proposed | — |
| [0036](0036-verifiable-supply-chain-reproducible-bootstrappable.md) | Verifiable supply chain | Proposed | — |
| [0037](0037-zero-touch-onboarding-flasher-provisioning.md) | Zero-touch onboarding & flasher-as-factory | Proposed | — |
| [0038](0038-ai-tiers-bpf-lsm-process-trust.md) | AI tiers & BPF-LSM process trust | Proposed | — |
| [0039](0039-system-minimization-image-cleaning.md) | System minimization & image cleaning | Proposed | — |
| [0040](0040-experience-ux-ui-scope-gui-features.md) | The experience layer: UX, UI scope, GUI features | Proposed | — |
| [0041](0041-container-vm-overlay-management.md) | The container & VM overlay | Proposed | — |
| [0042](0042-wifi-security-surface-wids-and-radio-tiers.md) | Wi-Fi as a security surface (WIDS) | Proposed | — |
| [0043](0043-heqk-microkernel-substrate.md) | The heqk microkernel substrate | Ratified | in part by 0047 |
| [0044](0044-zero-linux-rpi-native-cm5.md) | Zero-Linux on CM5 | Ratified | in part by 0047 (D2) |
| [0045](0045-default-dev-test-credentials.md) | Default dev/test credentials | Proposed | — |
| [0046](0046-github-migration-and-key-custody.md) | GitHub migration & key custody | Proposed (migration done 2026-11-07) | — |
| [0047](0047-heqk-everywhere-on-device-mission-control.md) | heqk replaces Linux everywhere; Mission Control on device | Ratified | — |
| [0048](0048-RESERVED.md) | Reserved: BOI / HookProbe Behavioural Genome | Reserved, not cut | — |
| [0049](0049-wan-policy-authority-and-ipv6-source-identity.md) | WAN policy authority, IPv6 source identity | Accepted | — |
| [0050](0050-heqk-parser-placement-el1-vs-el0.md) | heqk parser placement: EL1 vs EL0 | Accepted | — |
| [0051](0051-mission-control-https.md) | Mission Control HTTPS | Accepted | — |
| [0052](0052-shield-v2-dns-protection-on-heqk.md) | Shield v2: DNS protection on heqk | Accepted / implemented | — |
| [0053](0053-operator-write-actions-on-device.md) | Operator write actions in on-device Mission Control | Accepted with modifications | — |
| [0054](0054-ap-provisioning-per-device-credential.md) | Wi-Fi AP provisioning: per-device setup credential | Accepted (increment 1 built) | — |
| [0055](0055-owner-policy-journal.md) | Owner policy journal: durable owner settings from Mission Control | Proposed contract (direction approved 2026-11-09); amends 0053 D1/S7 | — |
| [0056](0056-device-upload-interface.md) | Device-side upload interface (signed artifacts over HTTPS) | Proposed contract (direction approved 2026-11-09); flasher countersign pending | — |
| [0057](0057-shield-protection-levels.md) | Shield protection levels (categories + relaxed/balanced/strict) | Implemented, metal-proven | — |
| [0058](0058-owner-signed-runtime-config.md) | Owner-signed configuration on a running device (WAN, Wi-Fi, policy) | Proposed (operator decision 2026-11-10: the owner signs in the browser) | 0056 (extends D2, answers open item 2) |
| [0059](0059-secure-configuration-management.md) | Secure configuration management: signed-bytes-only rule, HQCFG1 bundle, cfgd trial/commit/revert, key hierarchy, hsh at EL0, recovery | Proposed (2026-11-10; evidence: `docs/design/secure-config-assessment-2026-11-10.md`) | 0049 D1, 0056, 0058 (amends D2/D3/Consequences) |
| [0060](0060-heqk-smp-execution-model-core-roles-bkl.md) | heqk SMP execution model, core roles (DP/CP/MG), admission-time allocation, transitional BKL with gates | Proposed (2026-11-11; operator direction recorded, review pending) | Replaces `os/kernel/ARCHITECTURE.md` single-core contract (after D3) |
| [0061](0061-heqk-memory-budgets-and-admission.md) | heqk memory discovery, budgets and admission (every byte budgeted, no overcommit) | Proposed (2026-11-11) | — |
| [0062](0062-heqk-microarchitectural-isolation-multi-tenant-pop.md) | Microarchitectural isolation and verified security eligibility for multi-tenant SASE PoPs (V0: eligibility verified, never configured) | Proposed (2026-11-11; operator decisions recorded, review pending) | Amends `HEQK_REMEDIATION_PLAN.md` §4.4, `SECURITY.md` CNTPCT residual, ADR 0050 |
| [0052 CI/CD](0052-autonomous-cicd-gate-spine-and-heal-loop.md) | Autonomous CI/CD gate spine and heal loop (**duplicate number** — proposed renumber to 0058, operator decision) | Proposed; gates implemented | — |

Implementation status per ADR, with code evidence and deviations: `docs/design/heqk-audit-2026-11-10.md` §2.
