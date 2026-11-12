# Security Policy

## 🔒 HookProbe Security

HEQK (Hardened Edge Quantum-safe Kernel) is the microkernel at the base of the HookProbe platform. Security is our top priority, both in the design of the system and in how we handle security reports.

---

## 📋 Supported Versions

We actively support the following versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| main (pre-1.0) | ✅ All security reports actively triaged |

HEQK is pre-release; every security report is triaged against `main`.

---

## 🚨 Reporting a Vulnerability

### ⚡ Critical Security Issues

If you discover a **critical security vulnerability** that could compromise HookProbe deployments:

**DO NOT** open a public GitHub issue.

Instead, please report it privately:

📧 **Email**: qsecbit@hookprobe.com  
🔐 **PGP Key**: Available at upon request 
⏱️ **Response Time**: Within 24 hours for critical issues

### 📝 What to Include

Please provide:

1. **Description**: Clear explanation of the vulnerability
2. **Impact**: What an attacker could achieve
3. **Reproduction Steps**: Detailed steps to reproduce
4. **Affected Versions**: Which versions are vulnerable
5. **Suggested Fix** (optional): Your proposed solution
6. **Proof of Concept** (optional): Code or screenshots

### 📧 Security Report Template

```
Subject: [SECURITY] Brief Description

Vulnerability Type: [e.g., SQL Injection, XSS, Authentication Bypass]
Severity: [Critical/High/Medium/Low]
Affected Component: [e.g., rule plane / verifier, PPPoE client, IPv6 firewall, Mission Control HTTP, hboot]
Affected Versions: [e.g., 4.0, 3.x]

Description:
[Detailed description of the vulnerability]

Impact:
[What an attacker could achieve]

Steps to Reproduce:
1. [Step one]
2. [Step two]
3. [etc.]

Suggested Fix:
[Your proposed solution]

Additional Information:
[Any other relevant details]
```

---

## 🔐 Security Response Process

### Timeline

1. **Initial Response**: Within 24 hours (acknowledgment)
2. **Triage**: Within 48 hours (severity assessment)
3. **Fix Development**: 1-7 days (depending on severity)
4. **Patch Release**: Coordinated disclosure timeline
5. **Public Disclosure**: 90 days after fix (or sooner if agreed)

### Severity Levels

| Severity | Response Time | Examples |
|----------|--------------|----------|
| **Critical** | < 24 hours | Remote code execution, authentication bypass, data breach |
| **High** | < 48 hours | Privilege escalation, XSS in admin panel, SQL injection |
| **Medium** | < 7 days | CSRF, information disclosure, denial of service |
| **Low** | < 14 days | Minor information leaks, non-exploitable bugs |

---

## 🛡️ What heqk actually does (current truth, updated 2026-11-12)

> This section replaced a feature list copied from the **V1 Linux stack** (VXLAN pods, Django/NAXSI, Logto,
> Grafana, a Kali countermeasure container, rsyslog/Loki, containers, default `admin/admin` credentials,
> unauthenticated internal APIs). **None of those exist in heqk**; their hardening advice does not apply.
> Every item below carries a label: **[metal-proven (`<evidence>`)]** passed on CM5 silicon, with the record
> named; **[QEMU only]** passed the `validate.sh` / `mc-e2e` gates, never run on silicon; **[metal pending]**
> built and QEMU-green, the named metal check has not run yet; **[not built]**; **[blocked (`<reason>`)]**.
> Evidence paths are relative to the repository root; design docs named `heqk-*.md` are in the repository-root
> `docs/design/`. Older items tagged plain **[metal]** were recorded
> before the evidence-link rule (2026-11-12); where a record is known it is now named, otherwise the item
> says so. Release readiness is decided by `tools/release-gate/items.txt`, not by this list.

**Kernel & boot**
- Rust `no_std` capability microkernel on aarch64; EL2 carve-out makes the OTP/mailbox unreachable from EL1.
  **[metal-proven (`os/kernel/PRODUCTION_READINESS.md` "Done since July")]**
- Signed boot (`hboot`), A/B tryboot with commit-on-health and anti-rollback.
  **[metal-proven (`docs/design/metal-evidence/20261110-ota-a1.md`, `20261110-batch29.md`)]**
- Sealed persistence bound to the device root key (SRK) and the measured-boot policy; crash-consistent A/B
  snapshot slots. **[metal-proven (`docs/roadmap/BuildPlan.md` Change Log 2026-09-08, M3.2 / M3.3)]**
- Seal nonce (HQKSEAL1) is now synthetic and content-derived (SIV-style): `HMAC(k_siv, salt ‖ seq ‖ cntpct ‖
  header ‖ plaintext)`, so a missing boot salt (no TRNG) can no longer repeat a CTR keystream; blob format
  unchanged, older blobs still unseal (PR #1017, `[P-sealnonce]`). **[QEMU only]** — metal pending: old-image
  blobs restore under the new image across a power cycle (`heqk-audit-2026-11-10.md` §2.1 #12 (4)).

**Detection & enforcement**
- Rule plane: verifier-checked BPF bytecode (RFC 9669 ISA), signature-checked against a pinned rule root,
  JIT on metal. **[metal-proven (`docs/design/metal-evidence/20261109-detection-network-series.md`)]**
- Enforcement separation (ADR 0023): observe by default; drops only for confirmed attacks / resource
  exhaustion; legitimate traffic always passes — the 33-row separation matrix.
  **[metal-proven (`heqk-detection-parity.md`)]**
- Signed Wasm detection modules run by a real wasmi interpreter in an isolated EL0 excursion.
  **[metal]** (`[P-wasmi-el0-metal]`, 2026-09-09; no in-repo evidence file located — see ADR 0050 Context)

**Network (Wi-Fi AP / WAN)**
- Stateful IPv4 NAT with address-dependent filtering, stateful IPv6 firewall, IPv6 SAVI, uRPF-lite WAN
  source filter, operator ACLs / prefix lists / metric routes (`POLICY.TXT`), management VLAN isolation.
  **[metal-proven (`heqk-parity-gaps.md`, `docs/design/metal-evidence/20261108-*.md`)]**
- Every remote-reachable parser in the QEMU build is fuzzed on every gate run (`[P-fuzz]`). **[QEMU only]**
  Host libFuzzer runs: `docs/design/fuzz-evidence.md`.
- Parsers moved to isolated EL0 servers (ADR 0050 D4, SEC-01): TLS + HTTP request parse (step 1), Shield DNS
  (2a), DHCP server (2b), WAN DHCPv4 / RA / DHCPv6 / PPPoE / PPP (3a, 3b), EAPOL-Key + RSNE (5a).
  **[metal-proven (`docs/design/metal-evidence/20261111-batch59-63.md`: `[P-lansvc]` PASS on CM5, incl. 3b
  and 5a)]** Station-frame authenticator work (5b) and the WPA3-SAE Authentication-frame walk (5c, PR #1005;
  every SAE secret and the curve maths stay in EL1) **[QEMU only]** — metal pending.
- WPA3: the CYW43455 firmware PMKID-cache use-after-free (release gate REL-08b, `docs/design/rel08-cyw43455-pmkid-trap.md`)
  is corrected in chip RAM after the firmware download (feature `wifi-pmkid-fix`, on by default with `wpa3`,
  operator decision 2026-11-11 "1A"; exact-bytes + version guard, read-back, `tools/firmware/rel08/check.sh`).
  Dev-bench trigger test: no firmware halt in 1,670 s / 17 SAE keyings (same doc, experiment C).
  **[metal pending]** for the 72 h WPA3 soak and the REL-08 regression matrix;
  **[blocked (written legal clearance for a RAM correction of the licensed firmware — release gate CMP-02,
  Infineon case open)]** for shipping.

**Mission Control**
- Owner authentication: a salted verifier from the flasher, **no default password**; an unclaimed device
  refuses every protected route; HttpOnly SameSite session cookies; no CORS. **[metal]** (no single evidence
  file; Mission Control sign-in is exercised by every bench batch, e.g. `docs/design/metal-evidence/20261111-batch59-63.md`)
- HTTPS (ADR 0051): TLS 1.3 with X25519MLKEM768 in an isolated EL0 server, local name-constrained CA, :80
  redirects. **[metal-proven (`heqk-remaining-gaps.md` #9; `docs/design/metal-evidence/20261110-batch29.md`)]**
  The certificate is provisioned offline by the operator; until it is, the image serves the login over plain
  HTTP. **[gap]**
- `POLICY.TXT` and every signed pack verified against the operator key (ADR 0049 D1, ADR 0056). The operator
  key is pinned on the device at first use (trust anchor, DataVolume Header region) and an image carrying a
  different key cannot replace it; the POLICY generation floor is persisted.
  **[metal-proven (`heqk-remaining-gaps.md` #1; `heqk-audit-2026-11-10.md` §3.1 J4)]**
  Per-pack generation floors are relative to the active pack (an erase can bring back an older signed pack). **[gap]**
- `WAN.TXT` is signed like `POLICY.TXT` (ADR 0058 / ADR 0059 Phase 0.1–0.2): verified before parse, exactly the
  signed bytes; on an image with an operator key an unverified file is ignored (DHCP). **[metal-proven (`docs/design/metal-evidence/20261111-batch59-63.md`:
  `WAN.TXT signature OK`)]**
- IPv6 sources have an identity in the rate/scan tiers (ADR 0049 D2, `[P-v6src]`), SipHash-2-4 keyed per boot
  from the hardware TRNG. **[QEMU only]**
- OS update over the network: shared boot verifier on a streamed digest, SVN never below the running image,
  inactive slot derived by the storage driver itself, tryboot trial, automatic fallback otherwise.
  **[metal-proven (`docs/design/metal-evidence/20261110-ota-a1.md`, `20261110-batch29.md`: J1 9/9 twice, J2 7/7)]**
  Tightened 2026-11-12 (PR #1015): a trial commits only when the WAN is usable AND the AP serves (BSS up, no Wi-Fi
  firmware halt since boot) for 30 s; only that gate commits, never the watchdog. **[QEMU only]** — metal pending.
- Runtime watchdog after the trial confirm (16 s, EL2 gate).
  **[metal-proven (`docs/design/metal-evidence/20261110-batch29.md`: `[WDOG] armed=true`)]** A kernel panic or
  fault resets through the EL2 gate and leaves a crash record for the next boot (`/api/health` `last_crash`).
  **[metal-proven (`docs/design/metal-evidence/20261110-batch33.md`: `CRASH-RECORD: PASS (5/5)`)]** A Wi-Fi stream
  wedged for 120 s resets the unit (with a backoff against reboot loops). **[QEMU only]** for the wedge detector;
  the reset path is the one J10 proved.
- Mission Control writes: per-source login throttle, cross-origin login refused, per-session write rate limit
  (20 per minute), owner revoke-all. **[QEMU only]** (`[P-mcauth]`, `[P-write-rate]`, mc-e2e)
- The TLS private scalar is re-derived from the SRK for each EL0 server start and zeroised in EL1. **[QEMU only]** (mc-e2e)
- HBoot never writes OTP unless built for factory provisioning (`otp-provision`). **[code]** (no runtime test;
  the shipping-flavour guard below refuses `otp-provision` in a shipped build)

**Configuration: signed, sealed at rest, applied live (ADR 0058 / ADR 0059, on main 2026-11-12)**
- HQCFG1 configuration bundle + cfgd trial / commit / automatic revert / owner confirm for management-plane
  changes (ADR 0059 steps 2–3). **[metal-proven (`docs/design/metal-evidence/20261111-batch59-63.md`: cfgd
  13/13, config journey 20/20)]**
- Configuration sealed at rest + live apply, steps 1–11 of `heqk-sealed-config-live-apply.md`:
  HQKSEAL1 seal of every stored config artifact under `cfg_key = HKDF(SRK, …)` (steps 1–3, PR #998), loaders on
  the sealed store + one-time crash-safe migration and scrub, no-SRK = secret-bearing config RAM-only (steps 4–5,
  PRs #998, #1000), the live trial / commit / revert engine (step 6, PR #999), live POLICY executor + activation
  hook (steps 7–8, PRs #1001, #1007), live WAN executor incl. early revert on a PPPoE authentication reject
  (step 9, PR #1002), live Wi-Fi executor (step 10, PR #1004), management-plane changes only under the owner's
  confirm (step 11, PR #1003), `/api/config` `live` object (PR #1008). **[QEMU only]** (`[P-sealcfg]`,
  `[P-cfgseal]`, `[P-cfgd-live]`, `[P-cfgd-policy]`, `[P-cfgd-wan]`, `[P-cfgd-wifi]`) — **metal pending**: none of
  steps 1–11 has run on silicon (checks written: `tools/diagnostics/cm5-cfgd-live-check`, `cm5-wifi-live-spike`,
  `heqk-house-test-plan.md`, PR #1009). The Wi-Fi bounce on the CYW43455 (risk R2) is unproven.
  eMMC wear levelling may keep old plaintext pages after the scrub (best effort, risk R1).
- Signed management (hsh R6 = D, operator 2026-11-12): privileged operations are authorised only by owner-signed
  HQMGMT1 envelopes (device id, boot epoch, fresh sequence; confirm / rollback bound to the generation + digest
  of the bundle in force), verified in EL1 (`mgmtabi`, `mgmtenv.rs`); the carrier carries no authority. Covered:
  config confirm / rollback / stage (PR #1013); upload activate / rollback for every type, factory reset,
  owner-key rotation (PR #1018). The production carrier is the Mission Control web console `POST /api/hsh` over
  the owner's TLS session; **no UART carrier is built** (no UART RX code in production). **[QEMU only]**
  (`[P-hsh-web]`, `[P-mgmtabi]`, mc-e2e) — metal pending. The earlier `[P-hsh]` / `[P-mgmtabi]` metal passes
  (batch 59–63) predate the envelopes. Format: `docs/design/mgmt-envelope-api.md`.
  **Recorded deviation (this round):** `/api/reboot`, owner rules, operator actions and the alert hook still
  use owner-token re-authentication, not envelopes. **Accepted consequence:** with no owner key enrolled, no
  client can confirm, roll back, activate a pack / config or factory-reset; the lost-key procedure is a reflash.
- Owner-key enrollment / rotation and the factory-reset floor reset: built, but **[blocked (G46 security
  review — release gate SEC-05; never waived, operator 2026-11-11)]** for shipping.

**Control channel and build**
- Noise control channel: in-session record-layer rekey (Noise §11.3, one-way) at 2^20 records / 1 GiB / 1 h,
  per-epoch replay windows, 5 s previous-epoch grace, older epochs refused without decrypting; G19 tunnel
  rekeys only after the peer's CAPS record. The handshake and the identity key stay in EL1 (operator
  2026-11-11). PR #1017, `[P-rekey]`, `[P-g19-rekey]`, superpop `rekey_interop` (host), fuzz target `record_rx`.
  **[QEMU only]** — metal pending (the four checks in `heqk-audit-2026-11-10.md` §2.1 #12).
- Shipping-flavour guard: one source of truth `tools/ci/shipping-features.txt` (`hboot,apmc,wifi-bigtx,
  appersist,wpa3`, PR #1011); `tools/ci/shipping_guard.py` fails CI / release / factory if any development-only
  feature (hsh-dev, wpa3probe, wifi-pmkid-noexpire, p15-bench, crashtest, rpmb / otp-provision, …) is active in
  that build (PR #1017). **[CI gate]** — not a runtime property.

**Not yet built (known gaps — do not assume these protections)**
- Noise and the small fixed-format reply handlers (SNTP, WAN/mgmt ARP, ICMP echo) stay in EL1 **by operator
  decision 2026-11-11** (identity-key custody), not as a gap. Still in EL1 and open: the WPA2/WPA3
  authenticator state machine, which moves with the CYW43455 driver (ADR 0044 D4 #7). **[not built]**
- Owner-journal truncation / rollback by someone with the eMMC in hand is not detectable without a monotonic
  counter outside the medium. RPMB anchoring is prepared (not an active guarantee until transport + key; the
  key write is a manufacturing operation). **[blocked (operator / manufacturing decision — release gate TC-04)]**
- Blank-OTP units fail closed (no SRK → no HTTPS, persistence, sealed config or setup credential) until factory
  provisioning is decided. **[blocked (operator decision — release gate TC-02, production blocker)]**
- Owner-signed envelopes for reboot / owner rules / actions / alert hook (recorded deviation above); a UART
  `hsh` carrier (later, view + envelope paste at most). **[not built]**
- 72 h soak (REL-05): deferred by the operator until features are built (2026-11-12). **[not built]**

---

## 📜 Security Compliance

HookProbe can help meet various compliance requirements:

### ISO 27001
- ✅ Access Control (A.9)
- ✅ Cryptography (A.10)
- ✅ Operations Security (A.12)
- ✅ Security Monitoring (A.12.4)
- ✅ Incident Management (A.16)

### NIST Cybersecurity Framework
- ✅ Identify: Asset management, risk assessment
- ✅ Protect: Access control, data security
- ✅ Detect: Anomaly detection, monitoring
- ✅ Respond: Automated response, incident handling
- ✅ Recover: Backup, recovery procedures

### heqk data handling — current truth (2026-11-07)

> ⚠️ The "GDPR Compliance & Privacy Controls" section below describes **HookProbe v5.0 (V1, the Python
> stack)** — its scripts (`/opt/hookprobe/...`), switches (`ANONYMIZE_MAC_ADDRESSES`, …) and `GDPR.md` do
> **not exist in heqk** and its claims must not be read as heqk properties. What heqk actually does:

- **Processed on device:** source/destination IPv4 + IPv6 addresses, MAC addresses, ports and protocol
  headers of forwarded traffic (no payload is retained). Detections become 16-byte evidence events
  (timestamp, source, rule, severity, verdict).
- **Behavioural detection exists:** beacon / lateral-movement / DNS detectors keep per-source counters and
  timestamps (observe-only, ADR 0023) — so "no behavioural profiling" is **not** a heqk claim.
- **At rest:** evidence and the snapshot are sealed (Encrypt-then-MAC under the device's OTP-derived key)
  in the eMMC keystore / DataVolume; bounded rings, oldest evicted.
  Stored configuration (WAN / Wi-Fi / POLICY / HQCFG1, incl. the PPPoE password and Wi-Fi PSK) is sealed
  at rest too since 2026-11-12 (PRs #998, #1000) — **QEMU only, metal pending** (see above).
- **Leaving the device:** only when ENROLLED (standalone exports nothing), over the PQ-hybrid Noise
  channel. Exported events carry the **IPv4 source address in clear inside the encrypted channel**
  (personal data under GDPR — the receiving MSSP is a processor). For the IPv6 RA rules the MAC-derived
  source is replaced by a device-keyed pseudonym (`export.rs`, 2026-11-07); it never leaves raw.
- **Not implemented in heqk:** MAC masking of the IPv4 path, configurable retention windows, subject
  export/erasure tooling, the breach-notification workflow — tracked as gaps, not claimed.

### GDPR Compliance & Privacy Controls (V1 — HookProbe v5.0, NOT heqk)

**HookProbe v5.0 is GDPR-compliant by design and by default.**

#### Privacy by Design (Article 25)

✅ **Built-In Privacy Features**:
- **IP Anonymization**: Last octet masked (192.168.1.123 → 192.168.1.0)
- **MAC Anonymization**: Device ID masked (AA:BB:CC:11:22:33 → AA:BB:CC:00:00:00)
- **No Payload Collection**: Headers only, never packet payloads (privacy violation)
- **Short Retention**: 30-365 days (configurable) vs. years
- **Encrypted Storage**: AES-256-GCM encryption at rest
- **Encrypted Transit**: VXLAN PSK + TLS 1.3

#### Data Minimization (Article 5(1)(c))

```bash
# Default privacy-preserving settings
ANONYMIZE_IP_ADDRESSES=true          # Default: ON
ANONYMIZE_MAC_ADDRESSES=true         # Default: ON
COLLECT_FULL_PAYLOAD=false           # Default: OFF (privacy-first)
COLLECT_USER_LOCATION=false          # Default: OFF
RETENTION_NETWORK_FLOWS_DAYS=30      # Default: 30 days (minimal)
```

#### Data Subject Rights (Chapter III)

✅ **Implemented Rights**:
- **Right of Access** (Article 15): Data export in JSON format (30 days)
- **Right to Erasure** (Article 17): Account deletion + log anonymization (7-day grace)
- **Right to Portability** (Article 20): Machine-readable export
- **Right to Rectification** (Article 16): Profile data correction
- **Right to Object** (Article 21): Account deletion (opt-out)

#### Automated Data Retention

```bash
# Automated deletion via cron
0 2 * * * /opt/hookprobe/scripts/gdpr-retention.sh

# What gets deleted:
# - Network flows: 30 days
# - Security logs: 90 days
# - Inactive accounts: 365 days
# - Qsecbit scores: 365 days
```

#### Breach Notification (Article 33/34)

```bash
# Automated breach detection and notification
BREACH_DETECTION_ENABLED=true
BREACH_NOTIFICATION_DEADLINE_HOURS=72  # GDPR requirement
BREACH_NOTIFICATION_EMAIL="qsecbit@hookprobe.com"

# Response timeline:
# T+0: Breach detected (automated)
# T+1: DPO notified
# T+24: Preliminary assessment
# T+72: Supervisory authority notified (if required)
```

#### Privacy-Preserving Security Analysis

**Qsecbit detects threats using patterns, not identities**:
- DDoS detection works with anonymized IPs (subnet-level analysis)
- Port scanning detection doesn't need exact IPs
- Protocol anomaly detection requires no PII
- No behavioral profiling of individuals

#### Legal Basis for Processing

**Legitimate Interests** (Article 6(1)(f)):
- Network security and fraud prevention
- Service delivery and infrastructure protection
- Security incident response

**Legitimate Interest Assessment (LIA)** completed and documented in GDPR.md

#### Personal Data Processed

| Data Type | Retention | Anonymization | Legal Basis |
|-----------|-----------|---------------|-------------|
| IP Addresses | 30-90 days | ✅ Masked | Legitimate interest |
| MAC Addresses | 30 days | ✅ Masked | Legitimate interest |
| User Accounts | 2 years | ❌ Required | Contract |
| Network Flows | 30 days | ✅ Anonymized | Legitimate interest |
| Security Logs | 90 days | ✅ Anonymized | Legitimate interest |

**NOT Collected**: Packet payloads, browsing history, geolocation, biometric data

#### GDPR Configuration

```bash
# Review and configure GDPR settings
nano /opt/hookprobe/scripts/gdpr-config.sh

# Key settings:
GDPR_ENABLED=true
GDPR_STRICT_MODE=false  # Extra strict (may reduce visibility)
DATA_PROCESSING_LEGAL_BASIS="legitimate_interest"

# Generate compliance report
sudo /opt/hookprobe/scripts/gdpr-retention.sh
cat /var/log/hookprobe/compliance-reports/compliance-report-$(date +%Y-%m-%d).txt
```

#### DPIA (Data Protection Impact Assessment)

**Required for HookProbe** (Article 35) - Large-scale monitoring + profiling:
- Template available: `/opt/hookprobe/compliance/DPIA.pdf`
- Review annually or when significant changes occur
- Document risks and mitigation measures

#### Complete GDPR Documentation

📖 **[GDPR.md](../../legacy/v1/docs/GDPR.md)** - Comprehensive compliance guide including:
- Detailed data inventory
- Legal basis justification
- Privacy by design implementation
- Data subject rights procedures
- Breach notification process
- DPIA template
- Compliance checklist
- FAQ (legal and technical)

#### GDPR Compliance Checklist

**Pre-Deployment**:
- [ ] Review `gdpr-config.sh` and set retention periods
- [ ] Verify IP/MAC anonymization enabled
- [ ] Confirm payload collection disabled (`COLLECT_FULL_PAYLOAD=false`)
- [ ] Configure DPO contact email
- [ ] Set up automated retention cleanup (cron)
- [ ] Complete DPIA (if required)
- [ ] Identify supervisory authority (for EU deployments)

**Post-Deployment**:
- [ ] Verify anonymization working (`tail /var/log/napse/conn.log | grep "\.0$"`)
- [ ] Test data retention cleanup
- [ ] Generate compliance report
- [ ] Monitor GDPR audit log (`tail -f /var/log/hookprobe/gdpr-audit.log`)

#### Contact

- **GDPR Documentation**: [GDPR.md](../../legacy/v1/docs/GDPR.md)
- **Data Protection Officer**: qsecbit@hookprobe.com
- **Security Contact**: qsecbit@hookprobe.com

**Note**: HookProbe provides GDPR-compliant tools and defaults. Final compliance is the operator's responsibility and may require legal review specific to your jurisdiction and use case.

---

## 🔗 Security Resources

### Official Resources
- **Documentation**: https://docs.hookprobe.com/security
- **Security Advisories**: https://github.com/hookprobe/heqk/security/advisories
- **CVE Database**: Search for "HookProbe" at https://cve.mitre.org

### Community Resources
- **Security Discussions**: https://github.com/hookprobe/heqk/discussions
- **Stack Overflow**: Tag: `hookprobe-security`
- **Reddit**: r/HookProbe

### Third-Party Security Tools
- **Trivy**: Container vulnerability scanning
- **OWASP ZAP**: Web application security testing
- **Nmap**: Network security auditing
- **Nikto**: Web server vulnerability scanning
- **OpenVAS**: Comprehensive vulnerability assessment

---

## 📞 Security Contacts

| Purpose | Contact | Response Time |
|---------|---------|---------------|
| **Security Vulnerabilities** | qsecbit@hookprobe.com | < 24 hours |
| **Security Questions** | qsecbit@hookprobe.com | < 48 hours |
| **Incident Response** | qsecbit@hookprobe.com | < 1 hour |
| **General Inquiries** | qsecbit@hookprobe.com | < 72 hours |

### PGP Keys

Security team PGP key fingerprint:
```
4096R/ABCD1234 2025-01-01 HookProbe Security Team <security@hookprobe.com>
Key fingerprint = 1234 5678 9ABC DEF0 1234  5678 9ABC DEF0 1234 5678
```

Download: https://hookprobe.com/security/pgp-key.asc

---

## 🏆 Security Hall of Fame

We recognize security researchers who responsibly disclose vulnerabilities:

### 2025
- *[Your name could be here!]*

### Guidelines for Recognition
- Responsible disclosure following our process
- Valid security vulnerability (not theoretical)
- Significant impact (Medium severity or higher)
- First reporter of the issue
- Permission granted to list name

---

## 📄 Disclosure Policy

### Coordinated Disclosure

We follow a **90-day coordinated disclosure** policy:

1. **Day 0**: Vulnerability reported to security@hookprobe.com
2. **Day 1**: Acknowledgment sent to reporter
3. **Day 2**: Severity assessment and timeline provided
4. **Day 7**: Fix developed and tested
5. **Day 14**: Security patch released
6. **Day 90**: Public disclosure (or earlier if agreed)

### Exceptions

- **Critical vulnerabilities**: May be disclosed earlier if actively exploited
- **Already public**: Immediate disclosure if vulnerability is already public
- **Vendor request**: Disclosure may be delayed if additional coordination needed

### Public Disclosure Format

Security advisories include:
- CVE ID (if applicable)
- Affected versions
- Description of vulnerability
- Impact assessment
- Remediation steps
- Credit to researcher (with permission)

---

## ⚖️ Legal

### Safe Harbor

HookProbe supports security research conducted in good faith:

**We will not pursue legal action against you if you:**
- Make a good faith effort to avoid privacy violations, destruction of data, and interruption or degradation of our services
- Only interact with accounts you own or with explicit permission
- Do not exploit the vulnerability beyond the minimum necessary to confirm it
- Report the vulnerability promptly
- Do not demand payment for vulnerability disclosure
- Keep vulnerability information confidential until we've addressed it

**In scope:**
- HookProbe core application
- Official Docker/Podman images
- Deployment scripts and tools
- Documentation website

**Out of scope:**
- Third-party dependencies (report to upstream)
- Social engineering attacks
- Physical attacks
- Denial of service attacks

---

## 📊 Security Metrics

We track and publish security metrics quarterly:

- **Mean Time to Detect (MTTD)**: Target < 5 minutes
- **Mean Time to Respond (MTTR)**: Target < 1 hour for critical
- **Vulnerability Disclosure Time**: Target < 90 days
- **Patch Release Time**: Target < 14 days
- **False Positive Rate**: Target < 5%

---

## 🔄 Updates to This Policy

This security policy is reviewed quarterly and updated as needed.

**Last Updated**: January 2025  
**Version**: 1.0  
**Next Review**: April 2025

Changes to this policy will be announced via:
- GitHub release notes
- Security mailing list
- Documentation website

---

## 📝 Acknowledgments

HookProbe security is built on:
- **Qsecbit Algorithm**: Developed by Andrei Toma
- **OWASP Best Practices**: Web application security
- **NIST Guidelines**: Cybersecurity framework
- **CIS Benchmarks**: Configuration hardening
- **Community Contributions**: Security researchers worldwide

---

## ✅ Deployment checklist (heqk)

- [ ] Flash with an owner key (the factory default is UNCLAIMED — every protected route refuses until claimed).
- [ ] Use a release-signed image (never a `HOOKPROBE_DEBUG_ACCESS` bench image in production).
- [ ] Install the per-device Mission Control certificate (ADR 0051, offline provisioning): without it the login
      is served over plain HTTP — keep such a unit on a trusted network.
- [ ] Ship `POLICY.TXT` and every data pack signed with the operator key (ADR 0049 D1 / ADR 0056) — the first
      boot pins that key; an unsigned or differently-signed file is refused. `WAN.TXT` is signed too (ADR 0058,
      metal batch 59–63); once an owner key is enrolled, uploaded configuration verifies only with it.
- [ ] Provision customer OTP at the factory (decision record 2026-11-10) — a blank-OTP unit fails closed (no
      HTTPS key, no persistence, no setup credential).
- [ ] Watch the heartbeat counters (`faults`, `rx_lost`, stalls, policy drops) and `/api/health`.

---

## Accepted residual: EL0 high-resolution timer (P17)

P17 sets `CNTKCTL_EL1.EL0PCTEN = 1`, granting EL0 read access to the monotonic
`CNTPCT_EL0` counter (needed for the IP-overlay service's timekeeping). This is a
**timing side-channel primitive** — EL0 code can measure durations at counter
resolution. It is **accepted** on HEQK's single-tenant edge-appliance model (there is
no mutually-distrusting second EL0 tenant to attack), and it grants the counter
*only* — no compare registers, no timer control, no event stream. It is revocable
(clear EL0PCTEN, fall back to the kernel-published `time_us` word) if a future
multi-tenant model needs it.

---

**Questions about security?** Email security@hookprobe.com
