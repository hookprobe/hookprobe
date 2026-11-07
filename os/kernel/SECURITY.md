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

## 🛡️ What heqk actually does (current truth, 2026-11-07)

> This section replaced a feature list copied from the **V1 Linux stack** (VXLAN pods, Django/NAXSI, Logto,
> Grafana, a Kali countermeasure container, rsyslog/Loki, containers, default `admin/admin` credentials,
> unauthenticated internal APIs). **None of those exist in heqk**; their hardening advice does not apply.
> Every item below is tagged: **[metal]** proven on CM5 silicon, **[qemu]** proven in the `validate.sh` gate,
> **[not built]** decided but not implemented.

**Kernel & boot**
- Rust `no_std` capability microkernel on aarch64; EL2 carve-out makes the OTP/mailbox unreachable from EL1. **[metal]**
- Signed boot (`hboot`), A/B tryboot with commit-on-health and anti-rollback. **[metal]**
- Sealed persistence bound to the device root key (SRK) and the measured-boot policy; crash-consistent A/B
  snapshot slots. **[metal]**

**Detection & enforcement**
- Rule plane: verifier-checked BPF bytecode (RFC 9669 ISA), signature-checked against a pinned rule root,
  JIT on metal. **[metal]**
- Enforcement separation (ADR 0023): observe by default; drops only for confirmed attacks / resource
  exhaustion; legitimate traffic always passes — the 33-row separation matrix. **[metal]**
- Signed Wasm detection modules run by a real wasmi interpreter in an isolated EL0 excursion. **[metal]**

**Network (Wi-Fi AP / WAN)**
- Stateful IPv4 NAT with address-dependent filtering, stateful IPv6 firewall, IPv6 SAVI, uRPF-lite WAN
  source filter, operator ACLs / prefix lists / metric routes (`POLICY.TXT`), management VLAN isolation. **[metal]**
- Every remote-reachable parser in the QEMU build is fuzzed on every gate run (`[P-fuzz]`). **[qemu]**

**Mission Control**
- Owner authentication: a salted verifier from the flasher, **no default password**; an unclaimed device
  refuses every protected route; HttpOnly SameSite session cookies; no CORS. **[metal]**
- Served over **plain HTTP today** — HTTPS is ADR 0051 (EL0 TLS server, local name-constrained CA). **[not built]**

**Not yet built (known gaps — do not assume these protections)**
- `POLICY.TXT` is not yet signature-checked (ADR 0049 D1). **[not built]**
- Control protocols (HTTP, DHCP, DNS, PPPoE, Noise) still parse in EL1; moving them to isolated EL0 servers is
  ADR 0050. **[not built]**
- IPv6 sources have no identity in the rate/scan tiers (ADR 0049 D2). **[not built]**

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

📖 **[GDPR.md](GDPR.md)** - Comprehensive compliance guide including:
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

- **GDPR Documentation**: [GDPR.md](GDPR.md)
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
- [ ] Keep Mission Control on a trusted network until HTTPS lands (ADR 0051): it is plain HTTP today.
- [ ] Treat physical access to the card as access to `POLICY.TXT` / `WAN.TXT` until policy signing lands (ADR 0049 D1).
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
