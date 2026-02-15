# Security Policy

## 🔒 HookProbe Security

HookProbe is a cybersecurity platform designed to protect infrastructure through AI-driven threat detection and automated response. Security is our top priority, both in the design of the system and in how we handle security reports.

---

## 📋 Supported Versions

We actively support the following versions with security updates:

| Version | Supported          | End of Support |
| ------- | ------------------ | -------------- |
| 5.x     | ✅ Fully supported | TBD            |
| 4.x     | ⚠️ Security fixes only | 2025-12-31 |
| 3.x     | ❌ Not supported   | 2025-06-30     |
| < 2.0   | ❌ Not supported   | 2024-12-31     |

**Current stable version**: 5.0

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
Affected Component: [e.g., Django Admin, WAF, Qsecbit API]
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

## 🛡️ Security Features

HookProbe includes multiple layers of security:

### 🔒 Network Security
- ✅ **PSK-Encrypted VXLAN**: All inter-POD traffic encrypted
- ✅ **Network Segmentation**: 7 isolated POD networks
- ✅ **Firewall Rules**: Strict iptables configuration
- ✅ **Zero Trust Architecture**: Optional Cloudflare Tunnel integration

### 🌐 Web Application Security
- ✅ **NAXSI WAF**: Web Application Firewall protecting Django
- ✅ **ModSecurity**: Additional WAF layer
- ✅ **Input Validation**: All user inputs sanitized
- ✅ **CSRF Protection**: Django CSRF middleware enabled
- ✅ **XSS Prevention**: Content Security Policy headers
- ✅ **SQL Injection Protection**: Parameterized queries only

### 🔐 Authentication & Authorization
- ✅ **Logto IAM**: Enterprise-grade identity management
- ✅ **Multi-Factor Authentication**: Supported via Logto
- ✅ **Role-Based Access Control**: Granular permissions
- ✅ **Session Management**: Secure session handling
- ✅ **Password Hashing**: Industry-standard bcrypt

### 🤖 AI-Driven Security (Qsecbit v5.0)
- ✅ **Cyber Resilience Metric**: Real-time threat scoring (RAG status) measuring attack-defense equilibrium
- ✅ **XDP/eBPF DDoS Mitigation**: Kernel-level packet filtering with automatic NIC detection
- ✅ **Energy Monitoring**: RAPL + per-PID power tracking for anomaly detection
- ✅ **Network Direction-Aware Analysis**: Role-based traffic pattern detection (PUBLIC_SERVER vs USER_ENDPOINT)
- ✅ **Automated Response**: Kali Linux countermeasures triggered on AMBER/RED status
- ✅ **Behavioral Analysis**: NAPSE AI-native IDS/NSM/IPS
- ✅ **Honeypot System**: Attacker intelligence gathering
- ✅ **Attack Mitigation**: Automated blocking and redirection
- ✅ **Dual-Database Support**: ClickHouse (edge) and Apache Doris (cloud) for security analytics

### 📊 Monitoring & Logging
- ✅ **Centralized Logging**: Rsyslog + Loki aggregation
- ✅ **Audit Trail**: Complete activity logging
- ✅ **SIEM Integration**: VictoriaMetrics + VictoriaLogs
- ✅ **Alert System**: Email notifications for incidents
- ✅ **Log Integrity**: Append-only logging

### 🔒 Container Security
- ✅ **Rootless Containers**: Non-root execution where possible
- ✅ **Image Scanning**: Vulnerability scanning recommended
- ✅ **Minimal Base Images**: Alpine-based containers
- ✅ **Resource Limits**: CPU/Memory quotas enforced
- ✅ **Network Policies**: Pod-to-pod access control

---

## ⚠️ Security Considerations

### Known Security Design Decisions

#### 1. Honeypot Exposure
**Design**: Honeypots are intentionally vulnerable to attract attackers.

**Mitigation**:
- Honeypots are network-isolated from production
- All honeypot traffic is logged and monitored
- Automatic cleanup of honeypot data after 90 days
- No sensitive data stored in honeypots

#### 2. Automated Response Capabilities
**Design**: Kali Linux container can execute automated countermeasures.

**Mitigation**:
- Kali container is only activated on AMBER/RED Qsecbit status
- All actions are logged and reported
- Human approval required for critical actions (configurable)
- Automatic cooldown and shutdown after mitigation

#### 3. Email Notifications
**Design**: Security alerts sent via email to qsecbit@hookprobe.com.

**Security Notes**:
- Emails may contain sensitive attack data
- Ensure email channel is secured (TLS required)
- Consider PGP encryption for sensitive alerts
- Monitor email account 24/7

#### 4. Default Credentials
**WARNING**: Default credentials are provided for initial setup ONLY.

**Action Required**:
- ⚠️ Change Django admin password (admin/admin)
- ⚠️ Change Grafana password (admin/admin)
- ⚠️ Generate strong Django SECRET_KEY
- ⚠️ Rotate all database passwords
- ⚠️ Update PSK keys for VXLAN tunnels

#### 5. API Endpoints
**Design**: Several internal APIs exposed for system communication.

**Mitigation**:
- APIs only accessible within 10.200.0.0/16 network
- No authentication required for internal APIs (trust model)
- Use firewall rules to restrict external access
- Consider adding API authentication for production

---

## 🔧 Security Best Practices

### Deployment Security

#### Before Deployment
- [ ] Change all default passwords
- [ ] Generate unique PSK keys for VXLAN (minimum 32 characters)
- [ ] Generate strong Django SECRET_KEY (minimum 50 characters)
- [ ] Configure SSL/TLS certificates (Let's Encrypt or commercial)
- [ ] Review and update IP whitelist
- [ ] Configure firewall to block unnecessary ports
- [ ] Set up email notifications with secure SMTP
- [ ] Review Qsecbit thresholds for your environment

#### After Deployment
- [ ] Enable automated backups
- [ ] Set up monitoring alerts
- [ ] Configure log retention policies
- [ ] Schedule regular security audits
- [ ] Enable automatic security updates
- [ ] Document your security configuration
- [ ] Train team on incident response procedures

### Operational Security

#### Daily
- [ ] Monitor Grafana dashboards for anomalies
- [ ] Review Qsecbit RAG status
- [ ] Check email alerts for security incidents
- [ ] Verify all services are running

#### Weekly
- [ ] Review honeypot logs for attack patterns
- [ ] Analyze blocked IPs and attack trends
- [ ] Update WAF rules based on new attack signatures
- [ ] Check disk space and log rotation

#### Monthly
- [ ] Review and update IP whitelist
- [ ] Audit user accounts and permissions
- [ ] Test backup restoration procedures
- [ ] Update container images
- [ ] Review firewall rules for optimization

#### Quarterly
- [ ] Conduct security audit
- [ ] Penetration testing (optional but recommended)
- [ ] Review and update security policies
- [ ] Team security training
- [ ] Disaster recovery drill

---

## 🔐 Hardening Guide

### Network Hardening

```bash
# Disable unnecessary services
sudo systemctl disable --now avahi-daemon
sudo systemctl disable --now cups

# Enable firewall
sudo systemctl enable --now firewalld

# Restrict SSH (production)
sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Enable automatic security updates
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

### Container Hardening

```bash
# Scan images for vulnerabilities
podman run --rm aquasec/trivy image hookprobe-django:latest

# Run containers as non-root (where possible)
podman run --user 1000:1000 ...

# Set resource limits
podman run --memory="1g" --cpus="2" ...

# Use read-only root filesystem
podman run --read-only ...
```

### Application Hardening

```python
# Django settings.py - Production hardening

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

# HTTPS enforcement
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

# HSTS (HTTP Strict Transport Security)
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# XSS Protection
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# Content Security Policy
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")

# Limit allowed hosts
ALLOWED_HOSTS = ['your-domain.com', 'www.your-domain.com']
```

---

## 🚨 Incident Response

### If You're Compromised

1. **Immediate Actions**
   ```bash
   # Isolate affected systems
   sudo iptables -I INPUT -j DROP
   sudo iptables -I OUTPUT -j DROP
   
   # Keep localhost communication
   sudo iptables -I INPUT -i lo -j ACCEPT
   sudo iptables -I OUTPUT -o lo -j ACCEPT
   
   # Preserve evidence
   sudo tar -czf /tmp/evidence-$(date +%Y%m%d-%H%M%S).tar.gz \
       /var/log/hookprobe/ \
       /var/lib/hookprobe/ \
       /opt/hookprobe/honeypots/
   
   # Create memory dump (if forensics needed)
   sudo dd if=/dev/mem of=/tmp/memory-dump-$(date +%Y%m%d-%H%M%S).img
   ```

2. **Investigation**
   - Review Qsecbit analysis for attack timeline
   - Check honeypot logs for attacker behavior
   - Analyze Loki/Grafana for unusual patterns
   - Examine WAF logs for attack vectors

3. **Containment**
   - Block attacker IPs
   - Rotate all credentials
   - Patch vulnerabilities
   - Restore from clean backup if needed

4. **Recovery**
   - Deploy updated system
   - Verify integrity
   - Monitor closely for 72 hours
   - Document lessons learned

5. **Reporting**
   - Email incident details to qsecbit@hookprobe.com
   - Document timeline and impact
   - Share findings with community (after remediation)

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

### GDPR Compliance & Privacy Controls

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
- **Security Advisories**: https://github.com/hookprobe/hookprobe/security/advisories
- **CVE Database**: Search for "HookProbe" at https://cve.mitre.org

### Community Resources
- **Security Discussions**: https://github.com/hookprobe/hookprobe/discussions
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

## ✅ Security Checklist

Before going to production:

### Critical (Must Do)
- [ ] Change all default passwords
- [ ] Generate unique encryption keys
- [ ] Enable SSL/TLS
- [ ] Configure firewall
- [ ] Set up backups
- [ ] Enable security monitoring
- [ ] Review security logs

### Recommended (Should Do)
- [ ] Implement MFA
- [ ] Configure rate limiting
- [ ] Set up intrusion detection
- [ ] Enable audit logging
- [ ] Perform security scan
- [ ] Document security procedures
- [ ] Train team on security

### Optional (Nice to Have)
- [ ] Penetration testing
- [ ] Bug bounty program
- [ ] Security certifications
- [ ] Third-party security audit
- [ ] Security awareness training

---

**Remember**: Security is a continuous process, not a one-time setup. Stay vigilant! 🛡️

---

**Questions about security?** Email security@hookprobe.com
