# HookProbe Infrastructure

**Optional Components & Extensions**

This directory contains optional infrastructure components that extend HookProbe's core capabilities beyond the standard 7-POD deployment.

---

## 📁 Directory Structure

```
infrastructure/
└── pod-009-email/    # POD-009: Enterprise Email System with DMZ
```

---

## 📧 POD-009: Enterprise Email System

**Secure email infrastructure with dual-firewall DMZ architecture** - Perfect for organizations requiring self-hosted email with enterprise-grade security.

### Overview

POD-009 provides a complete email solution with:

- ✅ **Dual-Firewall DMZ Architecture** - Defense-in-depth security
- ✅ **Postfix** - SMTP relay (DMZ) + mail server (internal zone)
- ✅ **DKIM/SPF/DMARC** - Email authentication and anti-spoofing
- ✅ **Dovecot** - IMAP/POP3 server for mail retrieval
- ✅ **SMTP IDS** - Real-time email traffic monitoring
- ✅ **Cloudflare Tunnel** - Zero-trust remote access
- ✅ **Podman Deployment** - Rootless containers for enhanced security

### Why POD-009?

**For Organizations:**
- Full control over email infrastructure
- No third-party access to sensitive communications
- GDPR-compliant data residency
- Integration with HookProbe security monitoring

**For Home Users:**
- Professional email hosting on your SBC
- Learning email security concepts
- Custom domain email (@yourdomain.com)
- Privacy-focused alternative to Gmail/Outlook

### Architecture

```
                    Internet
                       │
                       ▼
              ┌────────────────┐
              │  Firewall 1    │  ← External firewall (iptables)
              │  (External)    │
              └────────┬───────┘
                       │
              ┌────────▼───────┐
              │   DMZ Zone     │
              │  10.200.9.10   │
              │                │
              │  Components:   │
              │  - Postfix     │  ← SMTP relay
              │    Relay       │
              │  - SMTP IDS    │  ← Mail traffic monitor
              │    IDS         │
              └────────┬───────┘
                       │
              ┌────────▼───────┐
              │  Firewall 2    │  ← Internal firewall (iptables)
              │  (Internal)    │
              └────────┬───────┘
                       │
              ┌────────▼───────┐
              │ Internal Zone  │
              │  10.200.9.20   │
              │                │
              │  Components:   │
              │  - Postfix     │  ← Mail server
              │    Server      │
              │  - Dovecot     │  ← IMAP/POP3
              │  - Storage     │
              └────────────────┘
```

### Network Topology

**VNI 209** (10.200.9.0/24):
- `10.200.9.10` - DMZ Mail Gateway (Postfix relay + SMTP IDS)
- `10.200.9.11` - DMZ IDS Monitor (SMTP traffic analysis logs)
- `10.200.9.20` - Internal Mail Server (Postfix + Dovecot)
- `10.200.9.21` - Cloudflare Tunnel Client

### Security Features

1. **Defense-in-Depth**:
   - Two independent firewalls
   - DMZ isolation for public-facing components
   - Internal zone for mailbox storage

2. **Email Authentication**:
   - **DKIM**: Cryptographic signing of outbound emails
   - **SPF**: Sender IP validation
   - **DMARC**: Policy enforcement and reporting

3. **Threat Detection**:
   - SMTP IDS monitoring all email traffic
   - Integration with Qsecbit AI for threat scoring
   - Automated response to email-based attacks

4. **Zero-Trust Access**:
   - Cloudflare Tunnel for remote management
   - No exposed ports (optional)
   - TLS encryption end-to-end

---

## 🚀 Quick Start: POD-009 Email

### Prerequisites

- HookProbe core infrastructure (PODs 001-007) installed
- Domain name with DNS access
- Public IP address (or Cloudflare Tunnel)

### Installation

```bash
cd /home/user/hookprobe

# Run installer
sudo ./install.sh

# Select: 5) Optional Extensions / Add-ons
# Then: 2) POD-009: Email System & Notification [Manual Guide]
```

Or deploy directly:

```bash
cd /home/user/hookprobe/infrastructure/pod-009-email

# Review configuration
nano docker-compose.yml

# Deploy with Podman
podman-compose up -d

# Configure firewalls
sudo bash firewall-rules/iptables-firewall1-external.sh
sudo bash firewall-rules/iptables-firewall2-internal.sh

# Setup DKIM
podman exec hookprobe-dmz-mail-gateway bash /opt/dkim-setup.sh

# Configure DNS (see dmz-gateway/spf-dmarc-setup.md)
```

### Access & Testing

```bash
# Send test email
echo "Test email body" | mail -s "Test Subject" recipient@example.com

# Check mail queue
podman exec hookprobe-internal-mail mailq

# View logs
podman logs -f hookprobe-dmz-mail-gateway
podman logs -f hookprobe-internal-mail
```

---

## 📖 Documentation

### POD-009 Email System

- **[README.md](pod-009-email/README.md)** - Architecture overview and features
- **[DEPLOYMENT.md](pod-009-email/DEPLOYMENT.md)** - Complete deployment guide
- **[PODMAN.md](pod-009-email/PODMAN.md)** - Podman-specific configuration
- **[SPF-DMARC Setup](pod-009-email/dmz-gateway/spf-dmarc-setup.md)** - Email authentication

---

## 🔧 Use Cases

### Home Users

**Personal Email Server:**
```
- Domain: johndoe.com
- Email: john@johndoe.com
- Use Case: Privacy-focused email, learning
- Hardware: Raspberry Pi 4 or Intel N100
```

### Small Business

**Company Email Infrastructure:**
```
- Domain: acmecorp.com
- Emails: team@acmecorp.com, sales@acmecorp.com
- Use Case: Professional email, GDPR compliance
- Hardware: Intel NUC or Mini PC
```

### Service Provider Deployment

**Multi-Tenant Email (Advanced):**
```
- Multiple customer domains
- Centralized management
- Per-tenant isolation
- Hardware: Server-grade (Xeon/EPYC)
```

---

## ⚙️ Configuration

### Basic Settings

Edit `docker-compose.yml`:

```yaml
environment:
  # Domain configuration
  MAIL_DOMAIN: "yourdomain.com"
  MAIL_HOSTNAME: "mail.yourdomain.com"

  # SMTP relay settings
  RELAY_HOST: "smtp.yourprovider.com"
  RELAY_PORT: "587"
  RELAY_USER: "your-smtp-user"
  RELAY_PASSWORD: "your-smtp-password"

  # DKIM settings
  DKIM_SELECTOR: "mail"
```

### DNS Records

Required DNS records for email authentication:

```dns
# MX Record (Mail server)
yourdomain.com.    IN MX 10 mail.yourdomain.com.

# A Record (Mail server IP)
mail.yourdomain.com.    IN A    YOUR_PUBLIC_IP

# SPF Record (Authorized senders)
yourdomain.com.    IN TXT "v=spf1 mx ip4:YOUR_PUBLIC_IP -all"

# DKIM Record (Email signing)
mail._domainkey.yourdomain.com.    IN TXT "v=DKIM1; k=rsa; p=YOUR_PUBLIC_KEY"

# DMARC Record (Policy)
_dmarc.yourdomain.com.    IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com"
```

---

## 🛡️ Security Hardening

### Firewall Rules

**External Firewall (FW1)**:
```bash
# Allow SMTP inbound
iptables -A INPUT -p tcp --dport 25 -j ACCEPT

# Allow SMTP submission (authenticated)
iptables -A INPUT -p tcp --dport 587 -j ACCEPT

# Allow IMAP/POP3 (if needed)
iptables -A INPUT -p tcp --dport 993 -j ACCEPT  # IMAPS
iptables -A INPUT -p tcp --dport 995 -j ACCEPT  # POP3S
```

**Internal Firewall (FW2)**:
```bash
# Allow DMZ → Internal mail relay only
iptables -A FORWARD -s 10.200.9.10 -d 10.200.9.20 -p tcp --dport 25 -j ACCEPT

# Drop everything else
iptables -A FORWARD -j DROP
```

### Anti-Spam Measures

1. **Rate Limiting**:
   ```bash
   # Limit outbound email rate (prevent spam abuse)
   postconf -e "anvil_rate_time_unit = 60s"
   postconf -e "smtpd_client_message_rate_limit = 100"
   ```

2. **Greylisting**:
   ```bash
   # Delay unknown senders (reduces spam)
   postconf -e "smtpd_recipient_restrictions = check_policy_service inet:127.0.0.1:10023"
   ```

3. **Reputation Monitoring**:
   - Monitor Spamhaus DNSBL
   - Check MXToolbox regularly
   - Review DMARC reports

---

## 📊 Monitoring

### Grafana Dashboards

POD-009 integrates with HookProbe monitoring:

- **Email Traffic**: Inbound/outbound message counts
- **Queue Size**: Mail queue depth and delays
- **Threat Detection**: SMTP IDS alerts
- **Performance**: SMTP response times, CPU/RAM usage

Access: http://YOUR_IP:3000 → POD-009 Email Dashboard

### Logs

```bash
# Postfix logs (DMZ relay)
podman exec hookprobe-dmz-mail-gateway tail -f /var/log/mail.log

# Postfix logs (internal server)
podman exec hookprobe-internal-mail tail -f /var/log/mail.log

# SMTP IDS alerts
podman exec hookprobe-dmz-mail-ids tail -f /var/log/napse/intents.json

# Dovecot logs
podman exec hookprobe-internal-mail tail -f /var/log/dovecot.log
```

---

## 🔄 Maintenance

### Regular Tasks

**Daily**:
- Monitor mail queue: `mailq`
- Check SMTP IDS alerts
- Review authentication failures

**Weekly**:
- Review DMARC reports
- Check disk space (mailbox storage)
- Update spam filter rules

**Monthly**:
- Rotate DKIM keys
- Review firewall logs
- Update container images
- Backup mailboxes

### Backup Strategy

```bash
# Backup mailboxes
rsync -avz /var/mail/ /backup/mail/$(date +%Y%m%d)/

# Backup configuration
tar -czf /backup/mail-config-$(date +%Y%m%d).tar.gz \
    /etc/postfix/ \
    /etc/dovecot/ \
    /etc/dkim/

# Backup to remote (optional)
rsync -avz /backup/mail/ backup-server:/remote/backup/mail/
```

---

## 🚨 Troubleshooting

### Email Not Sending

```bash
# Check mail queue
podman exec hookprobe-internal-mail mailq

# View pending messages
podman exec hookprobe-internal-mail postqueue -p

# Flush queue (retry delivery)
podman exec hookprobe-internal-mail postqueue -f

# Check Postfix status
podman exec hookprobe-dmz-mail-gateway postfix status
```

### Email Not Receiving

```bash
# Test SMTP connectivity
telnet mail.yourdomain.com 25

# Check DNS MX record
dig MX yourdomain.com

# Verify firewall rules
iptables -L -n -v | grep 25

# Check Postfix logs
podman logs hookprobe-dmz-mail-gateway | grep "reject"
```

### Authentication Failures

```bash
# Check DKIM signature
opendkim-testkey -d yourdomain.com -s mail

# Verify SPF record
dig TXT yourdomain.com | grep spf

# Check DMARC policy
dig TXT _dmarc.yourdomain.com

# Test email authentication
https://www.mail-tester.com/
```

---

## 🎯 Performance Tuning

### For Edge Devices (SBCs)

```yaml
# Reduce memory usage
postconf -e "default_process_limit = 50"
postconf -e "qmgr_message_active_limit = 10000"

# Disable unnecessary features
postconf -e "disable_vrfy_command = yes"
```

### For Production Servers

```yaml
# Increase throughput
postconf -e "default_process_limit = 200"
postconf -e "qmgr_message_active_limit = 50000"
postconf -e "smtp_destination_concurrency_limit = 20"

# Enable caching
postconf -e "smtp_connection_cache_on_demand = yes"
```

---

## 🤝 Contributing

Help us improve POD-009!

### Areas for Contribution

- **Email Automation**: Workflow integrations (n8n)
- **Anti-Spam**: Additional filtering techniques
- **Documentation**: Setup tutorials, troubleshooting guides
- **Testing**: Email deliverability testing
- **Monitoring**: Custom Grafana dashboards

---

## 📚 Additional Resources

### Official Documentation

- **Postfix**: http://www.postfix.org/documentation.html
- **Dovecot**: https://www.dovecot.org/documentation.html
- **DKIM**: https://www.dkim.org/
- **DMARC**: https://dmarc.org/

### HookProbe Documentation

- **Main README**: [../README.md](../README.md)
- **Installation Guide**: [../QUICK-START.md](../QUICK-START.md)
- **Security Model**: [../docs/architecture/security-model.md](../docs/architecture/security-model.md)

### Tools & Testing

- **MX Toolbox**: https://mxtoolbox.com/ - DNS/email testing
- **Mail Tester**: https://www.mail-tester.com/ - Email deliverability test
- **DMARC Analyzer**: https://dmarc.postmarkapp.com/ - DMARC record checker

---

## 📞 Support

- **GitHub Issues**: https://github.com/hookprobe/hookprobe/issues
- **Email Security Contact**: qsecbit@hookprobe.com
- **Community**: [CONTRIBUTING.md](../docs/CONTRIBUTING.md)

---

**HookProbe Infrastructure** - *Enterprise-Grade Optional Components*

Built with ❤️ for secure communications by the HookProbe Team

🔒 Privacy-focused | 🛡️ Security-hardened | 🚀 Production-ready
