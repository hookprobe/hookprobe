# POD-009: Email System with DMZ Architecture

## Overview

POD-009 provides secure email services for HookProbe with a defense-in-depth architecture using DMZ deployment, dual firewalls, and comprehensive monitoring.

## Network Architecture

```
Internet
   │
   ├─ Cloudflare Tunnel (TLS termination, DDoS protection)
   │
   ▼
[Firewall 1 - External]
   │
   ├─ Rules: Allow port 25, 587, 993 from Internet to DMZ only
   │
   ▼
┌──────────────────────────────────────────┐
│           DMZ (10.200.9.0/24)            │
│                                          │
│  ┌────────────────────────────────┐     │
│  │  Mail Gateway (10.200.9.10)    │     │
│  │  - Postfix SMTP Relay          │     │
│  │  - Anti-spam (SpamAssassin)    │     │
│  │  - Anti-virus (ClamAV)         │     │
│  │  - Rate limiting               │     │
│  │  - Greylisting                 │     │
│  │  - DKIM signing (outbound)     │     │
│  └────────────────────────────────┘     │
│                                          │
│  ┌────────────────────────────────┐     │
│  │  IDS/IPS (10.200.9.11)         │     │
│  │  - Suricata monitoring         │     │
│  │  - Traffic analysis            │     │
│  └────────────────────────────────┘     │
└──────────────────────────────────────────┘
   │
   ▼
[Firewall 2 - Internal]
   │
   ├─ Rules: Allow SMTP relay from DMZ gateway only
   │          Block all other DMZ → Internal traffic
   │
   ▼
┌──────────────────────────────────────────┐
│      Internal Network (10.200.1.0/24)    │
│                                          │
│  ┌────────────────────────────────┐     │
│  │  Internal Mail Server          │     │
│  │  (10.200.1.25)                 │     │
│  │  - Postfix (employee mailboxes)│     │
│  │  - Dovecot IMAP                │     │
│  │  - User authentication         │     │
│  │  - Mail storage                │     │
│  └────────────────────────────────┘     │
│                                          │
│  ┌────────────────────────────────┐     │
│  │  Django Application            │     │
│  │  (10.200.1.12)                 │     │
│  │  - Connects to Internal Server │     │
│  │  - Sends transactional emails  │     │
│  └────────────────────────────────┘     │
└──────────────────────────────────────────┘
```

## Components

### 1. DMZ Mail Gateway (10.200.9.10)
**Purpose**: Public-facing SMTP relay with security filtering
- **Software**: Postfix 3.7+
- **Function**: SMTP relay only (no mailbox storage)
- **Ports**: 25 (SMTP), 587 (Submission)
- **Security**:
  - Rate limiting (max 100 emails/hour per IP)
  - Greylisting (temporary rejection)
  - SPF/DKIM verification (inbound)
  - DKIM signing (outbound)
  - Anti-spam (SpamAssassin)
  - Anti-virus (ClamAV)
  - TLS encryption required

### 2. Internal Mail Server (10.200.1.25)
**Purpose**: Employee mailboxes and storage
- **Software**: Postfix + Dovecot
- **Function**: Mail storage, IMAP access
- **Ports**: 993 (IMAPS - internal only)
- **Features**:
  - User authentication (LDAP/Database)
  - Encrypted storage
  - Quota management
  - No direct internet access

### 3. Firewall 1 - External (DMZ Boundary)
**Rules**:
```
# Inbound from Internet
ALLOW   tcp/25   Internet → 10.200.9.10    (SMTP)
ALLOW   tcp/587  Internet → 10.200.9.10    (Submission with STARTTLS)
ALLOW   tcp/443  Internet → 10.200.9.10    (Cloudflare Tunnel)
DENY    *        Internet → 10.200.9.0/24  (Default deny)

# Outbound from DMZ
ALLOW   tcp/25   10.200.9.10 → Internet    (Outbound mail relay)
ALLOW   tcp/53   10.200.9.10 → Internet    (DNS queries)
ALLOW   tcp/80,443 10.200.9.10 → Internet  (Updates, CRL checks)
DENY    *        10.200.9.0/24 → Internet  (Default deny)
```

### 4. Firewall 2 - Internal (DMZ → Internal)
**Rules**:
```
# DMZ to Internal (VERY restrictive)
ALLOW   tcp/25   10.200.9.10 → 10.200.1.25  (SMTP relay only)
DENY    *        10.200.9.0/24 → 10.200.1.0/24 (Block all other DMZ traffic)

# Internal to DMZ (for outbound mail)
ALLOW   tcp/25   10.200.1.25 → 10.200.9.10  (Relay outbound mail)
ALLOW   tcp/25   10.200.1.12 → 10.200.9.10  (Django app → gateway)
DENY    *        10.200.1.0/24 → 10.200.9.0/24 (Default deny)
```

## Security Features

### 1. Attack Surface Reduction
- DMZ gateway runs SMTP relay ONLY
- No shell access (minimal container image)
- No unnecessary services
- Read-only file system where possible
- No mailbox storage in DMZ

### 2. DKIM, SPF, DMARC
- **SPF**: Authorize sending IPs
- **DKIM**: Cryptographically sign outbound mail
- **DMARC**: Policy for handling failures

DNS Records:
```
hookprobe.com.           IN TXT "v=spf1 ip4:10.200.9.10 include:_spf.google.com ~all"
_dmarc.hookprobe.com.    IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@hookprobe.com"
default._domainkey.hookprobe.com. IN TXT "v=DKIM1; k=rsa; p=<public-key>"
```

### 3. Intrusion Detection (IDS)
- **Suricata IDS** in DMZ (10.200.9.11)
- Monitor all SMTP traffic
- Detect:
  - SMTP enumeration attacks
  - Brute force attempts
  - Spam campaigns
  - Command injection attempts
  - Abnormal traffic patterns

### 4. Logging & Monitoring
- Centralized logging to POD-007 (Wazuh)
- Mail logs forwarded to SIEM
- Real-time alerts for:
  - Failed authentication attempts
  - Rate limit violations
  - Suspicious attachments
  - Policy violations
- Retention: 90 days minimum

### 5. Cloudflare Tunnel Integration
- TLS termination at Cloudflare
- DDoS protection
- Zero-trust access
- Hide origin IP
- WAF rules for SMTP abuse

## Mail Flow

### Inbound Mail Flow
```
Internet
  → Cloudflare (DDoS protection, TLS)
  → Firewall 1 (port 25 allowed)
  → DMZ Gateway (10.200.9.10)
      ├─ SPF/DKIM verification
      ├─ Anti-spam (SpamAssassin)
      ├─ Anti-virus (ClamAV)
      ├─ Rate limiting
      └─ Greylisting
  → Firewall 2 (SMTP relay allowed)
  → Internal Server (10.200.1.25)
  → User mailbox
```

### Outbound Mail Flow
```
Django App (10.200.1.12)
  → Internal Server (10.200.1.25)
  → Firewall 2 (allowed)
  → DMZ Gateway (10.200.9.10)
      ├─ DKIM signing
      ├─ SPF check
      └─ TLS encryption
  → Firewall 1 (port 25 outbound allowed)
  → Internet
```

## Deployment

### Docker Compose
All components deployed as containers:
- `dmz-mail-gateway`: Postfix relay + security filtering
- `dmz-mail-ids`: Suricata IDS monitoring
- `internal-mail-server`: Postfix + Dovecot
- `cloudflared`: Cloudflare Tunnel client

### Networks
```yaml
networks:
  dmz:
    ipam:
      config:
        - subnet: 10.200.9.0/24
  internal:
    ipam:
      config:
        - subnet: 10.200.1.0/24
```

## Monitoring Endpoints

- **Mail Queue Status**: `/var/spool/postfix` monitoring
- **Delivery Metrics**: Success/failure rates
- **Security Events**: IDS alerts from Suricata
- **Performance**: Queue length, delivery time
- **Health Check**: `postfix status`, `dovecot status`

## Compliance

- **Data at Rest**: Encrypted mailbox storage
- **Data in Transit**: TLS required for all connections
- **Access Control**: Role-based access to mail logs
- **Audit Trail**: All mail operations logged
- **Retention**: 90-day log retention

## Disaster Recovery

- **Backup**: Daily mailbox backups to POD-006
- **Queue Persistence**: Postfix queue backed up every 6 hours
- **Configuration Backup**: Daily backups of all configs
- **Recovery Time**: < 1 hour for mail service restoration
- **Redundancy**: Secondary MX record for failover

## Maintenance

- **Updates**: Weekly security patches (automated)
- **Certificate Renewal**: Auto-renewal via Let's Encrypt/Cloudflare
- **Log Rotation**: Daily rotation, 90-day retention
- **Queue Management**: Automated queue flushing
- **Blocklist Updates**: Daily updates for anti-spam

## Integration with HookProbe

### Django Email Backend
```python
# settings.py
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = '10.200.1.25'  # Internal mail server
EMAIL_PORT = 25
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'noreply@hookprobe.com'
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_PASSWORD')
DEFAULT_FROM_EMAIL = 'HookProbe <noreply@hookprobe.com>'
```

### Use Cases
1. **Transactional Emails**: Password resets, account verification
2. **Alert Notifications**: Security alerts to customers
3. **Report Delivery**: Scheduled vulnerability reports
4. **Marketing**: Newsletter campaigns (rate-limited)

## Cost Estimate

| Component | Monthly Cost |
|-----------|--------------|
| Cloudflare Tunnel | $0 (Free tier) |
| Container Resources | ~$20 (2 vCPU, 4GB RAM) |
| Storage (mailboxes) | ~$10 (100GB) |
| Bandwidth | ~$5 (estimate) |
| **Total** | **~$35/month** |

## References

- [Postfix Documentation](http://www.postfix.org/documentation.html)
- [Dovecot Wiki](https://wiki.dovecot.org/)
- [DKIM Best Practices](https://www.dkim.org/)
- [Cloudflare Tunnel Setup](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/)
- [Suricata Rules](https://suricata.readthedocs.io/)
