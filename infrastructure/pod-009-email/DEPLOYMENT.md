# POD-009 Email System Deployment Guide

## Quick Start

```bash
cd /home/user/hookprobe/infrastructure/pod-009-email

# 1. Deploy containers with Podman
podman-compose up -d

# 2. Configure firewalls
sudo bash firewall-rules/iptables-firewall1-external.sh
sudo bash firewall-rules/iptables-firewall2-internal.sh

# 3. Setup DKIM
podman exec hookprobe-dmz-mail-gateway bash /opt/dkim-setup.sh

# 4. Configure DNS records (see dmz-gateway/spf-dmarc-setup.md)

# 5. Setup Cloudflare Tunnel
cloudflared tunnel create hookprobe-mail
cloudflared tunnel route dns hookprobe-mail mail.hookprobe.com

# 6. Test email
podman exec hookprobe-internal-mail echo "Test" | mail -s "Test" your-email@example.com
```

## Detailed Deployment Steps

### 1. Prerequisites

- **Podman** and **podman-compose** installed
- DNS access to create TXT/MX records
- Cloudflare account (free tier works)
- Public IP address for DMZ gateway
- iptables-persistent package

**Install Podman (if not installed):**
```bash
# Ubuntu/Debian
sudo apt-get install podman podman-compose

# Verify installation
podman --version
podman-compose --version
```

> **Note**: RHEL-based systems are not supported due to OpenVSwitch availability limitations.

### 2. Network Setup

```bash
# Create Podman networks
podman network create hookprobe-dmz --subnet=10.200.9.0/24
podman network create hookprobe-internal --subnet=10.200.1.0/24 --internal

# Verify networks
podman network ls
```

### 3. Deploy Containers

```bash
# Start all services with podman-compose
podman-compose up -d

# Verify containers are running
podman ps | grep hookprobe

# Check logs
podman-compose logs -f

# Or check individual container
podman logs -f hookprobe-dmz-mail-gateway
```

### 4. Configure Firewalls

**Firewall 1 - External (Internet ↔ DMZ):**
```bash
sudo bash firewall-rules/iptables-firewall1-external.sh

# Verify rules
sudo iptables -L -v -n

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

**Firewall 2 - Internal (DMZ ↔ Internal):**
```bash
sudo bash firewall-rules/iptables-firewall2-internal.sh

# Verify rules
sudo iptables -L -v -n

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

**Make rules persistent:**
```bash
sudo apt-get install iptables-persistent
sudo netfilter-persistent save
sudo systemctl enable netfilter-persistent
```

### 5. Setup DKIM Signing

```bash
# Generate DKIM keys
podman exec -it hookprobe-dmz-mail-gateway bash dmz-gateway/dkim-setup.sh

# Copy DNS record
podman exec hookprobe-dmz-mail-gateway cat /etc/postfix/dkim/keys/hookprobe.com/default.txt

# Add to DNS (see next section)
```

### 6. Configure DNS Records

**Add these records to your DNS provider:**

```dns
; MX Record
hookprobe.com.           IN  MX  10  mail.hookprobe.com.

; A Record
mail.hookprobe.com.      IN  A   YOUR_PUBLIC_IP

; SPF Record
hookprobe.com.           IN  TXT "v=spf1 ip4:YOUR_PUBLIC_IP ~all"

; DKIM Record (from step 5)
default._domainkey.hookprobe.com.  IN  TXT "v=DKIM1; k=rsa; p=..."

; DMARC Record
_dmarc.hookprobe.com.    IN  TXT "v=DMARC1; p=none; rua=mailto:dmarc@hookprobe.com"
```

**Request PTR record from ISP/hosting provider:**
```
YOUR_PUBLIC_IP → mail.hookprobe.com
```

### 7. Setup Cloudflare Tunnel

```bash
# Login to Cloudflare
cloudflared tunnel login

# Create tunnel
cloudflared tunnel create hookprobe-mail

# Copy credentials
sudo mkdir -p /etc/cloudflared
sudo cp ~/.cloudflared/*.json /etc/cloudflared/credentials.json

# Update config with your tunnel ID
# Edit cloudflare/config.yml

# Route DNS
cloudflared tunnel route dns hookprobe-mail mail.hookprobe.com

# Start tunnel
podman-compose restart cloudflare-tunnel

# Verify tunnel
cloudflared tunnel info hookprobe-mail
```

### 8. Configure Internal Mail Server

```bash
# Create mailboxes
podman exec -it hookprobe-internal-mail bash

# Add user
setup email add admin@hookprobe.com SecurePassword123

# List users
setup email list

# Set quota
setup quota set admin@hookprobe.com 10G
```

### 9. Configure Django Integration

**Update Django settings:**
```python
# settings.py
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = '10.200.1.25'
EMAIL_PORT = 25
EMAIL_USE_TLS = True
DEFAULT_FROM_EMAIL = 'HookProbe <noreply@hookprobe.com>'
```

**Test from Django:**
```python
from django.core.mail import send_mail

send_mail(
    'Test Email',
    'If you receive this, POD-009 is working!',
    'noreply@hookprobe.com',
    ['your-email@example.com'],
)
```

### 10. Enable IDS Monitoring

```bash
# Start Suricata
podman-compose up -d dmz-mail-ids

# Verify Suricata is running
podman exec hookprobe-dmz-mail-ids suricata --build-info

# Check rules
podman exec hookprobe-dmz-mail-ids cat /var/lib/suricata/rules/*.rules | wc -l

# Monitor alerts
podman exec hookprobe-dmz-mail-ids tail -f /var/log/suricata/fast.log

# Update rules
podman exec hookprobe-dmz-mail-ids suricata-update
podman-compose restart dmz-mail-ids
```

## Verification & Testing

### 1. Test SMTP Connectivity

```bash
# From external host
telnet mail.hookprobe.com 25

# Expected output:
# 220 mail.hookprobe.com ESMTP Postfix
# EHLO test.com
# 250-mail.hookprobe.com
# QUIT
```

### 2. Test Email Sending

```bash
# From Django app
podman exec hookprobe-django python manage.py shell

>>> from apps.common.email import send_hookprobe_email
>>> send_hookprobe_email(
...     subject="Test",
...     message="Test from POD-009",
...     recipient_list=["your-email@example.com"]
... )
1
```

### 3. Verify DKIM Signing

Send test email, check headers for:
```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=hookprobe.com;
    s=default; t=1234567890;
```

### 4. Check SPF/DKIM/DMARC

Send email to: `check-auth@verifier.port25.com`

You'll receive a report showing:
- SPF: PASS
- DKIM: PASS
- DMARC: PASS

### 5. Test Mail Delivery

Use online tools:
- https://www.mail-tester.com/
- https://mxtoolbox.com/deliverability

Target score: **9/10 or higher**

## Monitoring

### 1. Check Mail Queue

```bash
# On DMZ gateway
podman exec hookprobe-dmz-mail-gateway mailq

# On internal server
podman exec hookprobe-internal-mail mailq
```

### 2. Monitor Logs

```bash
# DMZ gateway logs
podman logs -f hookprobe-dmz-mail-gateway

# Internal server logs
podman logs -f hookprobe-internal-mail

# Suricata IDS alerts
podman logs -f hookprobe-dmz-mail-ids

# Firewall drops
tail -f /var/log/syslog | grep -E 'FW[12]'
```

### 3. Check Metrics

```bash
# Cloudflare Tunnel metrics
curl http://localhost:9090/metrics

# Postfix metrics
podman exec hookprobe-dmz-mail-gateway postfix status
```

## Maintenance

### Daily Tasks

- Review IDS alerts: `tail -f /var/log/suricata/fast.log`
- Check mail queue: `mailq`
- Monitor delivery failures: `grep "status=bounced" /var/log/mail.log`

### Weekly Tasks

- Review DMARC reports
- Update Suricata rules: `suricata-update`
- Check firewall logs for anomalies
- Verify backup completion

### Monthly Tasks

- Review and update firewall rules
- Check certificate expiration
- Rotate logs
- Security audit

### Annual Tasks

- Rotate DKIM keys
- Review and update SPF/DMARC policies
- Audit user accounts
- Disaster recovery drill

## Troubleshooting

### Problem: Emails not sending

**Check:**
1. Mail queue: `mailq`
2. Logs: `tail -f /var/log/mail.log`
3. Firewall: `iptables -L -v -n | grep 25`
4. DNS records: `dig MX hookprobe.com`

### Problem: DKIM failures

**Check:**
1. DNS propagation: `dig default._domainkey.hookprobe.com TXT`
2. OpenDKIM: `journalctl -u opendkim -f`
3. Key permissions: `ls -l /etc/postfix/dkim/keys/`

### Problem: High spam score

**Check:**
1. SPF record: `dig hookprobe.com TXT`
2. PTR record: `dig -x YOUR_PUBLIC_IP`
3. IP reputation: https://mxtoolbox.com/blacklists.aspx

### Problem: IDS alerts

**Check:**
1. Alert details: `/var/log/suricata/fast.log`
2. Source IP: `grep ALERT /var/log/suricata/eve.json`
3. Block if malicious: Add to firewall rules

## Security Checklist

- [ ] Firewalls configured and tested
- [ ] DKIM signing enabled and verified
- [ ] SPF record published
- [ ] DMARC policy set (start with p=none)
- [ ] PTR record configured
- [ ] TLS encryption enabled
- [ ] IDS monitoring active
- [ ] Rate limiting configured
- [ ] Backups scheduled
- [ ] Logging to SIEM enabled
- [ ] Incident response plan documented
- [ ] Team trained on procedures

## Support

- Documentation: /infrastructure/pod-009-email/README.md
- Logs: /var/log/mail/
- Issues: security@hookprobe.com
