# HookProbe Attack Mitigation System - Installation & Deployment Guide

## 🎯 Overview

The HookProbe Attack Mitigation System provides **automated threat detection and response** with:

- ✅ **Multi-Source Intelligence**: Qsecbit AI, VictoriaMetrics, VictoriaLogs, Snort3, Zeek, ModSecurity
- ✅ **Honeypot Redirection**: SNAT rules redirect attackers to honeypots for analysis
- ✅ **Automated Blocking**: Critical threats blocked immediately
- ✅ **Email Alerts**: Security team notified at qsecbit@hookprobe.com
- ✅ **Clean Traffic**: Normal users unaffected by mitigation

---

## 📋 Prerequisites

### System Requirements
- **OS**: RHEL 10 / Fedora / CentOS Stream (same as HookProbe)
- **HookProbe**: v4.0 installed and running
- **Root Access**: Required for iptables and system configuration
- **Email**: MTA configured (postfix/sendmail) for notifications

### Dependencies
```bash
# Install required packages
sudo dnf install -y \
    iptables \
    jq \
    curl \
    tar \
    gzip \
    mailx \
    cronie
```

---

## 🚀 Quick Installation

### Step 1: Download Scripts

```bash
# Create installation directory
sudo mkdir -p /opt/hookprobe/mitigation
cd /opt/hookprobe/mitigation

# Download all scripts
wget https://your-repo/attack-mitigation-orchestrator.sh
wget https://your-repo/mitigation-config.conf
wget https://your-repo/honeypot-manager.sh
wget https://your-repo/mitigation-maintenance.sh

# Make executable
chmod +x *.sh
```

### Step 2: Configure

```bash
# Edit configuration
sudo nano mitigation-config.conf
```

**Critical settings to change:**

```bash
# Email notification
NOTIFICATION_EMAIL="qsecbit@hookprobe.com"

# API endpoints (verify these match your setup)
QSECBIT_API="http://10.200.6.12:8888"
VICTORIAMETRICS_URL="http://10.200.5.11:9090"
VICTORIALOGS_URL="http://10.200.5.12:9428"

# Log file paths (adjust based on your installation)
SNORT3_ALERT_FILE="/var/log/snort/alert_fast.txt"
ZEEK_NOTICE_LOG="/opt/zeek/logs/current/notice.log"
```

### Step 3: Install System Files

```bash
# Copy to system directories
sudo cp attack-mitigation-orchestrator.sh /usr/local/bin/
# Note: honeypot-manager.sh is planned for future release
# sudo cp honeypot-manager.sh /usr/local/bin/
sudo cp mitigation-maintenance.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/{attack-mitigation-orchestrator,# honeypot-manager,  # Plannedmitigation-maintenance}.sh

# Copy configuration
sudo mkdir -p /etc/hookprobe
sudo cp mitigation-config.conf /etc/hookprobe/
sudo chmod 600 /etc/hookprobe/mitigation-config.conf

# Create required directories
sudo mkdir -p /var/log/hookprobe/mitigation
sudo mkdir -p /var/lib/hookprobe/mitigation
sudo mkdir -p /var/lib/hookprobe/reports
```

### Step 4: Deploy Honeypots

```bash
# Deploy all honeypots
# sudo honeypot-manager.sh  # Planned feature deploy

# Verify deployment
# sudo honeypot-manager.sh  # Planned feature stats
```

Expected output:
```
Cowrie SSH/Telnet attacks logged: 0
Web honeypot requests logged: 0

Container Status:
NAMES                              STATUS              PORTS
hookprobe-honeypot-cowrie         Up 2 minutes        0.0.0.0:2222->2222/tcp
hookprobe-honeypot-dionaea        Up 2 minutes        0.0.0.0:21->21/tcp, ...
hookprobe-honeypot-web            Up 2 minutes        0.0.0.0:8080->80/tcp
```

### Step 5: Set Up Automation

#### Option A: Systemd (Recommended)

```bash
# Extract systemd units from the config file
cat > /etc/systemd/system/hookprobe-mitigation.service << 'EOF'
[Unit]
Description=HookProbe Attack Mitigation Service
After=network.target podman.service
Requires=podman.service

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/bin/attack-mitigation-orchestrator.sh
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/hookprobe-mitigation.timer << 'EOF'
[Unit]
Description=HookProbe Attack Mitigation Timer
Requires=hookprobe-mitigation.service

[Timer]
OnBootSec=1min
OnUnitActiveSec=30s
AccuracySec=1s
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable hookprobe-mitigation.timer
sudo systemctl start hookprobe-mitigation.timer
```

#### Option B: Cron

```bash
# Add to root crontab
sudo crontab -e

# Run every minute
* * * * * /usr/local/bin/attack-mitigation-orchestrator.sh >> /var/log/hookprobe/mitigation/cron.log 2>&1
```

### Step 6: Set Up Maintenance

```bash
# Add daily maintenance cron job
sudo crontab -e

# Daily at 2 AM
0 2 * * * /usr/local/bin/mitigation-maintenance.sh auto >> /var/log/hookprobe/mitigation/maintenance.log 2>&1
```

---

## 🔧 Configuration Guide

### Email Notifications

**Test email configuration:**
```bash
echo "Test email from HookProbe" | mail -s "Test" qsecbit@hookprobe.com
```

**Configure postfix (if not already configured):**
```bash
sudo dnf install -y postfix mailx
sudo systemctl enable --now postfix

# Configure as relay or smarthost
sudo vi /etc/postfix/main.cf
```

### Qsecbit Integration

Ensure Qsecbit thresholds are configured:

```bash
# In network-config.sh (from Stage 1)
QSECBIT_AMBER_THRESHOLD=0.45
QSECBIT_RED_THRESHOLD=0.70
```

Mitigation activates when Qsecbit enters **AMBER** or **RED** status.

### Honeypot Customization

**Change honeypot ports (if needed):**
```bash
# Edit mitigation-config.conf
HONEYPOT_SSH_PORT=2222      # SSH honeypot
HONEYPOT_TELNET_PORT=2223   # Telnet honeypot
HONEYPOT_HTTP_PORT=8080     # Web honeypot

# Redeploy
# sudo honeypot-manager.sh  # Planned feature remove
# sudo honeypot-manager.sh  # Planned feature deploy
```

### IP Whitelisting

**Prevent blocking trusted IPs:**
```bash
# Edit mitigation-config.conf
IP_WHITELIST=(
    "127.0.0.1"
    "::1"
    "10.200.0.0/16"             # Internal HookProbe
    "192.168.1.0/24"            # Your office network
    "203.0.113.10"              # Trusted partner IP
)
```

---

## 📊 Monitoring & Operations

### Check System Status

```bash
# Systemd status
sudo systemctl status hookprobe-mitigation.timer
sudo systemctl status hookprobe-mitigation.service

# View logs
sudo journalctl -u hookprobe-mitigation.service -f

# Or direct log file
sudo tail -f /var/log/hookprobe/mitigation/attack-mitigation.log
```

### View Active Mitigations

```bash
# Blocked IPs
cat /var/lib/hookprobe/mitigation/blocked_ips.txt

# Honeypot redirects
cat /var/lib/hookprobe/mitigation/honeypot_redirects.txt

# Recent attack reports
ls -lt /var/lib/hookprobe/reports/attack_report_*.json | head -5
```

### Honeypot Analytics

```bash
# Show honeypot statistics
# sudo honeypot-manager.sh  # Planned feature stats

# Analyze specific attacker
# sudo honeypot-manager.sh  # Planned feature analyze 192.168.1.100

# Export all honeypot logs
# sudo honeypot-manager.sh  # Planned feature export
```

### Manual Operations

```bash
# Run mitigation manually
sudo /usr/local/bin/attack-mitigation-orchestrator.sh

# Run maintenance
sudo /usr/local/bin/mitigation-maintenance.sh auto

# Health check
sudo /usr/local/bin/mitigation-maintenance.sh health
```

---

## 🎯 How It Works

### Attack Detection Flow

```
1. Qsecbit detects AMBER/RED status
           ↓
2. Query all log sources:
   - Snort3 (network attacks)
   - Zeek (behavioral anomalies)
   - ModSecurity (web attacks)
   - VictoriaLogs (application logs)
           ↓
3. Identify malicious IPs
           ↓
4. Classify severity:
   - CRITICAL: 10+ attacks
   - HIGH: 5-9 attacks
   - MEDIUM: 2-4 attacks
   - LOW: 1 attack
           ↓
5. Execute mitigation:
   - CRITICAL/HIGH → Block immediately
   - MEDIUM/LOW → Redirect to honeypot
           ↓
6. Send email notification
```

### Mitigation Decision Matrix

| Severity | Qsecbit Status | Action | Honeypot | Email |
|----------|----------------|--------|----------|-------|
| CRITICAL | RED | Block | No | Yes |
| HIGH | RED/AMBER | Block | No | Yes |
| MEDIUM | AMBER | Honeypot | Yes | Yes |
| LOW | AMBER | Honeypot | Yes | No |

### SNAT Redirection

When an IP is redirected to honeypot:

```bash
# SSH traffic (port 22) → Honeypot SSH (2222)
iptables -t nat -A PREROUTING -s <ATTACKER_IP> -p tcp --dport 22 \
    -j DNAT --to-destination 10.200.7.10:2222

# HTTP traffic (port 80) → Honeypot Web (8080)
iptables -t nat -A PREROUTING -s <ATTACKER_IP> -p tcp --dport 80 \
    -j DNAT --to-destination 10.200.7.10:8080

# HTTPS traffic (port 443) → Honeypot Web (8080)
iptables -t nat -A PREROUTING -s <ATTACKER_IP> -p tcp --dport 443 \
    -j DNAT --to-destination 10.200.7.10:8080
```

**Result**: Attacker thinks they're attacking real system, but all traffic goes to honeypot for analysis.

---

## 🐛 Troubleshooting

### Mitigation Not Running

```bash
# Check timer
sudo systemctl status hookprobe-mitigation.timer

# If not active
sudo systemctl start hookprobe-mitigation.timer

# Check for errors
sudo journalctl -u hookprobe-mitigation.service --since "1 hour ago"
```

### Qsecbit API Not Reachable

```bash
# Test connectivity
curl http://10.200.6.12:8888/health

# If fails, check Qsecbit container
podman ps | grep qsecbit
podman logs hookprobe-pod-007-ai-response-qsecbit
```

### No Attacks Detected

This is normal if system is healthy. To test:

```bash
# Manually create test attack report
cat > /var/lib/hookprobe/reports/attack_report_test.json << 'EOF'
{
  "timestamp": "2025-01-15T10:30:00Z",
  "qsecbit_status": "AMBER",
  "attacks": [
    {"source": "test", "ip": "203.0.113.100", "alert": "Test attack"}
  ],
  "total_attacks": 1
}
EOF

# Add test IP
echo "203.0.113.100" > /var/lib/hookprobe/mitigation/malicious_ips.txt

# Run manually
sudo /usr/local/bin/attack-mitigation-orchestrator.sh
```

### Email Not Sending

```bash
# Test mail command
echo "Test" | mail -s "Test" qsecbit@hookprobe.com

# Check mail logs
sudo journalctl -u postfix -f

# Verify SMTP configuration
sudo postconf | grep relayhost
```

### Honeypot Not Logging

```bash
# Check honeypot containers
podman logs hookprobe-honeypot-cowrie
podman logs hookprobe-honeypot-web

# Check log directories
ls -la /opt/hookprobe/honeypots/cowrie/var/log/
ls -la /opt/hookprobe/honeypots/web/logs/
```

---

## 📧 Email Notification Example

When attacks are detected, security team receives:

```
Subject: 🚨 HookProbe Security Alert - AMBER Status - 5 Attacks Detected

HookProbe Security Alert - Attack Detected
=============================================

Timestamp: 2025-01-15T10:30:45Z
Qsecbit Status: AMBER
Total Attacks Detected: 5

INCIDENT SUMMARY:
-----------------
Multiple attack patterns have been detected by HookProbe's security systems.
The Qsecbit AI analysis engine has classified the current threat level as: AMBER

ACTIONS TAKEN:
--------------
- Malicious IPs identified and catalogued
- Automatic mitigation initiated
- Honeypot redirection activated
- IP blocking applied for critical threats
- Detailed attack report attached

NEXT STEPS:
-----------
1. Review the attached attack report
2. Analyze honeypot logs for attacker behavior
3. Update WAF rules based on attack patterns
4. Review and adjust Qsecbit thresholds if needed

[Full JSON report attached]
```

---

## 🔒 Security Best Practices

1. **Regular Reviews**: Check honeypot logs weekly for patterns
2. **Threshold Tuning**: Adjust Qsecbit thresholds based on your environment
3. **Whitelist Management**: Keep trusted IP list updated
4. **Backup**: Mitigation automatically backs up configuration daily
5. **Monitoring**: Set up alerts for mitigation system failures

---

## 📈 Performance Tuning

### High-Traffic Environments

```bash
# Edit mitigation-config.conf

# Increase parallel processing
MAX_CONCURRENT_PROCESSES=8

# Reduce check interval (careful - high CPU)
QSECBIT_CHECK_INTERVAL=15  # seconds

# Increase rate limit
MAX_MITIGATIONS_PER_MINUTE=500
```

### Low-Resource Systems

```bash
# Reduce honeypot instances
# Only deploy essential honeypots

# Increase check interval
QSECBIT_CHECK_INTERVAL=60  # seconds

# Disable expensive features
ENABLE_ML_CORRELATION=false
```

---

## 🗑️ Uninstallation

```bash
# Stop services
sudo systemctl stop hookprobe-mitigation.timer
sudo systemctl disable hookprobe-mitigation.timer

# Remove honeypots
# sudo honeypot-manager.sh  # Planned feature remove

# Remove files
sudo rm -f /usr/local/bin/attack-mitigation-orchestrator.sh
sudo rm -f /usr/local/bin/honeypot-manager.sh
sudo rm -f /usr/local/bin/mitigation-maintenance.sh
sudo rm -rf /etc/hookprobe
sudo rm -rf /var/log/hookprobe/mitigation
sudo rm -rf /var/lib/hookprobe/mitigation
sudo rm -rf /var/lib/hookprobe/reports
sudo rm -f /etc/systemd/system/hookprobe-mitigation.*

# Flush iptables rules (CAREFUL - this removes ALL rules)
# sudo iptables -F
# sudo iptables -t nat -F
```

---

## 📝 Maintenance Schedule

| Task | Frequency | Command |
|------|-----------|---------|
| Health Check | Daily | `mitigation-maintenance.sh health` |
| Statistics Review | Weekly | `mitigation-maintenance.sh stats` |
| Honeypot Export | Weekly | `honeypot-manager.sh export` |
| Full Maintenance | Daily (auto) | `mitigation-maintenance.sh auto` |
| Configuration Backup | Daily (auto) | Automatic |

---

## 🎓 Advanced Usage

### Custom Attack Patterns

Add your own attack signatures to `mitigation-config.conf`:

```bash
# Custom pattern for your application
CUSTOM_PATTERN='(your_app_error AND suspicious_param) AND level:error'
```

Then modify `attack-mitigation-orchestrator.sh` to query this pattern.

### Integration with SIEM

Export attack data to your SIEM:

```bash
# Continuous export to syslog
tail -f /var/lib/hookprobe/reports/attack_report_*.json | \
    logger -t hookprobe-attacks -p local0.warning
```

### Geo-Blocking

Enable in `mitigation-config.conf`:

```bash
ENABLE_GEO_BLOCKING=true
BLOCKED_COUNTRIES=("CN" "RU" "KP")  # ISO country codes
```

(Requires GeoIP database installation)

---

## 📞 Support

**Email**: qsecbit@hookprobe.com  
**GitHub Issues**: https://github.com/hookprobe/hookprobe/issues  
**Documentation**: https://docs.hookprobe.com

---

## 📄 License

MIT License - See LICENSE file

---

**Version**: 1.0  
**Last Updated**: 2025  
**Status**: Production Ready 🚀
