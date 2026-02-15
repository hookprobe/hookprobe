# HookProbe v3.0 Deployment Checklist
## Enhanced with WAF + Cloudflare Tunnel + Centralized Logging

## Pre-Deployment Checklist

### System Requirements
- [ ] Hardware: Intel N100 or equivalent x86_64 processor
- [ ] RAM: Minimum 16GB (recommended)
- [ ] Storage: Minimum 500GB SSD
- [ ] OS: Ubuntu 22.04+, Debian 11+/12+, or Raspberry Pi OS installed
- [ ] Root access available
- [ ] Internet connectivity for downloading images

### Network Configuration
- [ ] Physical network interface identified (e.g., eth0, enp0s3)
- [ ] Host IP address noted
- [ ] Gateway IP address noted
- [ ] Remote peer IP (if multi-host) noted
- [ ] No IP conflicts with 10.200.0.0/16 range
- [ ] Firewall allows required ports (or will be configured)

### Cloudflare Tunnel Setup (Optional but Recommended)
- [ ] Cloudflare account created
- [ ] Domain added to Cloudflare
- [ ] Zero Trust dashboard accessed
- [ ] Tunnel created and token obtained
- [ ] Token saved for configuration

---

## Configuration Phase

### 1. Edit network-config.sh
- [ ] Set `HOST_A_IP` to your physical IP
- [ ] Set `HOST_B_IP` (if multi-host deployment)
- [ ] Set `PHYSICAL_HOST_INTERFACE` (verify with `ip a`)
- [ ] Set `INTERNET_GATEWAY`
- [ ] Change all PSK keys (minimum 32 characters)
  - [ ] `OVS_PSK_MAIN`
  - [ ] `OVS_PSK_DMZ`
  - [ ] `OVS_PSK_INTERNAL`
- [ ] Change database passwords
  - [ ] `POSTGRES_PASSWORD`
  - [ ] `LOGTO_DB_PASSWORD`
- [ ] Change Django secret key
  - [ ] `DJANGO_SECRET_KEY` (generate with: `openssl rand -base64 50`)
- [ ] Update `DJANGO_ALLOWED_HOSTS` for production
- [ ] **NEW**: Configure Cloudflare Tunnel
  - [ ] Set `CLOUDFLARE_TUNNEL_TOKEN` (from Cloudflare dashboard)
  - [ ] Set `CLOUDFLARE_DOMAIN` (your domain)
- [ ] **NEW**: Review NAXSI WAF settings
  - [ ] Set `NAXSI_LEARNING_MODE` (0=blocking, 1=learning)

### 2. Review Port Mappings
- [ ] Port 80 (HTTP) - Available
- [ ] Port 443 (HTTPS) - Available
- [ ] Port 3000 (Grafana) - Available
- [ ] Port 3001 (Logto) - Available
- [ ] Port 3002 (Logto Admin) - Available
- [ ] Port 5432 (PostgreSQL) - Available (optional external access)
- [ ] Port 8080 (WAF Management) - Available
- [ ] Port 9090 (Prometheus) - Available
- [ ] Port 9093 (Alertmanager) - Available
- [ ] Port 514 (Syslog UDP/TCP) - Available
- [ ] Port 6514 (Syslog TLS) - Available

### 3. Make Scripts Executable
```bash
chmod +x network-config.sh setup.sh uninstall.sh
```

---

## Deployment Phase

### 4. Run Setup Script
```bash
sudo ./setup.sh
```

**Estimated Time**: 15-20 minutes (includes WAF build)

### 5. Monitor Deployment
Watch for these checkpoints:
- [ ] ✓ Environment validated
- [ ] ✓ Cloudflare token verified (or skipped)
- [ ] ✓ Dependencies installed
- [ ] ✓ Kernel modules loaded
- [ ] ✓ OVS bridges created
- [ ] ✓ VXLAN tunnels established
- [ ] ✓ Firewall configured
- [ ] ✓ Rsyslog forwarding configured
- [ ] ✓ Podman networks created
- [ ] ✓ Volumes created
- [ ] ✓ POD 003 deployed (Database)
- [ ] ✓ POD 004 deployed (Redis)
- [ ] ✓ Django built
- [ ] ✓ POD 002 deployed (Logto IAM)
- [ ] ✓ POD 005 deployed (Monitoring + Logging)
  - [ ] Rsyslog server started
  - [ ] Prometheus started
  - [ ] Loki started
  - [ ] Promtail started
  - [ ] Alertmanager started
  - [ ] Node Exporter started
  - [ ] cAdvisor started
  - [ ] Grafana started
- [ ] ✓ POD 001 deployed (Web DMZ)
  - [ ] Django started
  - [ ] NAXSI WAF built (or standard Nginx)
  - [ ] Nginx started
  - [ ] Cloudflare Tunnel started (if configured)
- [ ] ✓ POD 006 deployed (Security)

---

## Post-Deployment Verification

### 6. Verify Services
```bash
# Check all PODs are running
podman pod ps

# Verify container status
podman ps -a

# Check OVS configuration
ovs-vsctl show

# Test network connectivity
ping 10.200.1.10  # Django
ping 10.200.2.10  # Logto
ping 10.200.3.10  # PostgreSQL
ping 10.200.5.17  # Rsyslog

# Check rsyslog forwarding
logger -t hookprobe-test "Test message from host"
# Then check in Grafana Loki
```

- [ ] All 6 PODs showing as "Running"
- [ ] All containers in "Up" state
- [ ] OVS bridge shows 7 VXLAN tunnels
- [ ] Network connectivity confirmed
- [ ] Log forwarding working

### 7. Access Web Interfaces

#### Django Admin
- [ ] Open: http://YOUR_IP/admin
- [ ] Login: admin / admin
- [ ] Login successful
- [ ] Change admin password immediately

#### NAXSI WAF
- [ ] Check WAF logs: `podman logs hookprobe-pod-001-web-dmz-nginx-naxsi`
- [ ] Verify WAF is intercepting requests
- [ ] Test with a simple XSS attempt (blocked)
- [ ] Review learning mode logs

#### Cloudflare Tunnel (if configured)
- [ ] Open Cloudflare Zero Trust Dashboard
- [ ] Verify tunnel is connected
- [ ] Configure public hostname routing
- [ ] Test access via Cloudflare domain

#### Logto Admin Console
- [ ] Open: http://YOUR_IP:3002
- [ ] Complete initial setup wizard
- [ ] Create admin account
- [ ] Note credentials securely

#### Grafana
- [ ] Open: http://YOUR_IP:3000
- [ ] Login: admin / admin
- [ ] Change admin password
- [ ] Verify data sources (Prometheus, Loki)
- [ ] Data sources showing green checkmarks
- [ ] Test log query in Explore

#### Prometheus
- [ ] Open: http://YOUR_IP:9090
- [ ] Check Status → Targets
- [ ] All targets showing as "UP"

#### Centralized Logging
- [ ] Access Grafana → Explore → Loki
- [ ] Query: `{job="rsyslog"}`
- [ ] Verify system logs are visible
- [ ] Query: `{job="containerlogs"}`
- [ ] Verify container logs are aggregated

---

## Security Hardening

### 8. Change Default Passwords
- [ ] Django admin password changed
- [ ] Grafana admin password changed
- [ ] Logto admin password changed
- [ ] PostgreSQL password updated (if needed)
- [ ] Document new passwords securely

### 9. Configure WAF Rules
- [ ] Review NAXSI learning mode logs
- [ ] Identify false positives
- [ ] Create whitelist rules
- [ ] Switch to blocking mode: `NAXSI_LEARNING_MODE="0"`
- [ ] Restart Nginx container
- [ ] Test WAF blocking

### 10. Configure SSL/TLS
**Option A: Cloudflare Tunnel (Recommended)**
- [ ] Cloudflare automatically provides SSL
- [ ] Configure origin certificate (optional)
- [ ] Enable Full (Strict) SSL mode

**Option B: Let's Encrypt**
- [ ] Install certbot
- [ ] Obtain SSL certificates
- [ ] Configure Nginx for HTTPS
- [ ] Set up auto-renewal

### 11. Review Firewall Rules
```bash
firewall-cmd --list-all
```
- [ ] Only necessary ports exposed
- [ ] Internal networks properly trusted
- [ ] No unintended open ports
- [ ] WAF management port restricted to admin IPs

---

## Logto IAM Configuration

### 12. Configure Logto Application
- [ ] Access Logto Admin Console
- [ ] Create new application (Traditional Web)
- [ ] Application name: "HookProbe Django"
- [ ] Note App ID
- [ ] Note App Secret
- [ ] Add redirect URI: http://YOUR_IP/auth/callback
- [ ] Add post logout redirect: http://YOUR_IP/
- [ ] Save configuration

### 13. Integrate Django with Logto
- [ ] Update Django settings with Logto credentials
- [ ] Restart Django container: `podman restart hookprobe-pod-001-web-dmz-django`
- [ ] Test SSO login flow
- [ ] Verify user creation in Django
- [ ] Test logout flow

---

## Monitoring & Logging Configuration

### 14. Configure Grafana Dashboards
- [ ] Import HookProbe dashboards (use provided JSON)
- [ ] Create WAF monitoring dashboard
- [ ] Create log aggregation dashboard
- [ ] Verify metrics are flowing
- [ ] Test log queries in Loki
- [ ] Configure dashboard refresh intervals

### 15. Verify Centralized Logging
- [ ] Query system logs: `{job="rsyslog"} |= "error"`
- [ ] Query kernel logs: `{job="rsyslog"} |= "kernel"`
- [ ] Query WAF logs: `{job="containerlogs"} | container_name=~".*naxsi.*"`
- [ ] Query Django logs: `{job="containerlogs"} | container_name=~".*django.*"`
- [ ] Query all IDS alerts: `{job="containerlogs"} | container_name=~".*napse.*" |= "ALERT"`

### 16. Set Up Alerting
- [ ] Configure notification channels (email, Slack, etc.)
- [ ] Create alert rules for:
  - [ ] High CPU usage (>80%)
  - [ ] High memory usage (>90%)
  - [ ] Container down
  - [ ] Disk space low (<10%)
  - [ ] Database connection issues
  - [ ] Security threats detected
  - [ ] **NEW**: WAF blocks exceeding threshold
  - [ ] **NEW**: Cloudflare tunnel disconnected
  - [ ] **NEW**: Rsyslog server unreachable
- [ ] Test alert delivery

### 17. Configure Log Retention
- [ ] Set Loki retention period
- [ ] Configure log rotation for rsyslog
- [ ] Set up automated log archival
- [ ] Document retention policies

---

## Cloudflare Configuration (if using Tunnel)

### 18. Configure Cloudflare Routing
- [ ] Open Cloudflare Zero Trust Dashboard
- [ ] Navigate to Access → Tunnels
- [ ] Select your tunnel
- [ ] Add public hostname:
  - [ ] Domain: your-domain.com
  - [ ] Service: http://localhost:80
- [ ] Save configuration
- [ ] Test access via domain

### 19. Configure Cloudflare WAF (Optional - Additional Layer)
- [ ] Enable Cloudflare WAF rules
- [ ] Configure rate limiting
- [ ] Set up bot protection
- [ ] Configure DDoS protection
- [ ] Note: This complements NAXSI WAF

---

## Application Deployment

### 20. Upload ThemeForest Template
- [ ] Copy template files to Django container
- [ ] Convert HTML to Django templates
- [ ] Update static file references
- [ ] Collect static files: `podman exec hookprobe-pod-001-web-dmz-django python manage.py collectstatic`
- [ ] Test template rendering
- [ ] Verify responsive design

### 21. Configure Django CMS
- [ ] Create CMS pages
- [ ] Configure page templates
- [ ] Add content placeholders
- [ ] Test page creation workflow
- [ ] Configure user permissions

---

## Backup & Recovery Setup

### 22. Configure Automated Backups
```bash
# Create backup script
cat > /usr/local/bin/hookprobe-backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/backup/hookprobe/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup volumes
podman volume export hookprobe-postgres-data > "$BACKUP_DIR/postgres.tar"
podman volume export hookprobe-grafana-data > "$BACKUP_DIR/grafana.tar"
podman volume export hookprobe-django-static > "$BACKUP_DIR/django-static.tar"
podman volume export hookprobe-rsyslog-data > "$BACKUP_DIR/rsyslog.tar"
podman volume export hookprobe-waf-logs > "$BACKUP_DIR/waf-logs.tar"

# Backup configurations
cp /path/to/network-config.sh "$BACKUP_DIR/"
ovs-vsctl show > "$BACKUP_DIR/ovs-config.txt"

# Compress
tar -czf "$BACKUP_DIR.tar.gz" -C "$(dirname $BACKUP_DIR)" "$(basename $BACKUP_DIR)"
rm -rf "$BACKUP_DIR"

# Keep only last 7 days
find /backup/hookprobe/ -name "*.tar.gz" -mtime +7 -delete
EOF

chmod +x /usr/local/bin/hookprobe-backup.sh
```

- [ ] Backup script created
- [ ] Test backup script execution
- [ ] Configure cron job for daily backups
- [ ] Verify backup storage location has sufficient space
- [ ] Test restore procedure

### 23. Create Cron Job
```bash
# Add to crontab
crontab -e

# Daily backup at 2 AM
0 2 * * * /usr/local/bin/hookprobe-backup.sh
```

- [ ] Cron job configured
- [ ] First backup completed successfully
- [ ] Backup files verified

---

## Testing & Validation

### 24. Functional Testing
- [ ] Test user registration/login via Logto
- [ ] Test Django CMS page creation
- [ ] Test file uploads (media)
- [ ] Test static file serving
- [ ] Test database connectivity
- [ ] Test Redis caching
- [ ] Verify email sending (if configured)

### 25. WAF Testing
- [ ] Test XSS attack (should be blocked)
- [ ] Test SQL injection (should be blocked)
- [ ] Test directory traversal (should be blocked)
- [ ] Test command injection (should be blocked)
- [ ] Verify legitimate traffic passes
- [ ] Review WAF logs in Grafana
- [ ] Tune false positives

### 26. Logging Testing
- [ ] Generate test log from host: `logger -t test "Test message"`
- [ ] Verify log appears in Grafana Loki
- [ ] Test container log aggregation
- [ ] Test kernel log collection
- [ ] Verify log timestamps are correct
- [ ] Test log search and filtering

### 27. Performance Testing
- [ ] Run load test on web application
- [ ] Monitor resource usage in Grafana
- [ ] Check response times
- [ ] Verify WAF doesn't significantly impact performance
- [ ] Test under high load scenarios
- [ ] Monitor log ingestion rates

### 28. Security Testing
- [ ] Run security scan (nmap, OpenVAS)
- [ ] Verify IDS/IPS alerts in POD 006
- [ ] Test firewall rules
- [ ] Attempt unauthorized access
- [ ] Review security logs
- [ ] Verify encryption on VXLAN tunnels
- [ ] Test WAF effectiveness
- [ ] If using Cloudflare: Test tunnel security

---

## Production Readiness

### 29. Final Security Checks
- [ ] All services running stable for 24+ hours
- [ ] No error logs or critical warnings
- [ ] Monitoring alerts working
- [ ] Backups completing successfully
- [ ] SSL/TLS configured and working
- [ ] All default passwords changed
- [ ] WAF in blocking mode (not learning)
- [ ] Cloudflare tunnel connected (if used)
- [ ] Documentation complete
- [ ] Team trained

### 30. Performance Optimization
- [ ] Django static files served efficiently
- [ ] Database queries optimized
- [ ] Redis caching configured
- [ ] Nginx caching enabled
- [ ] WAF rules optimized
- [ ] Log retention policies set

---

## Monitoring Checklist (Daily)
- [ ] Check Grafana for anomalies
- [ ] Review critical alerts
- [ ] Verify backup completion
- [ ] Check disk space
- [ ] Review security logs
- [ ] Check WAF block statistics
- [ ] Verify all services running
- [ ] Review Cloudflare tunnel status (if used)
- [ ] Check centralized syslog server
- [ ] Review IDS/IPS alerts

---

## New Features Summary (v3.0)

### ✨ Added Components:
1. **NAXSI WAF** - Web Application Firewall protecting Django
2. **Cloudflare Tunnel** - Secure external access (optional)
3. **Rsyslog Server** - Centralized syslog collection
4. **Enhanced Logging** - All logs forwarded to Loki
5. **Journald Integration** - All containers log via journald

### 🛡️ Security Enhancements:
- WAF filtering XSS, SQL injection, command injection
- Cloudflare Zero Trust access
- Complete audit trail in centralized logs
- Real-time WAF alerts in Grafana

### 📊 Monitoring Improvements:
- Centralized syslog server in POD 005
- System logs aggregated in Loki
- Kernel logs collected
- Container logs via journald
- WAF logs tracked separately
- Query all logs in single interface (Grafana)

---

**Version**: 3.0  
**Last Updated**: 2025  
**Maintained by**: HookProbe Team

## Pre-Deployment Checklist

### System Requirements
- [ ] Hardware: Intel N100 or equivalent x86_64 processor
- [ ] RAM: Minimum 16GB (recommended)
- [ ] Storage: Minimum 500GB SSD
- [ ] OS: Ubuntu 22.04+, Debian 11+/12+, or Raspberry Pi OS installed
- [ ] Root access available
- [ ] Internet connectivity for downloading images

### Network Configuration
- [ ] Physical network interface identified (e.g., eth0, enp0s3)
- [ ] Host IP address noted
- [ ] Gateway IP address noted
- [ ] Remote peer IP (if multi-host) noted
- [ ] No IP conflicts with 10.200.0.0/16 range
- [ ] Firewall allows required ports (or will be configured)

---

## Configuration Phase

### 1. Edit network-config.sh
- [ ] Set `HOST_A_IP` to your physical IP
- [ ] Set `HOST_B_IP` (if multi-host deployment)
- [ ] Set `PHYSICAL_HOST_INTERFACE` (verify with `ip a`)
- [ ] Set `INTERNET_GATEWAY`
- [ ] Change all PSK keys (minimum 32 characters)
  - [ ] `OVS_PSK_MAIN`
  - [ ] `OVS_PSK_DMZ`
  - [ ] `OVS_PSK_INTERNAL`
- [ ] Change database passwords
  - [ ] `POSTGRES_PASSWORD`
  - [ ] `LOGTO_DB_PASSWORD`
- [ ] Change Django secret key
  - [ ] `DJANGO_SECRET_KEY` (generate with: `openssl rand -base64 50`)
- [ ] Update `DJANGO_ALLOWED_HOSTS` for production

### 2. Review Port Mappings
- [ ] Port 80 (HTTP) - Available
- [ ] Port 443 (HTTPS) - Available
- [ ] Port 3000 (Grafana) - Available
- [ ] Port 3001 (Logto) - Available
- [ ] Port 3002 (Logto Admin) - Available
- [ ] Port 5432 (PostgreSQL) - Available (optional external access)
- [ ] Port 9090 (Prometheus) - Available
- [ ] Port 9093 (Alertmanager) - Available

### 3. Make Scripts Executable
```bash
chmod +x network-config.sh setup.sh uninstall.sh
```

---

## Deployment Phase

### 4. Run Setup Script
```bash
sudo ./setup.sh
```

**Estimated Time**: 10-15 minutes

### 5. Monitor Deployment
Watch for these checkpoints:
- [ ] ✓ Environment validated
- [ ] ✓ Dependencies installed
- [ ] ✓ Kernel modules loaded
- [ ] ✓ OVS bridges created
- [ ] ✓ VXLAN tunnels established
- [ ] ✓ Firewall configured
- [ ] ✓ Podman networks created
- [ ] ✓ Volumes created
- [ ] ✓ POD 003 deployed (Database)
- [ ] ✓ POD 004 deployed (Redis)
- [ ] ✓ Django built
- [ ] ✓ POD 002 deployed (Logto IAM)
- [ ] ✓ POD 001 deployed (Web DMZ)
- [ ] ✓ POD 005 deployed (Monitoring)
- [ ] ✓ POD 006 deployed (Security)

---

## Post-Deployment Verification

### 6. Verify Services
```bash
# Check all PODs are running
podman pod ps

# Verify container status
podman ps -a

# Check OVS configuration
ovs-vsctl show

# Test network connectivity
ping 10.200.1.10  # Django
ping 10.200.2.10  # Logto
ping 10.200.3.10  # PostgreSQL
```

- [ ] All 6 PODs showing as "Running"
- [ ] All containers in "Up" state
- [ ] OVS bridge shows 7 VXLAN tunnels
- [ ] Network connectivity confirmed

### 7. Access Web Interfaces

#### Django Admin
- [ ] Open: http://YOUR_IP/admin
- [ ] Login: admin / admin
- [ ] Login successful
- [ ] Change admin password immediately

#### Logto Admin Console
- [ ] Open: http://YOUR_IP:3002
- [ ] Complete initial setup wizard
- [ ] Create admin account
- [ ] Note credentials securely

#### Grafana
- [ ] Open: http://YOUR_IP:3000
- [ ] Login: admin / admin
- [ ] Change admin password
- [ ] Verify data sources (Prometheus, Loki)
- [ ] Data sources showing green checkmarks

#### Prometheus
- [ ] Open: http://YOUR_IP:9090
- [ ] Check Status → Targets
- [ ] All targets showing as "UP"

---

## Security Hardening

### 8. Change Default Passwords
- [ ] Django admin password changed
- [ ] Grafana admin password changed
- [ ] Logto admin password changed
- [ ] PostgreSQL password updated (if needed)
- [ ] Document new passwords securely

### 9. Configure SSL/TLS (Recommended)
- [ ] Obtain SSL certificates (Let's Encrypt, self-signed, or commercial)
- [ ] Configure Nginx for HTTPS
- [ ] Update firewall for port 443
- [ ] Test HTTPS access
- [ ] Configure HTTP to HTTPS redirect

### 10. Review Firewall Rules
```bash
firewall-cmd --list-all
```
- [ ] Only necessary ports exposed
- [ ] Internal networks properly trusted
- [ ] No unintended open ports

---

## Logto IAM Configuration

### 11. Configure Logto Application
- [ ] Access Logto Admin Console
- [ ] Create new application (Traditional Web)
- [ ] Application name: "HookProbe Django"
- [ ] Note App ID
- [ ] Note App Secret
- [ ] Add redirect URI: http://YOUR_IP/auth/callback
- [ ] Add post logout redirect: http://YOUR_IP/
- [ ] Save configuration

### 12. Integrate Django with Logto
- [ ] Update Django settings with Logto credentials
- [ ] Restart Django container: `podman restart hookprobe-pod-001-web-dmz-django`
- [ ] Test SSO login flow
- [ ] Verify user creation in Django
- [ ] Test logout flow

---

## Monitoring Configuration

### 13. Configure Grafana Dashboards
- [ ] Import HookProbe dashboards (use provided JSON)
- [ ] Create custom dashboards as needed
- [ ] Verify metrics are flowing
- [ ] Test log queries in Loki
- [ ] Configure dashboard refresh intervals

### 14. Set Up Alerting
- [ ] Configure notification channels (email, Slack, etc.)
- [ ] Create alert rules for:
  - [ ] High CPU usage (>80%)
  - [ ] High memory usage (>90%)
  - [ ] Container down
  - [ ] Disk space low (<10%)
  - [ ] Database connection issues
  - [ ] Security threats detected
- [ ] Test alert delivery

---

## Application Deployment

### 15. Upload ThemeForest Template
- [ ] Copy template files to Django container
- [ ] Convert HTML to Django templates
- [ ] Update static file references
- [ ] Collect static files: `podman exec hookprobe-pod-001-web-dmz-django python manage.py collectstatic`
- [ ] Test template rendering
- [ ] Verify responsive design

### 16. Configure Django CMS
- [ ] Create CMS pages
- [ ] Configure page templates
- [ ] Add content placeholders
- [ ] Test page creation workflow
- [ ] Configure user permissions

---

## Backup & Recovery Setup

### 17. Configure Automated Backups
```bash
# Create backup script
cat > /usr/local/bin/hookprobe-backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/backup/hookprobe/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup volumes
podman volume export hookprobe-postgres-data > "$BACKUP_DIR/postgres.tar"
podman volume export hookprobe-grafana-data > "$BACKUP_DIR/grafana.tar"
podman volume export hookprobe-django-static > "$BACKUP_DIR/django-static.tar"

# Backup configurations
cp /path/to/network-config.sh "$BACKUP_DIR/"
ovs-vsctl show > "$BACKUP_DIR/ovs-config.txt"

# Compress
tar -czf "$BACKUP_DIR.tar.gz" -C "$(dirname $BACKUP_DIR)" "$(basename $BACKUP_DIR)"
rm -rf "$BACKUP_DIR"

# Keep only last 7 days
find /backup/hookprobe/ -name "*.tar.gz" -mtime +7 -delete
EOF

chmod +x /usr/local/bin/hookprobe-backup.sh
```

- [ ] Backup script created
- [ ] Test backup script execution
- [ ] Configure cron job for daily backups
- [ ] Verify backup storage location has sufficient space
- [ ] Test restore procedure

### 18. Create Cron Job
```bash
# Add to crontab
crontab -e

# Daily backup at 2 AM
0 2 * * * /usr/local/bin/hookprobe-backup.sh
```

- [ ] Cron job configured
- [ ] First backup completed successfully
- [ ] Backup files verified

---

## Documentation

### 19. Create Documentation
- [ ] Document custom configurations
- [ ] Note any modifications to scripts
- [ ] Record Logto application credentials
- [ ] Document backup/restore procedures
- [ ] Create runbook for common tasks
- [ ] Document troubleshooting steps

### 20. Train Team
- [ ] Share access credentials securely
- [ ] Train team on Grafana dashboards
- [ ] Demonstrate Django admin usage
- [ ] Show how to check logs
- [ ] Explain monitoring alerts
- [ ] Document escalation procedures

---

## Testing & Validation

### 21. Functional Testing
- [ ] Test user registration/login via Logto
- [ ] Test Django CMS page creation
- [ ] Test file uploads (media)
- [ ] Test static file serving
- [ ] Test database connectivity
- [ ] Test Redis caching
- [ ] Verify email sending (if configured)

### 22. Performance Testing
- [ ] Run load test on web application
- [ ] Monitor resource usage in Grafana
- [ ] Check response times
- [ ] Verify auto-scaling (if configured)
- [ ] Test under high load scenarios

### 23. Security Testing
- [ ] Run security scan (nmap, OpenVAS)
- [ ] Verify IDS/IPS alerts in POD 006
- [ ] Test firewall rules
- [ ] Attempt unauthorized access
- [ ] Review security logs
- [ ] Verify encryption on VXLAN tunnels

---

## Multi-Host Deployment (Optional)

### 24. Deploy to Second Host
- [ ] Copy network-config.sh to second host
- [ ] Verify PSK keys match exactly
- [ ] Update HOST_A_IP and HOST_B_IP
- [ ] Run setup.sh on second host
- [ ] Verify VXLAN mesh formation
- [ ] Test inter-host communication
- [ ] Verify data synchronization

---

## Production Readiness

### 25. Final Checks
- [ ] All services running stable for 24+ hours
- [ ] No error logs or warnings
- [ ] Monitoring alerts working
- [ ] Backups completing successfully
- [ ] SSL/TLS configured (if required)
- [ ] All default passwords changed
- [ ] Documentation complete
- [ ] Team trained
- [ ] Incident response plan documented
- [ ] Disaster recovery plan tested

### 26. Go-Live Preparation
- [ ] Schedule maintenance window (if needed)
- [ ] Notify users of new system
- [ ] DNS records updated (if applicable)
- [ ] Load balancer configured (if applicable)
- [ ] CDN configured (if applicable)
- [ ] Monitoring alerts to appropriate channels
- [ ] On-call rotation established

---

## Post-Production

### 27. Ongoing Maintenance
Create schedule for:
- [ ] Weekly security updates
- [ ] Monthly review of monitoring data
- [ ] Quarterly disaster recovery drills
- [ ] Bi-annual performance reviews
- [ ] Annual architecture reviews

### 28. Monitoring Checklist (Daily)
- [ ] Check Grafana for anomalies
- [ ] Review critical alerts
- [ ] Verify backup completion
- [ ] Check disk space
- [ ] Review security logs
- [ ] Verify all services running

---

## Troubleshooting Reference

### Common Issues

**Containers won't start:**
```bash
podman logs <container-name>
podman pod restart <pod-name>
```

**Network connectivity issues:**
```bash
ovs-vsctl show
systemctl status openvswitch
ping <internal-ip>
```

**Database connection errors:**
```bash
podman exec hookprobe-pod-003-db-persistent-postgres pg_isready
```

**High resource usage:**
```bash
podman stats
htop
```

---

## Sign-Off

### Deployment Sign-Off
- [ ] System Administrator: ______________ Date: ______
- [ ] Security Officer: ______________ Date: ______
- [ ] Application Owner: ______________ Date: ______

### Production Ready
- [ ] All checklist items completed
- [ ] System stable and monitored
- [ ] Team trained and ready
- [ ] Documentation complete

**Deployment Status**: ☐ In Progress  ☐ Complete  ☐ Production

---

**Version**: 2.0  
**Last Updated**: 2025  
**Maintained by**: HookProbe Team
