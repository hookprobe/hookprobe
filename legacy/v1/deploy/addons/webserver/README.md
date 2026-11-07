# HookProbe Web Server - Optional Addon

**Post-Installation Web Interface for HookProbe v5.0**

The HookProbe web server is an **optional addon** that provides a Django-based CMS and management interface. It integrates with POD-001 (Web DMZ) and can be deployed in stages after the main HookProbe infrastructure is running.

## 🎯 Overview

### Why Post-Installation?

The web server is optional and installed **after** the main HookProbe deployment to:

1. **Reduce installation complexity** - Core security functions work without web UI
2. **Support edge deployments** - Not all edge devices need full web interface
3. **Enable cloud centralization** - Service Provider can run centralized web server for multiple edges
4. **Staged deployment** - Install web components when ready
5. **Resource efficiency** - Save RAM/CPU on constrained edge devices

### Deployment Scenarios

| Scenario | Description | Web Server Location | Use Case |
|----------|-------------|---------------------|----------|
| **Edge with UI** | Full web interface on edge device | Local (edge SBC) | Home users, SMB with dedicated hardware |
| **Edge headless** | No web interface, only APIs | None (metrics via API) | Constrained SBCs, remote sites |
| **Cloud centralized** | Centralized web for multiple edges | Cloud backend | Service Provider managing 10+ customer sites |
| **Hybrid** | Cloud web + edge APIs | Cloud + selective edge | Large Service Provider with mix of deployments |

## 📋 Prerequisites

### Before Installing Web Server

Ensure the following are **already installed and running**:

1. ✅ **HookProbe PODs 001-007** deployed via main `install.sh`
2. ✅ **POD-003 (PostgreSQL)** running and accessible at `10.200.3.12:5432`
3. ✅ **POD-004 (Redis)** running and accessible at `10.200.4.12:6379`
4. ✅ **POD-005 (Monitoring)** running for ClickHouse and Grafana
5. ✅ **POD-006 (Qsecbit)** running for security API

### System Requirements

**Minimum (Edge with UI):**
- Additional 2GB RAM (on top of base HookProbe)
- 10GB disk space
- Python 3.11+

**Recommended (Cloud Centralized):**
- Additional 4GB RAM
- 20GB disk space
- Python 3.11+
- Separate server/VM

### Verify Prerequisites

```bash
# Check if PODs are running
podman pod ps | grep hookprobe

# Check PostgreSQL connectivity
nc -zv 10.200.3.12 5432

# Check Redis connectivity
nc -zv 10.200.4.12 6379

# Check Python version
python3 --version  # Should be 3.11+
```

## 🚀 Quick Start

### Option 1: Edge Deployment (Full UI on Edge Device)

Install web server directly on the edge device where HookProbe is running:

```bash
cd /path/to/hookprobe/install/addons/webserver

# Edit configuration (optional)
nano config/webserver-config.sh

# Run installation
sudo ./setup-webserver.sh edge
```

**Access:**
- Public Site: `http://<edge-ip>/`
- Admin Dashboard: `http://<edge-ip>/admin/`
- Device Management: `http://<edge-ip>/devices/`

### Option 2: Cloud Centralized (Service Provider Multi-Tenant)

Install web server on a separate cloud server/VM:

```bash
cd /path/to/hookprobe/install/addons/webserver

# Configure for cloud deployment
export DEPLOYMENT_TYPE=cloud
export MULTITENANT_ENABLED=true
export POSTGRES_HOST=10.100.1.10  # Cloud PostgreSQL
export REDIS_HOST=10.100.1.11     # Cloud Redis

# Run installation
sudo ./setup-webserver.sh cloud
```

**Access:**
- Centralized UI: `http://<cloud-ip>/`
- Multi-tenant admin: `http://<cloud-ip>/admin/`

### Option 3: Standalone (Development/Testing)

For development or testing purposes:

```bash
cd /path/to/hookprobe/install/addons/webserver

# Run in standalone mode
sudo ./setup-webserver.sh standalone
```

## 📖 Detailed Installation

### Step 1: Configure Deployment

Edit `config/webserver-config.sh`:

```bash
cd install/addons/webserver/config
nano webserver-config.sh
```

**Key settings:**

```bash
# Deployment type
DEPLOYMENT_TYPE="edge"  # or "cloud" or "standalone"

# Database (POD-003)
POSTGRES_HOST="10.200.3.12"
POSTGRES_PASSWORD="your-strong-password"

# Django configuration
DJANGO_SECRET_KEY="generate-a-random-secret-key"
DJANGO_ALLOWED_HOST="your-domain.com,10.200.1.12"

# Nginx
NGINX_ENABLED="true"
NGINX_PORT="80"

# Multi-tenant (cloud only)
MULTITENANT_ENABLED="false"
```

### Step 2: Run Installation Script

```bash
cd install/addons/webserver
sudo ./setup-webserver.sh
```

The installer will:
1. ✅ Check prerequisites (Python, PostgreSQL, Redis)
2. ✅ Install system dependencies (nginx, python packages)
3. ✅ Create virtual environment
4. ✅ Install Django and dependencies
5. ✅ Configure database connection
6. ✅ Run database migrations
7. ✅ Download frontend themes (Forty + AdminLTE)
8. ✅ Collect static files
9. ✅ Create systemd service
10. ✅ Configure Nginx reverse proxy
11. ✅ Prompt for superuser creation
12. ✅ Start services

### Step 3: Create Admin User

During installation, you'll be prompted:

```
Create Django Admin Superuser
Username: admin
Email: admin@example.com
Password: ********
Password (again): ********
```

### Step 4: Verify Installation

```bash
# Check web server status
systemctl status hookprobe-webserver

# Check logs
journalctl -u hookprobe-webserver -f

# Test web interface
curl http://localhost:8000
```

## 🔧 Configuration

### Environment Variables

All configuration is in `/opt/hookprobe/src/web/.env`:

```bash
# Edit configuration
nano /opt/hookprobe/src/web/.env

# Restart service after changes
systemctl restart hookprobe-webserver
```

### Common Configuration Tasks

#### Change Django Secret Key

```bash
# Generate new secret key
python3 -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"

# Update .env file
nano /opt/hookprobe/src/web/.env
# Update: DJANGO_SECRET_KEY=<new-key>

# Restart
systemctl restart hookprobe-webserver
```

#### Configure Email Notifications

```bash
nano /opt/hookprobe/src/web/.env
```

Add:
```bash
EMAIL_ENABLED=true
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
DEFAULT_FROM_EMAIL=noreply@hookprobe.local
```

#### Enable SSL/HTTPS

```bash
# Install certbot
dnf install certbot python3-certbot-nginx

# Obtain certificate
certbot --nginx -d your-domain.com

# Certificate auto-renewal is configured
systemctl status certbot-renew.timer
```

#### Configure Firewall

```bash
# Allow HTTP/HTTPS
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --reload
```

## 🏗️ Architecture Integration

### POD-001 Integration

The web server runs within the POD-001 (Web DMZ) network space:

```
┌─────────────────────────────────┐
│  POD-001 (Web DMZ)             │
│  Network: 10.200.1.0/24        │
│                                 │
│  ┌──────────────────────────┐  │
│  │ Nginx (80/443)           │  │
│  │ ↓                        │  │
│  │ Gunicorn (8000)          │  │
│  │ ↓                        │  │
│  │ Django Web Application   │  │
│  └──────────────────────────┘  │
└─────────────────────────────────┘
           │
           ├─→ POD-003 (PostgreSQL) - Database
           ├─→ POD-004 (Redis) - Cache
           ├─→ POD-005 (ClickHouse) - Analytics
           └─→ POD-006 (Qsecbit) - Security API
```

### Data Flow

1. **User Request** → Nginx (80/443)
2. **Nginx** → Gunicorn (8000)
3. **Django** → PostgreSQL (POD-003) for data
4. **Django** → Redis (POD-004) for cache
5. **Django** → ClickHouse (POD-005) for analytics
6. **Django** → Qsecbit API (POD-006) for threat scores

## 🔐 Security Considerations

### Production Checklist

- [ ] **Change Django secret key** in `.env`
- [ ] **Update ALLOWED_HOSTS** to specific domain/IP
- [ ] **Disable DEBUG mode** (`DJANGO_DEBUG=False`)
- [ ] **Enable SSL/HTTPS** with valid certificate
- [ ] **Strong database password** for PostgreSQL
- [ ] **Configure firewall** to allow only HTTP/HTTPS
- [ ] **Regular security updates** (`apt update && apt upgrade`, `pip install -U`)
- [ ] **Configure AppArmor** (enabled by default on Ubuntu/Debian)
- [ ] **Configure CORS** for API access
- [ ] **Set up log rotation** for Django/Nginx logs

### Security Best Practices

```bash
# Set restrictive permissions
chmod 600 /opt/hookprobe/src/web/.env
chown root:root /opt/hookprobe/src/web/.env

# Configure fail2ban for brute-force protection
apt install fail2ban
systemctl enable --now fail2ban
```

## 📊 Features

### Public CMS (Forty Theme)

- **Blog Posts** - Security updates, news, CVE analysis
- **Static Pages** - About, Contact, Documentation
- **Contact Forms** - User inquiries
- **SEO Optimized** - Meta descriptions, slugs
- **Responsive Design** - Mobile-friendly

### Admin Dashboard (AdminLTE)

- **System Overview** - POD status, metrics
- **Qsecbit Monitoring** - Real-time threat scores
- **Device Management** - Service Provider edge device tracking
- **Security Events** - IDS/IPS/WAF aggregation
- **User Management** - Role-based access control

### Device Management (Service Provider)

- **Multi-Tenant** - Customer/tenant isolation
- **Device Tracking** - Hardware specs, status
- **Metrics Collection** - CPU, RAM, disk, network
- **Heartbeat API** - Automated device check-ins
- **Logs Aggregation** - Centralized logging

### Security Integration

- **IDS/IPS Events** - NAPSE
- **WAF Events** - NAXSI/ModSecurity
- **Qsecbit Scores** - RAG status tracking
- **Kali Responses** - Automated mitigation logs
- **Threat Intelligence** - IOC database

### REST APIs

```bash
# Device Management
GET /api/v1/devices/devices/
POST /api/v1/devices/devices/{id}/heartbeat/
GET /api/v1/devices/devices/{id}/metrics/

# Security Events
GET /api/v1/security/events/
GET /api/v1/security/qsecbit/
GET /api/v1/security/kali/

# Authentication required (Basic Auth or Session)
curl -u admin:password http://localhost:8000/api/v1/devices/devices/
```

## 🛠️ Management

### Service Control

```bash
# Start web server
systemctl start hookprobe-webserver

# Stop web server
systemctl stop hookprobe-webserver

# Restart web server
systemctl restart hookprobe-webserver

# Check status
systemctl status hookprobe-webserver

# View logs
journalctl -u hookprobe-webserver -f
```

### Nginx Control

```bash
# Start Nginx
systemctl start nginx

# Restart Nginx
systemctl restart nginx

# Test configuration
nginx -t

# View Nginx logs
tail -f /var/log/hookprobe/nginx-access.log
tail -f /var/log/hookprobe/nginx-error.log
```

### Database Management

```bash
# Activate virtual environment
source /opt/hookprobe/src/web/venv/bin/activate
cd /opt/hookprobe/src/web

# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Django shell
python manage.py shell

# Database shell
python manage.py dbshell
```

### Backup & Restore

```bash
# Backup database
pg_dump -h 10.200.3.12 -U hookprobe hookprobe > hookprobe-backup.sql

# Backup media files
tar -czf media-backup.tar.gz /opt/hookprobe/src/web/media/

# Restore database
psql -h 10.200.3.12 -U hookprobe hookprobe < hookprobe-backup.sql
```

## 🐛 Troubleshooting

### Web Server Won't Start

```bash
# Check logs
journalctl -u hookprobe-webserver -n 50

# Common issues:
# 1. PostgreSQL not accessible
nc -zv 10.200.3.12 5432

# 2. Redis not accessible
nc -zv 10.200.4.12 6379

# 3. Port already in use
netstat -tuln | grep 8000

# 4. Permission issues
ls -la /opt/hookprobe/src/web/
```

### Database Connection Errors

```bash
# Test PostgreSQL connection
psql -h 10.200.3.12 -U hookprobe -d hookprobe

# Check password in .env
grep POSTGRES_PASSWORD /opt/hookprobe/src/web/.env

# Check POD-003 status
podman ps | grep pod-003
```

### Static Files Not Loading

```bash
# Collect static files
source /opt/hookprobe/src/web/venv/bin/activate
cd /opt/hookprobe/src/web
python manage.py collectstatic --noinput

# Check Nginx configuration
nginx -t
cat /etc/nginx/conf.d/hookprobe-webserver.conf

# Check permissions
ls -la /opt/hookprobe/src/web/staticfiles/
```

### 502 Bad Gateway

```bash
# Check if Gunicorn is running
systemctl status hookprobe-webserver

# Check Gunicorn logs
journalctl -u hookprobe-webserver -n 50

# Test Gunicorn directly
curl http://localhost:8000

# Check Nginx upstream
cat /etc/nginx/conf.d/hookprobe-webserver.conf
```

## 🔄 Updating

### Update Web Application

```bash
# Pull latest changes
cd /path/to/hookprobe
git pull

# Copy updated files
cp -r src/web/* /opt/hookprobe/src/web/

# Update dependencies
source /opt/hookprobe/src/web/venv/bin/activate
pip install -r /opt/hookprobe/src/web/requirements.txt

# Run migrations
cd /opt/hookprobe/src/web
python manage.py migrate

# Collect static files
python manage.py collectstatic --noinput

# Restart service
systemctl restart hookprobe-webserver
```

## 📚 Additional Resources

- **Django Documentation**: https://docs.djangoproject.com/
- **Forty Theme**: https://html5up.net/forty
- **AdminLTE**: https://adminlte.io/
- **HookProbe Main Docs**: `/path/to/hookprobe/README.md`
- **Web App Docs**: `/opt/hookprobe/src/web/README.md`

## 🤝 Support

- **GitHub Issues**: https://github.com/hookprobe/hookprobe/issues
- **Email**: qsecbit@hookprobe.com
- **Documentation**: See `/opt/hookprobe/src/web/SETUP_GUIDE.md`

## 📝 License

MIT License - See main repository LICENSE file

---

**HookProbe Web Server** - Optional addon for POD-001 Web DMZ
