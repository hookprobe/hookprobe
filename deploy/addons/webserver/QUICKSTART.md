# HookProbe Web Server - Quick Start

This is a **5-minute quick start** guide for installing the HookProbe web server addon.

## ✅ Prerequisites

Before starting, ensure:

1. **HookProbe PODs are running**
   ```bash
   podman pod ps | grep hookprobe
   ```

2. **PostgreSQL is accessible** (POD-003)
   ```bash
   nc -zv 10.200.3.12 5432
   ```

3. **Redis is accessible** (POD-004)
   ```bash
   nc -zv 10.200.4.12 6379
   ```

## 🚀 Installation Methods

### Method 1: Podman Container (Recommended)

**Best for:** Production, edge devices, easy management

```bash
# Navigate to addon directory
cd /path/to/hookprobe/install/addons/webserver

# Run Podman installation
sudo ./setup-webserver-podman.sh edge

# Follow prompts to create superuser
# Username: admin
# Email: admin@example.com
# Password: <strong-password>
```

**That's it!** The web server is now running in a Podman container.

### Method 2: Native Installation

**Best for:** Development, custom setups

```bash
# Navigate to addon directory
cd /path/to/hookprobe/install/addons/webserver

# Run native installation
sudo ./setup-webserver.sh edge

# Follow prompts to create superuser
```

## 🌐 Access the Web Interface

After installation:

- **Public Site**: http://YOUR_IP/
- **Admin Login**: http://YOUR_IP/admin/
- **Dashboard**: http://YOUR_IP/dashboard/
- **API Docs**: http://YOUR_IP/api/v1/

## 🔧 Management

### Podman Container

```bash
# View logs
podman logs -f hookprobe-webserver

# Restart container
podman restart hookprobe-webserver

# Stop container
podman stop hookprobe-webserver

# Start container
podman start hookprobe-webserver
```

### Native Installation

```bash
# View logs
journalctl -u hookprobe-webserver -f

# Restart service
systemctl restart hookprobe-webserver

# Stop service
systemctl stop hookprobe-webserver

# Check status
systemctl status hookprobe-webserver
```

## 🔐 Post-Installation Security

### 1. Change Django Secret Key

**Podman:**
```bash
nano /path/to/hookprobe/install/addons/webserver/container.env
# Update: DJANGO_SECRET_KEY=<new-random-key>
podman restart hookprobe-webserver
```

**Native:**
```bash
nano /opt/hookprobe/src/web/.env
# Update: DJANGO_SECRET_KEY=<new-random-key>
systemctl restart hookprobe-webserver
```

### 2. Update Allowed Hosts

Edit the same file and update:
```bash
DJANGO_ALLOWED_HOST=your-domain.com,10.200.1.12
```

### 3. Enable HTTPS (Production)

```bash
# Install certbot
dnf install certbot python3-certbot-nginx

# Obtain certificate
certbot --nginx -d your-domain.com

# Auto-renewal is configured
systemctl status certbot-renew.timer
```

### 4. Configure Firewall

```bash
# Allow HTTP/HTTPS
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --reload
```

## 🐛 Troubleshooting

### Container/Service Won't Start

```bash
# Check logs
podman logs hookprobe-webserver  # Podman
journalctl -u hookprobe-webserver -n 50  # Native

# Common issues:
# 1. PostgreSQL not accessible
nc -zv 10.200.3.12 5432

# 2. Redis not accessible
nc -zv 10.200.4.12 6379

# 3. Check POD-003 is running
podman ps | grep pod-003

# 4. Check POD-004 is running
podman ps | grep pod-004
```

### Cannot Access Web Interface

```bash
# Check if port 8000 is listening
netstat -tuln | grep 8000

# Check Nginx status (if enabled)
systemctl status nginx
nginx -t

# Test direct access to Gunicorn
curl http://localhost:8000
```

### Database Connection Error

```bash
# Test PostgreSQL connection
psql -h 10.200.3.12 -U hookprobe -d hookprobe

# If fails, check POD-003 logs
podman logs hookprobe-pod-003-db-persistent-postgres
```

## 📚 Next Steps

1. **Customize templates** - Edit HTML templates for your brand
2. **Add content** - Create blog posts, pages via admin interface
3. **Configure devices** - Add edge devices via Device Management
4. **Set up monitoring** - Configure Grafana integration
5. **Enable email** - Configure SMTP for notifications

## 📖 Full Documentation

- [Complete README](README.md) - Full feature documentation
- [Main HookProbe Docs](../../../README.md) - Overall project documentation
- [Web App Development Guide](../../../src/web/SETUP_GUIDE.md) - Development setup

## ❓ Need Help?

- **GitHub Issues**: https://github.com/hookprobe/hookprobe/issues
- **Email**: qsecbit@hookprobe.com
- **Documentation**: See README.md in this directory

---

**Installation complete!** 🎉

Your HookProbe web server is now running and integrated with POD-001.
