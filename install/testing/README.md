# HookProbe Lightweight Testing/Development Deployment

**Target Platform:** Raspberry Pi 4 (4GB RAM), Development Machines
**Purpose:** Testing, Development, CI/CD
**NOT FOR PRODUCTION USE**

---

## Overview

This lightweight deployment installs only essential PODs for testing and development:

- ✅ **POD-001: Web Server** (Django + Nginx + NAXSI WAF)
- ✅ **POD-002: IAM** (Logto authentication)
- ✅ **POD-003: Database** (PostgreSQL 16-alpine)
- ✅ **POD-005: Cache** (Redis 7-alpine)
- ❌ **POD-004: Monitoring** (Excluded - too heavy)
- ❌ **POD-007: AI/Qsecbit** (Excluded - too heavy)

**Memory Usage:** ~2.5GB (leaves 1.5GB for OS on 4GB system)

---

## Prerequisites

### Hardware
- **Raspberry Pi 4 (4GB RAM)** or equivalent
- **20GB+ storage** (microSD or USB SSD)
- **Network connection**

### Software
- **OS:** Ubuntu Server 22.04 LTS ARM64, Raspberry Pi OS 64-bit, or Debian 12+
- **Podman:** Container runtime (will be installed if missing)
- **Root access:** Required for installation

---

## ⚠️ **CRITICAL REQUIREMENT: Cgroup Configuration** ⚠️

**🔴 MANDATORY FOR RASPBERRY PI AND ARM64 SYSTEMS 🔴**

Before running the installation, you **MUST** enable cgroup support in the boot configuration. Without this, Podman containers will fail with errors like:

```
crun: opening file `memory.max` for writing: No such file or directory
```

### Fix for Raspberry Pi OS / Debian-based Systems

1. **Edit boot configuration:**

   ```bash
   # For Raspberry Pi OS Bookworm (Debian 12+)
   sudo nano /boot/firmware/cmdline.txt

   # For older Raspberry Pi OS
   sudo nano /boot/cmdline.txt
   ```

2. **Add these parameters to the EXISTING line** (do NOT create a new line):

   ```
   cgroup_enable=cpuset cgroup_enable=memory cgroup_memory=1 systemd.unified_cgroup_hierarchy=1
   ```

   **Example:** If your `cmdline.txt` contains:
   ```
   console=serial0,115200 console=tty1 root=PARTUUID=12345678-02 rootfstype=ext4 fsck.repair=yes rootwait
   ```

   It should become:
   ```
   console=serial0,115200 console=tty1 root=PARTUUID=12345678-02 rootfstype=ext4 fsck.repair=yes rootwait cgroup_enable=cpuset cgroup_enable=memory cgroup_memory=1 systemd.unified_cgroup_hierarchy=1
   ```

3. **Save and reboot:**

   ```bash
   sudo reboot
   ```

4. **Verify cgroup is enabled after reboot:**

   ```bash
   cat /proc/cgroups | grep memory
   # Should show: memory ... 1

   ls /sys/fs/cgroup/memory.max
   # Should exist without errors
   ```

### Fix for Ubuntu Server ARM64

Ubuntu Server typically has cgroups enabled by default. If you encounter issues:

1. **Edit GRUB configuration:**

   ```bash
   sudo nano /etc/default/grub
   ```

2. **Modify the `GRUB_CMDLINE_LINUX` line:**

   ```
   GRUB_CMDLINE_LINUX="cgroup_enable=cpuset cgroup_enable=memory cgroup_memory=1 systemd.unified_cgroup_hierarchy=1"
   ```

3. **Update GRUB and reboot:**

   ```bash
   sudo update-grub
   sudo reboot
   ```

**🔴 DO NOT SKIP THIS STEP 🔴** - Container deployment will fail without proper cgroup configuration.

---

## Quick Installation

```bash
# 1. Clone repository
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe

# 2. Run lightweight installation
sudo ./install.sh

# 3. Select option: 2) Select Deployment Mode
# 4. Choose: 3) Lightweight Testing (Raspberry Pi 4 / Development)
```

### Alternative: Direct Installation

```bash
cd hookprobe/install/testing
sudo bash lightweight-setup.sh
```

---

## Installation Steps (Detailed)

### Step 1: System Check

The installer will check:
- RAM: Minimum 4GB
- Disk: Minimum 20GB free
- Architecture: ARM64 or x86_64
- Podman: Will install if missing

### Step 2: Network Configuration

Simple network setup for testing:
- Web: 10.250.1.0/24
- Database: 10.250.2.0/24
- Cache: 10.250.3.0/24
- IAM: 10.250.4.0/24

### Step 3: POD Deployment

**POD-001: Web Server**
- Django application
- Nginx reverse proxy
- NAXSI WAF
- Memory: 1GB
- Port: 80, 443

**POD-002: IAM (Logto)**
- Authentication service
- Memory: 512MB
- Port: 3001 (app), 3002 (admin)

**POD-003: Database (PostgreSQL)**
- PostgreSQL 16-alpine
- Memory: 512MB
- Port: 5432 (internal only)

**POD-005: Cache (Redis)**
- Redis 7-alpine
- Memory: 256MB
- Port: 6379 (internal only)

### Step 4: Verification

After installation:
```bash
# Check running pods
podman pod ls

# Check containers
podman ps

# Access web interface
curl http://localhost
```

---

## Configuration

### Default Credentials (⚠️ CHANGE THESE)

**Django Admin:**
- URL: http://localhost/admin
- Username: admin
- Password: admin

**PostgreSQL:**
- Database: hookprobe
- User: hookprobe
- Password: hookprobe_test_password_CHANGE_ME

**Redis:**
- Password: redis_test_password_CHANGE_ME

**Logto:**
- URL: http://localhost:3002
- Default setup wizard on first access

### Configuration File

Edit `/home/user/hookprobe/install/testing/lightweight-config.sh` to change:
- Database passwords
- Django secret key
- Resource limits
- Network subnets

---

## Testing

### Unit Tests
```bash
cd hookprobe
./scripts/run-unit-tests.sh
```

### Integration Tests
```bash
./scripts/run-integration-tests.sh
```

### Performance Tests
```bash
./scripts/run-performance-tests.sh
```

---

## Resource Usage

### Expected Memory Usage

| Component | Memory Limit | Typical Usage |
|-----------|--------------|---------------|
| Django | 1GB | ~600MB |
| PostgreSQL | 512MB | ~300MB |
| Logto | 512MB | ~250MB |
| Redis | 256MB | ~100MB |
| Nginx | 256MB | ~50MB |
| **Total** | **2.5GB** | **~1.3GB** |

Leaves ~2.7GB for OS on 4GB system, ~6.5GB on 8GB system

### CPU Usage

- Light load: 10-20% of 4 cores
- Under test: 40-60% of 4 cores
- Stress test: 80-100% of 4 cores

---

## Troubleshooting

### Pod won't start
```bash
# Check pod status
podman pod ps -a

# Check container logs
podman logs hookprobe-web-django
podman logs hookprobe-database-postgres

# Restart pod
podman pod restart hookprobe-web
```

### Out of memory
```bash
# Check memory usage
free -h

# Reduce resource limits in lightweight-config.sh
# Restart pods after changes
```

### Network issues
```bash
# Check podman networks
podman network ls

# Inspect network
podman network inspect web-net

# Recreate networks
podman network rm web-net database-net cache-net iam-net
# Re-run installation
```

---

## Upgrading to Full Deployment

To upgrade from lightweight to full edge deployment:

```bash
# 1. Backup data
podman exec hookprobe-database-postgres pg_dump hookprobe > backup.sql

# 2. Uninstall lightweight
sudo ./install.sh
# Select: 9) Uninstall / Cleanup → 1) Uninstall Lightweight

# 3. Install full edge deployment
sudo ./install.sh
# Select: 2) Select Deployment Mode → 1) Edge Deployment

# 4. Restore data
podman exec -i hookprobe-database-postgres psql hookprobe < backup.sql
```

---

## Uninstallation

```bash
sudo ./install.sh
# Select: 9) Uninstall / Cleanup
# Select: 1) Uninstall Lightweight Deployment
```

Or manually:
```bash
# Stop and remove all pods
podman pod stop hookprobe-web hookprobe-database hookprobe-cache hookprobe-iam
podman pod rm hookprobe-web hookprobe-database hookprobe-cache hookprobe-iam

# Remove networks
podman network rm web-net database-net cache-net iam-net

# Remove volumes
podman volume prune
```

---

## Limitations

This lightweight deployment is intended for:
- ✅ Development and testing
- ✅ Learning HookProbe
- ✅ CI/CD pipelines
- ✅ Proof of concept

It is NOT suitable for:
- ❌ Production deployments
- ❌ High-traffic environments
- ❌ Multi-tenant MSSP
- ❌ Advanced monitoring needs
- ❌ AI-powered threat detection

For production, use:
- **[Edge Deployment](../edge/README.md)** - Full single-tenant (16GB+ RAM)
- **[Cloud Deployment](../cloud/README.md)** - Multi-tenant MSSP (64GB+ RAM)

---

## Support

- **Documentation:** [DOCUMENTATION-INDEX.md](../../DOCUMENTATION-INDEX.md)
- **Testing Guide:** [SOFTWARE-TESTING-STRATEGY.md](../../SOFTWARE-TESTING-STRATEGY.md)
- **Issues:** https://github.com/hookprobe/hookprobe/issues

---

**Last Updated:** 2025-12-02
**Version:** 5.0
**Status:** Beta - For testing only
