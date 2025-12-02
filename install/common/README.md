# Common Installation Scripts

**Shared utilities and configuration for all deployment types**

This directory contains common scripts, configuration files, and utilities shared across Edge, Cloud, and addon deployments.

---

## 📁 Contents

```
common/
├── config-wizard.sh       # Interactive configuration wizard
├── unified-config.sh      # Centralized configuration system
├── pre-install-check.sh   # System requirements validation
└── gdpr-config.sh         # GDPR compliance settings
```

---

## 🧙 Configuration Wizard (`config-wizard.sh`)

Interactive wizard for setting up HookProbe configuration.

### Features

- ✅ Network interface auto-detection
- ✅ IP address validation and configuration
- ✅ Password generation (secure random)
- ✅ Deployment type selection (edge/cloud/hybrid)
- ✅ Optional component selection
- ✅ Configuration file generation

### Usage

```bash
# Via main installer
sudo ./install.sh
# Select: 4) Basic Configuration → 6) Run Configuration Wizard

# Direct invocation
cd install/common
sudo ./config-wizard.sh edge ../edge/config.sh
```

### What It Configures

- Network interfaces and IP addresses
- VXLAN encryption keys (PSK)
- Database passwords (PostgreSQL, ClickHouse)
- Service credentials (Grafana, Logto, etc.)
- Optional features (n8n, LTE/5G, email)

---

## 🔧 Unified Configuration (`unified-config.sh`)

Centralized configuration system for all PODs.

### Purpose

Single source of truth for:
- Network topology (VXLANs, subnets, IPs)
- Service credentials
- Feature flags
- Deployment-specific settings

### Configuration Structure

```bash
# Deployment type
DEPLOYMENT_TYPE="edge"  # edge, cloud, hybrid, headless, development

# Network configuration
HOST_A_IP="192.168.1.100"
PHYSICAL_HOST_INTERFACE="eth0"
VXLAN_PSK="your-psk-key"

# Database credentials
POSTGRES_PASSWORD="secure-password"
CLICKHOUSE_PASSWORD="another-secure-password"

# Feature flags
ENABLE_N8N=true
ENABLE_EMAIL=false
ENABLE_LTE=false
```

### Loading Configuration

```bash
# From any script
source /home/user/hookprobe/install/common/unified-config.sh

# Variables are now available
echo "Database: $POSTGRES_PASSWORD"
echo "Deployment: $DEPLOYMENT_TYPE"
```

---

## ✅ Pre-Install Check (`pre-install-check.sh`)

Validates system requirements before installation.

### Checks Performed

1. **Hardware Requirements**:
   - CPU cores (4+ required)
   - RAM (16GB+ recommended)
   - Disk space (500GB+ recommended)
   - Network interface availability

2. **Software Requirements**:
   - Kernel version (5.x+ required)
   - Podman installation
   - OVS (Open vSwitch) availability
   - Required tools (ip, iptables, ovs-vsctl)

3. **Network Configuration**:
   - Interface status (UP/DOWN)
   - IP configuration
   - Default route
   - DNS resolution

4. **Security**:
   - SELinux / AppArmor status
   - Firewall configuration
   - Port availability (80, 443, 3000, etc.)

### Usage

```bash
# Via main installer
sudo ./install.sh
# Select: 1) Pre-Install / System Check → 5) Run Complete Pre-Install Check

# Direct invocation
cd install/common
sudo ./pre-install-check.sh
```

### Output

```
========================================
HOOKPROBE PRE-INSTALL SYSTEM CHECK
========================================

[✓] CPU: 8 cores (4+ required)
[✓] RAM: 32GB (16GB+ recommended)
[✓] Disk: 1TB available (500GB+ recommended)
[✓] Kernel: 6.1.0 (5.x+ required)
[✓] Podman: 4.9.4 installed
[✗] OVS: Not installed (will install)
[✓] Network: eth0 (192.168.1.100) UP

Overall: READY TO INSTALL
(1 warning, non-blocking)
```

---

## 🔐 GDPR Configuration (`gdpr-config.sh`)

GDPR compliance settings and data retention policies.

### Key Settings

```bash
# Privacy settings
GDPR_ENABLED=true
ANONYMIZE_IP_ADDRESSES=true
ANONYMIZE_MAC_ADDRESSES=true
COLLECT_FULL_PAYLOAD=false  # NEVER enable (privacy violation)

# Data retention (days)
RETENTION_NETWORK_FLOWS_DAYS=30
RETENTION_SECURITY_LOGS_DAYS=90
RETENTION_IDS_ALERTS_DAYS=365
RETENTION_INACTIVE_ACCOUNTS_DAYS=365

# Breach notification
BREACH_DETECTION_ENABLED=true
BREACH_NOTIFICATION_DEADLINE_HOURS=72
BREACH_NOTIFICATION_EMAIL="qsecbit@hookprobe.com"
```

### Compliance Features

- IP address anonymization (last octet masked)
- MAC address pseudonymization (vendor OUI preserved)
- Automated data retention cleanup (cron job)
- Data subject rights support (access, erasure, portability)
- Breach detection and notification

### Usage

```bash
# Review settings
nano /home/user/hookprobe/install/common/gdpr-config.sh

# Apply configuration (loaded by setup scripts automatically)
source /home/user/hookprobe/install/common/gdpr-config.sh
```

**Documentation**: [../../docs/GDPR.md](../../docs/GDPR.md)

---

## 🔄 Configuration Workflow

### 1. Run Pre-Install Check

```bash
sudo ./install/common/pre-install-check.sh
```

### 2. Run Configuration Wizard

```bash
sudo ./install.sh
# Select: 4) Basic Configuration → 6) Run Configuration Wizard
```

### 3. Review Generated Configuration

```bash
# Edge deployment
cat install/edge/config.sh

# Cloud deployment
cat install/cloud/config.sh
```

### 4. Customize (Optional)

```bash
# Edit generated configuration
nano install/edge/config.sh

# Validate changes
bash -n install/edge/config.sh  # Syntax check
```

### 5. Deploy

```bash
sudo ./install.sh
# Select: 2) Select Deployment Mode → 1) Edge or 2) Cloud
```

---

## 🛠️ Utility Functions

Common functions available to all installation scripts:

### Network Functions

```bash
# Detect default network interface
detect_default_interface()

# Validate IP address
validate_ip_address "$IP"

# Generate random password
generate_password 32  # 32 characters
```

### Logging Functions

```bash
# Log levels
log_info "Starting installation..."
log_warn "Configuration not found, using defaults"
log_error "Installation failed"
log_success "Installation completed"
```

### Validation Functions

```bash
# Check if command exists
command_exists "podman"

# Check if port is available
is_port_available 3000

# Check disk space
check_disk_space "/var/lib" 100  # 100GB required
```

---

## 📚 Documentation

- **Main Installer**: [../install.sh](../../install.sh)
- **Edge Deployment**: [../edge/README.md](../edge/README.md)
- **Cloud Deployment**: [../cloud/README.md](../cloud/README.md)
- **GDPR Compliance**: [../../docs/GDPR.md](../../docs/GDPR.md)

---

**Common Installation Scripts** - *Shared Foundation for All Deployments*

Built with ❤️ for consistent, reliable installations
