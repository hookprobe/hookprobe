# HookProbe Installation Cleanup & Unification Plan

**Date**: 2025-12-03
**Status**: **CRITICAL - Installation broken, needs immediate cleanup**
**Goal**: Single unified installation path with clear flavors for edge/cloud/MSSP

---

## 🔴 Current Problems

### 1. **Fragmented Installation Structure**
```
hookprobe/
├── install.sh                          ← Main menu (44KB, complex)
├── install-validator.sh                ← Separate validator install
├── install/
│   ├── edge/setup.sh                   ← Full edge deployment (68KB)
│   ├── cloud/setup.sh                  ← Cloud deployment
│   ├── testing/lightweight-setup.sh    ← Testing (20KB) ⚠️ DOESN'T WORK
│   ├── testing/lightweight-config.sh   ← Testing config ⚠️ DUPLICATED
│   └── addons/                         ← Scattered add-ons
```

**Issues**:
- ❌ 3 different installation paths (edge, testing, validator)
- ❌ Testing installation doesn't work (user reported)
- ❌ Duplicated configuration files
- ❌ No Raspberry Pi memory limits
- ❌ No clear "edge with qsecbit but no AI" option
- ❌ User confusion: "Which script do I run?"

### 2. **Testing vs Production Confusion**
```
install/testing/
├── README.md                           ← 390 lines of instructions
├── lightweight-setup.sh                ← Broken installation
└── lightweight-config.sh               ← Duplicates edge config
```

**Problems**:
- Testing installation is **separate** from edge
- Should be integrated as **edge flavor** (lightweight)
- No upgrade path from testing → full edge
- Wasted maintenance effort on duplicate code

### 3. **Missing Raspberry Pi Support**
- ❌ No memory limits for containers (RPi has 4GB/8GB)
- ❌ No cgroup validation in main install.sh
- ❌ No architecture-specific optimizations
- ❌ Testing script has RPi support, but main edge doesn't

### 4. **Unclear Edge Flavors**
```
User wants:
1. Edge with qsecbit (NO AI) ← DEFAULT
2. Edge with qsecbit + AI (monitoring, detection)
3. Edge lightweight (testing, Raspberry Pi 4GB)

Current:
- install/edge/setup.sh deploys EVERYTHING (including AI)
- install/testing/lightweight-setup.sh tries to do minimal, but broken
- No "qsecbit only" option
```

---

## ✅ Proposed Solution: Unified Installation Flow

### New Structure

```
hookprobe/
├── install.sh                          ← SIMPLIFIED menu
├── scripts/
│   ├── install-edge.sh                 ← UNIFIED edge installation
│   ├── install-cloud.sh                ← Cloud/MSSP installation
│   ├── install-validator.sh            ← Validator installation
│   └── utils/
│       ├── detect-platform.sh          ← OS/hardware detection
│       ├── check-requirements.sh       ← Validate system
│       └── setup-cgroups.sh            ← Raspberry Pi cgroup setup
├── config/
│   ├── edge-minimal.yaml               ← Edge with qsecbit only (DEFAULT)
│   ├── edge-full.yaml                  ← Edge with AI/monitoring
│   ├── edge-rpi.yaml                   ← Raspberry Pi 4GB optimized
│   ├── cloud.yaml                      ← Cloud/MSSP
│   └── validator.yaml                  ← Validator nodes
└── DELETE:
    ├── install/testing/                ← REMOVE entirely
    ├── install/edge/setup.sh           ← MERGE into scripts/install-edge.sh
    └── install-validator.sh (root)     ← MOVE to scripts/
```

---

## 📋 Cleanup Tasks

### Phase 1: Remove Broken/Duplicate Files

**DELETE:**
```bash
rm -rf install/testing/                  # Broken lightweight install
rm install-validator.sh                  # Move to scripts/
rm install/edge/setup.sh                 # Merge into unified script
rm install/edge/config.sh                # Move to config/
```

**KEEP (for reference, then delete after migration):**
- `install/edge/README.md` → Merge into docs/installation/
- `install/edge/checklist.md` → Merge into docs/installation/

---

### Phase 2: Create Unified Edge Installation

**New file: `scripts/install-edge.sh`**

```bash
#!/bin/bash
#
# install-edge.sh - Unified Edge Node Installation
# Supports 3 flavors via --flavor flag
#

set -e

# ============================================================
# EDGE FLAVORS
# ============================================================

FLAVOR="minimal"  # DEFAULT: qsecbit only, no AI

case "$1" in
    --flavor=minimal)
        FLAVOR="minimal"
        CONFIG="config/edge-minimal.yaml"
        PODS="001,002,003,005,010"  # Web, IAM, DB, Cache, Neuro (qsecbit)
        MEMORY_REQUIRED="4GB"
        ;;
    --flavor=full)
        FLAVOR="full"
        CONFIG="config/edge-full.yaml"
        PODS="001,002,003,004,005,006,007,010"  # All PODs including AI
        MEMORY_REQUIRED="16GB"
        ;;
    --flavor=rpi)
        FLAVOR="rpi"
        CONFIG="config/edge-rpi.yaml"
        PODS="001,003,005,010"  # Minimal for RPi 4GB
        MEMORY_REQUIRED="4GB"
        ENABLE_CGROUP_CHECK=true
        ;;
    *)
        echo "Usage: $0 [--flavor=minimal|full|rpi]"
        echo ""
        echo "Flavors:"
        echo "  minimal  - Qsecbit only, no AI (DEFAULT) [4GB RAM]"
        echo "  full     - All features: Qsecbit + AI + Monitoring [16GB RAM]"
        echo "  rpi      - Raspberry Pi optimized [4GB RAM]"
        exit 1
        ;;
esac

# ============================================================
# RASPBERRY PI CGROUP CHECK
# ============================================================

if [ "$ENABLE_CGROUP_CHECK" = true ]; then
    source "$(dirname $0)/utils/setup-cgroups.sh"
    check_cgroup_support

    if ! is_cgroup_enabled; then
        echo "⚠️  CRITICAL: Cgroup not enabled on Raspberry Pi"
        echo ""
        echo "You must enable cgroups in /boot/firmware/cmdline.txt"
        echo "Add this to the EXISTING line (do NOT create new line):"
        echo ""
        echo "  cgroup_enable=cpuset cgroup_enable=memory cgroup_memory=1"
        echo ""
        echo "Then reboot and re-run this script."
        exit 1
    fi
fi

# ============================================================
# MEMORY LIMITS FOR RASPBERRY PI
# ============================================================

if [ "$FLAVOR" = "rpi" ]; then
    # Raspberry Pi memory limits (conservative for 4GB)
    export POD_MEMORY_LIMIT_WEB="768M"       # Django + Nginx
    export POD_MEMORY_LIMIT_DATABASE="512M"  # PostgreSQL
    export POD_MEMORY_LIMIT_CACHE="256M"     # Redis
    export POD_MEMORY_LIMIT_NEURO="512M"     # Qsecbit (int16, lightweight)
    # Total: ~2GB, leaves 2GB for OS
else
    # Standard edge memory limits
    export POD_MEMORY_LIMIT_WEB="2G"
    export POD_MEMORY_LIMIT_DATABASE="2G"
    export POD_MEMORY_LIMIT_CACHE="1G"
    export POD_MEMORY_LIMIT_NEURO="1G"
fi

# ============================================================
# POD DEPLOYMENT
# ============================================================

deploy_pods() {
    echo "Deploying Edge Flavor: $FLAVOR"
    echo "Configuration: $CONFIG"
    echo "PODs: $PODS"
    echo ""

    IFS=',' read -ra POD_LIST <<< "$PODS"
    for pod in "${POD_LIST[@]}"; do
        case "$pod" in
            001) deploy_pod_web ;;
            002) deploy_pod_iam ;;
            003) deploy_pod_database ;;
            004) deploy_pod_monitoring ;;
            005) deploy_pod_cache ;;
            006) deploy_pod_detection ;;
            007) deploy_pod_ai ;;
            010) deploy_pod_neuro ;;
        esac
    done
}

deploy_pod_neuro() {
    echo "🧠 Deploying POD-010: Neuro Protocol (Qsecbit)"

    podman pod create \
        --name hookprobe-neuro \
        --network neuro-net

    # Qsecbit engine (lightweight, no AI models)
    podman run -d \
        --name hookprobe-neuro-qsecbit \
        --pod hookprobe-neuro \
        --memory "$POD_MEMORY_LIMIT_NEURO" \
        --memory-swap 0 \
        -v hookprobe-neuro-data:/data \
        hookprobe/qsecbit:latest

    # HTP transport protocol
    podman run -d \
        --name hookprobe-neuro-htp \
        --pod hookprobe-neuro \
        --memory 256M \
        hookprobe/htp:latest
}

# Main deployment
deploy_pods
```

---

### Phase 3: Create Configuration Files

**File: `config/edge-minimal.yaml` (DEFAULT)**

```yaml
# Edge Minimal Configuration
# Qsecbit only, no AI/monitoring
# Memory: 4GB minimum
# Target: Home users, SMB, IoT edge devices

deployment:
  mode: edge
  flavor: minimal

pods:
  enabled:
    - pod-001  # Web Server (Django + Nginx + NAXSI)
    - pod-002  # IAM (Logto authentication)
    - pod-003  # Database (PostgreSQL 16)
    - pod-005  # Cache (Redis 7)
    - pod-010  # Neuro Protocol (Qsecbit + HTP)

  disabled:
    - pod-004  # Monitoring (VictoriaMetrics, Grafana) - TOO HEAVY
    - pod-006  # Detection (Suricata, Zeek, Snort) - AI NOT INCLUDED
    - pod-007  # AI Analysis (ML models) - NOT INCLUDED
    - pod-008  # Automation (n8n) - Optional

resources:
  memory:
    web: 2G
    database: 2G
    cache: 1G
    neuro: 1G
    # Total: ~6GB (requires 8GB system for OS overhead)

security:
  # Qsecbit enabled by default
  qsecbit:
    enabled: true
    algorithm: SHA256  # Quantum-resistant hash
    rdv_algorithm: BLAKE3
    posf_enabled: true

  # HTP transport protocol
  htp:
    enabled: true
    quantum_resistant: true
    adaptive_mode: true
    rtt_measurement: true
    bandwidth_detection: true
    stress_monitoring: true

  # AI features DISABLED in minimal
  ai_detection:
    enabled: false

  monitoring:
    enabled: false
```

**File: `config/edge-rpi.yaml`**

```yaml
# Raspberry Pi Edge Configuration
# Optimized for 4GB RAM (leaves 2GB for OS)
# Ultra-lightweight: Qsecbit only

deployment:
  mode: edge
  flavor: rpi
  platform: arm64

pods:
  enabled:
    - pod-001  # Web (lightweight)
    - pod-003  # Database (PostgreSQL alpine)
    - pod-005  # Cache (Redis alpine)
    - pod-010  # Neuro (Qsecbit only, no AI models)

  disabled:
    - pod-002  # IAM (optional, can enable if needed)
    - pod-004  # Monitoring (too heavy)
    - pod-006  # Detection (too heavy)
    - pod-007  # AI (too heavy)
    - pod-008  # Automation (too heavy)

resources:
  # Conservative limits for Raspberry Pi 4GB
  memory:
    web: 768M           # Django + Nginx
    database: 512M      # PostgreSQL alpine
    cache: 256M         # Redis alpine
    neuro: 512M         # Qsecbit (int16, no ML)
    # Total: ~2GB, leaves 2GB for OS

  cpu:
    # Use CPU quotas to prevent thermal throttling
    web: 1.5            # 1.5 cores max
    database: 1.0       # 1 core max
    cache: 0.5          # 0.5 cores max
    neuro: 1.0          # 1 core max

platform:
  raspberry_pi:
    # Raspberry Pi specific optimizations
    enable_cgroup_check: true
    thermal_throttle_check: true
    max_temperature_celsius: 70  # Throttle if CPU > 70°C

    # Memory pressure handling
    oom_score_adjust:
      web: 0           # Normal priority
      database: -100   # Protect database from OOM killer
      cache: 100       # Cache can be killed first
      neuro: -50       # Protect qsecbit engine

security:
  qsecbit:
    enabled: true
    # Lightweight mode for Raspberry Pi
    weight_evolution_interval: 120  # Every 2 minutes (vs 60s default)
    ter_compression: true           # Compress TER logs

  htp:
    enabled: true
    adaptive_mode: true
    # Reduce cryptographic load on RPi
    chacha20_enabled: false         # Disable encryption (trust LAN)
    posf_verification_interval: 300 # Every 5 minutes (vs 60s)

  ai_detection:
    enabled: false  # NO AI on Raspberry Pi

  monitoring:
    enabled: false  # NO monitoring on Raspberry Pi
```

---

## 🚀 New Installation Flow

### User Experience

```bash
# Install HookProbe Edge (DEFAULT: qsecbit only, no AI)
sudo ./install.sh

# Main Menu:
# 1) Select Deployment Mode
#    ├─ Edge (Minimal) - Qsecbit only [DEFAULT] [4GB RAM]
#    ├─ Edge (Full) - Qsecbit + AI + Monitoring [16GB RAM]
#    ├─ Edge (Raspberry Pi) - Optimized for RPi 4GB
#    ├─ Cloud/MSSP - Multi-tenant [64GB+ RAM]
#    └─ Validator - Byzantine consensus node [8GB+ RAM]
```

**Simplified edge install:**
```bash
# Method 1: Interactive menu
sudo ./install.sh
# Select: 1) Edge (Minimal)

# Method 2: Direct command
sudo bash scripts/install-edge.sh --flavor=minimal

# Method 3: Raspberry Pi
sudo bash scripts/install-edge.sh --flavor=rpi
```

---

## 📦 Files to DELETE

### Immediate Deletion (Broken/Duplicated)

```bash
# Testing directory (broken, integrate into edge)
install/testing/README.md
install/testing/lightweight-setup.sh
install/testing/lightweight-config.sh

# Duplicated edge setup (merge into scripts/install-edge.sh)
install/edge/setup.sh
install/edge/config.sh

# Duplicated validator install (move to scripts/)
install-validator.sh  # Move to scripts/install-validator.sh

# Obsolete documentation (merge into docs/installation/)
install/edge/checklist.md
install/edge/QUICK-START.md
```

### Files to KEEP (but reorganize)

```bash
# Move to scripts/utils/
install/edge/hookprobe-bootstrap.sh → scripts/utils/bootstrap.sh
install/edge/hookprobe-ctl → scripts/utils/hookprobe-ctl
install/edge/provision.sh → scripts/utils/provision.sh
install/edge/update.sh → scripts/utils/update.sh
install/edge/cleanup.sh → scripts/utils/cleanup.sh
install/edge/uninstall.sh → scripts/utils/uninstall.sh

# Move systemd services
install/edge/systemd/*.service → systemd/edge/

# Keep common utilities
install/common/ → scripts/common/
```

---

## 🛠️ Implementation Steps

### Step 1: Create New Structure (No Breaking Changes Yet)

```bash
# Create new directories
mkdir -p scripts/utils
mkdir -p scripts/common
mkdir -p systemd/edge
mkdir -p config/

# Create new unified scripts
scripts/install-edge.sh          # New unified edge installer
scripts/install-cloud.sh         # Cloud/MSSP
scripts/install-validator.sh     # Validators

# Create configuration files
config/edge-minimal.yaml         # DEFAULT: qsecbit only
config/edge-full.yaml            # Full edge with AI
config/edge-rpi.yaml             # Raspberry Pi optimized
config/cloud.yaml                # Cloud/MSSP
config/validator.yaml            # Validators

# Create utility scripts
scripts/utils/detect-platform.sh        # OS/arch detection
scripts/utils/check-requirements.sh     # Validate system
scripts/utils/setup-cgroups.sh          # Raspberry Pi cgroups
scripts/utils/deploy-pod.sh             # Generic POD deployment
scripts/utils/configure-memory.sh       # Memory limit calculation
```

### Step 2: Migrate Edge Installation

**Copy best parts from:**
- `install/edge/setup.sh` → Platform detection, POD deployment
- `install/testing/lightweight-setup.sh` → Raspberry Pi support, memory limits

**New `scripts/install-edge.sh` features:**
- ✅ 3 flavors: minimal (default), full, rpi
- ✅ Raspberry Pi cgroup validation
- ✅ Memory limits per platform
- ✅ Architecture detection (x86_64 vs ARM64)
- ✅ Configuration via YAML files
- ✅ No AI in minimal mode (qsecbit only)

### Step 3: Update Main Menu

**Simplify `install.sh`:**

```bash
show_deployment_menu() {
    echo "Select Deployment Mode:"
    echo ""
    echo "  1) Edge (Minimal) - Qsecbit only [DEFAULT] [4GB RAM]"
    echo "  2) Edge (Full) - Qsecbit + AI + Monitoring [16GB RAM]"
    echo "  3) Edge (Raspberry Pi) - Optimized for RPi 4/5 [4GB RAM]"
    echo "  4) Cloud/MSSP - Multi-tenant [64GB+ RAM]"
    echo "  5) Validator - Consensus node [8GB+ RAM]"
    echo ""

    read -p "Select option: " choice

    case $choice in
        1) bash scripts/install-edge.sh --flavor=minimal ;;
        2) bash scripts/install-edge.sh --flavor=full ;;
        3) bash scripts/install-edge.sh --flavor=rpi ;;
        4) bash scripts/install-cloud.sh ;;
        5) bash scripts/install-validator.sh ;;
        *) echo "Invalid option" ;;
    esac
}
```

### Step 4: Delete Old Files

**After migration is complete and tested:**

```bash
# Backup first
tar -czf hookprobe-install-backup-$(date +%Y%m%d).tar.gz install/

# Delete testing directory
rm -rf install/testing/

# Delete old edge setup
rm install/edge/setup.sh
rm install/edge/config.sh

# Delete duplicated validator
rm install-validator.sh

# Cleanup
git rm -r install/testing/
git rm install/edge/setup.sh install/edge/config.sh
git rm install-validator.sh
git commit -m "cleanup: Remove duplicated/broken installation scripts"
```

### Step 5: Update Documentation

**Update:**
- `docs/installation/INSTALLATION.md`
- `README.md` (quick start section)
- `QUICK-START.md`

**Add:**
- `docs/installation/EDGE_FLAVORS.md` (explain minimal vs full vs rpi)
- `docs/installation/RASPBERRY_PI.md` (RPi-specific guide)

---

## 🎯 Benefits of This Cleanup

### For Users

1. **Clear Choice**: 3 edge flavors, not confusing paths
   - Minimal (default): Qsecbit only, no AI
   - Full: Everything (AI + monitoring)
   - RPi: Raspberry Pi optimized

2. **Single Command**: `sudo ./install.sh` → Select flavor
   - No more "which script do I run?"
   - No more broken testing installation

3. **Raspberry Pi Support**: Built-in, not afterthought
   - Automatic cgroup validation
   - Memory limits optimized for 4GB
   - Thermal throttling protection

### For Developers

1. **Less Code to Maintain**:
   - Delete 600+ lines of broken testing code
   - Merge edge installation into one script
   - Single configuration system (YAML)

2. **Easier to Extend**:
   - Add new flavor? Just create new YAML config
   - Add new platform? Update detect-platform.sh
   - Add new POD? Add to deploy-pod.sh

3. **Better Testing**:
   - One installation path = one test suite
   - Clear flavors = clear test matrix
   - No duplicate code = no divergence

---

## 📊 Comparison: Before vs After

### Before (Current - Broken)

```
Installation Paths: 3 (confusing)
- install.sh → edge/setup.sh (full, 16GB)
- install/testing/lightweight-setup.sh (broken)
- install-validator.sh (separate)

Edge Flavors: 1 (all or nothing)
- Full edge only (includes AI, requires 16GB)

Raspberry Pi Support: Partial (only in testing, broken)
Qsecbit-only option: NO
Lines of Code: ~1,500 (duplicated across scripts)
```

### After (Proposed - Clean)

```
Installation Paths: 1 (clear)
- install.sh → scripts/install-{edge,cloud,validator}.sh

Edge Flavors: 3 (clear choice)
- Minimal: Qsecbit only, no AI (DEFAULT) [4GB]
- Full: Qsecbit + AI + Monitoring [16GB]
- RPi: Raspberry Pi optimized [4GB]

Raspberry Pi Support: Full (built-in)
Qsecbit-only option: YES (default minimal flavor)
Lines of Code: ~800 (unified, no duplication)
```

---

## ⚠️ Migration Risks

### Low Risk
- ✅ New scripts don't break existing installations
- ✅ Old scripts can coexist temporarily
- ✅ Users can test new flow before old is removed

### Medium Risk
- ⚠️ Configuration file migration (edge-minimal.yaml vs old config.sh)
- ⚠️ Users may have customized install/edge/config.sh
- **Mitigation**: Auto-migrate old config.sh → edge-minimal.yaml

### High Risk
- ❌ Deleting install/testing/ breaks anyone using it
- **Mitigation**: Keep for 1 release cycle, mark deprecated
- ❌ Changing install.sh menu breaks documentation
- **Mitigation**: Update all docs in same commit

---

## 🚦 Rollout Plan

### Phase 1: Create (No Breaking Changes) ✅ Safe
- Create `scripts/install-edge.sh` with 3 flavors
- Create `config/*.yaml` configuration files
- Create `scripts/utils/*.sh` helper scripts
- **Existing install.sh still works**

### Phase 2: Test ✅ Safe
- Test new installation on:
  - x86_64 (16GB) - edge minimal
  - x86_64 (16GB) - edge full
  - ARM64 Raspberry Pi 4 (4GB) - edge rpi
  - ARM64 Raspberry Pi 5 (8GB) - edge rpi
- Validate all PODs start correctly
- **Existing install.sh still works**

### Phase 3: Update Menu ⚠️ Medium Risk
- Update `install.sh` to call new scripts
- Mark old paths as deprecated
- Update documentation
- **Old scripts still exist as fallback**

### Phase 4: Deprecation ⚠️ Medium Risk
- Add deprecation warnings to:
  - `install/testing/lightweight-setup.sh`
  - `install/edge/setup.sh`
- Redirect to new scripts
- Keep files for 1 release (6 months)

### Phase 5: Deletion ❌ Breaking
- Delete deprecated files
- Final documentation update
- Release notes: "Simplified installation"

---

## 📝 Summary: What Gets Deleted

### Immediate Deletion (After Migration)

```bash
# Broken/duplicated files
install/testing/README.md                    # 390 lines
install/testing/lightweight-setup.sh         # 600+ lines (BROKEN)
install/testing/lightweight-config.sh        # 200+ lines (duplicate)

# Merged into scripts/install-edge.sh
install/edge/setup.sh                        # 2,000+ lines
install/edge/config.sh                       # 500+ lines

# Moved to scripts/
install-validator.sh                         # Move to scripts/

# Total deleted: ~3,700 lines of duplicated/broken code
```

### Kept (Reorganized)

```bash
# Utilities (move to scripts/utils/)
install/edge/hookprobe-ctl
install/edge/provision.sh
install/edge/update.sh
install/edge/cleanup.sh
install/edge/uninstall.sh

# Common (move to scripts/common/)
install/common/*

# Systemd services (move to systemd/edge/)
install/edge/systemd/*.service
```

---

## 🎯 Success Criteria

1. ✅ **Single installation path**: `sudo ./install.sh` works for all modes
2. ✅ **Clear flavors**: Minimal (qsecbit), Full (AI), RPi (optimized)
3. ✅ **Raspberry Pi support**: Built-in cgroup validation, memory limits
4. ✅ **Qsecbit-only mode**: Default minimal flavor, no AI
5. ✅ **No broken code**: Delete install/testing/ (doesn't work)
6. ✅ **Less code**: Reduce from ~3,700 to ~800 lines (unified)
7. ✅ **Better UX**: "Which script?" → "Which flavor?"

---

## 🔄 Next Steps

1. **Create** new structure (scripts/, config/, systemd/)
2. **Migrate** edge installation to scripts/install-edge.sh
3. **Test** on x86_64 and ARM64 platforms
4. **Update** install.sh menu to use new scripts
5. **Delete** broken/duplicated files
6. **Update** all documentation
7. **Release** v5.1 with simplified installation

**Estimated Effort**: 2-3 days
**Risk Level**: Medium (backward compatibility required)
**User Impact**: Positive (simpler, clearer, works on RPi)

---

**End of Cleanup Plan**
