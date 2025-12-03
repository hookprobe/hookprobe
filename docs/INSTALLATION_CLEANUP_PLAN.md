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

## ✅ Proposed Solution: ONE Unified Edge Installation

### New Structure (Simplified)

```
hookprobe/
├── install.sh                          ← Main entry point (simplified menu)
├── scripts/
│   ├── install-edge.sh                 ← ONE unified edge (auto-detects everything)
│   ├── install-cloud.sh                ← Cloud/MSSP installation
│   ├── install-validator.sh            ← Validator installation
│   └── lib/
│       ├── platform.sh                 ← Platform detection (OS/arch/RAM/RPi)
│       ├── requirements.sh             ← System validation
│       ├── instructions.sh             ← Show user instructions when needed
│       └── pods.sh                     ← POD deployment functions
└── DELETE:
    ├── install/testing/                ← REMOVE entirely (broken)
    ├── install/edge/setup.sh           ← MERGE into scripts/install-edge.sh
    ├── install/edge/config.sh          ← MERGE into scripts/lib/platform.sh
    └── install-validator.sh (root)     ← MOVE to scripts/
```

**Key Principle**: ONE script that's smart, not multiple flavors.

---

## 📋 Cleanup Tasks

### Phase 1: Remove Broken/Duplicate Files

**DELETE:**
```bash
rm -rf install/testing/                  # Broken lightweight install
rm install-validator.sh                  # Move to scripts/
rm install/edge/setup.sh                 # Merge into unified script
rm install/edge/config.sh                # Merge into lib/platform.sh
```

**KEEP (for reference, then delete after migration):**
- `install/edge/README.md` → Merge into docs/installation/
- `install/edge/checklist.md` → Merge into docs/installation/

---

### Phase 2: Create ONE Unified Edge Installation

**New file: `scripts/install-edge.sh`**

```bash
#!/bin/bash
#
# install-edge.sh - ONE Unified Edge Installation
# Auto-detects platform and adjusts accordingly
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/platform.sh"
source "$SCRIPT_DIR/lib/requirements.sh"
source "$SCRIPT_DIR/lib/instructions.sh"
source "$SCRIPT_DIR/lib/pods.sh"

# ============================================================
# DEFAULT CONFIGURATION (User can override with flags)
# ============================================================

ENABLE_AI=false          # DEFAULT: NO AI (qsecbit only)
ENABLE_MONITORING=false  # DEFAULT: NO monitoring
ENABLE_IAM=true          # IAM usually needed

# Parse command-line flags
while [[ $# -gt 0 ]]; do
    case $1 in
        --enable-ai)
            ENABLE_AI=true
            shift
            ;;
        --enable-monitoring)
            ENABLE_MONITORING=true
            shift
            ;;
        --disable-iam)
            ENABLE_IAM=false
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--enable-ai] [--enable-monitoring] [--disable-iam]"
            exit 1
            ;;
    esac
done

echo "============================================================"
echo "   HOOKPROBE EDGE INSTALLATION"
echo "   One Unified Installer - Auto-Detection"
echo "============================================================"
echo ""

# ============================================================
# STEP 1: DETECT PLATFORM
# ============================================================

echo "[1/6] Detecting platform..."
detect_platform  # Sets: PLATFORM_OS, PLATFORM_ARCH, TOTAL_RAM_GB, IS_RASPBERRY_PI

echo "  OS:           $PLATFORM_OS"
echo "  Architecture: $PLATFORM_ARCH"
echo "  RAM:          ${TOTAL_RAM_GB}GB"
echo "  Raspberry Pi: $IS_RASPBERRY_PI"
echo ""

# ============================================================
# STEP 2: CHECK REQUIREMENTS & SHOW INSTRUCTIONS
# ============================================================

echo "[2/6] Checking requirements..."

# Check if Raspberry Pi needs cgroup setup
if [ "$IS_RASPBERRY_PI" = true ]; then
    if ! check_cgroup_enabled; then
        echo ""
        echo "⚠️  CRITICAL: Cgroups not enabled (required for Raspberry Pi)"
        echo ""
        show_cgroup_instructions  # From lib/instructions.sh
        echo ""
        echo "After making these changes, reboot and re-run this script."
        exit 1
    fi
    echo "  ✓ Cgroups enabled"
fi

# Check RAM requirements
if [ "$TOTAL_RAM_GB" -lt 4 ]; then
    echo "  ✗ Insufficient RAM: ${TOTAL_RAM_GB}GB (minimum 4GB required)"
    exit 1
fi
echo "  ✓ RAM sufficient: ${TOTAL_RAM_GB}GB"

# Check disk space
if ! check_disk_space 20; then  # Minimum 20GB free
    echo "  ✗ Insufficient disk space (minimum 20GB required)"
    exit 1
fi
echo "  ✓ Disk space sufficient"

echo ""

# ============================================================
# STEP 3: CALCULATE MEMORY LIMITS (Auto-adjust based on RAM)
# ============================================================

echo "[3/6] Calculating resource limits..."

if [ "$TOTAL_RAM_GB" -le 4 ]; then
    # Conservative for 4GB systems (Raspberry Pi)
    export POD_MEMORY_WEB="768M"
    export POD_MEMORY_DATABASE="512M"
    export POD_MEMORY_CACHE="256M"
    export POD_MEMORY_NEURO="512M"
    echo "  Profile: Lightweight (4GB system)"
elif [ "$TOTAL_RAM_GB" -le 8 ]; then
    # Moderate for 8GB systems
    export POD_MEMORY_WEB="1.5G"
    export POD_MEMORY_DATABASE="1.5G"
    export POD_MEMORY_CACHE="512M"
    export POD_MEMORY_NEURO="1G"
    echo "  Profile: Moderate (8GB system)"
else
    # Full for 16GB+ systems
    export POD_MEMORY_WEB="2G"
    export POD_MEMORY_DATABASE="2G"
    export POD_MEMORY_CACHE="1G"
    export POD_MEMORY_NEURO="1G"
    echo "  Profile: Full (16GB+ system)"
fi

echo "  Memory limits configured for ${TOTAL_RAM_GB}GB RAM"
echo ""

# ============================================================
# STEP 4: DETERMINE PODS TO DEPLOY
# ============================================================

echo "[4/6] Determining PODs to deploy..."
echo ""
echo "  Core PODs (always deployed):"
echo "    ✓ POD-001: Web Server (Django + Nginx + NAXSI)"
echo "    ✓ POD-003: Database (PostgreSQL)"
echo "    ✓ POD-005: Cache (Redis)"
echo "    ✓ POD-010: Neuro Protocol (Qsecbit + HTP)"

if [ "$ENABLE_IAM" = true ]; then
    echo "    ✓ POD-002: IAM (Logto authentication)"
fi

echo ""
echo "  Optional PODs (disabled by default):"

if [ "$ENABLE_MONITORING" = true ]; then
    echo "    ✓ POD-004: Monitoring (Grafana, VictoriaMetrics)"
else
    echo "    ✗ POD-004: Monitoring (use --enable-monitoring to enable)"
fi

if [ "$ENABLE_AI" = true ]; then
    echo "    ✓ POD-006: Detection (Suricata, Zeek)"
    echo "    ✓ POD-007: AI Analysis (Qsecbit ML models)"
else
    echo "    ✗ POD-006: Detection (use --enable-ai to enable)"
    echo "    ✗ POD-007: AI Analysis (use --enable-ai to enable)"
fi

echo ""

# Warn if trying to enable AI on low RAM
if [ "$ENABLE_AI" = true ] && [ "$TOTAL_RAM_GB" -lt 16 ]; then
    echo "  ⚠️  WARNING: AI enabled but only ${TOTAL_RAM_GB}GB RAM available"
    echo "     Recommended: 16GB+ for AI features"
    echo ""
    read -p "  Continue anyway? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "  Installation cancelled."
        exit 0
    fi
fi

# ============================================================
# STEP 5: DEPLOY PODS
# ============================================================

echo "[5/6] Deploying PODs..."
echo ""

deploy_pod_web        # Always
deploy_pod_database   # Always
deploy_pod_cache      # Always
deploy_pod_neuro      # Always (qsecbit + HTP)

if [ "$ENABLE_IAM" = true ]; then
    deploy_pod_iam
fi

if [ "$ENABLE_MONITORING" = true ]; then
    deploy_pod_monitoring
fi

if [ "$ENABLE_AI" = true ]; then
    deploy_pod_detection
    deploy_pod_ai
fi

echo ""
echo "  ✓ All PODs deployed successfully"

# ============================================================
# STEP 6: POST-INSTALL INSTRUCTIONS
# ============================================================

echo ""
echo "[6/6] Installation complete!"
echo ""
echo "============================================================"
echo "   HOOKPROBE EDGE NODE READY"
echo "============================================================"
echo ""
echo "Configuration:"
echo "  Platform:    $PLATFORM_ARCH on $PLATFORM_OS"
echo "  RAM:         ${TOTAL_RAM_GB}GB"
echo "  Qsecbit:     ✓ Enabled (quantum-resistant)"
echo "  HTP:         ✓ Enabled (adaptive transport)"
echo "  AI:          $([ "$ENABLE_AI" = true ] && echo "✓ Enabled" || echo "✗ Disabled")"
echo "  Monitoring:  $([ "$ENABLE_MONITORING" = true ] && echo "✓ Enabled" || echo "✗ Disabled")"
echo ""
echo "Next steps:"
echo "  1. Check status:  podman pod ls"
echo "  2. View logs:     podman logs -f hookprobe-web-django"
echo "  3. Access web:    http://localhost"
echo ""
echo "To enable AI later:  sudo bash $0 --enable-ai"
echo "To enable monitoring: sudo bash $0 --enable-monitoring"
echo ""
```

**New file: `scripts/lib/platform.sh`**

```bash
#!/bin/bash
#
# platform.sh - Platform Detection Library
#

detect_platform() {
    # Detect OS
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        PLATFORM_OS="$PRETTY_NAME"
    else
        PLATFORM_OS="Unknown Linux"
    fi

    # Detect architecture
    case "$(uname -m)" in
        x86_64|amd64)
            PLATFORM_ARCH="x86_64"
            ;;
        aarch64|arm64)
            PLATFORM_ARCH="ARM64"
            ;;
        armv7l)
            PLATFORM_ARCH="ARM32"
            ;;
        *)
            PLATFORM_ARCH="$(uname -m)"
            ;;
    esac

    # Detect total RAM in GB
    local ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    TOTAL_RAM_GB=$((ram_kb / 1024 / 1024))

    # Detect if Raspberry Pi
    IS_RASPBERRY_PI=false
    if [ -f /proc/device-tree/model ]; then
        local model=$(cat /proc/device-tree/model)
        if [[ "$model" == *"Raspberry Pi"* ]]; then
            IS_RASPBERRY_PI=true
        fi
    fi

    # Export for use by other scripts
    export PLATFORM_OS PLATFORM_ARCH TOTAL_RAM_GB IS_RASPBERRY_PI
}

check_cgroup_enabled() {
    # Check if cgroup memory controller is enabled
    if [ -f /sys/fs/cgroup/memory.max ]; then
        return 0  # Enabled
    else
        return 1  # Not enabled
    fi
}
```

**New file: `scripts/lib/instructions.sh`**

```bash
#!/bin/bash
#
# instructions.sh - Show user instructions when manual changes needed
#

show_cgroup_instructions() {
    cat << 'EOF'
┌────────────────────────────────────────────────────────────┐
│ RASPBERRY PI CGROUP CONFIGURATION REQUIRED                 │
└────────────────────────────────────────────────────────────┘

Raspberry Pi requires cgroup configuration for containers.

STEP 1: Edit boot configuration

  # For Raspberry Pi OS Bookworm (Debian 12+)
  sudo nano /boot/firmware/cmdline.txt

  # For older Raspberry Pi OS
  sudo nano /boot/cmdline.txt

STEP 2: Add these parameters to the EXISTING line
        (Do NOT create a new line)

  cgroup_enable=cpuset cgroup_enable=memory cgroup_memory=1

EXAMPLE:

  Before:
  console=serial0,115200 root=PARTUUID=12345-02 rootwait

  After:
  console=serial0,115200 root=PARTUUID=12345-02 rootwait cgroup_enable=cpuset cgroup_enable=memory cgroup_memory=1

STEP 3: Save and reboot

  sudo reboot

STEP 4: Verify (after reboot)

  cat /proc/cgroups | grep memory
  # Should show: memory ... 1

  ls /sys/fs/cgroup/memory.max
  # Should exist without errors

EOF
}
```

---

### Phase 3: Simplify Main Menu

**Update `install.sh` to use new unified installer:**

```bash
show_deployment_menu() {
    echo "Select Deployment Mode:"
    echo ""
    echo "  1) Edge Node - Qsecbit only (DEFAULT) [4GB+ RAM]"
    echo "     └─ Optional: --enable-ai, --enable-monitoring"
    echo ""
    echo "  2) Cloud/MSSP - Multi-tenant [64GB+ RAM]"
    echo "  3) Validator - Consensus node [8GB+ RAM]"
    echo ""

    read -p "Select option: " choice

    case $choice in
        1)
            echo ""
            echo "Edge installation options:"
            echo "  a) Standard (qsecbit only)"
            echo "  b) With AI detection and monitoring"
            echo ""
            read -p "Select: " edge_choice
            case $edge_choice in
                a) bash scripts/install-edge.sh ;;
                b) bash scripts/install-edge.sh --enable-ai --enable-monitoring ;;
                *) echo "Invalid option" ;;
            esac
            ;;
        2) bash scripts/install-cloud.sh ;;
        3) bash scripts/install-validator.sh ;;
        *) echo "Invalid option" ;;
    esac
}
```

**Key Point**: No configuration files needed! Everything is auto-detected and adjusted in the script.

---

## 🚀 New Installation Flow (Simplified)

### User Experience

```bash
# Install HookProbe Edge (DEFAULT: qsecbit only, auto-detects platform)
sudo ./install.sh

# Main Menu:
# 1) Edge Node - Qsecbit only [DEFAULT] [4GB+ RAM]
#    ├─ Auto-detects: x86_64, ARM64, Raspberry Pi
#    ├─ Auto-adjusts: Memory limits based on RAM
#    └─ Optional: --enable-ai, --enable-monitoring
#
# 2) Cloud/MSSP - Multi-tenant [64GB+ RAM]
# 3) Validator - Byzantine consensus node [8GB+ RAM]
```

**Direct installation (bypassing menu):**
```bash
# Standard edge (qsecbit only, auto-detects everything)
sudo bash scripts/install-edge.sh

# Edge with AI and monitoring
sudo bash scripts/install-edge.sh --enable-ai --enable-monitoring

# Edge without IAM (if you don't need authentication)
sudo bash scripts/install-edge.sh --disable-iam
```

**What gets auto-detected:**
- ✅ Operating system (RHEL, Debian, Ubuntu, Raspberry Pi OS)
- ✅ Architecture (x86_64, ARM64, ARM32)
- ✅ Total RAM (adjusts memory limits automatically)
- ✅ Raspberry Pi detection (enables cgroup check)
- ✅ Disk space (validates 20GB+ available)

---

## 📦 Files to DELETE

### Immediate Deletion (Broken/Duplicated)

```bash
# Testing directory (broken, ~1,000 lines)
install/testing/README.md               # 390 lines of obsolete instructions
install/testing/lightweight-setup.sh    # 600+ lines of broken code
install/testing/lightweight-config.sh   # 200+ lines of duplicate config

# Duplicated edge setup (merge into scripts/install-edge.sh)
install/edge/setup.sh                   # 2,000+ lines → merge
install/edge/config.sh                  # 500+ lines → merge into lib/platform.sh

# Duplicated validator install (move to scripts/)
install-validator.sh                    # Move to scripts/install-validator.sh

# Obsolete documentation (merge into docs/installation/)
install/edge/checklist.md               # Merge into INSTALLATION.md
install/edge/QUICK-START.md             # Merge into QUICK-START.md

# Total deleted: ~3,700 lines of duplicated/broken code
```

### Files to KEEP (but reorganize)

```bash
# Move to scripts/lib/ (renamed from utils/)
install/edge/hookprobe-bootstrap.sh → scripts/lib/bootstrap.sh
install/edge/hookprobe-ctl → scripts/lib/hookprobe-ctl
install/edge/provision.sh → scripts/lib/provision.sh
install/edge/update.sh → scripts/lib/update.sh
install/edge/cleanup.sh → scripts/lib/cleanup.sh
install/edge/uninstall.sh → scripts/lib/uninstall.sh

# Move systemd services
install/edge/systemd/*.service → systemd/edge/

# Keep common utilities
install/common/ → scripts/lib/common/
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

Edge Options: 1 (all or nothing)
- Full edge only (includes AI, requires 16GB)
- No qsecbit-only option

Raspberry Pi Support: Partial (only in testing, broken)
Platform Detection: None (user must know their system)
Memory Limits: Fixed (doesn't adjust to available RAM)
User Instructions: None (fails silently on Raspberry Pi)

Lines of Code: ~3,700 (duplicated across 3 scripts)
```

### After (Proposed - Clean)

```
Installation Paths: 1 (clear)
- install.sh → scripts/install-edge.sh (one smart script)

Edge Options: Simple flags
- DEFAULT: Qsecbit only, no AI [4GB+]
- --enable-ai: Add detection and AI
- --enable-monitoring: Add Grafana/metrics
- --disable-iam: Remove authentication

Raspberry Pi Support: Full (auto-detected, built-in)
Platform Detection: Automatic (OS, arch, RAM, RPi)
Memory Limits: Dynamic (adjusts to available RAM)
User Instructions: Clear (shows exactly what to modify)

Lines of Code: ~800 (one unified script + libs)
Code Reduction: 79% less code (3,700 → 800 lines)
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

1. ✅ **Single installation command**: `sudo ./install.sh` works for all platforms
2. ✅ **Auto-detection**: Platform, RAM, Raspberry Pi detected automatically
3. ✅ **Dynamic adjustment**: Memory limits scale with available RAM
4. ✅ **Clear instructions**: If manual change needed (cgroup), show exact steps
5. ✅ **Qsecbit-only default**: NO AI by default (user must opt-in with --enable-ai)
6. ✅ **Raspberry Pi support**: Built-in detection, cgroup validation, memory limits
7. ✅ **No broken code**: Delete install/testing/ (doesn't work)
8. ✅ **Less code**: Reduce from ~3,700 to ~800 lines (79% reduction)
9. ✅ **Simple flags**: --enable-ai, --enable-monitoring, --disable-iam
10. ✅ **Better UX**: "Which script?" → ONE script, auto-detects everything

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
