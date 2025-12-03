# Installation Cleanup Summary

**Date**: 2025-12-03
**Purpose**: Remove obsolete installation files replaced by unified installer

## Unified Installer (NEW)

Created files that replace fragmented installation:

```
scripts/install-edge.sh          ✅ NEW - Main unified installer
scripts/lib/platform.sh          ✅ NEW - Platform detection
scripts/lib/requirements.sh      ✅ NEW - System validation
scripts/lib/instructions.sh      ✅ NEW - User instructions
```

**Key features**:
- Auto-detects OS, RAM, Raspberry Pi model
- Dynamic memory limits (4GB/8GB/16GB+ profiles)
- Simple flags: `--enable-ai`, `--enable-monitoring`, `--disable-iam`
- Default: Qsecbit enabled, NO AI
- Target: Raspberry Pi 4B (4GB RAM, 32GB storage)

---

## Files to REMOVE

### 1. `install/testing/` Directory (44K) - DELETED ✓

**Reason**: Broken lightweight testing setup, replaced by unified installer

**Files removed**:
- `install/testing/lightweight-setup.sh` (setup script)
- `install/testing/lightweight-config.sh` (config)
- `install/testing/README.md` (documentation)

**Replacement**: `scripts/install-edge.sh` (default installation)

---

### 2. `install/edge/setup.sh` (67K) - DELETED ✓

**Reason**: Old edge setup script, replaced by unified installer

**Replacement**: `scripts/install-edge.sh`

---

### 3. `install/edge/config.sh` (20K) - DELETED ✓

**Reason**: Old static configuration, replaced by auto-detection

**Replacement**: `scripts/lib/platform.sh` (auto-detects everything)

---

### 4. `install/common/` Directory (61K) - DELETED ✓

**Reason**: Old configuration wizards, replaced by library files

**Files removed**:
- `install/common/config-wizard.sh` (21K) - old wizard
- `install/common/unified-config.sh` (19K) - old unified config
- `install/common/pre-install-check.sh` (11K) - old checks
- `install/common/README.md` (6.5K) - documentation

**Replacement**:
- `scripts/lib/requirements.sh` (system validation)
- `scripts/lib/platform.sh` (auto-detection)

---

## Files to KEEP

### 1. `install/edge/` - PARTIAL KEEP

**Keep these files** (may be useful):
- `uninstall.sh` - Uninstall old installations
- `cleanup.sh` - Cleanup utilities
- `update.sh` - Update scripts
- `hookprobe-ctl` - Control script
- `hookprobe-bootstrap.sh` - Bootstrap script
- `provision.sh` - Provisioning
- `systemd/` - Service files
- `README.md`, `QUICK-START.md`, `checklist.md` - Documentation

**Remove**:
- `setup.sh` (replaced by unified installer)
- `config.sh` (replaced by auto-detection)

---

### 2. `install/cloud/` - KEEP ENTIRELY ✓

**Reason**: MSSP/cloud deployment (different use case)

**Keep all files**:
- `setup.sh` - Cloud setup
- `config.sh` - Cloud configuration
- `uninstall.sh` - Cloud uninstall
- `README.md` - Cloud documentation

---

### 3. `install/addons/` - KEEP ENTIRELY ✓

**Reason**: Optional add-ons (n8n, webserver, LTE)

**Keep all subdirectories**:
- `n8n/` - Workflow automation
- `webserver/` - Web server addons
- `lte/` - LTE/5G connectivity

---

### 4. `install/scripts/` - KEEP ENTIRELY ✓

**Reason**: Validation scripts still referenced

**Keep**:
- `validate-config.sh`
- `README.md`

---

## Space Saved

**Before cleanup**:
- `install/testing/`: 44K
- `install/edge/setup.sh`: 67K
- `install/edge/config.sh`: 20K
- `install/common/`: 61K
- **Total**: ~192K

**After cleanup**: ~192K space saved

---

## Migration Path

### Old Installation (OBSOLETE)
```bash
# Option 1: Testing
cd install/testing
sudo bash lightweight-setup.sh

# Option 2: Edge
cd install/edge
sudo bash setup.sh
```

### New Installation (CURRENT)
```bash
# Default: Qsecbit only
sudo bash scripts/install-edge.sh

# With AI
sudo bash scripts/install-edge.sh --enable-ai

# With monitoring
sudo bash scripts/install-edge.sh --enable-monitoring
```

---

## Verification

After cleanup, verify:

```bash
# Check unified installer exists
ls -lh scripts/install-edge.sh
ls -lh scripts/lib/*.sh

# Check old files removed
ls install/testing/          # Should not exist
ls install/edge/setup.sh     # Should not exist
ls install/edge/config.sh    # Should not exist
ls install/common/           # Should not exist

# Check kept files
ls install/cloud/            # Should exist (MSSP)
ls install/addons/           # Should exist (add-ons)
ls install/edge/uninstall.sh # Should exist (cleanup)
```

---

## Next Steps

1. ✅ Remove obsolete files (completed)
2. ⏳ Update `install.sh` to call unified installer
3. ⏳ Test unified installer on Raspberry Pi 4B
4. ⏳ Update documentation to reference new installer

---

**Summary**: Removed 4 obsolete installation paths (~192K), replaced with ONE unified installer (~32K). Simplified installation from multiple confusing scripts to one clear command.
