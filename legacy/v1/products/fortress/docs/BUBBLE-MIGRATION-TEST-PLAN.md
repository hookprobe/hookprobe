# Bubble Management Migration Test Plan

## Terminology: Device Groups vs D2D Bubbles

> **IMPORTANT**: As of v5.5, we distinguish between two independent concepts:
>
> | Concept | Description | UI Location |
> |---------|-------------|-------------|
> | **Device Groups** | Manual CRUD for user-organized device grouping with OpenFlow policies. Users create, edit, delete groups and assign devices manually. | Web UI → Device Groups |
> | **D2D Bubbles** | Background algorithm for automatic device relationship detection/coloring based on network traffic patterns. Devices that communicate frequently are colored similarly. | Background (AIOCHI) |
>
> The "bubble" code in `shared/aiochi/bubble/` and `products/fortress/lib/` is primarily for **D2D bubble coloring**.
> The "Device Groups" UI (formerly "Device Bubbles") manages user-created groups with network policies.
> These systems are INDEPENDENT - a device can be in a "Work" group but colored the same as "Dad's iPhone" based on D2D traffic.

## Overview

This document outlines the end-to-end test plan for the unified bubble management architecture migration from `products/fortress/lib/` to `shared/aiochi/bubble/`.

## Architecture Summary

### New Unified Module (`shared/aiochi/bubble/`)
- `types.py` - BubbleType, NetworkPolicy, Bubble dataclass, POLICY_INFO
- `policy_resolver.py` - Maps bubbles to OpenFlow with device overrides
- `manager.py` - EcosystemBubbleManager wrapper

### Legacy Files (to be cleaned up)
| File | Status | Action |
|------|--------|--------|
| `fortress/lib/ecosystem_bubble.py` | Duplicate | Keep as fallback, mark deprecated |
| `fortress/lib/device_policies.py` | Duplicate NetworkPolicy | Update to import from unified |
| `fortress/lib/network_policy_manager.py` | Uses local types | Update imports |
| `fortress/web/modules/bubbles/views.py` | Duplicate BubbleType | Update imports |
| `fortress/lib/presence_sensor.py` | Helper module | Keep, may import unified types |
| `fortress/lib/behavior_clustering.py` | Helper module | Keep |
| `fortress/lib/connection_graph.py` | Helper module | Keep |

---

## Test Checklist

### 1. Module Import Tests
```bash
# Run from hookprobe root directory
```

- [ ] **1.1** Unified bubble types import
  ```python
  from shared.aiochi.bubble import BubbleType, NetworkPolicy, Bubble
  ```

- [ ] **1.2** Policy resolver import
  ```python
  from shared.aiochi.bubble import get_policy_resolver, PolicyResolver
  ```

- [ ] **1.3** Bubble manager import
  ```python
  from shared.aiochi.bubble import get_bubble_manager, EcosystemBubbleManager
  ```

- [ ] **1.4** AIOCHI top-level imports
  ```python
  from shared.aiochi import BubbleType, NetworkPolicy, get_bubble_manager
  ```

- [ ] **1.5** Fortress lib shim imports
  ```python
  from products.fortress.lib import get_ecosystem_bubble_manager, get_policy_resolver
  ```

### 2. Policy Resolution Chain Tests

- [ ] **2.1** Device with no override → uses bubble default
  - FAMILY bubble → SMART_HOME policy
  - Priority: 600

- [ ] **2.2** Device with override → uses override
  - Dad in FAMILY → FULL_ACCESS override
  - Priority: 900

- [ ] **2.3** Unknown device (no bubble) → QUARANTINE
  - Priority: 1000+

- [ ] **2.4** Clear override → falls back to bubble default

- [ ] **2.5** Multiple devices in same bubble with different overrides
  - Dad: FULL_ACCESS
  - Mom: SMART_HOME (default)
  - Kids: LAN_ONLY (grounded)

### 3. OpenFlow/NAC Policy Sync Tests

- [ ] **3.1** Shell script syntax validation
  ```bash
  bash -n products/fortress/devices/common/nac-policy-sync.sh
  ```

- [ ] **3.2** Priority offset calculation
  - Default mode: priorities 600-850
  - Override mode: priorities 900-1150 (+300 offset)

- [ ] **3.3** Policy application (dry run)
  ```bash
  # Test each policy type
  apply_policy "AA:BB:CC:DD:EE:FF" "quarantine"
  apply_policy "AA:BB:CC:DD:EE:FF" "lan_only"
  apply_policy "AA:BB:CC:DD:EE:FF" "internet_only"
  apply_policy "AA:BB:CC:DD:EE:FF" "full_access"
  ```

### 4. Database Tests

- [ ] **4.1** Bubble database schema
  - Path: `/var/lib/hookprobe/bubbles.db`
  - Tables: `bubbles`, `bubble_devices`

- [ ] **4.2** Autopilot database policy columns
  - Path: `/var/lib/hookprobe/autopilot.db`
  - Table: `device_identity`
  - Column: `policy_override`

- [ ] **4.3** Policy resolution persistence
  - Table: `policy_resolutions`

### 5. Web UI Integration Tests

- [ ] **5.1** Dashboard loads without import errors
- [ ] **5.2** Bubbles page displays correctly
- [ ] **5.3** SDN/Policy page functions
- [ ] **5.4** AIOCHI page bubble management works
- [ ] **5.5** Device policy override UI

### 6. Trigger File Communication Tests

- [ ] **6.1** Policy trigger file
  - Path: `/opt/hookprobe/fortress/data/.nac_policy_sync`
  - Format: JSON with `mac`, `policy`, `timestamp`

- [ ] **6.2** Bubble SDN trigger file
  - Path: `/opt/hookprobe/fortress/data/.bubble_sdn_sync`
  - Format: JSON with `rules` array

- [ ] **6.3** Policy resolution file
  - Path: `/opt/hookprobe/fortress/data/.policy_resolutions`

### 7. End-to-End Flow Tests

- [ ] **7.1** New device joins network
  1. DHCP assigns IP
  2. Device detected (unknown) → QUARANTINE
  3. AI identifies device type
  4. Device assigned to bubble
  5. Bubble default policy applied
  6. OpenFlow rules updated

- [ ] **7.2** User manually moves device to bubble
  1. UI action: move device
  2. Bubble membership updated
  3. Policy recalculated
  4. OpenFlow rules updated
  5. n8n webhook triggered (if configured)

- [ ] **7.3** User sets device override
  1. UI action: set policy override
  2. Override stored in database
  3. Higher priority OpenFlow rules applied
  4. Device uses override, not bubble default

---

## Cleanup Tasks

### Files to Update (import unified types)
1. `products/fortress/lib/device_policies.py`
2. `products/fortress/lib/network_policy_manager.py`
3. `products/fortress/web/modules/bubbles/views.py`
4. `products/fortress/web/modules/sdn/views.py`

### Files to Mark as Deprecated (keep as fallback)
1. `products/fortress/lib/ecosystem_bubble.py`

### Files to Keep (helper modules)
1. `products/fortress/lib/presence_sensor.py`
2. `products/fortress/lib/behavior_clustering.py`
3. `products/fortress/lib/connection_graph.py`
4. `products/fortress/lib/clickhouse_graph.py`
5. `products/fortress/lib/n8n_webhook.py`
6. `products/fortress/lib/reinforcement_feedback.py`

---

## Test Commands

```bash
# 1. Syntax validation
python3 -m py_compile shared/aiochi/bubble/*.py
bash -n products/fortress/devices/common/nac-policy-sync.sh

# 2. Import tests
python3 -c "from shared.aiochi.bubble import BubbleType, NetworkPolicy; print('OK')"

# 3. Functional tests
python3 -c "
from shared.aiochi.bubble import get_policy_resolver, BubbleType, NetworkPolicy, Bubble
resolver = get_policy_resolver()
bubble = Bubble(bubble_id='test', name='Test', bubble_type=BubbleType.FAMILY, devices=['AA:BB:CC:DD:EE:FF'])
resolver.update_bubble(bubble)
res = resolver.resolve('AA:BB:CC:DD:EE:FF', bubble)
print(f'Policy: {res.effective_policy.value}, Priority: {res.openflow_priority}')
"

# 4. Fortress lib shim test
python3 -c "
import sys
sys.path.insert(0, '/home/user/hookprobe')
from products.fortress.lib import get_policy_resolver
print('Fortress shim works:', get_policy_resolver)
"
```

---

## Expected Test Results

| Test | Expected Result |
|------|-----------------|
| Import unified types | ✓ No errors |
| FAMILY bubble default | SMART_HOME (priority 600) |
| Device override | Uses override (priority 900) |
| Unknown device | QUARANTINE (priority 1000+) |
| Shell syntax | Valid bash |
| Web UI loads | No import errors |
