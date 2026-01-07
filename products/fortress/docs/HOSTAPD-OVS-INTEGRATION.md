# hostapd-ovs Integration Architecture

**Version**: 1.0.0
**Status**: Design Complete
**Last Updated**: 2026-01-07

## Executive Summary

This document outlines the complete migration from traditional hostapd (with br-wifi Linux bridge) to **hostapd-ovs** (direct OVS integration) for the Fortress product. It addresses three critical issues:

1. **MAC Randomization Device Tracking** - Stop device name incrementing ("iPhone 3, 4, 5...")
2. **Cross-Band D2D Communication** - Ensure mDNS/multicast flows between 2.4GHz and 5GHz
3. **Policy-Based Isolation** - Devices in same policy CAN discover each other, different policies CANNOT

---

## Problem Statement

### Issue 1: MAC Randomization Causes Device Incrementing

**Symptom**: "Andrei's iPhone" becomes "Andrei's iPhone 3", "Andrei's iPhone 4", etc.

**Root Cause**:
- Device Manager uses MAC address as PRIMARY KEY
- Apple/Android devices randomize MAC every 30-60 minutes
- Each new MAC creates a NEW database entry
- No linking between old and new MACs

**Available Persistent Identifiers (NOT currently used for linking)**:

| Identifier | Persistence | Reliability | Current Use |
|------------|-------------|-------------|-------------|
| DHCP Option 55 | Stable across MACs | 8/10 | Fingerbank lookup only |
| mDNS Device Name | "John's iPhone" stays same | 9/10 | Display name only |
| mDNS Hostname | "Johns-iPhone.local" | 9/10 | Not indexed |
| Fingerbank Device Type | Stays same | 8/10 | Classification only |

### Issue 2: Cross-Band mDNS/Multicast Gaps

**Current Architecture** (br-wifi mode):
```
wlan_24ghz ──┐
              ├── br-wifi (Linux bridge) ── veth-wifi-a ── veth-wifi-b ── OVS(FTS)
wlan_5ghz ──┘
```

**With hostapd-ovs** (direct mode):
```
wlan_24ghz ── OVS(FTS) ── OpenFlow rules
wlan_5ghz  ── OVS(FTS) ── OpenFlow rules
```

**Gap**: When WiFi interfaces connect directly to OVS (no br-wifi), multicast/mDNS does NOT automatically bridge between bands because:
1. OVS uses L2 MAC learning per-port
2. Multicast must be explicitly flooded to target ports
3. No hairpin mode available (that's a Linux bridge feature)

### Issue 3: Policy-Based D2D Rules Missing

**Current OpenFlow Priorities**:

| Priority | Rule | Status |
|----------|------|--------|
| 850 | INTERNET_ONLY blocks mDNS | ✅ |
| 800 | Base mDNS allow | ✅ |
| 700 | IPv4/IPv6 Multicast allow | ✅ |
| 500 | LAN allow | ✅ |
| 450 | Bubble D2D allow | ✅ |
| 0 | Default NORMAL | ✅ |

**Gap**: No rules for:
- **Priority 475**: Same-policy mDNS discovery (SMART_HOME ↔ SMART_HOME)
- **Priority 400**: Cross-band multicast reflection (2.4GHz ↔ 5GHz)

---

## Solution Architecture

### Solution 1: Device Identity Layer

Add a new database schema that links MACs to persistent identities:

```sql
-- New table: Device Identities (persistent across MAC changes)
CREATE TABLE device_identities (
    identity_id     TEXT PRIMARY KEY,  -- UUID
    canonical_name  TEXT UNIQUE,       -- "John's iPhone" (from mDNS)
    mdns_device_id  TEXT,              -- Bonjour device ID
    dhcp_option55   TEXT,              -- DHCP fingerprint (most reliable)
    fingerbank_id   INTEGER,           -- Device type classification
    current_mac     TEXT,              -- Most recent MAC address
    all_macs        TEXT,              -- JSON array of historical MACs
    bubble_id       TEXT,              -- Ecosystem bubble assignment
    policy          TEXT,              -- Network policy
    first_seen      TEXT,              -- ISO timestamp
    last_seen       TEXT               -- ISO timestamp
);
CREATE INDEX idx_identities_mdns ON device_identities(mdns_device_id);
CREATE INDEX idx_identities_dhcp ON device_identities(dhcp_option55);
CREATE INDEX idx_identities_mac ON device_identities(current_mac);

-- New table: MAC to Identity mapping
CREATE TABLE mac_to_identity (
    mac             TEXT PRIMARY KEY,  -- MAC address
    identity_id     TEXT NOT NULL,     -- Links to device_identities
    assigned_at     TEXT,              -- When this MAC was first seen
    dhcp_option55   TEXT,              -- Captured at DHCP time
    FOREIGN KEY (identity_id) REFERENCES device_identities(identity_id)
);
CREATE INDEX idx_mac_identity ON mac_to_identity(identity_id);
```

**Identity Resolution Algorithm**:
```python
def find_or_create_identity(mac: str, dhcp_option55: str, mdns_name: str) -> Identity:
    """
    Link a MAC address to a persistent device identity.
    Uses multiple signals to track device across MAC randomization.

    Priority order:
    1. mDNS name match (e.g., "John's iPhone")
    2. DHCP Option 55 fingerprint match
    3. Create new identity
    """
    # Step 1: Check if MAC already linked
    existing = db.query("SELECT identity_id FROM mac_to_identity WHERE mac = ?", mac)
    if existing:
        identity = db.get_identity(existing.identity_id)
        identity.update_last_seen()
        return identity

    # Step 2: Try to find existing identity by mDNS name
    if mdns_name:
        identity = db.query("SELECT * FROM device_identities WHERE canonical_name = ?", mdns_name)
        if identity:
            # Same device, new MAC - link it
            db.execute("INSERT INTO mac_to_identity VALUES (?, ?, ?, ?)",
                       mac, identity.identity_id, datetime.now(), dhcp_option55)
            identity.current_mac = mac
            identity.all_macs = json.loads(identity.all_macs or '[]') + [mac]
            identity.update_last_seen()
            log.info(f"Linked new MAC {mac} to existing identity '{mdns_name}'")
            return identity

    # Step 3: Try to find existing identity by DHCP fingerprint
    if dhcp_option55:
        identity = db.query("SELECT * FROM device_identities WHERE dhcp_option55 = ?", dhcp_option55)
        if identity:
            # Same device type with same fingerprint - likely same device
            db.execute("INSERT INTO mac_to_identity VALUES (?, ?, ?, ?)",
                       mac, identity.identity_id, datetime.now(), dhcp_option55)
            identity.current_mac = mac
            identity.all_macs = json.loads(identity.all_macs or '[]') + [mac]
            identity.update_last_seen()
            log.info(f"Linked new MAC {mac} to identity via DHCP fingerprint")
            return identity

    # Step 4: Truly new device - create identity
    identity_id = str(uuid.uuid4())
    db.execute("""
        INSERT INTO device_identities
        (identity_id, canonical_name, dhcp_option55, current_mac, all_macs, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, identity_id, mdns_name or f"Device-{mac[-5:]}", dhcp_option55, mac,
         json.dumps([mac]), datetime.now(), datetime.now())

    db.execute("INSERT INTO mac_to_identity VALUES (?, ?, ?, ?)",
               mac, identity_id, datetime.now(), dhcp_option55)

    log.info(f"Created new identity for MAC {mac}")
    return db.get_identity(identity_id)
```

### Solution 2: Cross-Band Multicast Reflection

When using hostapd-ovs, add explicit OpenFlow rules for multicast bridging:

```bash
# Get OVS port numbers for WiFi interfaces
get_wifi_ports() {
    WIFI_24_PORT=$(ovs-vsctl get interface wlan_24ghz ofport 2>/dev/null || echo "")
    WIFI_5_PORT=$(ovs-vsctl get interface wlan_5ghz ofport 2>/dev/null || echo "")
}

# Apply cross-band multicast reflection rules
apply_multicast_reflection() {
    get_wifi_ports

    if [ -z "$WIFI_24_PORT" ] || [ -z "$WIFI_5_PORT" ]; then
        log_warn "WiFi ports not ready for multicast reflection"
        return 1
    fi

    log_info "Setting up cross-band multicast reflection (ports $WIFI_24_PORT ↔ $WIFI_5_PORT)"

    # Priority 400: Multicast bridging between WiFi bands
    # This ensures mDNS/SSDP reaches devices on both bands

    # IPv4 mDNS (224.0.0.251:5353) - Bonjour/Zeroconf
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "priority=400,udp,in_port=$WIFI_24_PORT,nw_dst=224.0.0.251,tp_dst=5353,actions=output:$WIFI_5_PORT,NORMAL"
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "priority=400,udp,in_port=$WIFI_5_PORT,nw_dst=224.0.0.251,tp_dst=5353,actions=output:$WIFI_24_PORT,NORMAL"

    # IPv6 mDNS (ff02::fb) - HomeKit, AirPlay, Matter
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "priority=400,udp6,in_port=$WIFI_24_PORT,ipv6_dst=ff02::fb,tp_dst=5353,actions=output:$WIFI_5_PORT,NORMAL"
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "priority=400,udp6,in_port=$WIFI_5_PORT,ipv6_dst=ff02::fb,tp_dst=5353,actions=output:$WIFI_24_PORT,NORMAL"

    # SSDP/UPnP (239.255.255.250:1900) - Chromecast, Roku, smart TVs
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "priority=400,udp,in_port=$WIFI_24_PORT,nw_dst=239.255.255.250,tp_dst=1900,actions=output:$WIFI_5_PORT,NORMAL"
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "priority=400,udp,in_port=$WIFI_5_PORT,nw_dst=239.255.255.250,tp_dst=1900,actions=output:$WIFI_24_PORT,NORMAL"

    # IPv6 All-Nodes multicast (ff02::1) - NDP, router advertisements
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "priority=400,ipv6,in_port=$WIFI_24_PORT,ipv6_dst=ff02::1,actions=output:$WIFI_5_PORT,NORMAL"
    ovs-ofctl add-flow "$OVS_BRIDGE" \
        "priority=400,ipv6,in_port=$WIFI_5_PORT,ipv6_dst=ff02::1,actions=output:$WIFI_24_PORT,NORMAL"

    log_success "Cross-band multicast reflection configured"
}
```

### Solution 3: Policy-Aware mDNS Rules

Update `nac-policy-sync.sh` to add policy-specific mDNS rules:

```bash
# NEW: Apply SMART_HOME mDNS discovery rules
apply_smart_home_mdns() {
    local mac="$1"

    # Priority 475: Allow mDNS for SMART_HOME devices
    # This is between INTERNET_ONLY block (850) and base allow (800)
    # Ensures smart home devices can discover each other

    # Allow mDNS queries FROM this device
    add_flow "priority=475,udp,dl_src=$mac,tp_dst=5353,actions=NORMAL"
    add_flow "priority=475,udp6,dl_src=$mac,tp_dst=5353,actions=NORMAL"

    # Allow mDNS responses TO this device
    add_flow "priority=475,udp,dl_dst=$mac,tp_src=5353,actions=NORMAL"
    add_flow "priority=475,udp6,dl_dst=$mac,tp_src=5353,actions=NORMAL"

    log_info "Applied SMART_HOME mDNS discovery rules for $mac"
}

# NEW: Apply LAN_ONLY mDNS discovery rules (same as SMART_HOME)
apply_lan_only_mdns() {
    local mac="$1"

    # Allow mDNS for LAN_ONLY devices (IoT, cameras, printers)
    add_flow "priority=475,udp,dl_src=$mac,tp_dst=5353,actions=NORMAL"
    add_flow "priority=475,udp6,dl_src=$mac,tp_dst=5353,actions=NORMAL"
    add_flow "priority=475,udp,dl_dst=$mac,tp_src=5353,actions=NORMAL"
    add_flow "priority=475,udp6,dl_dst=$mac,tp_src=5353,actions=NORMAL"

    log_info "Applied LAN_ONLY mDNS discovery rules for $mac"
}

# Updated apply_policy function
apply_policy() {
    local mac="$1"
    local policy="$2"
    local priority_mode="${3:-default}"

    # ... existing code ...

    case "$policy" in
        smart_home)
            # SMART_HOME: Full access + explicit mDNS allow
            apply_smart_home_mdns "$mac"
            log_info "Applied SMART_HOME policy for $mac (full access + mDNS)"
            ;;

        lan_only)
            # LAN_ONLY: Add mDNS rules before LAN block rules
            apply_lan_only_mdns "$mac"
            # ... existing LAN_ONLY rules ...
            ;;

        internet_only)
            # INTERNET_ONLY: mDNS is BLOCKED (priority 850)
            # No change needed - existing rules work
            ;;
    esac
}
```

---

## Complete OpenFlow Priority Hierarchy

After implementing all solutions:

```
PRIORITY   RULE TYPE                           POLICY
────────────────────────────────────────────────────────
1001       QUARANTINE DHCP/DNS/ARP allow       Quarantine
1000       QUARANTINE IP drop                  Quarantine
999        QUARANTINE L2 drop                  Quarantine
────────────────────────────────────────────────────────
950        Device override + 300               All (override mode)
────────────────────────────────────────────────────────
850        INTERNET_ONLY mDNS block            Internet Only
800        INTERNET_ONLY DHCP/DNS/ARP allow    Internet Only
750        INTERNET_ONLY containers block      Internet Only
700        INTERNET_ONLY LAN block             Internet Only
650        INTERNET_ONLY internet allow        Internet Only
────────────────────────────────────────────────────────
750        LAN_ONLY gateway allow              LAN Only
730        LAN_ONLY containers block           LAN Only
720        LAN_ONLY D2D allow                  LAN Only
600        LAN_ONLY internet block             LAN Only
────────────────────────────────────────────────────────
500        Base LAN + mDNS + containers        Full Access/Smart Home
────────────────────────────────────────────────────────
475        SMART_HOME/LAN_ONLY mDNS allow      NEW! (per-device)
────────────────────────────────────────────────────────
450        BUBBLE D2D allow                    All (intra-bubble)
────────────────────────────────────────────────────────
400        CROSS-BAND MULTICAST REFLECTION     NEW! (global)
────────────────────────────────────────────────────────
0          Default NORMAL                      Fallback
────────────────────────────────────────────────────────
```

---

## D2D Communication Matrix

| Source Policy | Dest Policy | mDNS Discovery | IP D2D Traffic |
|---------------|-------------|----------------|----------------|
| SMART_HOME | SMART_HOME | ✅ Allowed (475) | ✅ Base allow (500) |
| SMART_HOME | LAN_ONLY | ✅ Allowed (475) | ✅ Base allow (500) |
| SMART_HOME | INTERNET_ONLY | ❌ Blocked (850) | ❌ Blocked (700) |
| SMART_HOME | FULL_ACCESS | ✅ Allowed (475) | ✅ Base allow (500) |
| LAN_ONLY | LAN_ONLY | ✅ Allowed (475) | ✅ D2D allow (720) |
| LAN_ONLY | INTERNET_ONLY | ❌ Blocked (850) | ❌ Blocked (700) |
| INTERNET_ONLY | INTERNET_ONLY | ❌ Blocked (850) | ❌ Blocked (700) |
| INTERNET_ONLY | Any | ❌ Blocked (850) | ❌ Blocked (700) |
| Same Bubble | Same Bubble | ✅ Bubble D2D (450) | ✅ Bubble D2D (450) |

---

## Implementation Checklist

### Phase 1: Device Identity Layer
- [ ] Create `device_identities` and `mac_to_identity` tables
- [ ] Modify `device_manager.py` to use identity linking
- [ ] Modify DHCP hook to capture Option 55 fingerprint
- [ ] Modify mDNS resolver to extract device ID/name
- [ ] Update Web UI to show single device with MAC history

### Phase 2: Cross-Band Multicast (hostapd-ovs mode)
- [ ] Add `apply_multicast_reflection()` to `ovs-post-setup.sh`
- [ ] Detect hostapd-ovs mode from `/etc/hookprobe/fortress.conf`
- [ ] Apply multicast rules only when `HOSTAPD_OVS_MODE=true`
- [ ] Test mDNS discovery between 2.4GHz and 5GHz devices

### Phase 3: Policy-Aware mDNS
- [ ] Add `apply_smart_home_mdns()` to `nac-policy-sync.sh`
- [ ] Add `apply_lan_only_mdns()` to `nac-policy-sync.sh`
- [ ] Update `apply_policy()` to call mDNS functions
- [ ] Test HomeKit discovery between SMART_HOME devices

### Phase 4: Testing & Validation
- [ ] Test MAC randomization tracking (iPhone, Android)
- [ ] Test cross-band AirPlay (iPhone on 5GHz → HomePod on 2.4GHz)
- [ ] Test policy isolation (Guest → Smart Home = blocked)
- [ ] Test same-policy discovery (Smart Home ↔ Smart Home = allowed)
- [ ] Performance benchmark (latency, throughput)

---

## Rollback Plan

If issues occur, rollback by:

1. **Revert to br-wifi mode**:
   ```bash
   # Set mode in fortress.conf
   sed -i 's/HOSTAPD_OVS_MODE=true/HOSTAPD_OVS_MODE=false/' /etc/hookprobe/fortress.conf

   # Use standard hostapd
   systemctl restart fts-hostapd-24ghz fts-hostapd-5ghz
   ```

2. **Remove new OpenFlow rules**:
   ```bash
   # Remove multicast reflection rules
   ovs-ofctl del-flows FTS "priority=400"

   # Remove policy mDNS rules
   ovs-ofctl del-flows FTS "priority=475"
   ```

3. **Restore device database**:
   ```bash
   # Backup current, restore previous
   cp /var/lib/hookprobe/devices.db /var/lib/hookprobe/devices.db.new
   cp /var/lib/hookprobe/devices.db.bak /var/lib/hookprobe/devices.db
   ```

---

## References

- [hostapd-ovs Build Script](../../../shared/hostapd-ovs/build-hostapd-ovs.sh)
- [hostapd-ovs README](../../../shared/hostapd-ovs/README.md)
- [OVS Post-Setup Script](../devices/common/ovs-post-setup.sh)
- [NAC Policy Sync Script](../devices/common/nac-policy-sync.sh)
- [Ecosystem Bubble Manager](../lib/ecosystem_bubble.py)
- [Device Manager](../lib/device_manager.py)
