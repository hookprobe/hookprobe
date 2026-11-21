# Fortress SDN Integration Architecture

## Executive Summary

This document provides the integration path between the physical network infrastructure (flat bridge) and the logical SDN segmentation layer (OpenFlow-based NAC) with Device Trust Framework integration.

## Current Architecture Analysis

### Physical Layer (Flat Bridge)

The install scripts (`install-container.sh`, `ovs-post-setup.sh`) define a **flat bridge** architecture:

| Component | Subnet | Purpose |
|-----------|--------|---------|
| **FTS Bridge** | 10.200.0.0/XX | All WiFi clients, LAN devices |
| **OpenFlow** | N/A | NAC via device fingerprinting policies |

- **FTS Bridge**: OVS bridge with gateway IP (10.200.0.1/XX)
- **DHCP**: dnsmasq binds to FTS bridge (10.200.0.100-200)
- **Gateway**: 10.200.0.1 on FTS bridge
- **WiFi**: Single SSID bridged to FTS
- **NAC**: OpenFlow rules based on device fingerprints

### Logical Layer (SDN Auto-Pilot)

The SDN Auto-Pilot defines segments for device classification:

| Segment | Segment ID | Purpose | Trust Floor |
|---------|------------|---------|-------------|
| SECMON | 10 | Security monitoring | L3 HIGH |
| POS | 20 | Payment terminals | L3 HIGH |
| CLIENTS | 30 | Staff devices | L2 STANDARD |
| GUEST | 40 | Visitor devices | L1 MINIMAL |
| CAMERAS | 50 | Security cameras | L2 STANDARD |
| IIOT | 60 | Industrial IoT | L2 STANDARD |
| QUARANTINE | 99 | Untrusted devices | L0 UNTRUSTED |

### Gap Identified

**Mismatch**: Python config.py uses 10.250.x.x subnet while install scripts use 10.200.x.x subnet.

**Resolution**: The segment VLANs (10-99) operate as **logical sub-segments within FTS bridge** using OVS OpenFlow rules, not as separate physical VLANs.

---

## Unified Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           FORTRESS SDN ARCHITECTURE                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │                         PHYSICAL LAYER                                       ││
│  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  ││
│  │  │   WAN       │    │  WiFi AP    │    │  LAN Ports  │    │  MGMT Port  │  ││
│  │  │   (eth0)    │    │ (2.4+5GHz)  │    │ (eth1,eth2) │    │   (eth3)    │  ││
│  │  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘    └──────┬──────┘  ││
│  │         │                  │                  │                  │          ││
│  │         │         ┌────────┴────────┬─────────┘                  │          ││
│  │         │         │   FTS bridge      │                    removed│          ││
│  │         │         │   (LAN)         │                    (MGMT)  │          ││
│  │  ┌──────┴─────────┴────────────────────────────────────┬─────────┴──────┐  ││
│  │  │                      FTS OVS BRIDGE                  │               │  ││
│  │  │  Gateway: 10.200.0.1/24                             │ 10.200.100.1/30│  ││
│  │  └──────────────────────┬───────────────────────────────┴───────────────┘  ││
│  │                         │                                                   ││
│  └─────────────────────────┼───────────────────────────────────────────────────┘│
│                            │                                                    │
│  ┌─────────────────────────┼───────────────────────────────────────────────────┐│
│  │                    LOGICAL SDN LAYER (OpenFlow)                             ││
│  │                         │                                                   ││
│  │    ┌────────────────────┴────────────────────────────────┐                 ││
│  │    │              DEVICE TRUST FRAMEWORK                  │                 ││
│  │    │  ┌─────────────────────────────────────────────────┐│                 ││
│  │    │  │ L0 UNTRUSTED → Quarantine (VLAN 99)            ││                 ││
│  │    │  │ L1 MINIMAL   → Guest (VLAN 40) - MAC only      ││                 ││
│  │    │  │ L2 STANDARD  → Segment VLAN - MAC + OUI        ││                 ││
│  │    │  │ L3 HIGH      → Full access - Attestation       ││                 ││
│  │    │  │ L4 ENTERPRISE→ MGMT access - TPM + Neuro       ││                 ││
│  │    │  └─────────────────────────────────────────────────┘│                 ││
│  │    └─────────────────────────────────────────────────────┘                 ││
│  │                         │                                                   ││
│  │    ┌────────────────────┼────────────────────────────────┐                 ││
│  │    │         SDN AUTO-PILOT (OUI Classification)         │                 ││
│  │    │  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐  │                 ││
│  │    │  │ 10  │ │ 20  │ │ 30  │ │ 40  │ │ 50  │ │ 99  │  │                 ││
│  │    │  │SECM │ │ POS │ │STAFF│ │GUEST│ │ CAM │ │QUAR │  │                 ││
│  │    │  └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘  │                 ││
│  │    └─────┼───────┼───────┼───────┼───────┼───────┼─────┘                 ││
│  │          │       │       │       │       │       │                       ││
│  │    ┌─────┴───────┴───────┴───────┴───────┴───────┴─────┐                 ││
│  │    │           OVS OpenFlow Rules (Priority 200)       │                 ││
│  │    │  MAC → Segment Tag → Traffic Isolation            │                 ││
│  │    └───────────────────────────────────────────────────┘                 ││
│  │                                                                           ││
│  └───────────────────────────────────────────────────────────────────────────┘│
│                                                                                │
└────────────────────────────────────────────────────────────────────────────────┘
```

---

## Traffic Flow

### 1. New Device Connection (Single SSID)

```
Device connects to WiFi (HookProbe-Fortress)
    ↓
DHCP Request → dnsmasq on FTS bridge
    ↓
Device assigned IP from 10.200.0.100-200
    ↓
Device Trust Framework Assessment:
    ├─ Check MAC against known devices
    ├─ Verify OUI (vendor lookup)
    ├─ Check for existing certificate
    └─ Calculate trust level (L0-L4)
    ↓
SDN Auto-Pilot Classification:
    ├─ OUI → Vendor → Segment mapping
    └─ Trust level → Minimum VLAN floor
    ↓
OVS OpenFlow Rule Applied:
    dl_src=XX:XX:XX:XX:XX:XX → mod_vlan_vid:SEGMENT
    ↓
Device traffic tagged with segment VLAN
```

### 2. Segment VLAN Assignment

Within FTS bridge, devices are logically segmented via OVS flow rules:

| Trust Level | Default Segment | Can Upgrade To |
|-------------|-----------------|----------------|
| L0 UNTRUSTED | 99 (Quarantine) | None |
| L1 MINIMAL | 40 (Guest) | 40 only |
| L2 STANDARD | OUI-based | 30, 40, 50, 60 |
| L3 HIGH | OUI-based | 10, 20, 30, 50 |
| L4 ENTERPRISE | Any + MGMT | All + removed |

### 3. Inter-Segment Isolation

```python
# OVS Flow Rules (installed by SDN Auto-Pilot)

# Segment 40 (Guest) → Isolated, internet only
priority=300,dl_vlan=40,ip,nw_dst=10.200.0.0/16,actions=drop
priority=200,dl_vlan=40,actions=NORMAL

# Segment 20 (POS) → Isolated, payment gateway only
priority=300,dl_vlan=20,ip,nw_dst=!payment-gateway,actions=drop
priority=200,dl_vlan=20,actions=NORMAL

# Segment 30 (Staff) → Full LAN access
priority=200,dl_vlan=30,actions=NORMAL
```

---

## SDN Management Dashboard Integration

### Unified Dashboard Components

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           SDN MANAGEMENT                                         │
├─────────────────────────────────────────────────────────────────────────────────┤
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐│
│  │    LAN     │  │   WiFi     │  │  Channel   │  │   Radar    │  │     CH     ││
│  │  Network   │  │  Network   │  │   Score    │  │   Events   │  │  Switches  ││
│  │  24 dev    │  │  18 dev    │  │    92%     │  │     2      │  │     5      ││
│  └────────────┘  └────────────┘  └────────────┘  └────────────┘  └────────────┘│
│                                                                                 │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │                        NETWORK DEVICES (42 total)                         │  │
│  ├──────────┬───────────────┬──────────┬─────────┬─────────┬────────────────┤  │
│  │ Device   │ Vendor        │ Segment  │ Trust   │ IP      │ Actions        │  │
│  ├──────────┼───────────────┼──────────┼─────────┼─────────┼────────────────┤  │
│  │ POS-1    │ Ingenico      │ POS(20)  │ HIGH    │ .101    │ [Enroll][Move] │  │
│  │ iPhone   │ Apple         │ STAFF(30)│ STD     │ .102    │ [Enroll][Move] │  │
│  │ Camera   │ Hikvision     │ CAM(50)  │ STD     │ .103    │ [Enroll][Move] │  │
│  │ Unknown  │ Unknown       │ QUAR(99) │ UNTRUST │ .104    │ [Trust][Block] │  │
│  └──────────┴───────────────┴──────────┴─────────┴─────────┴────────────────┘  │
│                                                                                 │
│  ┌──────────────────────────┐  ┌──────────────────────────────────────────────┐│
│  │   SEGMENT DISTRIBUTION   │  │          TRUST LEVEL SUMMARY                 ││
│  │  ┌────────────────────┐  │  │  ┌────────────────────────────────────────┐ ││
│  │  │ STAFF(30)   ████ 15│  │  │  │ L4 ENTERPRISE  ██                   2 │ ││
│  │  │ GUEST(40)   ███  10│  │  │  │ L3 HIGH        ████                 8 │ ││
│  │  │ CAM(50)     ██    6│  │  │  │ L2 STANDARD    ████████            18 │ ││
│  │  │ POS(20)     █     4│  │  │  │ L1 MINIMAL     ██████              12 │ ││
│  │  │ SECMON(10)  ▏     2│  │  │  │ L0 UNTRUSTED   █                    2 │ ││
│  │  │ QUAR(99)    ▏     2│  │  │  └────────────────────────────────────────┘ ││
│  │  └────────────────────┘  │  └──────────────────────────────────────────────┘│
│  └──────────────────────────┘                                                   │
│                                                                                 │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │                        WIFI INTELLIGENCE                                  │  │
│  │  Channel: 149 (5GHz)  │  Width: 80MHz  │  Power: 23dBm                   │  │
│  │  ┌─────────────────────────────────────────────────────────────────────┐ │  │
│  │  │ Channel Score: [████████████████████████████░░░░░░] 85/100          │ │  │
│  │  │ DFS Status: CLEAR  │  Last Radar: 2h ago  │  CAC: Complete          │ │  │
│  │  └─────────────────────────────────────────────────────────────────────┘ │  │
│  │  Recent Events:                                                          │  │
│  │  • 14:32 - Channel switched 36 → 149 (congestion)                       │  │
│  │  • 12:15 - Radar detected on CH 52 (weather)                            │  │
│  │  • 09:00 - CAC completed on CH 149                                      │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Configuration Alignment

### 1. Update config.py Segments

Segment configuration aligned with 10.200.x.x subnet:

```python
# CURRENT ARCHITECTURE (Flat bridge with OpenFlow segments)
# FTS Bridge: 10.200.0.0/XX - All devices share same L2 subnet
# Segmentation via OpenFlow rules, not VLANs
"lan": SegmentConfig(0, "LAN", "10.200.0.0/24", "10.200.0.1"),
# Logical segments (OpenFlow-enforced within FTS bridge)
"secmon": SegmentConfig(10, "Security Monitor", "10.200.0.0/24", "10.200.0.1", is_logical=True),
"pos": SegmentConfig(20, "POS", "10.200.0.0/24", "10.200.0.1", is_logical=True),
"staff": SegmentConfig(30, "Staff", "10.200.0.0/24", "10.200.0.1", is_logical=True),
"guest": SegmentConfig(40, "Guest", "10.200.0.0/24", "10.200.0.1", is_isolated=True, is_logical=True),
"cameras": SegmentConfig(50, "Cameras", "10.200.0.0/24", "10.200.0.1", is_logical=True),
"iiot": SegmentConfig(60, "Industrial IoT", "10.200.0.0/24", "10.200.0.1", is_logical=True),
"quarantine": SegmentConfig(99, "Quarantine", "10.200.0.0/24", "10.200.0.1", is_isolated=True, is_logical=True),
```

### 2. DHCP Configuration

The install scripts correctly configure DHCP on `FTS bridge`:
- Interface: `FTS bridge` (not FTS bridge in VLAN mode)
- Range: 10.200.0.100 - 10.200.0.200 (configurable)
- Gateway: 10.200.0.1
- DNS: 10.200.0.1 (dnsXai container)

### 3. OVS Flow Integration

SDN Auto-Pilot installs flows at priority 200 for MAC-to-segment mapping:

```bash
# View current flows
ovs-ofctl dump-flows FTS | grep priority=200

# Example flow for device in POS segment
priority=200,dl_src=AA:BB:CC:DD:EE:FF,actions=mod_vlan_vid:20,NORMAL
```

---

## Trust-to-Segment Mapping

### Trust Level → Allowed Segments

| Trust | Allowed Segments | Justification |
|-------|------------------|---------------|
| L0 | 99 only | Unknown device, must verify |
| L1 | 40, 99 | MAC known but not verified |
| L2 | 30, 40, 50, 60, 99 | OUI verified, behavioral ok |
| L3 | 10, 20, 30, 50, 99 | Attestation passed |
| L4 | All + MGMT (200) | Full enterprise access |

### OUI → Segment Defaults

From SDN Auto-Pilot OUI database:

| Vendor | Default Segment | Trust Floor |
|--------|-----------------|-------------|
| Ingenico, Verifone | POS (20) | L3 HIGH |
| Hikvision, Dahua | CAMERAS (50) | L2 STANDARD |
| Apple, Samsung | STAFF (30) | L2 STANDARD |
| Unknown | GUEST (40) | L1 MINIMAL |
| Blacklisted | QUARANTINE (99) | L0 UNTRUSTED |

---

## Integration Checklist

### Phase 1: Configuration Alignment ✓

- [ ] Update `config.py` VLANs to use 10.200.x.x subnet
- [ ] Add `is_logical` flag to VLANConfig for segment VLANs
- [ ] Add FTS bridge (LAN) and 200 (MGMT) to config
- [ ] Update `dnsmasq-fortress.conf` template

### Phase 2: SDN Auto-Pilot Update ✓

- [ ] Update segment VLAN subnet references
- [ ] Add trust level enforcement to classification
- [ ] Integrate with Device Trust Framework
- [ ] Add segment transition rules

### Phase 3: Dashboard Consolidation

- [ ] Create unified SDN Management dashboard
- [ ] Remove separate Clients and Networks views
- [ ] Add WiFi Intelligence panel (DFS, Channel Score)
- [ ] Add Trust Level distribution chart
- [ ] Integrate real-time device updates

### Phase 4: WiFi Integration

- [ ] Add DFS Intelligence API to SDN views
- [ ] Display channel score, radar events, switches
- [ ] Add channel history timeline
- [ ] Integrate with hostapd for channel control

---

## API Endpoints

### SDN Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/sdn/dashboard` | GET | Unified SDN dashboard |
| `/api/sdn/devices` | GET | All network devices |
| `/api/sdn/segments` | GET | Segment statistics |
| `/api/sdn/trust` | GET | Trust level summary |
| `/api/sdn/wifi` | GET | WiFi intelligence data |

### Device Trust

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/trust/enroll` | POST | Enroll device certificate |
| `/api/trust/revoke` | POST | Revoke device trust |
| `/api/trust/quarantine` | POST | Move to quarantine |
| `/api/trust/move` | POST | Change device segment |

### WiFi Intelligence

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/wifi/channel` | GET | Current channel info |
| `/api/wifi/score` | GET | ML channel score |
| `/api/wifi/radar` | GET | Radar event history |
| `/api/wifi/switch` | POST | Trigger channel switch |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-12-26 | Initial architecture document |
