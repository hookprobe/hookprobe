# Fortress Traffic Flow Architecture

## Network Topology

```
                                    INTERNET
                                        │
                    ┌───────────────────┴───────────────────┐
                    │           WAN FAILOVER (PBR)          │
                    │  ┌─────────────┐  ┌─────────────────┐ │
                    │  │  eth0/enp*  │  │   wwan0 (LTE)   │ │
                    │  │  Table 100  │  │    Table 200    │ │
                    │  │ (primary)   │  │    (backup)     │ │
                    │  └──────┬──────┘  └────────┬────────┘ │
                    │         │                  │          │
                    │         └────────┬─────────┘          │
                    │                  │                    │
                    │           nftables marks              │
                    │      (fwmark 0x100 or 0x200)          │
                    └──────────────────┬────────────────────┘
                                       │
                    ┌──────────────────┴──────────────────────┐
                    │              HOST (Ubuntu)               │
                    │                                          │
                    │  ┌────────────────────────────────────┐  │
                    │  │     Host-Network Containers        │  │
                    │  │  ┌──────────┐ ┌────────┐ ┌──────┐  │  │
                    │  │  │ QSecBit  │ │Suricata│ │ Zeek │  │  │
                    │  │  │ :9090    │ │  IDS   │ │ NSM  │  │  │
                    │  │  └──────────┘ └────────┘ └──────┘  │  │
                    │  └────────────────────────────────────┘  │
                    │                                          │
                    │  ┌────────────────────────────────────┐  │
                    │  │         OVS Bridge: FTS            │  │
                    │  │                                    │  │
                    │  │  ┌──────────────────────────────┐  │  │
                    │  │  │        LAN Tier              │  │  │
                    │  │  │     10.200.0.0/23            │  │  │
                    │  │  │   (WiFi + Wired Clients)     │  │  │
                    │  │  │        NAT → Internet        │  │  │
                    │  │  └──────────────────────────────┘  │  │
                    │  │                                    │  │
                    │  └────────────────────────────────────┘  │
                    │                                          │
                    │  ┌────────────────────────────────────┐  │
                    │  │       Podman Bridge Networks       │  │
                    └──┴────────────────────────────────────┴──┘
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        │                              │                              │
┌───────┴───────┐            ┌─────────┴─────────┐          ┌─────────┴─────────┐
│   DATA TIER   │            │  SERVICES TIER    │          │    MGMT TIER      │
│ 172.20.200/24 │            │  172.20.201/24    │          │  172.20.203/24    │
│  (internal)   │            │   (internet OK)   │          │   (internal)      │
├───────────────┤            ├───────────────────┤          ├───────────────────┤
│ postgres :5432│◄───────────│ web      :8443    │          │ grafana   :3000   │
│ redis    :6379│            │ dnsxai   :5353    │          │ victoria  :8428   │
│               │            │ dfs      :8050    │          │                   │
└───────────────┘            └───────────────────┘          └───────────────────┘
                                       │
                              ┌────────┴────────┐
                              │    ML TIER      │
                              │ 172.20.202/24   │
                              │  (internal)     │
                              ├─────────────────┤
                              │ lstm-trainer    │
                              │ (one-shot job)  │
                              └─────────────────┘
```

## Container Network Assignments

| Container | Network(s) | IP Address(es) | Internet | Notes |
|-----------|------------|----------------|----------|-------|
| **postgres** | fts-data | 172.20.200.10 | NO | Primary database |
| **redis** | fts-data | 172.20.200.11 | NO | Session cache |
| **web** | fts-services, fts-data | 172.20.201.10, 172.20.200.20 | YES | Admin portal |
| **dnsxai** | fts-services | 172.20.201.11 | YES | DNS ML protection |
| **dfs** | fts-services | 172.20.201.12 | YES | WiFi intelligence |
| **grafana** | fts-mgmt, fts-data | 172.20.203.10, 172.20.200.30 | NO | Monitoring UI |
| **victoria** | fts-mgmt | 172.20.203.11 | NO | Metrics DB |
| **qsecbit** | host | host IPs | YES | Threat detection |
| **suricata** | host | host IPs | YES | IDS/IPS |
| **zeek** | host | host IPs | YES | Network analysis |
| **xdp** | host | host IPs | YES | DDoS protection |
| **lstm-trainer** | fts-ml | 172.20.202.10 | NO | ML training |

## Traffic Flow Rules

### 1. LAN Client → Internet

```
Client (10.200.0.x)
    │
    ▼
OVS Bridge (FTS-lan)
    │
    ├─► Table 0: ARP/DHCP/DNS → NORMAL
    │
    ▼
Table 10: Tier Isolation
    │
    ├─► LAN src allowed → Table 20
    │
    ▼
Table 20: Internet Control
    │
    ├─► LAN allowed internet → Table 30
    │
    ▼
Table 30: Mirror → Table 40
    │
    ▼
Table 40: NORMAL (L2 forward)
    │
    ▼
iptables/nftables NAT (MASQUERADE)
    │
    ▼
PBR: fwmark → routing table
    │
    ├─► 0x100 → Table 100 (eth0)
    └─► 0x200 → Table 200 (wwan0)
    │
    ▼
INTERNET
```

### 2. Container → Internet (services tier)

```
dnsxai (172.20.201.11)
    │
    ▼
Podman bridge (fts-services)
    │
    ▼
Host routing (172.20.201.0/24 → gateway)
    │
    ├─► NOT through OVS (podman bridge is separate!)
    │
    ▼
iptables/nftables NAT
    │
    ▼
PBR: fwmark → routing table
    │
    ▼
INTERNET
```

### 3. Container → Container (cross-tier)

```
web (172.20.201.10) → postgres (172.20.200.10)
    │
    ├─► Web has interface on BOTH networks
    │   - fts-services: 172.20.201.10
    │   - fts-data: 172.20.200.20
    │
    ▼
Direct podman bridge routing (172.20.200.0/24)
    │
    ▼
postgres (172.20.200.10)
```

## Identified Gaps & Fixes

### GAP 1: PBR Not Applied to Container Traffic

**Problem**: Container traffic uses podman bridge networks which bypass the host's nftables OUTPUT chain where PBR marking happens.

**Impact**: If primary WAN fails, container traffic may not failover correctly.

**Fix**: Add nftables rules in FORWARD chain to mark container-originated traffic:

```bash
# Mark container traffic in FORWARD chain (before NAT)
nft add rule inet fts_wan_failover forward \
    ip saddr 172.20.0.0/16 \
    meta mark set $FWMARK_PRIMARY
```

### GAP 2: No NAT for Container Networks

**Problem**: Services tier (172.20.201.0/24) is allowed internet by OVS rules, but no NAT masquerade rule exists.

**Impact**: Container internet access fails silently.

**Fix**: Add masquerade rule in nftables:

```bash
nft add rule inet nat postrouting \
    ip saddr 172.20.201.0/24 \
    oifname { "eth0", "enp*", "wwan0" } \
    masquerade
```

### GAP 3: OVS vs Podman Bridge Mismatch

**Problem**: OVS OpenFlow rules control traffic on OVS bridge, but containers use podman bridge networks (separate from OVS).

**Impact**: Container isolation relies on podman's `internal: true` flag, not OVS OpenFlow rules.

**Clarification**: This is actually by design:
- **Podman bridges**: Handle container-to-container traffic
- **OVS bridge**: Handles LAN client traffic (WiFi/wired)
- **Host-network containers**: See all traffic directly

### GAP 4: DNS Resolution Path

**Problem**: How does LAN client DNS reach dnsXai?

**Current flow**:
1. Client DNS → OVS bridge gateway (10.200.0.1)
2. dnsmasq on host receives DNS
3. dnsmasq configured to forward to dnsXai (172.20.201.11:5353)

**Fix**: Ensure dnsmasq config includes:
```conf
server=172.20.201.11#5353
```

### GAP 5: Host-Network Container PBR

**Problem**: QSecBit, Suricata, Zeek use host network. Their outbound traffic should also use PBR.

**Status**: ✅ Working - host-network containers share host's network stack, so PBR marking in OUTPUT chain applies.

### GAP 6: Grafana → Postgres via Separate Network

**Problem**: Grafana needs to query postgres for dashboards. Both now on fts-data network.

**Status**: ✅ Fixed in previous commit - Grafana added to fts-data network (172.20.200.30)

## Validation Commands

```bash
# 1. Check PBR status
wan-failover-pbr.sh status

# 2. Check container network connectivity
podman exec fts-web ping -c1 172.20.200.10   # web → postgres
podman exec fts-grafana ping -c1 172.20.200.10  # grafana → postgres
podman exec fts-dnsxai ping -c1 8.8.8.8      # dnsxai → internet

# 3. Check NAT rules
nft list ruleset | grep -A5 masquerade

# 4. Check OVS flows
ovs-ofctl dump-flows FTS

# 5. Check LAN client internet
# From client: ping 8.8.8.8

# 6. Check DNS resolution
# From client: dig hookprobe.com @10.200.0.1

# 7. Verify PBR marking
nft list chain inet fts_wan_failover forward
```

## Traffic Matrix

| Source | Destination | Allowed | Via |
|--------|-------------|---------|-----|
| LAN Client | Internet | ✅ | OVS → NAT → PBR |
| LAN Client | Containers | ❌ | Blocked by OVS |
| web | postgres | ✅ | Direct (dual-homed) |
| web | Internet | ✅ | Podman → NAT → PBR |
| dnsxai | Internet | ✅ | Podman → NAT → PBR |
| grafana | postgres | ✅ | Direct (dual-homed) |
| grafana | victoria | ✅ | fts-mgmt network |
| grafana | Internet | ❌ | internal network |
| qsecbit | Internet | ✅ | Host → PBR |
| qsecbit | Containers | ✅ | Host → Direct IP |
| postgres | Internet | ❌ | internal network |
| redis | Internet | ❌ | internal network |

## Version
- Document: 1.0.0
- Fortress: 5.5.0
- Date: 2024-12-26
