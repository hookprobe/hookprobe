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
│ redis    :6379│            │ dnsxai   :53      │          │ victoria  :8428   │
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

All containers use a **single consolidated network** (`fts-internal` / 172.20.200.0/24) managed by podman-compose. The "tier" concept is used for OpenFlow policy decisions (which containers get internet access) rather than actual network segmentation.

| Container | Network | IP Address | Internet | Tier Policy | Notes |
|-----------|---------|------------|----------|-------------|-------|
| **postgres** | fts-internal | 172.20.200.10 | NO | data | Primary database |
| **redis** | fts-internal | 172.20.200.11 | NO | data | Session cache |
| **web** | fts-internal | 172.20.200.20 | YES | services | Admin portal |
| **dnsxai** | fts-internal | 172.20.200.21 | YES | services | DNS ML protection |
| **dfs** | fts-internal | 172.20.200.22 | YES | services | WiFi intelligence |
| **grafana** | fts-internal | 172.20.200.30 | NO | mgmt | Monitoring UI |
| **victoria** | fts-internal | 172.20.200.31 | NO | mgmt | Metrics DB |
| **lstm-trainer** | fts-internal | 172.20.200.40 | NO | ml | ML training (one-shot) |
| **n8n** | fts-internal | 172.20.200.50 | YES | services | Workflow automation |
| **clickhouse** | fts-internal | 172.20.200.51 | NO | data | Analytics DB |
| **cloudflared** | fts-internal | 172.20.200.60 | YES | services | Tunnel client |
| **qsecbit** | host | host IPs | YES | - | Threat detection |
| **suricata** | host | host IPs | YES | - | IDS/IPS |
| **zeek** | host | host IPs | YES | - | Network analysis |
| **xdp** | host | host IPs | YES | - | DDoS protection |
| **bubble-manager** | host | host IPs | YES | - | Device ecosystem detection |

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
dnsxai (172.20.200.21)
    │
    ▼
Podman bridge (fts-internal)
    │
    ▼
Host routing (172.20.200.0/24 → gateway)
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

### 3. Container → Container (same network)

```
web (172.20.200.20) → postgres (172.20.200.10)
    │
    ├─► All containers on same fts-internal network
    │   Direct communication via podman bridge
    │
    ▼
Podman bridge routing (172.20.200.0/24)
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

**Problem**: Container network (172.20.200.0/24) needs NAT masquerade for internet access.

**Impact**: Container internet access fails silently without NAT.

**Fix**: Add masquerade rule in nftables:

```bash
nft add rule inet nat postrouting \
    ip saddr 172.20.200.0/24 \
    oifname { "eth0", "enp*", "wwan0" } \
    masquerade
```

**Status**: ✅ Fixed - NAT rules added in traffic-flow-setup.sh

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
3. dnsmasq configured to forward to dnsXai (127.0.0.1:53)

**Fix**: Ensure dnsmasq config includes:
```conf
server=127.0.0.1
```
Note: dnsXai binds to 127.0.0.1:53 (host port 53 → container port 5353).
This frees port 5353 for mDNS (Avahi + bubble manager ecosystem detection).

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

All containers are on the same `fts-internal` network (172.20.200.0/24). The "Tier Policy" column indicates OpenFlow rules for internet access control.

| Source | Destination | Allowed | Via |
|--------|-------------|---------|-----|
| LAN Client | Internet | ✅ | OVS → NAT → PBR |
| LAN Client | Containers | ❌ | Blocked by OVS |
| web | postgres | ✅ | fts-internal (same network) |
| web | Internet | ✅ | Podman → NAT → PBR |
| dnsxai | Internet | ✅ | Podman → NAT → PBR |
| grafana | postgres | ✅ | fts-internal (same network) |
| grafana | victoria | ✅ | fts-internal (same network) |
| grafana | Internet | ❌ | Tier policy: mgmt (no internet) |
| victoria | Internet | ❌ | Tier policy: mgmt (no internet) |
| qsecbit | Internet | ✅ | Host network → PBR |
| qsecbit | Containers | ✅ | Host → Direct IP (172.20.200.x) |
| bubble-manager | Containers | ✅ | Host → Direct IP (172.20.200.x) |
| postgres | Internet | ❌ | Tier policy: data (no internet) |
| redis | Internet | ❌ | Tier policy: data (no internet) |
| clickhouse | Internet | ❌ | Tier policy: data (no internet) |

## Version
- Document: 1.1.0
- Fortress: 5.5.0
- Date: 2025-01-04
