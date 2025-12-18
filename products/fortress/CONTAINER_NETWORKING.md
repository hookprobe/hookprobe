# Fortress Container Network Architecture

**Version**: 1.1
**Date**: 2025-12-18

---

## Current State Analysis

### Problem

The containers currently use basic podman bridge networks which are:
- **Isolated** from the main Fortress OVS bridge (10.250.0.0/23)
- **Not encrypted** - traffic flows in plain text between containers
- **Not segmented** properly by security tier

### Current Network Layout

```
┌─────────────────────────────────────────────────────────────────────┐
│                     HOST NETWORK STACK                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  WAN Interface          Fortress OVS Bridge       Podman Networks   │
│  (eth0/wlan0)           (br-fortress)             (isolated)        │
│       │                      │                         │             │
│       │                 10.250.0.1/23                  │             │
│       │                      │                         │             │
│       │              ┌───────┴───────┐           podman0             │
│       │              │  LAN Clients  │         10.88.0.0/16         │
│       │              │ 10.250.0.x    │              │                │
│       │              └───────────────┘         ┌────┴────┐          │
│       │                                        │ Grafana │          │
│       │                                        │Victoria │          │
│       │                                        └─────────┘          │
│       │                                                              │
│       └── NAT ──────────────────────────────────────────────────────│
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘

ISSUES:
1. Containers can't see LAN clients (different network)
2. QSecBit agent needs traffic visibility (currently uses host network)
3. No encryption between containers
4. dnsXai can't serve DNS to fortress clients
```

---

## Proposed Architecture

### Network Segmentation by Security Tier

| Network | Subnet | Purpose | Internet | Encryption |
|---------|--------|---------|----------|------------|
| **fortress-data** | 10.250.200.0/24 | PostgreSQL, Redis (sensitive) | NO | TLS (PostgreSQL SSL, Redis AUTH) |
| **fortress-services** | 10.250.201.0/24 | Web, dnsXai, DFS (services) | Limited | TLS + HTP for mesh participation |
| **fortress-ml** | 10.250.202.0/24 | QSecBit, ML inference | NO | Internal isolation |
| **fortress-mgmt** | 10.250.203.0/24 | Monitoring (Grafana, Victoria) | NO | Internal isolation |

### Security Model

**Intra-Host Communication** (container-to-container on same Fortress):
- Network isolation via internal podman bridges
- TLS for database connections (PostgreSQL SSL, Redis with password)
- Firewall rules (nftables) for port-level access control

**Inter-Node Communication** (Fortress-to-Fortress, Fortress-to-Guardian):
- **HTP** - HookProbe Transport Protocol with post-quantum Kyber KEM
- **DSM** - Decentralized Security Mesh for consensus and validation
- **Neuro** - Neural Resonance Protocol for keyless authentication
- QSecBit agent participates in mesh via host network

### Container Network Access Matrix

| Container | Data | Services | ML | Mgmt | Host | Internet |
|-----------|------|----------|-----|------|------|----------|
| **postgres** | ✅ PRIMARY | ❌ | ❌ | ❌ | ❌ | ❌ |
| **redis** | ✅ PRIMARY | ❌ | ❌ | ❌ | ❌ | ❌ |
| **web** | ✅ client | ✅ PRIMARY | ✅ client | ✅ client | ✅ 8443 | ❌ |
| **dnsxai** | ❌ | ✅ PRIMARY | ❌ | ❌ | ✅ 5353 | ✅ (upstream DNS) |
| **dfs-intelligence** | ❌ | ✅ PRIMARY | ❌ | ❌ | ✅ 8050 | ❌ |
| **qsecbit-agent** | ✅ client | ✅ client | ✅ PRIMARY | ✅ client | ✅ HOST NET | ❌ |
| **grafana** | ❌ | ❌ | ❌ | ✅ PRIMARY | ✅ 3000 | ❌ |
| **victoria** | ❌ | ❌ | ❌ | ✅ PRIMARY | ✅ 8428 | ❌ |

### Network Topology Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        FORTRESS CONTAINER NETWORK                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    FORTRESS-DATA (10.250.200.0/24)                   │   │
│  │                    internal=true (NO internet)                       │   │
│  │                    PostgreSQL SSL + Redis AUTH                       │   │
│  │  ┌─────────────┐            ┌─────────────┐                         │   │
│  │  │  postgres   │            │    redis    │                         │   │
│  │  │ .200.10     │            │  .200.11    │                         │   │
│  │  │ :5432 (SSL) │            │  :6379      │                         │   │
│  │  └──────┬──────┘            └──────┬──────┘                         │   │
│  │         │                          │                                 │   │
│  └─────────┼──────────────────────────┼─────────────────────────────────┘   │
│            │                          │                                      │
│            │    DB Connections        │ Cache/Sessions                       │
│            ▼                          ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                  FORTRESS-SERVICES (10.250.201.0/24)                 │   │
│  │                  TLS encrypted, HTP mesh participation               │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │   │
│  │  │    web      │  │   dnsxai    │  │     dfs     │                  │   │
│  │  │ .201.10     │  │  .201.11    │  │   .201.12   │                  │   │
│  │  │ :8443 ←─────┼──┼─ HOST :8443 │  │             │                  │   │
│  │  │             │  │ :5353 ←─────┼──┼─ HOST :5353 │                  │   │
│  │  │             │  │             │  │ :8050 ←─────┼─ HOST :8050      │   │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                  │   │
│  │         │                │                │                          │   │
│  └─────────┼────────────────┼────────────────┼──────────────────────────┘   │
│            │                │                │                               │
│            │ API calls      │ ML requests    │ Channel recommendations       │
│            ▼                ▼                ▼                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                     FORTRESS-ML (10.250.202.0/24)                    │   │
│  │                     internal=true (NO internet)                      │   │
│  │  ┌───────────────────────────────────────────────────────────────┐  │   │
│  │  │                    qsecbit-agent                               │  │   │
│  │  │                    network_mode: host (traffic capture)        │  │   │
│  │  │                    Participates in HTP/DSM/Neuro mesh          │  │   │
│  │  │                    Reads: eth0, wlan0, fortress bridge         │  │   │
│  │  └───────────────────────────────────────────────────────────────┘  │   │
│  │                                                                      │   │
│  │  ┌─────────────────────────────────────────────────────────────┐    │   │
│  │  │  lstm-trainer (job)  │  Runs periodically for model training │    │   │
│  │  └─────────────────────────────────────────────────────────────┘    │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    FORTRESS-MGMT (10.250.203.0/24)                   │   │
│  │                    internal=true (NO internet)                       │   │
│  │  ┌─────────────┐            ┌─────────────┐                         │   │
│  │  │  grafana    │            │  victoria   │                         │   │
│  │  │ .203.10     │◀──────────▶│  .203.11    │                         │   │
│  │  │ :3000 ←─────┼─ HOST :3000│  :8428 ←────┼─ HOST :8428             │   │
│  │  └─────────────┘            └─────────────┘                         │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

                              HOST NETWORK
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│  ┌────────────┐    ┌────────────┐    ┌─────────────────────────────────┐   │
│  │   WAN      │───▶│    NAT     │───▶│     FORTRESS OVS BRIDGE        │   │
│  │ (internet) │    │ (iptables) │    │     10.250.0.0/23              │   │
│  └────────────┘    └────────────┘    │                                 │   │
│                                       │  WiFi Clients: 10.250.0.x      │   │
│                                       │  LAN Clients:  10.250.1.x      │   │
│                                       │                                 │   │
│                                       │  dnsmasq → dnsxai:5353         │   │
│                                       │  (DNS queries forwarded)       │   │
│                                       └─────────────────────────────────┘   │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                     HTP/DSM/NEURO MESH                               │   │
│  │  QSecBit agent (host network) participates in:                       │   │
│  │  - HTP: Post-quantum encrypted transport (Kyber KEM + ChaCha20)     │   │
│  │  - DSM: Threat consensus with other nodes (BLS signatures)          │   │
│  │  - Neuro: Neural resonance authentication (keyless)                 │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Implementation

### 1. Security Layers

#### Intra-Host: TLS + Network Isolation

For container-to-container communication within the same Fortress:

```yaml
# PostgreSQL with SSL
services:
  postgres:
    environment:
      POSTGRES_SSL: "on"
      POSTGRES_SSL_CERT_FILE: /certs/server.crt
      POSTGRES_SSL_KEY_FILE: /certs/server.key
    volumes:
      - postgres_certs:/certs:ro

# Redis with password authentication
  redis:
    command: >
      redis-server
      --requirepass "${REDIS_PASSWORD}"
      --appendonly yes
```

**Pros**: Standard, well-supported, no external dependencies
**Cons**: Certificate management required

#### Inter-Node: HTP/DSM/Neuro Stack

For communication between Fortress nodes and other HookProbe devices:

```python
# QSecBit agent uses HTP for mesh communication
from core.htp.transport import HTPTransport
from shared.dsm.consensus import ConsensusEngine
from core.neuro.identity import HardwareFingerprint

# Threat intelligence propagation uses DSM
dsm_node.create_microblock(event_type='threat_intel', payload=threat.to_bytes())

# Authentication via Neuro (keyless)
fingerprint = HardwareFingerprint.generate()
posf_signature = neuro_engine.sign(message, fingerprint)
```

---

### 2. Updated podman-compose.yml Networks

```yaml
networks:
  # Tier 1: Data (most sensitive - database, cache)
  fortress-data:
    driver: bridge
    internal: true  # NO internet access
    ipam:
      config:
        - subnet: 10.250.200.0/24
          gateway: 10.250.200.1
    driver_opts:
      mtu: 9000  # Jumbo frames for DB traffic
      com.docker.network.bridge.enable_ip_masquerade: "false"
      com.docker.network.bridge.enable_icc: "true"

  # Tier 2: Services (web, DNS, APIs)
  fortress-services:
    driver: bridge
    ipam:
      config:
        - subnet: 10.250.201.0/24
          gateway: 10.250.201.1
    driver_opts:
      mtu: 1500

  # Tier 3: ML (threat detection, inference)
  fortress-ml:
    driver: bridge
    internal: true  # NO internet access
    ipam:
      config:
        - subnet: 10.250.202.0/24
          gateway: 10.250.202.1

  # Tier 4: Management (monitoring)
  fortress-mgmt:
    driver: bridge
    internal: true  # NO internet access
    ipam:
      config:
        - subnet: 10.250.203.0/24
          gateway: 10.250.203.1
```

---

### 3. Container Network Assignments

```yaml
services:
  postgres:
    networks:
      fortress-data:
        ipv4_address: 10.250.200.10
    # NO other networks - most isolated

  redis:
    networks:
      fortress-data:
        ipv4_address: 10.250.200.11

  web:
    networks:
      fortress-data:        # Read/write to DB
        ipv4_address: 10.250.200.20
      fortress-services:    # Serve HTTPS
        ipv4_address: 10.250.201.10
      fortress-ml:          # Query QSecBit
        ipv4_address: 10.250.202.20
      fortress-mgmt:        # Query metrics
        ipv4_address: 10.250.203.20
    ports:
      - "8443:8443"  # Only service exposed to host

  dnsxai:
    networks:
      fortress-services:
        ipv4_address: 10.250.201.11
    ports:
      - "5353:5353/udp"  # DNS service

  dfs-intelligence:
    networks:
      fortress-services:
        ipv4_address: 10.250.201.12
    ports:
      - "8050:8050"

  qsecbit-agent:
    network_mode: host  # REQUIRED for traffic capture + HTP mesh
    # Uses host network to:
    # 1. Capture traffic on all interfaces
    # 2. Participate in HTP/DSM/Neuro mesh with other nodes

  grafana:
    networks:
      fortress-mgmt:
        ipv4_address: 10.250.203.10
    ports:
      - "3000:3000"

  victoria:
    networks:
      fortress-mgmt:
        ipv4_address: 10.250.203.11
    ports:
      - "8428:8428"
```

---

### 4. DNS Integration with dnsXai

To make dnsXai serve DNS for Fortress clients:

```bash
# dnsmasq configuration (/etc/dnsmasq.d/fortress.conf)
# Forward DNS queries to dnsXai container
server=10.250.201.11#5353

# Or if using host port
# server=127.0.0.1#5353
```

---

### 5. Inter-Container TLS Certificates

```yaml
volumes:
  # Shared CA for all containers
  fortress-ca:
    driver: local
    name: fortress-ca

  # Per-service certificates
  postgres-certs:
    driver: local
  redis-certs:
    driver: local
  web-certs:
    driver: local

services:
  postgres:
    volumes:
      - fortress-ca:/ca:ro
      - postgres-certs:/certs:ro
    environment:
      POSTGRES_SSL: "on"
```

---

### 6. Firewall Rules (nftables)

```nft
table inet fortress_containers {
    chain input {
        type filter hook input priority filter;

        # Allow established connections
        ct state established,related accept

        # Data network - only postgres/redis ports
        iifname "br-fortress-data" tcp dport { 5432, 6379 } accept
        iifname "br-fortress-data" drop

        # Services network - HTTP/HTTPS/DNS
        iifname "br-fortress-services" tcp dport { 8443, 8050 } accept
        iifname "br-fortress-services" udp dport 5353 accept

        # Management network - Grafana/Victoria
        iifname "br-fortress-mgmt" tcp dport { 3000, 8428 } accept

        # ML network - internal only
        iifname "br-fortress-ml" drop
    }

    chain forward {
        type filter hook forward priority filter;

        # Allow data <-> services (web needs DB)
        iifname "br-fortress-data" oifname "br-fortress-services" accept
        iifname "br-fortress-services" oifname "br-fortress-data" accept

        # Allow services <-> ml (web queries qsecbit)
        iifname "br-fortress-services" oifname "br-fortress-ml" accept
        iifname "br-fortress-ml" oifname "br-fortress-services" accept

        # Allow services <-> mgmt (web queries metrics)
        iifname "br-fortress-services" oifname "br-fortress-mgmt" accept
        iifname "br-fortress-mgmt" oifname "br-fortress-services" accept

        # Block everything else
        drop
    }
}
```

---

## HookProbe Security Stack Integration

### QSecBit Agent - Mesh Participant

The QSecBit agent runs with `network_mode: host` to:

1. **Traffic Capture**: Monitor all network interfaces (eth0, wlan0, br-fortress)
2. **HTP Mesh**: Participate in encrypted mesh communication with other nodes
3. **DSM Consensus**: Create microblocks for threat intelligence propagation
4. **Neuro Auth**: Keyless authentication via neural resonance

```
┌─────────────────────────────────────────────────────────────────┐
│                    QSECBIT AGENT (HOST NETWORK)                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │    HTP      │  │    DSM      │  │   NEURO     │             │
│  │  Transport  │  │  Consensus  │  │   Auth      │             │
│  │ (Kyber KEM) │  │ (BLS sigs)  │  │ (Keyless)   │             │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
│         │                │                │                      │
│         └────────────────┼────────────────┘                      │
│                          │                                       │
│                  ┌───────▼───────┐                              │
│                  │ Threat Intel  │                              │
│                  │ Propagation   │                              │
│                  └───────────────┘                              │
│                          │                                       │
│  ┌───────────────────────▼───────────────────────────────────┐  │
│  │              OTHER HOOKPROBE NODES                         │  │
│  │  Guardian ←→ Fortress ←→ Nexus ←→ MSSP                    │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Summary

| Aspect | Before | After |
|--------|--------|-------|
| **Networks** | 2 (internal, external) | 4 (data, services, ml, mgmt) |
| **Intra-Host Security** | None | TLS + network isolation |
| **Inter-Node Security** | None | HTP/DSM/Neuro stack |
| **Isolation** | Basic | Tiered by sensitivity |
| **DNS Integration** | None | dnsXai serves fortress clients |
| **Firewall** | None | nftables per-network rules |
| **Performance** | Default MTU | Jumbo frames for DB |

---

## Next Steps

1. [x] Update podman-compose.yml with new networks
2. [ ] Create TLS certificate generation script
3. [ ] Update dnsmasq to forward to dnsXai
4. [ ] Add nftables rules for container networks
5. [ ] Test inter-container communication
6. [ ] Document troubleshooting procedures
