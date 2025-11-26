# HookProbe Security Mitigation Plan
**AI-Powered Hybrid Edge-to-Cloud Security Architecture**

Version: 5.0 "Liberty"  
Last Updated: November 2025  
Status: Production Ready

---
![SecurityMitigataionPlan](../../assets/xSOC-HLD-v1.2.png)
---

## Executive Summary

HookProbe implements a **zero-trust, AI-driven security architecture** combining edge computing resilience with cloud-scale analytics. This plan addresses the complete attack surface across edge SBCs, encrypted overlay networks, and centralized cloud backends while maintaining sub-second threat response through the Qsecbit AI engine.

**Core Philosophy**: Defense-in-depth with automated response, designed for resource-constrained edge environments and elastic cloud backends.

**Key Differentiators**:
- **Qsecbit AI Analysis**: Real-time threat scoring (0.0-1.0) with RAG classification
- **Automated Kali Response**: On-demand countermeasures for XSS, SQLi, memory attacks
- **Hybrid Architecture**: Edge detection + cloud correlation + distributed enforcement
- **Cost-Optimized**: $150 SBC edge nodes, commodity cloud infrastructure
- **15-Minute Deployment**: Full stack operational in minutes

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Threat Model](#2-threat-model)
3. [Security Zones & Trust Boundaries](#3-security-zones--trust-boundaries)
4. [Control Plane Protection](#4-control-plane-protection)
5. [Network Layer Security](#5-network-layer-security)
6. [Application Layer Defense](#6-application-layer-defense)
7. [AI Threat Detection & Response](#7-ai-threat-detection--response)
8. [Hybrid Cloud Integration](#8-hybrid-cloud-integration)
9. [Operational Security](#9-operational-security)
10. [Compliance & Governance](#10-compliance--governance)
11. [Implementation Roadmap](#11-implementation-roadmap)

---

## 1. Architecture Overview

### 1.1 Hybrid Deployment Model

```
┌─────────────────────────────────────────────────────────────┐
│                    CLOUD BACKEND                             │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Kubernetes Cluster (Proxmox VE)                       │ │
│  │  - ClickHouse Cluster (distributed analytics)         │ │
│  │  - Centralized SIEM/SOAR                               │ │
│  │  - ML Model Training (GPU passthrough)                 │ │
│  │  - Historical Analytics (ClickHouse OLAP)              │ │
│  │  - Policy Orchestration                                │ │
│  │  - Threat Intelligence Aggregation                     │ │
│  └────────────────────────────────────────────────────────┘ │
│                          ▲                                   │
│                          │ Encrypted WireGuard/IPsec        │
│                          │ + mTLS API                        │
└──────────────────────────┼───────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    EDGE NODES (SBCs)                         │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  7-POD Architecture + Optional n8n (Intel N100/ARM64)  │ │
│  │                                                         │ │
│  │  POD 001: Web DMZ + NAXSI WAF                          │ │
│  │  POD 002: IAM (Logto)                                  │ │
│  │  POD 003: Persistent DB (PostgreSQL + ClickHouse)     │ │
│  │  POD 004: Transient Cache (Redis)                     │ │
│  │  POD 005: Monitoring + ClickHouse Edge                 │ │
│  │  POD 006: IDS/IPS (Zeek/Snort3 → ClickHouse)          │ │
│  │  POD 007: Qsecbit AI + Kali Response                   │ │
│  │  POD 008: n8n Workflow Automation (Optional)          │ │
│  │                                                         │ │
│  │  Network: PSK-encrypted VXLAN mesh                     │ │
│  │  Connectivity: LTE/5G failover                         │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 Why This Architecture?

**Edge Computing Benefits**:
- **Low Latency**: Sub-100ms threat detection at the edge
- **Resilience**: Operates offline during cloud connectivity loss
- **Privacy**: Sensitive data stays local; only metadata to cloud
- **Cost**: $150 SBC vs $500+/month cloud compute

**Cloud Backend Benefits**:
- **ClickHouse Analytics**: Billion-row queries in milliseconds (100x faster than PostgreSQL for OLAP)
- **Correlation**: Cross-site threat intelligence with real-time aggregation
- **ML Training**: GPU-accelerated model updates using ClickHouse feature engineering
- **Compliance**: Centralized audit logs with columnar compression (10:1 ratio)
- **Scaling**: Elastic resources for burst analysis, horizontal ClickHouse sharding

**Hybrid Synergy**:
- Edge detects + responds immediately (Qsecbit < 30s cycle)
- Edge ClickHouse buffers logs locally (survives cloud outages)
- Cloud ClickHouse aggregates patterns across all sites (distributed tables)
- Bidirectional policy updates (cloud → edge rules)
- Graceful degradation during network partitions
- Historical analysis on billions of events (ClickHouse materialized views)

---

## 2. Threat Model

### 2.1 Attack Scenarios Addressed

| Threat | Edge Mitigation | Cloud Correlation | Qsecbit Response |
|--------|----------------|-------------------|------------------|
| **XSS Injection** | NAXSI WAF blocks | Pattern analysis across sites | Auto-update WAF rules, block IP |
| **SQL Injection** | Input validation + WAF | Query pattern detection | DB snapshot, emergency rules |
| **Memory Overflow** | Container limits | Resource anomaly detection | Restart with reduced limits |
| **DDoS (L3/L4)** | XDP/eBPF drop | Traffic baseline analysis | Rate limits, temp blacklist |
| **DDoS (L7)** | NAXSI + rate limits | Behavioral fingerprinting | Challenge-response, Cloudflare |
| **Lateral Movement** | VXLAN isolation + nftables | Unusual east-west traffic | Network segmentation, kill switch |
| **Credential Stuffing** | Logto rate limits + MFA | Cross-site credential reuse | Account lockout, CAPTCHA |
| **Container Escape** | Seccomp + AppArmor | Kernel syscall anomalies | Container kill, host isolation |
| **Supply Chain** | Image scanning | Known vuln correlation | Auto-patch, rollback |
| **Insider Threat** | RBAC + audit logs | Privilege escalation patterns | Alert + require approval |

### 2.2 Attack Surface Analysis

**External Attack Surface**:
- HTTP/HTTPS endpoints (POD 001)
- Cloudflare Tunnel (optional, zero-trust)
- LTE/5G data interfaces (NAT + firewall)

**Internal Attack Surface**:
- Container-to-container (VXLAN isolation)
- Host-to-container (cgroup limits)
- Container-to-DB (TLS + auth)
- Management APIs (mTLS + RBAC)

**Supply Chain Surface**:
- Container images (DockerHub, Quay)
- Python packages (PyPI)
- OS packages (DNF repos)
- AI models (HuggingFace, custom)

---

## 3. Security Zones & Trust Boundaries

### 3.1 Network Segmentation (VXLAN VNIs)

| Zone | VNI | Subnet | Trust Level | Purpose | Firewall Policy |
|------|-----|--------|-------------|---------|-----------------|
| **DMZ** | 101 | 10.101.0.0/24 | **Untrusted** | Public web, WAF | Default deny, allowlist HTTP/HTTPS |
| **IAM** | 102 | 10.102.0.0/24 | **Low Trust** | Authentication | Isolated, API only from DMZ |
| **DB-Persistent** | 103 | 10.103.0.0/24 | **High Trust** | PostgreSQL, ClickHouse edge | Only from app tier, TLS enforced |
| **DB-Transient** | 104 | 10.104.0.0/24 | **Medium Trust** | Redis cache | No persistent data, ephemeral |
| **Monitoring** | 105 | 10.105.0.0/24 | **High Trust** | Grafana, VictoriaMetrics, ClickHouse | Read-only from all zones |
| **Security** | 106 | 10.106.0.0/24 | **Highest Trust** | IDS/IPS, ClickHouse security logs | Mirror traffic, no egress |
| **AI Response** | 107 | 10.107.0.0/24 | **Highest Trust** | Qsecbit, Kali | Isolated, API to DMZ only |
| **Automation** | 108 | 10.108.0.0/24 | **Medium Trust** | n8n workflows (optional) | API access to all zones, controlled egress |

### 3.2 Zero-Trust Principles

**Network Access**:
- No implicit trust based on network location
- All zone-to-zone traffic authenticated (mTLS where possible)
- Explicit allowlist rules per service (IP:port pairs)
- Continuous verification via Qsecbit monitoring

**Service Identity**:
- Every container has unique identity (cert-based)
- Short-lived tokens (< 1 hour TTL)
- Mutual TLS for service mesh
- Secrets rotation every 90 days

**Data Access**:
- Principle of least privilege (RBAC)
- Attribute-based access control (ABAC) for AI services
- Data classification (Public, Internal, Confidential, Secret)
- Encryption at rest + in transit

---

## 4. Control Plane Protection

### 4.1 OVS Control Plane Hardening

**Problem**: OVS control plane compromise = complete network bypass

**Mitigations**:

1. **Unix Socket Only** (No TCP)
```bash
# Disable remote ovsdb access
ovs-appctl -t ovsdb-server ovsdb-server/remove-remote ptcp:6640

# Restrict socket permissions
chmod 600 /var/run/openvswitch/db.sock
chown root:openvswitch /var/run/openvswitch/db.sock
```

2. **TLS + Client Certs** (If remote management needed)
```bash
# Generate CA and certs
ovs-pki init
ovs-pki req+sign ovsdb-server switch
ovs-pki req+sign controller

# Enable TLS
ovs-vsctl set-ssl /etc/openvswitch/ovsdb-server-privkey.pem \
  /etc/openvswitch/ovsdb-server-cert.pem \
  /etc/openvswitch/cacert.pem
```

3. **RBAC on Management Host**
```bash
# Only specific mgmt host can access
firewall-cmd --permanent --add-rich-rule='
  rule family="ipv4" 
  source address="192.168.1.100" 
  service name="ovsdb" 
  accept'
```

4. **PSK Rotation** (Automated)
```bash
# Vault-managed PSK rotation script
#!/bin/bash
NEW_PSK=$(vault kv get -field=psk secret/vxlan/main)
ovs-vsctl set Interface vxlan-100 options:psk="$NEW_PSK"
# Rotate every 90 days via cron
```

### 4.2 Kubernetes Control Plane (Cloud Backend)

**Problem**: K8s API server compromise = cluster takeover

**Mitigations**:

1. **API Server Hardening**
```yaml
# kube-apiserver flags
--anonymous-auth=false
--enable-admission-plugins=PodSecurityPolicy,NodeRestriction
--audit-log-path=/var/log/kubernetes/audit.log
--tls-min-version=VersionTLS13
--authorization-mode=Node,RBAC
```

2. **Network Policies** (Default Deny)
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

3. **RBAC Least Privilege**
```yaml
# Example: Monitoring read-only
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: monitoring-reader
rules:
- apiGroups: [""]
  resources: ["pods", "nodes", "services"]
  verbs: ["get", "list", "watch"]
```

4. **Secrets Encryption at Rest**
```yaml
# encryption-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
    - secrets
    providers:
    - aescbc:
        keys:
        - name: key1
          secret: <base64-encoded-32-byte-key>
    - identity: {}
```

---

## 5. Network Layer Security

### 5.1 Per-VNI Anti-Spoofing (OpenFlow)

**Problem**: Containers can spoof source IP/MAC, bypassing ACLs

**Solution**: OpenFlow MAC/IP binding per port

```bash
# Example: POD 001 Django container
# Allowed: MAC=aa:bb:cc:dd:ee:ff, IP=10.101.0.10
# Port: in_port=5 (from ovs-ofctl show br-core)

# Allow only valid traffic
ovs-ofctl add-flow br-core "table=0, priority=100, \
  tun_id=101, in_port=5, \
  dl_src=aa:bb:cc:dd:ee:ff, nw_src=10.101.0.10, \
  actions=normal"

# Drop everything else from this port in VNI 101
ovs-ofctl add-flow br-core "table=0, priority=50, \
  tun_id=101, in_port=5, \
  actions=drop"

# Log drops for monitoring
ovs-ofctl add-flow br-core "table=0, priority=10, \
  tun_id=101, \
  actions=controller"
```

**Automation**: Generate rules from container metadata
```python
# Auto-generate from Podman inspect
import json, subprocess

def generate_antispoofing_rules(pod_name):
    inspect = json.loads(subprocess.check_output([
        'podman', 'inspect', pod_name
    ]))
    
    for container in inspect:
        mac = container['NetworkSettings']['MacAddress']
        ip = container['NetworkSettings']['IPAddress']
        vni = get_vni_from_network(container['NetworkSettings']['Networks'])
        port = get_ovs_port(container['Id'])
        
        subprocess.run([
            'ovs-ofctl', 'add-flow', 'br-core',
            f'table=0,priority=100,tun_id={vni},in_port={port},'
            f'dl_src={mac},nw_src={ip},actions=normal'
        ])
        
        subprocess.run([
            'ovs-ofctl', 'add-flow', 'br-core',
            f'table=0,priority=50,tun_id={vni},in_port={port},'
            f'actions=drop'
        ])
```

### 5.2 ARP/NDP Protection

**Problem**: ARP poisoning allows MITM attacks within VNI

**Solution**: Static ARP + OpenFlow ARP inspection

```bash
# Static ARP for critical hosts (gateways, DB)
arp -s 10.101.0.1 aa:bb:cc:dd:ee:01  # Gateway
arp -s 10.103.0.10 aa:bb:cc:dd:ee:10 # PostgreSQL

# Drop gratuitous ARP (attacker broadcast)
ovs-ofctl add-flow br-core "table=0, priority=200, \
  arp, arp_spa=10.101.0.0/24, arp_tpa=10.101.0.0/24, \
  arp_op=1, \
  actions=controller"  # Log suspicious ARP

# Rate-limit ARP requests
ovs-ofctl add-flow br-core "table=0, priority=150, \
  arp, \
  actions=meter:1,normal"  # Max 100 ARP/sec
```

**IPv6 NDP Protection**:
```bash
# Enable RA guard on host
sysctl -w net.ipv6.conf.all.accept_ra=0

# Drop rogue RA advertisements
ovs-ofctl add-flow br-core "table=0, priority=200, \
  icmp6, icmpv6_type=134, \
  actions=drop"  # Block RA unless from gateway
```

### 5.3 Encrypted Underlay (WireGuard)

**Problem**: VXLAN PSK is weak; traffic visible on underlay

**Solution**: WireGuard mesh between all SBC nodes

```bash
# Generate keys
wg genkey | tee privatekey | wg pubkey > publickey

# /etc/wireguard/wg-hookprobe.conf
[Interface]
Address = 172.16.0.1/24
PrivateKey = <private-key>
ListenPort = 51820

[Peer]
PublicKey = <peer-public-key>
AllowedIPs = 172.16.0.2/32, 10.100.0.0/16
Endpoint = peer.example.com:51820
PersistentKeepalive = 25

# Enable and start
systemctl enable --now wg-quick@wg-hookprobe

# Route VXLAN over WireGuard
ovs-vsctl set Interface vxlan-100 \
  options:remote_ip=172.16.0.2  # WireGuard peer IP
```

**Benefits**:
- ChaCha20-Poly1305 encryption (stronger than PSK)
- Perfect forward secrecy
- Roaming support (for LTE/5G failover)
- Automatic key rotation with rekeying

### 5.4 nftables Layered Firewall

**Default Deny + Explicit Allow**

```bash
# /etc/nftables/hookprobe.nft
table inet filter {
  # Default drop all forwarded traffic
  chain forward {
    type filter hook forward priority 0; policy drop;
    
    # Allow established connections
    ct state established,related accept
    
    # Allow monitoring scrapes (Prometheus → exporters)
    ip saddr 10.105.0.0/24 tcp dport 9100 ct state new accept
    ip saddr 10.105.0.0/24 tcp dport 9090 ct state new accept
    
    # Allow DMZ → IAM (authentication)
    ip saddr 10.101.0.0/24 ip daddr 10.102.0.10 tcp dport 3001 ct state new accept
    
    # Allow DMZ → DB (Django app only)
    ip saddr 10.101.0.10 ip daddr 10.103.0.10 tcp dport 5432 ct state new accept
    
    # Allow DMZ → Redis
    ip saddr 10.101.0.10 ip daddr 10.104.0.10 tcp dport 6379 ct state new accept
    
    # Allow n8n → Django API (for blog publishing)
    ip saddr 10.108.0.10 ip daddr 10.101.0.10 tcp dport 8000 ct state new accept
    
    # Allow n8n → ClickHouse (for analytics)
    ip saddr 10.108.0.10 ip daddr 10.103.0.11 tcp dport 9000 ct state new accept
    
    # Allow n8n → Qsecbit API (for alert enrichment)
    ip saddr 10.108.0.10 ip daddr 10.107.0.13 tcp dport 8888 ct state new accept
    
    # Allow n8n outbound HTTPS (rate limited for external APIs)
    ip saddr 10.108.0.10 tcp dport 443 ct state new limit rate 100/minute accept
    
    # Log drops for SIEM
    log prefix "nft-drop: " drop
  }
  
  # Rate limit SSH to management
  chain input {
    type filter hook input priority 0; policy drop;
    
    # Loopback
    iif lo accept
    
    # SSH with rate limit
    tcp dport 22 ct state new limit rate 5/minute accept
    tcp dport 22 drop  # Drop after rate limit
    
    # Allow established
    ct state established,related accept
    
    # ICMP (ping)
    icmp type echo-request limit rate 10/second accept
    
    # Drop everything else
    log prefix "nft-input-drop: " drop
  }
}

# Load rules
nft -f /etc/nftables/hookprobe.nft

# Make persistent
systemctl enable nftables
```

### 5.5 DDoS Mitigation (XDP/eBPF)

**L3/L4 Volumetric Attacks**

```c
// xdp_ddos_drop.c - Drop SYN floods at NIC
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_drop_syn_flood(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
    
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;
    
    // Drop SYN packets over rate limit
    // (Use eBPF map to track per-IP SYN rate)
    if (tcp->syn && !tcp->ack) {
        // Check rate limit map
        // If over limit: return XDP_DROP
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

**Compile and Load**:
```bash
clang -O2 -target bpf -c xdp_ddos_drop.c -o xdp_ddos_drop.o
ip link set dev eth0 xdp obj xdp_ddos_drop.o sec xdp
```

**L7 DDoS (Application Layer)**:
- NAXSI WAF rate limits
- Cloudflare (if enabled)
- Challenge-response for suspicious IPs

---

## 6. Application Layer Defense

### 6.1 NAXSI WAF Configuration

**Blocking Mode** (Production)

```nginx
# /etc/nginx/naxsi.conf
SecRulesEnabled;
DeniedUrl "/RequestDenied";

# Thresholds (blocking)
CheckRule "$SQL >= 8" BLOCK;
CheckRule "$RCE >= 8" BLOCK;
CheckRule "$TRAVERSAL >= 4" BLOCK;
CheckRule "$XSS >= 8" BLOCK;
CheckRule "$EVADE >= 4" BLOCK;

LearningMode;  # Set to 0 for production blocking
LibInjectionSql;
LibInjectionXss;

# Custom rules (auto-updated by Qsecbit)
include /etc/nginx/naxsi_custom_rules.rules;
```

**Auto-Update from Qsecbit**:
```python
# In Kali response script
def update_naxsi_rules(attack_pattern, attack_type):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    rule_id = f"9{timestamp[:6]}"  # e.g., 9202511
    
    rule = f'''
# Auto-generated {attack_type} rule - {timestamp}
MainRule "str:{attack_pattern}" "msg:{attack_type} blocked" \
  "mz:$ARGS|$BODY" "s:${attack_type}:8" id:{rule_id};
'''
    
    with open('/etc/nginx/naxsi_custom_rules.rules', 'a') as f:
        f.write(rule)
    
    # Reload Nginx
    subprocess.run(['podman', 'exec', 'nginx', 'nginx', '-s', 'reload'])
```

### 6.2 ModSecurity (Alternative/Complement)

```nginx
# /etc/nginx/modsecurity.conf
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off

# OWASP CRS
Include /etc/nginx/modsecurity/crs/crs-setup.conf
Include /etc/nginx/modsecurity/crs/rules/*.conf

# Custom rules
SecRule ARGS "@detectSQLi" \
  "id:1000,phase:2,deny,status:403,msg:'SQL Injection Detected'"

SecRule REQUEST_HEADERS:User-Agent "@contains bot" \
  "id:1001,phase:1,deny,status:403,msg:'Bot Blocked'"
```

### 6.3 Django Security Hardening

**settings.py**:
```python
# Security middleware
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'csp.middleware.CSPMiddleware',  # Content Security Policy
]

# HTTPS enforcement
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True

# Content Security Policy
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "'unsafe-inline'")
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
CSP_IMG_SRC = ("'self'", "data:", "https:")

# Rate limiting (django-ratelimit)
RATELIMIT_ENABLE = True
RATELIMIT_USE_CACHE = 'default'

# Input validation
ALLOWED_HOSTS = ['hookprobe.example.com', '10.101.0.10']
CSRF_TRUSTED_ORIGINS = ['https://hookprobe.example.com']
```

**Rate Limiting**:
```python
from django_ratelimit.decorators import ratelimit

@ratelimit(key='ip', rate='5/m', method='POST')
def login_view(request):
    # Login logic
    pass

@ratelimit(key='user', rate='100/h')
def api_endpoint(request):
    # API logic
    pass
```

### 6.4 Database Security

**PostgreSQL Hardening**:
```sql
-- /var/lib/postgresql/data/postgresql.conf

# Network security
listen_addresses = '10.103.0.10'  # Only internal
ssl = on
ssl_cert_file = '/etc/postgresql/server.crt'
ssl_key_file = '/etc/postgresql/server.key'
ssl_ca_file = '/etc/postgresql/ca.crt'

# Authentication
password_encryption = scram-sha-256

# Logging
log_connections = on
log_disconnections = on
log_statement = 'ddl'  # Log schema changes
log_min_duration_statement = 1000  # Log slow queries

# Query limits
statement_timeout = 60000  # 60 seconds max
```

**pg_hba.conf**:
```
# TYPE  DATABASE  USER          ADDRESS         METHOD
hostssl all       hookprobe_admin 10.101.0.10/32 scram-sha-256
hostssl all       hookprobe_admin 10.102.0.10/32 scram-sha-256
host    all       all             0.0.0.0/0      reject  # Deny all else
```

**Principle of Least Privilege**:
```sql
-- Django app user (limited)
CREATE USER django_app WITH PASSWORD 'strong_password';
GRANT CONNECT ON DATABASE hookprobe_db TO django_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO django_app;
REVOKE CREATE ON SCHEMA public FROM django_app;

-- Read-only monitoring user
CREATE USER monitoring WITH PASSWORD 'strong_password';
GRANT CONNECT ON DATABASE hookprobe_db TO monitoring;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO monitoring;
```

### 6.5 ClickHouse Security Hardening

**Why ClickHouse for HookProbe**:
- **Speed**: 100-1000x faster than PostgreSQL for analytical queries
- **Compression**: 10:1 compression ratio (saves storage on edge SBCs)
- **Real-time**: Materialized views for instant aggregations
- **Scale**: Billions of security events, sub-second queries
- **Cost**: Open-source, no licensing fees

**ClickHouse Configuration** (Edge Node):
```xml
<!-- /etc/clickhouse-server/config.xml -->
<clickhouse>
    <!-- Network security -->
    <listen_host>10.103.0.11</listen_host>
    <https_port>8443</https_port>
    
    <!-- TLS configuration -->
    <openSSL>
        <server>
            <certificateFile>/etc/clickhouse-server/server.crt</certificateFile>
            <privateKeyFile>/etc/clickhouse-server/server.key</privateKeyFile>
            <caConfig>/etc/clickhouse-server/ca.crt</caConfig>
            <verificationMode>strict</verificationMode>
        </server>
    </openSSL>
    
    <!-- User authentication -->
    <users>
        <default>
            <password remove='1'/>
            <access_management>0</access_management>
        </default>
        
        <admin>
            <password_sha256_hex><!-- SHA256 hash --></password_sha256_hex>
            <networks>
                <ip>10.105.0.0/24</ip>  <!-- Monitoring only -->
            </networks>
            <profile>default</profile>
            <quota>default</quota>
        </admin>
        
        <qsecbit>
            <password_sha256_hex><!-- SHA256 hash --></password_sha256_hex>
            <networks>
                <ip>10.107.0.10/32</ip>  <!-- Qsecbit AI only -->
            </networks>
            <profile>readonly</profile>
            <databases>
                <database>security_logs</database>
            </databases>
        </qsecbit>
        
        <grafana>
            <password_sha256_hex><!-- SHA256 hash --></password_sha256_hex>
            <networks>
                <ip>10.105.0.10/32</ip>
            </networks>
            <profile>readonly</profile>
        </grafana>
    </users>
    
    <!-- Query limits -->
    <profiles>
        <default>
            <max_memory_usage>10000000000</max_memory_usage>  <!-- 10GB -->
            <max_execution_time>60</max_execution_time>
            <max_rows_to_read>1000000000</max_rows_to_read>
        </default>
        
        <readonly>
            <readonly>1</readonly>
            <max_memory_usage>5000000000</max_memory_usage>  <!-- 5GB -->
            <max_execution_time>30</max_execution_time>
        </readonly>
    </profiles>
    
    <!-- Logging -->
    <logger>
        <level>information</level>
        <log>/var/log/clickhouse-server/clickhouse-server.log</log>
        <errorlog>/var/log/clickhouse-server/clickhouse-server.err.log</errorlog>
        <size>1000M</size>
        <count>10</count>
    </logger>
    
    <!-- Data retention -->
    <merge_tree>
        <parts_to_throw_insert>300</parts_to_throw_insert>
        <parts_to_delay_insert>150</parts_to_delay_insert>
    </merge_tree>
</clickhouse>
```

**Security Event Schema**:
```sql
-- Create database
CREATE DATABASE IF NOT EXISTS security_logs;

-- Create table with automatic partitioning
CREATE TABLE security_logs.events
(
    timestamp DateTime64(3),
    event_id String,
    site_id String,
    pod_id String,
    severity Enum8('GREEN' = 0, 'AMBER' = 1, 'RED' = 2),
    event_type String,
    source_ip IPv4,
    dest_ip IPv4,
    source_port UInt16,
    dest_port UInt16,
    protocol String,
    qsecbit_score Float32,
    attack_type String,
    waf_action Enum8('PASS' = 0, 'BLOCK' = 1, 'CHALLENGE' = 2),
    raw_log String,
    metadata String  -- JSON metadata
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, severity, site_id)
TTL timestamp + INTERVAL 90 DAY  -- 90-day retention on edge
SETTINGS index_granularity = 8192;

-- Create materialized view for real-time aggregations
CREATE MATERIALIZED VIEW security_logs.attacks_by_hour
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, site_id, attack_type)
AS
SELECT
    toStartOfHour(timestamp) AS hour,
    site_id,
    attack_type,
    severity,
    count() AS attack_count,
    uniq(source_ip) AS unique_attackers,
    avg(qsecbit_score) AS avg_qsecbit
FROM security_logs.events
WHERE event_type = 'ATTACK'
GROUP BY hour, site_id, attack_type, severity;

-- Create view for Grafana dashboard
CREATE VIEW security_logs.dashboard_summary AS
SELECT
    toStartOfInterval(timestamp, INTERVAL 5 MINUTE) AS time_window,
    site_id,
    countIf(severity = 'RED') AS red_alerts,
    countIf(severity = 'AMBER') AS amber_alerts,
    countIf(severity = 'GREEN') AS green_status,
    avg(qsecbit_score) AS avg_qsecbit,
    topK(5)(source_ip) AS top_attackers,
    topK(5)(attack_type) AS top_attack_types
FROM security_logs.events
WHERE timestamp >= now() - INTERVAL 1 HOUR
GROUP BY time_window, site_id
ORDER BY time_window DESC;
```

**Insert Security Events** (from Qsecbit):
```python
# In qsecbit_service.py
from clickhouse_driver import Client

clickhouse_client = Client(
    host='10.103.0.11',
    port=9440,  # Secure native protocol
    user='qsecbit',
    password=os.environ['CLICKHOUSE_PASSWORD'],
    database='security_logs',
    secure=True,
    verify=True,
    ca_certs='/etc/ssl/ca.crt',
    client_name='qsecbit-edge'
)

def log_security_event(sample, attack_data):
    """Log security event to ClickHouse for analysis"""
    event = {
        'timestamp': sample.timestamp,
        'event_id': str(uuid.uuid4()),
        'site_id': SITE_ID,
        'pod_id': '007',
        'severity': sample.rag_status,
        'event_type': 'ATTACK' if sample.rag_status in ['RED', 'AMBER'] else 'NORMAL',
        'source_ip': attack_data.get('attacker_ip', '0.0.0.0'),
        'dest_ip': '10.101.0.10',  # Django app
        'source_port': attack_data.get('source_port', 0),
        'dest_port': 80,
        'protocol': 'HTTP',
        'qsecbit_score': sample.score,
        'attack_type': attack_data.get('attack_type', 'UNKNOWN'),
        'waf_action': attack_data.get('waf_action', 'PASS'),
        'raw_log': attack_data.get('raw_log', ''),
        'metadata': json.dumps(sample.metadata)
    }
    
    clickhouse_client.execute(
        'INSERT INTO security_logs.events VALUES',
        [event]
    )
```

**WAF Log Ingestion** (NAXSI → ClickHouse):
```python
#!/usr/bin/env python3
# /usr/local/bin/naxsi-to-clickhouse.py
import re
from clickhouse_driver import Client

clickhouse = Client(host='10.103.0.11', database='security_logs')

def parse_naxsi_log(line):
    """Parse NAXSI log format"""
    pattern = r'(\d+\.\d+\.\d+\.\d+).*"([^"]+)".*NAXSI_FMT: (.*)'
    match = re.search(pattern, line)
    
    if match:
        ip, request, naxsi_data = match.groups()
        
        # Parse NAXSI fields
        fields = dict(re.findall(r'(\w+)=([^&]+)', naxsi_data))
        
        return {
            'timestamp': datetime.now(),
            'source_ip': ip,
            'attack_type': fields.get('id', 'UNKNOWN'),
            'severity': 'AMBER' if int(fields.get('score', 0)) >= 8 else 'GREEN',
            'waf_action': 'BLOCK',
            'raw_log': line
        }

# Tail NAXSI log and insert to ClickHouse
with open('/var/log/nginx/naxsi.log', 'r') as f:
    f.seek(0, 2)  # Go to end
    while True:
        line = f.readline()
        if line:
            event = parse_naxsi_log(line)
            if event:
                clickhouse.execute('INSERT INTO security_logs.events VALUES', [event])
```

**IDS/IPS Integration** (Zeek/Snort3 → ClickHouse):
```python
# Zeek notice.log to ClickHouse
def zeek_to_clickhouse(notice_log):
    """Convert Zeek notice.log to ClickHouse format"""
    with open(notice_log) as f:
        for line in f:
            if line.startswith('#'):
                continue
            
            fields = line.strip().split('\t')
            
            event = {
                'timestamp': datetime.fromtimestamp(float(fields[0])),
                'source_ip': fields[2],
                'dest_ip': fields[4],
                'source_port': int(fields[3]) if fields[3] != '-' else 0,
                'dest_port': int(fields[5]) if fields[5] != '-' else 0,
                'protocol': fields[6],
                'attack_type': fields[8],  # Zeek notice type
                'severity': 'RED' if 'critical' in fields[8].lower() else 'AMBER',
                'raw_log': line
            }
            
            clickhouse.execute('INSERT INTO security_logs.events VALUES', [event])
```

**ClickHouse Distributed Architecture** (Cloud):
```xml
<!-- Cloud ClickHouse cluster configuration -->
<remote_servers>
    <hookprobe_cluster>
        <shard>
            <replica>
                <host>clickhouse-01.internal</host>
                <port>9000</port>
            </replica>
            <replica>
                <host>clickhouse-02.internal</host>
                <port>9000</port>
            </replica>
        </shard>
        <shard>
            <replica>
                <host>clickhouse-03.internal</host>
                <port>9000</port>
            </replica>
            <replica>
                <host>clickhouse-04.internal</host>
                <port>9000</port>
            </replica>
        </shard>
    </hookprobe_cluster>
</remote_servers>
```

**Distributed Table** (aggregates from all edge sites):
```sql
-- On cloud ClickHouse cluster
CREATE TABLE security_logs.events_distributed AS security_logs.events
ENGINE = Distributed(hookprobe_cluster, security_logs, events, rand());

-- Query across all sites
SELECT
    site_id,
    count() AS total_events,
    countIf(severity = 'RED') AS critical_events,
    topK(10)(source_ip) AS top_attackers
FROM security_logs.events_distributed
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY site_id
ORDER BY critical_events DESC;
```

**ClickHouse Security Best Practices**:

1. **Network Isolation**: Only allow from specific IPs
2. **TLS Everywhere**: Native protocol + HTTPS
3. **User Segmentation**: Different users for each service
4. **Query Limits**: Prevent resource exhaustion
5. **Read Replicas**: Separate query load from ingestion
6. **Backup Strategy**: Incremental backups to S3-compatible storage
7. **Monitoring**: Track query performance, disk usage, replication lag

### 6.6 n8n Workflow Automation Security (Optional POD 008)

**Why n8n for HookProbe**:
- **Content Automation**: Autonomous blog posting for vertical #1
- **Security Orchestration**: Enhanced SOAR workflows beyond Kali scripts
- **Web Scraping**: Threat intelligence gathering from public sources
- **API Integration**: MCP (Model Context Protocol) for AI content generation
- **No-Code**: Visual workflow builder for rapid iteration
- **Self-Hosted**: Complete data control, no external dependencies

**Threat Model for n8n**:
- **Risk**: n8n has broad API access across all zones
- **Risk**: Credentials stored for external services (Claude API, social media)
- **Risk**: Webhook endpoints could be exploited for unauthorized workflow execution
- **Risk**: Malicious workflows could exfiltrate data or pivot laterally

**n8n Security Hardening**:

```yaml
# docker-compose.yml for n8n (POD 008)
version: '3.8'

services:
  n8n:
    image: n8nio/n8n:latest
    container_name: hookprobe-pod-008-n8n
    restart: unless-stopped
    
    environment:
      # Security settings
      - N8N_BASIC_AUTH_ACTIVE=true
      - N8N_BASIC_AUTH_USER=admin
      - N8N_BASIC_AUTH_PASSWORD=${N8N_PASSWORD}  # Strong password from Vault
      
      # Encryption
      - N8N_ENCRYPTION_KEY=${N8N_ENCRYPTION_KEY}  # AES-256 key from Vault
      
      # Network security
      - N8N_HOST=10.108.0.10
      - N8N_PORT=5678
      - N8N_PROTOCOL=https
      - N8N_SSL_KEY=/certs/n8n.key
      - N8N_SSL_CERT=/certs/n8n.crt
      
      # Webhook security
      - WEBHOOK_URL=https://hookprobe.example.com/webhook
      - N8N_PAYLOAD_SIZE_MAX=16  # 16MB max
      
      # Execution settings
      - EXECUTIONS_TIMEOUT=300  # 5 min max per workflow
      - EXECUTIONS_TIMEOUT_MAX=600  # 10 min absolute max
      - N8N_METRICS=true  # Enable Prometheus metrics
      
      # Database
      - DB_TYPE=postgresdb
      - DB_POSTGRESDB_HOST=10.103.0.10
      - DB_POSTGRESDB_PORT=5432
      - DB_POSTGRESDB_DATABASE=n8n_db
      - DB_POSTGRESDB_USER=n8n_user
      - DB_POSTGRESDB_PASSWORD=${N8N_DB_PASSWORD}
      - DB_POSTGRESDB_SSL_ENABLED=true
      - DB_POSTGRESDB_SSL_REJECT_UNAUTHORIZED=true
    
    volumes:
      - n8n-data:/home/node/.n8n
      - /etc/ssl/n8n:/certs:ro
    
    networks:
      - pod-008-automation-net
    
    labels:
      - "podman.io/security.audit=true"
      - "podman.io/security.role=automation"

volumes:
  n8n-data:

networks:
  pod-008-automation-net:
    driver: bridge
```

**Network Firewall Rules for n8n**:

```bash
# Allow n8n to access specific services only
nft add rule inet filter forward \
  ip saddr 10.108.0.10 ip daddr 10.101.0.10 tcp dport 8000 ct state new accept  # Django API

nft add rule inet filter forward \
  ip saddr 10.108.0.10 ip daddr 10.103.0.11 tcp dport 9000 ct state new accept  # ClickHouse

nft add rule inet filter forward \
  ip saddr 10.108.0.10 ip daddr 10.107.0.13 tcp dport 8888 ct state new accept  # Qsecbit API

# Block n8n from accessing sensitive databases directly
nft add rule inet filter forward \
  ip saddr 10.108.0.10 ip daddr 10.103.0.10 tcp dport 5432 ct state new drop  # PostgreSQL

# Allow outbound HTTPS for external APIs (Claude, social media)
nft add rule inet filter forward \
  ip saddr 10.108.0.10 tcp dport 443 ct state new limit rate 100/minute accept

# Log all n8n traffic for audit
nft add rule inet filter forward \
  ip saddr 10.108.0.10 log prefix "n8n-traffic: "
```

**Credential Management** (Vault Integration):

```python
# n8n custom node: vault-credential-provider.py
import hvac
import os

class VaultCredentialProvider:
    """Fetch credentials from HashiCorp Vault instead of n8n storage"""
    
    def __init__(self):
        self.client = hvac.Client(
            url='https://vault.example.com:8200',
            token=os.environ['VAULT_TOKEN']
        )
    
    def get_credential(self, path):
        """Get credential from Vault"""
        secret = self.client.secrets.kv.v2.read_secret_version(path=path)
        return secret['data']['data']
    
    def get_claude_api_key(self):
        """Get Claude API key for content generation"""
        return self.get_credential('n8n/claude-api')['api_key']
    
    def get_social_media_tokens(self):
        """Get social media OAuth tokens"""
        return {
            'twitter': self.get_credential('n8n/twitter')['oauth_token'],
            'linkedin': self.get_credential('n8n/linkedin')['access_token'],
            'github': self.get_credential('n8n/github')['personal_token']
        }
```

**n8n Security Workflows**:

**Workflow 1: Autonomous Blog Publishing**
```json
{
  "name": "Autonomous Blog Content Generation",
  "nodes": [
    {
      "name": "Schedule Trigger",
      "type": "n8n-nodes-base.scheduleTrigger",
      "parameters": {
        "rule": {
          "interval": [{"field": "hours", "value": 24}]
        }
      }
    },
    {
      "name": "Check Visitor Traffic",
      "type": "n8n-nodes-base.httpRequest",
      "parameters": {
        "url": "http://10.103.0.11:8123",
        "method": "POST",
        "jsonParameters": true,
        "bodyParametersJson": "SELECT count() FROM security_logs.events WHERE timestamp >= now() - INTERVAL 24 HOUR"
      }
    },
    {
      "name": "Generate Content via Claude",
      "type": "n8n-nodes-base.httpRequest",
      "parameters": {
        "url": "https://api.anthropic.com/v1/messages",
        "method": "POST",
        "authentication": "predefinedCredentialType",
        "nodeCredentialType": "anthropicApi",
        "headerParameters": {
          "anthropic-version": "2023-06-01"
        },
        "bodyParametersJson": {
          "model": "claude-sonnet-4-20250514",
          "max_tokens": 4096,
          "messages": [
            {
              "role": "user",
              "content": "Generate a cybersecurity blog post about {{$json.top_attack_type}} based on recent traffic patterns. Focus on SMB/home user defense strategies."
            }
          ]
        }
      }
    },
    {
      "name": "Publish to Django CMS",
      "type": "n8n-nodes-base.httpRequest",
      "parameters": {
        "url": "http://10.101.0.10:8000/api/cms/pages/",
        "method": "POST",
        "authentication": "predefinedCredentialType",
        "nodeCredentialType": "djangoApi",
        "bodyParametersJson": {
          "title": "{{$json.title}}",
          "content": "{{$json.content}}",
          "template": "blog.html",
          "published": true,
          "seo_meta": {
            "description": "{{$json.description}}",
            "keywords": "{{$json.keywords}}"
          }
        }
      }
    },
    {
      "name": "Post to Social Media",
      "type": "n8n-nodes-base.twitter",
      "parameters": {
        "operation": "tweet",
        "text": "New blog post: {{$json.title}} {{$json.url}} #cybersecurity #infosec"
      }
    },
    {
      "name": "Log to ClickHouse",
      "type": "n8n-nodes-base.httpRequest",
      "parameters": {
        "url": "http://10.103.0.11:8123",
        "method": "POST",
        "bodyParametersJson": "INSERT INTO automation_logs.workflow_executions VALUES ('{{$now}}', 'blog_generation', 'success', '{{$json.page_id}}')"
      }
    }
  ]
}
```

**Workflow 2: Threat Intelligence Scraping**
```json
{
  "name": "Threat Intel Web Scraping",
  "nodes": [
    {
      "name": "Schedule Every 6 Hours",
      "type": "n8n-nodes-base.scheduleTrigger",
      "parameters": {
        "rule": {"interval": [{"field": "hours", "value": 6}]}
      }
    },
    {
      "name": "Scrape AlienVault OTX",
      "type": "n8n-nodes-base.httpRequest",
      "parameters": {
        "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "method": "GET",
        "authentication": "predefinedCredentialType",
        "nodeCredentialType": "otxApi"
      }
    },
    {
      "name": "Filter Critical IOCs",
      "type": "n8n-nodes-base.function",
      "parameters": {
        "functionCode": "const criticalIOCs = items.filter(item => item.json.pulse_info.tlp === 'red');\nreturn criticalIOCs;"
      }
    },
    {
      "name": "Update Firewall Rules",
      "type": "n8n-nodes-base.httpRequest",
      "parameters": {
        "url": "http://10.107.0.13:8888/api/firewall/bulk-block",
        "method": "POST",
        "bodyParametersJson": {
          "ips": "{{$json.indicators.IPv4}}",
          "reason": "AlienVault OTX - {{$json.name}}",
          "expires": "{{$now.plus(24, 'hours')}}"
        }
      }
    }
  ]
}
```

**Workflow 3: Security Alert Enrichment**
```json
{
  "name": "Qsecbit Alert Enrichment",
  "nodes": [
    {
      "name": "Webhook - Qsecbit RED Alert",
      "type": "n8n-nodes-base.webhook",
      "parameters": {
        "path": "qsecbit-alert",
        "authentication": "headerAuth",
        "headerAuthName": "X-Webhook-Secret",
        "headerAuthValue": "{{$env.WEBHOOK_SECRET}}"
      }
    },
    {
      "name": "Query ClickHouse - Attacker History",
      "type": "n8n-nodes-base.httpRequest",
      "parameters": {
        "url": "http://10.103.0.11:8123",
        "method": "POST",
        "bodyParametersJson": "SELECT count() AS prev_attacks, groupArray(attack_type) AS attack_types FROM security_logs.events WHERE source_ip = '{{$json.attacker_ip}}' AND timestamp >= now() - INTERVAL 30 DAY"
      }
    },
    {
      "name": "GeoIP Lookup",
      "type": "n8n-nodes-base.httpRequest",
      "parameters": {
        "url": "https://ipapi.co/{{$json.attacker_ip}}/json/"
      }
    },
    {
      "name": "Check Threat Intel",
      "type": "n8n-nodes-base.httpRequest",
      "parameters": {
        "url": "https://otx.alienvault.com/api/v1/indicators/IPv4/{{$json.attacker_ip}}/general"
      }
    },
    {
      "name": "Send Enriched Alert",
      "type": "n8n-nodes-base.httpRequest",
      "parameters": {
        "url": "http://10.101.0.10:8000/api/alerts/",
        "method": "POST",
        "bodyParametersJson": {
          "severity": "RED",
          "attacker_ip": "{{$json.attacker_ip}}",
          "previous_attacks": "{{$node['ClickHouse'].json.prev_attacks}}",
          "geolocation": "{{$node['GeoIP'].json.country_name}}",
          "known_malicious": "{{$node['ThreatIntel'].json.pulse_info.count > 0}}",
          "recommended_action": "Immediate block + incident investigation"
        }
      }
    }
  ]
}
```

**n8n Access Control**:

```javascript
// Custom middleware for n8n webhook authentication
const crypto = require('crypto');

function validateWebhookSignature(req, res, next) {
    const signature = req.headers['x-webhook-signature'];
    const payload = JSON.stringify(req.body);
    
    const hmac = crypto.createHmac('sha256', process.env.WEBHOOK_SECRET);
    const expectedSignature = hmac.update(payload).digest('hex');
    
    if (signature !== expectedSignature) {
        return res.status(403).json({error: 'Invalid signature'});
    }
    
    // Log webhook access to ClickHouse
    logWebhookAccess(req.ip, req.body);
    
    next();
}
```

**n8n Monitoring**:

```yaml
# Prometheus scrape config for n8n metrics
scrape_configs:
  - job_name: 'n8n'
    static_configs:
      - targets: ['10.108.0.10:5678']
    metrics_path: '/metrics'
    scheme: https
    tls_config:
      ca_file: /etc/ssl/ca.crt
```

**Security Best Practices for n8n**:

1. **Credential Isolation**: Never store credentials in n8n database - use Vault
2. **Webhook Authentication**: Always use HMAC signatures or API keys
3. **Network Segmentation**: n8n in isolated VNI with strict firewall rules
4. **Workflow Validation**: Code review all workflows before production
5. **Rate Limiting**: Limit webhook execution rate to prevent abuse
6. **Audit Logging**: Log all workflow executions to ClickHouse
7. **Execution Timeouts**: Prevent infinite loops (5 min default, 10 min max)
8. **Input Validation**: Sanitize all external data before processing
9. **TLS Everywhere**: HTTPS for n8n UI, encrypt DB connections
10. **Regular Updates**: Keep n8n patched for security vulnerabilities

**Threat Scenarios & Mitigations**:

| Threat | Mitigation |
|--------|-----------|
| **Credential Theft** | Vault integration, no plaintext storage |
| **Malicious Workflow** | Code review, execution limits, network restrictions |
| **Webhook Abuse** | HMAC signatures, rate limiting, IP allowlisting |
| **Data Exfiltration** | Egress firewall rules, audit all external API calls |
| **Lateral Movement** | VNI isolation, no direct DB access, API-only communication |
| **Resource Exhaustion** | Execution timeouts, memory limits, concurrent workflow caps |

---

## 7. AI Threat Detection & Response

### 7.1 Qsecbit Algorithm

**Purpose**: Real-time cyber resilience metric combining:
1. **System Drift** (Mahalanobis distance from baseline)
2. **Attack Probability** (ML classifier output)
3. **Classifier Decay** (rate of confidence change)
4. **Quantum Drift** (entropy deviation)

**Formula**:
```
R = α·drift(x_t) + β·P(attack) + γ·decay(c_t) + δ·qdrift(q_t)

Where:
- α, β, γ, δ = weights (sum to 1.0)
- drift(x_t) = normalized Mahalanobis distance
- P(attack) = ML model output [0, 1]
- decay(c_t) = rate of classifier confidence change
- qdrift(q_t) = entropy deviation from baseline
```

**RAG Classification**:
- **GREEN**: R < 0.45 (normal operation)
- **AMBER**: 0.45 ≤ R < 0.70 (warning)
- **RED**: R ≥ 0.70 (critical threat)

**Configuration** (network-config.sh):
```bash
QSECBIT_ALPHA=0.30       # System drift weight
QSECBIT_BETA=0.30        # Attack probability weight
QSECBIT_GAMMA=0.20       # Classifier decay weight
QSECBIT_DELTA=0.20       # Quantum drift weight

QSECBIT_AMBER_THRESHOLD=0.45
QSECBIT_RED_THRESHOLD=0.70

QSECBIT_CHECK_INTERVAL=30  # Seconds between calculations
```

### 7.2 Automated Response Playbooks

**XSS Injection Response** (kali-response-scripts.sh):
```bash
anti_xss_response() {
    local ATTACK_IP=$1
    local ATTACK_PATTERN=$2
    
    # 1. Update NAXSI WAF rules
    echo "MainRule \"str:${ATTACK_PATTERN}\" \"msg:XSS blocked\" \
      \"mz:\$ARGS|\$BODY\" \"s:\$XSS:8\" id:9$(date +%y%m%d);" \
      >> /etc/nginx/naxsi_custom_rules.rules
    
    # 2. Block attacker IP (temporary 1 hour)
    iptables -I INPUT -s $ATTACK_IP -j DROP
    echo "iptables -D INPUT -s $ATTACK_IP -j DROP" | \
      at now + 1 hour
    
    # 3. Scan attacker
    nmap -sV -O $ATTACK_IP > /reports/attacker_scan_$(date +%s).txt
    
    # 4. Alert SIEM
    logger -t hookprobe-qsecbit \
      "XSS attack blocked: IP=$ATTACK_IP pattern=$ATTACK_PATTERN"
    
    # 5. Reload WAF
    podman exec nginx nginx -s reload
}
```

**SQL Injection Response**:
```bash
anti_sql_injection_response() {
    local ATTACK_IP=$1
    local SQL_QUERY=$2
    
    # 1. Emergency DB snapshot
    pg_dump -h 10.103.0.10 -U hookprobe_admin -d hookprobe_db \
      > /reports/db_snapshot_$(date +%s).sql
    
    # 2. Update WAF rules
    echo "MainRule \"rx:union.*select\" \"msg:SQLi blocked\" \
      \"mz:\$ARGS|\$BODY\" \"s:\$SQL:8\" id:8$(date +%y%m%d);" \
      >> /etc/nginx/naxsi_custom_rules.rules
    
    # 3. Block IP
    iptables -I INPUT -s $ATTACK_IP -j DROP
    
    # 4. Enable detailed DB logging
    psql -h 10.103.0.10 -U postgres -c \
      "ALTER SYSTEM SET log_statement = 'all';"
    psql -h 10.103.0.10 -U postgres -c \
      "SELECT pg_reload_conf();"
    
    # 5. Run sqlmap scan on attacker
    sqlmap -u "http://${ATTACK_IP}" --batch \
      > /reports/sqlmap_$(date +%s).txt
}
```

**Memory Overflow Response**:
```bash
memory_attack_response() {
    local AFFECTED_CONTAINER=$1
    
    # 1. Capture diagnostics
    podman stats --no-stream > /reports/memory_stats_$(date +%s).txt
    
    # 2. Reduce memory limit to 50%
    CURRENT_MEMORY=$(podman inspect $AFFECTED_CONTAINER | \
      jq '.[0].HostConfig.Memory')
    NEW_MEMORY_LIMIT=$((CURRENT_MEMORY / 2))
    
    podman update --memory=${NEW_MEMORY_LIMIT} $AFFECTED_CONTAINER
    
    # 3. Clear caches
    if [[ $AFFECTED_CONTAINER == *"redis"* ]]; then
        podman exec $AFFECTED_CONTAINER redis-cli FLUSHALL
    fi
    
    # 4. Restart with new limits
    podman restart $AFFECTED_CONTAINER
}
```

### 7.3 On-Demand Kali Linux

**Spin-Up Logic** (qsecbit_service.py):
```python
def trigger_kali_response(sample):
    if sample.rag_status in ['RED', 'AMBER']:
        # Check if Kali is already running
        result = subprocess.run(
            ['podman', 'ps', '--filter', 'name=kali', '--format', '{{.Names}}'],
            capture_output=True, text=True
        )
        
        if 'kali' not in result.stdout:
            print("🚀 Spinning up Kali Linux response container...")
            subprocess.run([
                'podman', 'start', 'hookprobe-pod-007-ai-response-kali'
            ])
            
            # Wait for initialization
            time.sleep(10)
        
        # Execute response script
        attack_type = determine_attack_type(sample)
        subprocess.run([
            'podman', 'exec', 'hookprobe-pod-007-ai-response-kali',
            '/tools/kali-response-scripts.sh', attack_type
        ])
        
        # Schedule auto-shutdown after cooldown
        schedule_kali_shutdown(cooldown_minutes=30)
```

**Resource Efficiency**:
- Kali only runs during threats (saves ~2GB RAM)
- Cooldown period prevents thrashing (30 min default)
- Auto-shutdown after GREEN status for 1 hour

### 7.4 Cloud Correlation (Hybrid Intelligence)

**Edge → Cloud Telemetry**:
```python
# In qsecbit_service.py
def send_to_cloud_siem(sample):
    payload = {
        'site_id': SITE_ID,
        'timestamp': sample.timestamp.isoformat(),
        'qsecbit_score': sample.score,
        'rag_status': sample.rag_status,
        'components': sample.components,
        'attack_type': sample.metadata.get('attack_type'),
        'attacker_ip': sample.metadata.get('attacker_ip')
    }
    
    # Send via encrypted WireGuard tunnel + mTLS
    response = requests.post(
        'https://cloud-siem.example.com/api/v1/ingest',
        json=payload,
        cert=('/etc/ssl/client.crt', '/etc/ssl/client.key'),
        verify='/etc/ssl/ca.crt'
    )
```

**Cloud → Edge Policy Updates**:
```python
# Cloud backend identifies cross-site attack pattern
def push_policy_update(rule_type, rule_data):
    for edge_node in get_active_edge_nodes():
        requests.post(
            f'https://{edge_node}/api/policy/update',
            json={
                'rule_type': rule_type,  # 'naxsi', 'iptables', 'openflow'
                'rule_data': rule_data,
                'priority': 100,
                'expires': datetime.now() + timedelta(hours=24)
            },
            cert=('/etc/ssl/cloud.crt', '/etc/ssl/cloud.key')
        )
```

---

## 8. Hybrid Cloud Integration

### 8.1 Proxmox VE Backend Architecture

**Why Proxmox Over VMware**:
- **Cost Savings**: €52,000+ annually (no licensing fees)
- **Open Source**: Auditable, extensible
- **GPU Passthrough**: For ML model training
- **ZFS/Ceph**: Enterprise storage without SAN costs

**Kubernetes on Proxmox**:
```yaml
# proxmox-k8s-cluster.yml (Terraform)
resource "proxmox_vm_qemu" "k8s_master" {
  count = 3
  name  = "k8s-master-${count.index + 1}"
  
  cores   = 8
  memory  = 32768
  sockets = 1
  
  # GPU passthrough for ML workloads
  hostpci0 = "0000:01:00,pcie=1"  # NVIDIA GPU
  
  # Network
  network {
    model  = "virtio"
    bridge = "vmbr0"
  }
  
  # Disk
  disk {
    type    = "scsi"
    storage = "local-zfs"
    size    = "200G"
    ssd     = 1
  }
}

resource "proxmox_vm_qemu" "k8s_worker" {
  count = 5
  name  = "k8s-worker-${count.index + 1}"
  
  cores   = 16
  memory  = 65536
  sockets = 1
  
  # Network
  network {
    model  = "virtio"
    bridge = "vmbr0"
  }
  
  # Disk
  disk {
    type    = "scsi"
    storage = "ceph-pool"  # Distributed storage
    size    = "500G"
    ssd     = 1
  }
}
```

### 8.2 Edge-to-Cloud Connectivity

**WireGuard VPN Mesh**:
```bash
# Edge node config
[Interface]
Address = 172.16.0.10/24
PrivateKey = <edge-private-key>

[Peer]
PublicKey = <cloud-public-key>
Endpoint = cloud.example.com:51820
AllowedIPs = 172.16.0.0/24, 10.200.0.0/16  # Cloud K8s network
PersistentKeepalive = 25
```

**LTE/5G Failover**:
```bash
# ModemManager + NetworkManager setup
nmcli connection add type gsm ifname '*' con-name lte-backup \
  apn internet.provider.com autoconnect yes

# Routing priority (prefer wired, fallback to LTE)
ip route add default via 192.168.1.1 dev eth0 metric 100
ip route add default via 10.64.64.64 dev wwan0 metric 200
```

### 8.3 Centralized SIEM (Cloud)

**Architecture**:
```
Edge Nodes (ClickHouse) → WireGuard → Cloud K8s → ClickHouse Cluster → Grafana
                                                ↓
                                         Correlation Engine (ClickHouse materialized views)
                                                ↓
                                         Policy Orchestrator
```

**ClickHouse Cluster Deployment** (Kubernetes):
```yaml
apiVersion: clickhouse.altinity.com/v1
kind: ClickHouseInstallation
metadata:
  name: hookprobe-siem
spec:
  configuration:
    clusters:
      - name: hookprobe-cluster
        layout:
          shardsCount: 4
          replicasCount: 2
    
    users:
      admin/password_sha256_hex: "<!-- SHA256 hash -->"
      admin/networks/ip:
        - "10.200.0.0/16"  # K8s network
      
      grafana/password_sha256_hex: "<!-- SHA256 hash -->"
      grafana/profile: readonly
      grafana/networks/ip:
        - "10.200.0.0/16"
    
    profiles:
      readonly:
        readonly: 1
        max_memory_usage: 10000000000
        max_execution_time: 60
    
    settings:
      compression/case/method: zstd
      
    files:
      tls/server.crt: |
        -----BEGIN CERTIFICATE-----
        ...
        -----END CERTIFICATE-----
      tls/server.key: |
        -----BEGIN PRIVATE KEY-----
        ...
        -----END PRIVATE KEY-----
  
  templates:
    podTemplates:
      - name: clickhouse-template
        spec:
          containers:
            - name: clickhouse
              image: clickhouse/clickhouse-server:23.8
              resources:
                requests:
                  memory: "16Gi"
                  cpu: "4"
                limits:
                  memory: "32Gi"
                  cpu: "8"
              volumeMounts:
                - name: data
                  mountPath: /var/lib/clickhouse
          
          volumes:
            - name: data
              persistentVolumeClaim:
                claimName: clickhouse-data
    
    volumeClaimTemplates:
      - name: data
        spec:
          accessModes:
            - ReadWriteOnce
          resources:
            requests:
              storage: 1Ti
          storageClassName: ceph-block
```

**Edge-to-Cloud Replication**:
```sql
-- On edge ClickHouse
CREATE TABLE security_logs.events_buffer AS security_logs.events
ENGINE = Buffer(security_logs, events, 16, 10, 100, 10000, 1000000, 10000000, 100000000);

-- Replicate to cloud via Kafka or direct insert
CREATE TABLE security_logs.events_cloud
ENGINE = Kafka()
SETTINGS
    kafka_broker_list = 'cloud-kafka.example.com:9093',
    kafka_topic_list = 'security-events',
    kafka_group_name = 'edge-replicator',
    kafka_format = 'JSONEachRow',
    kafka_skip_broken_messages = 100;

-- Materialized view to push data to Kafka
CREATE MATERIALIZED VIEW security_logs.to_cloud TO security_logs.events_cloud AS
SELECT * FROM security_logs.events;
```

**Alternative: Direct HTTPS Insert** (for low-volume edge sites):
```python
# In qsecbit_service.py
import requests

def replicate_to_cloud(events):
    """Batch insert to cloud ClickHouse"""
    response = requests.post(
        'https://clickhouse-cloud.example.com:8443/',
        params={
            'database': 'security_logs',
            'query': 'INSERT INTO events_distributed FORMAT JSONEachRow'
        },
        data='\n'.join(json.dumps(e) for e in events),
        auth=('edge-replicator', os.environ['CLICKHOUSE_CLOUD_PASSWORD']),
        headers={'X-ClickHouse-User': 'edge-replicator'},
        verify='/etc/ssl/ca.crt'
    )
    
    if response.status_code != 200:
        logger.error(f"Failed to replicate: {response.text}")
```

**Cross-Site Correlation** (ClickHouse SQL):
```sql
-- Find coordinated attacks (same IP across multiple sites)
SELECT
    source_ip,
    groupArray(site_id) AS affected_sites,
    count(DISTINCT site_id) AS site_count,
    count() AS total_attacks,
    groupArray(attack_type) AS attack_types,
    max(qsecbit_score) AS max_qsecbit,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen
FROM security_logs.events_distributed
WHERE timestamp >= now() - INTERVAL 1 HOUR
  AND severity IN ('RED', 'AMBER')
GROUP BY source_ip
HAVING site_count >= 3  -- Attacked 3+ sites
ORDER BY total_attacks DESC
LIMIT 100;

-- Create materialized view for real-time correlation
CREATE MATERIALIZED VIEW security_logs.coordinated_attacks
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMMDD(hour)
ORDER BY (hour, source_ip)
AS
SELECT
    toStartOfHour(timestamp) AS hour,
    source_ip,
    uniqState(site_id) AS unique_sites,
    countState() AS attack_count,
    maxState(qsecbit_score) AS max_qsecbit
FROM security_logs.events_distributed
WHERE severity IN ('RED', 'AMBER')
GROUP BY hour, source_ip;

-- Query coordinated attacks in real-time
SELECT
    hour,
    source_ip,
    uniqMerge(unique_sites) AS sites_attacked,
    countMerge(attack_count) AS total_attacks,
    maxMerge(max_qsecbit) AS worst_qsecbit
FROM security_logs.coordinated_attacks
WHERE hour >= now() - INTERVAL 24 HOUR
  AND uniqMerge(unique_sites) >= 3
ORDER BY total_attacks DESC;
```

**Policy Orchestrator** (Python + ClickHouse):
```python
def detect_and_respond_to_coordinated_attacks():
    """Query ClickHouse for coordinated attacks and push global block policy"""
    
    query = """
    SELECT
        source_ip,
        uniqMerge(unique_sites) AS sites,
        countMerge(attack_count) AS attacks
    FROM security_logs.coordinated_attacks
    WHERE hour >= now() - INTERVAL 1 HOUR
      AND uniqMerge(unique_sites) >= 3
    ORDER BY attacks DESC
    LIMIT 100
    """
    
    results = clickhouse_cloud.execute(query)
    
    for row in results:
        source_ip, sites, attacks = row
        
        if attacks >= 10:  # High-volume coordinated attack
            logger.warning(f"Coordinated attack detected: {source_ip} targeted {sites} sites")
            
            # Push global block policy to all edge nodes
            for edge_node in get_active_edge_nodes():
                push_firewall_rule(
                    edge_node=edge_node,
                    rule={
                        'action': 'DROP',
                        'source_ip': source_ip,
                        'priority': 100,
                        'expires': datetime.now() + timedelta(hours=24),
                        'reason': f'Coordinated attack: {attacks} attacks across {sites} sites'
                    }
                )

def push_firewall_rule(edge_node, rule):
    """Push firewall rule to edge node via API"""
    response = requests.post(
        f'https://{edge_node}/api/firewall/rules',
        json=rule,
        cert=('/etc/ssl/cloud.crt', '/etc/ssl/cloud.key'),
        verify=True
    )
    
    if response.status_code == 200:
        logger.info(f"Rule pushed to {edge_node}: {rule}")
```

**ClickHouse Performance Tuning**:
```sql
-- Optimize table (merge parts)
OPTIMIZE TABLE security_logs.events FINAL;

-- Check table statistics
SELECT
    partition,
    count() AS parts,
    formatReadableSize(sum(bytes_on_disk)) AS size,
    sum(rows) AS total_rows
FROM system.parts
WHERE database = 'security_logs' AND table = 'events'
GROUP BY partition
ORDER BY partition DESC;

-- Monitor query performance
SELECT
    query_id,
    user,
    query_duration_ms,
    read_rows,
    formatReadableSize(read_bytes) AS read_size,
    result_rows,
    memory_usage
FROM system.query_log
WHERE type = 'QueryFinish'
  AND event_time >= now() - INTERVAL 1 HOUR
ORDER BY query_duration_ms DESC
LIMIT 20;
```

### 8.4 ML Model Training (Cloud GPU)

**GPU Passthrough for TensorFlow**:
```yaml
# k8s-ml-training-job.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: qsecbit-model-training
spec:
  template:
    spec:
      containers:
      - name: tensorflow
        image: tensorflow/tensorflow:latest-gpu
        resources:
          limits:
            nvidia.com/gpu: 1  # Request 1 GPU
        volumeMounts:
        - name: training-data
          mountPath: /data
        command: ["python", "train_qsecbit_model.py"]
      volumes:
      - name: training-data
        persistentVolumeClaim:
          claimName: edge-telemetry-pvc
      restartPolicy: Never
```

**Model Distribution**:
```bash
# After training, push model to edge nodes
scp qsecbit_model_v2.pkl edge-node-01:/mnt/qsecbit-models/
ssh edge-node-01 "podman exec qsecbit \
  cp /models/qsecbit_model_v2.pkl /models/active/ && \
  systemctl restart qsecbit"
```

---

## 9. Operational Security

### 9.1 Secrets Management (Vault)

**HashiCorp Vault Setup** (Cloud K8s):
```yaml
# vault-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vault
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: vault
        image: vault:1.15
        env:
        - name: VAULT_ADDR
          value: "http://127.0.0.1:8200"
        volumeMounts:
        - name: vault-storage
          mountPath: /vault/data
      volumes:
      - name: vault-storage
        persistentVolumeClaim:
          claimName: vault-pvc
```

**Edge Integration**:
```bash
# On edge node, fetch secrets from Vault
vault login -method=approle role_id=$ROLE_ID secret_id=$SECRET_ID

# Fetch database password
export POSTGRES_PASSWORD=$(vault kv get -field=password secret/hookprobe/db)

# Fetch PSK for VXLAN
export OVS_PSK_MAIN=$(vault kv get -field=psk secret/vxlan/main)

# Auto-rotate every 90 days
0 0 1 */3 * /usr/local/bin/rotate-secrets.sh
```

**Automated Rotation**:
```python
#!/usr/bin/env python3
# rotate-secrets.sh
import hvac, subprocess, os

client = hvac.Client(url='https://vault.example.com:8200')
client.auth.approle.login(
    role_id=os.environ['ROLE_ID'],
    secret_id=os.environ['SECRET_ID']
)

# Generate new PSK
new_psk = os.urandom(32).hex()

# Store in Vault with metadata
client.secrets.kv.v2.create_or_update_secret(
    path='vxlan/main',
    secret={'psk': new_psk, 'rotated_at': datetime.now().isoformat()}
)

# Update OVS
subprocess.run([
    'ovs-vsctl', 'set', 'Interface', 'vxlan-100',
    f'options:psk={new_psk}'
])

# Notify other nodes to pull new PSK
for node in get_edge_nodes():
    requests.post(f'https://{node}/api/secrets/rotate')
```

### 9.2 Certificate Management (cert-manager)

**Automatic TLS Cert Issuance**:
```yaml
# cert-manager-issuer.yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@hookprobe.example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
```

**Service Mesh mTLS**:
```yaml
# istio-mtls.yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
spec:
  mtls:
    mode: STRICT  # Require mTLS for all services
```

### 9.3 Audit Logging

**Comprehensive Audit Trail**:
```bash
# All actions logged to centralized syslog
logger -t hookprobe-audit "User=admin Action=firewall_rule_add IP=10.101.0.15"

# PostgreSQL audit
# /var/lib/postgresql/data/postgresql.conf
log_statement = 'all'
log_line_prefix = '%t [%p]: user=%u,db=%d,app=%a,client=%h '

# Container exec audit
podman events --filter type=exec --format json | \
  while read event; do
    logger -t podman-audit "$(echo $event | jq -c .)"
  done
```

**Audit Log Retention** (Cloud):
```yaml
# ElasticSearch retention policy
PUT _ilm/policy/audit-logs-policy
{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": {
            "max_size": "50GB",
            "max_age": "30d"
          }
        }
      },
      "warm": {
        "min_age": "30d",
        "actions": {
          "allocate": {
            "number_of_replicas": 1
          }
        }
      },
      "cold": {
        "min_age": "90d",
        "actions": {
          "freeze": {}
        }
      },
      "delete": {
        "min_age": "365d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}
```

### 9.4 Backup & Disaster Recovery

**Edge Backup Strategy**:
```bash
#!/bin/bash
# /usr/local/bin/hookprobe-backup.sh

BACKUP_DIR="/backup/hookprobe/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Volume backups
podman volume export hookprobe-postgres-data > "$BACKUP_DIR/postgres.tar"
podman volume export hookprobe-qsecbit-data > "$BACKUP_DIR/qsecbit.tar"
podman volume export hookprobe-kali-reports > "$BACKUP_DIR/kali-reports.tar"

# Configuration backups
cp /root/hookprobe/network-config.sh "$BACKUP_DIR/"
ovs-vsctl show > "$BACKUP_DIR/ovs-config.txt"
nft list ruleset > "$BACKUP_DIR/nftables-rules.txt"

# Encrypt and upload to cloud
tar -czf "$BACKUP_DIR.tar.gz" "$BACKUP_DIR"
gpg --encrypt --recipient admin@hookprobe.example.com "$BACKUP_DIR.tar.gz"
rclone copy "$BACKUP_DIR.tar.gz.gpg" s3-backup:hookprobe-backups/

# Cleanup local
rm -rf "$BACKUP_DIR" "$BACKUP_DIR.tar.gz" "$BACKUP_DIR.tar.gz.gpg"

# Retention (keep last 30 days on S3)
rclone delete --min-age 30d s3-backup:hookprobe-backups/
```

**Cloud Backup** (Proxmox + Ceph):
```bash
# Automated VM snapshots
pvesh create /nodes/pve-01/qemu/100/snapshot --snapname "daily-$(date +%Y%m%d)"

# Ceph RBD snapshots
rbd snap create ceph-pool/k8s-master-1@daily-$(date +%Y%m%d)

# Offsite replication
rbd mirror pool enable ceph-pool pool
rbd mirror pool peer add ceph-pool client.remote@remote-cluster
```

**Disaster Recovery Testing**:
```bash
# Quarterly DR drill
# 1. Simulate edge node failure
systemctl stop podman
systemctl stop openvswitch

# 2. Restore from backup
./restore-from-backup.sh /backup/hookprobe/20251123-020000.tar.gz

# 3. Verify services
./health-check.sh

# 4. Document recovery time
echo "RTO: $(cat /var/log/dr-drill.log | grep recovery_time)"
```

---

## 10. Compliance & Governance

### 10.1 Regulatory Alignment

**GDPR** (Data Privacy):
- Personal data encrypted at rest + in transit
- Right to erasure: automated data purge scripts
- Data minimization: only metadata to cloud
- Audit logs: 365-day retention

**PCI-DSS** (If processing payments):
- Network segmentation (separate VNI for payment processing)
- Encrypted cardholder data (AES-256)
- Regular vulnerability scans (Nessus/OpenVAS)
- Access control (RBAC + MFA)

**HIPAA** (If handling health data):
- PHI encryption (FIPS 140-2 compliant)
- Access logs (all DB queries logged)
- Breach notification (automated alerts)
- Business Associate Agreements (BAAs)

### 10.2 Security Frameworks

**NIST Cybersecurity Framework**:

| Function | HookProbe Implementation |
|----------|-------------------------|
| **Identify** | Asset inventory (Podman inspect), threat model (this document) |
| **Protect** | Firewalls, WAF, encryption, IAM, container hardening |
| **Detect** | IDS/IPS (Zeek/Snort3), Qsecbit AI, SIEM correlation |
| **Respond** | Automated Kali playbooks, incident response runbooks |
| **Recover** | Automated backups, DR testing, failover mechanisms |

**CIS Controls**:
- **CIS Control 1**: Inventory (automated via Podman/K8s)
- **CIS Control 3**: Data protection (encryption, backups)
- **CIS Control 6**: Access control (RBAC, MFA, least privilege)
- **CIS Control 8**: Audit logs (centralized syslog, retention)
- **CIS Control 12**: Network monitoring (mirroring, flow logs)

### 10.3 Security Metrics (KPIs)

**Qsecbit Dashboard** (Grafana + ClickHouse):
```
┌─────────────────────────────────────────────┐
│  Qsecbit Score: 0.23 (GREEN)               │
│  24h Avg: 0.28  |  Peak: 0.62 (AMBER)     │
├─────────────────────────────────────────────┤
│  Component Breakdown:                       │
│  - Drift:        0.15  ████░░░░░░          │
│  - Attack Prob:  0.08  ██░░░░░░░░          │
│  - Decay:        0.32  ██████░░░░          │
│  - Quantum:      0.18  ████░░░░░░          │
├─────────────────────────────────────────────┤
│  Incidents (24h):                           │
│  - RED:   2  (resolved avg: 12 min)        │
│  - AMBER: 15 (resolved avg: 4 min)         │
│  - GREEN: 97.3% uptime                     │
├─────────────────────────────────────────────┤
│  Automated Responses:                       │
│  - WAF rule updates:    23                 │
│  - IP blocks:            8                 │
│  - Container restarts:   2                 │
│  - DB snapshots:         2                 │
├─────────────────────────────────────────────┤
│  ClickHouse Performance:                    │
│  - Events/sec:     1,234                   │
│  - Query time:     45ms (p95)              │
│  - Storage:        2.3TB (23TB compressed) │
│  - Total events:   4.2B                    │
└─────────────────────────────────────────────┘
```

**Grafana ClickHouse Queries**:
```sql
-- Real-time attack rate
SELECT
    toStartOfInterval(timestamp, INTERVAL 1 MINUTE) AS time,
    count() AS attack_rate
FROM security_logs.events
WHERE timestamp >= now() - INTERVAL 1 HOUR
  AND severity IN ('RED', 'AMBER')
GROUP BY time
ORDER BY time;

-- Top attackers (last 24h)
SELECT
    source_ip,
    count() AS attack_count,
    groupUniqArray(attack_type) AS attack_types,
    max(qsecbit_score) AS max_qsecbit
FROM security_logs.events
WHERE timestamp >= now() - INTERVAL 24 HOUR
  AND severity IN ('RED', 'AMBER')
GROUP BY source_ip
ORDER BY attack_count DESC
LIMIT 10;

-- Attack types distribution
SELECT
    attack_type,
    count() AS count,
    countIf(waf_action = 'BLOCK') AS blocked,
    countIf(waf_action = 'PASS') AS passed
FROM security_logs.events
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY attack_type
ORDER BY count DESC;

-- Site health overview
SELECT
    site_id,
    countIf(severity = 'GREEN') * 100.0 / count() AS green_pct,
    countIf(severity = 'AMBER') AS amber_count,
    countIf(severity = 'RED') AS red_count,
    avg(qsecbit_score) AS avg_qsecbit
FROM security_logs.events
WHERE timestamp >= now() - INTERVAL 1 HOUR
GROUP BY site_id;
```

**Key Metrics**:
- **Mean Time to Detect (MTTD)**: < 30 seconds (Qsecbit cycle)
- **Mean Time to Respond (MTTR)**: < 5 minutes (automated)
- **False Positive Rate**: < 5% (tuned via learning mode)
- **Uptime**: 99.9% (edge resilience + cloud failover)
- **Recovery Time Objective (RTO)**: < 15 minutes
- **Recovery Point Objective (RPO)**: < 1 hour (hourly backups)

---

## 11. Implementation Roadmap

### Phase 1: Edge Hardening (Weeks 1-2)

**Week 1: Control Plane**
- [ ] Implement OVS Unix socket restriction
- [ ] Deploy Vault for secrets management
- [ ] Configure PSK rotation automation
- [ ] Harden Podman daemon (rootless mode)

**Week 2: Network Layer**
- [ ] Deploy OpenFlow anti-spoofing rules
- [ ] Configure ARP/NDP protection
- [ ] Implement WireGuard underlay
- [ ] Deploy nftables default-deny policies

### Phase 2: Application Defense (Weeks 3-4)

**Week 3: WAF & App Hardening**
- [ ] Deploy NAXSI WAF in learning mode
- [ ] Harden Django (CSP, HSTS, rate limits)
- [ ] Implement PostgreSQL SSL + RBAC
- [ ] Configure Logto MFA

**Week 4: Tuning & Testing**
- [ ] Review NAXSI learning logs
- [ ] Create WAF whitelists
- [ ] Switch NAXSI to blocking mode
- [ ] Penetration testing (OWASP Top 10)

### Phase 3: AI Integration (Weeks 5-6)

**Week 5: Qsecbit + ClickHouse Deployment**
- [ ] Deploy ClickHouse edge instance (POD 003)
- [ ] Create security event schema
- [ ] Deploy Qsecbit analysis engine
- [ ] Configure baseline metrics
- [ ] Integrate Qsecbit → ClickHouse logging
- [ ] Create materialized views for aggregations
- [ ] Create Grafana dashboards (ClickHouse datasource)

**Week 6: Automated Response + Cloud Integration**
- [ ] Deploy Kali on-demand container
- [ ] Configure response playbooks
- [ ] Test XSS/SQLi/memory responses
- [ ] Deploy cloud ClickHouse cluster (Kubernetes)
- [ ] Configure edge → cloud replication (Kafka or direct)
- [ ] Test cross-site correlation queries
- [ ] Implement policy orchestrator

### Phase 4: Cloud Backend (Weeks 7-10)

**Week 7-8: Proxmox K8s Cluster**
- [ ] Deploy Proxmox VE nodes (Terraform)
- [ ] Configure Kubernetes cluster
- [ ] Implement GPU passthrough
- [ ] Deploy Ceph distributed storage

**Week 9: SIEM & Correlation**
- [ ] Deploy centralized Loki aggregator
- [ ] Configure cross-site correlation engine
- [ ] Implement policy orchestrator
- [ ] Test edge → cloud → edge policy loop

**Week 10: Testing & Validation**
- [ ] Simulate multi-site coordinated attack
- [ ] Verify cloud correlation accuracy
- [ ] Test ML model training pipeline
- [ ] Validate disaster recovery procedures

### Phase 5: Production Readiness (Weeks 11-12)

**Week 11: Compliance & Audit**
- [ ] Complete security audit (internal)
- [ ] Document compliance mappings (GDPR, PCI-DSS)
- [ ] Implement audit log retention policies
- [ ] Create incident response playbooks
- [ ] **Optional**: Deploy n8n (POD 008)
  - [ ] Configure n8n with Vault credential integration
  - [ ] Create autonomous blog generation workflow
  - [ ] Create threat intelligence scraping workflow
  - [ ] Configure webhook authentication
  - [ ] Set up firewall rules for n8n isolation

**Week 12: Go-Live Preparation**
- [ ] Final penetration testing (external firm)
- [ ] Load testing (simulate 10,000 req/s)
- [ ] Train operations team
- [ ] Deploy to production
- [ ] **Optional**: Test n8n autonomous content generation
  - [ ] Verify Claude API integration
  - [ ] Test social media posting workflows
  - [ ] Validate ClickHouse logging integration

---

## Conclusion

This security mitigation plan establishes HookProbe as a **future-proof, AI-powered cybersecurity platform** capable of defending against current and emerging threats through:

1. **Defense-in-Depth**: 6 layers from XDP/eBPF kernel protection through AI analysis
2. **Automated Response**: Sub-5-minute MTTR via Qsecbit + Kali playbooks
3. **Hybrid Resilience**: Edge autonomy + cloud intelligence
4. **ClickHouse Analytics**: Billion-row queries in milliseconds, 10:1 compression
5. **Cost Efficiency**: $150 SBC edge vs $500+/month cloud-only
6. **Enterprise Features**: mTLS, RBAC, audit logs, compliance

**Next Steps**:
1. Review and approve roadmap
2. Allocate resources (hardware, personnel)
3. Begin Phase 1 implementation
4. Schedule quarterly security audits

**Expected Outcomes**:
- **99.9% uptime** through edge resilience
- **< 30s threat detection** via Qsecbit
- **< 5min threat response** via automation
- **< 100ms query time** for billion-row analytics (ClickHouse)
- **€52,000+ annual savings** (Proxmox vs VMware)
- **90% storage savings** (ClickHouse compression vs raw logs)
- **Enterprise-grade security** on commodity hardware
- **Unlimited retention** (ClickHouse columnar storage scales to petabytes)

---

**Document Version**: 5.0 "Liberty"  
**Classification**: Internal - Restricted  
**Approved By**: [Security Team]  
**Next Review**: Q1 2026

---

## Appendix A: Quick Reference Commands

### Check Security Status
```bash
# Qsecbit current score
curl -s http://localhost:8888/api/qsecbit/latest | jq '.score, .rag_status'

# ClickHouse query - recent attacks
clickhouse-client --host 10.103.0.11 --secure --query "
SELECT 
    count() AS attacks,
    countIf(severity='RED') AS critical
FROM security_logs.events 
WHERE timestamp >= now() - INTERVAL 1 HOUR"

# Active firewall rules
nft list ruleset

# OVS flows (anti-spoofing)
ovs-ofctl dump-flows br-core

# Container security status
podman ps --format "{{.Names}}: {{.Status}}"

# Recent security events from ClickHouse
clickhouse-client --host 10.103.0.11 --secure --query "
SELECT 
    timestamp,
    source_ip,
    attack_type,
    severity,
    qsecbit_score
FROM security_logs.events
WHERE timestamp >= now() - INTERVAL 1 HOUR
  AND severity IN ('RED', 'AMBER')
ORDER BY timestamp DESC
LIMIT 20"

# ClickHouse performance check
clickhouse-client --host 10.103.0.11 --secure --query "
SELECT
    formatReadableSize(sum(bytes_on_disk)) AS total_size,
    count() AS total_events,
    sum(rows) AS total_rows
FROM system.parts
WHERE database = 'security_logs'"
```

### Emergency Response
```bash
# Block IP immediately
iptables -I INPUT -s <ATTACKER_IP> -j DROP

# Emergency DB snapshot
pg_dump -h 10.103.0.10 -U hookprobe_admin -d hookprobe_db > /backup/emergency-$(date +%s).sql

# Restart Qsecbit analysis
podman restart hookprobe-pod-007-ai-response-qsecbit

# View Kali reports
podman exec hookprobe-pod-007-ai-response-kali ls -lt /reports/ | head -10

# Query coordinated attacks in ClickHouse
clickhouse-client --host 10.103.0.11 --secure --query "
SELECT
    source_ip,
    uniqMerge(unique_sites) AS sites_attacked,
    countMerge(attack_count) AS total_attacks
FROM security_logs.coordinated_attacks
WHERE hour >= now() - INTERVAL 24 HOUR
  AND uniqMerge(unique_sites) >= 3
ORDER BY total_attacks DESC"
```

### Health Checks
```bash
# All PODs status
podman pod ps

# Network connectivity
ping -c 1 10.101.0.10  # Django
ping -c 1 10.103.0.10  # PostgreSQL
ping -c 1 10.103.0.11  # ClickHouse
ping -c 1 10.107.0.10  # Qsecbit

# ClickHouse connectivity
clickhouse-client --host 10.103.0.11 --secure --query "SELECT version()"

# ClickHouse replication status (cloud)
clickhouse-client --host clickhouse-cloud.example.com --secure --query "
SELECT
    database,
    table,
    formatReadableSize(total_replicas) AS replicas,
    active_replicas
FROM system.replicas
WHERE database = 'security_logs'"

# Disk space
df -h

# Memory usage
free -h

# Container resource usage
podman stats --no-stream

# ClickHouse table statistics
clickhouse-client --host 10.103.0.11 --secure --query "
SELECT
    partition,
    count() AS parts,
    formatReadableSize(sum(bytes_on_disk)) AS size,
    sum(rows) AS rows
FROM system.parts
WHERE database = 'security_logs' AND table = 'events'
GROUP BY partition
ORDER BY partition DESC"
```

---

## Appendix B: Threat Intelligence Sources

**Free Feeds**:
- AlienVault OTX: https://otx.alienvault.com/
- Abuse.ch: https://abuse.ch/
- MISP: https://www.misp-project.org/feeds/
- EmergingThreats: https://rules.emergingthreats.net/

**Commercial** (Optional):
- CrowdStrike Falcon Intelligence
- Recorded Future
- ThreatConnect

**Integration**:
```python
# Auto-update threat feeds (cron daily)
import requests

def update_threat_feeds():
    # AlienVault OTX
    otx_api = 'https://otx.alienvault.com/api/v1/pulses/subscribed'
    headers = {'X-OTX-API-KEY': os.environ['OTX_API_KEY']}
    
    response = requests.get(otx_api, headers=headers)
    threats = response.json()
    
    # Update firewall blocklist
    for threat in threats['results']:
        for indicator in threat['indicators']:
            if indicator['type'] == 'IPv4':
                subprocess.run([
                    'iptables', '-I', 'INPUT', '-s', indicator['indicator'], '-j', 'DROP'
                ])
```

---

**End of Document**
