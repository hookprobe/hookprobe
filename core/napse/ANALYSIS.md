# NAPSE Stage 1: IDS Dependency Analysis

**Version**: 1.0.0
**Date**: 2026-02-14
**Author**: NAPSE Architecture Team
**Status**: Complete - Ready for Stage 2 (Design)

---

## Executive Summary

HookProbe currently depends on **Zeek**, **Suricata**, and **Snort3** for IDS/NSM/IPS
functionality across **26+ consumer files** spanning the QSecBit detection engine, AIOCHI
cognitive layer, dnsXai DPI analyzer, response orchestration, D2D bubble detection, and
container infrastructure.

**NAPSE** (Neural Adaptive Packet Synthesis Engine) will replace all three with a unified,
in-house packet analysis system built on eBPF/XDP, eliminating ~600MB of external binary
dependencies and 3 separate log format parsers.

### Dependency Summary

| IDS Tool   | Consumer Files | Log Formats Read       | Container Images      |
|------------|---------------|------------------------|-----------------------|
| Suricata   | 13            | EVE JSON (`eve.json`)  | `jasonish/suricata:7.0.8` |
| Zeek       | 14            | TSV + JSON (6 log types) | `zeek/zeek:7.0.3`    |
| Snort3     | 2             | Fast alert text        | (not containerized)   |
| **Total**  | **29 touchpoints** | **8 distinct formats** | **2 images (~400MB)** |

### Risk Assessment

Replacing these dependencies carries **HIGH** architectural risk because:

1. Every QSecBit detector (L2-L7) reads Suricata EVE JSON and/or Zeek TSV logs
2. The AIOCHI bubble system's D2D detection is entirely built on Zeek `conn.log` parsing
3. The log shipper pipeline ships both Suricata and Zeek data to ClickHouse
4. Custom Suricata rules (local.rules + small-business-mitre.rules) encode domain-specific
   detection logic that must be preserved

The mitigation strategy is the **compatibility seam pattern**: NAPSE will produce output in
the same formats (EVE JSON, Zeek TSV) during the transition period, allowing consumers to
migrate incrementally.

---

## Suricata Dependencies (13 Consumers)

### Log Format

Suricata outputs EVE JSON to `/var/log/suricata/eve.json`. Each line is a complete JSON
object. Consumers filter on `event_type == "alert"` and match regex patterns against
`alert.signature`.

### Consumer Table

| # | Consumer File | What It Reads | Method |
|---|--------------|---------------|--------|
| 1 | `core/qsecbit/detectors/base.py:233-281` | EVE JSON alerts filtered by regex pattern list | `_read_suricata_alerts()` - tails last 500 lines, parses JSON, matches `alert.signature` against caller-provided patterns |
| 2 | `core/qsecbit/detectors/l2_detector.py:227-258` | VLAN hopping alerts | Patterns: `vlan`, `double.?tag`, `802\.1q` |
| 3 | `core/qsecbit/detectors/l3_detector.py:68-115,179-236,297-319` | IP spoofing, Smurf attack, fragmentation alerts | Patterns: `spoof`, `bogon`, `martian`, `impossible.source`, `smurf`, `icmp.*.broadcast`, `amplification`, `frag`, `teardrop`, `overlap`, `reassembly` |
| 4 | `core/qsecbit/detectors/l4_detector.py:109-124,237-274` | SYN flood, session hijacking alerts | Patterns: `syn.?flood`, `syn.?attack`, `tcp.?syn`, `session.?hijack`, `seq.?num`, `ack.?storm`, `tcp.?state`, `connection.?reset` |
| 5 | `core/qsecbit/detectors/l5_detector.py:64-124,126-180,182-242` | SSL strip, TLS downgrade, certificate anomaly alerts | Patterns: `ssl.?strip`, `https.?downgrade`, `hsts.?bypass`, `mitm`, `tls.?downgrade`, `poodle`, `drown`, `beast`, `crime`, `breach`, `certificate`, `cert.?invalid`, `self.?signed`, `expired`, `untrusted`, `ca.?invalid` |
| 6 | `core/qsecbit/detectors/l7_detector.py:93-161,163-223,371-397,399-425,427-486` | SQL injection, XSS, malware C2, command injection, path traversal alerts | Patterns: `sql.?inject`, `sqli`, `select.*from`, `union.*select`, `xss`, `cross.?site`, `<script`, `command.?control`, `c2`, `beacon`, `trojan`, `botnet`, `cobalt.?strike`, `command.?inject`, `rce`, `path.?traversal`, `lfi`, `rfi`, `\.\./\.\.` |
| 7 | `core/threat_detection/layer_threat_detector.py:134,527,741` | EVE JSON alerts for VLAN hopping, fragmentation | Direct `grep` of eve.json (legacy approach, no structured parsing) |
| 8 | `shared/aiochi/containers/scripts/log_shipper.py:73-97` | Ships EVE JSON alerts to ClickHouse | `parse_suricata_event()` - filters `event_type == 'alert'`, extracts 12 fields into `suricata_alerts` table |
| 9 | `shared/aiochi/containers/configs/suricata/suricata.yaml` | AF-PACKET capture config, app-layer protocols, EVE JSON output settings | YAML configuration: ring-size 200000, community-id enabled, 16 app-layer protocols, fast.log + stats.log outputs |
| 10 | `shared/aiochi/containers/configs/suricata/rules/local.rules` | 10 custom detection rules | SSH brute force (sid:1000001), DNS tunneling (sid:1000002), port scan (sid:1000003), DNS non-standard port (sid:1000004), IoT beaconing (sid:1000005), crypto mining (sid:1000006), C2 beaconing (sid:1000007), new DHCP (sid:1000008), rogue DHCP (sid:1000009), self-signed cert (sid:1000010) |
| 11 | `shared/aiochi/containers/configs/suricata/small-business-mitre.rules` | MITRE ATT&CK-mapped rules for small business threats | POS data theft, ransomware, and other domain-specific detections (sid:9000001+) |
| 12 | `shared/response/attack-mitigation-orchestrator.sh:6,143-156` | Reads Snort3/Zeek/Suricata alerts for mitigation triggers | Queries multiple sources including ClickHouse (where Suricata alerts land via log shipper) |
| 13 | `core/qsecbit/response/orchestrator.py` | Responds to ThreatEvents originally detected via Suricata signatures | Consumes `ThreatEvent` objects (indirect dependency - events created from Suricata data by detectors) |

### Container Definition

**Fortress** (`products/fortress/containers/podman-compose.yml`):
- Service: `fts-suricata` - uses host network, AF-PACKET capture
- Profile: `ids` (optional)

**AIOCHI** (`shared/aiochi/containers/podman-compose.aiochi.yml`):
- Service: `aiochi-suricata`
- Image: `docker.io/jasonish/suricata:7.0.8`
- Network: host (for AF-PACKET)
- Captures from: `FTS-mirror` (OVS mirror port)
- Volumes: `suricata_logs:/var/log/suricata`

### Suricata Rule Inventory

| Rule File | Rule Count | Categories |
|-----------|-----------|------------|
| `local.rules` | 10 | SSH brute force, DNS tunneling, port scan, IoT beaconing, crypto mining, C2, DHCP, TLS |
| `small-business-mitre.rules` | 20+ | POS theft, ransomware, WiFi deauth, credential theft, lateral movement, data exfiltration |
| `suricata.rules` | ~30K | ET Open ruleset (community) |

---

## Zeek Dependencies (14 Consumers)

### Log Formats

Zeek outputs tab-separated (TSV) log files to `/var/log/zeek/current/` (or `/opt/zeek/logs/current/`
in containers). Each log type has a `#fields` header line defining column names. When configured
with `LogAscii::use_json = T`, Zeek outputs JSON instead.

### Consumer Table

| # | Consumer File | What It Reads | Log File(s) |
|---|--------------|---------------|-------------|
| 1 | `core/qsecbit/detectors/base.py:283-315` | Generic Zeek TSV log reader | `_read_zeek_log()` - tails N lines from `/var/log/zeek/current/{log_name}`, splits on tab, skips `#` comments |
| 2 | `core/qsecbit/detectors/l2_detector.py:385-427` | DHCP server detection (rogue DHCP) | `dhcp.log` - reads field index 4 for server_ip, alerts on multiple servers |
| 3 | `core/qsecbit/detectors/l3_detector.py:206-236` | Smurf attack broadcast ICMP detection | `conn.log` - checks field[6]=proto for `icmp`, field[4]=dest_ip for `.255` broadcast |
| 4 | `core/qsecbit/detectors/l4_detector.py:127-173` | Port scan detection via connection patterns | `conn.log` - reads field[2]=src_ip, field[5]=dst_port, alerts when >50 unique ports from single source |
| 5 | `core/qsecbit/detectors/l5_detector.py:97-124,134-180,218-242` | SSL strip HTTP detection, TLS downgrade, certificate validation | `http.log` - field[8]=host, field[9]=uri for secure domain HTTP traffic; `ssl.log` - field[6]=ssl_version for weak TLS, field[9]=server_name, field[14]=validation_status |
| 6 | `core/qsecbit/detectors/l7_detector.py:124-161,199-223,237-320,337-369,452-486` | SQL injection in URIs, XSS, DNS tunneling, HTTP flood, path traversal | `http.log` - field[9]=uri, field[12]=post_body for SQLI/XSS/traversal patterns; `dns.log` - field[9]=query, field[13]=qtype for tunneling detection |
| 7 | `core/threat_detection/layer_threat_detector.py:135,559-562` | DHCP log and Suricata log paths | `dhcp.log` - legacy detector with hardcoded field positions |
| 8 | `shared/dnsXai/dpi_analyzer.py:293-443` | TLS metadata, JA3 fingerprints, certificate analysis | `ssl.log` - field-name-based parsing via `#fields` header; `ja3.log` - JA3 hash lookup against malicious DB |
| 9 | `shared/aiochi/containers/scripts/zeek_mdns_parser.py` | mDNS device ecosystem detection | `dns.log` - filters mDNS traffic (port 5353, multicast 224.0.0.251, `.local` domains), detects Apple/Google/Samsung/Amazon ecosystems |
| 10 | `shared/aiochi/bubble/zeek_mdns_parser.py` | Identical mDNS parser (bubble module copy) | `dns.log` - same as #9, used by bubble manager |
| 11 | `shared/aiochi/containers/scripts/log_shipper.py:99-221` | Ships Zeek conn and DNS logs to ClickHouse | `conn.log` - 13 fields into `zeek_connections` table; `dns.log` - 11 fields into `zeek_dns` table; supports both JSON and TSV formats |
| 12 | `shared/aiochi/containers/configs/zeek/local.zeek` | Zeek configuration: 26 protocol analyzers, custom Notice types, DHCP fingerprinting | Configuration file defining: `New_Device`, `Device_Hostname_Change`, `Suspicious_DNS`, `Port_Scan_Detected`, `SSH_Bruteforce`, `TLS_Cert_Invalid` notices |
| 13 | `shared/aiochi/bubble/connection_graph.py:1244-1282,1447-1562` | D2D device relationship analysis via connection patterns | `conn.log` - parses LAN-only connections, builds affinity graph; `dns.log` - mDNS query/response pairing for ecosystem detection |
| 14 | `shared/aiochi/containers/scripts/d2d_tracker.py` | D2D connection tracking API | `conn.log` - reads Zeek connection logs for device-to-device communication patterns |

### Container Definition

**AIOCHI** (`shared/aiochi/containers/podman-compose.aiochi.yml`):
- Service: `aiochi-zeek`
- Image: `docker.io/zeek/zeek:7.0.3`
- Network: host (for packet capture)
- Captures from: `FTS-mirror` (OVS mirror port)
- Volumes: `zeek_logs:/opt/zeek/logs`
- Config: `local.zeek` enables JSON logging, 1-hour rotation, custom notice types

### Zeek Log Field Contracts

These are the exact field positions used by hardcoded index-based parsers in the QSecBit
detectors. NAPSE must produce output with compatible field ordering.

**conn.log** (positional access by QSecBit detectors):
```
Index  Field        Used By
[0]    ts           l3_detector (implicit)
[1]    uid          (unused by detectors)
[2]    id.orig_h    l3_detector, l4_detector, l5_detector, l7_detector (src_ip)
[3]    id.orig_p    (unused by most detectors)
[4]    id.resp_h    l3_detector, l5_detector, l7_detector (dest_ip)
[5]    id.resp_p    l4_detector, l5_detector (dst_port)
[6]    proto        l3_detector (icmp check)
[7]    service      (unused by detectors)
[8+]   duration...  (unused by detectors)
```

**dns.log** (positional access):
```
Index  Field        Used By
[9]    query        l7_detector (DNS tunneling: length, entropy)
[13]   qtype        l7_detector (TXT record detection)
```

**http.log** (positional access):
```
Index  Field        Used By
[2]    id.orig_h    l5_detector, l7_detector (src_ip)
[4]    id.resp_h    l5_detector, l7_detector (dest_ip)
[5]    id.resp_p    l5_detector (dest_port)
[8]    host         l5_detector (secure domain check)
[9]    uri          l5_detector, l7_detector (SQLI/XSS/traversal patterns)
[12]   post_body    l7_detector (SQLI patterns)
```

**ssl.log** (positional access):
```
Index  Field              Used By
[2]    id.orig_h          l5_detector (src_ip)
[4]    id.resp_h          l5_detector (dest_ip)
[5]    id.resp_p          l5_detector (dest_port)
[6]    version            l5_detector (weak TLS check)
[9]    server_name        l5_detector (certificate validation)
[14]   validation_status  l5_detector (cert validity)
```

**dhcp.log** (positional access):
```
Index  Field        Used By
[4]    server_ip    l2_detector (rogue DHCP detection)
```

### Zeek Notice Types (Custom)

Defined in `local.zeek` and consumed by the mitigation orchestrator:

| Notice Type | Trigger | Consumer |
|------------|---------|----------|
| `AIOCHI::New_Device` | DHCP ACK with hostname | narrative engine, bubble manager |
| `AIOCHI::Device_Hostname_Change` | Hostname change detected | identity engine |
| `AIOCHI::Suspicious_DNS` | Query length > 60 or suspicious TLD | QSecBit L7, alert pipeline |
| `AIOCHI::Port_Scan_Detected` | (defined but triggered by Zeek policy) | response orchestrator |
| `AIOCHI::SSH_Bruteforce` | (defined but triggered by Zeek policy) | response orchestrator |
| `AIOCHI::TLS_Cert_Invalid` | SSL validation failure | QSecBit L5, DPI analyzer |

---

## Snort3 Dependencies (2 Consumers)

Snort3 has the lightest footprint in the codebase. It is not containerized and appears to be
a legacy integration from the mitigation orchestrator.

| # | Consumer File | What It Reads | Method |
|---|--------------|---------------|--------|
| 1 | `shared/response/attack-mitigation-orchestrator.sh:103-111` | Fast alert file (`$SNORT3_ALERT_FILE`) | `get_snort3_alerts()` - tails last 100 lines, filters `Priority: [0-2]` via grep |
| 2 | `shared/response/README.md:68,203,205,209` | Documentation references | Port scanning, DDoS, buffer overflow detection attribution |

### Notes

- Snort3 is referenced in the mitigation config as `SNORT3_ALERT_FILE="/var/log/snort/alert_fast.txt"`
- No container image is defined for Snort3 in any podman-compose file
- The `get_snort3_alerts()` function has a graceful fallback (`log_warning`) when the file is missing
- Snort3 can be fully replaced by NAPSE with zero migration risk

---

## Data Format Contract

NAPSE must produce output compatible with these formats during the transition period.
Post-migration, consumers will use native NAPSE APIs.

### 1. EVE-Compatible JSON (Replaces Suricata)

```json
{
    "timestamp": "2026-02-14T10:30:00.123456+0000",
    "event_type": "alert",
    "src_ip": "192.168.1.100",
    "src_port": 54321,
    "dest_ip": "10.200.0.1",
    "dest_port": 443,
    "proto": "TCP",
    "alert": {
        "action": "allowed",
        "gid": 1,
        "signature_id": 1000001,
        "rev": 1,
        "signature": "NAPSE SSH Brute Force Attempt",
        "category": "attempted-admin",
        "severity": 2,
        "metadata": {}
    },
    "flow_id": 1234567890,
    "community_id": "1:abc123..."
}
```

**Required fields**: `timestamp`, `event_type`, `src_ip`, `src_port`, `dest_ip`, `dest_port`,
`proto`, `alert.action`, `alert.gid`, `alert.signature_id`, `alert.rev`, `alert.signature`,
`alert.category`, `alert.severity`

**Optional fields**: `flow_id`, `community_id`, `alert.metadata`

### 2. conn.log (Replaces Zeek)

Tab-separated, `#fields` header required.

```
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	orig_pkts	resp_pkts
1707900600.123	C1a2b3c	10.200.0.45	54321	10.200.0.1	443	tcp	ssl	1.234	500	1200	SF	10	15
```

| Field | Type | Description |
|-------|------|-------------|
| `ts` | float | Unix timestamp with microseconds |
| `uid` | string | Unique connection ID |
| `id.orig_h` | string | Source IP |
| `id.orig_p` | int | Source port |
| `id.resp_h` | string | Destination IP |
| `id.resp_p` | int | Destination port |
| `proto` | string | Protocol (`tcp`, `udp`, `icmp`) |
| `service` | string | Application protocol (`http`, `ssl`, `dns`, `ssh`, `-`) |
| `duration` | float | Connection duration in seconds |
| `orig_bytes` | int | Bytes sent by originator |
| `resp_bytes` | int | Bytes sent by responder |
| `conn_state` | string | Connection state (`S0`, `S1`, `SF`, `REJ`, `RSTO`, etc.) |
| `orig_pkts` | int | Packets from originator |
| `resp_pkts` | int | Packets from responder |

### 3. dns.log (Replaces Zeek)

```
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	trans_id	rtt	query	qclass	qclass_name	qtype	qtype_name	rcode	rcode_name	AA	TC	RD	RA	Z	answers	TTLs	rejected
```

| Field | Type | Critical Consumer |
|-------|------|-------------------|
| `ts` | float | timestamp |
| `id.orig_h` | string | source IP for mDNS pairing |
| `id.orig_p` | int | mDNS port detection (5353) |
| `id.resp_h` | string | multicast address detection |
| `id.resp_p` | int | mDNS port detection (5353) |
| `query` | string | L7 detector (tunneling), mDNS parser (ecosystem) |
| `qtype` / `qtype_name` | int/string | L7 detector (TXT records), mDNS parser |
| `AA` | bool | mDNS response detection |
| `answers` | comma-separated | mDNS response content |
| `TTLs` | comma-separated | mDNS TTL extraction |

### 4. http.log (Replaces Zeek)

```
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	method	host	uri	referrer	version	user_agent	origin	...
```

Critical fields: `id.orig_h` (index 2), `id.resp_h` (index 4), `id.resp_p` (index 5),
`host` (index 8), `uri` (index 9), request body (index 12).

### 5. ssl.log (Replaces Zeek)

```
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	cipher	curve	server_name	resumed	...	subject	issuer	validation_status
```

Critical fields: `id.orig_h` (index 2), `id.resp_h` (index 4), `id.resp_p` (index 5),
`version` (index 6), `server_name` (index 9), `validation_status` (index 14).

### 6. dhcp.log (Replaces Zeek)

Critical field: `server_ip` at index 4, `client_mac` for device tracking.

### 7. Notice Events (Replaces Zeek Notice Framework)

JSON format (when `LogAscii::use_json = T`):

```json
{
    "note": "AIOCHI::New_Device",
    "msg": "New device on network: AA:BB:CC:DD:EE:FF (hostname: DadsIPhone)",
    "src": "10.200.0.45",
    "dst": "",
    "conn": { ... }
}
```

NAPSE must emit equivalent notice events for: `New_Device`, `Suspicious_DNS`,
`TLS_Cert_Invalid`, `Port_Scan_Detected`, `SSH_Bruteforce`.

### 8. Community-ID Flow Hashing

Both Suricata (`community-id: true` in suricata.yaml) and Zeek support community-ID v1
flow hashing for cross-tool correlation. NAPSE must implement the same algorithm:

```
community-id-v1 = base64(sha1(seed + src_ip + dst_ip + proto + src_port + dst_port))
```

Reference: https://github.com/corelight/community-id-spec

---

## Critical Integration Points

### 1. BaseDetector._read_suricata_alerts() -- The Suricata Compatibility Seam

**File**: `core/qsecbit/detectors/base.py:233-281`

This is the single most important compatibility point. Every L2-L7 detector calls this method.

```python
def _read_suricata_alerts(self, patterns: List[str], limit: int = 50) -> List[Dict[str, Any]]:
    # 1. Checks self.suricata_log (/var/log/suricata/eve.json) exists
    # 2. Tails last 500 lines
    # 3. JSON-parses each line
    # 4. Filters event_type == 'alert'
    # 5. Regex-matches alert.signature against caller's patterns
    # 6. Returns list of matching event dicts
```

**NAPSE Strategy**: Either write EVE-compatible JSON to the same path, or replace this
method with a NAPSE native API call. The method signature is the contract.

### 2. BaseDetector._read_zeek_log() -- The Zeek Compatibility Seam

**File**: `core/qsecbit/detectors/base.py:283-315`

```python
def _read_zeek_log(self, log_name: str, limit: int = 200) -> List[List[str]]:
    # 1. Checks self.zeek_log_dir / log_name exists
    # 2. Tails last N lines
    # 3. Skips lines starting with '#'
    # 4. Splits on tab
    # 5. Returns list of field arrays
```

**NAPSE Strategy**: Write Zeek-compatible TSV files to the same directory, or replace this
method. Note that consumers use **hardcoded positional indexes** (e.g., `parts[9]` for DNS
query), making field ordering critical.

### 3. ThreatEvent Dataclass -- The Shared Vocabulary

**File**: `core/qsecbit/threat_types.py:269-382`

All detection flows produce `ThreatEvent` objects. This is the interface between detection
and response. NAPSE detections must produce the same dataclass.

Key fields: `id`, `timestamp`, `attack_type` (enum), `layer` (enum), `severity` (enum),
`source_ip`, `source_mac`, `dest_ip`, `dest_port`, `description`, `confidence`,
`detector`, `evidence` (dict), `mitre_attack_id`.

### 4. XDPManager -- The Existing eBPF Foundation

**File**: `core/qsecbit/xdp_manager.py`

XDP is already used for DDoS mitigation (SYN flood, rate limiting). NAPSE extends this
foundation by adding packet classification and protocol analysis in eBPF, pushing
detection logic to the kernel where possible.

### 5. LogShipper -- The ClickHouse Pipeline

**File**: `shared/aiochi/containers/scripts/log_shipper.py`

The log shipper expects specific table schemas in ClickHouse:
- `suricata_alerts` - 12 columns (timestamp through alert_severity)
- `zeek_connections` - 13 columns (ts through resp_pkts)
- `zeek_dns` - 11 columns (ts through TTLs)

NAPSE must either produce compatible data or provide its own ClickHouse integration.

### 6. ConnectionGraphAnalyzer.parse_zeek_conn_log() -- The D2D Bubble Engine

**File**: `shared/aiochi/bubble/connection_graph.py:1244-1282`

The D2D bubble system's core detection relies entirely on Zeek `conn.log` parsing. It
filters for LAN-only connections (both IPs in `10.200.0.0/16`) and builds affinity scores
from connection frequency, service type, and temporal patterns.

---

## Security Findings (from Trio+ Audit)

| Severity | Count | Key Issues |
|----------|-------|------------|
| **CRITICAL** | 1 | Hardcoded ClickHouse password fallback `aiochi_secure_password` in `log_shipper.py:37` - should use secrets management |
| **HIGH** | 3 | (1) Unescaped shell variable `$alert` interpolated into JSON in `attack-mitigation-orchestrator.sh:150` - allows JSON injection; (2) Unvalidated IPs passed to `iptables` commands in `orchestrator.sh:274-293` - weak regex `^[0-9]{1,3}\.` allows values like `999.999.999.999`; (3) `conntrack -D -s {ip}` in `response/orchestrator.py:429` terminates all sessions from IP without confirmation |
| **MEDIUM** | 4 | (1) Weak IP validation regex in `attack-mitigation-orchestrator.sh:259` does not validate octet ranges; (2) Hardcoded Zeek field positions (e.g., `parts[9]` for query) break silently if Zeek config changes column order; (3) Duplicate detection systems - `core/threat_detection/layer_threat_detector.py` (1,564 lines) duplicates `core/qsecbit/detectors/` (2,663 lines) with incompatible type systems; (4) Community-ID seed hardcoded to `0` in `suricata.yaml:54` |
| **LOW** | 3 | (1) ClickHouse connection details logged at INFO level in `log_shipper.py:67`; (2) NIC capability information written to stdout in `nic_detector.py`; (3) IP blocking via `iptables -A INPUT -s {ip} -j DROP` and `ebtables -A INPUT -s {mac} -j DROP` execute without confirmation prompts |

### Critical Finding Detail

**Hardcoded ClickHouse Password** (`shared/aiochi/containers/scripts/log_shipper.py:37`):
```python
CLICKHOUSE_PASSWORD = os.getenv('CLICKHOUSE_PASSWORD', 'aiochi_secure_password')
```
The fallback password is committed to source control. While the environment variable
override exists, the default allows unauthenticated ClickHouse access if the env var is
not set. NAPSE should use a secrets file or Podman secrets.

---

## Consolidation Opportunities

### 1. Duplicate Detector Systems (HIGH Priority)

`core/threat_detection/layer_threat_detector.py` (1,564 lines) duplicates the functionality
of `core/qsecbit/detectors/` (2,663 lines across 6 files) with **incompatible type systems**:

| Aspect | `layer_threat_detector.py` (Legacy) | `qsecbit/detectors/` (Current) |
|--------|--------------------------------------|--------------------------------|
| Threat type | Custom dict with string keys | `ThreatEvent` dataclass with `AttackType` enum |
| Severity | String: `"critical"`, `"high"` | Enum: `ThreatSeverity.CRITICAL` |
| Layer | Integer literal | `OSILayer` enum |
| Suricata access | Direct `grep` of eve.json | Structured JSON parse via `_read_suricata_alerts()` |
| Zeek access | Direct file read with hardcoded paths | Shared `_read_zeek_log()` base method |

**Recommendation**: Retire `layer_threat_detector.py` during NAPSE migration. It is used by
`products/guardian/lib/` but can be replaced by the QSecBit detectors which have better
structure, deduplication, and MITRE ATT&CK mapping.

### 2. Autopilot Probe Gap (MEDIUM Priority)

`products/fortress/lib/autopilot/probe_service.py` captures packets via tshark for 60-second
bursts during device identification but does **not** feed results into QSecBit detectors.

The captured data (MAC fingerprint, protocol usage, connection patterns) could enrich L2
detection (evil twin, rogue DHCP) and L7 detection (DNS tunneling, C2 beaconing) if wired
through NAPSE's unified pipeline.

**Recommendation**: NAPSE's packet capture engine should serve both the autopilot probe and
the detection pipeline, eliminating the tshark dependency.

### 3. Duplicate JA3 Databases (LOW Priority)

JA3 fingerprint databases exist in two locations:

| Location | Entries | Used By |
|----------|---------|---------|
| `shared/dnsXai/dpi_analyzer.py:52-68` | 9 known-malicious JA3 hashes | DPI TLS analysis |
| `products/fortress/lib/ja3_fingerprint.py` (if exists) | Unknown | Device fingerprinting |

**Recommendation**: Consolidate into a single JA3 database under `core/napse/signatures/`
with both malicious detection and device fingerprinting capabilities.

### 4. Dual mDNS Parser (LOW Priority)

The Zeek mDNS parser exists in two nearly identical copies:
- `shared/aiochi/containers/scripts/zeek_mdns_parser.py` (409 lines)
- `shared/aiochi/bubble/zeek_mdns_parser.py` (similar)

**Recommendation**: Single NAPSE mDNS parser feeding both bubble manager and identity engine.

---

## Migration Path Summary

### Phase 1: Compatibility Layer (Weeks 1-4)
- NAPSE writes EVE-compatible JSON to `/var/log/suricata/eve.json`
- NAPSE writes Zeek-compatible TSV to `/var/log/zeek/current/`
- All existing consumers work unchanged
- Suricata and Zeek containers can be stopped

### Phase 2: Native API Migration (Weeks 5-8)
- Replace `_read_suricata_alerts()` with NAPSE event query API
- Replace `_read_zeek_log()` with NAPSE flow query API
- Log shipper reads from NAPSE event stream directly
- Connection graph reads from NAPSE D2D flow data

### Phase 3: Legacy Removal (Weeks 9-12)
- Remove Suricata container definitions
- Remove Zeek container definitions
- Remove Snort3 integration code
- Remove compatibility log writers
- Retire `layer_threat_detector.py`

### Consumer Migration Checklist

| Consumer | Phase 1 | Phase 2 | Phase 3 |
|----------|---------|---------|---------|
| `base.py` `_read_suricata_alerts()` | Compat | Replace with NAPSE API | Remove compat |
| `base.py` `_read_zeek_log()` | Compat | Replace with NAPSE API | Remove compat |
| L2-L7 detectors (6 files) | Compat | Use NAPSE detections directly | Remove Suricata/Zeek patterns |
| `log_shipper.py` | Compat | NAPSE ClickHouse integration | Remove shipper |
| `dpi_analyzer.py` | Compat | NAPSE TLS analyzer | Remove Zeek dependency |
| `zeek_mdns_parser.py` (x2) | Compat | NAPSE mDNS engine | Remove parser |
| `connection_graph.py` | Compat | NAPSE flow API | Remove Zeek parsing |
| `d2d_tracker.py` | Compat | NAPSE D2D API | Remove Zeek dependency |
| `attack-mitigation-orchestrator.sh` | Compat | NAPSE alert API | Remove Snort3/Zeek reads |
| `response/orchestrator.py` | No change | No change | No change (consumes ThreatEvent) |
| Container definitions (2) | Containers optional | Containers removed | Clean up compose files |
| Rule files (3) | Translate to NAPSE | NAPSE signatures active | Remove Suricata rules |
| `local.zeek` config | Compat | NAPSE protocol analyzers | Remove Zeek config |
| `layer_threat_detector.py` | Compat | Retire | Delete file |

---

## Appendix: File Line Counts

| File | Lines | Role |
|------|-------|------|
| `core/qsecbit/detectors/base.py` | 384 | Base detector with Suricata/Zeek readers |
| `core/qsecbit/detectors/l2_detector.py` | 440 | L2 detection (ARP, VLAN, Evil Twin, DHCP) |
| `core/qsecbit/detectors/l3_detector.py` | 319 | L3 detection (IP spoof, ICMP, Smurf) |
| `core/qsecbit/detectors/l4_detector.py` | 329 | L4 detection (SYN flood, port scan, session hijack) |
| `core/qsecbit/detectors/l5_detector.py` | 321 | L5 detection (SSL strip, TLS downgrade, cert) |
| `core/qsecbit/detectors/l7_detector.py` | 486 | L7 detection (SQLI, XSS, DNS tunnel, C2) |
| `core/qsecbit/threat_types.py` | 487 | ThreatEvent dataclass and enums |
| `core/qsecbit/response/orchestrator.py` | 520 | Response orchestrator (XDP/firewall) |
| `core/threat_detection/layer_threat_detector.py` | 1,564 | **Legacy duplicate** detector |
| `shared/aiochi/containers/scripts/log_shipper.py` | 439 | Suricata/Zeek to ClickHouse pipeline |
| `shared/aiochi/containers/scripts/zeek_mdns_parser.py` | 409 | mDNS ecosystem detection |
| `shared/aiochi/bubble/connection_graph.py` | 2,471 | D2D bubble detection via Zeek |
| `shared/aiochi/containers/scripts/d2d_tracker.py` | 969 | D2D tracking API |
| `shared/dnsXai/dpi_analyzer.py` | 684 | TLS/JA3 analysis via Zeek |
| `shared/response/attack-mitigation-orchestrator.sh` | 533 | Multi-source mitigation |
| **Total consumer code** | **~9,855** | |

---

*NAPSE -- Replacing complexity with clarity, three tools with one.*
