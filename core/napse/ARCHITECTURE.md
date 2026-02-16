# NAPSE - Neural Adaptive Packet Synthesis Engine

**Version**: 1.0.0
**Status**: Phase 1 Development
**Author**: Andrei Toma
**License**: Proprietary - see LICENSING.md
**Last Updated**: 2026-02-14
**Tagline**: *"See every packet. Understand every intent."*

---

## Table of Contents

- [Overview](#overview)
- [Name Origin](#name-origin)
- [Architecture Overview](#architecture-overview)
- [Performance Targets](#performance-targets)
- [Tier Scaling](#tier-scaling)
- [Component Details](#component-details)
  - [Layer 0: Kernel Fast Path](#layer-0-kernel-fast-path)
  - [Layer 1: Protocol Engine (Rust)](#layer-1-protocol-engine-rust)
  - [Layer 2: Event Synthesis (Python)](#layer-2-event-synthesis-python)
- [Integration Map](#integration-map)
- [Implementation Phases](#implementation-phases)
- [Container Architecture](#container-architecture)
- [Risk Mitigation](#risk-mitigation)
- [Directory Structure](#directory-structure)
- [Appendix: Protocol Parser Reference](#appendix-protocol-parser-reference)

---

## Overview

NAPSE is HookProbe's proprietary IDS/NSM/IPS engine -- a unified 3-layer architecture optimized for resource-constrained edge devices. Unlike general-purpose IDS tools designed for data-center visibility on powerful servers, NAPSE is designed from the ground up for the realities of edge computing: limited RAM, limited CPU, and a requirement for microsecond-level blocking decisions.

Traditional IDS/NSM approaches require running multiple heavyweight processes for network security monitoring, typically consuming **~2GB RAM** and **15-40% CPU** even when idle. This is the single largest resource bottleneck on 4GB Fortress devices and makes deployment on 256MB Sentinel devices impossible. Separate log formats require normalization and forwarding, and startup times (~25 seconds) create a window of blindness after every reboot.

NAPSE solves this with a single binary that:

- Uses **~200MB RAM** on Fortress (10x reduction) and **~30MB** on Sentinel
- Idles at **<1% CPU** through eBPF/XDP kernel-level packet steering
- Produces **typed events** directly consumable by QSecBit, AEGIS, and the D2D Bubble system
- Starts in **<2 seconds** with zero warmup penalty
- Handles **~10 Gbps** on Nexus hardware with AF_XDP zero-copy sockets

NAPSE is not a general-purpose IDS tool. It is purpose-built for the HookProbe security stack and its specific integration points: QSecBit scoring, AEGIS reasoning, D2D device relationship detection, dnsXai DNS classification, and mesh threat propagation.

---

## Name Origin

The name **NAPSE** references the biological **synapse**: a junction where signals are received, interpreted, and transmitted. In neuroscience, the synapse is the most critical component of the nervous system -- not because it generates signals, but because it decides which signals matter, amplifies the important ones, and suppresses noise.

NAPSE does the same at the packet level:

1. **Receives** raw Ethernet frames from the kernel via eBPF/XDP zero-copy sockets
2. **Synthesizes understanding** through protocol state machines, pattern matching, and ML inference
3. **Transmits structured intelligence** to the HookProbe stack as typed events

The "N" prefix also aligns with HookProbe's naming convention for neural/cognitive components (Neuro, NSE, Neural Command Center).

The full acronym expands the metaphor:

| Letter | Word | Meaning |
|--------|------|---------|
| **N** | Neural | ML-powered classification at the packet level |
| **A** | Adaptive | Learns per-device baselines, adapts to network personality |
| **P** | Packet | Operates on raw frames, not abstracted flows |
| **S** | Synthesis | Combines protocol parsing, signatures, and ML into unified events |
| **E** | Engine | Single binary, single process, single source of truth |

---

## Architecture Overview

### 3-Layer Design

NAPSE follows a strict 3-layer separation that maps to different execution contexts and languages, each chosen for the performance characteristics of its responsibilities:

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                        NAPSE - Neural Adaptive Packet Synthesis Engine               │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                      │
│  LAYER 0: KERNEL FAST PATH (eBPF/XDP) ─── C                                        │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐    │
│  │   XDP Gate     │  │  AF_XDP        │  │  eBPF Ringbuf  │  │ Conntrack-Lite │    │
│  │  (drop/pass/   │  │  Zero-Copy     │  │  (metadata     │  │ (TCP state in  │    │
│  │   redirect)    │  │  Socket RX     │  │   export)      │  │  eBPF maps)    │    │
│  └───────┬────────┘  └───────┬────────┘  └───────┬────────┘  └───────┬────────┘    │
│          │                   │                   │                   │              │
│  ════════╪═══════════════════╪═══════════════════╪═══════════════════╪══════════    │
│          │  AF_XDP umem      │                   │  ringbuf          │              │
│          │  zero-copy        │                   │  callback         │              │
│          ▼                   ▼                   ▼                   ▼              │
│                                                                                      │
│  LAYER 1: PROTOCOL ENGINE ─── Rust (PyO3 bindings)                                  │
│  ┌────────────────┐  ┌────────────────────────────────┐  ┌────────────────────┐    │
│  │  Connection    │  │  Protocol Parsers              │  │  Pattern Matcher   │    │
│  │  Table         │  │  ┌──────┬──────┬──────┬──────┐ │  │  (Aho-Corasick    │    │
│  │  (lock-free,   │  │  │ TCP  │ DNS  │ HTTP │ TLS  │ │  │   SIMD + Bloom    │    │
│  │   5-tuple key) │  │  ├──────┼──────┼──────┼──────┤ │  │   filters)        │    │
│  │                │  │  │ DHCP │ SSH  │ mDNS │ SSDP │ │  │                    │    │
│  │  Community ID  │  │  ├──────┼──────┼──────┼──────┤ │  ├────────────────────┤    │
│  │  (1:xxxx)      │  │  │ SMTP │ SMB  │ MQTT │Modbus│ │  │  ML Inference      │    │
│  │                │  │  ├──────┼──────┼──────┼──────┤ │  │  (ONNX Runtime     │    │
│  │  File Tracker  │  │  │ DNP3 │ QUIC │ RDP  │ FTP  │ │  │   DGA + anomaly)   │    │
│  │  (reassembly)  │  │  └──────┴──────┴──────┴──────┘ │  │                    │    │
│  └───────┬────────┘  └───────────────┬────────────────┘  └─────────┬──────────┘    │
│          │                           │                             │                │
│  ════════╪═══════════════════════════╪═════════════════════════════╪════════════    │
│          │  typed ring buffer        │                             │                │
│          │  (shared memory)          │                             │                │
│          ▼                           ▼                             ▼                │
│                                                                                      │
│  LAYER 2: EVENT SYNTHESIS ─── Python                                                │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐               │
│  │  Event Bus   │ │  Log Emitter │ │  QSecBit     │ │  AEGIS       │               │
│  │  (typed ring │ │  (TSV/EVE    │ │  Direct Feed │ │  Bridge      │               │
│  │   buffer)    │ │   compat)    │ │  (bypass     │ │  (Standard-  │               │
│  │              │ │              │ │   log files)  │ │   Signal)    │               │
│  ├──────────────┤ ├──────────────┤ ├──────────────┤ ├──────────────┤               │
│  │  D2D Bubble  │ │  ClickHouse  │ │  Notice      │ │  Prometheus  │               │
│  │  Feed        │ │  Shipper     │ │  Emitter     │ │  Metrics     │               │
│  │  (mDNS +     │ │  (direct     │ │  (New_Device │ │  (/metrics   │               │
│  │   conn recs) │ │   insert)    │ │   Susp_DNS)  │ │   endpoint)  │               │
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘               │
│                                                                                      │
│  OUTPUTS:                                                                            │
│  ┌─────────────────────────────────────────────────────────────────────────────┐    │
│  │  QSecBit ── AEGIS ── D2D Bubbles ── ClickHouse ── Cortex ── Mesh ── OVS   │    │
│  └─────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                      │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

### Data Flow

A single packet traverses the system as follows:

```
Raw Ethernet Frame (wire)
    │
    ▼
┌─ XDP Gate (eBPF) ──────────────────────────────────────────────────┐
│  1. Check blocked_ips map → XDP_DROP (microsecond blocking)        │
│  2. Check rate_limit maps → XDP_DROP if exceeded                   │
│  3. Extract 5-tuple, write to ringbuf (metadata only)              │
│  4. Redirect to AF_XDP socket → XDP_REDIRECT                      │
└────────────────────────────────────────────────────────────────────┘
    │                              │
    │ AF_XDP zero-copy             │ ringbuf metadata
    │ (full packet)                │ (5-tuple + stats)
    ▼                              ▼
┌─ Rust Protocol Engine ─────────────────────────────────────────────┐
│  5. Connection table lookup/create (lock-free hashmap)             │
│  6. Protocol detection (port + heuristic)                          │
│  7. Protocol parser (stateful, per-connection)                     │
│  8. Pattern matcher (Aho-Corasick on reassembled payload)          │
│  9. ML inference (DGA score for DNS, anomaly for flows)            │
│ 10. Emit typed events to ring buffer                               │
└────────────────────────────────────────────────────────────────────┘
    │
    │ typed event structs (shared memory ring buffer)
    ▼
┌─ Python Event Synthesis ───────────────────────────────────────────┐
│ 11. Event bus dispatches to registered consumers:                   │
│     → QSecBit feed (ThreatEvent objects, direct Python call)       │
│     → AEGIS bridge (StandardSignal emission)                       │
│     → D2D Bubble feed (mDNS pairs, connection records)             │
│     → ClickHouse shipper (batch INSERT)                            │
│     → Log emitter (TSV conn.log / EVE JSON compat)                │
│     → Notice emitter (high-severity alerts)                        │
│     → Prometheus metrics (counters, histograms)                    │
└────────────────────────────────────────────────────────────────────┘
```

### Why Three Languages?

| Layer | Language | Rationale |
|-------|----------|-----------|
| **L0** | C | eBPF bytecode compiles from restricted C; only language the BPF verifier accepts |
| **L1** | Rust | Zero-cost abstractions, no GC pauses, SIMD intrinsics, memory safety without runtime |
| **L2** | Python | Rich HookProbe ecosystem integration (QSecBit, AEGIS, D2D are all Python) |

The Rust engine is exposed to Python via **PyO3** (compiled to a `.so` via maturin), giving Python callers native-speed access to connection state, parsed protocol fields, and pattern match results without serialization overhead.

---

## Performance Targets

### Legacy IDS vs NAPSE

| Metric | Legacy IDS/NSM (Typical) | NAPSE (Target) | Improvement |
|--------|---------------------------|-----------------|-------------|
| **Packet capture** | AF_PACKET | AF_XDP zero-copy | 3-5x throughput |
| **Connection tracking** | ~10 us/lookup | <1 us/lookup (lock-free) | 10x |
| **Signature matching** | ~50 us/packet | <10 us/packet (Aho-Corasick SIMD) | 5x |
| **TLS fingerprinting (JA3)** | ~100 us/handshake | <5 us/handshake (Rust) | 20x |
| **RAM (Fortress, 4GB)** | ~2 GB combined | ~200 MB | 10x reduction |
| **RAM (Sentinel, 256MB)** | Not feasible | ~30 MB | Enables Sentinel |
| **CPU idle** | 15-40% | <1% | 15-40x reduction |
| **Alert latency** | ~100 ms (log parse) | <1 ms (direct feed) | 100x |
| **Startup time** | ~25 s combined | <2 s | 12x |
| **Max throughput** | ~1 Gbps | ~10 Gbps (AF_XDP) | 10x |
| **Container image size** | ~900 MB combined | ~100 MB | 9x reduction |
| **Log normalization** | Required (log shipper) | Not needed (typed events) | Eliminates component |
| **Processes** | 2 (separate configs) | 1 (unified config) | Simplified operations |

### Latency Breakdown (per packet, Fortress tier)

```
XDP Gate decision:           ~100 ns  (block/pass/redirect)
AF_XDP to userspace:         ~500 ns  (zero-copy mmap)
Connection table lookup:     ~200 ns  (lock-free, cache-warm)
Protocol parsing:           ~1-5 us   (depends on protocol complexity)
Aho-Corasick scan:          ~2-8 us   (payload dependent)
ML inference (if triggered): ~50 us   (ONNX, DNS queries only)
Ring buffer write:           ~100 ns  (single producer)
Python event dispatch:      ~10 us    (async, non-blocking)
────────────────────────────────────────
Total (typical):             ~5-15 us  (vs ~150 us current)
Total (with ML):             ~50-70 us (vs ~250 us current)
```

---

## Tier Scaling

NAPSE adapts its feature set to the hardware capabilities of each HookProbe product tier:

| Feature | Sentinel (256MB) | Guardian (1.5GB) | Fortress (4GB) | Nexus (16GB+) |
|---------|:-----------------:|:-----------------:|:---------------:|:--------------:|
| **Layer 0: XDP Gate** | SKB mode | SKB/DRV mode | DRV/HW mode | HW mode |
| **Layer 0: AF_XDP** | No (AF_PACKET) | Yes (1 queue) | Yes (2 queues) | Yes (N queues) |
| **Layer 0: Conntrack-Lite** | No | Yes | Yes | Yes |
| **Layer 1: Connection Table** | 1K entries | 10K entries | 100K entries | 1M entries |
| **Layer 1: TCP Reassembly** | No | Partial (64KB) | Full (256KB) | Full (1MB) |
| **Layer 1: Protocol Parsers** | DNS, DHCP, mDNS | +HTTP, TLS, SSH | +All 16 parsers | +All + custom |
| **Layer 1: Aho-Corasick** | No (bloom only) | 1K patterns | 10K patterns | 50K+ patterns |
| **Layer 1: ONNX ML** | No | DGA only | DGA + anomaly | DGA + anomaly + custom |
| **Layer 2: QSecBit Feed** | Simplified | Full | Full | Full + correlation |
| **Layer 2: AEGIS Bridge** | No | Yes | Yes | Yes |
| **Layer 2: D2D Bubble Feed** | mDNS only | mDNS + conn | Full | Full + historical |
| **Layer 2: ClickHouse** | No | No | Yes | Yes (batch) |
| **Layer 2: Log Compat** | No | Yes | Yes | Yes |
| **Layer 2: Prometheus** | Basic | Standard | Full | Full + custom |
| **Target RAM** | ~30 MB | ~80 MB | ~200 MB | ~500 MB |
| **Target CPU idle** | <0.5% | <1% | <1% | <1% |
| **Max connections** | 1,000 | 10,000 | 100,000 | 1,000,000 |
| **Config file** | `sentinel.yaml` | `guardian.yaml` | `fortress.yaml` | `nexus.yaml` |

### Tier Selection Logic

The tier is determined at startup from `/etc/hookprobe/fortress.conf` (or equivalent per-product config):

```python
# In synthesis/__init__.py
import os

TIER = os.environ.get("HOOKPROBE_TIER", "fortress").lower()
CONFIG_MAP = {
    "sentinel": "config/sentinel.yaml",
    "guardian": "config/guardian.yaml",
    "fortress": "config/fortress.yaml",
    "nexus":    "config/nexus.yaml",
}
```

---

## Component Details

### Layer 0: Kernel Fast Path

Layer 0 runs entirely in the Linux kernel as eBPF programs attached to the XDP hook point. Its role is twofold: (1) drop known-bad traffic at wire speed before it reaches userspace, and (2) deliver accepted packets to userspace via zero-copy AF_XDP sockets.

#### XDP Gate (`kernel/xdp_gate.c`)

The XDP Gate is the first code to touch every inbound packet. It extends the existing `XDPManager` in `core/qsecbit/xdp_manager.py` by adding packet steering alongside blocking:

```
Packet arrives at NIC
    │
    ├── Check blocked_ips BPF map → XDP_DROP
    ├── Check rate_limit BPF maps → XDP_DROP if exceeded
    ├── Extract 5-tuple (src_ip, dst_ip, src_port, dst_port, proto)
    ├── Write metadata to eBPF ringbuf (5-tuple + timestamp + pkt_len)
    └── XDP_REDIRECT to AF_XDP socket (zero-copy)
```

**Relationship to existing `xdp_manager.py`**: The current XDP DDoS program in `core/qsecbit/xdp_manager.py` defines `blocked_ips`, `rate_limit_ts`, `rate_limit_count`, and `stats` BPF maps. NAPSE's XDP Gate reuses these exact map definitions for backward compatibility. During the transition period (Phases 1-6), both the legacy XDP program and NAPSE's XDP Gate can coexist because they share the same map pinning path (`/sys/fs/bpf/hookprobe/`). In Phase 7, the legacy program is retired and NAPSE owns the XDP hook exclusively.

**Verdicts**:

| Verdict | Meaning | Cost |
|---------|---------|------|
| `XDP_DROP` | Blocked IP or rate-limited; packet is discarded at NIC driver level | ~100 ns |
| `XDP_REDIRECT` | Packet steered to AF_XDP socket for userspace processing | ~200 ns |
| `XDP_PASS` | Fallback: packet goes through normal kernel stack (SKB mode) | ~1 us |

**NIC Compatibility**: The existing `NICDetector` class in `core/qsecbit/nic_detector.py` detects the best XDP mode for the installed NIC. NAPSE uses this detection at startup:

| XDP Mode | NIC Examples | Performance |
|----------|-------------|-------------|
| `XDP-HW` | Netronome SmartNIC, Mellanox ConnectX | Line rate, offloaded |
| `XDP-DRV` | Intel i225, Realtek r8169 (5.x+), Broadcom | Near line rate, in driver |
| `XDP-SKB` | All NICs (generic fallback) | Good, after SKB allocation |

#### AF_XDP Zero-Copy Socket (`kernel/af_xdp_rx.c`)

AF_XDP provides a kernel-bypass path for packet delivery. Instead of the kernel allocating an `sk_buff`, copying data, and waking the socket, AF_XDP uses a shared memory region (`umem`) mapped into both kernel and userspace:

```
┌─────── Kernel ───────┐     ┌─────── Userspace (Rust) ──────┐
│                       │     │                                │
│  NIC DMA → umem page  │────▶│  Read packet from umem page    │
│  (zero copy)          │     │  (no memcpy, mmap'd)           │
│                       │     │                                │
│  Fill ring ◀──────────│─────│  Return consumed pages          │
│  Completion ring ────▶│────▶│  Track completed TX             │
│  RX ring ────────────▶│────▶│  Receive descriptor (offset)    │
│  TX ring ◀────────────│─────│  Submit TX descriptors          │
│                       │     │                                │
└───────────────────────┘     └────────────────────────────────┘
```

**Queue Configuration**:
- Sentinel: AF_PACKET fallback (no AF_XDP)
- Guardian: 1 RX queue, 512 frame umem
- Fortress: 2 RX queues, 4096 frame umem
- Nexus: N RX queues (per-CPU), 16384 frame umem

#### eBPF Ringbuf (`kernel/ringbuf_events.c`)

The ringbuf exports lightweight metadata about every packet for connection tracking and flow statistics, without copying the full packet payload. Each event is a fixed 40-byte struct:

```c
struct napse_pkt_meta {
    __u64 timestamp_ns;    // ktime_get_ns()
    __u32 src_ip;          // network byte order
    __u32 dst_ip;          // network byte order
    __u16 src_port;        // network byte order
    __u16 dst_port;        // network byte order
    __u16 pkt_len;         // total packet length
    __u8  ip_proto;        // IPPROTO_TCP / UDP / ICMP
    __u8  tcp_flags;       // SYN/ACK/FIN/RST
    __u8  vlan_id;         // 802.1Q VLAN tag (0 = untagged)
    __u8  _pad[7];         // alignment to 40 bytes
};
```

The ringbuf is sized per tier:
- Sentinel: 256 KB (6,400 events)
- Guardian: 1 MB (25,600 events)
- Fortress: 4 MB (102,400 events)
- Nexus: 16 MB (409,600 events)

#### Conntrack-Lite (`kernel/conntrack_lite.c`)

A minimal TCP state machine implemented entirely in eBPF maps. This is NOT a replacement for the full Rust connection table; it provides enough state in the kernel to make XDP-level decisions about established flows:

```
BPF_HASH(conntrack, struct ct_key, struct ct_state, 65536);

States: NEW → SYN_SENT → SYN_RECV → ESTABLISHED → FIN_WAIT → CLOSED
```

**Use Cases**:
- Drop packets for connections in `CLOSED` state (stale RST floods)
- Fast-pass packets for `ESTABLISHED` connections (reduce userspace load)
- Detect SYN floods (too many `SYN_SENT` from same source)

On Sentinel and Guardian tiers where AF_XDP is not available or limited, Conntrack-Lite is the primary mechanism for reducing userspace processing load.

---

### Layer 1: Protocol Engine (Rust)

The Rust engine is the core of NAPSE. It is compiled as a shared library (`.so`) via PyO3/maturin, loadable from Python as `import napse_engine`. The engine is single-threaded per RX queue, using a run-to-completion model (no async, no thread pool) for predictable latency.

#### Connection Table (`engine/src/conntrack.rs`)

A lock-free hash map keyed by 5-tuple (source IP, destination IP, source port, destination port, IP protocol), storing per-connection state:

```rust
pub struct Connection {
    pub id: CommunityId,           // Community ID v1 (1:xxxx)
    pub state: ConnState,          // TCP FSM or UDP pseudo-state
    pub protocol: DetectedProtocol,// Detected application protocol
    pub parser: Box<dyn Parser>,   // Protocol-specific parser instance
    pub bytes_to_server: u64,      // Total bytes client → server
    pub bytes_to_client: u64,      // Total bytes server → client
    pub packets_to_server: u32,    // Packet count client → server
    pub packets_to_client: u32,    // Packet count server → client
    pub start_time: Instant,       // Connection start
    pub last_seen: Instant,        // Last packet timestamp
    pub ja3_hash: Option<[u8; 16]>,// JA3 fingerprint (TLS only)
    pub ja3s_hash: Option<[u8; 16]>,// JA3S fingerprint (TLS only)
    pub server_name: Option<String>,// SNI from TLS ClientHello
    pub matched_sigs: Vec<SigId>,  // Matched signature IDs
}
```

**Community ID** (`engine/src/community_id.rs`): Every connection is assigned a [Community ID](https://github.com/corelight/community-id-spec) v1 hash for cross-system correlation. The existing AIOCHI ClickHouse schema at `shared/aiochi/schemas/clickhouse-init.sql` already indexes on `community_id`, enabling correlation across all NAPSE event types.

**Connection Lifecycle**:

```
Packet arrives → 5-tuple extraction → HashMap lookup
    │
    ├── Miss: Create new Connection, detect protocol, instantiate parser
    │         → Emit connection_new event
    │
    ├── Hit:  Update counters, advance TCP FSM, feed parser
    │         → Parser may emit protocol-specific events
    │
    └── Timeout/FIN: Emit connection_closed event with summary
                     → Reclaim entry
```

**Eviction**: Connections are evicted by a background sweep (every 10 seconds) using configurable timeouts:

| Protocol | Established Timeout | Idle Timeout |
|----------|-------------------|--------------|
| TCP | 3600 s | 300 s |
| UDP | 180 s | 30 s |
| ICMP | 30 s | 10 s |

#### File Tracker (`engine/src/file_tracker.rs`)

Tracks file transfers across protocols (HTTP, FTP, SMB) by reassembling file content and computing hashes:

```rust
pub struct TrackedFile {
    pub conn_id: CommunityId,
    pub filename: Option<String>,
    pub mime_type: Option<String>,
    pub size: u64,
    pub sha256: [u8; 32],         // Computed incrementally
    pub md5: [u8; 16],            // For legacy signature compat
    pub extraction_path: Option<PathBuf>,  // If file extraction enabled
}
```

File extraction is optional and disabled by default on Sentinel/Guardian tiers to conserve disk space.

#### Protocol Parsers (`engine/src/protocols/`)

NAPSE includes 16 protocol parsers, each implementing the `Parser` trait:

```rust
pub trait Parser: Send {
    /// Feed a chunk of reassembled data to the parser.
    /// Returns zero or more typed events.
    fn parse(&mut self, direction: Direction, data: &[u8], ts: Instant)
        -> Vec<ProtocolEvent>;

    /// Called when the connection closes. Emit final summary events.
    fn finalize(&mut self) -> Vec<ProtocolEvent>;

    /// Estimated memory usage of this parser instance.
    fn mem_usage(&self) -> usize;
}
```

| # | Protocol | File | Log Output | Key Outputs |
|---|----------|------|------------|-------------|
| 1 | **TCP** | `tcp.rs` | `conn.log` | Connection records, RST analysis, retransmit stats |
| 2 | **DNS** | `dns.rs` | `dns.log` + EVE DNS | Query/response pairs, NXDOMAIN tracking, EDNS info |
| 3 | **HTTP** | `http.rs` | `http.log` + EVE HTTP | Request/response headers, URI, method, status, body hash |
| 4 | **TLS** | `tls.rs` | `ssl.log` + EVE TLS | JA3/JA3S, SNI, certificate chain, ALPN, cipher suite |
| 5 | **DHCP** | `dhcp.rs` | `dhcp.log` | Lease events, Option 55 fingerprint, hostname, vendor |
| 6 | **SSH** | `ssh.rs` | `ssh.log` | HASSH/HASSHServer fingerprints, auth methods, banner |
| 7 | **mDNS** | `mdns.rs` | `mdns.log` | Service announcements, query/response pairing for D2D |
| 8 | **SSDP** | `ssdp.rs` | `ssdp.log` | UPnP device discovery, service types |
| 9 | **SMTP** | `smtp.rs` | `smtp.log` + EVE SMTP | Envelope, headers, attachment hashes, STARTTLS |
| 10 | **SMB** | `smb.rs` | `smb_files.log` | File access, share enumeration, named pipes |
| 11 | **MQTT** | `mqtt.rs` | EVE MQTT | CONNECT, PUBLISH topics, QoS levels |
| 12 | **Modbus** | `modbus.rs` | EVE Modbus | Function codes, register reads/writes, exception codes |
| 13 | **DNP3** | `dnp3.rs` | EVE DNP3 | Application layer objects, unsolicited responses |
| 14 | **QUIC** | `quic.rs` | EVE QUIC | Initial packet SNI, QUIC version, connection ID |
| 15 | **RDP** | `rdp.rs` | EVE RDP | Cookie, negotiation, NLA detection |
| 16 | **FTP** | `ftp.rs` | `ftp.log` | Commands, data channel tracking, file transfers |

**Protocol Detection**: Protocols are detected using a two-stage approach:

1. **Port-based hint**: Well-known ports provide the initial guess (e.g., 53 = DNS, 443 = TLS)
2. **Heuristic confirmation**: The first N bytes are inspected to confirm or override:
   - TLS: `0x16 0x03 0x0X` (ContentType Handshake, Version)
   - HTTP: `GET `, `POST `, `HTTP/`
   - SSH: `SSH-2.0-`
   - DNS: Valid header structure on port 53
   - QUIC: Long header form bit + version field

Unknown protocols get a generic `RawParser` that tracks byte counts and timing without deep inspection.

#### Pattern Matcher (`engine/src/matcher/`)

The pattern matcher provides signature-based detection using NAPSE native rule format:

**Aho-Corasick Automaton** (`engine/src/matcher/aho_corasick.rs`):
- Multi-pattern string matching in a single pass over the payload
- SIMD-accelerated on x86_64 (AVX2) and aarch64 (NEON) via the `aho-corasick` crate
- Patterns compiled at startup from `signatures/napse_rules.yaml`

**Bloom Filter Pre-screen** (`engine/src/matcher/bloom.rs`):
- Fast probabilistic check before expensive regex evaluation
- 1% false positive rate, zero false negatives
- Eliminates ~90% of packets from Aho-Corasick scanning

**Rule Format** (`signatures/napse_rules.yaml`):

```yaml
rules:
  - id: NAPSE-2024-001
    msg: "ET SCAN Potential SSH Brute Force"
    proto: tcp
    dst_port: 22
    flow: to_server, established
    content: "SSH-2.0-"
    threshold:
      type: both
      track: by_src
      count: 5
      seconds: 60
    severity: high
    classtype: attempted-admin
    mitre: T1110.001
    reference: "https://attack.mitre.org/techniques/T1110/001/"
```

**Rule Converter** (`signatures/converter.py`): Converts legacy IDS `.rules` files into NAPSE's YAML format for importing existing rulesets.

#### ML Inference (`engine/src/ml/`)

NAPSE embeds ONNX Runtime for lightweight ML inference at the protocol engine layer:

**DGA Classifier** (`engine/src/ml/dga.rs`):
- Classifies DNS query names as benign or DGA-generated
- Model: quantized ONNX (INT8), ~500KB
- Latency: ~50 us per domain
- Integrates with dnsXai's existing DGA detection but runs before DNS response arrives
- Features: character entropy, bigram frequency, consonant ratio, length, TLD risk

**Anomaly Detector** (`engine/src/ml/anomaly.rs`):
- Per-connection anomaly scoring based on flow features
- Model: Isolation Forest exported to ONNX
- Features: bytes ratio, packet size variance, inter-arrival time jitter, port entropy
- Triggered only for connections with >100 packets (avoids overhead on short flows)

ML inference is disabled on Sentinel tier and limited to DGA-only on Guardian tier.

---

### Layer 2: Event Synthesis (Python)

Layer 2 is where NAPSE meets the existing HookProbe Python ecosystem. It reads typed events from the Rust engine's ring buffer and dispatches them to registered consumers. Each consumer is an independent module that can be enabled/disabled per tier.

#### Event Bus (`synthesis/event_bus.py`)

The event bus reads from a shared-memory ring buffer exposed by the Rust engine via PyO3. Events are pre-deserialized by PyO3 into Python dataclasses:

```python
@dataclass
class NapseEvent:
    """Base event from the NAPSE engine."""
    event_type: str          # "conn_new", "conn_closed", "dns_query", "tls_handshake", etc.
    timestamp: float         # Unix timestamp with microsecond precision
    community_id: str        # Community ID v1 (e.g., "1:abcdef123456")
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str               # "tcp", "udp", "icmp"
    payload: dict            # Protocol-specific fields

@dataclass
class ConnectionEvent(NapseEvent):
    """Connection lifecycle event."""
    duration: float
    bytes_to_server: int
    bytes_to_client: int
    packets_to_server: int
    packets_to_client: int
    conn_state: str          # "S0", "S1", "SF", "REJ", etc. (industry-standard)

@dataclass
class DNSEvent(NapseEvent):
    """DNS query/response event."""
    query: str
    qtype: str               # "A", "AAAA", "CNAME", "MX", etc.
    rcode: str               # "NOERROR", "NXDOMAIN", "SERVFAIL"
    answers: list
    dga_score: float         # 0.0 - 1.0 (ML DGA classifier)

@dataclass
class TLSEvent(NapseEvent):
    """TLS handshake event."""
    server_name: str         # SNI
    ja3: str                 # JA3 fingerprint hash
    ja3s: str                # JA3S fingerprint hash
    version: str             # "TLSv1.2", "TLSv1.3"
    cipher: str              # Selected cipher suite
    certificate_chain: list  # Subject CN, issuer, expiry

@dataclass
class AlertEvent(NapseEvent):
    """Signature match or ML alert."""
    signature_id: str        # "NAPSE-2024-001"
    message: str             # Human-readable alert message
    severity: str            # "low", "medium", "high", "critical"
    classtype: str           # Standard IDS classification type
    mitre_id: str            # MITRE ATT&CK technique ID
```

The bus runs in a dedicated thread, dispatching events to consumers asynchronously:

```python
class EventBus:
    def __init__(self, engine: napse_engine.Engine):
        self._engine = engine
        self._consumers: list[Callable[[NapseEvent], None]] = []

    def register(self, consumer: Callable[[NapseEvent], None]) -> None:
        self._consumers.append(consumer)

    def run(self) -> None:
        """Main loop: drain events from engine, dispatch to consumers."""
        while self._running:
            events = self._engine.drain_events(max_batch=256)
            for event in events:
                for consumer in self._consumers:
                    consumer(event)
            if not events:
                time.sleep(0.001)  # 1ms idle sleep
```

#### Log Emitter (`synthesis/log_emitter.py`)

Writes structured log files in standard IDS/NSM formats for compatibility with third-party log analysis tools, SIEM integrations, and the AIOCHI log shipper.

**TSV-format outputs**:

| Log File | Source Events | Format |
|----------|--------------|--------|
| `conn.log` | `ConnectionEvent` | NAPSE TSV |
| `dns.log` | `DNSEvent` | NAPSE TSV |
| `http.log` | `HTTPEvent` | NAPSE TSV |
| `ssl.log` | `TLSEvent` | NAPSE TSV |
| `dhcp.log` | `DHCPEvent` | NAPSE TSV |
| `ssh.log` | `SSHEvent` | NAPSE TSV |
| `smtp.log` | `SMTPEvent` | NAPSE TSV |
| `ftp.log` | `FTPEvent` | NAPSE TSV |
| `files.log` | `FileEvent` | NAPSE TSV |
| `notice.log` | `AlertEvent` | NAPSE TSV |

**EVE JSON output**:

| Log File | Source Events | Format |
|----------|--------------|--------|
| `eve.json` | All events | JSON-per-line (EVE format) |

All log files are written to `/var/log/napse/`.

#### QSecBit Direct Feed (`synthesis/qsecbit_feed.py`)

The highest-priority consumer. NAPSE feeds `ThreatEvent` objects directly into the QSecBit unified engine, bypassing log file parsing entirely:

```python
from core.qsecbit.unified_engine import UnifiedQsecbitEngine, ThreatEvent

class QSecBitFeed:
    """Direct feed from NAPSE to QSecBit scoring engine."""

    def __init__(self, qsecbit: UnifiedQsecbitEngine):
        self._qsecbit = qsecbit

    def on_event(self, event: NapseEvent) -> None:
        if isinstance(event, AlertEvent):
            threat = ThreatEvent(
                attack_type=event.classtype,
                source_ip=event.src_ip,
                dest_ip=event.dst_ip,
                confidence=self._severity_to_confidence(event.severity),
                evidence={"signature_id": event.signature_id,
                          "message": event.message,
                          "mitre_id": event.mitre_id},
                layer=self._classify_layer(event),
            )
            self._qsecbit.ingest_threat(threat)
```

This eliminates the ~100ms log-parse latency and enables sub-millisecond alert-to-score propagation.

#### AEGIS Bridge (`synthesis/aegis_bridge.py`)

Emits `StandardSignal` objects to the AEGIS orchestrator, following the same bridge pattern as existing bridges in `core/aegis/bridges/`:

```python
from core.aegis.bridges.base_bridge import BaseBridge
from core.aegis.types import StandardSignal

class NapseBridge(BaseBridge):
    """NAPSE → AEGIS signal bridge.

    Translates NAPSE events into StandardSignal format
    for the AEGIS orchestrator to route to agents.
    """

    name = "napse"
    poll_interval = 0.0  # Event-driven, not polling

    def on_event(self, event: NapseEvent) -> None:
        if isinstance(event, AlertEvent):
            signal = StandardSignal(
                source="napse",
                event_type=f"ids.{event.classtype}",
                severity=event.severity,
                data={
                    "signature_id": event.signature_id,
                    "message": event.message,
                    "src_ip": event.src_ip,
                    "dst_ip": event.dst_ip,
                    "mitre_id": event.mitre_id,
                    "community_id": event.community_id,
                },
            )
            self.publish(signal)
```

The AEGIS orchestrator routes NAPSE signals using the same `source.event_type_keyword` pattern as other bridges. Example routing rules:

```
"napse.scan"     → WATCHDOG agent
"napse.exploit"  → SHIELD agent
"napse.malware"  → GUARDIAN agent
"napse.anomaly"  → ORACLE agent
```

#### D2D Bubble Feed (`synthesis/bubble_feed.py`)

Provides mDNS query/response pairs and connection records directly to the D2D Bubble system:

```python
class BubbleFeed:
    """Feed mDNS discoveries and D2D connections to the Bubble system."""

    def on_event(self, event: NapseEvent) -> None:
        if event.event_type == "mdns_query":
            # Record mDNS query for D2D pairing
            self._presence_sensor.record_mdns_query(
                mac=event.payload["src_mac"],
                service_type=event.payload["service_type"],
                target=event.payload.get("target"),
            )
        elif event.event_type == "mdns_response":
            # Record mDNS response for D2D pairing
            self._presence_sensor.record_mdns_response(
                mac=event.payload["src_mac"],
                service_type=event.payload["service_type"],
            )
        elif isinstance(event, ConnectionEvent):
            # Feed D2D connection data to connection graph
            self._connection_graph.record_connection(
                src_mac=event.payload.get("src_mac"),
                dst_mac=event.payload.get("dst_mac"),
                protocol=event.proto,
                bytes_total=event.bytes_to_server + event.bytes_to_client,
                duration=event.duration,
            )
```

This provides real-time mDNS pairing with sub-second latency, avoiding any log rotation delays.

#### ClickHouse Shipper (`synthesis/clickhouse_shipper.py`)

Replaces the AIOCHI `log_shipper.py` for IDS/NSM events. Inserts events directly into ClickHouse using batch async inserts:

```python
class ClickHouseShipper:
    """Batch-insert NAPSE events into ClickHouse."""

    def __init__(self, dsn: str, batch_size: int = 1000, flush_interval: float = 5.0):
        self._dsn = dsn
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._buffer: list[dict] = []

    def on_event(self, event: NapseEvent) -> None:
        self._buffer.append(event.to_clickhouse_row())
        if len(self._buffer) >= self._batch_size:
            self._flush()
```

**Target tables** (extending existing AIOCHI schema):

| Table | Events | Existing? |
|-------|--------|-----------|
| `napse_connections` | `ConnectionEvent` | Primary |
| `napse_alerts` | `AlertEvent` | Primary |
| `napse_tls` | `TLSEvent` | Primary |
| `napse_files` | `FileEvent` | Primary |
| `napse_dns` | `DNSEvent` | Primary |

#### Notice Emitter (`synthesis/notice_emitter.py`)

Generates high-severity notices for events that require human attention or automated escalation:

| Notice Type | Trigger | Severity |
|-------------|---------|----------|
| `New_Device` | Unknown MAC on DHCP or first connection | info |
| `Suspicious_DNS` | DGA score > 0.8, DNS tunneling pattern | high |
| `Port_Scan` | >10 unique ports from single source in 60s | medium |
| `Brute_Force` | >5 failed SSH/RDP auth in 60s | high |
| `TLS_Anomaly` | Self-signed cert, expired cert, JA3 blacklist | medium |
| `Lateral_Movement` | Internal-to-internal SMB/RDP/SSH spike | critical |
| `Data_Exfiltration` | Large outbound transfer to new destination | high |
| `C2_Communication` | Known C2 JA3 hash or DNS pattern | critical |

Notices are emitted both as AEGIS `StandardSignal` events and as Napse `notice.log` entries.

#### Prometheus Metrics (`synthesis/metrics.py`)

Exposes NAPSE operational metrics on a `/metrics` HTTP endpoint:

```
# Packet processing
napse_packets_total{verdict="pass|drop|redirect"} counter
napse_bytes_total{direction="rx|tx"} counter
napse_connections_active gauge
napse_connections_total{proto="tcp|udp|icmp"} counter

# Protocol parsing
napse_protocol_events_total{protocol="dns|http|tls|..."} counter
napse_protocol_parse_errors_total{protocol="..."} counter

# Signature matching
napse_signature_matches_total{severity="low|medium|high|critical"} counter
napse_signature_scan_duration_seconds histogram

# ML inference
napse_ml_inferences_total{model="dga|anomaly"} counter
napse_ml_inference_duration_seconds histogram
napse_ml_dga_detections_total counter

# Resource usage
napse_memory_bytes gauge
napse_cpu_seconds_total counter
napse_ring_buffer_usage_ratio gauge
napse_connection_table_usage_ratio gauge
```

---

## Integration Map

### How NAPSE Connects to the HookProbe Stack

```
┌─────────────────────────────────────────────────────────────────────┐
│                         NAPSE Integration Map                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│                          ┌─────────┐                                 │
│              ┌──────────▶│ QSecBit │  Direct ThreatEvent feed        │
│              │           └─────────┘  (replaces log parsing)         │
│              │                                                       │
│              │           ┌─────────┐                                 │
│              ├──────────▶│  AEGIS  │  StandardSignal bridge          │
│              │           └─────────┘  (core/aegis/bridges/napse.py)  │
│              │                                                       │
│              │           ┌─────────┐                                 │
│              ├──────────▶│ dnsXai  │  TLS/JA3 enrichment             │
│  ┌───────┐   │           └─────────┘  (SNI + JA3 for DNS context)    │
│  │       │   │                                                       │
│  │ NAPSE │───┤           ┌─────────┐                                 │
│  │       │   ├──────────▶│D2D Bubble│ mDNS pairs + conn records      │
│  └───────┘   │           └─────────┘  (native mDNS + conn records)   │
│              │                                                       │
│              │           ┌──────────┐                                │
│              ├──────────▶│Autopilot │  Sleep-wake coordination        │
│              │           └──────────┘  (probe_service integration)    │
│              │                                                       │
│              │           ┌─────────┐                                 │
│              ├──────────▶│  Mesh   │  ThreatIntel propagation         │
│              │           └─────────┘  (standard ThreatEvent objects)  │
│              │                                                       │
│              │           ┌─────────┐                                 │
│              ├──────────▶│ Cortex  │  Attack arcs + node status       │
│              │           └─────────┘  (WebSocket events)              │
│              │                                                       │
│              │           ┌──────────┐                                │
│              ├──────────▶│ClickHouse│ Direct batch INSERT             │
│              │           └──────────┘  (replaces log_shipper.py)      │
│              │                                                       │
│              │           ┌─────────┐                                 │
│              └──────────▶│OVS / FTS│  Microsecond blocking            │
│                          └─────────┘  (ovs-ofctl via XDP feedback)    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Integration Details

#### QSecBit (`core/qsecbit/`)

| Phase | Integration Mode | Latency | Mechanism |
|-------|-----------------|---------|-----------|
| 1-4 | **Compatibility**: NAPSE writes structured log files; QSecBit parses them as today | ~100 ms | Log files (existing path) |
| 5+ | **Direct**: `QSecBitFeed` injects `ThreatEvent` objects into `UnifiedQsecbitEngine` | <1 ms | Python function call |

The compatibility mode is critical for risk-free rollout. QSecBit continues reading log files during Phases 1-4 with zero code changes. The switch to direct feed is a configuration toggle:

```yaml
# config/fortress.yaml
qsecbit:
  feed_mode: "direct"    # "compat" for log-file mode, "direct" for in-process
```

#### AEGIS (`core/aegis/`)

A new bridge file at `core/aegis/bridges/napse_bridge.py` follows the `BaseBridge` pattern established by `qsecbit_bridge.py`, `dnsxai_bridge.py`, `dhcp_bridge.py`, and `wan_bridge.py`. Unlike those bridges which poll files or APIs, the NAPSE bridge is push-based: the event bus calls `on_event()` directly.

The orchestrator routing rules for NAPSE signals:

| Signal Pattern | Target Agent | Rationale |
|---------------|-------------|-----------|
| `napse.scan` | WATCHDOG | Port scan, network sweep detection |
| `napse.exploit` | SHIELD | Exploit attempt, CVE match |
| `napse.malware` | GUARDIAN | Malware C2, trojan callback |
| `napse.anomaly` | ORACLE | Statistical anomaly, baseline deviation |
| `napse.brute_force` | VIGIL | Authentication attack |
| `napse.exfiltration` | SCOUT | Data leak, large outbound transfer |
| `napse.lateral` | WATCHDOG + SHIELD | Internal movement, privilege escalation |

#### dnsXai (`shared/dnsXai/`)

NAPSE provides two enrichment points for dnsXai:

1. **TLS Context**: When dnsXai classifies a domain, NAPSE can provide the `TLSEvent` for that connection (JA3 hash, certificate chain, cipher suite). This enriches dnsXai's ML classifier with TLS behavioral features.

2. **DNS Event Pre-classification**: NAPSE's built-in DGA classifier runs at Layer 1 (Rust, ~50us) before dnsXai's Python classifier. If the DGA score exceeds 0.9, the domain can be blocked at XDP level on the next packet without waiting for dnsXai's verdict.

#### D2D Bubble System (`products/fortress/lib/`)

NAPSE replaces two legacy-dependent components:

| Current Component | NAPSE Replacement | Benefit |
|-------------------|-------------------|---------|
| `MDNSParser` in `presence_sensor.py` | `BubbleFeed.on_event(mdns_query/response)` | Real-time (vs 5-10s log rotation) |
| `ConnectionGraphAnalyzer` in `connection_graph.py` | `BubbleFeed.on_event(ConnectionEvent)` | Native flow data, no log parsing |

The D2D Bubble system continues to use its existing `PresenceSensor` and `ConnectionGraph` classes. Only the data source changes from log file parsing to NAPSE event callbacks.

#### Autopilot (`products/fortress/lib/autopilot/`)

NAPSE integrates with the Autopilot "sleep-and-wake" architecture:

- **SLEEPING state**: NAPSE runs in minimal mode (XDP Gate + Conntrack-Lite only, no protocol parsing). CPU usage: <0.1%.
- **IDENTIFYING state**: When Autopilot's DHCP Sentinel or MAC Watcher detects a new device, NAPSE activates full protocol parsing for traffic involving that device's MAC address for 60 seconds (matching the existing `probe_service.py` burst window).
- **PROTECTED state**: NAPSE runs in standard mode with per-device protocol parsing budgets.

This replaces the existing `probe_service.py` tshark-based capture with native NAPSE packet analysis, reducing the burst-mode CPU from 10% to ~3%.

#### Mesh Propagation (`shared/mesh/`)

When NAPSE generates an `AlertEvent` with severity `high` or `critical`, the QSecBit feed converts it to a standard `ThreatEvent` which is then propagated via the existing `QsecbitMeshBridge.report_threat()` pathway. No changes to the mesh layer are required.

#### Cortex Visualization (`shared/cortex/`)

NAPSE events are surfaced on the Cortex globe via the existing `ConnectorManager`:

| NAPSE Event | Cortex Visualization |
|-------------|---------------------|
| `AlertEvent(severity=critical)` | Red attack arc (source IP → node) |
| Response action (block) | Blue repulsion arc (node → source IP) |
| Connection spike | Node pulse animation |
| DGA detection | DNS threat indicator |

#### ClickHouse (`shared/aiochi/`)

The `ClickHouseShipper` replaces the AIOCHI `log_shipper.py` for IDS/NSM events. It uses the native ClickHouse HTTP interface with batch inserts:

```
NAPSE events → Buffer (1000 events or 5s) → HTTP POST → ClickHouse
```

During the transition period, both the legacy log shipper and the NAPSE shipper can run simultaneously. They write to different tables (`napse_intents`, `napse_flows` for the v3 schema).

#### OpenFlow / OVS (`FTS` bridge)

For Fortress deployments, NAPSE can trigger microsecond-level blocking via the OVS `FTS` bridge:

```python
# When XDP blocks an IP, also add OVS flow rule for Layer 2 blocking
def block_at_ovs(src_mac: str, reason: str) -> None:
    """Add OpenFlow drop rule to FTS bridge for MAC address."""
    subprocess.run([
        "ovs-ofctl", "add-flow", "FTS",
        f"table=0,priority=100,dl_src={src_mac},actions=drop"
    ], check=True)
```

This provides defense-in-depth: even if XDP misses a packet (e.g., from a local WiFi client that doesn't transit the WAN interface), the OVS flow rule catches it at Layer 2.

---

## Implementation Phases

### 28-Week Roadmap

```
 W01 ──── W04    W05 ──── W08    W09 ──── W12    W13 ──── W16
┌──────────────┬──────────────┬──────────────┬──────────────┐
│  PHASE 1     │  PHASE 2     │  PHASE 3     │  PHASE 4     │
│  Foundation  │  Protocol    │  Signature   │  eBPF        │
│              │  Completeness│  Engine      │  Enhancement │
│  Rust engine │  +12 parsers │  Aho-Corasick│  AF_XDP      │
│  TCP FSM     │  HTTP, TLS   │  Bloom filter│  Ringbuf     │
│  DNS parser  │  DHCP, SSH   │  Rule convert│  Conntrack   │
│  Conntrack   │  mDNS, SSDP  │  ET compat   │  Zero-copy   │
└──────────────┴──────────────┴──────────────┴──────────────┘

 W17 ──── W20    W21 ──── W24    W25 ──── W28
┌──────────────┬──────────────┬──────────────┐
│  PHASE 5     │  PHASE 6     │  PHASE 7     │
│  Direct      │  ML          │  Deprecation │
│  Integration │  Integration │              │
│  QSecBit feed│  ONNX DGA    │  Remove      │
│  AEGIS bridge│  Anomaly det │   legacy IDS │
│  D2D feed    │  Adaptive    │  Aegis+Napse │
│  ClickHouse  │   baselines  │   split-brain│
│  Autopilot   │  Per-device  │  architecture│
└──────────────┴──────────────┴──────────────┘
```

### Phase 1: Foundation (Weeks 1-4)

**Goal**: Minimal viable engine that can parse TCP connections and DNS queries.

**Deliverables**:
- Rust crate with PyO3 bindings (`napse-engine`)
- Connection table with 5-tuple keyed hashmap
- Community ID v1 implementation
- TCP finite state machine (SYN/ACK/FIN/RST tracking)
- DNS protocol parser (query/response, A/AAAA/CNAME/MX/TXT)
- Napse native `conn.log` and `dns.log` output
- Unit tests with pcap replay
- CI pipeline for Rust + Python build

**Validation**: Compare `conn.log` and `dns.log` output against reference pcap files. Fields must match within tolerance (timestamps within 1ms, byte counts exact).

### Phase 2: Protocol Completeness (Weeks 5-8)

**Goal**: Parse all 16 protocols with Napse native output.

**Deliverables**:
- HTTP parser (request/response headers, URI, body hash)
- TLS parser (JA3/JA3S, SNI, certificate chain, ALPN)
- DHCP parser (lease events, Option 55, hostname)
- SSH parser (HASSH fingerprints, banner)
- mDNS parser (service announcements, query/response pairing)
- SSDP parser (UPnP discovery)
- SMTP, SMB, MQTT, Modbus, DNP3, QUIC, RDP, FTP parsers
- File tracker (SHA256 hashing, MIME detection)
- Napse native log output for all protocols
- EVE JSON output

**Validation**: Full pcap corpus comparison against reference implementations. Protocol-specific field accuracy verified per parser.

### Phase 3: Signature Engine (Weeks 9-12)

**Goal**: Pattern matching engine with native NAPSE rule format.

**Deliverables**:
- Aho-Corasick automaton with SIMD acceleration
- Bloom filter pre-screening layer
- Legacy IDS rule format converter (`converter.py`)
- Native NAPSE rule format (`napse_rules.yaml`)
- Emerging Threats ruleset compatibility
- Threshold and rate tracking per rule
- Signature match event generation
- Performance benchmarks (packets/second at various rule counts)

**Validation**: Alert parity on reference pcap + ruleset. False negative rate must be 0%; false positive rate within 5% tolerance.

### Phase 4: eBPF Enhancement (Weeks 13-16)

**Goal**: Kernel-level fast path for maximum performance.

**Deliverables**:
- XDP Gate program (`xdp_gate.c`) with shared BPF maps
- AF_XDP zero-copy socket integration
- eBPF ringbuf for metadata export
- Conntrack-Lite in eBPF maps
- NICDetector integration for automatic mode selection
- Fallback path for kernels without AF_XDP (<5.4)
- Performance benchmarks (AF_XDP vs AF_PACKET)

**Validation**: Throughput tests on Fortress hardware (Intel N100). Target: 5 Gbps with AF_XDP, 1 Gbps with AF_PACKET fallback.

### Phase 5: Direct Integration (Weeks 17-20)

**Goal**: Replace log-file-based integration with direct event feeds.

**Deliverables**:
- `QSecBitFeed`: Direct `ThreatEvent` injection into `UnifiedQsecbitEngine`
- `NapseBridge`: AEGIS `StandardSignal` emission (new bridge file)
- `BubbleFeed`: Direct mDNS pair + connection record feed to D2D system
- `ClickHouseShipper`: Batch INSERT replacing log_shipper.py
- Autopilot integration (sleep/wake mode switching)
- OVS/FTS flow rule injection for L2 blocking
- Configuration toggle for compat vs direct mode

**Validation**: End-to-end integration test (`tests/test_integration.py`) verifying that a simulated attack flows from NAPSE through QSecBit scoring, AEGIS routing, mesh propagation, and Cortex visualization.

### Phase 6: ML Integration (Weeks 21-24)

**Goal**: Embedded ML inference for DGA detection and anomaly scoring.

**Deliverables**:
- ONNX Runtime integration in Rust engine
- DGA classifier (INT8 quantized, ~500KB model)
- Flow anomaly detector (Isolation Forest, ~200KB model)
- Per-device behavioral baseline learning
- Adaptive threshold calibration
- Model update mechanism (download from mesh)
- ML metrics in Prometheus

**Validation**: DGA detection rate >95% on DGArchive dataset. False positive rate <1% on Alexa top 1M. Anomaly detector validated against labeled attack pcaps.

### Phase 7: Deprecation (Weeks 25-28)

**Goal**: Remove all legacy IDS containers entirely.

**Deliverables**:
- Remove legacy IDS services from `podman-compose.yml`
- Remove legacy log volumes
- Remove AIOCHI log_shipper legacy parsers
- Aegis (Zig+eBPF) + Napse (Mojo) split-brain architecture active
- Updated `install-container.sh` (no legacy IDS download)
- Updated `uninstall.sh` (cleanup NAPSE paths)
- Updated `fortress-ctl.sh` (NAPSE status/logs)
- Updated documentation (CLAUDE.md, ARCHITECTURE.md)
- Migration guide for existing deployments

**Validation**: Full regression test suite. Resource usage benchmarks confirming targets. 48-hour soak test on Fortress hardware.

---

## Container Architecture

### Single Container: `fts-napse`

NAPSE runs as a single container for AI-native intent classification:

```yaml
# In products/fortress/containers/podman-compose.yml
  napse:
    container_name: fts-napse
    build:
      context: ../../../core/napse
      dockerfile: Containerfile.napse
    restart: unless-stopped
    network_mode: host               # Required for raw packet access
    cap_add:
      - SYS_BPF                      # eBPF program loading
      - NET_ADMIN                     # AF_XDP socket creation
      - NET_RAW                       # Raw packet capture
    volumes:
      - /etc/hookprobe:/etc/hookprobe:ro          # Configuration
      - napse_logs:/var/log/napse                  # Log output
      - /sys/fs/bpf:/sys/fs/bpf                   # BPF map pinning
    environment:
      - HOOKPROBE_TIER=fortress
      - NAPSE_CONFIG=/etc/hookprobe/napse.yaml
      - NAPSE_INTERFACE=${WAN_INTERFACE:-eth0}
    profiles:
      - ids                            # IDS profile
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:9100/metrics"]
      interval: 30s
      timeout: 5s
      retries: 3
```

### Resource Comparison

| Metric | Legacy IDS stack | Aegis + Napse | Savings |
|--------|-----------------|---------------|---------|
| **Container images** | ~900 MB (combined) | ~100 MB | 800 MB |
| **RAM (running)** | ~2 GB (combined) | ~200 MB | 1.8 GB |
| **CPU (idle)** | 15-40% | <1% | 14-39% |
| **CPU (1 Gbps)** | Saturated | ~15% | Headroom |
| **Startup time** | ~25s | <2s | 23s |
| **Log volume** | ~50 MB/day (two formats) | ~20 MB/day (unified) | 60% |
| **Processes** | Multiple containers, N threads each | 2 containers (Aegis+Napse), N+1 threads | Simplified |
| **Capabilities** | NET_ADMIN, NET_RAW (x2) | SYS_BPF, NET_ADMIN, NET_RAW | +SYS_BPF |
| **Network mode** | host (x2) | host | -1 container |

### Containerfile

```dockerfile
# core/napse/Containerfile.napse
FROM rust:1.75-slim AS rust-builder
WORKDIR /build
COPY engine/ ./engine/
RUN cd engine && cargo build --release

FROM python:3.11-slim AS python-builder
WORKDIR /build
COPY engine/pyproject.toml engine/Cargo.toml ./engine/
COPY --from=rust-builder /build/engine/target/release/libnapse_engine.so ./engine/
RUN pip install maturin && cd engine && maturin build --release

FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libbpf1 libelf1 clang llvm && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/hookprobe/napse
COPY --from=python-builder /build/engine/target/wheels/*.whl /tmp/
RUN pip install /tmp/*.whl && rm /tmp/*.whl

COPY synthesis/ ./synthesis/
COPY signatures/ ./signatures/
COPY config/ ./config/
COPY kernel/ ./kernel/
COPY requirements.txt .

RUN pip install -r requirements.txt

# Build eBPF programs
RUN cd kernel && make

EXPOSE 9100/tcp
ENTRYPOINT ["python", "-m", "synthesis"]
```

### AIOCHI Integration

When AIOCHI is enabled (`--enable-aiochi`), the Aegis+Napse containers replace all legacy IDS services. NAPSE writes to the same ClickHouse tables that AIOCHI's Grafana dashboards query, so dashboards continue working without modification.

---

## Risk Mitigation

### 1. Backward Compatibility

**Risk**: Existing tools parse legacy IDS log files. Breaking these integrations would cascade failures.

**Mitigation**: The Log Emitter writes structured logs to `/var/log/napse/` using standard formats during the transition period (Phases 1-6). All consumers have been migrated to read from NAPSE native paths.

Only in Phase 7, after all consumers have been migrated to direct feeds, are log files deprecated.

### 2. Protocol Correctness

**Risk**: Protocol parsers produce incorrect output, causing false positives/negatives.

**Mitigation**: Every protocol parser is validated against reference output using a corpus of pcap files:

```bash
# tests/test_log_compat.py
# For each pcap in the corpus:
# 1. Generate reference output from pcap
# 2. Run NAPSE on pcap → test output
# 3. Compare field-by-field within tolerance
```

The pcap corpus includes:
- ISTS public dataset (normal traffic)
- Malware Traffic Analysis samples (malicious traffic)
- Wireshark sample captures (protocol edge cases)
- HookProbe-specific captures (D2D, mDNS, DHCP)

### 3. eBPF Portability

**Risk**: eBPF programs may not load on older kernels or unusual NIC drivers.

**Mitigation**: Multi-level fallback using the existing `NICDetector`:

```
Attempt 1: XDP-HW (hardware offload)
    │ fail
    ▼
Attempt 2: XDP-DRV (native driver)
    │ fail
    ▼
Attempt 3: XDP-SKB (generic)
    │ fail
    ▼
Attempt 4: AF_PACKET (no XDP, pure userspace)
    │ always works
    ▼
Running with degraded performance but full functionality
```

Each fallback level is logged and surfaced in Prometheus metrics (`napse_xdp_mode{mode="hw|drv|skb|none"}`).

### 4. Rust Compilation

**Risk**: Rust cross-compilation for aarch64 (Raspberry Pi) and x86_64 is complex.

**Mitigation**:

1. **Pre-built wheels**: GitHub CI builds `napse_engine` wheels for `manylinux2014_aarch64` and `manylinux2014_x86_64`. The Containerfile downloads the appropriate wheel.

2. **Pure-Python fallback**: A `napse_engine_py` module implements the same API in pure Python. It is 10-50x slower but functionally correct. Used automatically when the Rust wheel fails to load:

```python
# synthesis/__init__.py
try:
    import napse_engine  # Rust via PyO3
    RUST_AVAILABLE = True
except ImportError:
    from .fallback import napse_engine_py as napse_engine
    RUST_AVAILABLE = False
    logger.warning("NAPSE Rust engine not available; using Python fallback (reduced performance)")
```

### 5. Memory Pressure

**Risk**: Connection table growth could exceed available RAM on constrained devices.

**Mitigation**: Per-tier connection table limits with LRU eviction:

| Tier | Max Connections | Eviction Policy |
|------|----------------|-----------------|
| Sentinel | 1,000 | LRU, oldest idle first |
| Guardian | 10,000 | LRU, oldest idle first |
| Fortress | 100,000 | LRU, oldest idle first |
| Nexus | 1,000,000 | LRU with priority (active parsers kept) |

Memory usage is tracked per-connection (`Connection.mem_usage()`) and reported via Prometheus. If total memory exceeds 80% of the configured limit, aggressive eviction kicks in (timeout halved).

### 6. Rule Conversion Accuracy

**Risk**: Legacy IDS rules may not convert perfectly to NAPSE format.

**Mitigation**: The converter (`signatures/converter.py`) tracks unsupported features:

```python
class ConversionResult:
    converted: int        # Successfully converted rules
    skipped: int          # Rules using unsupported features
    warnings: list[str]   # Partial conversions with notes
```

Unsupported legacy rule features (initially):
- `lua` scripts
- `file_data` with `filestore`
- Complex `flowbits` chains (>3 levels)
- `dataset` operations

These represent <5% of the Emerging Threats ruleset and are tracked in a compatibility matrix.

---

## Directory Structure

```
core/napse/
├── __init__.py                        # Package init, version, tier detection
├── README.md                          # Quick-start guide
├── ANALYSIS.md                        # Research: legacy IDS gap analysis
├── ARCHITECTURE.md                    # This document
├── Containerfile.napse                # Multi-stage build (Rust + Python)
├── requirements.txt                   # Python dependencies
│
├── kernel/                            # LAYER 0: eBPF/XDP programs (C)
│   ├── xdp_gate.c                     # XDP entry point: block/pass/redirect
│   ├── af_xdp_rx.c                    # AF_XDP zero-copy socket setup
│   ├── ringbuf_events.c               # eBPF ringbuf metadata export
│   ├── conntrack_lite.c               # Minimal TCP state machine in BPF
│   └── Makefile                       # eBPF compilation (clang -target bpf)
│
├── engine/                            # LAYER 1: Rust protocol engine
│   ├── Cargo.toml                     # Rust crate manifest
│   ├── pyproject.toml                 # maturin/PyO3 build config
│   └── src/
│       ├── lib.rs                     # PyO3 module entry, Engine struct
│       ├── conntrack.rs               # Lock-free connection table
│       ├── community_id.rs            # Community ID v1 implementation
│       ├── file_tracker.rs            # File reassembly and hashing
│       ├── protocols/                 # Protocol parsers
│       │   ├── mod.rs                 # Parser trait definition
│       │   ├── tcp.rs                 # TCP connection tracking
│       │   ├── dns.rs                 # DNS query/response
│       │   ├── http.rs                # HTTP request/response
│       │   ├── tls.rs                 # TLS handshake (JA3/JA3S/SNI)
│       │   ├── dhcp.rs                # DHCP lease events
│       │   ├── ssh.rs                 # SSH (HASSH fingerprints)
│       │   ├── mdns.rs                # mDNS service discovery
│       │   ├── ssdp.rs                # SSDP/UPnP discovery
│       │   ├── smtp.rs                # SMTP envelope and headers
│       │   ├── smb.rs                 # SMB file access
│       │   ├── mqtt.rs                # MQTT pub/sub
│       │   ├── modbus.rs              # Modbus TCP (ICS/SCADA)
│       │   ├── dnp3.rs                # DNP3 (ICS/SCADA)
│       │   ├── quic.rs                # QUIC initial packets
│       │   ├── rdp.rs                 # RDP negotiation
│       │   └── ftp.rs                 # FTP commands and data
│       ├── matcher/                   # Signature matching
│       │   ├── mod.rs                 # Matcher trait definition
│       │   ├── aho_corasick.rs        # Multi-pattern string matching (SIMD)
│       │   └── bloom.rs              # Bloom filter pre-screening
│       └── ml/                        # Embedded ML inference
│           ├── mod.rs                 # ML module entry
│           ├── dga.rs                 # DGA domain classifier (ONNX)
│           └── anomaly.rs             # Flow anomaly detector (ONNX)
│
├── synthesis/                         # LAYER 2: Python event synthesis
│   ├── __init__.py                    # Module init, consumer registration
│   ├── event_bus.py                   # Ring buffer reader, event dispatch
│   ├── log_emitter.py                 # Napse native log writer
│   ├── qsecbit_feed.py               # Direct QSecBit ThreatEvent feed
│   ├── aegis_bridge.py               # AEGIS StandardSignal emission
│   ├── bubble_feed.py                # D2D Bubble mDNS + connection feed
│   ├── notice_emitter.py             # High-severity notice generation
│   ├── clickhouse_shipper.py         # Direct ClickHouse batch INSERT
│   └── metrics.py                     # Prometheus /metrics endpoint
│
├── signatures/                        # Signature database
│   ├── __init__.py
│   ├── napse_rules.yaml               # Native NAPSE rules
│   └── converter.py                   # Legacy IDS .rules → NAPSE YAML
│
├── config/                            # Per-tier configuration
│   ├── napse.yaml                     # Base configuration (all tiers)
│   ├── sentinel.yaml                  # Sentinel overrides (256MB)
│   ├── guardian.yaml                  # Guardian overrides (1.5GB)
│   ├── fortress.yaml                  # Fortress overrides (4GB)
│   └── nexus.yaml                     # Nexus overrides (16GB+)
│
└── tests/                             # Test suite
    ├── __init__.py
    ├── test_conntrack.py              # Connection table unit tests
    ├── test_protocols.py              # Protocol parser unit tests
    ├── test_log_compat.py             # Log output format tests
    ├── test_signature_match.py        # Signature matching accuracy
    └── test_integration.py            # End-to-end integration tests
```

---

## Appendix: Protocol Parser Reference

### Event Type Mapping

Each protocol parser emits specific event types that map to existing HookProbe consumers:

| Parser | Event Types | QSecBit Layer | AEGIS Agent | D2D Bubble |
|--------|-------------|---------------|-------------|------------|
| TCP | `conn_new`, `conn_closed`, `conn_reset` | L4 Transport | WATCHDOG | Connection records |
| DNS | `dns_query`, `dns_response`, `dns_nx` | L7 Application | ORACLE | - |
| HTTP | `http_request`, `http_response` | L7 Application | SHIELD | - |
| TLS | `tls_handshake`, `tls_alert` | L5 Session | WATCHDOG | - |
| DHCP | `dhcp_discover`, `dhcp_ack`, `dhcp_release` | L3 Network | VIGIL | Device join/leave |
| SSH | `ssh_auth`, `ssh_channel` | L5 Session | VIGIL | - |
| mDNS | `mdns_query`, `mdns_response` | L7 Application | - | Query/response pairs |
| SSDP | `ssdp_search`, `ssdp_notify` | L7 Application | - | UPnP discovery |
| SMTP | `smtp_envelope`, `smtp_data` | L7 Application | SCOUT | - |
| SMB | `smb_tree`, `smb_file` | L7 Application | SHIELD | File access pairs |
| MQTT | `mqtt_connect`, `mqtt_publish` | L7 Application | ORACLE | IoT D2D |
| Modbus | `modbus_request`, `modbus_response` | L7 Application | GUARDIAN | ICS D2D |
| DNP3 | `dnp3_request`, `dnp3_response` | L7 Application | GUARDIAN | ICS D2D |
| QUIC | `quic_initial`, `quic_handshake` | L5 Session | WATCHDOG | - |
| RDP | `rdp_negotiate`, `rdp_auth` | L5 Session | VIGIL | - |
| FTP | `ftp_command`, `ftp_transfer` | L7 Application | SCOUT | File transfer pairs |

### Napse Log Output Matrix

| Log File | NAPSE Event Type | Completeness | Notes |
|----------|-----------------|-------------|-------|
| `conn.log` | `ConnectionEvent` | 100% | All fields mapped |
| `dns.log` | `DNSEvent` | 100% | Including EDNS |
| `http.log` | `HTTPEvent` | 95% | Missing: `tags`, `proxied` |
| `ssl.log` | `TLSEvent` | 100% | JA3/JA3S/SNI/certs |
| `dhcp.log` | `DHCPEvent` | 100% | Option 55 included |
| `ssh.log` | `SSHEvent` | 100% | HASSH included |
| `smtp.log` | `SMTPEvent` | 90% | Missing: MIME entity details |
| `ftp.log` | `FTPEvent` | 100% | Including data channel |
| `files.log` | `FileEvent` | 95% | Missing: `analyzers` field |
| `notice.log` | `AlertEvent` | 80% | Different severity model |

### Napse EVE JSON Output Matrix

| EVE Event Type | NAPSE Event Type | Completeness | Notes |
|----------------|-----------------|-------------|-------|
| `alert` | `AlertEvent` | 90% | Different rule ID format |
| `dns` | `DNSEvent` | 100% | Full query/answer |
| `http` | `HTTPEvent` | 95% | Missing: `http_refer` |
| `tls` | `TLSEvent` | 100% | JA3/JA3S/SNI |
| `flow` | `ConnectionEvent` | 100% | Byte/packet counts |
| `fileinfo` | `FileEvent` | 95% | SHA256 + MIME |
| `mqtt` | `MQTTEvent` | 100% | CONNECT + PUBLISH |
| `smb` | `SMBEvent` | 90% | Missing: DCERPC details |
| `stats` | Prometheus metrics | N/A | Different format (Prometheus) |

---

*NAPSE is a proprietary component of HookProbe. Commercial license required for SaaS/OEM use. See LICENSING.md for details.*

*HookProbe v5.1 "Neural" - Federated Cybersecurity Mesh*
*"One node's detection -> Everyone's protection"*
