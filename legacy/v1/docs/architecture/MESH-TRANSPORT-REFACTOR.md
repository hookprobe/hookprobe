# Mesh / Transport Refactor — Scoping Plan & Findings

**Date:** 2026-06-16
**Status:** Phase 1 (dead-code removal) DONE; "duplication merge" assessed and **declined** with evidence; remaining items scoped.
**Scope:** `shared/mesh/`, `core/htp/`, `core/neuro/`, and the three federated/gossip paths.

This document is the authoritative outcome of a four-agent deep investigation of the
mesh / transport surface. Its main purpose is to **stop the recurring "mesh
reimplements core/htp + dup neuro_encoder" audit finding from being treated as a
mechanical dedup** — it is not one — and to record what was actually fixed and what
genuinely remains.

---

## 1. Runtime reality (what is actually live)

| Component | Live where | Imports core/htp? | Imports shared/mesh? |
|-----------|-----------|-------------------|----------------------|
| Fortress VPN client (`products/fortress/lib/htp_vpn_client.py`) | Fortress (`fts-htp-vpn.service`) | **No** — self-contained (stdlib + `cryptography`) | No |
| Guardian VPN client (`products/guardian/lib/htp_vpn_client.py`) | Guardian (offline) | **No** — self-contained | No |
| HTP VPN gateway (`shared/mesh/htp_gateway.py`) | MSSP (`hookprobe-mesh`) | **No** — protocol inline | only `mesh_telemetry` |
| Mesh server (`shared/mesh/mesh_server.py`) | MSSP | No | `neuro_encoder` (resonance handshake) |
| Mesh consciousness (`shared/mesh/consciousness.py`) | Guardian (`guardian-mesh.service`, offline) | No | `unified_transport`, `neuro_encoder`, `nat_traversal` |
| CNO federated sync (`core/cno/federated_sync.py`) | Fortress (`fts-cno`) | No | **No** — gossips over plain HTTP (`urllib`) to MSSP |

**Key consequences**

- The live **VPN does not depend on `core/htp` at all.** The three VPN files
  (Fortress client, Guardian client, MSSP gateway) each implement the VPN wire
  protocol inline and share a byte contract with each other (see §4).
- `core/htp/transport/htp.py` (`HookProbeTransport`, 1274 LOC) has only two
  importers — `core/htp/transport/htp_vpn.py` (a non-deployed VPN variant) and
  `shared/cortex/backend/htp_bridge.py` (the Cortex demo bridge). **Neither is a
  running production service.**
- On **Fortress**, none of `shared/mesh/consciousness`, `shared/dsm/gossip`,
  `shared/mesh/unified_transport`, or `core/htp` is loaded by a running service.
  The mesh stack is live only on **Guardian (offline)** and **MSSP**.

---

## 2. Phase 1 — dead code removed (DONE, commit b0c8e14d)

2,189 LOC of genuinely unreferenced code deleted from `shared/mesh/`:

| File | LOC | Why dead |
|------|-----|----------|
| `relay.py` | 938 | Only re-exported by `__init__`; the live `RelayClient` is `core/neuro/network/nat_traversal` (different class) |
| `tunnel.py` | 1020 | Only re-exported; the live tunnel manager is `products/fortress/lib/cloudflare_tunnel.CloudflareTunnelManager` |
| `propagation.py` | 231 | No importers anywhere; the only references are in a test to a *different*, non-existent path `shared.mssp.mesh_propagation` |

`shared.mesh` still imports cleanly (33 exports). Recoverable via git history.

---

## 3. The "duplication merge" — assessed and DECLINED (false positive)

The audit flagged `shared/mesh/unified_transport.py` as "70% redundant with
`core/htp`" and `shared/mesh/neuro_encoder.py` as "duplicating TER/WeightFingerprint
from `core/neuro`," recommending consolidation. A byte-level comparison shows these
are **divergent reimplementations / different protocols**, not duplicates. Merging
them would change bytes on the wire and break the live mesh handshake and gateway,
for no correctness benefit.

### 3.1 `neuro_encoder.py` vs `core/neuro/` — DIVERGENT

| Aspect | `shared/mesh/neuro_encoder.py` | `core/neuro/` | Compatible? |
|--------|-------------------------------|---------------|-------------|
| TER serialization | `struct.pack('>32s20sQHH', …)` **big-endian**, 64 B | `core/neuro/core/ter.py`: `'<32s20sQHH'` **little-endian**, 64 B | ❌ endianness differs |
| Weight evolution | hash-chain: `W_new = HASH(W_old ‖ TER ‖ η)`, η=0.001, BLAKE3/SHA256 | `core/neuro/neural/engine.py`: fixed-point (Q16.16) gradient descent, SHA512 fingerprint | ❌ different algorithm |
| Resonance handshake | 3-way `RESONATE_INIT(0x01) → ACK(0x02) → CONFIRM(0x03)` with RDV exchange | no equivalent | ❌ unique to mesh |

### 3.2 `unified_transport.py` vs `core/htp/` — DIFFERENT PROTOCOLS

| Aspect | `unified_transport.py` (`MeshPacket`) | `core/htp/transport/htp.py` (`HTPHeader`) | Compatible? |
|--------|---------------------------------------|-------------------------------------------|-------------|
| Header | `'>HBBIQ8sII16s'` = **48 B** (incl. `rdv_prefix`) | `'>HHIQQQ'` = **32 B** | ❌ size + field order |
| Packet taxonomy | `PacketType`: 30 values (HTP + DSM + Neuro + app), `SENSOR=0x20` | `PacketMode`: 4 values, `SENSOR=0x01` | ❌ different value space |
| Handshake | 3-way INIT/ACK/CONFIRM, RDV + weight-fingerprint auth | 2-way minimal + entropy-echo, qsecbit auth | ❌ different flow |

### 3.3 Verdict

**Do not merge.** `core/htp` is a low-bandwidth, keyless, sensor-centric transport;
the mesh `unified_transport` is a DSM-integrated, neurally-authenticated, resilient
transport. They share *concepts* (TER, weight fingerprint, resonance, flow tokens)
but deliberately differ on the wire. The genuine duplication in this area was the
dead `relay.py`/`tunnel.py`/`propagation.py` (now removed). The `neuro_encoder` /
`unified_transport` overlap is a **vocabulary** overlap, not a wire overlap, and is
recorded here as **WON'T-MERGE** so future audits don't re-open it.

If code sharing is ever desired it must be done as **shared interfaces with two
adapters** (not import-aliases), and only in a maintenance window with **Guardian
online** to validate the mesh handshake end-to-end.

---

## 4. Do-not-break VPN wire contract (for any future change)

The three VPN files (Fortress client, Guardian client, MSSP gateway) must stay
byte-identical on these. Changing any one without the others **breaks all tunnels**:

- **HKDF context strings** (all four must match):
  `htp-vpn-session-salt-v2`, `htp-vpn-session-key-v2`,
  `htp-vpn-rekey-salt-v2`, `htp-vpn-rekey-v2`
- **Packet types:** `HELLO=0x01, CHALLENGE=0x02, ATTEST=0x03, ACCEPT=0x04,
  REJECT=0x05, IP_PACKET=0x10, KEEPALIVE=0x14, REKEY=0x18, REKEY_ACK=0x19`
- **Frame:** `struct.pack('>QIB', flow_token, sequence & 0xFFFFFFFF, type)` +
  `nonce(12)` + `ChaCha20Poly1305(ciphertext+tag)`
- **MAC (ATTEST):** `hmac(session_key, nonce+challenge, sha256)`
- **Identity:** Ed25519 server key signs CHALLENGE; clients pin TOFU
- **Addressing:** gateway TUN `10.250.0.1`, client pool `10.250.0.2–254`, UDP `8144`
- **Keepalive 25 s / dead-peer 75 s / old-key grace 10 s on rekey**

---

## 5. Federated / gossip paths — keep separate (verified)

Three paths were assessed for consolidation into DSM. They share gossip *primitives*
(hop-count, `seen_by`, dedup, peer discovery) but their payloads and trust models are
fundamentally different and must not be merged:

| Path | Payload | Trust model | Live |
|------|---------|-------------|------|
| `core/cno/federated_sync.py` | Bloom filters of malicious IPs (privacy-preserving, ε=1.0) | MSSP HTTP relay + peer reputation decay | Fortress (`fts-cno`) |
| `shared/dsm/gossip.py` + `consensus.py` | TPM-signed microblocks, BLS checkpoints | Byzantine 2/3 quorum, hardware identity | MSSP / Guardian |
| `shared/mesh/consciousness.py` | `ThreatIntelligence` records | Neural-resonance HMAC, tier state machine | Guardian (offline) |

**Optional future improvement (low priority):** extract the shared gossip primitives
(hop-limit + `seen_by` + dedup-by-hash + per-peer rate-limit) into one helper that all
three import, leaving payloads/crypto untouched. Not a correctness gap; defer.

---

## 6. Remaining real items (not blocking, scoped)

1. **`tests/test_cross_tier_integration.py` is aspirational** — it imports
   `shared.mssp.{mesh_propagation,auth,recommendation_handler,webhook}` which do not
   exist (`shared/mssp/` has only `bootstrap, client, telemetry_collector, types`).
   Action: align the test to reality or skip with an explicit reason. (Closeable now.)
2. **MSSP mesh_server recurring `Channel handshake failed from 172.30.0.13`** every
   ~5 min (TCP channel path). Needs mesh_server debugging on MSSP; benign to data
   plane (VPN/gateway unaffected). Blocked on a dedicated MSSP session.
3. **`htp_gateway.py` (1712 LOC) has no test coverage** despite being the live
   gateway. Action: add handshake integration tests (HELLO/CHALLENGE/ATTEST). Large;
   schedule separately.
4. **Mesh consolidation requiring Guardian** — any change to `consciousness.py`,
   `unified_transport.py`, `neuro_encoder.py`, or the Guardian VPN client must wait
   for Guardian to be back online so the mesh handshake can be validated end-to-end.

---

## 7. Summary

- **Closed:** 2,189 LOC dead code removed; duplication claim investigated and
  resolved (WON'T-MERGE with evidence); do-not-break contract and federated-paths
  verdict documented.
- **Not a gap:** the `neuro_encoder` / `unified_transport` "duplication" — different
  protocols by design.
- **Open (scoped):** the aspirational cross-tier test; MSSP mesh_server channel
  handshake; gateway test coverage; any Guardian-dependent mesh work.
