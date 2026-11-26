<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Fleet compute aggregation on heqk: what 1,000 nodes with 4 GB each can and cannot do

**Date:** 2026-11-26. **Status:** research note (Green). It feeds the ADR 0071 amendment of the same date and
ADR 0004 `fleet_mesh`. All throughput figures marked *estimate* are arithmetic from published bandwidth figures,
not measurements; no heqk device speed has been measured yet (ADR 0071 D8).

**Question (operator, 2026-11-26):** if heqk can aggregate compute from many nodes, the local-AI ceiling stops
being one CM5. What does a fleet of 1,000 nodes with 4 GB of RAM each actually buy, and what did V1 already
research?

**Constraint (operator, 2026-11-26):** heqk-native only. No Claude Code, no external model API (ADR 0071 P5
removed), no Linux or GPU workers (ADR 0071, 2026-11-24).

---

## 1. Short answer

1,000 × 4 GB is **a fleet with 1,000 times the throughput, not one machine with 4 TB of RAM.** Over anything
slower than NVLink, the fleet can move **requests**, not **tensors** (ADR 0071, Alternatives). Used that way it
is very strong:

| Pattern | What aggregates | Network cost per request | Fits 4 GB nodes |
|---|---|---|---|
| A. Request parallelism | 1,000 independent explanations / agent jobs at once | one request + one answer | yes |
| B. Specialists across nodes (request-level mixture of experts) | many different small models; a router sends each request to one | one hop | yes |
| C. Sharded memory and retrieval | evidence, IOC and embedding indexes spread over ~2.5 TB usable RAM | fan-out query, top-k merge | yes |
| D. Verified best-of-N | N attempts on N nodes, gates pick the winner (ADR 0071 D7) | N requests | yes |
| E. Federated training of small specialists | data stays on each node; only clipped, noised, signed updates move | one update per round | yes |
| F. One large model sharded across nodes | layers (pipeline) or heads (tensor) on different nodes | per token, per stage or per layer | **LAN cluster only, batch work only** |

The one thing it cannot do is make a single interactive answer come from a model larger than one node can
hold, at interactive speed, over a WAN.

## 2. The physics

**Per node (CM5-class, 4 GB SKU), estimates:**
- Decode reads every weight once per token. LPDDR4X on the CM5 is about 17 GB/s theoretical; assume ~10 GB/s
  achieved.
- Usable for models after the kernel, data plane and the ADR 0060 MG reserve (≥ 64 MiB): roughly 2.5–3 GB.
- Fits: Qwen3-1.7B at Q8 (~1.8 GB, ≤ ~5–9 tok/s) or Q4 (~1 GB, ≤ ~10–17 tok/s); a ~4B model at Q4 (~2.3 GB).
  An 8B model at Q4 (~4.5 GB) does not fit a 4 GB node.
- Today heqk maps no RAM above 4 GiB at all (ADR 0061), so 8 GB and 16 GB CM5 SKUs do not help yet either.

**Across nodes:**
- **Tensor parallelism** needs two all-reduces per transformer layer. A 70B model has 80 layers: 160
  synchronisations per token. At LAN latency (~0.1–0.5 ms) that is tolerable; at WAN latency (20–50 ms) it is
  3–8 s per token from synchronisation alone. distributed-llama also caps the node count at the model's KV-head
  count and needs 2^n nodes.
- **Pipeline parallelism** does not reduce single-request latency: every token still reads all the weights,
  stage after stage. A 70B Q4 model (~40 GB) is ~4 s of memory reads per token at ~10 GB/s, plus one network
  hop per stage. Batching many requests through the pipeline raises *throughput*, not latency.
- **Measured elsewhere:** 4 × Raspberry Pi 5 running an 8B model with distributed-llama: ~3.5 tok/s on a
  100 Mbps switch, ~6 tok/s on 1 GbE (community write-up). Petals ran BLOOM-176B over the internet at roughly
  one step per second. prima.cpp reports ~26 tok/s for 32B on a heterogeneous *home LAN* cluster with GPUs.

**Conclusion:** pattern F belongs inside one site (a P1 LAN cluster of 8–16 nodes) and only for work that can
wait: overnight retro-hunts, report generation, labelling candidate training data. Everything interactive
uses patterns A–E.

## 3. What V1 already had (legacy/v1), honestly

V1 never pooled **compute**. It aggregated **model deltas, IOCs and signatures**. Most of it was in-process,
stubbed, or unsound; it is a requirements source, not code to port.

| V1 mechanism | What it did | Reality | Lesson for heqk |
|---|---|---|---|
| Nexus federated learning (`products/nexus/lib/federated/`) | FedAvg weighted by sample count on one central Nexus server; Gaussian DP (ε 8, δ 1e-5) with an RDP accountant; int8 update compression | No Byzantine-robust aggregation; updates unauthenticated (self-declared `node_id`); no secure aggregation; DP noise from `random.Random()` (not a CSPRNG); largest test 3 nodes in one process, with DP effectively off (`noise_multiplier=0.001`) | Robust aggregation, device-signed updates, secure aggregation, TRNG-seeded noise, real multi-node tests |
| DSM consensus (`shared/dsm/`) | BFT quorum `n − ⌊(n−1)/3⌋` over BLS-aggregated Merkle checkpoints; gossip UDP fanout 3, 5 hops | Signatures gathered sequentially from in-process objects; BLS falls back to RSA; one shared HMAC gossip key; consensus loop never started (constructor bug) | ADR 0004 keeps DSM but needs real aggregate signatures over device identity; per-node keys, never a shared mesh key |
| Bloom-filter IOC sharing (`shared/dsm/bloom_ioc.py`) | Randomised response (ε = 1, ~27% bit flips) then OR-merge between peers | OR-merging noisy filters drives the fill ratio to 1 and the false-positive rate with it | Merge counts or use secure aggregation, not OR of noised bits |
| Mesh consciousness, dnsXai mesh intelligence | Gossip of threats, peer trust EMA, model updates after 3 peers | Share functions log only; one node can replay itself to the consensus threshold; node counts hardcoded | Per-sender dedup, signed contributions, measured scale |
| Scale claims | "1000 nodes share intelligence instantly" (`HOOKPROBE-ARCHITECTURE.md:29`) | No benchmark behind it | Gate every scale claim on a measurement |

Sources: `legacy/v1/products/nexus/lib/federated/aggregation_server.py:243-273`, `privacy.py:87-158`,
`legacy/v1/tests/test_federated_learning.py:706`, `legacy/v1/shared/dsm/consensus.py:209-235`,
`legacy/v1/shared/dsm/crypto/bls.py:15`, `legacy/v1/shared/dsm/bloom_ioc.py:187-241`,
`legacy/v1/shared/mesh/consciousness.py:434-436, 521-524`, `legacy/v1/shared/dnsXai/mesh_intelligence.py:333-340`;
V2 review in `docs/research/htp-dsm-neuro-investigation.md` §1.4, §1.6.

## 4. What heqk can do that the field cannot: bit-exact verified compute

The hard problem of pooling compute from 1,000 nodes is trust: any node may be compromised or faulty. Petals
and similar systems mostly trust volunteers or use reputation.

heqk has an unusual property. The native engine is **integer-only and bit-exact** (ADR 0071 D8): the NEON
path equals the scalar path bit for bit (`neuro-kernels` gate), and a batched pass equals one-token passes.
Two honest heqk nodes given the same model digest and the same request produce **the same output bytes**.

So verification needs no zero-knowledge proofs and no trusted hardware:
- **k-of-n replication:** run a job on k nodes; accept only if the signed output hashes agree. HP-EXEC
  already makes workers sign `(capability_id, request_hash, output_hash, final_seq)` (ADR 0071 D2).
- **Audit sampling:** run most jobs once and re-execute a random fraction elsewhere. A node that ever signs a
  wrong hash is provably faulty: two signed, contradictory results for one request are evidence, recorded in
  the ledger, and the node is suspended.
- The cost is chosen per data class and tier: high-stakes jobs at k = 3, bulk jobs at a few percent audit.

This only holds if determinism is kept as a hard invariant: same engine ABI, same model digest, no
nondeterministic reductions, no float. It should become a gate (`[P-fleet-exact]`): the same job on two
nodes with different core counts and timings returns identical hashes.

## 5. Training: the half of ADR 0071 that had no home

ADR 0071's context named two needs: inference and Neuro's learning. With no GPU or Linux workers, large-model
training has no path in the product. Federated training of **small specialists** does: Neuro's S1 specialist
ships as a 212-byte package, and heads and adapters of that size train on a CPU core. Pattern E, built on the
V1 lessons above:
- updates signed by the device identity, clipped, int8-quantised;
- robust aggregation (coordinate-wise median or trimmed mean), not plain FedAvg;
- secure aggregation, so the aggregator sees only the sum;
- DP noise from the hardware TRNG, with the budget accounted per device;
- the aggregator is a heqk node (or a quorum of them), not a central GPU server;
- Neuro owns models, datasets and quality gates; Conductor only moves signed updates.

Large-model fine-tuning stays in Neuro's development pipeline, shipping signed HNX packages. That split
needs Neuro's agreement (open question in the ADR 0071 amendment).

## 6. The first duty of every node

A fleet node is first a security device for its owner. Donated compute must never cost that:
- fleet jobs run only on compute-role cores (ADR 0060 amendment, worker cores), never on data-plane cores;
- they are preemptible and lowest priority, and stop under the ADR 0023 resource-shed signals;
- memory for fleet jobs comes from a separate budget below the MG reserve;
- the 33-row separation matrix must hold with a fleet job running (gate).

Standalone stays the default. `fleet_mesh` is additive and off by default (ADR 0004); cross-owner pooling
moves only aggregated or public-class data (ADR 0071 D5).

## 7. What has to exist first

| Building block | State | Where |
|---|---|---|
| Compute-role cores with local FP/SIMD | not built | ADR 0060 amendment S0–S2, ADR 0072 |
| A measured tok/s on CM5 | not measured | ADR 0071 C5 |
| Delegation signer, sealed counter, ledger anchor | not built | ADR 0071 C1 |
| Node-to-node transport and `fleet_mesh` | securechannel (Noise IK + ML-KEM-768) exists; mesh and DSM unbuilt | ADR 0004 |
| P1 pairing | built (C1 prep) | `os/conductor` |
| Fleet placement (Select-N quotes at scale, churn, hierarchy: site → region) | design only | ADR 0071 D3 |
| Determinism gate across nodes | not built | this note §4 |

## Sources

- distributed-llama: <https://github.com/b4rtaz/distributed-llama>; 4 × Pi 5 measurements:
  <https://www.hackster.io/lijiahaoxyz/distributed-inference-of-deepseek-using-raspberry-pis-45439a>
- Petals (inference and fine-tuning over the internet): <https://arxiv.org/abs/2312.08361>
- prima.cpp (home clusters): <https://arxiv.org/abs/2504.08791>
- V1 sources: listed under §3.
