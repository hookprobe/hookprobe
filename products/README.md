# HookProbe Products

> **Choose Your Level of Protection - Same Transparency at Every Scale**

HookProbe believes enterprise-grade security should be accessible to everyone. Whether you're protecting a home network on a $75 Raspberry Pi or managing a global mesh of thousands of nodes, you get the same transparent, auditable, empowering technology.

```
products/
├── sentinel/   # DSM Validator (IoT, 256MB RAM)
├── guardian/   # Travel Companion (RPi, 1.5GB RAM)
├── fortress/   # Edge Router (Mini PC, 4GB RAM)
├── nexus/      # ML/AI Compute (Server, 16GB+ RAM)
└── mssp/       # Cloud Federation (mssp.hookprobe.com)
```

---

## The Same Core, Different Scales

Every HookProbe product tier runs the same transparent algorithms. The difference is scale, not quality.

| What You Get | Sentinel | Guardian | Fortress | Nexus | MSSP |
|--------------|----------|----------|----------|-------|------|
| **Transparent threat scoring** | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Auditable decisions** | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Privacy-preserving mesh** | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Your data stays yours** | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Open source foundation** | ✓ | ✓ | ✓ | ✓ | ✓ |

**The only differences:** RAM requirements, hardware capabilities, and advanced features that need more resources.

---

## Product Hierarchy

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          HOOKPROBE PRODUCT TIERS                                │
│                    Same Transparency. Different Scales.                         │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ┌──────────────────────────────────────────────────────────────────────────┐ │
│   │                              MSSP                                         │ │
│   │                    Cloud Federation Platform                              │ │
│   │        Manage thousands of nodes · Same transparency at scale            │ │
│   └──────────────────────────────────────────────────────────────────────────┘ │
│                                      ▲                                          │
│                                      │ HTP                                      │
│   ┌──────────────────────────────────┴───────────────────────────────────────┐ │
│   │                              NEXUS                                        │ │
│   │               ML/AI Heavy Computation · 16GB+ RAM                         │ │
│   │        Train models locally · Full visibility into ML decisions          │ │
│   └──────────────────────────────────────────────────────────────────────────┘ │
│                                      ▲                                          │
│                                      │ HTP                                      │
│         ┌────────────────────────────┼────────────────────────────┐            │
│         ▼                            ▼                            ▼            │
│   ┌───────────┐              ┌───────────┐              ┌───────────┐          │
│   │ FORTRESS  │              │ GUARDIAN  │              │ SENTINEL  │          │
│   │Edge Router│              │  Travel   │              │ Validator │          │
│   │   4GB     │              │  1.5GB    │              │  256MB    │          │
│   │ Mini PC   │              │   RPi     │              │   IoT     │          │
│   │           │              │           │              │           │          │
│   │ Business  │              │ Personal  │              │  Verify   │          │
│   │ Networks  │              │ Protection│              │  & Watch  │          │
│   └───────────┘              └───────────┘              └───────────┘          │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Choosing Your Tier

### What You're Protecting

```
Do you need to train ML models locally?
├── YES → Nexus (16GB+ RAM, GPU optional)
└── NO
    └── Do you need VLAN segmentation or advanced SDN?
        ├── YES → Fortress (4GB RAM, business networks)
        └── NO
            └── Do you need L2-L7 detection and WiFi hotspot?
                ├── YES → Guardian (1.5GB RAM, travel/home)
                └── NO → Sentinel (256MB RAM, IoT validation)
```

### What You're Spending

| Tier | Hardware Cost | Software Cost | Total Investment |
|------|---------------|---------------|------------------|
| **Sentinel** | ~$25 | $0 | ~$25 |
| **Guardian** | ~$75 | $0 | ~$75 |
| **Fortress** | ~$200 | $0 | ~$200 |
| **Nexus** | ~$2000+ | $0 | ~$2000+ |
| **MSSP** | Cloud | Contact us | SaaS pricing |

**Enterprise-grade security for the cost of a nice dinner.**

---

## Sentinel — The Watchful Eye

> **256MB RAM · $25 · IoT-scale protection**

**What it enables:** Lightweight validation for IoT networks, LTE gateways, and constrained devices.

**Transparency features:**
- Full visibility into DSM validation decisions
- Auditable health monitoring logs
- Open source mesh participation

**Best for:** IoT deployments, edge validators, minimal footprint needs

```bash
./install.sh --tier sentinel
```

---

## Guardian — Protection on the Move

> **1.5GB RAM · $75 · Travel companion**

**What it enables:** Take enterprise security with you. Hotel WiFi, coffee shops, airports - everywhere becomes safe.

**Transparency features:**
- See every blocked domain and why (dnsXai)
- View L2-L7 threat decisions in real-time
- Web dashboard shows exactly what's happening
- Export all security data - it's yours

**Best for:** Travelers, remote workers, home labs, personal protection

```bash
./install.sh --tier guardian
```

**What you achieve:**
- Connect to any WiFi knowing you're protected
- Block ads/trackers with full visibility into decisions
- Share threat intelligence without sharing your data

---

## Fortress — Your Digital Stronghold

> **4GB RAM · $200 · Business-grade protection**

**What it enables:** Permanent installation for home offices and small businesses with advanced network segmentation.

**Transparency features:**
- Everything in Guardian, plus:
- VLAN decisions are visible and auditable
- SDN flow rules are documented
- Local AI inference with explainable outputs
- Full integration tests available

**Best for:** Home offices, small businesses, NIS2 compliance needs

```bash
./install.sh --tier fortress --enable-n8n --enable-monitoring
```

**What you achieve:**
- Isolate IoT devices with clear visibility
- Meet compliance requirements with audit-ready logs
- Automate security workflows transparently

---

## Nexus — The Regional Brain

> **16GB+ RAM · $2000+ · ML training capability**

**What it enables:** Local ML model training, regional threat aggregation, federated learning coordination.

**Transparency features:**
- Everything in Fortress, plus:
- See exactly how ML models make decisions
- Audit federated learning contributions
- Full visibility into adversarial testing results
- Export model weights for verification

**Best for:** Multi-site organizations, security research, ML-heavy workloads

```bash
./install.sh --tier nexus --enable-gpu --enable-ha
```

**What you achieve:**
- Train security models without sending data to clouds
- Understand exactly how your AI makes decisions
- Contribute to collective defense while keeping data local

---

## MSSP — Cloud Federation

> **Auto-scale · SaaS pricing · Global coordination**

**What it enables:** Manage thousands of nodes with the same transparency principles.

**Transparency features:**
- Multi-tenant with per-tenant visibility
- Every customer sees their own complete picture
- Aggregated threat intelligence without exposing individual data
- Full audit trail for compliance

**Best for:** Managed Security Service Providers, large enterprises

**Contact:** qsecbit@hookprobe.com

**What you achieve:**
- Offer transparent security as a service
- Show clients exactly how they're protected
- Scale without sacrificing visibility

---

## Feature Comparison

| Feature | Sentinel | Guardian | Fortress | Nexus | MSSP |
|---------|----------|----------|----------|-------|------|
| **RAM Required** | 256MB | 1.5GB | 4GB | 16GB+ | Auto |
| **Typical Hardware** | IoT gateway | RPi 4/5 | Mini PC | Server | Cloud |
| **L2-L7 Detection** | - | ✓ | ✓ | ✓ | - |
| **dnsXai Protection** | - | ✓ | ✓ | ✓ | ✓ |
| **Explainable Decisions** | ✓ | ✓ | ✓ | ✓ | ✓ |
| **WiFi Hotspot** | - | ✓ | ✓ | - | - |
| **VLAN Segmentation** | - | - | ✓ | - | - |
| **OpenFlow SDN** | - | - | ✓ | - | - |
| **Local ML Training** | - | - | ✓ | ✓ | ✓ |
| **Federated Learning** | Participate | Participate | Coordinate | Train | Global |
| **Web Dashboard** | Health | Full | Full | Full | Multi-tenant |
| **Data Export** | ✓ | ✓ | ✓ | ✓ | ✓ |

---

## Upgrade Path

```
Sentinel → Guardian → Fortress → Nexus
   ↓          ↓           ↓          ↓
 Verify    Protect    Segment    Train

Each tier adds capability while maintaining transparency.
Your security data migrates with you.
```

```bash
# Upgrade Guardian to Fortress (keeps your data and config)
./install.sh --tier fortress --migrate
```

---

## Shared Transparent Infrastructure

All products use the same transparent infrastructure from `shared/`:

| Module | What It Does | Transparency |
|--------|--------------|--------------|
| **dnsXai** | AI DNS protection | Every block is explained |
| **mesh** | Collective defense | See your mesh contributions |
| **dsm** | Decentralized consensus | Audit validation decisions |
| **response** | Automated mitigation | View every response action |

### dnsXai Transparency by Tier

| Feature | Guardian | Fortress | Nexus | MSSP |
|---------|----------|----------|-------|------|
| Classification explanations | ✓ | ✓ | ✓ | ✓ |
| Block reason visibility | ✓ | ✓ | ✓ | ✓ |
| ML confidence scores | ✓ | ✓ | ✓ | ✓ |
| CNAME chain visibility | ✓ | ✓ | ✓ | ✓ |
| Federated learning stats | ✓ | ✓ | Full | Global |
| Custom model training | - | - | ✓ | ✓ |

---

## The HookProbe Difference

**Every tier, same principles:**

1. **You see everything** - No hidden decisions
2. **You own your data** - Export anytime, no lock-in
3. **You verify the code** - Open source foundation
4. **You join the collective** - Strengthen everyone while protecting yourself

**Enterprise security isn't about price. It's about capability.**
**HookProbe brings that capability to everyone.**

---

**HookProbe Products v5.0** — *Transparent Security at Every Scale*

AGPL v3.0 (Open Source Components) + Commercial License (Proprietary Components)
