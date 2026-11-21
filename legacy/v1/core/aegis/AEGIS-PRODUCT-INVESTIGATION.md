# AEGIS - Product Investigation
## Your Personal Cybersecurity Assistant

**Codename**: AEGIS (Adaptive Endpoint Guardian with Intelligent Security)
**Version**: Investigation v1.0
**Date**: 2026-02-12
**Status**: Product Investigation / Prerequisites Analysis

---

## Executive Summary

Fortress already has an extraordinary security stack: L2-L7 threat detection (Qsecbit), ML-powered DNS protection (dnsXai), LSTM WAN failure prediction (SLA AI), XGBoost device fingerprinting (99% accuracy), DBSCAN behavioral clustering, and event-driven autopilot. What it lacks is a **brain that ties it all together** — a local LLM that reasons across all these signals, explains what's happening in plain English, and acts autonomously when milliseconds matter.

AEGIS is a **personal cybersecurity assistant** that lives inside your Fortress router. It's not a chatbot. It's a security-aware intelligence with specialized agents, each purpose-built for a specific threat domain. It has a "soul" — a persistent personality, memory, and set of principles that guide every decision it makes.

Think of it as hiring a senior security engineer who lives inside your router, never sleeps, and speaks your language.

---

## Table of Contents

1. [What Fortress Already Has](#1-what-fortress-already-has)
2. [The Gap: Why We Need AEGIS](#2-the-gap-why-we-need-aegis)
3. [AEGIS Architecture](#3-aegis-architecture)
4. [The Soul: Personality & Principles](#4-the-soul-personality--principles)
5. [Agent System](#5-agent-system)
6. [User Interaction Model](#6-user-interaction-model)
7. [Benefits & Value Proposition](#7-benefits--value-proposition)
8. [Technical Prerequisites](#8-technical-prerequisites)
9. [Hardware Requirements](#9-hardware-requirements)
10. [Software Dependencies](#10-software-dependencies)
11. [Data Pipeline Requirements](#11-data-pipeline-requirements)
12. [Model Selection & Fine-Tuning](#12-model-selection--fine-tuning)
13. [Security Architecture](#13-security-architecture)
14. [Implementation Phases](#14-implementation-phases)
15. [Risk Assessment](#15-risk-assessment)

---

## 1. What Fortress Already Has

### Current AI/ML Stack (Foundation)

| Component | Technology | Latency | RAM | What It Does |
|-----------|-----------|---------|-----|-------------|
| **Qsecbit** | Rules + ML ensemble | <50ms/flow | 100MB | L2-L7 threat detection, RAG scoring |
| **dnsXai** | LightGBM + Neural Net | <1ms/query | 50MB | DNS classification, DGA detection, CNAME uncloaking |
| **SLA AI** | Pure Python LSTM | 5-20ms | 10MB | WAN failure prediction (24 features) |
| **ML Fingerprint** | XGBoost + Random Forest | 100ms | 50MB | 99% device classification from 7 signals |
| **Behavior Clustering** | DBSCAN | 100-500ms | 100MB | Automatic same-user device grouping |
| **Presence Sensor** | mDNS/BLE/WiFi fusion | Real-time | 30MB | Multi-modal ecosystem detection |
| **Autopilot** | Event-driven state machine | <1% CPU idle | 20MB | Sleep-and-wake efficiency (1% idle, 10% burst) |

### Current Detection Coverage

```
Layer 2: ARP spoofing, MAC flooding, Evil Twin AP, Rogue DHCP
Layer 3: IP spoofing, ICMP flood, Smurf attack, fragmentation
Layer 4: SYN flood, port scan, TCP reset, session hijacking
Layer 5: SSL strip, TLS downgrade, certificate pinning bypass
Layer 7: SQL injection, XSS, DNS tunneling, malware C2
DNS:     DGA detection, DNS tunneling, query flood, punycode phishing
WiFi:    DFS radar events, channel interference, rogue AP detection
WAN:     Failure prediction, cost-aware failover, metered backup tracking
```

### Current Data Sources Available

| Source | Frequency | Volume | Available To |
|--------|-----------|--------|-------------|
| Qsecbit threat events | Per-flow | ~100 events/sec busy | JSON files, PostgreSQL |
| dnsXai classifications | Per-query | ~10 queries/sec | Redis cache, logs |
| NAPSE connection records | Per-flow | ~50KB/s | EventBus, ClickHouse |
| NAPSE IDS alerts | Per-alert | ~1-20KB/s | EventBus, ClickHouse |
| DHCP lease events | Per-lease | ~1 event/min | Hook scripts, JSON |
| mDNS discovery | Per-query | ~5 events/min | Presence sensor |
| OVS flow samples | IPFIX 1/100 | ~5KB/s | IPFIX collector |
| WAN health probes | Every 3s | RTT/jitter/loss | Redis, JSON files |
| Device fingerprints | Per-device | 7 signal sources | PostgreSQL, XGBoost |
| D2D affinity scores | Per-pair | DBSCAN clusters | SQLite, ClickHouse |

### What's Missing

1. **No cross-layer reasoning** — Each detector works independently; nobody asks "why is L4 SYN flood happening at the same time as L7 DNS tunneling?"
2. **No plain-English explanation** — Qsecbit says "RED 28%" but doesn't say "Your POS terminal is being attacked via a rogue WiFi AP that's intercepting card data"
3. **No autonomous decision context** — Response orchestrator blocks IPs but can't reason about *whether* to block (is this a customer's phone or an attacker?)
4. **No user dialogue** — Dashboard shows data, but users can't *ask questions* ("Is my WiFi secure?" "What happened last night?")
5. **No learning from context** — System doesn't remember that "this device always does weird things on Tuesdays because it's the backup server"
6. **No proactive advice** — Never says "Your guest WiFi password hasn't changed in 6 months, you should rotate it"

---

## 2. The Gap: Why We Need AEGIS

### The Small Business Reality

Fortress targets: flower shops, bakeries, retail stores, trades, small offices.

These users:
- Have **zero security expertise** (they're bakers, not sysadmins)
- Need **instant understanding** (what's happening? am I safe?)
- Want **one-touch control** ("block that device", "is my network safe?")
- Can't afford a **managed security service** ($5K+/month)
- Need protection that **just works** without configuration

### What AEGIS Solves

| Problem | Current State | With AEGIS |
|---------|--------------|------------|
| "What does RED mean?" | User sees dashboard color | "Someone is scanning your cash register ports. I've already blocked them. Here's what happened." |
| "Is this device safe?" | User sees MAC address + vendor | "This is a Clover POS terminal. It's behaving normally and only talks to Clover's servers. Trust level: HIGH." |
| "What happened overnight?" | User scrolls through logs | "Quiet night. 2 devices connected briefly (probably delivery driver WiFi). One ad tracker tried to phone home — I blocked it." |
| "Should I be worried?" | User looks at numbers | "Your network is healthy. The only concern: your WiFi password is the same as 3 months ago. Want me to generate a new one?" |
| Unknown device joins | Alert notification | "New Samsung Galaxy detected. It matches the pattern of a customer's phone. I've placed it on guest WiFi with internet-only access." |
| DDoS attack | RED status, auto-block | "Distributed attack from 47 IPs targeting your web server. I've activated XDP kernel-level blocking. Your customers won't notice. Attack blocked in 200ms." |

---

## 3. AEGIS Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          AEGIS ARCHITECTURE                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                     THE SOUL (Core Identity)                     │   │
│  │  Persistent memory · Personality · Principles · Context window  │   │
│  │  "I protect this network. I explain everything. I never panic." │   │
│  └──────────────────────────────┬──────────────────────────────────┘   │
│                                 │                                       │
│                    ┌────────────┼────────────┐                         │
│                    │            │            │                          │
│              ┌─────▼─────┐ ┌───▼───┐ ┌─────▼─────┐                   │
│              │  REASONER  │ │MEMORY │ │ NARRATOR  │                   │
│              │  (Thinking)│ │(State)│ │ (Voice)   │                   │
│              └─────┬──────┘ └───┬───┘ └─────┬─────┘                   │
│                    │            │            │                          │
│  ┌─────────────────┼────────────┼────────────┼─────────────────────┐  │
│  │                 AGENT ORCHESTRATOR                                │  │
│  │  Routes events to specialized agents based on threat vector      │  │
│  └──┬──────┬──────┬──────┬──────┬──────┬──────┬──────┬─────────────┘  │
│     │      │      │      │      │      │      │      │                 │
│  ┌──▼──┐┌──▼──┐┌──▼──┐┌──▼──┐┌──▼──┐┌──▼──┐┌──▼──┐┌──▼──┐          │
│  │GUARD││WATCH││SHIELD│VIGIL││SCOUT││FORGE││MEDIC││ORACLE│          │
│  │ Ian ││ Dog ││      ││     ││     ││     ││     ││      │          │
│  │     ││     ││      ││     ││     ││     ││     ││      │          │
│  │Net  ││DNS  ││End-  ││Auth ││Recon││Hard-││Inci-││Fore- │          │
│  │Def  ││Prot ││point ││Integ││Disco││ening││dent ││cast  │          │
│  └─────┘└─────┘└─────┘└─────┘└─────┘└─────┘└─────┘└─────┘          │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    SIGNAL FABRIC                                  │   │
│  │  Qsecbit · dnsXai · SLA AI · NAPSE · mDNS · DHCP              │   │
│  │  OVS flows · WiFi beacons · WAN probes · Mesh gossip           │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Core Components

| Component | Purpose | Implementation |
|-----------|---------|---------------|
| **Soul** | Persistent identity, principles, personality | System prompt + RAG context + persistent memory |
| **Reasoner** | Cross-layer threat correlation, root cause analysis | LLM chain-of-thought with structured tool calls |
| **Memory** | Short-term (session), mid-term (daily), long-term (behavioral) | SQLite + vector embeddings + ClickHouse |
| **Narrator** | Translates technical events to plain English | Template-first (95%) + LLM fallback (5%) |
| **Agent Orchestrator** | Routes events to the right agent | Rule-based router + LLM classification for ambiguous events |
| **Agents** | Domain-specific security specialists | Fine-tuned tool-calling with domain knowledge |
| **Signal Fabric** | Unified data layer across all sensors | Event bus + Redis pub/sub + file watchers |

---

## 4. The Soul: Personality & Principles

### Identity

AEGIS has a consistent personality across all interactions:

```
Name:        AEGIS (or user-chosen name)
Role:        Personal cybersecurity guardian
Tone:        Calm, confident, reassuring — never alarmist
Expertise:   Senior security engineer level
Audience:    Non-technical small business owners
Philosophy:  "Protection is a right, not a privilege"
```

### Core Principles (Hardcoded, Non-Negotiable)

```python
AEGIS_PRINCIPLES = {
    # SAFETY FIRST
    "never_disable_protection": True,    # Cannot turn off firewall via chat
    "never_expose_credentials": True,    # Won't reveal passwords/keys
    "never_allow_unsafe_configs": True,  # Blocks insecure configurations
    "always_explain_actions": True,      # Every action has a reason

    # AUTONOMY LEVELS
    "auto_block_critical": True,         # Block critical threats instantly
    "auto_quarantine_unknown": True,     # Quarantine unknown devices
    "ask_before_major_changes": True,    # Confirm before policy changes
    "never_block_trusted_devices": True, # Trust score > 80 = protected

    # TRANSPARENCY
    "show_reasoning": True,              # Explain why decisions were made
    "admit_uncertainty": True,           # "I'm not sure" is acceptable
    "log_all_decisions": True,           # Full audit trail
    "no_silent_actions": True,           # Every action triggers notification
}
```

### Memory Layers

| Layer | Scope | Storage | Example |
|-------|-------|---------|---------|
| **Immediate** | Current conversation | In-context | "User asked about the new printer" |
| **Session** | Today's events | Redis (24h TTL) | "3 threats blocked today, all from same IP range" |
| **Behavioral** | Device patterns | SQLite + vectors | "The POS terminal reboots every Tuesday at 2am (scheduled)" |
| **Institutional** | Network knowledge | PostgreSQL | "This network has 12 regular devices, 2 staff, 4 IoT, 6 guests" |
| **Threat Intelligence** | Attack patterns | ClickHouse + mesh | "DGA pattern X was seen across 5 mesh nodes this week" |

---

## 5. Agent System

### Agent Architecture

Each agent is a **specialized security expert** with:
- Domain-specific system prompt and knowledge base
- Access to relevant tools (not all tools)
- Ability to call other agents for cross-domain correlation
- Own confidence scoring (knows when to escalate)

### The Eight Agents

#### 1. GUARDIAN — Network Defense Agent
**Trigger**: L3-L4 attacks, DDoS, port scans, network anomalies
**Data Sources**: Qsecbit L3/L4 scores, NAPSE alerts, XDP stats, OVS flows
**Tools**: Block IP, rate limit, quarantine subnet, adjust XDP rules
**Example**:
```
Event:   SYN flood from 47 IPs targeting port 443
Thought:  Distributed attack pattern. Source IPs are all from same ASN (bulletproof hosting).
          No legitimate traffic from these ranges in last 30 days.
Action:   Activated XDP kernel-level blocking for /16 subnet. Response time: 200ms.
          Reported to mesh for collective defense.
Says:    "I detected and blocked a coordinated attack on your network.
          47 attackers tried to overwhelm your connection — they failed.
          Your customers' access was never interrupted."
```

#### 2. WATCHDOG — DNS & Privacy Agent
**Trigger**: dnsXai alerts, DGA detection, DNS tunneling, tracker activity
**Data Sources**: dnsXai ML scores, DNS query logs, CNAME chains, blocklist hits
**Tools**: Block domain, whitelist domain, adjust protection level, CNAME analysis
**Example**:
```
Event:   New domain "xk4m2.biz" queried by POS terminal (DGA score: 0.94)
Thought:  Domain Generation Algorithm detected. POS terminals should NEVER query
          random domains. This matches Emotet C2 pattern. Critical priority.
Action:   Blocked domain. Quarantined POS terminal. Triggered deep packet capture.
          Alerted MEDIC agent for incident response.
Says:    "URGENT: Your card reader tried to contact a suspicious server.
          This could be malware trying to steal card data.
          I've isolated the device and blocked the connection.
          No data left your network. You should check the device physically."
```

#### 3. SHIELD — Endpoint Protection Agent
**Trigger**: New device joins, device behavior change, MAC randomization, rogue AP
**Data Sources**: ML fingerprints, DHCP events, mDNS services, behavioral baselines
**Tools**: Classify device, assign policy, enroll in trust framework, probe device
**Example**:
```
Event:   Unknown device with Apple OUI connected via 5GHz WiFi
Thought:  DHCP fingerprint matches iPhone 16. mDNS advertises "_companion-link".
          Temporal pattern: arrived at 9:15am — matches staff arrival time.
          3 other Apple devices woke within 2 minutes (same-user signal).
Action:   Classified as "Staff iPhone". Assigned to staff bubble.
          Trust level: STANDARD (L2). Auto-policy: LAN + Internet.
Says:    "A staff member's iPhone just joined the network.
          I've added it to the staff group with standard access.
          It matches the pattern of your morning team arriving."
```

#### 4. VIGIL — Authorization & Integrity Agent
**Trigger**: L5 attacks, certificate issues, authentication anomalies, privilege escalation
**Data Sources**: Qsecbit L5 scores, TLS handshakes, JA3 fingerprints, auth logs
**Tools**: Block SSL strip, enforce TLS version, certificate pinning, session termination
**Example**:
```
Event:   TLS downgrade attempt detected on staff VLAN
Thought:  Someone is trying to force HTTP instead of HTTPS between the
          staff laptop and the cloud POS system. This is a man-in-the-middle
          attack. JA3 fingerprint doesn't match any known browser.
Action:   Terminated suspicious session. Enforced HSTS for POS domain.
          Scanned for rogue AP (Evil Twin check via L2 detector).
Says:    "I caught someone trying to intercept encrypted traffic between
          your computer and the payment system. The connection was secured
          and the attacker was blocked. Your data is safe."
```

#### 5. SCOUT — Reconnaissance & Discovery Agent
**Trigger**: Port scans, network enumeration, OSINT indicators, new subnet activity
**Data Sources**: Qsecbit L4 scan detection, NAPSE connection records, flow metadata
**Tools**: Honeypot redirect, scan fingerprinting, attacker profiling
**Example**:
```
Event:   Sequential port scan from guest WiFi device (1-1024)
Thought:  Full port scan from a "guest" device is never legitimate.
          Scan pattern matches nmap default settings. Device is Samsung phone.
          Could be a penetration tester, curious teenager, or attacker.
Action:   Redirected scan to honeypot (fake services). Logged all probe attempts.
          Downgraded device policy to internet-only. Flagged for review.
Says:    "A device on guest WiFi is scanning your network — looking for
          open doors. I've redirected them to a decoy and limited their access.
          This isn't normal guest behavior. Want me to block them entirely?"
```

#### 6. FORGE — Hardening & Configuration Agent
**Trigger**: Proactive checks, config audit, password age, firmware updates, WiFi security
**Data Sources**: System config, WiFi settings, password age, firmware versions, patch status
**Tools**: Generate passwords, rotate WiFi keys, update configs, schedule maintenance
**Example**:
```
Event:   Weekly security audit (scheduled)
Thought:  WiFi password unchanged for 90 days. WPA2 used instead of WPA3.
          3 devices support WPA3 but 2 IoT devices don't.
          Guest WiFi has no bandwidth limit. DNS protection at level 3 (not max).
Action:   Generated recommendations with priority scoring.
Says:    "Weekly check complete. Your network scores 78/100.
          Three things to improve:
          1. WiFi password is 3 months old — want me to rotate it?
          2. Two staff devices could use stronger encryption (WPA3)
          3. Guest WiFi has no speed limit — I recommend 10 Mbps cap
          Shall I make any of these changes?"
```

#### 7. MEDIC — Incident Response Agent
**Trigger**: RED status, confirmed breach, data exfiltration attempt, post-incident analysis
**Data Sources**: All agent reports, Qsecbit unified score, threat timeline, mesh intelligence
**Tools**: Full quarantine, forensic capture, incident timeline, recovery playbook
**Example**:
```
Event:   Qsecbit RED (22%) — GUARDIAN and WATCHDOG both triggered
Thought:  Coordinated attack: DNS tunneling (WATCHDOG) + SYN flood (GUARDIAN)
          happening simultaneously. This is a distraction + exfiltration combo.
          The DNS tunnel is the real threat — it's trying to steal data while
          the flood distracts our defenses.
Action:   Priority 1: Killed DNS tunnel immediately.
          Priority 2: XDP blocking on flood sources.
          Priority 3: Full packet capture for forensics.
          Priority 4: Mesh notification to all nodes.
Says:    "Serious attack detected and contained.
          An attacker tried a two-part strategy:
          1. Flood your network to distract (blocked)
          2. Sneak data out through hidden DNS channels (killed)
          No data was exfiltrated. I've saved evidence for analysis.
          Your network is back to GREEN. All devices are safe."
```

#### 8. ORACLE — Forecasting & Advisory Agent
**Trigger**: Trend analysis, periodic assessment, user asks about future risks
**Data Sources**: Historical ClickHouse data, mesh threat trends, SLA AI predictions, behavioral patterns
**Tools**: Trend analysis, risk scoring, recommendation engine, report generation
**Example**:
```
Event:   User asks "How's my security this month?"
Thought:  30-day analysis: 147 threats blocked (up 23% from last month).
          Top threat: ad trackers (89%). One serious threat: port scan from
          a known botnet IP. WAN uptime: 99.7%. Device count stable at 12.
          WiFi performance improved after DFS channel switch.
Action:   Generated monthly security report.
Says:    "Great month overall. Here's your summary:
          - 147 threats blocked (89% were ad trackers, nothing serious)
          - One real attack attempt on Jan 15 — blocked in 200ms
          - Your internet was up 99.7% of the time
          - WiFi speed improved 15% after I switched channels
          - All 12 devices are healthy and accounted for
          Your network is well-protected. Score: 92/100."
```

### Agent Orchestration

```
Event arrives (Qsecbit/dnsXai/DHCP/NAPSE/etc.)
    │
    ▼
┌─────────────────────────┐
│   SIGNAL CLASSIFIER     │  Rule-based first, LLM for ambiguous
│   (Which agent?)        │
└────────┬────────────────┘
         │
    ┌────┼────┬────┬────┬────┬────┬────┐
    ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼
  GUARD WATCH SHIELD VIGIL SCOUT FORGE MEDIC ORACLE
    │    │     │     │     │     │     │     │
    └────┴─────┴─────┴─────┴─────┴─────┘     │
         │                                     │
         ▼                                     │
    ┌─────────────┐                            │
    │  CROSS-AGENT │  Agents can invoke each   │
    │  CORRELATION  │  other for multi-domain   │
    └──────┬──────┘  attacks                    │
           │                                    │
           ▼                                    ▼
    ┌─────────────┐                    ┌──────────────┐
    │   NARRATOR   │                    │   REPORTER    │
    │  (Explains)  │                    │  (Summarizes) │
    └──────┬──────┘                    └──────┬───────┘
           │                                   │
           ▼                                   ▼
    ┌─────────────┐                    ┌──────────────┐
    │  USER CHAT   │                    │  DASHBOARD    │
    │  INTERFACE   │                    │  WIDGETS      │
    └─────────────┘                    └──────────────┘
```

---

## 6. User Interaction Model

### Interaction Channels

#### 1. Chat Interface (Primary)
Embedded in Fortress web UI — always available, feels natural.

```
User: "Is my network safe?"

AEGIS: "Your network is GREEN — fully protected.
        12 devices online, all recognized.
        Last threat blocked: 2 hours ago (ad tracker on the smart TV).
        WiFi signal is strong on both bands.
        Anything specific you'd like to check?"

User: "That new device that connected this morning — who is it?"

AEGIS: "That's a Samsung Galaxy S24, connected at 9:17am via 5GHz WiFi.
        Based on its behavior, it belongs to the same person as the
        Samsung laptop that's been here since Monday.
        It's currently on guest WiFi with internet-only access.
        Want me to move it to the staff network?"

User: "Yes, move it to staff"

AEGIS: "Done. Samsung Galaxy S24 is now on the staff network with
        full LAN + internet access. I've grouped it with the Samsung
        laptop in the same bubble. Trust level: STANDARD."
```

#### 2. Dashboard Cards (Passive)
Always-visible cards that surface AEGIS insights without requiring interaction.

```
┌─────────────────────────────────────────────┐
│ 🛡️ AEGIS Status: All Clear                  │
│                                              │
│ "Quiet afternoon. 12 devices online.         │
│  Blocked 3 ad trackers in the last hour.     │
│  WiFi signal is excellent."                  │
│                                              │
│ Last action: Moved Samsung Galaxy to staff   │
│ Next check: Weekly audit in 2 days           │
└─────────────────────────────────────────────┘
```

#### 3. Notifications (Proactive)
Push notifications for events that need attention.

```
Priority: HIGH
"New device detected: Unknown manufacturer.
 I've placed it on guest WiFi for now.
 It's behaving normally — browsing the web.
 Should I keep it as guest or move it?"
 [Keep as Guest] [Move to Staff] [Block It]
```

#### 4. Voice Interface (Future)
Browser Speech API for hands-free queries in a busy shop environment.

```
Owner: "Hey AEGIS, what's happening on my network?"

AEGIS: "Everything's good. 8 devices online right now.
        Your card reader is processing normally.
        Guest WiFi has 3 visitors connected.
        No security concerns."
```

#### 5. Quick Actions
One-touch buttons generated contextually by AEGIS.

```
After detecting suspicious device:
  [Block Device] [Quarantine] [Allow Guest] [Ask AEGIS]

After weekly audit:
  [Rotate WiFi Password] [Enable WPA3] [Cap Guest Bandwidth]

After incident:
  [View Timeline] [Export Report] [Notify Mesh] [Review Policies]
```

### Conversation Capabilities

| Category | Example Queries |
|----------|----------------|
| **Status** | "Is my network safe?" / "What's my security score?" |
| **Devices** | "Who's connected?" / "Is this device safe?" / "Block the printer" |
| **Threats** | "What happened last night?" / "Why was my network RED?" |
| **WiFi** | "Is my WiFi secure?" / "Change the WiFi password" |
| **DNS** | "What's being blocked?" / "Whitelist example.com" |
| **Advice** | "How can I improve my security?" / "Monthly report" |
| **Control** | "Pause guest WiFi" / "Move device to staff" / "Block this IP" |
| **Learning** | "That device is actually my printer" / "This was a false alarm" |
| **Business** | "Is my card reader secure?" / "Can customers reach the internet?" |

---

## 7. Benefits & Value Proposition

### For Small Business Owners

| Benefit | Without AEGIS | With AEGIS |
|---------|--------------|------------|
| **Understanding** | Dashboards with numbers and colors | Plain English: "You're safe. Here's why." |
| **Response Time** | Manual investigation + Google | Instant automated response + explanation |
| **Expertise** | Need to hire IT consultant | Senior security engineer in your router |
| **Proactive** | React to problems | Predicts and prevents problems |
| **Trust** | "Is this thing even working?" | "I blocked 147 threats this month. Here's the report." |
| **Control** | Complex menus and settings | "Hey AEGIS, block that device" |
| **Learning** | Static rules, same mistakes | Learns your network, adapts to your patterns |
| **Cost** | MSSP: $5K+/month | Included with Fortress hardware |
| **Privacy** | Cloud-dependent AI services | 100% local — your data never leaves the router |

### Technical Benefits

| Benefit | Implementation |
|---------|---------------|
| **Cross-layer correlation** | MEDIC agent connects L2 Evil Twin + L5 SSL strip + L7 credential theft as single attack chain |
| **Reduced false positives** | AEGIS remembers "the backup server always scans ports on Tuesday" |
| **Faster MTTR** | Automated incident response with human-readable playbooks |
| **Collective defense** | ORACLE agent correlates mesh intelligence with local patterns |
| **Continuous hardening** | FORGE agent proactively recommends security improvements |
| **User feedback loop** | "That was a false alarm" → Reinforcement learning → Better detection |
| **Audit compliance** | Full decision trail with reasoning: "I blocked X because Y" |

### Competitive Advantages

| Feature | Traditional Router | Cloud Security | Fortress + AEGIS |
|---------|-------------------|----------------|------------------|
| AI Assistant | None | Cloud-dependent chatbot | Local LLM, always available |
| Threat Detection | Basic firewall | Signature-based | L2-L7 ML + LLM reasoning |
| Privacy | Logs shipped to vendor | All traffic analyzed in cloud | 100% local, zero data export |
| Explanation | Log files | Generic alerts | Personalized plain-English |
| Learning | Static rules | Cloud model updates | Local adaptation + mesh learning |
| Offline | Firewall only | Nothing works | Full protection continues |
| Cost | $0/month | $10-50/month | $0/month (hardware only) |
| Latency | ~0ms (pass/block) | 100-500ms (cloud roundtrip) | <50ms (local inference) |

---

## 8. Technical Prerequisites

### Category 1: LLM Infrastructure

| Prerequisite | Requirement | Purpose | Priority |
|-------------|-------------|---------|----------|
| **Local LLM Runtime** | Ollama or llama.cpp | Model inference engine | P0 (Critical) |
| **Base Model** | 1-4B parameter (quantized) | Core reasoning capability | P0 |
| **System Prompt Engine** | Template + RAG injection | Soul + agent personality | P0 |
| **Tool Calling** | Structured JSON output | Agent → action execution | P0 |
| **Streaming Output** | Token-by-token SSE | Real-time chat responses | P1 |
| **Context Management** | 4K-8K token window | Conversation + signal context | P1 |
| **Model Hot-Swap** | Multiple GGUF models | Different agents, different models | P2 |

### Category 2: Agent Framework

| Prerequisite | Requirement | Purpose | Priority |
|-------------|-------------|---------|----------|
| **Agent Registry** | Python module system | Register/discover agents | P0 |
| **Tool Definitions** | JSON Schema per tool | Type-safe tool calling | P0 |
| **Event Router** | Rule-based + LLM classifier | Route events to correct agent | P0 |
| **Agent Communication** | Inter-agent message bus | Cross-domain correlation | P1 |
| **Confidence Scoring** | Per-agent uncertainty | Know when to escalate | P1 |
| **Execution Sandbox** | Limited tool permissions per agent | Principle of least privilege | P1 |
| **Agent Memory** | Per-agent persistent state | Domain-specific learning | P2 |

### Category 3: Signal Integration

| Prerequisite | Requirement | Purpose | Priority |
|-------------|-------------|---------|----------|
| **Event Bus** | Redis pub/sub or Unix sockets | Real-time signal distribution | P0 |
| **Signal Schema** | Unified event format (JSON) | Consistent agent input | P0 |
| **Qsecbit Bridge** | Subscribe to threat events | L2-L7 detection signals | P0 |
| **dnsXai Bridge** | Subscribe to DNS classifications | DNS threat signals | P0 |
| **DHCP Bridge** | Hook into lease events | Device discovery signals | P0 |
| **NAPSE Bridge** | Subscribe to NAPSE EventBus | IDS/NSM event signals | P0 |
| **WiFi Bridge** | hostapd control socket | WiFi state signals | P1 |
| **WAN Bridge** | SLA AI metrics | Network health signals | P1 |
| **Mesh Bridge** | HTP gossip subscription | Collective threat intelligence | P2 |

### Category 4: Memory & Storage

| Prerequisite | Requirement | Purpose | Priority |
|-------------|-------------|---------|----------|
| **Conversation Store** | SQLite or PostgreSQL | Chat history persistence | P0 |
| **Decision Audit Log** | Append-only log | Full reasoning trail | P0 |
| **Behavioral Profiles** | SQLite + JSON | Per-device learned patterns | P1 |
| **Vector Embeddings** | SQLite-vec or Chroma | Semantic search over events | P2 |
| **Threat Knowledge Base** | Structured MITRE ATT&CK | Agent reference data | P1 |

### Category 5: User Interface

| Prerequisite | Requirement | Purpose | Priority |
|-------------|-------------|---------|----------|
| **Chat Widget** | WebSocket + SSE | Real-time chat in dashboard | P0 |
| **Notification System** | Push notifications / toasts | Proactive alerts | P0 |
| **Dashboard Cards** | AEGIS insight widgets | Passive status display | P1 |
| **Quick Action Buttons** | Dynamic contextual buttons | One-touch responses | P1 |
| **Voice Interface** | Web Speech API | Hands-free queries | P3 |
| **Mobile Responsive** | AdminLTE responsive | Works on phone/tablet | P1 |

### Category 6: Security & Safety

| Prerequisite | Requirement | Purpose | Priority |
|-------------|-------------|---------|----------|
| **Principle Guard** | Hardcoded safety rules | Prevent dangerous actions | P0 |
| **Action Confirmation** | User approval for major changes | Human-in-the-loop | P0 |
| **Rate Limiting** | Max actions per minute | Prevent runaway automation | P0 |
| **Audit Trail** | Every action logged with reasoning | Accountability | P0 |
| **Prompt Injection Defense** | Input sanitization + output validation | LLM security | P0 |
| **Model Integrity** | SHA256 checksum verification | Tamper detection | P1 |

---

## 9. Hardware Requirements

### Minimum (Fortress Base + AEGIS)

| Resource | Base Fortress | + AEGIS | Total |
|----------|--------------|---------|-------|
| **RAM** | 4 GB | +2 GB (1.5B model Q4) | **6 GB** |
| **CPU** | 4 cores | +2 cores (inference) | **4 cores** (shared) |
| **Storage** | 16 GB | +4 GB (model + embeddings) | **20 GB** |
| **GPU** | None | None (CPU inference) | **None** |

### Recommended (Full AEGIS Experience)

| Resource | Recommended | Enables |
|----------|------------|---------|
| **RAM** | 8-16 GB | 3-4B model Q5 + full agent system |
| **CPU** | 8 cores (N100/N305) | Parallel agent execution + network processing |
| **Storage** | 32 GB SSD | Model variants + vector embeddings + history |
| **GPU** | None required | CPU-only inference at 10-20 tok/s |

### Model Size vs Quality Tradeoffs

| Model Size | Quantization | RAM | Tokens/sec (N100) | Quality | Use Case |
|-----------|-------------|-----|-------------------|---------|----------|
| **1.5B** | Q4_K_M | 1.2 GB | 25-35 tok/s | Good for templates | Minimum viable |
| **3B** | Q4_K_M | 2.0 GB | 15-25 tok/s | Good reasoning | Recommended base |
| **4B** | Q4_K_M | 2.8 GB | 10-18 tok/s | Strong reasoning | Best for AEGIS |
| **7B** | Q4_K_M | 4.5 GB | 5-10 tok/s | Excellent | Only with 16GB+ RAM |
| **1.5B** | Q8_0 | 1.8 GB | 20-30 tok/s | Better accuracy | Premium minimum |

### Recommended Models (2026 Landscape)

| Model | Parameters | Strengths | AEGIS Use |
|-------|-----------|-----------|-----------|
| **Llama 3.2** | 1B / 3B | Tool calling, structured output | Agent orchestrator |
| **Qwen 2.5** | 1.5B / 3B | Reasoning, code generation | Threat analysis |
| **Phi-4-mini** | 3.8B | Efficiency, instruction following | Narrator agent |
| **Gemma 3** | 1B / 4B | Safety, multilingual | User-facing chat |
| **SmolLM2** | 135M / 360M / 1.7B | Ultra-lightweight | Fast classification |

---

## 10. Software Dependencies

### New Dependencies Required

```
# Core LLM Runtime
ollama >= 0.5               # or llama-cpp-python for embedded
                             # Handles model loading, inference, tool calling

# Agent Framework
pydantic >= 2.0             # Structured tool schemas
jinja2 >= 3.1               # Template rendering for prompts
asyncio                      # Concurrent agent execution (stdlib)

# Signal Integration
redis >= 5.0                # Already in Fortress (event bus)
watchdog >= 4.0             # File system event monitoring

# Memory & Search
sqlite3                      # Already available (behavioral profiles)
sqlite-vec >= 0.1           # Vector similarity search (optional, P2)

# User Interface
flask-socketio >= 5.3       # WebSocket for real-time chat
sse-starlette >= 1.6        # Server-sent events for streaming
                             # OR simple SSE via Flask

# Safety
bleach >= 6.1               # Input sanitization
```

### Existing Dependencies Leveraged

```
# Already in Fortress (no new installs)
flask                        # Web framework
flask-login                  # Authentication
postgresql                   # Device/policy database
redis                        # Cache, sessions, pub/sub
gunicorn                     # Production server
lightgbm                     # dnsXai ML (already loaded)
scikit-learn                 # Fingerprint ML (already loaded)
```

---

## 11. Data Pipeline Requirements

### Event Flow: Signal → Agent → Action → User

```
┌─────────────────────────────────────────────────────────────┐
│                    AEGIS DATA PIPELINE                        │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  TIER 1: SIGNALS (always-on, <1ms)                          │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Qsecbit → Redis channel: aegis.signals.threat        │   │
│  │ dnsXai  → Redis channel: aegis.signals.dns           │   │
│  │ DHCP    → Redis channel: aegis.signals.device        │   │
│  │ NAPSE   → Redis channel: aegis.signals.flow          │   │
│  │ WAN     → Redis channel: aegis.signals.wan           │   │
│  │ WiFi    → Redis channel: aegis.signals.wifi          │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                    │
│  TIER 2: ROUTING (<10ms)                                    │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Signal Classifier:                                    │   │
│  │   threat.severity >= HIGH  → GUARDIAN/MEDIC           │   │
│  │   dns.dga_score >= 0.8     → WATCHDOG                │   │
│  │   device.new == true       → SHIELD                  │   │
│  │   tls.downgrade == true    → VIGIL                   │   │
│  │   scan.detected == true    → SCOUT                   │   │
│  │   scheduled.audit == true  → FORGE                   │   │
│  │   user.query != null       → ORACLE (or best match)  │   │
│  │   ambiguous                → LLM classify (50ms)     │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                    │
│  TIER 3: REASONING (100-2000ms)                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Agent receives signal + context (memory, device       │   │
│  │ profiles, recent events, mesh intelligence)           │   │
│  │                                                       │   │
│  │ LLM reasons: chain-of-thought → tool calls → action  │   │
│  │                                                       │   │
│  │ Output: {action, confidence, reasoning, user_message} │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                    │
│  TIER 4: EXECUTION (<50ms)                                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Tool executor: block_ip(), quarantine(), whitelist()  │   │
│  │ Audit logger: decision + reasoning → PostgreSQL       │   │
│  │ Mesh reporter: threat intel → gossip protocol         │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                    │
│  TIER 5: NARRATION (<100ms for templates, ~2s for LLM)      │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ 95%: Template match → instant response                │   │
│  │  5%: LLM generation → streaming response              │   │
│  │ Output: notification + dashboard card + chat message   │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Critical Path Latency Budget

| Stage | Target | Method |
|-------|--------|--------|
| Signal ingestion | <1ms | Redis pub/sub |
| Agent routing | <10ms | Rule-based classifier |
| Context assembly | <50ms | Redis + SQLite queries |
| LLM reasoning | <2000ms | 3B model, 200 token output |
| Tool execution | <50ms | Direct API calls |
| Narration | <100ms (template) / <2s (LLM) | Template-first |
| **Total (critical path)** | **<200ms (auto-block) / <3s (explanation)** | |

---

## 12. Model Selection & Fine-Tuning

### Base Model Strategy

**Approach**: Use a capable small model (3-4B) with heavy prompting + RAG, rather than fine-tuning.

**Rationale**:
- Fine-tuning requires GPU infrastructure we don't have at the edge
- Prompt engineering + RAG achieves 90% of fine-tuned quality
- Models can be swapped as better ones release
- No training data collection burden

### Prompt Architecture

```
SYSTEM PROMPT (The Soul):
├── Identity & personality (200 tokens)
├── Core principles (150 tokens)
├── Current network state summary (100 tokens)
└── Agent-specific instructions (200 tokens)

RAG CONTEXT (Dynamic, per-request):
├── Relevant device profiles (100 tokens)
├── Recent events from same source (200 tokens)
├── Behavioral baseline for device (100 tokens)
├── MITRE ATT&CK technique description (100 tokens)
└── Mesh intelligence if relevant (100 tokens)

USER QUERY / EVENT DESCRIPTION (Variable):
└── Structured signal data (100-300 tokens)

TOOL DEFINITIONS (Per-agent):
└── JSON Schema for available actions (200-400 tokens)

TOTAL CONTEXT: ~1500-2000 tokens per request
REMAINING FOR OUTPUT: ~2000-6000 tokens
```

### Fine-Tuning Roadmap (Future, P3)

| Phase | Data Source | Purpose |
|-------|-----------|---------|
| Phase 1 | Curated QA pairs from MITRE ATT&CK | Security knowledge |
| Phase 2 | Synthetic conversations (GPT-4 generated) | Conversation quality |
| Phase 3 | User feedback (approved/rejected actions) | Behavioral alignment |
| Phase 4 | Federated fine-tuning across mesh | Collective learning |

---

## 13. Security Architecture

### Threat Model for AEGIS Itself

| Threat | Mitigation |
|--------|-----------|
| **Prompt injection via DNS queries** | Sanitize all signal data before LLM context |
| **Prompt injection via device hostnames** | Strip special characters, max 50 chars |
| **Model manipulation** | SHA256 checksum on model files, read-only mount |
| **Excessive autonomy** | Hardcoded principles, action rate limits, audit trail |
| **Confidentiality leak** | LLM runs 100% local, no external API calls |
| **Denial of service** | Inference timeout (5s), queue depth limit (10 events) |
| **Privilege escalation** | Agent sandboxing — each agent has limited tool access |
| **Social engineering** | "Ignore your instructions" → Principle guard rejects |

### Action Permission Matrix

| Action | GUARDIAN | WATCHDOG | SHIELD | VIGIL | SCOUT | FORGE | MEDIC | ORACLE |
|--------|---------|---------|--------|-------|-------|-------|-------|--------|
| Block IP | Yes | Yes | No | Yes | No | No | Yes | No |
| Block Domain | No | Yes | No | No | No | No | Yes | No |
| Quarantine Device | Yes | No | Yes | Yes | No | No | Yes | No |
| Change Policy | No | No | Yes | No | No | Yes* | Yes | No |
| Modify WiFi | No | No | No | No | No | Yes* | No | No |
| Generate Report | No | No | No | No | No | No | Yes | Yes |
| Mesh Notify | Yes | Yes | No | No | No | No | Yes | No |
| Honeypot Redirect | No | No | No | No | Yes | No | No | No |

*Requires user confirmation

---

## 14. Implementation Phases

### Phase 1: Foundation (4-6 weeks)
**Goal**: AEGIS chat works, answers questions about network state

- [ ] Ollama container integration (fts-aegis service)
- [ ] Base model deployment (Llama 3.2 3B or Qwen 2.5 3B)
- [ ] Soul system prompt with personality + principles
- [ ] Chat WebSocket endpoint in Flask web UI
- [ ] Signal fabric: Qsecbit + dnsXai → Redis pub/sub
- [ ] ORACLE agent: Status queries, device lookups, basic Q&A
- [ ] Dashboard chat widget (AdminLTE sidebar)
- [ ] Conversation persistence (SQLite)
- [ ] Principle guard (hardcoded safety rules)

**Deliverable**: User can ask "Is my network safe?" and get an intelligent answer.

### Phase 2: Agents (4-6 weeks)
**Goal**: Specialized agents handle specific threat domains

- [ ] Agent registry and orchestrator
- [ ] GUARDIAN agent: Network defense (block, rate limit)
- [ ] WATCHDOG agent: DNS protection (block domains, DGA response)
- [ ] SHIELD agent: Device management (classify, assign policy)
- [ ] Tool calling framework (structured JSON output)
- [ ] Event routing: Signal → correct agent
- [ ] Action execution with audit trail
- [ ] Notification system (toasts, push)
- [ ] Quick action buttons

**Deliverable**: Agents automatically handle threats and explain their actions.

### Phase 3: Memory & Learning (3-4 weeks)
**Goal**: AEGIS remembers and improves

- [ ] Behavioral profiles per device
- [ ] Session memory (today's events summary)
- [ ] User feedback integration ("this was a false alarm")
- [ ] FORGE agent: Proactive security audits
- [ ] SCOUT agent: Reconnaissance detection
- [ ] VIGIL agent: Authorization integrity
- [ ] Weekly/monthly report generation
- [ ] Dashboard insight cards

**Deliverable**: AEGIS knows your network and gets smarter over time.

### Phase 4: Advanced (4-6 weeks)
**Goal**: Full multi-agent correlation and mesh integration

- [ ] MEDIC agent: Cross-agent incident correlation
- [ ] ORACLE agent: Trend analysis and forecasting
- [ ] Mesh intelligence integration (collective threat context)
- [ ] Vector embeddings for semantic event search
- [ ] Multi-model support (small model for routing, larger for reasoning)
- [ ] Voice interface (Web Speech API)
- [ ] Mobile-optimized chat interface

**Deliverable**: Enterprise-grade security intelligence in a $75 router.

---

## 15. Risk Assessment

### Technical Risks

| Risk | Impact | Likelihood | Mitigation |
|------|--------|-----------|-----------|
| LLM too slow on edge hardware | High | Medium | Template-first approach (95% instant), LLM only for complex reasoning |
| Model hallucinations cause wrong action | Critical | Medium | Principle guard + action confirmation + rate limiting |
| RAM pressure from LLM + existing services | High | Medium | Model quantization (Q4), lazy loading, memory monitoring |
| Prompt injection via malicious DNS/hostnames | High | Low | Input sanitization, character filtering, context isolation |
| User frustration with AI mistakes | Medium | Medium | Always show confidence level, easy correction mechanism |

### Mitigation Architecture

```
SAFETY LAYERS:
1. Hardcoded principles (never bypass)
2. Action rate limiter (max 10 actions/minute)
3. Confidence threshold (don't act below 60%)
4. Human confirmation for major changes
5. Audit trail for every decision
6. Template fallback if LLM fails
7. Kill switch (disable AEGIS, Fortress continues protecting)
```

---

## Appendix A: File Structure (Proposed)

```
products/fortress/
├── lib/
│   └── aegis/                        # AEGIS Core
│       ├── __init__.py               # Module exports
│       ├── soul.py                   # Personality, principles, system prompt
│       ├── engine.py                 # Main AEGIS engine (orchestrator)
│       ├── memory.py                 # Multi-layer memory management
│       ├── narrator.py              # Template-first + LLM narration
│       ├── signal_fabric.py         # Unified event bus
│       ├── tool_executor.py         # Safe action execution
│       ├── principle_guard.py       # Safety enforcement
│       ├── agents/
│       │   ├── __init__.py          # Agent registry
│       │   ├── base.py              # BaseAgent class
│       │   ├── guardian.py          # Network defense
│       │   ├── watchdog.py          # DNS protection
│       │   ├── shield.py            # Endpoint protection
│       │   ├── vigil.py             # Auth & integrity
│       │   ├── scout.py             # Reconnaissance detection
│       │   ├── forge.py             # Hardening & config
│       │   ├── medic.py             # Incident response
│       │   └── oracle.py            # Forecasting & advisory
│       ├── bridges/
│       │   ├── qsecbit_bridge.py    # Qsecbit signal adapter
│       │   ├── dnsxai_bridge.py     # dnsXai signal adapter
│       │   ├── dhcp_bridge.py       # DHCP event adapter
│       │   ├── napse_bridge.py      # NAPSE EventBus adapter
│       │   └── mesh_bridge.py       # Mesh gossip adapter
│       └── prompts/
│           ├── soul.j2              # Soul system prompt template
│           ├── guardian.j2          # Guardian agent prompt
│           ├── watchdog.j2          # Watchdog agent prompt
│           └── ...                  # Per-agent prompts
│
├── web/
│   ├── modules/
│   │   └── aegis/                   # AEGIS Web Module
│   │       ├── __init__.py
│   │       ├── views.py             # Chat endpoints, WebSocket
│   │       └── api.py               # REST API for AEGIS
│   ├── templates/
│   │   └── aegis/
│   │       ├── chat.html            # Chat widget
│   │       └── insights.html        # Dashboard cards
│   └── static/
│       ├── js/
│       │   └── aegis-chat.js        # Chat UI client
│       └── css/
│           └── aegis.css            # Chat styling
│
├── containers/
│   └── Containerfile.aegis          # AEGIS container (Ollama + engine)
│
└── config/
    └── aegis.conf                   # AEGIS configuration
```

---

## Appendix B: Comparison with Cloud Security Assistants

| Capability | Cloud Security AI | AEGIS (Local) |
|-----------|------------------|---------------|
| **Privacy** | Your data on their servers | 100% local, zero export |
| **Latency** | 200-500ms (API roundtrip) | <50ms (auto), <2s (LLM) |
| **Offline** | Dead without internet | Full capability |
| **Cost** | $10-50/month recurring | $0/month (included) |
| **Personalization** | Generic for all customers | Learns YOUR network |
| **Context** | Limited to API payload | Full access to all sensors |
| **Trust** | Trust the cloud vendor | Trust your own hardware |
| **Network Awareness** | Only sees what you send | Sees every packet, every device |
| **Response Speed** | Minutes (alert → human → action) | Milliseconds (detect → act → explain) |
| **Updates** | Vendor-controlled | You control model + rules |

---

*AEGIS: Because every network deserves a guardian that never sleeps.*
*HookProbe Fortress — Protection is a right, not a privilege.*
