# AIOCHI L1 SOC Dashboard Design

## Overview

This document describes the L1 SOC (Physical Layer Security Operations Center) dashboard widgets for AIOCHI. These transform the dashboard from a passive telemetry viewer into a proactive L1 security platform.

## Design Philosophy: "Less is More Automation"

**Core Principle**: The AI handles 95% of decisions automatically. Users are only prompted when the AI is genuinely uncertain.

```
┌─────────────────────────────────────────────────────────────────┐
│                    AI DECISION FRAMEWORK                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Confidence > 85%    →  Act automatically, brief narrative      │
│  Confidence 60-85%   →  Act, explain "I did X because Y"        │
│  Confidence 30-60%   →  Notify, suggest, auto-execute timeout   │
│  Confidence < 30%    →  Ask OpenRouter AI for reasoning         │
│                         If still uncertain → prompt user         │
│                                                                  │
│  User corrections → AI learns, adjusts future confidence        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**User Experience Goals:**
- Ambient dashboard - mostly green, nothing to do
- Narrative notifications - "I blocked a suspicious tower"
- User prompts ONLY when AI genuinely doesn't know
- Learn from every user correction

**OpenRouter Integration:**
- Uses Gemini models for uncertain situations
- AI tries to reason before bothering user
- Falls back to user prompt if AI also uncertain

**Trio+ Validated Approach:**
- **Gemini 3 Flash**: Technical validation of detection methods
- **Nemotron**: Security audit of autonomous actions
- **Devstral**: Algorithm verification for L1 Trust Score

## Dashboard Layout

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        AIOCHI L1 SOC DASHBOARD                                  │
├───────────────────────────────┬─────────────────────────────────────────────────┤
│   L1 TRUST GAUGE              │          TOWER PROXIMITY MAP                    │
│   ┌─────────────────┐         │   ┌─────────────────────────────────────────┐  │
│   │       85%       │         │   │                                         │  │
│   │    ████████░░   │         │   │  [Map with tower markers]               │  │
│   │    TRUSTED      │         │   │  🟢 Whitelisted  🟡 OpenCellID          │  │
│   └─────────────────┘         │   │  🔴 Blacklisted  ⚫ Unknown             │  │
│                               │   │                                         │  │
│   Components:                 │   │  📍 Your Location                       │  │
│   • Identity: 100% ████████   │   │                                         │  │
│   • SNR: 75% ██████░░         │   └─────────────────────────────────────────┘  │
│   • Stability: 90% ████████   │                                                 │
│   • Temporal: 95% █████████   │                                                 │
│   • Handover: 100% █████████  │                                                 │
│                               │                                                 │
├───────────────────────────────┼─────────────────────────────────────────────────┤
│   SNR WATERFALL               │          ANOMALY TIMELINE                       │
│   ┌─────────────────┐         │   ┌─────────────────────────────────────────┐  │
│   │ Time↓  -10    30│         │   │ 14:32 🔴 IMSI Catcher detected (Cell X) │  │
│   │ 14:30 ▓▓▓▓▓▓░░░░│         │   │ 14:28 🟡 Unknown tower (Cell Y)         │  │
│   │ 14:31 ▓▓▓▓▓▓▓░░░│         │   │ 14:15 🟢 Handover to trusted tower     │  │
│   │ 14:32 ▓▓░░░░░░░░│ ← Drop! │   │ 13:45 🟢 Network type: 5G SA           │  │
│   │ 14:33 ▓▓▓▓▓▓▓▓░░│         │   │                                         │  │
│   └─────────────────┘         │   └─────────────────────────────────────────┘  │
│                               │                                                 │
├───────────────────────────────┴─────────────────────────────────────────────────┤
│                          CURRENT CELL STATUS                                     │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │ Cell ID: 12345678 | PCI: 42 | TAC: 1234 | MCC-MNC: 310-260 | Band: n78 │   │
│   │ RSRP: -85 dBm | SINR: 22 dB | SNR: 20.5 dB | TA: 15 (~1.2km)           │   │
│   │ Carrier: Verizon | Network: 5G SA | Status: 🟢 TRUSTED                  │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
├──────────────────────────────────────────────────────────────────────────────────┤
│                          SURVIVAL MODE CONTROLS                                  │
│   ┌──────────────────────────────────────────────────────────────────────────┐  │
│   │ Status: NORMAL  |  [Enter Survival Mode]  |  VPN: Pre-Established ✓     │  │
│   │                                                                          │  │
│   │ Auto-triggers: ☑ Trust < 20%  ☑ IMSI Catcher  ☑ Jamming  □ Manual Only │  │
│   └──────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

## Widget Specifications

### 1. L1 Trust Gauge (Radio Nerve Center)

**Purpose**: Single metric showing physical link integrity probability.

**Display**:
- Large circular gauge (0-100%)
- Color-coded: Green (>70%), Yellow (30-70%), Red (<30%)
- State label: TRUSTED / SUSPICIOUS / HOSTILE

**Component Breakdown** (stacked bars):
| Component | Weight | Description |
|-----------|--------|-------------|
| Tower Identity | 35% | Whitelist + GPS verification |
| SNR Score | 20% | Signal-to-noise ratio |
| Signal Stability | 15% | RSRP variance over time |
| Temporal Consistency | 15% | Handover frequency |
| Handover Score | 10% | Handover count per hour |
| Unexpected Pairs | 5% | Neighbor cell verification |

**Hard Thresholds** (per Nemotron audit):
- Unknown tower → Force score to 0%
- SNR < 30% → Cap at 30%
- Handover storm → Cap at 40%

### 2. Tower Proximity Map

**Purpose**: Visualize tower locations vs device GPS.

**Display**:
- Leaflet.js or MapLibre GL map
- Device location marker (📍)
- Tower markers with status colors:
  - 🟢 Green: Whitelisted + GPS verified
  - 🟡 Yellow: OpenCellID only
  - 🔴 Red: Blacklisted
  - ⚫ Gray: Unknown
- Range circles showing timing advance distance

**Interactions**:
- Click tower → Show tower details popup
- Click "Add to Whitelist" button
- Click "Report Suspicious" button

### 3. SNR Waterfall Chart

**Purpose**: Spot intermittent interference patterns and jamming.

**Display**:
- Heatmap (Time vs SNR in dB)
- X-axis: SNR range (-10 to 30 dB)
- Y-axis: Time (scrolling, 30-minute window)
- Color intensity: Brighter = better SNR

**Jamming Signature**:
```
Normal:     ▓▓▓▓▓▓▓▓░░  (consistent)
Jamming:    ▓▓░░░░░░░░  (sudden drop while RSRP stays high)
Recovering: ▓▓▓▓▓▓▓░░░  (gradual return)
```

**Alert Highlight**: Red border when SNR drops >15dB suddenly.

### 4. Anomaly Timeline

**Purpose**: Chronological security events.

**Display**:
- Scrollable list of events
- Color-coded severity icons:
  - 🔴 Critical (IMSI catcher, confirmed rogue)
  - 🟠 High (jamming, downgrade attack)
  - 🟡 Medium (unknown tower, GPS mismatch)
  - 🟢 Info (handover, network change)

**Event Format**:
```
[Time] [Severity Icon] [Event Type] - [Brief Description]
         └── Click to expand details + actions
```

**Actions per Event**:
- "Investigate" → Open detailed view
- "Whitelist Tower" (for unknown tower)
- "Blacklist Tower" (for suspicious)
- "Mark False Positive"

### 5. Current Cell Status Bar

**Purpose**: Real-time cellular metrics display.

**Metrics Shown**:
| Metric | Example | Meaning |
|--------|---------|---------|
| Cell ID | 12345678 | Unique tower identifier |
| PCI | 42 | Physical Cell ID |
| TAC | 1234 | Tracking Area Code |
| MCC-MNC | 310-260 | Country + Network |
| Band | n78 | Frequency band |
| RSRP | -85 dBm | Signal power |
| SINR | 22 dB | Signal quality |
| SNR | 20.5 dB | Noise ratio |
| TA | 15 (~1.2km) | Distance to tower |
| Carrier | Verizon | Network name |
| Network | 5G SA | Technology |
| Status | 🟢 TRUSTED | Trust state |

### 6. Survival Mode Controls

**Purpose**: Manual control and configuration of survival mode.

**Elements**:
- **Status Indicator**: NORMAL / ENTERING / ACTIVE / EXITING
- **Manual Trigger Button**: "Enter Survival Mode"
- **VPN Status**: Pre-Established ✓ / Not Ready ⚠️
- **Auto-trigger Checkboxes**:
  - ☑ Trust Score < 20%
  - ☑ IMSI Catcher Detected
  - ☑ Jamming Detected
  - □ Manual Only

**Survival Mode Active Display**:
```
┌─────────────────────────────────────────────┐
│ 🛡️ SURVIVAL MODE ACTIVE                     │
│                                             │
│ Active since: 14:32:15                      │
│ Trigger: IMSI catcher detected              │
│                                             │
│ Actions:                                    │
│ ✓ Protocol lockdown (2G/3G disabled)        │
│ ✓ VPN tunnel active                         │
│ ✓ Cell 12345678 blacklisted                 │
│                                             │
│ [Exit Survival Mode]  [Mark Attack Confirmed]│
└─────────────────────────────────────────────┘
```

## API Endpoints for Dashboard

### REST API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/l1/metrics` | GET | Current cellular metrics |
| `/api/l1/trust-score` | GET | L1 Trust Score + components |
| `/api/l1/anomalies` | GET | Recent anomalies (params: hours, severity) |
| `/api/l1/towers` | GET | Known towers list |
| `/api/l1/towers/{cell_id}` | GET | Tower details |
| `/api/l1/towers/{cell_id}/whitelist` | POST | Add to whitelist |
| `/api/l1/towers/{cell_id}/blacklist` | POST | Add to blacklist |
| `/api/l1/survival` | GET | Survival mode status |
| `/api/l1/survival/enter` | POST | Manual survival mode |
| `/api/l1/survival/exit` | POST | Exit survival mode |
| `/api/l1/history/snr` | GET | SNR history for waterfall |
| `/api/l1/history/handovers` | GET | Handover history |

### WebSocket Events

| Event | Direction | Description |
|-------|-----------|-------------|
| `l1_metrics_update` | Server→Client | Real-time metrics (5s interval) |
| `l1_trust_update` | Server→Client | Trust score change |
| `l1_anomaly_detected` | Server→Client | New anomaly |
| `l1_survival_state` | Server→Client | Survival mode state change |
| `l1_tower_status` | Server→Client | Tower verification result |

## Implementation Files

| File | Purpose |
|------|---------|
| `shared/aiochi/backend/l1_soc/__init__.py` | Module exports |
| `shared/aiochi/backend/l1_soc/trust_score.py` | L1 Trust Score algorithm |
| `shared/aiochi/backend/l1_soc/tower_reputation.py` | Tower whitelist + OpenCellID |
| `shared/aiochi/backend/l1_soc/cellular_monitor.py` | MBIM/mmcli integration |
| `shared/aiochi/backend/l1_soc/anomaly_detector.py` | Threat detection |
| `shared/aiochi/backend/l1_soc/survival_mode.py` | Emergency response |
| `shared/aiochi/schemas/clickhouse-l1-soc.sql` | ClickHouse schema |
| `shared/aiochi/playbooks/l1_imsi_catcher.json` | IMSI catcher response |
| `shared/aiochi/playbooks/l1_jamming_defense.json` | Jamming response |
| `shared/aiochi/playbooks/l1_rogue_tower.json` | Rogue tower response |

## Integration with Fortress Dashboard

The L1 SOC widgets integrate with the existing Fortress AdminLTE dashboard:

1. **New Menu Item**: "L1 SOC" under Security section
2. **Dashboard Cards**: Small trust gauge + alert count on main dashboard
3. **Full View**: Dedicated `/l1-soc` route with all widgets
4. **Alerts Integration**: L1 anomalies appear in main alert feed

## Mobile Considerations

For mobile/responsive display:
- Trust Gauge: Full width, prominent
- Map: Collapsible, tap to expand
- SNR Waterfall: Horizontal scroll
- Timeline: Full width list
- Cell Status: Horizontal scroll table
- Survival Controls: Fixed bottom bar when active

## Security Considerations (Nemotron Audit)

1. **Rate Limiting**: All modem commands rate-limited
2. **No 2G Fallback**: Protocol lockdown always available
3. **Multiple Indicators**: Require ≥2 corroborating indicators before action
4. **Blacklist Decay**: Auto-remove after 7 days
5. **VPN Pre-establish**: Keep tunnel ready before survival mode needed
6. **Audit Log**: All autonomous actions logged to ClickHouse
