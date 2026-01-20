# AIOCHI Dashboard Improvement Report

**Date**: 2026-01-12
**Prepared by**: Trio+ AI Collaboration (Devstral + Nemotron + Claude)
**Version**: 1.0

---

## Executive Summary

This report provides a comprehensive analysis of the AIOCHI dashboard and recommends improvements for:
1. **Performance Monitor** - Fix placeholder data to show real metrics
2. **Behavioral Analytics** - Auto-detect kids, gamers, and privacy concerns
3. **Quick Actions** - Implement actual network controls
4. **MITRE ATT&CK Coverage** - Protect small businesses from cyber threats

---

## 1. Current State Assessment

### 1.1 What Works Well
- **Architecture**: Clean separation between `real_data.py`, `performance_scorer.py`, and UI
- **Data Sources**: Integration ready for dnsXai, Suricata, Zeek, ClickHouse
- **UI Design**: Beautiful three-pillar layout (Presence, Privacy, Performance)
- **Quick Actions**: Well-defined action types with toggle support

### 1.2 Issues Found

| Component | Issue | Impact |
|-----------|-------|--------|
| **Performance Monitor** | Shows hardcoded "85" score | Users see fake data |
| **Latency/Bandwidth** | Default values returned when collection fails | Misleading metrics |
| **Quick Actions** | Handlers only log, don't execute | Buttons do nothing |
| **Kids Detection** | Not implemented | Can't auto-pause kids |
| **Gaming Detection** | Not implemented | Can't auto-enable game mode |

### 1.3 Data Flow Gap

```
Current:
  real_data.py → get_system_performance() → Returns DEFAULTS if ping fails

Should be:
  SLA AI Collector → ClickHouse → real_data.py → Actual metrics
  Zeek/Suricata → ClickHouse → Traffic classification → Device profiles
```

---

## 2. Performance Monitor Fixes

### 2.1 Problem: Hardcoded Default Values

**File**: `$HOOKPROBE_ROOT/products/fortress/web/modules/aiochi/real_data.py:436-444`

```python
# Current (returns defaults on any failure)
result = {
    'health_score': 85,        # HARDCODED!
    'latency_ms': 10,          # HARDCODED!
    'bandwidth_used_pct': 25,  # HARDCODED!
    'uptime_pct': 99.9,        # HARDCODED!
}
```

### 2.2 Recommended Fix

```python
def get_system_performance() -> Dict[str, Any]:
    """Get REAL system performance metrics with proper fallbacks."""

    # 1. Try SLA AI collector first (most accurate)
    try:
        from shared.slaai.metrics_collector import MetricsCollector
        collector = MetricsCollector()
        metrics = collector.collect()

        return {
            'health_score': calculate_health_score(metrics),
            'latency_ms': metrics.rtt_ms,
            'jitter_ms': metrics.jitter_ms,
            'bandwidth_used_pct': calculate_bandwidth_usage(),
            'uptime_pct': get_system_uptime_pct(),
            'packet_loss_pct': metrics.packet_loss_pct,
            'data_source': 'slaai'
        }
    except ImportError:
        pass

    # 2. Fallback to direct measurements
    latency = measure_gateway_latency()  # ping default gateway
    bandwidth = get_interface_throughput()  # from /proc/net/dev
    uptime = get_system_uptime()  # from /proc/uptime

    # 3. Calculate health score from real data
    health_score = calculate_health_from_metrics(latency, bandwidth, uptime)

    return {
        'health_score': health_score,
        'latency_ms': latency,
        'bandwidth_used_pct': bandwidth,
        'uptime_pct': uptime,
        'data_source': 'direct'
    }
```

### 2.3 Additional Data Sources to Integrate

| Metric | Source | How to Get |
|--------|--------|------------|
| **Latency** | Ping gateway | `ping -c 3 $(ip route \| grep default \| awk '{print $3}')` |
| **Bandwidth** | Interface stats | `/proc/net/dev` delta over time |
| **Uptime** | System | `/proc/uptime` first field |
| **Blocked (24h)** | dnsXai API | `GET /api/stats` → `blocked_queries` |
| **Threats** | Suricata | ClickHouse `suricata_alerts` count |
| **Jitter** | SLA AI | Variance in RTT samples |

---

## 3. Behavioral Analytics Implementation

### 3.1 Kids Traffic Detection

**Algorithm** (from Trio+ Devstral):

```python
class KidsTrafficDetector:
    """Detect devices primarily used by children."""

    # Kids-indicative domains
    KIDS_DOMAINS = {
        'high_confidence': [
            'youtubekids.com', 'pbskids.org', 'nickjr.com',
            'disney.com', 'cartoonnetwork.com', 'funbrain.com'
        ],
        'medium_confidence': [
            'roblox.com', 'minecraft.net', 'coolmathgames.com',
            'abcya.com', 'khanacademy.org', 'duolingo.com'
        ],
        'low_confidence': [
            'youtube.com', 'netflix.com', 'spotify.com'
        ]
    }

    # Time patterns (after school, weekends)
    KIDS_TIME_PATTERNS = {
        'weekday_peak': (15, 21),   # 3 PM - 9 PM
        'weekend_peak': (9, 21),    # 9 AM - 9 PM
    }

    def calculate_kids_score(self, device_mac: str) -> float:
        """
        Calculate probability device belongs to a child.

        Returns: 0.0 - 1.0 (higher = more likely kids device)
        """
        score = 0.0

        # Factor 1: Domain hits (30%)
        dns_hits = self.get_dns_history(device_mac, hours=24)
        kids_domain_hits = sum(1 for d in dns_hits
                               if self._is_kids_domain(d))
        domain_score = min(kids_domain_hits / 20, 1.0)  # Cap at 20 hits
        score += domain_score * 0.3

        # Factor 2: Mobile gaming patterns (20%)
        gaming_hits = self.get_gaming_patterns(device_mac)
        if gaming_hits.get('mobile_games', 0) > 5:
            score += 0.2

        # Factor 3: Education domain access (20%)
        education_hits = sum(1 for d in dns_hits
                            if self._is_education_domain(d))
        score += min(education_hits / 10, 1.0) * 0.2

        # Factor 4: Time pattern match (30%)
        time_score = self._calculate_time_pattern_match(device_mac)
        score += time_score * 0.3

        return score

    def classify_device(self, device_mac: str) -> Optional[str]:
        """Classify device if confidence > 0.7."""
        score = self.calculate_kids_score(device_mac)
        device_type = self.get_device_type(device_mac)

        if score > 0.7 and device_type in ['tablet', 'phone']:
            return 'kids_device'
        return None
```

### 3.2 Gamer Traffic Detection

**Algorithm** (from Trio+ Devstral):

```python
class GamerTrafficDetector:
    """Detect active gaming sessions for QoS prioritization."""

    # Gaming-specific ports
    GAMING_PORTS = {
        'xbox': [3074, 3478, 3479, 3480],
        'playstation': [3478, 3479, 3480, 9295, 9296],
        'steam': list(range(27000, 27050)),
        'blizzard': list(range(5000, 6000)),
        'epic': [5222, 5795, 5847],
        'riot': [5000, 5100, 5222, 5223],
    }

    # Gaming server domains
    GAMING_DOMAINS = [
        '*.xboxlive.com', '*.playstation.net', '*.steamcontent.com',
        '*.epicgames.com', '*.riotgames.com', '*.battle.net',
        '*.ea.com', '*.ubisoft.com', '*.activision.com'
    ]

    def calculate_gamer_score(self, device_mac: str) -> float:
        """
        Calculate probability of active gaming.

        Returns: 0.0 - 1.0 (higher = more likely gaming)
        """
        score = 0.0

        # Factor 1: Gaming port activity (40%)
        port_hits = self.get_port_activity(device_mac, minutes=5)
        gaming_port_hits = sum(1 for p in port_hits
                               if self._is_gaming_port(p))
        score += min(gaming_port_hits / 100, 1.0) * 0.4

        # Factor 2: Low latency requirements (30%)
        # Games send small, frequent UDP packets
        udp_stats = self.get_udp_stats(device_mac, minutes=5)
        if udp_stats['packet_rate'] > 30 and udp_stats['avg_size'] < 500:
            score += 0.3

        # Factor 3: Gaming server DNS (30%)
        dns_hits = self.get_dns_history(device_mac, minutes=10)
        gaming_dns = sum(1 for d in dns_hits
                        if self._matches_gaming_domain(d))
        score += min(gaming_dns / 10, 1.0) * 0.3

        return score

    def should_enable_game_mode(self, device_mac: str) -> bool:
        """Enable game mode if gaming sustained for 5+ minutes."""
        score = self.calculate_gamer_score(device_mac)

        if score > 0.6:
            # Check if sustained
            history = self.get_score_history(device_mac, minutes=5)
            if all(s > 0.5 for s in history):
                return True
        return False
```

### 3.3 Privacy Mode Implementation

**When Privacy Mode is enabled** (from Trio+ Devstral):

```python
class PrivacyModeController:
    """Implement Privacy Mode network-wide protection."""

    # Trackers to block
    TRACKER_DOMAINS = [
        # Analytics
        'google-analytics.com', 'analytics.google.com',
        'googletagmanager.com', 'hotjar.com', 'mixpanel.com',

        # Advertising
        'doubleclick.net', 'googlesyndication.com',
        'facebook.net', 'fbcdn.net', 'advertising.com',

        # Fingerprinting
        'fingerprintjs.com', 'canvas-tracker.com',

        # Social tracking
        'connect.facebook.net', 'platform.twitter.com',
        'platform.linkedin.com'
    ]

    def enable(self):
        """Enable privacy mode."""

        # 1. Set dnsXai to maximum protection level
        self._set_dnsxai_level(5)  # Block all trackers

        # 2. Block known tracker IPs at OVS level
        for ip in self.TRACKER_IPS:
            self._add_ovs_drop_rule(dst_ip=ip)

        # 3. Force DNS through encrypted resolver
        self._enable_dns_encryption()

        # 4. Block non-encrypted DNS (port 53 to external)
        self._block_external_dns()

        # 5. Randomize device fingerprint vectors
        self._enable_fingerprint_protection()

    def _set_dnsxai_level(self, level: int):
        """Set dnsXai protection level."""
        requests.post(f'{DNSXAI_API_URL}/api/level',
                     json={'level': level})

    def _add_ovs_drop_rule(self, dst_ip: str):
        """Add OVS flow rule to drop traffic."""
        subprocess.run([
            'ovs-ofctl', 'add-flow', 'FTS',
            f'priority=100,ip,nw_dst={dst_ip},actions=drop'
        ])
```

### 3.4 Algorithm Improvements (from Trio+ Nemotron Nano)

**Temporal Smoothing** to prevent flip-flopping:

```python
class SmoothingClassifier:
    """Apply temporal smoothing to classification scores."""

    def __init__(self, window_minutes: int = 10):
        self.window = window_minutes
        self._history: Dict[str, List[Tuple[datetime, float]]] = {}

    def get_smoothed_score(self, device_mac: str, raw_score: float) -> float:
        """Apply moving average smoothing."""
        now = datetime.now()

        # Add to history
        if device_mac not in self._history:
            self._history[device_mac] = []
        self._history[device_mac].append((now, raw_score))

        # Filter to window
        cutoff = now - timedelta(minutes=self.window)
        recent = [(t, s) for t, s in self._history[device_mac] if t > cutoff]
        self._history[device_mac] = recent

        # Calculate weighted average (recent scores weighted more)
        if not recent:
            return raw_score

        total_weight = 0
        weighted_sum = 0
        for i, (_, score) in enumerate(recent):
            weight = i + 1  # More recent = higher weight
            weighted_sum += score * weight
            total_weight += weight

        return weighted_sum / total_weight
```

**Multi-Profile Device Handling**:

```python
def handle_multi_profile(device_mac: str) -> str:
    """Handle devices that fit multiple profiles."""

    kids_score = kids_detector.calculate_kids_score(device_mac)
    gamer_score = gamer_detector.calculate_gamer_score(device_mac)

    # If both scores high, check time of day
    if kids_score > 0.5 and gamer_score > 0.5:
        hour = datetime.now().hour

        # Evening hours = more likely kids gaming
        if 15 <= hour <= 21:
            return 'kids_gaming'
        # Late night = probably adult
        elif hour >= 22 or hour <= 6:
            return 'adult_gaming'

    # Use highest score
    if gamer_score > kids_score and gamer_score > 0.6:
        return 'gamer'
    elif kids_score > 0.7:
        return 'kids'

    return 'normal'
```

---

## 4. Quick Actions Implementation

### 4.1 Current Gap

The handlers in `quick_actions.py` only log messages but don't execute actual network changes.

### 4.2 Implementation Guide

#### Pause Kids Internet (OVS + dnsXai)

```python
def _handle_pause_kids(self, action, target, params, revert=False):
    """Actually pause kids' internet access."""

    # Get all MACs in kids bubble
    bubble_manager = get_ecosystem_bubble_manager()
    kids_macs = bubble_manager.get_bubble_devices(target)

    for mac in kids_macs:
        if revert:
            # Remove drop rule
            subprocess.run([
                'ovs-ofctl', 'del-flows', 'FTS',
                f'dl_src={mac}'
            ])
        else:
            # Add drop rule for all traffic from this MAC
            subprocess.run([
                'ovs-ofctl', 'add-flow', 'FTS',
                f'priority=100,dl_src={mac},actions=drop'
            ])

    return f"{'Resumed' if revert else 'Paused'} {len(kids_macs)} devices"
```

#### Game Mode (QoS Priority)

```python
def _handle_game_mode(self, action, target, params, revert=False):
    """Enable QoS prioritization for gaming traffic."""

    if revert:
        # Remove QoS rules
        subprocess.run(['tc', 'qdisc', 'del', 'dev', 'eth0', 'root'])
    else:
        # Set up priority queuing
        subprocess.run([
            'tc', 'qdisc', 'add', 'dev', 'eth0', 'root',
            'handle', '1:', 'htb', 'default', '30'
        ])

        # High priority class for gaming (10Mbps guaranteed, 100Mbps ceiling)
        subprocess.run([
            'tc', 'class', 'add', 'dev', 'eth0', 'parent', '1:',
            'classid', '1:10', 'htb', 'rate', '10mbit',
            'ceil', '100mbit', 'prio', '0'
        ])

        # Filter gaming ports to high priority
        for port in GAMING_PORTS:
            subprocess.run([
                'tc', 'filter', 'add', 'dev', 'eth0', 'protocol', 'ip',
                'parent', '1:0', 'prio', '1', 'u32',
                'match', 'ip', 'dport', str(port), '0xffff',
                'flowid', '1:10'
            ])

    return f"Game mode {'disabled' if revert else 'enabled'}"
```

#### Guest Lockdown (VLAN Isolation)

```python
def _handle_guest_lockdown(self, action, target, params, revert=False):
    """Isolate guest VLAN from internal network."""

    GUEST_VLAN = 150

    if revert:
        # Allow guest-to-LAN
        subprocess.run([
            'ovs-ofctl', 'del-flows', 'FTS',
            f'dl_vlan={GUEST_VLAN},priority=200'
        ])
    else:
        # Block guest-to-LAN, allow guest-to-internet
        subprocess.run([
            'ovs-ofctl', 'add-flow', 'FTS',
            f'priority=200,dl_vlan={GUEST_VLAN},nw_dst=10.200.0.0/16,actions=drop'
        ])
        # Allow guest to internet (via NAT)
        subprocess.run([
            'ovs-ofctl', 'add-flow', 'FTS',
            f'priority=100,dl_vlan={GUEST_VLAN},actions=output:WAN'
        ])

    return f"Guest lockdown {'removed' if revert else 'applied'}"
```

---

## 5. MITRE ATT&CK Coverage

### 5.1 Priority Threats for Small Business (Flower Shop Scenario)

Based on Trio+ Nemotron analysis:

| Threat | MITRE ID | Risk Level | Detection Method |
|--------|----------|------------|------------------|
| **Phishing emails** | T1566 | HIGH | DNS for suspicious domains |
| **Ransomware** | T1486 | CRITICAL | Suricata signatures |
| **POS malware** | T1059 | HIGH | Behavioral analysis |
| **Rogue WiFi AP** | T1195 | MEDIUM | Wireless scanning |
| **DNS tunneling** | T1048 | MEDIUM | dnsXai entropy detection |
| **Credential theft** | T1078 | HIGH | Failed login monitoring |

### 5.2 Suricata Rules for Small Business

```yaml
# /etc/suricata/rules/smallbiz-local.rules

# Phishing URL detection
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"SMALLBIZ - Phishing URL pattern detected";
  flow:to_server,established;
  content:"login"; http_uri;
  content:"verify"; http_uri;
  pcre:"/\.(tk|ml|ga|cf|gq)/";
  classtype:policy-violation;
  sid:3000001; rev:1;
)

# Ransomware C2 beacon
alert dns any any -> any any (
  msg:"SMALLBIZ - Potential ransomware C2 domain";
  dns_query;
  content:".onion."; nocase;
  classtype:trojan-activity;
  sid:3000002; rev:1;
)

# Large outbound data (exfiltration)
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
  msg:"SMALLBIZ - Large outbound transfer (potential exfil)";
  flow:to_server,established;
  dsize:>10000;
  threshold:type both, track by_src, count 100, seconds 60;
  classtype:data-loss;
  sid:3000003; rev:1;
)

# SMB lateral movement
alert smb $HOME_NET any -> $HOME_NET any (
  msg:"SMALLBIZ - SMB admin share access";
  content:"|00|A|00|D|00|M|00|I|00|N|00|$|00|";
  classtype:attempted-admin;
  sid:3000004; rev:1;
)
```

### 5.3 Automated Response Playbooks

```python
# $HOOKPROBE_ROOT/shared/aiochi/playbooks/auto_response.py

class AutoResponsePlaybook:
    """Automated threat response with human-in-the-loop for critical actions."""

    # Actions safe to auto-execute
    AUTO_SAFE = {
        'rate_limit',      # Slow down suspicious traffic
        'dns_sinkhole',    # Redirect malicious DNS
        'alert_admin',     # Notify admin
        'log_forensics',   # Capture packets for analysis
    }

    # Actions requiring confirmation
    REQUIRE_CONFIRM = {
        'quarantine_device',  # Move to isolation VLAN
        'block_ip',           # Block at firewall
        'terminate_session',  # Kill connections
    }

    # Critical actions - NEVER auto-execute
    MANUAL_ONLY = {
        'block_pos_device',   # Could break payments
        'shutdown_network',   # Business impact
    }

    def handle_alert(self, alert: SuricataAlert):
        """Process alert and determine response."""

        severity = alert.severity
        device_role = self.get_device_role(alert.src_ip)

        # Critical device (POS) - always require human
        if device_role == 'POS':
            return self.notify_admin_urgent(alert)

        # High severity - auto-isolate + notify
        if severity <= 1:
            if 'quarantine_device' not in self.MANUAL_ONLY:
                self.quarantine_device(alert.src_mac)
            self.notify_admin(alert)

        # Medium severity - rate limit + log
        elif severity <= 2:
            self.rate_limit_device(alert.src_mac)
            self.capture_forensics(alert.src_mac, duration=300)

        # Low severity - log only
        else:
            self.log_event(alert)
```

### 5.4 Defense-in-Depth Network Segmentation

```
Internet
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  VLAN 10 - Guest WiFi                                   │
│  • Internet only (no LAN access)                        │
│  • Rate limited: 10 Mbps                                │
│  • DNS: dnsXai protection level 5                       │
└─────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  VLAN 20 - Staff Network                                │
│  • POS terminals, staff laptops                         │
│  • Proxy all HTTP/HTTPS                                 │
│  • Block direct internet except payment gateway         │
└─────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  VLAN 30 - IoT Devices                                  │
│  • Cameras, smart devices, printers                     │
│  • Internet via whitelist only                          │
│  • No LAN access except printer                         │
└─────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  VLAN 99 - Quarantine                                   │
│  • Isolated: no internet, no LAN                        │
│  • Packet capture active                                │
│  • Admin notification on any device here                │
└─────────────────────────────────────────────────────────┘
```

---

## 6. Implementation Roadmap

### Phase 1: Fix Performance Monitor (1-2 days)

- [ ] Update `real_data.py` to return actual metrics
- [ ] Add fallback chain: SLA AI → direct measurement → cached
- [ ] Test with AIOCHI containers running and stopped
- [ ] Update UI to show "data source" indicator

### Phase 2: Behavioral Analytics (3-5 days)

- [ ] Implement `KidsTrafficDetector` class
- [ ] Implement `GamerTrafficDetector` class
- [ ] Add ClickHouse queries for DNS/port history
- [ ] Integrate with bubble auto-assignment
- [ ] Add temporal smoothing to prevent flip-flop

### Phase 3: Quick Actions (2-3 days)

- [ ] Implement OVS flow rules for pause/block
- [ ] Implement tc/QoS for game mode
- [ ] Implement dnsXai integration for privacy mode
- [ ] Test all actions with revert functionality
- [ ] Add action audit logging

### Phase 4: MITRE ATT&CK (5-7 days)

- [ ] Deploy Suricata small business rules
- [ ] Implement automated response playbook
- [ ] Set up VLAN segmentation (if not exists)
- [ ] Configure rate limiting thresholds
- [ ] Test with simulated attacks

### Phase 5: Dashboard Enhancements (2-3 days)

- [ ] Add "Attack Map" visualization (blocked threats)
- [ ] Add device behavior profile cards
- [ ] Add network segmentation status view
- [ ] Add security health score (MITRE coverage %)

---

## 7. Summary

### Key Findings

1. **Performance data is fake** - The dashboard shows hardcoded values because metric collection falls back to defaults on any error.

2. **Quick actions are not implemented** - The buttons exist but handlers only log messages without executing network changes.

3. **No behavioral analytics** - Kids/gamer/privacy detection doesn't exist yet despite UI showing these quick actions.

4. **Missing threat coverage** - No MITRE ATT&CK awareness or automated response playbooks.

### Recommendations

| Priority | Item | Effort | Impact |
|----------|------|--------|--------|
| **P0** | Fix performance metrics | 1-2 days | Users see real data |
| **P0** | Implement pause kids | 1 day | Core parental feature |
| **P1** | Implement game mode | 1 day | Core performance feature |
| **P1** | Add Suricata rules | 2 days | Basic threat protection |
| **P2** | Behavioral analytics | 3-5 days | Auto-detection |
| **P2** | VLAN segmentation | 2-3 days | Defense in depth |
| **P3** | Attack visualization | 2 days | User awareness |

### Trio+ Synthesis

**Devstral** provided: Domain lists, port mappings, detection patterns, OVS/tc commands
**Nemotron** provided: MITRE ATT&CK mapping, Suricata rules, playbook logic, segmentation design
**Nemotron Nano** provided: Algorithm edge case analysis, temporal smoothing recommendations

---

## 8. Dual-Path WAN Monitoring Architecture (NEW)

**Added**: 2026-01-13
**Status**: Implemented

### 8.1 Problem Statement

The original WAN mirroring assumed all WAN interfaces support XDP (AF_XDP), but:
- **Mobile/LTE interfaces (wwan0)** use USB-based drivers (qmi_wwan, cdc_mbim) that **do not support XDP**
- Different WAN types have different security profiles (CGNAT vs public IP)
- Resource usage should adapt to WAN type (mobile = limited bandwidth)

### 8.2 Dual-Path Architecture

```
                        ┌─────────────────────────────────────────────┐
                        │            WAN PATH SELECTOR                 │
                        │  products/fortress/devices/common/           │
                        │  wan-path-selector.sh                        │
                        └─────────────────────────────────────────────┘
                                          │
                    ┌─────────────────────┴─────────────────────┐
                    ▼                                           ▼
    ┌───────────────────────────────┐       ┌───────────────────────────────┐
    │      WIRED PATH               │       │      MOBILE PATH              │
    │  (eth0, enp*, eno*)           │       │  (wwan0, wwp*, USB modems)    │
    ├───────────────────────────────┤       ├───────────────────────────────┤
    │  Detection:                   │       │  Detection:                   │
    │  • Check driver XDP support   │       │  • Interface prefix (wwan*)   │
    │  • Test AF_XDP capability     │       │  • USB bus detection          │
    │  • Kernel >= 5.10             │       │  • Mobile driver check        │
    │                               │       │  • CGNAT IP range detection   │
    ├───────────────────────────────┤       ├───────────────────────────────┤
    │  Capture Method:              │       │  Capture Method:              │
    │  • AF_XDP (zero-copy)         │       │  • TC-BPF + AF_PACKET         │
    │  • Fallback: TC-BPF           │       │  • No XDP (USB limitation)    │
    ├───────────────────────────────┤       ├───────────────────────────────┤
    │  Sampling:                    │       │  Sampling:                    │
    │  • 100% (full capture)        │       │  • 10% (bandwidth efficiency) │
    │  • Anomaly: 100% burst        │       │  • Anomaly: 100% burst        │
    ├───────────────────────────────┤       ├───────────────────────────────┤
    │  Security Profile:            │       │  Security Profile:            │
    │  • Public IP exposure         │       │  • CGNAT protection           │
    │  • Higher threat surface      │       │  • Lower inbound threat       │
    └───────────────────────────────┘       └───────────────────────────────┘
                    │                                           │
                    └─────────────────┬─────────────────────────┘
                                      ▼
                        ┌─────────────────────────────────────┐
                        │        wan-mirror (dummy)           │
                        │   TC mirred → Suricata/Zeek        │
                        └─────────────────────────────────────┘
```

### 8.3 Key Files

| File | Purpose |
|------|---------|
| `devices/common/wan-path-selector.sh` | Path detection and setup logic |
| `devices/common/ovs-post-setup.sh` | Sources wan-path-selector, integrates dual-path |
| `devices/common/wan-failover-pbr.sh` | Triggers path refresh on failover |
| `shared/aiochi/containers/podman-compose.aiochi.yml` | Suricata dual-interface capture |

### 8.4 Path Type Detection

```bash
# Automatic detection hierarchy
detect_wan_path() {
    1. Interface prefix (wwan*, wwp*) → MOBILE
    2. USB modem driver (qmi_wwan, cdc_mbim) → MOBILE
    3. USB bus location → MOBILE
    4. CGNAT IP range (100.64.0.0/10) → MOBILE
    5. XDP driver support (i40e, mlx5, igc) → WIRED_XDP
    6. Generic XDP (kernel >= 5.10) → WIRED_TC
    7. Fallback → UNKNOWN (use TC mirror)
}
```

### 8.5 Anomaly-Triggered Full Capture

When Suricata/Zeek detects an anomaly, sampling automatically increases to 100%:

```bash
# Trigger full capture (60 seconds by default)
./wan-path-selector.sh anomaly wwan0 ddos_detected

# Check current capture mode
./wan-path-selector.sh mode wwan0  # Returns: full | sampled

# Manually restore normal sampling
./wan-path-selector.sh restore wwan0
```

**Integration with Suricata**:
- Suricata rules can call `wan-path-selector.sh anomaly <iface> <reason>`
- Full capture enables detailed forensic analysis during incidents
- Auto-restores to sampled mode after anomaly period

### 8.6 Identified Gaps and Future Work

| Gap | Description | Priority | Status |
|-----|-------------|----------|--------|
| **AF_XDP Program** | Actual AF_XDP eBPF program not compiled yet | P2 | Planned |
| **DPDK Integration** | High-performance capture for 10G+ interfaces | P3 | Research |
| **Suricata Rule Hook** | Auto-trigger anomaly from Suricata alerts | P1 | Not started |
| **ClickHouse Integration** | Store path type in event metadata | P2 | Not started |
| **Dashboard Widget** | Show WAN path type and sampling rate | P2 | Not started |
| **PF_RING** | Alternative kernel-bypass (security concerns) | P4 | Not recommended |

### 8.7 Security Considerations

From Trio+ security review (Nemotron):

1. **XDP Key Material**: Keys stored in /run/fortress (tmpfs, root-only, mode 0600)
2. **Signed Configs**: Configuration validation before loading
3. **Rate Limiting**: TC-BPF pre-filters non-IP traffic to reduce CPU
4. **Audit Trail**: Path selection events logged to syslog
5. **CGNAT Assumption**: Mobile paths assumed more secure (no direct inbound)
6. **Failover Awareness**: Path reconfigured automatically on WAN failover

### 8.8 CLI Usage

```bash
# Check path type for interface
./wan-path-selector.sh detect eth0      # → wired_xdp
./wan-path-selector.sh detect wwan0     # → mobile

# Get recommended capture method
./wan-path-selector.sh capture eth0     # → af_xdp
./wan-path-selector.sh capture wwan0    # → tc_bpf

# Full setup for interface
./wan-path-selector.sh setup eth0 wan-mirror

# Show status of all WAN interfaces
./wan-path-selector.sh status

# Trigger anomaly (manual or from Suricata)
./wan-path-selector.sh anomaly wwan0 suricata_alert
```

---

*Report generated by Trio+ AI Collaboration System*
*Version 1.1 - January 2026*
