# Red & Purple Teaming Framework

**Location**: `products/nexus/lib/red_purple_teaming/`
**Status**: Production Ready
**Version**: 1.0.0

## Overview

The Red & Purple Teaming framework enables AI vs AI security testing of HookProbe's SDN Autopilot and Ecosystem Bubble systems without impacting production Fortress nodes.

> **Philosophy**: "Attack yourself before others do. Learn from every simulation."

### Key Innovation: Digital Twin Approach

Instead of attacking production infrastructure, we create a **Digital Twin** - a virtual replica of the Fortress SDN environment that runs entirely within the Nexus compute node. This allows:

- **Zero production impact** - All attacks run in simulation
- **Realistic testing** - Twin mirrors real OVS flows, devices, and bubbles
- **Rapid iteration** - Run thousands of simulations per day
- **Safe experimentation** - Test novel attack vectors without risk

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         RED & PURPLE TEAMING FRAMEWORK                           │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  NEXUS (16GB+ RAM) - Red Team Orchestrator                                      │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │                                                                              ││
│  │  ┌────────────────┐    ┌────────────────┐    ┌────────────────┐            ││
│  │  │  DIGITAL TWIN  │    │   RED TEAM     │    │  PURPLE TEAM   │            ││
│  │  │   SIMULATOR    │───▶│   ATTACKS      │───▶│   VALIDATION   │            ││
│  │  │                │    │   (9 Vectors)  │    │                │            ││
│  │  │  • Virtual OVS │    │                │    │  • Defense     │            ││
│  │  │  • Mock Devices│    │  • TER Replay  │    │    Scoring     │            ││
│  │  │  • Bubbles     │    │  • Entropy     │    │  • Risk        │            ││
│  │  │  • Flows       │    │  • Timing      │    │    Assessment  │            ││
│  │  └────────────────┘    │  • Weight Pred │    │  • Auto        │            ││
│  │         ▲              │  • MAC Spoof   │    │    Mitigations │            ││
│  │         │              │  • mDNS Spoof  │    └────────┬───────┘            ││
│  │         │              │  • Temporal    │             │                    ││
│  │  ┌──────┴───────┐      │  • DHCP Spoof  │             ▼                    ││
│  │  │   FORTRESS   │      │  • D2D Inject  │    ┌────────────────┐            ││
│  │  │   SNAPSHOT   │      └────────────────┘    │ META-REGRESSOR │            ││
│  │  │   (Read-Only)│                            │                │            ││
│  │  └──────────────┘                            │ E = β₀ + β₁Ts  │            ││
│  │                                              │   + β₂D2D      │            ││
│  │  ┌────────────────┐                          │   + β₃NSE + ε  │            ││
│  │  │ NSE HEARTBEAT  │                          └────────┬───────┘            ││
│  │  │                │                                   │                    ││
│  │  │ 40-byte token: │                                   ▼                    ││
│  │  │ ts|hash|sig|seq│                          ┌────────────────┐            ││
│  │  └────────────────┘                          │  OPTIMIZATION  │            ││
│  │                                              │ RECOMMENDATIONS│            ││
│  └──────────────────────────────────────────────┴────────────────┴────────────┘│
│                                                                                  │
│  INTEGRATION LAYER                                                              │
│  ┌──────────────────────────────────────────────────────────────────────────────┐│
│  │  n8n Webhooks ◄──► ClickHouse Analytics ◄──► Fortress SDN Autopilot        ││
│  └──────────────────────────────────────────────────────────────────────────────┘│
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Purple Team Orchestrator (`orchestrator.py`)

The central coordinator that runs the 5-phase simulation loop:

| Phase | Name | Description |
|-------|------|-------------|
| 1 | Twin Creation | Create/sync Digital Twin from Fortress |
| 2 | Red Attack | Execute selected attack vectors |
| 3 | Blue Defense | Evaluate SDN Autopilot detection |
| 4 | Validation | Calculate defense scores and risk |
| 5 | Meta-Learning | Update bubble accuracy weights |

```python
from products.nexus.lib.red_purple_teaming import (
    PurpleTeamOrchestrator,
    PurpleTeamConfig,
)

config = PurpleTeamConfig(
    fortress_api_url='http://fortress:8443',
    simulation_timeout_s=60,
    attack_vectors=['ter_replay', 'entropy_poisoning', 'mac_impersonation'],
    enable_auto_mitigation=True,
    clickhouse_enabled=True,
    n8n_webhook_enabled=True,
)

orchestrator = PurpleTeamOrchestrator(config=config)
result = orchestrator.run_simulation()

print(f"Defense Score: {result.defense_score}/100")
print(f"Risk Level: {result.validation['overall_risk']}")
```

### 2. Digital Twin Simulator (`digital_twin.py`)

Creates a virtual replica of the Fortress SDN environment.

```python
from products.nexus.lib.red_purple_teaming import (
    DigitalTwinSimulator,
    TwinConfig,
    VirtualDevice,
    VirtualBubble,
    BubbleType,
)

config = TwinConfig(
    max_virtual_devices=100,
    default_bubble_count=5,
    enable_traffic_simulation=True,
)

twin = DigitalTwinSimulator(config=config)

# Option 1: Sync from production Fortress
twin.sync_from_fortress(fortress_api)

# Option 2: Generate mock network
twin.generate_mock_network(device_count=20, bubble_count=4)

# Inject test device
device = VirtualDevice(
    mac='aa:bb:cc:dd:ee:ff',
    ip='10.200.0.100',
    hostname='attacker-device',
    vendor='Unknown',
)
twin.inject_device(device)

# Move device between bubbles
twin.move_device_to_bubble('aa:bb:cc:dd:ee:ff', 'bubble-guests')
```

### 3. NSE Heartbeat (`nse_heartbeat.py`)

Enhanced D2D verification using Neural Synaptic Encryption heartbeats.

**Token Format** (40 bytes):
```
┌──────────────────────────────────────────────────────────────────┐
│ Timestamp (8) │ Neural Hash (16) │ Resonance Sig (8) │ Seq (4) │ CRC (4) │
└──────────────────────────────────────────────────────────────────┘
```

```python
from products.nexus.lib.red_purple_teaming import (
    NSEHeartbeat,
    NSEValidator,
    HeartbeatToken,
)

# Device creates heartbeat generator with its neural weights
heartbeat = NSEHeartbeat(weights=device_neural_weights)

# Generate token for D2D verification
token = heartbeat.generate_token()
token_bytes = token.to_bytes()  # 40 bytes

# Peer validates token
validator = NSEValidator(weights=expected_weights)
is_valid, reason = validator.validate(token)

if not is_valid:
    print(f"D2D verification failed: {reason}")
```

### 4. Bubble Attack Vectors (`bubble_attacks.py`)

Nine SDN-specific attack vectors targeting the Ecosystem Bubble system:

| # | Attack | Target | MITRE ATT&CK |
|---|--------|--------|--------------|
| 1 | **TER Replay** | Replay TER sequences | T1134 |
| 2 | **Entropy Poisoning** | Inject low-entropy data | T1485 |
| 3 | **Timing Correlation** | Leak timing patterns | T1499 |
| 4 | **Weight Prediction** | Predict neural weights | T1606 |
| 5 | **MAC Impersonation** | Spoof trusted MAC | T1036 |
| 6 | **mDNS Spoofing** | Fake service discovery | T1557 |
| 7 | **Temporal Mimicry** | Copy device schedule | T1036.004 |
| 8 | **DHCP Fingerprint Spoof** | Fake OS fingerprint | T1036.005 |
| 9 | **D2D Affinity Injection** | Fake device relationships | T1098 |

```python
from products.nexus.lib.red_purple_teaming import (
    TERReplayBubbleAttack,
    MACImpersonationAttack,
    ATTACK_CLASSES,
)

# Run specific attack
attack = MACImpersonationAttack()
result = attack.execute(twin, target_mac='aa:bb:cc:dd:ee:01')

print(f"Attack: {result.attack_name}")
print(f"Success: {result.success}")
print(f"CVSS Score: {result.cvss_score()}")
print(f"Detected: {result.details.get('impersonation_detected', False)}")

# Run all attacks
for name, attack_class in ATTACK_CLASSES.items():
    attack = attack_class()
    result = attack.execute(twin)
    print(f"{name}: {'BLOCKED' if not result.success else 'SUCCEEDED'}")
```

### 5. Meta-Regressor (`meta_regressor.py`)

Optimizes bubble accuracy using meta-regression analysis.

**Formula**:
```
E = β₀ + β₁(Temporal_Sync) + β₂(D2D_Affinity) + β₃(NSE_Resonance) + ε
```

Where:
- **E**: Bubble accuracy (0.0 - 1.0)
- **β₀**: Intercept (baseline accuracy)
- **β₁**: Temporal sync coefficient
- **β₂**: D2D affinity coefficient
- **β₃**: NSE resonance coefficient
- **ε**: Error term

```python
from products.nexus.lib.red_purple_teaming import (
    MetaRegressor,
    BubbleObservation,
    OptimizationTarget,
)

regressor = MetaRegressor()

# Add observations from simulations
for simulation in past_simulations:
    obs = BubbleObservation(
        bubble_id=simulation.bubble_id,
        temporal_sync=simulation.temporal_sync_score,
        d2d_affinity=simulation.d2d_affinity_score,
        nse_resonance=simulation.nse_resonance_score,
        accuracy=simulation.measured_accuracy,
    )
    regressor.add_observation(obs)

# Run regression
result = regressor.run_regression(OptimizationTarget.ACCURACY)

print(f"R² Score: {result.r_squared:.3f}")
print(f"Coefficients: {result.coefficients}")

# Get optimization recommendations
recommendations = regressor.generate_recommendations(result)
for rec in recommendations:
    print(f"- {rec.parameter}: {rec.action} (Impact: {rec.expected_impact})")
```

## n8n Workflow Integration

The framework integrates with n8n for automated validation loops.

**Workflow**: `n8n-workflows/purple-team-validation.json`

### Events

| Event Type | Description | Webhook Path |
|------------|-------------|--------------|
| `purple_team_validation` | Simulation results | `/purple-team-validation` |
| `purple_team_optimization` | Optimization recommendations | `/purple-team-validation` |

### Workflow Actions

1. **Route Events** - Direct to validation or optimization path
2. **Process Results** - Calculate defense metrics
3. **Critical Alerts** - Send alerts for HIGH/CRITICAL risk
4. **Queue Mitigations** - Apply auto-mitigations
5. **Log to ClickHouse** - Persist for analytics

### Sample Event Payload

```json
{
  "event_type": "purple_team_validation",
  "timestamp": "2025-01-06T12:00:00Z",
  "data": {
    "simulation_id": "sim-abc123",
    "defense_score": 72,
    "overall_risk": "MEDIUM",
    "summary": {
      "attacks_total": 9,
      "attacks_successful": 2,
      "attacks_blocked": 7
    },
    "bubble_metrics": {
      "penetrated": 1,
      "total": 4
    },
    "recommendations": [
      "Increase NSE heartbeat frequency",
      "Enable MAC address binding"
    ],
    "auto_mitigations": [
      {
        "type": "rate_limit",
        "rule": "mDNS response rate",
        "priority": "high"
      }
    ]
  }
}
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PURPLE_TEAM_FORTRESS_URL` | `http://fortress:8443` | Fortress API URL |
| `PURPLE_TEAM_TIMEOUT` | `60` | Simulation timeout (seconds) |
| `PURPLE_TEAM_CLICKHOUSE` | `true` | Enable ClickHouse logging |
| `PURPLE_TEAM_N8N_WEBHOOK` | `true` | Enable n8n webhooks |
| `N8N_WEBHOOK_URL` | - | n8n webhook endpoint |

### PurpleTeamConfig Options

```python
@dataclass
class PurpleTeamConfig:
    fortress_api_url: str = 'http://fortress:8443'
    simulation_timeout_s: int = 60
    attack_vectors: List[str] = field(default_factory=lambda: list(ATTACK_CLASSES.keys()))
    enable_auto_mitigation: bool = True
    clickhouse_enabled: bool = True
    n8n_webhook_enabled: bool = True
    n8n_webhook_url: Optional[str] = None
    max_concurrent_attacks: int = 3
    meta_learning_enabled: bool = True
```

## Testing

```bash
# Run all tests
pytest tests/test_red_purple_teaming.py -v

# Run specific test class
pytest tests/test_red_purple_teaming.py::TestBubbleAttackVectors -v

# Run with coverage
pytest tests/test_red_purple_teaming.py --cov=products.nexus.lib.red_purple_teaming
```

## Security Considerations

1. **Simulation Isolation** - Digital Twin runs entirely in memory, no production impact
2. **Rate Limiting** - Max 100 simulations per hour per Nexus node
3. **Audit Logging** - All simulations logged to ClickHouse
4. **Access Control** - Requires NEXUS_ADMIN role
5. **No Real Attacks** - Framework cannot execute attacks on production systems

## Roadmap

### Phase 1 (Complete)
- [x] Digital Twin simulator
- [x] 9 bubble attack vectors
- [x] NSE heartbeat verification
- [x] Meta-regressor framework
- [x] n8n workflow integration

### Phase 2 (Planned)
- [ ] Federated learning across Nexus nodes
- [ ] Adversarial ML model training
- [ ] Real-time attack detection feedback
- [ ] Automated patch generation

### Phase 3 (Future)
- [ ] Cross-organization threat sharing
- [ ] Zero-day simulation framework
- [ ] AI-generated attack vectors

## References

- [CLAUDE.md](../../../../CLAUDE.md) - Main project guide
- [Ecosystem Bubble](../../../fortress/lib/ecosystem_bubble.py) - Bubble system implementation
- [NSE Protocol](../../../../core/neuro/README.md) - Neural Synaptic Encryption
- [Adversarial Framework](../../../../core/neuro/adversarial/) - Core adversarial testing

## License

Proprietary - Part of HookProbe Nexus tier (Commercial License Required)
