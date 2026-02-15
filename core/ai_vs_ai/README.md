# HookProbe AI vs AI Module

Unified framework for adversarial AI-based threat detection and response.

## Overview

The AI vs AI module provides end-to-end integration between:
- **LSTM Threat Prediction**: Predict next attack types from sequences
- **IoC Generation**: Create structured attack descriptions from predictions
- **Defense Orchestration**: Consult AI models for defense strategies
- **Compute Routing**: Route tasks between Fortress (lite) and Nexus (advanced)

```
┌─────────────────────────────────────────────────────────────┐
│                    AI VS AI FRAMEWORK                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ThreatPredictor ──► IoCGenerator ──► DefenseOrchestrator   │
│       (LSTM)           (Create)         (n8n + AI)          │
│                           │                  │               │
│                           ▼                  ▼               │
│                    ComputeEvaluator ───► Route Task         │
│                    (Fortress/Nexus)                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Components

### ThreatPredictor

Interface with LSTM models for attack sequence prediction.

```python
from core.ai_vs_ai import ThreatPredictor, ComputeTier

predictor = ThreatPredictor(compute_tier=ComputeTier.FORTRESS_STANDARD)

# Add detected events
predictor.add_event("port_scan")
predictor.add_event("address_scan")
predictor.add_event("brute_force")

# Get prediction
prediction = predictor.predict()
print(f"Next attack: {prediction.predicted_attack}")
print(f"Confidence: {prediction.confidence:.0%}")
print(f"Trend: {prediction.trend}")
```

**Features**:
- LSTM model inference (when PyTorch available)
- Statistical fallback (Markov chain)
- Temporal pattern analysis
- Anomaly detection

### IoCGenerator

Generate Indicators of Compromise from predictions.

```python
from core.ai_vs_ai import IoCGenerator, ThreatPrediction

generator = IoCGenerator()

# From LSTM prediction
ioc = generator.from_prediction(prediction, source_ip="192.168.1.100")

print(f"IoC Type: {ioc.ioc_type.value}")
print(f"Attack: {ioc.attack_category}")
print(f"Description: {ioc.attack_description}")
print(f"MITRE: {ioc.mitre_techniques}")

# Generate AI consultation prompt
prompt = ioc.to_prompt()
```

**Features**:
- MITRE ATT&CK mapping
- NAPSE IDS integration
- IoC aggregation and correlation
- Privacy-preserving IP anonymization

### DefenseOrchestrator

Orchestrate AI consultation for defense strategies.

```python
from core.ai_vs_ai import DefenseOrchestrator, ComputeTier

orchestrator = DefenseOrchestrator(compute_tier=ComputeTier.FORTRESS_STANDARD)

# Consult AI for defense strategy
strategy = orchestrator.consult(ioc, prediction)

print(f"Primary action: {strategy.primary_action.value}")
print(f"Reasoning: {strategy.reasoning}")
print(f"Confidence: {strategy.confidence:.0%}")

# Trigger n8n workflow
orchestrator.trigger_n8n_workflow(strategy, ioc)
```

**Supported AI Backends**:
- **Local (Ollama)**: llama2, mistral, etc.
- **OpenAI**: GPT-4, GPT-3.5
- **Anthropic**: Claude

### ComputeEvaluator

Route tasks between Fortress and Nexus.

```python
from core.ai_vs_ai import ComputeEvaluator, ComputeTask

evaluator = ComputeEvaluator(local_tier=ComputeTier.FORTRESS_STANDARD)

# Create task
task = ComputeTask(
    task_type="deep_analysis",
    estimated_memory_mb=4096,
    estimated_gpu_required=True,
    estimated_duration_sec=120,
)

# Get routing recommendation
rec = evaluator.get_recommendation(task)
print(f"Route to: {rec['recommended_tier']}")
print(f"Reasons: {rec['reasons']}")

# Route the task
task = evaluator.route_task(task)
```

## Compute Tiers

| Tier | RAM | GPU | Max Duration | Use Case |
|------|-----|-----|--------------|----------|
| `FORTRESS_LITE` | ≤1GB | No | 30s | Basic predictions |
| `FORTRESS_STANDARD` | ≤2GB | No | 60s | Full LSTM inference |
| `NEXUS_STANDARD` | ≤8GB | Yes | 5min | Deep analysis |
| `NEXUS_ADVANCED` | ≤32GB | Yes | 1hr | Model training |
| `MESH_CLOUD` | Unlimited | Yes | Unlimited | Heavy workloads |

## Integration with Products

### Fortress (Lite)

```python
# In products/fortress/lib/ai_integration.py
from core.ai_vs_ai import (
    ThreatPredictor,
    IoCGenerator,
    DefenseOrchestrator,
    ComputeEvaluator,
    ComputeTier,
)

class FortressAIIntegration:
    def __init__(self):
        self.predictor = ThreatPredictor(compute_tier=ComputeTier.FORTRESS_LITE)
        self.ioc_gen = IoCGenerator()
        self.orchestrator = DefenseOrchestrator(compute_tier=ComputeTier.FORTRESS_LITE)
        self.evaluator = ComputeEvaluator(local_tier=ComputeTier.FORTRESS_LITE)

    def process_attack(self, attack_type: str, source_ip: str):
        # Add to predictor
        self.predictor.add_event(attack_type)

        # Get prediction
        prediction = self.predictor.predict()

        # Check if complex task needs Nexus
        task = self.predictor.get_compute_task()
        if task.requires_nexus():
            # Forward to Nexus
            self.forward_to_nexus(prediction, source_ip)
            return

        # Generate IoC
        ioc = self.ioc_gen.from_prediction(prediction, source_ip)

        # Get defense strategy (using defaults, no AI consultation)
        strategy = self.orchestrator.consult(ioc, prediction, use_ai=False)

        return strategy
```

### Nexus (Advanced)

```python
# In products/nexus/lib/ai_integration.py
from core.ai_vs_ai import (
    ThreatPredictor,
    IoCGenerator,
    DefenseOrchestrator,
    ComputeTier,
)

class NexusAIIntegration:
    def __init__(self):
        self.predictor = ThreatPredictor(compute_tier=ComputeTier.NEXUS_ADVANCED)
        self.ioc_gen = IoCGenerator()
        self.orchestrator = DefenseOrchestrator(
            compute_tier=ComputeTier.NEXUS_ADVANCED,
            ai_config={
                "local": {"enabled": True, "model": "llama2:70b"},
                "openai": {"enabled": True},
                "anthropic": {"enabled": True},
            }
        )

    def deep_analysis(self, prediction, source_ip: str):
        # Generate IoC
        ioc = self.ioc_gen.from_prediction(prediction, source_ip)

        # Full AI consultation
        strategy = self.orchestrator.consult(ioc, prediction, use_ai=True)

        # Trigger n8n for execution
        self.orchestrator.trigger_n8n_workflow(strategy, ioc)

        return strategy
```

## n8n Workflow Integration

The defense orchestrator integrates with n8n for automated response:

1. **Webhook Trigger**: `POST /webhook/defense-execute`
2. **Payload**: IoC + DefenseStrategy JSON
3. **Actions**: Firewall rules, alerts, isolation

Example n8n workflow:
```
Webhook (defense-execute)
    ↓
Parse IoC and Strategy
    ↓
Route by Primary Action
    ├─ BLOCK_IP → nft add rule ...
    ├─ RATE_LIMIT → tc qdisc ...
    ├─ ISOLATE → SDN rule
    └─ ALERT → Notify SOC
    ↓
Log to ClickHouse
```

## Attack Categories

| Category | Description | Severity |
|----------|-------------|----------|
| `malware_c2` | Malware command & control | CRITICAL |
| `data_exfiltration` | Unauthorized data transfer | CRITICAL |
| `sql_injection` | SQL injection attack | HIGH |
| `privilege_escalation` | Privilege escalation attempt | HIGH |
| `lateral_movement` | Lateral movement | HIGH |
| `brute_force` | Credential brute force | HIGH |
| `syn_flood` | TCP SYN flood | MEDIUM |
| `dns_tunneling` | DNS tunneling | MEDIUM |
| `dos_attack` | Denial of service | MEDIUM |
| `port_scan` | Port scanning | LOW |
| `address_scan` | Address scanning | LOW |
| `reconnaissance` | General recon | INFO |

## MITRE ATT&CK Mapping

IoCs automatically include MITRE ATT&CK mappings:

```python
from core.ai_vs_ai.models import get_mitre_mapping

mapping = get_mitre_mapping("sql_injection")
# {'tactics': ['Initial Access', 'Execution'], 'techniques': ['T1190', 'T1059.001']}
```

## Privacy Considerations

- IP addresses are anonymized (network class only: `192.168.0.0`)
- No domain content stored in IoCs
- Raw evidence limited to attack patterns
- Configurable retention in IoCGenerator

## Testing

```bash
# Run unit tests
pytest tests/test_ai_vs_ai.py -v

# Test with coverage
pytest tests/test_ai_vs_ai.py --cov=core/ai_vs_ai
```

## Files

| File | Purpose |
|------|---------|
| `__init__.py` | Module exports |
| `models.py` | Data models (IoC, ThreatPrediction, DefenseStrategy) |
| `ioc_generator.py` | IoC generation from predictions |
| `threat_predictor.py` | LSTM/statistical prediction |
| `defense_orchestrator.py` | AI consultation and n8n integration |
| `compute_evaluator.py` | Task routing between Fortress/Nexus |

## Requirements

**Fortress Lite** (no additional requirements):
- Statistical prediction only
- Default defense strategies

**Fortress Standard**:
- PyTorch (optional, for LSTM)
- requests (for n8n)

**Nexus Advanced**:
- PyTorch
- Ollama (local AI)
- OpenAI/Anthropic API keys (optional)

## License

AGPL-3.0
