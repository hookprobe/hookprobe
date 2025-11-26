# HookProbe N8N Workflows

This directory contains N8N workflow definitions for HookProbe autonomous threat detection and response.

## Directory Structure

```
workflows/
├── core/                          # Core automation workflows
│   ├── event-ingestion.json       # Event collection and QSECBIT scoring
│   ├── qsecbit-scoring.json       # Risk scoring engine integration
│   ├── threat-correlation.json    # Threat intelligence correlation
│   └── automated-response.json    # Automated response actions
├── group-a/                       # Group A: Highest Impact
│   ├── attack-surface-mapping.json
│   ├── credential-defense.json
│   ├── container-guardian.json
│   └── iot-integrity.json
├── group-b/                       # Group B: Medium Priority
│   ├── dns-c2-detection.json
│   ├── behavioral-analytics.json
│   └── lateral-movement.json
└── group-c/                       # Group C: Learning-Focused
    ├── metasploit-testing.json
    ├── exfiltration-detection.json
    └── wireless-monitoring.json
```

## Core Workflows

### 1. Event Ingestion Pipeline (`core/event-ingestion.json`)

**Purpose**: Collect security events from all sources and route for processing

**Trigger**: Webhook `/webhook/hookprobe-events`

**Flow**:
1. Receive event via webhook
2. Normalize event data
3. Call QSECBIT for risk scoring
4. Route based on risk threshold (>= 0.7)
5. Store in ClickHouse
6. Send metrics to VictoriaMetrics

**Usage**:
```bash
# Send event to workflow
curl -X POST http://localhost:5678/webhook/hookprobe-events \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.1.100",
    "event_type": "ssh_login_attempt",
    "severity": "high"
  }'
```

### 2. Automated Response (`core/automated-response.json`)

**Purpose**: Execute automated security responses based on threat level

**Trigger**: Webhook `/webhook/hookprobe-response`

**Flow**:
1. Receive threat alert
2. Determine risk level (CRITICAL/HIGH/MEDIUM)
3. Execute appropriate response:
   - **CRITICAL** (0.9-1.0): Isolate device immediately
   - **HIGH** (0.8-0.9): Block IP + Alert SOC
   - **MEDIUM** (0.7-0.8): Rate limit + Monitor
4. Apply firewall rules
5. Log response to ClickHouse
6. Send Grafana alert if needed

**Usage**:
```bash
# Trigger automated response
curl -X POST http://localhost:5678/webhook/hookprobe-response \
  -H "Content-Type: application/json" \
  -d '{
    "qsecbit_score": 0.95,
    "source_ip": "192.168.1.100",
    "threat_type": "exploit_attempt"
  }'
```

## Importing Workflows

### Via N8N UI
1. Open N8N: `http://localhost:5678`
2. Go to "Workflows" → "Import from File"
3. Select workflow JSON file
4. Click "Import"

### Via CLI
```bash
# Install n8n CLI
npm install -g n8n

# Import workflow
n8n import:workflow --input=workflows/core/event-ingestion.json

# Import all core workflows
for file in workflows/core/*.json; do
  n8n import:workflow --input="$file"
done
```

### Via API
```bash
# Get n8n API key from UI
N8N_API_KEY="your-api-key"

# Import workflow
curl -X POST http://localhost:5678/api/v1/workflows \
  -H "X-N8N-API-KEY: $N8N_API_KEY" \
  -H "Content-Type: application/json" \
  -d @workflows/core/event-ingestion.json
```

## Workflow Dependencies

### Required Services
- **N8N**: Workflow execution engine (POD 008)
- **QSECBIT API**: http://localhost:8888
- **ClickHouse**: http://clickhouse:8123
- **VictoriaMetrics**: http://victoriametrics:8428
- **Grafana**: http://localhost:3000

### Environment Variables
```bash
# Set in n8n environment
N8N_CUSTOM_EXTENSIONS="qsecbit,clickhouse,victoriametrics"
QSECBIT_API_URL="http://localhost:8888"
CLICKHOUSE_URL="http://clickhouse:8123"
VICTORIAMETRICS_URL="http://victoriametrics:8428"
GRAFANA_API_URL="http://localhost:3000"
```

## Testing Workflows

### Validate JSON Structure
```bash
# Validate all workflows
python3 ../tests/validate_workflows.py

# Validate specific workflow
jq empty workflows/core/event-ingestion.json && echo "Valid JSON"
```

### Test Workflow Execution
```bash
# Start n8n in test mode
n8n start --tunnel

# Run automated tests
pytest ../tests/test_workflow_execution.py -v
```

### Manual Testing
```bash
# 1. Activate workflow in n8n UI
# 2. Send test event
curl -X POST http://localhost:5678/webhook/hookprobe-events \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.1.100",
    "event_type": "port_scan",
    "qsecbit_score": 0.85
  }'

# 3. Check execution in n8n UI → "Executions"
```

## Customization

### Modifying Workflows
1. Import workflow into n8n
2. Edit in visual editor
3. Test changes
4. Export updated workflow:
   ```bash
   n8n export:workflow --id=<workflow-id> --output=custom-workflow.json
   ```

### Adding New Nodes
Common node types for security workflows:
- **HTTP Request**: Call external APIs
- **Function**: Custom JavaScript logic
- **IF**: Conditional routing
- **Switch**: Multi-way routing
- **Execute Command**: Run shell commands
- **Schedule Trigger**: Periodic execution
- **Webhook**: HTTP endpoint trigger

### Custom Functions
Example QSECBIT scoring function:
```javascript
// In Function node
const event = items[0].json;

// Custom risk scoring logic
let risk_score = 0.0;

if (event.failed_attempts > 5) risk_score += 0.3;
if (event.unusual_time) risk_score += 0.2;
if (event.known_bad_ip) risk_score += 0.5;

return [{
  json: {
    ...event,
    custom_score: risk_score
  }
}];
```

## Monitoring

### Workflow Execution Metrics
- View in n8n UI → "Executions"
- Check logs: `docker logs hookprobe-n8n`
- Query ClickHouse:
  ```sql
  SELECT
    workflow_name,
    COUNT(*) as executions,
    AVG(duration_ms) as avg_duration
  FROM workflow_executions
  WHERE timestamp >= now() - INTERVAL 1 HOUR
  GROUP BY workflow_name;
  ```

### Alerting
Configure alerts for:
- Workflow failures
- High execution duration
- QSECBIT API errors
- ClickHouse write failures

## Troubleshooting

### Workflow Not Triggering
1. Check webhook is active
2. Verify n8n is running: `curl http://localhost:5678/healthz`
3. Check webhook URL matches configuration
4. Review n8n logs for errors

### QSECBIT API Errors
1. Verify QSECBIT is running: `curl http://localhost:8888/healthz`
2. Check API URL in workflow configuration
3. Verify network connectivity between n8n and QSECBIT PODs

### ClickHouse Write Failures
1. Check ClickHouse is running: `curl http://clickhouse:8123/ping`
2. Verify table exists: `clickhouse-client -q "SHOW TABLES"`
3. Check data format matches schema

## Best Practices

1. **Error Handling**: Add error catch nodes to all workflows
2. **Logging**: Log all important events to ClickHouse
3. **Testing**: Test workflows in staging before production
4. **Versioning**: Export and commit workflow changes to git
5. **Documentation**: Add descriptions to all nodes
6. **Monitoring**: Set up alerts for workflow failures
7. **Security**: Use credentials for API access, never hardcode secrets

## Contributing

To contribute new workflows:
1. Create workflow in n8n UI
2. Test thoroughly
3. Export to JSON
4. Add to appropriate directory (core/group-a/group-b/group-c)
5. Update this README
6. Submit pull request

## References

- [N8N Documentation](https://docs.n8n.io/)
- [HookProbe AUTOMATION.md](../AUTOMATION.md)
- [QSECBIT API](../../src/qsecbit/README.md)
- [ClickHouse Schema](../integrations/clickhouse/schema.sql)
