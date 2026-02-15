# POD-010: DSM Ledger

Decentralized Security Mesh - Cryptographically verifiable event ledger.

## Quick Start

### Edge Node Deployment

```bash
# Set environment variables
export HOOKPROBE_NODE_ID="edge-$(hostname)"
export DSM_NODE_ROLE="edge"
export DSM_TPM_ENABLED="true"  # Set to "false" if no TPM
export DSM_BOOTSTRAP_NODES="validator1.mesh.hookprobe.local:7946,validator2.mesh.hookprobe.local:7946"

# Deploy
docker-compose up -d

# Check status
docker-compose ps
docker-compose logs -f dsm-node
```

### Validator Node Deployment

```bash
# Set environment variables
export HOOKPROBE_NODE_ID="validator-$(hostname)"
export DSM_NODE_ROLE="validator"
export DSM_TPM_ENABLED="true"
export DSM_BOOTSTRAP_NODES="validator1.mesh.hookprobe.local:7946,validator2.mesh.hookprobe.local:7946"

# Deploy with validator certificate
cp /path/to/validator-cert.pem /var/lib/hookprobe/certs/validator.pem

docker-compose up -d
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HOOKPROBE_NODE_ID` | `edge-001` | Unique node identifier |
| `DSM_NODE_ROLE` | `edge` | Node role: `edge` or `validator` |
| `DSM_TPM_ENABLED` | `true` | Enable TPM hardware signing |
| `DSM_BOOTSTRAP_NODES` | `` | Comma-separated list of validator nodes |
| `DSM_LOG_LEVEL` | `INFO` | Log level: DEBUG, INFO, WARNING, ERROR |

### Storage Volumes

- `/var/lib/hookprobe/dsm/microblocks` - Local ledger storage (LevelDB)
- `/var/lib/hookprobe/dsm/keys` - Node signing keys
- `/var/lib/hookprobe/certs` - Certificates and validator credentials

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│ POD-010: DSM Ledger                                      │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──────────────┐         ┌──────────────┐             │
│  │  dsm-node    │◄────────┤  dsm-api     │             │
│  │              │         │              │             │
│  │  - Microblock│         │  - Query API │             │
│  │    creation  │         │  - REST/gRPC │             │
│  │  - Gossip    │         │  - Health    │             │
│  │  - Validator │         │              │             │
│  └───────┬──────┘         └──────────────┘             │
│          │                                              │
│          ▼                                              │
│  ┌──────────────────────┐                              │
│  │  LevelDB Ledger      │                              │
│  │  /data/microblocks   │                              │
│  └──────────────────────┘                              │
│                                                          │
└─────────────────────────────────────────────────────────┘
           ▲                        ▲
           │                        │
    POD-006 (IDS/IPS)        POD-007 (AI Response)
```

## Integration

### POD-006 (Security Detection)

```python
from hookprobe.dsm import DSMNode

# Initialize
dsm = DSMNode(node_id=os.getenv('HOOKPROBE_NODE_ID'))

# On NAPSE IDS alert
microblock = dsm.create_microblock(
    payload={'alert_id': alert.id, 'severity': alert.severity},
    event_type='ids_alert'
)
```

### POD-007 (AI Response)

```python
# On mitigation executed
microblock = dsm.create_microblock(
    payload={'threat_id': threat.id, 'action': 'blocked'},
    event_type='mitigation'
)
```

## API Endpoints

### Query API (Port 8100)

- `GET /health` - Health check
- `GET /api/v1/microblocks/:id` - Get microblock by ID
- `GET /api/v1/microblocks/node/:node_id` - Get microblocks for node
- `GET /api/v1/checkpoints/:epoch` - Get checkpoint for epoch
- `GET /api/v1/stats` - DSM statistics

## Monitoring

### Metrics (Prometheus)

- `dsm_microblocks_created_total` - Total microblocks created
- `dsm_microblocks_stored` - Current microblocks in ledger
- `dsm_storage_bytes` - Ledger storage size
- `dsm_gossip_peers` - Connected gossip peers
- `dsm_tpm_available` - TPM availability (0/1)

### Grafana Dashboard

Import dashboard from: `docs/dashboards/dsm-mesh-overview.json`

## Troubleshooting

### TPM Not Available

If TPM device is not found:
1. Check `/dev/tpm0` exists
2. Install `tpm2-tools` on host
3. Or set `DSM_TPM_ENABLED=false` to use software fallback

### No Gossip Peers

If node cannot connect to validators:
1. Check `DSM_BOOTSTRAP_NODES` is set correctly
2. Verify network connectivity: `nc -zv validator1.mesh.hookprobe.local 7946`
3. Check firewall rules allow port 7946

### Storage Issues

If LevelDB fails:
1. Check disk space: `df -h /var/lib/hookprobe/dsm`
2. Check permissions: `ls -ld /var/lib/hookprobe/dsm/microblocks`
3. System will fall back to in-memory storage with warning

## Development Status

**Phase 1 Complete** ✅

- TPM operations with fallback
- BLS signatures with fallback
- LevelDB storage with fallback
- Basic gossip protocol
- POD-006/007 integration points
- Container infrastructure

**Next Phase** (Q2 2025)

- Full validator quorum implementation
- Production gossip protocol (libp2p)
- Cross-node threat intelligence
- Grafana dashboard

## License

MIT License - See LICENSE file

## References

- [DSM Whitepaper](../../docs/architecture/dsm-whitepaper.md)
- [DSM Implementation](../../docs/architecture/dsm-implementation.md)
- [Security Model](../../docs/architecture/security-model.md#8-decentralized-security-mesh-dsm)
