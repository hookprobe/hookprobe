# CLAUDE.md - AI Assistant Guide for HookProbe

**Version**: 5.0
**Last Updated**: 2025-12-07
**Purpose**: Comprehensive guide for AI assistants working with the HookProbe codebase

---

## Quick Lookup: When User Wants To...

| User Request | Go To | Key Files |
|-------------|-------|-----------|
| **Run tests** | `pytest tests/` | `pytest.ini`, `tests/test_*.py` |
| **Check code quality** | `make lint` | `.pre-commit-config.yaml` |
| **Deploy Sentinel** | `./install.sh --tier sentinel` | `products/sentinel/` |
| **Deploy Guardian** | `./install.sh --tier guardian` | `products/guardian/` |
| **Deploy Fortress** | `./install.sh --tier fortress` | `products/fortress/` |
| **Deploy Nexus** | `./install.sh --tier nexus` | `products/nexus/` |
| **Modify Qsecbit algorithm** | Edit core logic | `core/qsecbit/qsecbit.py` |
| **Add XDP/eBPF rules** | Edit XDP manager | `core/qsecbit/xdp_manager.py` |
| **Work with HTP protocol** | Core transport | `core/htp/transport/htp.py` |
| **Configure n8n automation** | Deploy addon | `deploy/addons/n8n/` |
| **Add LTE/5G failover** | Check addon docs | `deploy/addons/lte/README.md` |
| **Debug CI/CD failures** | Check workflows | `.github/workflows/` |
| **Understand architecture** | Read architecture | `ARCHITECTURE.md` |
| **Add new security feature** | Check shared response | `shared/response/` |
| **Modify DSM consensus** | Check shared DSM | `shared/dsm/` |
| **GDPR compliance** | Check privacy module | `core/qsecbit/gdpr_privacy.py` |

---

## Table of Contents

- [Project Overview](#project-overview)
- [Accurate Codebase Structure](#accurate-codebase-structure)
- [Qsecbit v5.0 Modular Architecture](#qsecbit-v50-modular-architecture)
- [Testing Guide](#testing-guide)
- [CI/CD Workflows](#cicd-workflows)
- [Development Tooling](#development-tooling)
- [Scenario-Based Guidance](#scenario-based-guidance)
- [Key Conventions](#key-conventions)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

---

## Project Overview

### What is HookProbe?

HookProbe is a **federated cybersecurity mesh** built for edge computing and distributed security. It provides:

- **AI-Powered Threat Detection**: Qsecbit algorithm for real-time security analysis
- **Federated Defense**: Privacy-preserving collective intelligence
- **Multi-Tier Products**: Sentinel, Guardian, Fortress, Nexus, MSSP
- **Zero Trust Mesh**: HTP protocol with post-quantum cryptography

**Project Type**: Federated Security Platform / Infrastructure-as-Code
**Primary Languages**: Python (core logic), Bash (deployment)
**Deployment**: Podman containers with OVS networking
**License**: MIT (v5.0+)

### Product Tiers

| Tier | RAM | Use Case | Location |
|------|-----|----------|----------|
| **Sentinel** | 512MB | IoT Validator | `products/sentinel/` |
| **Guardian** | 3GB | Travel/Portable | `products/guardian/` |
| **Fortress** | 8GB | Edge Router | `products/fortress/` |
| **Nexus** | 64GB+ | ML/AI Compute | `products/nexus/` |
| **MSSP** | Cloud | Central Brain | `products/mssp/` |

---

## Accurate Codebase Structure

```
hookprobe/
├── install.sh                        # Main installer (--tier sentinel/guardian/fortress/nexus)
├── uninstall.sh                      # Main uninstaller
├── install-validator.sh              # Installation validation script
├── install-sentinel-lite.sh          # Lightweight Sentinel installer
├── ARCHITECTURE.md                   # Federated mesh architecture
├── CHANGELOG.md                      # Version history
├── Makefile                          # Development commands (make test, make lint)
├── pytest.ini                        # Test configuration
├── requirements.txt                  # Python dependencies
├── .pre-commit-config.yaml           # Pre-commit hooks config
│
├── core/                             # CORE INTELLIGENCE (The Neuron)
│   ├── htp/                          # HookProbe Transport Protocol
│   │   ├── transport/
│   │   │   ├── htp.py               # Main HTP implementation
│   │   │   ├── htp_vpn.py           # VPN integration
│   │   │   └── htp_file.py          # File transfer protocol
│   │   └── crypto/
│   │       ├── hybrid_kem.py        # Kyber post-quantum crypto
│   │       ├── transport.py         # ChaCha20-Poly1305
│   │       └── transport_v2.py      # Enhanced transport
│   │
│   ├── qsecbit/                      # Quantified Security Metric
│   │   ├── qsecbit.py               # Main algorithm (RAG scoring)
│   │   ├── qsecbit-agent.py         # Agent daemon
│   │   ├── energy_monitor.py        # RAPL power monitoring
│   │   ├── xdp_manager.py           # XDP/eBPF DDoS mitigation
│   │   ├── nic_detector.py          # NIC capability detection
│   │   ├── gdpr_privacy.py          # Privacy-preserving module
│   │   └── README.md                # Complete Qsecbit docs
│   │
│   └── neuro/                        # Neural Resonance Protocol
│       ├── core/
│       │   ├── ter.py               # Telemetry Event Record
│       │   ├── posf.py              # Proof of Secure Function
│       │   └── replay.py            # Replay protection
│       ├── neural/
│       │   ├── engine.py            # Neural weight evolution
│       │   └── fixedpoint.py        # Fixed-point arithmetic
│       └── validation/
│           └── validator_network.py  # Validator network
│
├── products/                         # PRODUCT TIERS
│   ├── sentinel/                     # DSM Validator (512MB)
│   ├── guardian/                     # Travel Companion (3GB)
│   │   ├── lib/
│   │   │   ├── guardian_agent.py    # Main agent
│   │   │   ├── htp_client.py        # HTP client
│   │   │   ├── layer_threat_detector.py
│   │   │   └── network_segmentation.py
│   │   └── scripts/
│   │       ├── setup.sh
│   │       └── uninstall.sh
│   ├── fortress/                     # Edge Router (8GB)
│   │   └── setup.sh
│   ├── nexus/                        # ML/AI Compute (64GB+)
│   │   └── vpn/                     # VPN integration
│   └── mssp/                         # Cloud MSSP
│       ├── device_registry.py
│       ├── geolocation.py
│       └── web/                     # Django web portal
│           ├── apps/
│           │   ├── dashboard/       # Main dashboard
│           │   ├── devices/         # Device management
│           │   ├── monitoring/      # Monitoring views
│           │   ├── sdn/             # SDN management
│           │   └── mssp_dashboard/  # MSSP-specific views
│           └── manage.py
│
├── shared/                           # SHARED INFRASTRUCTURE
│   ├── dsm/                          # Decentralized Security Mesh
│   │   ├── consensus.py             # BLS signature aggregation
│   │   ├── gossip.py                # P2P threat announcement
│   │   ├── ledger.py                # Microblock chain
│   │   ├── validator.py             # Validator logic
│   │   └── crypto/
│   │       ├── bls.py               # BLS signatures
│   │       ├── tpm.py               # TPM integration
│   │       └── attestation.py       # Remote attestation
│   └── response/                     # Automated Response
│       ├── kali-scripts.sh          # Kali mitigation
│       ├── attack-mitigation-orchestrator.sh
│       └── mitigation-maintenance.sh
│
├── deploy/                           # DEPLOYMENT SCRIPTS
│   ├── edge/                         # Edge deployment
│   │   ├── provision.sh             # Node provisioning
│   │   ├── cleanup.sh               # Cleanup script
│   │   ├── update.sh                # Update script
│   │   ├── hookprobe-ctl            # CLI control tool
│   │   └── systemd/                 # Systemd services
│   ├── cloud/                        # Cloud deployment
│   │   ├── setup.sh
│   │   ├── config.sh
│   │   └── uninstall.sh
│   ├── addons/                       # Optional addons
│   │   ├── n8n/                     # Workflow automation
│   │   │   ├── setup.sh
│   │   │   ├── config.sh
│   │   │   ├── uninstall.sh
│   │   │   └── workflows/           # Pre-built workflows
│   │   ├── lte/                     # LTE/5G connectivity
│   │   │   └── README.md
│   │   └── webserver/               # Web server addon
│   │       ├── setup-webserver.sh
│   │       └── Containerfile
│   └── install/
│       ├── validate-config.sh
│       └── README.md
│
├── scripts/                          # MAINTENANCE SCRIPTS
│   ├── install-edge.sh              # Edge installation
│   ├── gdpr-retention.sh            # GDPR data retention
│   ├── repo-cleanup-validator.sh    # Repository validation
│   ├── run-unit-tests.sh
│   ├── run-integration-tests.sh
│   ├── run-performance-tests.sh
│   └── lib/
│       ├── platform.sh              # Platform detection
│       ├── requirements.sh          # Dependency checks
│       └── instructions.sh          # Installation instructions
│
├── tests/                            # TEST SUITES
│   ├── test_qsecbit.py              # Qsecbit algorithm tests
│   ├── test_htp_e2e.py              # HTP end-to-end tests
│   ├── test_htp_keyless.py          # Keyless protocol tests
│   └── test_htp_security_enhancements.py
│
├── docs/                             # DOCUMENTATION
│   ├── CLAUDE.md                    # This file (for AI assistants)
│   ├── CONTRIBUTING.md              # Contribution guide
│   ├── SECURITY.md                  # Security policy
│   ├── GDPR.md                      # GDPR compliance
│   ├── CI-CD.md                     # CI/CD documentation
│   ├── architecture/
│   │   └── HOOKPROBE-ARCHITECTURE.md
│   ├── installation/
│   │   ├── INSTALLATION.md
│   │   ├── BEGINNER-GUIDE.md
│   │   └── cloud-deployment.md
│   ├── guides/
│   │   ├── clickhouse-integration.md
│   │   └── clickhouse-quick-start.md
│   └── dashboards/
│       ├── admin-dashboard.md
│       └── mssp-dashboard.md
│
├── .github/                          # CI/CD CONFIGURATION
│   ├── workflows/
│   │   ├── app-tests.yml            # Application tests
│   │   ├── python-lint.yml          # Python linting
│   │   ├── container-tests.yml      # Container tests
│   │   ├── installation-test.yml    # Installation tests
│   │   ├── arm64-tests.yml          # ARM64 tests
│   │   ├── documentation.yml        # Doc validation
│   │   ├── ci-status.yml            # CI status
│   │   ├── config-validation.yml    # Config validation
│   │   └── repo-cleanup-validation.yml
│   ├── actions/
│   │   ├── setup-python/            # Python setup action
│   │   └── setup-podman/            # Podman setup action
│   └── ISSUE_TEMPLATE/
│       ├── bug_report.md
│       ├── feature_request.md
│       └── security_vulnerability.md
│
└── config/                           # CONFIGURATION TEMPLATES
    └── (configuration files)
```

---

## Qsecbit v5.0 Modular Architecture

### Core Components

**Location**: `core/qsecbit/`

| File | Purpose |
|------|---------|
| `qsecbit.py` | Main orchestrator - resilience metric calculation |
| `energy_monitor.py` | RAPL + per-PID power tracking |
| `xdp_manager.py` | XDP/eBPF DDoS mitigation at kernel level |
| `nic_detector.py` | NIC capability detection (XDP-hw/drv/skb) |
| `gdpr_privacy.py` | Privacy-preserving data anonymization |
| `qsecbit-agent.py` | Agent daemon for continuous monitoring |

### Qsecbit Algorithm

```python
# The Formula
Qsecbit = α·drift + β·p_attack + γ·decay + δ·q_drift + ε·energy_anomaly

# Default Weights (without energy monitoring)
α = 0.30  # System drift (Mahalanobis distance)
β = 0.30  # Attack probability (ML-predicted)
γ = 0.20  # Classifier decay
δ = 0.20  # Quantum drift

# With Energy Monitoring (Intel CPUs with RAPL)
α = 0.25, β = 0.25, γ = 0.20, δ = 0.15, ε = 0.15
```

### RAG Status

| Status | Range | Meaning | Action |
|--------|-------|---------|--------|
| **GREEN** | < 0.45 | Normal | Learning baseline |
| **AMBER** | 0.45-0.70 | Warning | Kali spins up |
| **RED** | > 0.70 | Critical | Full mitigation |

### XDP/eBPF Modes

| Mode | Layer | Performance | When Used |
|------|-------|-------------|-----------|
| **XDP-hw** | Layer 0 | Ultra-fast | SmartNICs only |
| **XDP-drv** | Layer 1 | Fastest | Native driver support |
| **XDP-skb** | Layer 1.5 | Moderate | Universal fallback |

---

## Testing Guide

### Test Location

All tests are in the `tests/` directory:

```
tests/
├── __init__.py
├── test_qsecbit.py                   # Qsecbit algorithm tests
├── test_htp_e2e.py                   # HTP end-to-end tests
├── test_htp_keyless.py               # Keyless protocol tests
└── test_htp_security_enhancements.py # Security enhancement tests
```

### Running Tests

```bash
# Run all tests
pytest tests/

# Run with verbose output
pytest tests/ -vv

# Run with coverage
pytest tests/ --cov=core --cov=shared --cov-report=html

# Run specific test file
pytest tests/test_qsecbit.py

# Run specific test
pytest tests/test_qsecbit.py::test_function_name

# Run by marker
pytest tests/ -m "unit"           # Unit tests only
pytest tests/ -m "integration"    # Integration tests
pytest tests/ -m "security"       # Security tests
pytest tests/ -m "not slow"       # Skip slow tests

# Using Makefile
make test                         # Run all tests
make test-verbose                 # Verbose output
make test-coverage                # With coverage
make test-fast                    # Skip slow tests
```

### Test Markers (from pytest.ini)

```python
@pytest.mark.unit          # Unit tests
@pytest.mark.integration   # Integration tests
@pytest.mark.slow          # Long-running tests
@pytest.mark.security      # Security-related tests
@pytest.mark.network       # Network configuration tests
@pytest.mark.htp           # HTP protocol tests
@pytest.mark.qsecbit       # Qsecbit algorithm tests
```

### Coverage Requirements

- **Minimum**: 30% (configured in `pytest.ini`)
- **Coverage paths**: `core/`, `shared/`
- **Report formats**: HTML + terminal

---

## CI/CD Workflows

### Workflow Overview

Location: `.github/workflows/`

| Workflow | File | Triggers | Purpose |
|----------|------|----------|---------|
| **Python Lint** | `python-lint.yml` | Push/PR to main | Code quality (Black, flake8, bandit) |
| **App Tests** | `app-tests.yml` | Push/PR to main | Django, Nginx, addon validation |
| **Container Tests** | `container-tests.yml` | Push/PR | Container build/run tests |
| **Installation Test** | `installation-test.yml` | Push/PR | Install script validation |
| **ARM64 Tests** | `arm64-tests.yml` | Push/PR | ARM64 architecture tests |
| **Documentation** | `documentation.yml` | Push/PR | Markdown link checking |
| **Config Validation** | `config-validation.yml` | Push/PR | Config file validation |
| **CI Status** | `ci-status.yml` | Manual | Overall CI health check |
| **Repo Cleanup** | `repo-cleanup-validation.yml` | Push/PR | Repository hygiene |

### Debugging CI Failures

**Python Lint Failures**:
```bash
# Run locally before pushing
make lint
# Or individual tools
black core/ shared/ tests/
flake8 core/ shared/ tests/
bandit -r core/ shared/ -ll
```

**Test Failures**:
```bash
# Run full test suite locally
pytest tests/ -vv --tb=long

# Check specific test
pytest tests/test_qsecbit.py -vv
```

**Shell Script Failures**:
```bash
# Validate syntax
make validate

# ShellCheck
shellcheck products/**/*.sh deploy/**/*.sh
```

### CI Branches

Workflows run on:
- `main`, `master`, `develop`
- `claude/**` (Claude-created branches)

---

## Development Tooling

### Makefile Commands

```bash
# Setup
make install          # Install Python dependencies
make install-dev      # Install dev dependencies
make setup            # Complete dev environment

# Testing
make test             # Run all tests
make test-verbose     # Verbose output
make test-coverage    # With coverage report
make test-fast        # Skip slow tests

# Code Quality
make lint             # Run all linters
make format           # Format Python code
make security         # Security scan (bandit)
make check            # Lint + test

# Deployment
make deploy-sentinel  # Deploy Sentinel tier
make deploy-guardian  # Deploy Guardian tier
make deploy-fortress  # Deploy Fortress tier
make deploy-nexus     # Deploy Nexus tier
make deploy-mssp      # Deploy MSSP tier

# Status
make status           # Show deployment status
make logs             # Show recent logs
make health           # Service health check

# Cleanup
make clean            # Remove generated files
make validate         # Validate shell scripts
make version          # Show version info
```

### Pre-commit Hooks

Configuration: `.pre-commit-config.yaml`

**Installed Hooks**:
- `trailing-whitespace` - Remove trailing spaces
- `end-of-file-fixer` - Ensure newline at EOF
- `check-yaml` - YAML syntax validation
- `check-json` - JSON syntax validation
- `detect-private-key` - Prevent key commits
- `shellcheck` - Bash script linting
- `black` - Python formatting
- `isort` - Import sorting
- `flake8` - Python linting
- `bandit` - Security scanning
- `markdownlint` - Markdown linting
- `yamllint` - YAML linting

**Installation**:
```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files  # Run on all files
```

### Python Dependencies

Key packages (from `requirements.txt`):
- `numpy>=1.24.0` - Numerical computing
- `scipy>=1.10.0` - Scientific computing
- `clickhouse-driver>=0.2.6` - ClickHouse for edge
- `pymysql>=1.1.0` - Doris (MySQL protocol)

**XDP/eBPF** (system packages, not pip):
```bash
# Ubuntu/Debian
apt-get install bpfcc-tools python3-bpfcc

# RHEL/Fedora
dnf install bcc python3-bcc
```

---

## Scenario-Based Guidance

### Scenario 1: Adding a New Security Feature

```bash
# 1. Understand existing architecture
cat ARCHITECTURE.md

# 2. Check existing response mechanisms
ls -la shared/response/

# 3. Edit or add response script
nano shared/response/new-mitigation.sh

# 4. Integrate with Qsecbit if needed
nano core/qsecbit/qsecbit.py

# 5. Add tests
nano tests/test_new_feature.py

# 6. Run tests
make test

# 7. Check code quality
make lint
```

### Scenario 2: Modifying Qsecbit Algorithm

```bash
# 1. Read Qsecbit documentation
cat core/qsecbit/README.md

# 2. Understand current algorithm
cat core/qsecbit/qsecbit.py

# 3. Make changes
nano core/qsecbit/qsecbit.py

# 4. Run Qsecbit-specific tests
pytest tests/test_qsecbit.py -vv

# 5. Test with synthetic data
python core/qsecbit/qsecbit.py --test
```

### Scenario 3: Debugging Deployment Issues

```bash
# 1. Check current status
make status

# 2. View logs
make logs

# 3. Check health endpoints
make health

# 4. Validate configuration
./deploy/install/validate-config.sh

# 5. Check container status
podman ps -a

# 6. View specific container logs
podman logs <container-name>
```

### Scenario 4: Adding New Product Tier Feature

```bash
# 1. Find the product directory
ls products/

# 2. Check existing implementation
cat products/guardian/lib/guardian_agent.py

# 3. Add new functionality
nano products/guardian/lib/new_feature.py

# 4. Update setup script
nano products/guardian/scripts/setup.sh

# 5. Run tests
pytest tests/ -m "guardian"
```

### Scenario 5: Working with HTP Protocol

```bash
# 1. Read HTP documentation
cat docs/HTP_SECURITY_ENHANCEMENTS.md
cat docs/HTP_QUANTUM_CRYPTOGRAPHY.md

# 2. Check core implementation
cat core/htp/transport/htp.py

# 3. Understand crypto layer
cat core/htp/crypto/hybrid_kem.py

# 4. Run HTP tests
pytest tests/test_htp_e2e.py -vv
pytest tests/test_htp_keyless.py -vv
```

### Scenario 6: CI/CD Debugging

```bash
# 1. Check which workflow failed
# Look at .github/workflows/<workflow>.yml

# 2. Run equivalent locally
make lint    # For python-lint.yml failures
make test    # For app-tests.yml failures
make validate  # For shell script failures

# 3. Check specific tool output
black --check core/
flake8 core/ shared/
shellcheck products/**/*.sh
```

---

## Key Conventions

### File Naming

| Type | Convention | Example |
|------|------------|---------|
| Python modules | `lowercase_underscore.py` | `qsecbit.py` |
| Shell scripts | `kebab-case.sh` | `install-edge.sh` |
| Config files | `kebab-case.conf` | `hookprobe-config.sh` |
| Documentation | `UPPERCASE.md` | `README.md`, `CLAUDE.md` |

### Code Style

**Python** (PEP 8):
- Black formatting (line length 100)
- isort for imports (profile: black)
- Type hints for function signatures
- Google-style docstrings

**Bash**:
```bash
#!/bin/bash
set -e  # Exit on error
set -u  # Exit on undefined variable

# UPPERCASE for config variables
POSTGRES_PASSWORD="..."

# lowercase for local variables
local container_ip="10.200.1.10"
```

### Git Conventions

**Branch naming**:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation
- `security/` - Security updates
- `claude/` - AI-generated branches

**Commit format**:
```
type(scope): brief description

Detailed explanation

Fixes: #123
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `security`

---

## Security Considerations

### Critical Rules

1. **NEVER hardcode credentials**
2. **NEVER disable security features**
3. **ALWAYS validate input** in Python
4. **AVOID command injection**
5. **CHECK for secrets** before commit

### Sensitive Files

| File | Contains | Safe to Commit |
|------|----------|----------------|
| `deploy/*/config.sh` | Credentials | NO (with real values) |
| `*.py` | Logic only | YES |
| `*.sh` | Logic only | YES |
| `.env` files | Secrets | NO |

### Security Testing

```bash
# Static analysis
shellcheck deploy/**/*.sh

# Python security scan
bandit -r core/ shared/ -ll

# Check for secrets
make security
```

---

## Troubleshooting

### Common Issues

| Issue | Diagnosis | Solution |
|-------|-----------|----------|
| Tests fail | Check pytest output | `pytest tests/ -vv --tb=long` |
| Lint errors | Run formatters | `make format` |
| Import errors | Check dependencies | `pip install -r requirements.txt` |
| CI failure | Run locally first | `make check` |
| Container issues | Check podman | `podman ps -a && podman logs <name>` |

### Getting Help

1. **Check docs**: `docs/` directory
2. **Review tests**: `tests/` directory
3. **Search issues**: GitHub Issues
4. **Contact**: qsecbit@hookprobe.com (security only)

---

## Quick Reference

### Essential Paths

```
core/qsecbit/qsecbit.py          # Main algorithm
core/htp/transport/htp.py        # HTP protocol
products/*/                       # Product implementations
deploy/*/                         # Deployment scripts
tests/                            # All tests
.github/workflows/                # CI/CD
```

### Essential Commands

```bash
make test           # Run tests
make lint           # Check code quality
make format         # Format code
pytest tests/ -vv   # Verbose tests
./install.sh --tier <tier>  # Deploy
```

---

**HookProbe v5.0** - Federated Cybersecurity Mesh
*One node's detection -> Everyone's protection*
