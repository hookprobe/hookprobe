# HookProbe Documentation Index

<p align="center">
  <strong>The Future of Cybersecurity</strong><br>
  <em>Neural Resonance · Decentralized Mesh · Surgical Precision</em><br><br>
  <strong>Enterprise-Grade AI Security for $150 · Democratizing Cybersecurity for Millions</strong>
</p>

---

**Last Updated:** 2025-12-03
**Version:** 5.0.1 Liberty

This index provides a complete guide to HookProbe v5.0 "Liberty" documentation, organized by use case and audience. HookProbe is the world's first Neurosurgical Cybersecurity Platform — democratizing enterprise-grade security for everyone.

---

## 📖 Documentation Structure

### For Users (Installation & Deployment)

| Document | Purpose | Audience | Location |
|----------|---------|----------|----------|
| **[README.md](README.md)** | Project overview, features, architecture | Everyone | Root |
| **[QUICK-START.md](QUICK-START.md)** | 3-step installation wizard guide | New users | Root |
| **[Installation Guide](docs/installation/INSTALLATION.md)** | Complete installation instructions | All users | docs/installation/ |
| **[Beginner Guide](docs/installation/BEGINNER-GUIDE.md)** | Linux installation from scratch | Linux beginners | docs/installation/ |
| **[Edge Deployment README](install/edge/README.md)** | Edge deployment configuration | Edge deployments | install/edge/ |
| **[Cloud Deployment README](install/cloud/README.md)** | MSSP cloud backend setup | Cloud deployments | install/cloud/ |

### For Developers (Testing & Development)

| Document | Purpose | Audience | Location |
|----------|---------|----------|----------|
| **[SOFTWARE-TESTING-STRATEGY.md](SOFTWARE-TESTING-STRATEGY.md)** | Testing infrastructure for RPi4 | Developers, QA | Root |
| **[TESTING-VALIDATION-REPORT.md](TESTING-VALIDATION-REPORT.md)** | Validation report (Podman, DB versions) | Developers, DevOps | Root |
| **[IAM Integration Guide](docs/IAM-INTEGRATION-GUIDE.md)** | Logto authentication setup | Backend devs | docs/ |
| **[CONTRIBUTING.md](docs/CONTRIBUTING.md)** | Contribution guidelines | Contributors | docs/ |
| **[CI-CD.md](docs/CI-CD.md)** | CI/CD pipeline documentation | DevOps | docs/ |

### For Administrators (Configuration & Management)

| Document | Purpose | Audience | Location |
|----------|---------|----------|----------|
| **[MSSP Production Deployment](docs/deployment/MSSP-PRODUCTION-DEPLOYMENT.md)** | Production deployment guide | Admins | docs/deployment/ |
| **[Security Model](docs/architecture/security-model.md)** | Security architecture | Security teams | docs/architecture/ |
| **[SECURITY.md](docs/SECURITY.md)** | Security policies | Security teams | docs/ |
| **[GDPR.md](docs/GDPR.md)** | GDPR compliance | Legal/Compliance | docs/ |

### For Architects (Architecture & Design)

| Document | Purpose | Audience | Location |
|----------|---------|----------|----------|
| **[DSM Whitepaper](docs/architecture/dsm-whitepaper.md)** | Distributed Security Model | Architects | docs/architecture/ |
| **[DSM Implementation](docs/architecture/dsm-implementation.md)** | DSM technical details | Architects | docs/architecture/ |
| **[Neuro Protocol](docs/architecture/hookprobe-neuro-protocol.md)** | AI-powered threat analysis | AI engineers | docs/architecture/ |

---

## 🚀 Quick Navigation

### I Want To...

#### Install HookProbe
1. **First time with Linux?**
   → Start with [BEGINNER-GUIDE.md](docs/installation/BEGINNER-GUIDE.md)

2. **Already have Linux?**
   → Follow [QUICK-START.md](QUICK-START.md) - 3 steps, 15 minutes

3. **Need detailed instructions?**
   → Read [INSTALLATION.md](docs/installation/INSTALLATION.md)

4. **Deploy on Raspberry Pi 4 (4GB)?**
   → Use Method 3: [install/testing/README.md](install/testing/README.md) - Lightweight deployment

#### Configure HookProbe
1. **Edge deployment?**
   → [install/edge/README.md](install/edge/README.md) - Network, PSK keys, databases

2. **Cloud/MSSP deployment?**
   → [install/cloud/README.md](install/cloud/README.md) - Multi-tenant setup

3. **Setup IAM (Logto)?**
   → [docs/IAM-INTEGRATION-GUIDE.md](docs/IAM-INTEGRATION-GUIDE.md)

4. **Production deployment?**
   → [docs/deployment/MSSP-PRODUCTION-DEPLOYMENT.md](docs/deployment/MSSP-PRODUCTION-DEPLOYMENT.md)

#### Test HookProbe
1. **Set up testing environment?**
   → [SOFTWARE-TESTING-STRATEGY.md](SOFTWARE-TESTING-STRATEGY.md) - Complete testing guide

2. **Run tests (Podman)?**
   ```bash
   ./scripts/run-unit-tests.sh
   ./scripts/run-integration-tests.sh
   ./scripts/run-performance-tests.sh
   ```

3. **Validate infrastructure?**
   → [TESTING-VALIDATION-REPORT.md](TESTING-VALIDATION-REPORT.md) - Validation results

4. **CI/CD setup?**
   → [docs/CI-CD.md](docs/CI-CD.md) + `.github/workflows/arm64-tests.yml`

#### Develop for HookProbe
1. **Contribute code?**
   → [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md)

2. **Understand architecture?**
   → [docs/architecture/dsm-whitepaper.md](docs/architecture/dsm-whitepaper.md)

3. **Work with AI components?**
   → [docs/architecture/hookprobe-neuro-protocol.md](docs/architecture/hookprobe-neuro-protocol.md)

4. **Component documentation?**
   - Web: [src/web/README.md](src/web/README.md)
   - Qsecbit: [src/qsecbit/README.md](src/qsecbit/README.md)
   - Response: [src/response/README.md](src/response/README.md)
   - Neuro: [src/neuro/README.md](src/neuro/README.md)
   - DSM: [src/dsm/README.md](src/dsm/README.md)

---

## 📦 Installation Methods

### Method 1: Interactive Wizard (Recommended)
```bash
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe
sudo ./install.sh
```
**Features:**
- ✅ Interactive prompts
- ✅ Automatic network detection
- ✅ Secure password generation
- ✅ Input validation
- ✅ Production-ready configuration

**Documentation:** [QUICK-START.md](QUICK-START.md)

### Method 2: Manual Configuration (Advanced)
```bash
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe/install/edge
nano config.sh  # Edit configuration
sudo ./setup.sh
```
**Features:**
- ✅ Full control over settings
- ✅ Scriptable deployment
- ✅ CI/CD integration
- ✅ Custom network layouts

**Documentation:** [install/edge/README.md](install/edge/README.md)

### Method 3: Lightweight Testing/Development (Raspberry Pi 4)
```bash
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe
sudo ./install.sh
# Select: 2) Select Deployment Mode
# Choose: 3) Lightweight Testing/Development
```
**Features:**
- ✅ Optimized for 4GB RAM systems
- ✅ Only essential PODs (Web, IAM, Database, Cache)
- ✅ Excludes heavy components (Monitoring, AI)
- ✅ ~2.5GB total memory usage
- ⚠️  **NOT FOR PRODUCTION USE**

**Documentation:** [install/testing/README.md](install/testing/README.md)

### Method 4: Testing Environment (Unit/Integration Tests)
```bash
# Install Podman and dependencies
sudo apt install podman python3-pip
pip3 install podman-compose

# Enable ARM64 emulation (for RPi4 testing on x86_64)
podman run --rm --privileged multiarch/qemu-user-static --reset -p yes

# Run tests
./scripts/run-unit-tests.sh
./scripts/run-integration-tests.sh
```
**Features:**
- ✅ Podman-only (no Docker)
- ✅ ARM64 support (Raspberry Pi 4)
- ✅ CI/CD automated testing
- ✅ Resource-constrained testing (4GB RAM)

**Documentation:** [SOFTWARE-TESTING-STRATEGY.md](SOFTWARE-TESTING-STRATEGY.md)

---

## 🎯 Target Platforms

### Production Deployments

| Platform | RAM | Documentation | Method |
|----------|-----|---------------|--------|
| **x86_64 Edge** (N100, Core, AMD) | 16GB+ | [install/edge/README.md](install/edge/README.md) | Method 1 or 2 |
| **Cloud/MSSP** (Multi-tenant backend) | 64GB+ | [install/cloud/README.md](install/cloud/README.md) | Method 2 |
| **ARM64 Edge** (Jetson, Radxa) | 16GB+ | [install/edge/README.md](install/edge/README.md) | Method 2 |

### Testing/Development

| Platform | RAM | Documentation | Method |
|----------|-----|---------------|--------|
| **Raspberry Pi 4** (ARM64, lightweight) | 4GB | [install/testing/README.md](install/testing/README.md) | Method 3 |
| **Dev Machine** (x86_64 + QEMU) | 8GB+ | [SOFTWARE-TESTING-STRATEGY.md](SOFTWARE-TESTING-STRATEGY.md) | Method 4 |
| **CI/CD Pipeline** (GitHub Actions) | N/A | [.github/workflows/arm64-tests.yml](.github/workflows/arm64-tests.yml) | Method 4 |

---

## 🔧 Configuration Files

### Installation Scripts

| File | Purpose | Used By |
|------|---------|---------|
| `install.sh` | Interactive installation wizard | Method 1 |
| `install/edge/setup.sh` | Edge deployment script | Method 2 |
| `install/cloud/setup.sh` | Cloud deployment script | Method 2 |
| `install/testing/lightweight-setup.sh` | Lightweight testing/development script | Method 3 |
| `install/edge/config.sh` | Edge configuration | Manual editing |
| `install/cloud/config.sh` | Cloud configuration | Manual editing |
| `install/testing/lightweight-config.sh` | Lightweight testing configuration | Method 3 |
| `install/common/unified-config.sh` | Unified config system | All methods |

### Testing Scripts

| File | Purpose | Used By |
|------|---------|---------|
| `scripts/run-unit-tests.sh` | Podman unit tests (ARM64) | Method 3 |
| `scripts/run-integration-tests.sh` | Integration tests (multi-service) | Method 3 |
| `scripts/run-performance-tests.sh` | Performance baselines | Method 3 |
| `docker-compose.test.yml` | Test service stack (Podman) | Method 3 |
| `src/web/Dockerfile.test` | Test container image | Method 3 |

---

## 🧪 Testing Infrastructure

### Overview
HookProbe uses a **Podman-only** testing infrastructure optimized for ARM64 Raspberry Pi 4 deployment.

**Key Characteristics:**
- Container Runtime: **Podman** (no Docker)
- Database: **PostgreSQL 16-alpine** (consistent everywhere)
- Cache: **Redis 7-alpine** (consistent everywhere)
- Python: **3.11, 3.12** (test matrix)
- Platform: **ARM64** (Raspberry Pi 4 target)

### Test Layers
1. **Unit Tests** → Fast, isolated container tests (seconds)
2. **Integration Tests** → Multi-service stack with podman-compose (minutes)
3. **Performance Tests** → Load testing, resource monitoring (minutes)
4. **CI/CD Tests** → Automated ARM64 validation (every commit)

### Running Tests

```bash
# Prerequisites
sudo apt install podman python3-pip
pip3 install podman-compose

# Run all tests
./scripts/run-unit-tests.sh           # Unit tests
./scripts/run-integration-tests.sh    # Integration tests
./scripts/run-performance-tests.sh    # Performance baselines
```

**Full Documentation:** [SOFTWARE-TESTING-STRATEGY.md](SOFTWARE-TESTING-STRATEGY.md)

---

## 📊 Version Consistency

All environments use consistent versions:

| Component | Version | Location |
|-----------|---------|----------|
| PostgreSQL | 16-alpine | All configs, tests, CI/CD |
| Redis | 7-alpine | All configs, tests, CI/CD |
| Python | 3.11, 3.12 | Test matrix, Dockerfile |
| Container Runtime | Podman | Install scripts, tests, CI/CD |

**Validation Report:** [TESTING-VALIDATION-REPORT.md](TESTING-VALIDATION-REPORT.md)

---

## 🔍 Finding Information

### Search by Topic

**Installation:**
- Beginner: `BEGINNER-GUIDE.md`
- Quick: `QUICK-START.md`
- Complete: `docs/installation/INSTALLATION.md`
- Edge: `install/edge/README.md`
- Cloud: `install/cloud/README.md`

**Testing:**
- Strategy: `SOFTWARE-TESTING-STRATEGY.md`
- Validation: `TESTING-VALIDATION-REPORT.md`
- Scripts: `scripts/run-*.sh`
- CI/CD: `.github/workflows/arm64-tests.yml`

**Configuration:**
- Edge: `install/edge/config.sh`
- Cloud: `install/cloud/config.sh`
- Unified: `install/common/unified-config.sh`

**Architecture:**
- Overview: `README.md`
- DSM: `docs/architecture/dsm-whitepaper.md`
- Security: `docs/architecture/security-model.md`
- AI: `docs/architecture/hookprobe-neuro-protocol.md`

### Search by File Type

**Markdown Documentation:**
```bash
find . -name "*.md" -type f | grep -v node_modules
```

**Shell Scripts:**
```bash
find install/ -name "*.sh" -type f
find scripts/ -name "*.sh" -type f
```

**Configuration Files:**
```bash
find install/ -name "config.sh" -o -name "*-config.sh"
```

---

## 🚦 Getting Started Flowchart

```
┌─────────────────────────────────────────┐
│    I Want To Use HookProbe              │
└─────────────────────────────────────────┘
                    │
        ┌───────────┴───────────┐
        │                       │
        ▼                       ▼
┌──────────────┐        ┌──────────────┐
│ Production   │        │ Testing/Dev  │
│ Deployment   │        │ Environment  │
└──────────────┘        └──────────────┘
        │                       │
        │                       │
┌───────┴────────┐      ┌───────┴────────┐
│                │      │                │
▼                ▼      ▼                ▼
First time?  Have Linux? Dev Machine?  Raspberry Pi 4?
    │            │          │              │
    │            │          │              │
    ▼            ▼          ▼              ▼
BEGINNER-    QUICK-START  SOFTWARE-    SOFTWARE-
GUIDE.md     .md          TESTING-     TESTING-
                          STRATEGY.md  STRATEGY.md
                          (x86+QEMU)   (ARM64 native)
```

---

## 📚 Additional Resources

### Official Links
- **GitHub**: https://github.com/hookprobe/hookprobe
- **Issues**: https://github.com/hookprobe/hookprobe/issues
- **Pull Requests**: https://github.com/hookprobe/hookprobe/pulls

### Community
- **Discussions**: GitHub Discussions
- **Security Issues**: See [SECURITY.md](docs/SECURITY.md)
- **Contributing**: See [CONTRIBUTING.md](docs/CONTRIBUTING.md)

### Licenses
- **Project License**: See [LICENSE](LICENSE)
- **3rd Party**: See [3rd-party-licenses.md](3rd-party-licenses.md)

---

## 🔄 Document Maintenance

### Update Frequency
- **Installation docs**: Updated with each release
- **Testing docs**: Updated with infrastructure changes
- **API docs**: Auto-generated from source
- **Architecture docs**: Updated quarterly or on major changes

### Last Major Updates
- 2025-12-02: Added testing infrastructure documentation
- 2025-12-02: Unified Podman-only approach
- 2025-12-02: Validated all database versions (postgres:16-alpine)
- 2025-12-02: Created documentation index

---

## 📝 Documentation Standards

### File Naming
- **README files**: `README.md` (in component directories)
- **Guides**: `UPPERCASE-GUIDE.md` (at root)
- **Specific docs**: `lowercase-with-dashes.md` (in docs/)

### Structure
- Use clear headings (H1 for title, H2 for sections)
- Include table of contents for long documents
- Provide code examples with syntax highlighting
- Include "Last Updated" date for reference docs

### Maintenance
- Update this index when adding new documentation
- Keep installation guides synchronized with scripts
- Validate testing docs match actual test infrastructure
- Review architecture docs when system changes

---

**Questions?** Open an issue or check [CONTRIBUTING.md](docs/CONTRIBUTING.md)
