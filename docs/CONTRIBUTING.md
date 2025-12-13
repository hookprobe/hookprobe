# Contributing to HookProbe

> **"One node's detection → Everyone's protection"**

## 🤝 Welcome to the Family

Thank you for your interest in contributing to HookProbe! You're not just contributing to a project – **you're joining a family of protectors** building the future of collective defense.

**Our Philosophy:**
- 🛡️ **Protection is a right, not a privilege** - We make enterprise security accessible to everyone
- 🔍 **Transparency builds trust** - Every decision is explainable, every line of code is auditable
- 🤝 **Collective defense works** - One detection protects all
- 🧠 **AI serves humans** - Help people focus on what they love

**What "Family" Means:**
- We share knowledge freely (no paywalls on protection)
- We help each other (stuck? ask. know something? teach)
- We build together (your contribution makes everyone stronger)
- We protect each other (one node's detection → everyone's protection)

**Read our [Manifesto](../MANIFESTO.md)** to understand the full vision.

---

## 🎯 Ways to Contribute

We appreciate all forms of contribution:

- 🐛 **Bug Reports**: Help us identify and fix issues
- ✨ **Feature Requests**: Suggest new capabilities
- 📝 **Documentation**: Improve guides and examples
- 💻 **Code**: Submit bug fixes or new features
- 🧪 **Testing**: Test releases and report results
- 🔒 **Security**: Responsibly disclose vulnerabilities
- 💬 **Community**: Help others in discussions

---

## 🚀 Getting Started

### Prerequisites

1. **Familiarity with**:
   - Linux system administration
   - Container technologies (Podman/Docker)
   - Python and Bash scripting
   - Networking concepts (VLANs, VXLAN, OVS)

2. **Development Environment**:
   - Ubuntu 22.04+, Debian 11+/12+, or Raspberry Pi OS (Bookworm)
   - 16GB RAM minimum
   - Git installed
   - Text editor (vim, nano, VS Code, etc.)

   > **Note**: RHEL-based systems are not supported due to OpenVSwitch availability limitations. Support planned for future release.

3. **Accounts**:
   - GitHub account
   - (Optional) GPG key for signed commits

### Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/hookprobe-v5.git
cd hookprobe-v5

# Add upstream remote
git remote add upstream https://github.com/hookprobe/hookprobe-v5.git

# Verify remotes
git remote -v
```

---

## 🔧 Development Workflow

### 1. Create a Branch

```bash
# Update main
git checkout main
git pull upstream main

# Create feature branch
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b fix/issue-123
```

**Branch Naming Convention**:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `refactor/` - Code refactoring
- `test/` - Test improvements
- `security/` - Security enhancements

### 2. Make Changes

**Before you start**:
- Check existing issues to avoid duplicate work
- Open an issue to discuss large changes
- Follow coding standards (see below)

**Testing your changes**:
```bash
# Test deployment
sudo ./setup.sh

# Verify services
podman pod ps
podman ps -a

# Test functionality
curl http://localhost/admin
curl http://localhost:8888/health

# Clean up
sudo ./uninstall.sh
```

### 3. Commit Changes

**Commit Message Format**:
```
type(scope): brief description

Detailed explanation of the change.

Fixes: #123
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Code style (formatting)
- `refactor`: Code restructuring
- `test`: Tests
- `chore`: Maintenance

**Examples**:
```bash
git commit -m "feat(security): add XDP rate limiting for DNS queries"
git commit -m "fix(setup): correct PostgreSQL connection string"
git commit -m "docs(readme): add troubleshooting section for WAF issues"
```

**Sign your commits** (recommended):
```bash
git commit -S -m "your message"
```

### 4. Push and Create Pull Request

```bash
# Push to your fork
git push origin feature/your-feature-name
```

Then on GitHub:
1. Navigate to your fork
2. Click "Pull Request"
3. Select your branch
4. Fill out the PR template
5. Submit for review

---

## 📝 Coding Standards

### Bash Scripts

```bash
#!/bin/bash
#
# Script description
# Version: 1.0
#

set -e  # Exit on error
set -u  # Exit on undefined variable

# Use descriptive variable names
CONTAINER_NAME="hookprobe-web-dmz"
POD_NAME="hookprobe-web"

# Add comments for complex logic
# This function creates a Podman network
create_network() {
    local net_name=$1
    local subnet=$2
    
    podman network create \
        --driver bridge \
        --subnet="$subnet" \
        "$net_name"
}

# Use functions for reusable code
# Echo status messages
echo "✓ Network created successfully"
```

### Python Scripts

```python
#!/usr/bin/env python3
"""
Module docstring describing purpose.

Author: Your Name
License: MIT
"""

import os
from typing import Optional, Dict

# Constants in UPPER_CASE
DEFAULT_TIMEOUT = 30
API_ENDPOINT = "http://localhost:8888"


class QsecbitAnalyzer:
    """Class for threat analysis."""
    
    def __init__(self, config: Dict):
        """Initialize analyzer with configuration."""
        self.config = config
    
    def analyze(self, data: Dict) -> Optional[float]:
        """
        Analyze threat data and return score.
        
        Args:
            data: Telemetry data dictionary
            
        Returns:
            Threat score between 0.0 and 1.0, or None if error
        """
        try:
            # Implementation
            pass
        except Exception as e:
            print(f"Error analyzing data: {e}")
            return None
```

### Documentation

- Use **clear, concise** language
- Include **code examples** where helpful
- Keep **line length** under 100 characters
- Use **Markdown** formatting properly
- Add **table of contents** for long documents

---

## 🧪 Testing Guidelines

### Manual Testing

Before submitting a PR, test:

1. **Fresh Install**:
   ```bash
   sudo ./setup.sh
   # Verify all services start
   # Check logs for errors
   ```

2. **Configuration Changes**:
   ```bash
   # Modify network-config.sh
   sudo ./setup.sh
   # Verify changes applied
   ```

3. **Functionality**:
   - Test affected features
   - Check related components
   - Verify no regressions

4. **Clean Uninstall**:
   ```bash
   sudo ./uninstall.sh
   # Verify complete removal
   ```

### Security Testing

For security-related changes:

1. **Static Analysis**:
   ```bash
   # Bash
   shellcheck *.sh
   
   # Python
   bandit -r .
   pylint *.py
   ```

2. **Container Scanning**:
   ```bash
   trivy image hookprobe-django:v5
   ```

3. **Network Testing**:
   ```bash
   nmap -sV localhost
   ```

### Documentation Testing

- Check all links work
- Verify code examples execute
- Test on fresh environment
- Proofread for typos/grammar

---

## 🔒 Security Contributions

### Reporting Vulnerabilities

**DO NOT** create public issues for security vulnerabilities.

Instead:
1. Email: qsecbit@hookprobe.com
2. Include detailed report (see SECURITY.md)
3. Allow time for fix before disclosure

See [SECURITY.md](SECURITY.md) for full policy.

### Security Enhancements

We welcome security improvements:
- New security features
- Hardening recommendations
- Penetration testing results
- Vulnerability fixes

**Process**:
1. Open issue describing enhancement
2. Discuss approach with maintainers
3. Submit PR with implementation
4. Include testing evidence

---

## 📚 Documentation Contributions

### Types of Documentation

1. **User Documentation**:
   - Installation guides
   - Configuration examples
   - Troubleshooting tips
   - Use case tutorials

2. **Developer Documentation**:
   - Architecture overviews
   - API references
   - Contribution guides
   - Code comments

3. **Operations Documentation**:
   - Deployment patterns
   - Monitoring setup
   - Backup procedures
   - Disaster recovery

### Documentation Standards

- Use **clear headings** and structure
- Include **code examples** that work
- Add **screenshots** for UI features
- Keep **up-to-date** with code changes
- Use **inclusive language**

---

## 🎨 UI/UX Contributions

For Grafana dashboards or web interfaces:

1. **Design Principles**:
   - Clean and intuitive
   - Accessible (WCAG 2.1)
   - Responsive design
   - Consistent styling

2. **Dashboard Guidelines**:
   - Clear metric labels
   - Appropriate visualizations
   - Useful time ranges
   - Helpful descriptions

3. **Submission**:
   - Export JSON
   - Include screenshots
   - Document variables
   - Test on Grafana 11.4+

---

## 🐛 Bug Reports

### Before Reporting

1. **Search existing issues** - May already be reported
2. **Test on latest version** - Bug may be fixed
3. **Reproduce consistently** - Provide steps
4. **Gather logs** - Include relevant output

### Bug Report Template

```markdown
**Describe the bug**
Clear description of what's wrong.

**To Reproduce**
Steps to reproduce:
1. Run './setup.sh'
2. Access 'http://localhost/admin'
3. Click on '...'
4. See error

**Expected behavior**
What should happen.

**Actual behavior**
What actually happens.

**Environment**
- OS: Ubuntu 22.04
- HookProbe Version: 5.0.0
- Podman Version: 4.9.0

**Logs**
```bash
podman logs hookprobe-web-dmz-django
```
[Paste relevant logs]

**Screenshots**
If applicable, add screenshots.

**Additional context**
Any other information.
```

---

## ✨ Feature Requests

### Before Requesting

1. **Check roadmap** - May be planned
2. **Search issues** - May be requested
3. **Consider scope** - Fits project goals?
4. **Think implementation** - Feasible approach?

### Feature Request Template

```markdown
**Feature Description**
Clear description of the feature.

**Use Case**
Why is this needed? Who benefits?

**Proposed Implementation**
How could this work?

**Alternatives Considered**
Other approaches you've thought about.

**Additional Context**
Screenshots, mockups, examples, etc.
```

---

## 🏅 Recognition

Contributors are recognized in:

1. **CHANGELOG.md** - All contributors mentioned in release notes
2. **Git History** - Permanent record of all contributions
3. **Social Media** - Highlighted (with permission)
4. **GitHub Contributors** - Automatically tracked by GitHub

---

## 📜 Code of Conduct

### Our Pledge

We pledge to make participation in HookProbe a harassment-free experience for everyone, regardless of:
- Age, body size, disability
- Ethnicity, gender identity
- Experience level
- Nationality, personal appearance
- Race, religion
- Sexual identity and orientation

### Our Standards

**Positive behavior**:
- ✅ Using welcoming language
- ✅ Respecting differing viewpoints
- ✅ Accepting constructive criticism
- ✅ Focusing on community benefit
- ✅ Showing empathy

**Unacceptable behavior**:
- ❌ Harassment or discriminatory language
- ❌ Trolling or insulting comments
- ❌ Personal or political attacks
- ❌ Publishing private information
- ❌ Unprofessional conduct

### Enforcement

Violations can be reported to: qsecbit@hookprobe.com

Maintainers may:
- Remove inappropriate content
- Temporarily or permanently ban violators
- Take other appropriate action

---

## 📞 Getting Help

**Questions?**
- Open a [Discussion](https://github.com/hookprobe/hookprobe-v5/discussions)
- Join our community chat (link TBD)
- Email: qsecbit@hookprobe.com

**Stuck?**
- Check [README.md](README.md) first
- Search existing issues
- Ask in discussions

---

## 🎓 Learning Resources

### Recommended Reading

**Networking**:
- [Open vSwitch Documentation](https://docs.openvswitch.org/)
- [VXLAN RFC 7348](https://tools.ietf.org/html/rfc7348)

**Security**:
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [ModSecurity Handbook](https://www.feistyduck.com/books/modsecurity-handbook/)

**Containers**:
- [Podman Documentation](https://docs.podman.io/)
- [Container Security Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)

**Observability**:
- [VictoriaMetrics Docs](https://docs.victoriametrics.com/)
- [Grafana Tutorials](https://grafana.com/tutorials/)

---

## ⚖️ License

HookProbe uses a **dual licensing model**:

- **AGPL v3.0**: Open source components (deployment, Guardian, response, mesh, docs)
- **Proprietary**: Core AI/ML innovations (Qsecbit, Neural Resonance, dnsXai ML, DSM, MSSP)

By contributing to HookProbe, you agree that:

1. **AGPL Components**: Your contributions to AGPL-licensed directories will be licensed under AGPL v3.0
2. **Proprietary Components**: Contributions to proprietary directories require signing a Contributor License Agreement (CLA)
3. **Documentation**: All documentation contributions are licensed under AGPL v3.0

For full licensing details, see [LICENSING.md](../LICENSING.md).

**CLA Contact**: qsecbit@hookprobe.com

---

## 🙏 Thank You!

Every contribution, no matter how small, makes HookProbe better. We appreciate your time and effort!

---

**Questions?** Open a discussion or email qsecbit@hookprobe.com

**Ready to contribute?** Fork the repo and submit your first PR!

---

*HookProbe - Built by the community, for the community*
