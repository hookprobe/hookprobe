# Pull Request

## 📋 Description

**Brief summary of changes:**
<!-- Describe what this PR does in 1-2 sentences -->

**Related Issue:**
<!-- Link to related issue with #number, or write "N/A" -->
Fixes #

## 🎯 Type of Change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Security enhancement
- [ ] Infrastructure/CI improvement
- [ ] Refactoring (no functional changes)

## 🔧 Component(s) Affected

- [ ] Deployment scripts (`setup.sh`, `uninstall.sh`, `network-config.sh`)
- [ ] Security features (Qsecbit, WAF, IDS/IPS)
- [ ] Networking (VXLAN, OVS, OpenFlow)
- [ ] Containers/PODs
- [ ] Monitoring (Grafana, VictoriaMetrics)
- [ ] n8n automation (POD 008)
- [ ] LTE/5G connectivity
- [ ] Documentation
- [ ] Testing infrastructure
- [ ] Other: <!-- specify -->

## 🧪 Testing Done

**How was this tested?**

- [ ] Fresh deployment test (`./setup.sh` in clean environment)
- [ ] Uninstall test (`./uninstall.sh` verifies complete cleanup)
- [ ] Service functionality tests
- [ ] Network isolation tests
- [ ] Security regression tests
- [ ] Manual testing only
- [ ] Automated tests added/updated

**Test environment:**
- OS: <!-- e.g., RHEL 10, Fedora 40 -->
- Podman version: <!-- e.g., 4.9.0 -->
- Hardware: <!-- e.g., Intel N100, 16GB RAM -->

**Test results:**
```bash
# Paste relevant test output
```

## ✅ Checklist

**Before submitting this PR:**

- [ ] I have read CONTRIBUTING.md
- [ ] My code follows the project's coding standards
- [ ] I have tested my changes in a clean environment
- [ ] I have updated documentation (README.md, CLAUDE.md, etc.)
- [ ] I have checked for exposed secrets/credentials
- [ ] My commit messages follow the conventional commits format
- [ ] I have run shellcheck on bash scripts (if applicable)
- [ ] I have run linting on Python code (if applicable)
- [ ] All deployment scripts still work after my changes
- [ ] I have verified network ranges are correct (10.200.x.x)

**Security considerations:**

- [ ] No hardcoded credentials added
- [ ] No security features disabled
- [ ] User input is validated (if applicable)
- [ ] No command injection vulnerabilities introduced
- [ ] Changes reviewed for OWASP Top 10 vulnerabilities

## 📸 Screenshots/Logs

<!-- If applicable, add screenshots or relevant logs -->

**Before:**
```
# Show state before changes (if applicable)
```

**After:**
```
# Show state after changes
```

## 🔄 Breaking Changes

**Does this PR introduce breaking changes?**

- [ ] No
- [ ] Yes (explain below)

<!-- If yes, describe:
- What breaks
- How to migrate
- Why it's necessary
-->

## 📚 Documentation Updates

**Documentation changes made:**

- [ ] README.md updated
- [ ] CLAUDE.md updated (for AI-relevant changes)
- [ ] CHANGELOG.md updated
- [ ] Component-specific README updated
- [ ] Inline code comments added
- [ ] No documentation changes needed

## 💬 Additional Notes

<!-- Any additional information, context, or screenshots -->

## 📝 Reviewer Notes

**Specific areas to review:**
<!-- Highlight areas where you want extra attention -->

---

**By submitting this PR, I confirm:**
- This code is my own work or properly attributed
- I agree to license contributions under the MIT License
- I have followed the security disclosure policy for any security-related changes
