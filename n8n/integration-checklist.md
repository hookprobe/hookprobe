# HookProbe n8n Integration Checklist

## Pre-Deployment ✓

### System Requirements
- [ ] Main HookProbe (PODs 001-007) deployed and running
- [ ] Root access available
- [ ] Minimum 4GB RAM free for POD 008
- [ ] Port 5678 available (n8n UI)
- [ ] Port 8889 available (MCP API)

### Configuration Review
- [ ] `n8n_network-config.sh` reviewed
- [ ] N8N_BASIC_AUTH_PASSWORD changed
- [ ] N8N_DB_POSTGRESDB_PASSWORD changed
- [ ] OpenAI API key configured (optional)
- [ ] Anthropic API key configured (optional)
- [ ] Django CMS credentials verified

---

## Deployment ✓

### Installation
- [ ] Scripts downloaded to install directory
- [ ] Scripts made executable (`chmod +x`)
- [ ] `n8n_setup.sh` executed successfully
- [ ] All containers started without errors
- [ ] VXLAN tunnel (VNI 108) created

### Verification
```bash
# All checks should pass
podman pod ps | grep "008-automation"        # POD running
podman ps | grep "008-automation"            # 5 containers
ovs-vsctl show | grep "vxlan-108"            # VXLAN exists
curl http://localhost:8889/health            # MCP healthy
```

- [ ] POD 008 shows as "Running"
- [ ] All 5 containers in "Up" state
- [ ] VXLAN tunnel present
- [ ] MCP server responds to health check

---

## Configuration ✓

### n8n Access
- [ ] Accessed n8n UI at http://HOST:5678
- [ ] Logged in with configured credentials
- [ ] Interface loads without errors

### Credentials Setup (in n8n)
- [ ] Django CMS API credential
  - Type: Header Auth
  - Name: `X-API-Key` or `Authorization`
  - Value: Django API token
  
- [ ] Qsecbit API credential
  - Type: Generic
  - URL: http://10.107.0.10:8888
  
- [ ] MCP Server credential
  - Type: Generic
  - URL: http://10.108.0.15:8889

### Workflow Import
- [ ] Imported `daily-blog-post.json`
- [ ] Imported `qsecbit-monitor.json`
- [ ] Credentials assigned to nodes
- [ ] Workflows validated (no red nodes)

---

## Testing ✓

### MCP Server Tests
```bash
# Test each endpoint
curl http://localhost:8889/health
curl -X POST http://localhost:8889/api/content/generate \
  -H "Content-Type: application/json" \
  -d '{"topic":"Test","category":"Tutorials","min_words":800}'

curl -X POST http://localhost:8889/api/qsecbit/status
```

- [ ] Health check passes
- [ ] Content generation works
- [ ] Qsecbit integration works

### Workflow Execution Tests
- [ ] Executed "Daily Blog Post" workflow manually
- [ ] Content generated successfully
- [ ] Post created in Django CMS
- [ ] Qsecbit monitor workflow runs
- [ ] Alerts trigger correctly on RED status

### Web Scraping Test
```bash
# Test Chromium
curl http://10.108.0.13:3000
```

- [ ] Chromium service responds
- [ ] Can scrape test URL
- [ ] Content extracted successfully

---

## Production Readiness ✓

### Security
- [ ] Default passwords changed
- [ ] API keys stored securely
- [ ] Firewall rules applied
- [ ] Network isolation verified
- [ ] Webhook signatures implemented (if used)

### Monitoring
- [ ] n8n execution logs reviewed
- [ ] MCP server logs checked
- [ ] No errors in container logs
- [ ] Workflow success rate acceptable

### Documentation
- [ ] Team trained on n8n usage
- [ ] Workflow documentation created
- [ ] Backup procedures documented
- [ ] Emergency contacts listed

---

## Advanced: Autonomous Blogging System ✓

### Content Calendar Setup
- [ ] Created Monday-Sunday workflow schedule
- [ ] Topic rotation configured
- [ ] Category mapping defined
- [ ] SEO optimization enabled

### AI Integration
- [ ] AI provider selected (OpenAI/Anthropic)
- [ ] API rate limits configured
- [ ] Fallback provider set up
- [ ] Content quality thresholds set

### Publishing Pipeline
- [ ] Draft review process (if needed)
- [ ] Auto-publish or manual approval
- [ ] Social media cross-posting
- [ ] Analytics tracking

### Content Quality Checks
- [ ] Minimum word count: 800
- [ ] Maximum word count: 2500
- [ ] SEO score threshold: 70
- [ ] Readability check enabled
- [ ] Plagiarism detection (if needed)

---

## Maintenance Schedule ✓

### Daily
- [ ] Check workflow execution success rate
- [ ] Review generated content quality
- [ ] Monitor MCP server health
- [ ] Check for failed workflows

### Weekly
- [ ] Review and optimize workflows
- [ ] Update AI prompts if needed
- [ ] Check disk space usage
- [ ] Backup n8n data

### Monthly
- [ ] Update container images
- [ ] Review and tune AI models
- [ ] Analyze content performance
- [ ] Security audit

---

## Troubleshooting Reference ✓

### Common Issues

**Issue**: n8n won't start
```bash
# Check database
podman exec hookprobe-pod-008-automation-postgres pg_isready

# Check logs
podman logs hookprobe-pod-008-automation-n8n

# Restart POD
podman pod restart hookprobe-pod-008-automation
```

**Issue**: MCP server errors
```bash
# Check configuration
podman exec hookprobe-pod-008-automation-mcp env | grep API_KEY

# Test connectivity
curl http://10.101.0.10:8000  # Django
curl http://10.107.0.10:8888  # Qsecbit

# Restart service
podman restart hookprobe-pod-008-automation-mcp
```

**Issue**: Workflows fail
- Check credentials in n8n
- Verify target services are running
- Review execution logs in n8n UI
- Test endpoints manually with curl

**Issue**: Chromium scraping fails
```bash
# Increase memory
podman update --shm-size=2gb hookprobe-pod-008-automation-chromium

# Check logs
podman logs hookprobe-pod-008-automation-chromium
```

---

## Integration Success Criteria ✓

### Technical
- [ ] All containers running stable for 24+ hours
- [ ] No error logs or critical warnings
- [ ] Network connectivity verified between PODs
- [ ] Automated workflows executing on schedule
- [ ] Content generation quality acceptable

### Business
- [ ] Daily blog posts published automatically
- [ ] Security alerts automated
- [ ] Social media presence maintained
- [ ] Content meets brand standards
- [ ] SEO performance improving

### Operational
- [ ] Team can create/edit workflows
- [ ] Monitoring alerts configured
- [ ] Backup/restore procedures tested
- [ ] Documentation complete and accessible
- [ ] Support escalation path defined

---

## Sign-Off

### Deployment Sign-Off
- [ ] System Administrator: ______________ Date: ______
- [ ] Content Manager: ______________ Date: ______
- [ ] Security Officer: ______________ Date: ______

### Production Ready
- [ ] All checklist items completed
- [ ] System stable and monitored
- [ ] Team trained and ready
- [ ] Documentation complete

**Deployment Status**: ☐ In Progress  ☐ Complete  ☐ Production

---

**Version**: 1.0  
**Integration**: HookProbe POD 008  
**Last Updated**: 2025
