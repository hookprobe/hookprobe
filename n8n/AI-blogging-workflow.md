# Advanced Autonomous Blogging Workflow

## Complete Content Generation Pipeline

This workflow creates a fully autonomous blogging system for HookProbe that:
1. Monitors CVE databases and security news
2. Generates AI-powered content
3. Optimizes for SEO
4. Publishes to Django CMS
5. Cross-posts to social media
6. Tracks analytics

---

## Workflow: Complete Autonomous Blog System

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CONTENT SOURCES                          │
├─────────────────────────────────────────────────────────────┤
│  • CVE Database (NVD API)                                   │
│  • Security RSS Feeds (Krebs, Dark Reading, etc.)           │
│  • Qsecbit Threat Intelligence                              │
│  • Competitor Blog Monitoring                               │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ↓
┌─────────────────────────────────────────────────────────────┐
│                 CONTENT AGGREGATION                         │
├─────────────────────────────────────────────────────────────┤
│  • Deduplicate Topics                                       │
│  • Priority Scoring                                         │
│  • Category Assignment                                      │
│  • Schedule Distribution                                    │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ↓
┌─────────────────────────────────────────────────────────────┐
│                AI CONTENT GENERATION                        │
├─────────────────────────────────────────────────────────────┤
│  • Title Generation (engaging + SEO)                        │
│  • Outline Creation (H2/H3 structure)                       │
│  • Content Writing (800-2500 words)                         │
│  • Code Examples (if applicable)                            │
│  • Image Generation (featured image)                        │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ↓
┌─────────────────────────────────────────────────────────────┐
│                 QUALITY CONTROL                             │
├─────────────────────────────────────────────────────────────┤
│  • Plagiarism Check                                         │
│  • SEO Score (min 70)                                       │
│  • Readability Score (Flesch-Kincaid)                       │
│  • Technical Accuracy Verification                          │
│  • Fact Checking                                            │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ↓
┌─────────────────────────────────────────────────────────────┐
│                    PUBLISHING                               │
├─────────────────────────────────────────────────────────────┤
│  • Django CMS (primary)                                     │
│  • LinkedIn (professional)                                  │
│  • X/Twitter (snippets)                                     │
│  • Mastodon (tech community)                                │
│  • GitHub (if code-heavy)                                   │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ↓
┌─────────────────────────────────────────────────────────────┐
│                   ANALYTICS                                 │
├─────────────────────────────────────────────────────────────┤
│  • Track Page Views                                         │
│  • Monitor Engagement                                       │
│  • SEO Rankings                                             │
│  • Social Media Metrics                                     │
│  • Feedback Analysis                                        │
└─────────────────────────────────────────────────────────────┘
```

---

## n8n Workflow: `autonomous-blog-master.json`

### Node Structure

#### 1. Schedule & Content Sources (Parallel)

**Node: Schedule Trigger**
```javascript
{
  "type": "n8n-nodes-base.scheduleTrigger",
  "parameters": {
    "rule": {
      "interval": [{
        "field": "cronExpression",
        "expression": "0 9 * * *"  // Daily at 9 AM
      }]
    }
  }
}
```

**Node: CVE Monitor**
```javascript
{
  "type": "n8n-nodes-base.httpRequest",
  "parameters": {
    "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "method": "GET",
    "qs": {
      "resultsPerPage": "10",
      "pubStartDate": "{{ $today.minus({ days: 7 }).toISO() }}",
      "pubEndDate": "{{ $today.toISO() }}"
    }
  }
}
```

**Node: RSS Feed Aggregator**
```javascript
{
  "type": "n8n-nodes-base.rssFeedRead",
  "parameters": {
    "url": "=https://krebsonsecurity.com/feed/,https://www.darkreading.com/rss.xml"
  }
}
```

**Node: Qsecbit Intelligence**
```javascript
{
  "type": "n8n-nodes-base.httpRequest",
  "parameters": {
    "url": "http://10.200.8.0.15:8889/api/qsecbit/status",
    "method": "GET"
  }
}
```

#### 2. Content Aggregation & Prioritization

**Node: Merge Sources**
```javascript
{
  "type": "n8n-nodes-base.merge",
  "parameters": {
    "mode": "mergeByPosition"
  }
}
```

**Node: Deduplicate**
```javascript
{
  "type": "n8n-nodes-base.function",
  "parameters": {
    "functionCode": `
const seen = new Set();
return items.filter(item => {
  const key = item.json.title?.toLowerCase() || item.json.id;
  if (seen.has(key)) return false;
  seen.add(key);
  return true;
});
`
  }
}
```

**Node: Priority Scoring**
```javascript
{
  "type": "n8n-nodes-base.function",
  "parameters": {
    "functionCode": `
for (const item of items) {
  let score = 0;
  
  // CVE criticality
  if (item.json.cvss_score >= 9.0) score += 50;
  else if (item.json.cvss_score >= 7.0) score += 30;
  
  // Trending keywords
  const trending = ['zero-day', 'ransomware', 'xdp', 'ebpf', 'kubernetes'];
  const text = (item.json.title + ' ' + item.json.description).toLowerCase();
  trending.forEach(kw => {
    if (text.includes(kw)) score += 10;
  });
  
  // Qsecbit relevance
  if (item.json.qsecbit_score > 0.7) score += 20;
  
  item.json.priority_score = score;
}

return items.sort((a, b) => b.json.priority_score - a.json.priority_score);
`
  }
}
```

**Node: Category Assignment**
```javascript
{
  "type": "n8n-nodes-base.function",
  "parameters": {
    "functionCode": `
const dayOfWeek = new Date().getDay();
const categories = {
  1: 'Threat Intelligence',
  2: 'SBC Security',
  3: 'Red vs Blue',
  4: 'DevSecOps',
  5: 'Industry News',
  6: 'Tutorials',
  0: 'Deep Dive'
};

for (const item of items) {
  item.json.category = categories[dayOfWeek];
  
  // Override for urgent items
  if (item.json.priority_score >= 70) {
    item.json.category = 'Breaking News';
  }
}

return items;
`
  }
}
```

#### 3. AI Content Generation

**Node: Generate Title**
```javascript
{
  "type": "n8n-nodes-base.httpRequest",
  "parameters": {
    "url": "http://10.200.8.0.15:8889/api/content/generate",
    "method": "POST",
    "bodyParametersJson": `{
  "topic": "{{ $json.title }}",
  "category": "{{ $json.category }}",
  "tone": "technical",
  "style": "engaging",
  "include_seo": true
}`
  }
}
```

**Node: Create Outline**
```javascript
{
  "type": "n8n-nodes-base.function",
  "parameters": {
    "functionCode": `
// Generate H2/H3 structure based on topic
const topic = items[0].json.topic;
const category = items[0].json.category;

const outline = {
  "h1": topic,
  "sections": []
};

// Standard sections for security content
if (category === 'Threat Intelligence') {
  outline.sections = [
    { "h2": "Overview of the Threat", "h3s": ["What is it?", "Why it matters"] },
    { "h2": "Technical Analysis", "h3s": ["Attack Vector", "Exploitation Method"] },
    { "h2": "Mitigation Strategies", "h3s": ["Immediate Actions", "Long-term Solutions"] },
    { "h2": "Detection & Response", "h3s": ["Using Qsecbit", "IDS/IPS Configuration"] },
    { "h2": "Conclusion" }
  ];
} else if (category === 'SBC Security') {
  outline.sections = [
    { "h2": "Introduction", "h3s": ["Why SBCs for Security", "Current Landscape"] },
    { "h2": "Hardware Requirements", "h3s": ["Recommended SBCs", "Minimum Specs"] },
    { "h2": "Implementation Guide", "h3s": ["Step-by-step Setup", "Configuration"] },
    { "h2": "Security Hardening", "h3s": ["Network Isolation", "Container Security"] },
    { "h2": "Real-world Use Cases" }
  ];
}

items[0].json.outline = outline;
return items;
`
  }
}
```

**Node: Generate Content**
```javascript
{
  "type": "n8n-nodes-base.httpRequest",
  "parameters": {
    "url": "http://10.200.8.0.15:8889/api/content/generate",
    "method": "POST",
    "bodyParametersJson": `{
  "topic": "{{ $json.topic }}",
  "category": "{{ $json.category }}",
  "outline": {{ $json.outline }},
  "min_words": 1200,
  "max_words": 2500,
  "tone": "technical",
  "include_code_examples": true,
  "target_audience": "security professionals"
}`
  }
}
```

**Node: Generate Featured Image**
```javascript
{
  "type": "n8n-nodes-base.httpRequest",
  "parameters": {
    "url": "https://api.openai.com/v1/images/generations",
    "method": "POST",
    "authentication": "headerAuth",
    "bodyParametersJson": `{
  "model": "dall-e-3",
  "prompt": "Professional cybersecurity illustration: {{ $json.topic }}, dark theme, blue/green accents, futuristic, technical",
  "size": "1792x1024",
  "quality": "standard"
}`
  }
}
```

#### 4. Quality Control

**Node: Calculate SEO Score**
```javascript
{
  "type": "n8n-nodes-base.function",
  "parameters": {
    "functionCode": `
function calculateSEO(content, title, meta_description) {
  let score = 0;
  const wordCount = content.split(/\\s+/).length;
  
  // Word count (25 points)
  if (wordCount >= 800 && wordCount <= 2500) score += 25;
  
  // Title length (15 points)
  if (title.length >= 50 && title.length <= 60) score += 15;
  
  // Meta description (15 points)
  if (meta_description.length >= 150 && meta_description.length <= 160) score += 15;
  
  // Keyword density (20 points)
  const keywords = ['security', 'hookprobe', 'ebpf', 'vxlan', 'sbc'];
  let keywordCount = 0;
  keywords.forEach(kw => {
    const regex = new RegExp(kw, 'gi');
    keywordCount += (content.match(regex) || []).length;
  });
  const density = (keywordCount / wordCount) * 100;
  if (density >= 1.5 && density <= 3.0) score += 20;
  
  // Headers (10 points)
  const h2Count = (content.match(/<h2>/gi) || []).length;
  const h3Count = (content.match(/<h3>/gi) || []).length;
  if (h2Count >= 3 && h3Count >= 5) score += 10;
  
  // Internal links (10 points)
  const linkCount = (content.match(/href="\\/blog/gi) || []).length;
  if (linkCount >= 3) score += 10;
  
  // Images (5 points)
  const imgCount = (content.match(/<img/gi) || []).length;
  if (imgCount >= 2) score += 5;
  
  return score;
}

for (const item of items) {
  item.json.seo_score = calculateSEO(
    item.json.content,
    item.json.title,
    item.json.meta_description
  );
}

return items;
`
  }
}
```

**Node: Quality Gate**
```javascript
{
  "type": "n8n-nodes-base.if",
  "parameters": {
    "conditions": {
      "number": [
        {
          "value1": "={{ $json.seo_score }}",
          "operation": "largerEqual",
          "value2": 70
        },
        {
          "value1": "={{ $json.word_count }}",
          "operation": "largerEqual",
          "value2": 800
        }
      ]
    }
  }
}
```

**Node: Manual Review Alert (if quality fails)**
```javascript
{
  "type": "n8n-nodes-base.emailSend",
  "parameters": {
    "toEmail": "content-team@hookprobe.com",
    "subject": "Content Review Required: {{ $json.title }}",
    "text": `SEO Score: {{ $json.seo_score }}/100
Word Count: {{ $json.word_count }}

Please review and approve before publishing.

View draft: http://hookprobe.local/admin/drafts/{{ $json.draft_id }}`
  }
}
```

#### 5. Publishing

**Node: Publish to Django CMS**
```javascript
{
  "type": "n8n-nodes-base.httpRequest",
  "parameters": {
    "url": "http://10.200.8.0.15:8889/api/cms/publish",
    "method": "POST",
    "bodyParametersJson": `{
  "title": "{{ $json.title }}",
  "slug": "{{ $json.slug }}",
  "content": "{{ $json.content }}",
  "category": "{{ $json.category }}",
  "featured_image": "{{ $json.featured_image_url }}",
  "meta_title": "{{ $json.seo_title }}",
  "meta_description": "{{ $json.meta_description }}",
  "tags": {{ $json.tags }},
  "status": "published",
  "publish_date": "{{ $now.toISO() }}"
}`
  }
}
```

**Node: Cross-post to LinkedIn**
```javascript
{
  "type": "n8n-nodes-base.linkedIn",
  "parameters": {
    "operation": "create",
    "text": `📊 New on HookProbe: {{ $json.title }}

{{ $json.meta_description }}

Read more: {{ $json.canonical_url }}

#Cybersecurity #InfoSec #{{ $json.category.replace(' ', '') }}`
  }
}
```

**Node: Tweet Snippet**
```javascript
{
  "type": "n8n-nodes-base.twitter",
  "parameters": {
    "operation": "tweet",
    "text": `🔒 {{ $json.title.substring(0, 200) }}

{{ $json.canonical_url }}

#HookProbe #Cybersecurity`
  }
}
```

#### 6. Analytics & Monitoring

**Node: Log Publication**
```javascript
{
  "type": "n8n-nodes-base.httpRequest",
  "parameters": {
    "url": "http://10.200.8.0.15:8889/api/analytics/log",
    "method": "POST",
    "bodyParametersJson": `{
  "post_id": "{{ $json.post_id }}",
  "published_at": "{{ $now.toISO() }}",
  "category": "{{ $json.category }}",
  "seo_score": {{ $json.seo_score }},
  "word_count": {{ $json.word_count }},
  "sources": {{ $json.sources }},
  "platforms": ["django", "linkedin", "twitter"]
}`
  }
}
```

---

## Configuration in n8n

### 1. Import Workflow

1. Copy the complete workflow structure above
2. In n8n: **Workflows** → **Import from File**
3. Or manually create nodes following structure

### 2. Set Credentials

**Required Credentials**:
- MCP Server (http://10.200.8.0.15:8889)
- Django CMS API
- OpenAI API (for image generation)
- LinkedIn API
- Twitter API

### 3. Configure Schedule

Default: Daily at 9 AM
Modify cron expression for different schedule:
```
0 9 * * *    # Daily 9 AM
0 9 * * 1-5  # Weekdays only
0 6,12,18 * * *  # 3x daily
```

### 4. Activate Workflow

Toggle "Active" switch in top right

---

## Monitoring & Optimization

### Success Metrics

**Track in Grafana**:
- Posts published per day
- Average SEO score
- Publishing success rate
- Social media engagement
- Page views per post

### Weekly Review

1. Review top-performing content
2. Analyze failed quality checks
3. Optimize AI prompts
4. Update topic priorities
5. Refine SEO thresholds

---

## Troubleshooting

### Content Generation Fails

```bash
# Check MCP logs
podman logs hookprobe-pod-008-automation-mcp

# Test API directly
curl -X POST http://localhost:8889/api/content/generate \
  -H "Content-Type: application/json" \
  -d '{"topic":"Test","category":"Tutorials","min_words":800}'
```

### Quality Score Too Low

Adjust thresholds in Quality Gate node:
```javascript
// Lower SEO threshold
"value2": 60  // Instead of 70

// Accept shorter content
"value2": 600  // Instead of 800
```

### Publishing Errors

Check Django CMS:
```bash
# Test CMS API
curl http://10.200.1.12:8000/api/posts/

# Check logs
podman logs hookprobe-pod-001-web-dmz-django
```

---

## Advanced Customization

### Add Custom Content Sources

Create new parallel node for your source:
```javascript
{
  "type": "n8n-nodes-base.httpRequest",
  "parameters": {
    "url": "https://your-custom-source.com/api",
    "method": "GET"
  }
}
```

### Integrate Custom AI Models

Modify MCP server to use local models:
```python
# In mcp_server.py
from transformers import pipeline

llama = pipeline('text-generation', model='meta-llama/Llama-2-13b')

@app.route('/api/content/generate-local', methods=['POST'])
def generate_local():
    # Use local model instead of API
    pass
```

### Add A/B Testing

Split workflow to test different:
- Titles
- Featured images
- Publishing times
- Social media strategies

---

**Version**: 1.0  
**Complexity**: Advanced  
**Maintenance**: Medium  
**ROI**: High
