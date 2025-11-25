"""
Management command to seed sample AI content drafts.
"""

from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from apps.admin_dashboard.models import AIContentDraft, ContentResearchTask
from apps.cms.models import BlogCategory


class Command(BaseCommand):
    help = 'Seeds sample AI-generated content drafts for testing'

    def handle(self, *args, **options):
        self.stdout.write('Seeding AI content data...')

        # Get or create admin user
        admin_user = User.objects.filter(is_superuser=True).first()
        if not admin_user:
            self.stdout.write(self.style.WARNING('No admin user found. Creating default admin...'))
            admin_user = User.objects.create_superuser('admin', 'admin@hookprobe.com', 'admin')

        # Create blog categories if they don't exist
        security_cat, _ = BlogCategory.objects.get_or_create(
            slug='security-news',
            defaults={'name': 'Security News', 'description': 'Latest cybersecurity news and updates'}
        )

        threat_cat, _ = BlogCategory.objects.get_or_create(
            slug='threat-intelligence',
            defaults={'name': 'Threat Intelligence', 'description': 'Threat analysis and intelligence reports'}
        )

        tutorial_cat, _ = BlogCategory.objects.get_or_create(
            slug='tutorials',
            defaults={'name': 'Tutorials', 'description': 'Security tutorials and how-to guides'}
        )

        self.stdout.write(self.style.SUCCESS(f'✓ Created {BlogCategory.objects.count()} categories'))

        # Create sample AI content drafts
        self.stdout.write('Creating AI content drafts...')

        drafts_data = [
            {
                'title': 'Understanding Zero-Day Vulnerabilities in Modern Networks',
                'content': '''
# Understanding Zero-Day Vulnerabilities

Zero-day vulnerabilities represent one of the most significant threats in cybersecurity today. These are security flaws that are unknown to the software vendor and have no available patch.

## What Makes Zero-Days Dangerous?

1. **No Known Fix**: By definition, there's no patch available
2. **Active Exploitation**: Attackers can exploit before defenses are ready
3. **Detection Difficulty**: Traditional signature-based systems miss them

## HookProbe's Approach

HookProbe's Qsecbit AI uses behavioral analysis to detect zero-day exploits:
- Pattern recognition for anomalous behavior
- Real-time threat scoring (RAG system)
- Automated response with Kali Linux integration

## Best Practices

- Keep systems updated
- Implement defense-in-depth strategies
- Use AI-powered threat detection
- Monitor for unusual network behavior

Stay safe with HookProbe!
                ''',
                'summary': 'Learn about zero-day vulnerabilities and how HookProbe\'s AI-powered detection helps protect against them.',
                'ai_provider': 'anthropic',
                'ai_model': 'claude-3-sonnet-20240229',
                'ai_confidence_score': 0.92,
                'research_sources': [
                    'https://nvd.nist.gov/',
                    'https://www.cve.org/',
                    'https://www.cisa.gov/known-exploited-vulnerabilities'
                ],
                'seo_title': 'Zero-Day Vulnerabilities Explained | HookProbe Security',
                'seo_description': 'Understanding zero-day vulnerabilities and how AI-powered detection systems like HookProbe protect your network.',
                'seo_keywords': 'zero-day, vulnerability, cybersecurity, AI detection',
                'seo_score': 85,
                'status': 'review',
            },
            {
                'title': 'How to Set Up HookProbe on Raspberry Pi 5',
                'content': '''
# Setting Up HookProbe on Raspberry Pi 5

Transform your Raspberry Pi 5 into a powerful security appliance with HookProbe!

## Hardware Requirements

- Raspberry Pi 5 (8GB RAM recommended)
- 500GB+ SSD
- Gigabit Ethernet connection
- Power supply (27W USB-C)

## Installation Steps

### 1. Download HookProbe

```bash
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe
```

### 2. Run the Installer

```bash
sudo ./install.sh
```

The interactive wizard will guide you through:
- Network interface selection
- IP address configuration
- POD deployment
- Security hardening

### 3. Verify Installation

Access the dashboards:
- Grafana: http://your-pi:3000
- Admin Dashboard: http://your-pi/admin/

## Next Steps

- Configure your first security rules
- Set up email notifications
- Explore the Qsecbit AI dashboard

Happy securing!
                ''',
                'summary': 'Step-by-step guide to installing HookProbe on Raspberry Pi 5.',
                'ai_provider': 'openai',
                'ai_model': 'gpt-4',
                'ai_confidence_score': 0.88,
                'research_sources': [
                    'https://github.com/hookprobe/hookprobe',
                    'https://www.raspberrypi.com/products/raspberry-pi-5/'
                ],
                'seo_title': 'Install HookProbe on Raspberry Pi 5 - Complete Guide',
                'seo_description': 'Learn how to set up HookProbe security platform on your Raspberry Pi 5 in minutes.',
                'seo_keywords': 'hookprobe, raspberry pi, installation, tutorial',
                'seo_score': 78,
                'status': 'draft',
            },
            {
                'title': 'Top 10 CVEs of 2024: What You Need to Know',
                'content': '''
# Top 10 CVEs of 2024

Here are the most critical vulnerabilities discovered in 2024 that every security professional should know about.

## 1. CVE-2024-1234: Apache Struts RCE

A critical remote code execution vulnerability in Apache Struts affecting millions of web applications.

**Impact**: Critical (CVSS 9.8)
**Mitigation**: Update to version 2.5.33+

## 2. CVE-2024-5678: Linux Kernel Privilege Escalation

Local privilege escalation in the Linux kernel affecting all major distributions.

**Impact**: High (CVSS 8.4)
**Mitigation**: Apply kernel patches immediately

[... 8 more CVEs ...]

## How HookProbe Helps

HookProbe's vulnerability scanner automatically checks for known CVEs across your infrastructure:
- Real-time CVE database updates
- Automated scanning
- AI-powered risk assessment
- One-click mitigation playbooks

Stay protected with HookProbe!
                ''',
                'summary': 'Analysis of the top 10 most critical vulnerabilities discovered in 2024.',
                'ai_provider': 'anthropic',
                'ai_model': 'claude-3-sonnet-20240229',
                'ai_confidence_score': 0.95,
                'research_sources': [
                    'https://nvd.nist.gov/',
                    'https://www.cve.org/',
                    'https://www.cisa.gov/known-exploited-vulnerabilities',
                    'https://cve.mitre.org/'
                ],
                'seo_title': 'Top 10 CVEs of 2024 - Critical Vulnerabilities Explained',
                'seo_description': 'Comprehensive analysis of the most critical security vulnerabilities discovered in 2024.',
                'seo_keywords': 'CVE, vulnerability, 2024, security, exploit',
                'seo_score': 92,
                'status': 'approved',
            },
        ]

        for draft_data in drafts_data:
            draft, created = AIContentDraft.objects.get_or_create(
                title=draft_data['title'],
                defaults={
                    **draft_data,
                    'created_by': admin_user
                }
            )
            if created:
                self.stdout.write(f'  ✓ Created draft: {draft.title}')

        # Create sample research tasks
        self.stdout.write('Creating research tasks...')

        research_tasks = [
            {
                'topic': 'Latest DDoS Attack Trends',
                'description': 'Research recent DDoS attack methodologies and mitigation strategies for 2024',
                'keywords': 'DDoS, attack, mitigation, 2024',
                'include_cve': False,
                'include_news': True,
                'include_blogs': True,
                'status': 'pending',
            },
            {
                'topic': 'AI-Powered Threat Detection Systems',
                'description': 'Compare different AI approaches to cybersecurity threat detection',
                'keywords': 'AI, machine learning, threat detection, cybersecurity',
                'include_cve': False,
                'include_news': True,
                'include_blogs': True,
                'status': 'in_progress',
            },
            {
                'topic': 'Critical Infrastructure Security',
                'description': 'Analyze security challenges in critical infrastructure and ICS/SCADA systems',
                'keywords': 'critical infrastructure, ICS, SCADA, security',
                'include_cve': True,
                'include_news': True,
                'include_blogs': False,
                'status': 'completed',
            },
        ]

        for task_data in research_tasks:
            task, created = ContentResearchTask.objects.get_or_create(
                topic=task_data['topic'],
                defaults={
                    **task_data,
                    'created_by': admin_user
                }
            )
            if created:
                self.stdout.write(f'  ✓ Created research task: {task.topic}')

        total_drafts = AIContentDraft.objects.count()
        total_tasks = ContentResearchTask.objects.count()

        self.stdout.write(self.style.SUCCESS(f'✓ Created {total_drafts} AI content drafts'))
        self.stdout.write(self.style.SUCCESS(f'✓ Created {total_tasks} research tasks'))
        self.stdout.write(self.style.SUCCESS('✅ AI content data seeded successfully!'))
        self.stdout.write('')
        self.stdout.write('You can now access the Django admin to manage AI content:')
        self.stdout.write('  http://your-server/admin/admin_dashboard/')
