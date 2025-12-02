"""
Django management command to seed demo/sample data for HookProbe CMS

This command creates sample blog posts, categories, and pages for
demonstration and testing purposes.

Usage:
    python manage.py seed_demo_data
    python manage.py seed_demo_data --clear  # Clear existing data first
"""

from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.utils import timezone
from apps.cms.models import Page, BlogPost, BlogCategory


class Command(BaseCommand):
    help = 'Seed the database with demo CMS content (blog posts, pages, categories)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing demo data before seeding',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.MIGRATE_HEADING('Seeding HookProbe CMS Demo Data'))
        self.stdout.write('')

        # Clear data if requested
        if options['clear']:
            self.stdout.write(self.style.WARNING('Clearing existing demo data...'))
            BlogPost.objects.all().delete()
            BlogCategory.objects.all().delete()
            Page.objects.filter(slug__startswith='demo-').delete()
            self.stdout.write(self.style.SUCCESS('✓ Existing demo data cleared'))
            self.stdout.write('')

        # Create or get demo user
        demo_user, created = User.objects.get_or_create(
            username='demo_author',
            defaults={
                'email': 'demo@hookprobe.com',
                'first_name': 'Demo',
                'last_name': 'Author',
                'is_staff': False,
                'is_active': True,
            }
        )
        if created:
            demo_user.set_password('changeme123')
            demo_user.save()
            self.stdout.write(self.style.SUCCESS(f'✓ Created demo user: {demo_user.username}'))
        else:
            self.stdout.write(f'ℹ Using existing user: {demo_user.username}')

        self.stdout.write('')

        # Seed categories
        self.stdout.write(self.style.MIGRATE_LABEL('Creating blog categories...'))
        categories_data = [
            {
                'name': 'Security Updates',
                'slug': 'security-updates',
                'description': 'Latest security updates, patches, and vulnerability alerts'
            },
            {
                'name': 'Tutorials',
                'slug': 'tutorials',
                'description': 'Step-by-step guides and how-to articles'
            },
            {
                'name': 'News',
                'slug': 'news',
                'description': 'HookProbe news and announcements'
            },
            {
                'name': 'Network Security',
                'slug': 'network-security',
                'description': 'Network security tips, tools, and best practices'
            },
            {
                'name': 'Threat Intelligence',
                'slug': 'threat-intelligence',
                'description': 'Threat intelligence reports and analysis'
            },
        ]

        categories = {}
        for cat_data in categories_data:
            category, created = BlogCategory.objects.get_or_create(
                slug=cat_data['slug'],
                defaults={
                    'name': cat_data['name'],
                    'description': cat_data['description'],
                }
            )
            categories[cat_data['slug']] = category
            status = '✓ Created' if created else 'ℹ Exists'
            self.stdout.write(f'  {status}: {category.name}')

        self.stdout.write('')

        # Seed blog posts
        self.stdout.write(self.style.MIGRATE_LABEL('Creating blog posts...'))
        posts_data = [
            {
                'title': 'Welcome to HookProbe: Your Mini SOC Solution',
                'slug': 'welcome-to-hookprobe',
                'excerpt': 'Discover how HookProbe democratizes security tools for small businesses, smart homes, and DIY enthusiasts.',
                'content': '''
# Welcome to HookProbe

HookProbe is an open-source security platform designed to bring enterprise-grade security tools to everyone. Whether you're a small business, running a smart home, or a DIY security enthusiast, HookProbe makes it easy to deploy your own Mini SOC (Security Operations Center).

## Key Features

- **7-POD Architecture**: Isolated network segments for enhanced security
- **Comprehensive Monitoring**: Network traffic analysis with Zeek and Snort 3
- **Centralized Dashboard**: Beautiful web interface for managing your security infrastructure
- **AI-Powered Response**: Automated threat detection and mitigation
- **Open Source**: Community-driven development with transparent security

## Getting Started

Check out our [Installation Guide](#) to get started with HookProbe today!

## Community

Join our community on GitHub and contribute to democratizing security tools for everyone.
                ''',
                'is_published': True,
                'is_featured': True,
                'published_at': timezone.now(),
            },
            {
                'title': 'Understanding the 7-POD Architecture',
                'slug': 'understanding-7-pod-architecture',
                'excerpt': 'Learn about HookProbe\'s innovative POD-based architecture for network security.',
                'content': '''
# Understanding the 7-POD Architecture

HookProbe uses a unique 7-POD architecture to provide isolation, scalability, and security.

## The Seven PODs

1. **POD-001: Web DMZ** - Public-facing web interface and management API
2. **POD-002: IAM** - Identity and Access Management with Logto
3. **POD-003: Database** - PostgreSQL for persistent storage
4. **POD-004: Cache** - Redis for high-performance caching
5. **POD-005: Monitoring** - Grafana, VictoriaMetrics, and ClickHouse
6. **POD-006: Security** - Zeek, Snort 3, and Qsecbit integration
7. **POD-007: AI Response** - Kali Linux and automated mitigation

## Benefits

- **Isolation**: Each POD operates in its own network segment
- **Scalability**: Scale individual components independently
- **Security**: Defense in depth with network segmentation
- **Flexibility**: Deploy only the PODs you need

Read more in our [Architecture Documentation](#).
                ''',
                'is_published': True,
                'is_featured': True,
                'published_at': timezone.now(),
            },
            {
                'title': 'Setting Up Network Monitoring with Zeek',
                'slug': 'setting-up-network-monitoring-zeek',
                'excerpt': 'A complete guide to configuring Zeek for comprehensive network traffic analysis.',
                'content': '''
# Setting Up Network Monitoring with Zeek

Zeek (formerly Bro) is a powerful network security monitoring tool integrated into HookProbe's POD-006.

## Installation

HookProbe automatically configures Zeek during the installation process. To verify:

```bash
sudo podman ps | grep zeek
```

## Configuration

Zeek monitors your network interface and generates detailed logs:

- Connection logs
- HTTP traffic
- DNS queries
- SSL/TLS certificates
- File transfers

## Viewing Logs

Access Zeek logs through the HookProbe dashboard at `/security/zeek/logs/`.

## Custom Scripts

You can add custom Zeek scripts to detect specific threats or behaviors.

Learn more in our [Zeek Configuration Guide](#).
                ''',
                'is_published': True,
                'is_featured': False,
                'published_at': timezone.now(),
            },
            {
                'title': 'Integrating HookProbe with Grafana',
                'slug': 'integrating-hookprobe-grafana',
                'excerpt': 'Visualize your security metrics with beautiful Grafana dashboards.',
                'content': '''
# Integrating HookProbe with Grafana

HookProbe includes Grafana in POD-005 for powerful data visualization.

## Default Dashboards

HookProbe ships with pre-configured dashboards:

- Network Traffic Overview
- Security Alerts
- System Health
- POD Status

## Custom Dashboards

Create your own dashboards to monitor specific metrics:

1. Navigate to http://your-ip:3000
2. Log in with your credentials
3. Click "Create Dashboard"
4. Add panels for your metrics

## Data Sources

HookProbe automatically configures:

- VictoriaMetrics for time-series data
- ClickHouse for analytics
- PostgreSQL for application data

Start visualizing your security data today!
                ''',
                'is_published': True,
                'is_featured': False,
                'published_at': timezone.now(),
            },
            {
                'title': 'HookProbe 5.0 Release Notes',
                'slug': 'hookprobe-5-0-release-notes',
                'excerpt': 'Major improvements in version 5.0 including Django CMS, enhanced CI/CD, and better documentation.',
                'content': '''
# HookProbe 5.0 Release Notes

We're excited to announce HookProbe 5.0 with major architectural improvements!

## What's New

### Django CMS Integration
- Beautiful public-facing website
- Blog system for security updates
- Merchandise store
- Contact forms with GDPR compliance

### Enhanced CI/CD
- Comprehensive GitHub Actions workflows
- Multi-architecture container support (x86_64, ARM64)
- Automated testing for all components
- Configuration validation

### Improved Architecture
- Clarified POD-001 role (management API + optional CMS)
- Better database migration handling
- Health check endpoints for monitoring
- Kubernetes-style probes

### Better Documentation
- Comprehensive architecture assessment
- 12-week improvement roadmap
- Deployment guides
- API documentation

## Upgrade Guide

See our [Upgrade Guide](#) for detailed migration instructions.

## Thank You

Thanks to our community for making this release possible!
                ''',
                'is_published': True,
                'is_featured': True,
                'published_at': timezone.now(),
            },
        ]

        for post_data in posts_data:
            blog_post, created = BlogPost.objects.get_or_create(
                slug=post_data['slug'],
                defaults={
                    'title': post_data['title'],
                    'author': demo_user,
                    'excerpt': post_data['excerpt'],
                    'content': post_data['content'],
                    'is_published': post_data['is_published'],
                    'is_featured': post_data['is_featured'],
                    'published_at': post_data['published_at'],
                }
            )
            status = '✓ Created' if created else 'ℹ Exists'
            self.stdout.write(f'  {status}: {blog_post.title}')

        self.stdout.write('')

        # Seed static pages
        self.stdout.write(self.style.MIGRATE_LABEL('Creating static pages...'))
        pages_data = [
            {
                'title': 'Demo: Privacy Policy',
                'slug': 'demo-privacy-policy',
                'content': '''
# Privacy Policy

This is a demo privacy policy page.

## Data Collection
We respect your privacy and handle your data responsibly.

## GDPR Compliance
HookProbe is designed with privacy in mind.

## Contact
For privacy questions, contact us at privacy@hookprobe.com
                ''',
                'meta_description': 'HookProbe Privacy Policy - Demo Page',
                'is_published': True,
                'order': 10,
            },
            {
                'title': 'Demo: Terms of Service',
                'slug': 'demo-terms-of-service',
                'content': '''
# Terms of Service

This is a demo terms of service page.

## Usage Terms
HookProbe is provided as-is for security monitoring purposes.

## Liability
See full terms in the LICENSE file.

## Contact
For legal questions, contact us at legal@hookprobe.com
                ''',
                'meta_description': 'HookProbe Terms of Service - Demo Page',
                'is_published': True,
                'order': 20,
            },
        ]

        for page_data in pages_data:
            page, created = Page.objects.get_or_create(
                slug=page_data['slug'],
                defaults={
                    'title': page_data['title'],
                    'content': page_data['content'],
                    'meta_description': page_data['meta_description'],
                    'is_published': page_data['is_published'],
                    'order': page_data['order'],
                }
            )
            status = '✓ Created' if created else 'ℹ Exists'
            self.stdout.write(f'  {status}: {page.title}')

        self.stdout.write('')
        self.stdout.write(self.style.SUCCESS('━' * 60))
        self.stdout.write(self.style.SUCCESS('Demo data seeding completed successfully!'))
        self.stdout.write(self.style.SUCCESS('━' * 60))
        self.stdout.write('')
        self.stdout.write('Summary:')
        self.stdout.write(f'  Blog Categories: {BlogCategory.objects.count()}')
        self.stdout.write(f'  Blog Posts: {BlogPost.objects.count()}')
        self.stdout.write(f'  Static Pages: {Page.objects.count()}')
        self.stdout.write(f'  Demo User: {demo_user.username}')
        self.stdout.write('')
