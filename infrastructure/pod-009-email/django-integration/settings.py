# Django Email Settings for HookProbe POD-009 Integration
# Add these to your Django settings.py (or settings/base.py)

# ============================================
# EMAIL BACKEND CONFIGURATION
# ============================================

# Use SMTP backend (connects to internal mail server)
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'

# Internal mail server (10.200.1.25)
# This server relays through DMZ gateway (10.200.9.10) to internet
EMAIL_HOST = os.getenv('EMAIL_HOST', '10.200.1.25')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', '25'))

# TLS settings
EMAIL_USE_TLS = os.getenv('EMAIL_USE_TLS', 'True').lower() == 'true'
EMAIL_USE_SSL = False  # Don't use SSL on port 25

# Authentication (if required)
# Internal server may not require auth from Django app
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD', '')

# Connection timeout
EMAIL_TIMEOUT = 30  # seconds

# ============================================
# FROM EMAIL ADDRESSES
# ============================================

# Default sender for automated emails
DEFAULT_FROM_EMAIL = os.getenv(
    'DEFAULT_FROM_EMAIL',
    'HookProbe <noreply@hookprobe.com>'
)

# Server error notifications
SERVER_EMAIL = os.getenv(
    'SERVER_EMAIL',
    'server@hookprobe.com'
)

# ============================================
# RECIPIENT LISTS
# ============================================

# Security team emails (for alerts)
SECURITY_TEAM_EMAILS = [
    email.strip()
    for email in os.getenv(
        'SECURITY_TEAM_EMAILS',
        'security@hookprobe.com'
    ).split(',')
]

# SOC team emails (for playbook notifications)
SOC_TEAM_EMAILS = [
    email.strip()
    for email in os.getenv(
        'SOC_TEAM_EMAILS',
        'soc@hookprobe.com'
    ).split(',')
]

# Admin emails (Django ADMINS setting)
ADMINS = [
    ('HookProbe Admin', email.strip())
    for email in os.getenv(
        'ADMIN_EMAILS',
        'admin@hookprobe.com'
    ).split(',')
]

# ============================================
# EMAIL LIMITS
# ============================================

# Maximum emails per request (anti-spam)
EMAIL_MAX_RECIPIENTS = 50

# Rate limiting (if using django-ratelimit)
EMAIL_RATE_LIMIT = '100/h'  # 100 emails per hour per user

# ============================================
# DEVELOPMENT SETTINGS
# ============================================

# In development, log emails to console instead of sending
if DEBUG:
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
    # Or use file backend to save to disk:
    # EMAIL_BACKEND = 'django.core.mail.backends.filebased.EmailBackend'
    # EMAIL_FILE_PATH = BASE_DIR / 'sent_emails'

# ============================================
# EXAMPLE .ENV CONFIGURATION
# ============================================

# Add these to your .env file:
"""
# Email Configuration (POD-009)
EMAIL_HOST=10.200.1.25
EMAIL_PORT=25
EMAIL_USE_TLS=True
EMAIL_HOST_USER=
EMAIL_HOST_PASSWORD=

# Email Addresses
DEFAULT_FROM_EMAIL=HookProbe <noreply@hookprobe.com>
SERVER_EMAIL=server@hookprobe.com
SECURITY_TEAM_EMAILS=security@hookprobe.com,soc@hookprobe.com
SOC_TEAM_EMAILS=soc@hookprobe.com
ADMIN_EMAILS=admin@hookprobe.com

# Company Info
COMPANY_ADDRESS=123 Main St, City, State 12345
SUPPORT_EMAIL=support@hookprobe.com
SITE_URL=https://hookprobe.com
"""

# ============================================
# USAGE EXAMPLES
# ============================================

"""
# Simple email
from apps.common.email import send_hookprobe_email

send_hookprobe_email(
    subject="Test Email",
    message="This is a test email from HookProbe",
    recipient_list=["user@example.com"]
)

# HTML email with attachments
send_hookprobe_email(
    subject="Report Attached",
    message="Plain text version",
    recipient_list=["user@example.com"],
    html_message="<h1>HTML version</h1>",
    attachments=[
        ("report.pdf", pdf_content, "application/pdf")
    ]
)

# Security alert
from apps.common.email import send_security_alert

send_security_alert(
    alert_title="Critical Vulnerability Detected",
    alert_details={
        "cve_id": "CVE-2025-12345",
        "affected_devices": 5,
        "severity": "critical"
    },
    severity="critical"
)

# Vulnerability report
from apps.common.email import send_vulnerability_report

vulnerability = Vulnerability.objects.get(id=123)
send_vulnerability_report(vulnerability)

# SOAR playbook execution report
from apps.common.email import send_playbook_execution_report

execution = PlaybookExecution.objects.get(id=456)
send_playbook_execution_report(execution)

# Welcome email
from apps.common.email import send_welcome_email

user = User.objects.get(username="newuser")
send_welcome_email(user)

# Password reset
from apps.common.email import send_password_reset_email

reset_url = "https://hookprobe.com/reset/token123"
send_password_reset_email(user, reset_url)
"""

# ============================================
# TESTING
# ============================================

"""
# Test email configuration
from django.core.mail import send_mail

send_mail(
    subject="Test Email",
    message="If you receive this, POD-009 is working!",
    from_email="noreply@hookprobe.com",
    recipient_list=["your-email@example.com"],
    fail_silently=False
)

# Or use management command:
python manage.py sendtestemail your-email@example.com

# Check mail queue on internal server:
mailq

# Check Postfix logs on DMZ gateway:
docker logs hookprobe-dmz-mail-gateway

# Monitor DKIM signing:
tail -f /var/log/mail.log | grep DKIM
"""

# ============================================
# TROUBLESHOOTING
# ============================================

"""
Common Issues:

1. Connection Refused
   - Check firewall rules allow Django app → Internal mail server
   - Verify internal mail server is running:
     docker ps | grep internal-mail

2. Authentication Failed
   - Check EMAIL_HOST_USER and EMAIL_HOST_PASSWORD
   - Verify user exists on mail server

3. TLS Errors
   - Try EMAIL_USE_TLS=False for internal connections
   - Check certificate validity

4. Emails Not Sending
   - Check Django logs: tail -f /var/log/django/error.log
   - Check Postfix queue: mailq
   - Check DMZ gateway logs: docker logs hookprobe-dmz-mail-gateway

5. DKIM Failures
   - Verify DNS record: dig default._domainkey.hookprobe.com TXT
   - Check OpenDKIM: journalctl -u opendkim -f

6. SPF Failures
   - Verify DNS record: dig hookprobe.com TXT
   - Ensure DMZ gateway public IP is in SPF record

7. Emails Go to Spam
   - Check DMARC reports for failures
   - Verify PTR record (reverse DNS)
   - Test with mail-tester.com

Monitor POD-009:
- DMZ Gateway: docker logs -f hookprobe-dmz-mail-gateway
- Internal Server: docker logs -f hookprobe-internal-mail
- IDS Alerts: tail -f /var/log/suricata/fast.log
- Firewall Drops: tail -f /var/log/syslog | grep FW
"""
