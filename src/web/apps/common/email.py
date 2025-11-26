"""
Django Email Backend Configuration
HookProbe POD-009 Integration

This module provides email functionality for the Django application,
using the internal mail server (10.200.1.25) which relays through
the DMZ gateway for internet delivery.

Usage:
    from apps.common.email import send_hookprobe_email

    send_hookprobe_email(
        subject="Security Alert",
        message="Vulnerability detected...",
        recipient_list=["admin@hookprobe.com"],
        html_message="<h1>Vulnerability detected...</h1>"
    )
"""

from django.core.mail import send_mail, EmailMultiAlternatives
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import logging

logger = logging.getLogger(__name__)


def send_hookprobe_email(
    subject,
    message,
    recipient_list,
    from_email=None,
    html_message=None,
    fail_silently=False,
    attachments=None,
    headers=None
):
    """
    Send email via HookProbe POD-009 mail system.

    Args:
        subject (str): Email subject
        message (str): Plain text message
        recipient_list (list): List of recipient email addresses
        from_email (str, optional): Sender email. Defaults to DEFAULT_FROM_EMAIL.
        html_message (str, optional): HTML version of message
        fail_silently (bool, optional): If False, raise exceptions. Defaults to False.
        attachments (list, optional): List of attachments as (filename, content, mimetype)
        headers (dict, optional): Additional email headers

    Returns:
        int: Number of successfully sent emails

    Example:
        >>> send_hookprobe_email(
        ...     subject="Test",
        ...     message="Test message",
        ...     recipient_list=["user@example.com"]
        ... )
        1
    """
    from_email = from_email or settings.DEFAULT_FROM_EMAIL

    try:
        if html_message or attachments or headers:
            # Use EmailMultiAlternatives for rich emails
            email = EmailMultiAlternatives(
                subject=subject,
                body=message,
                from_email=from_email,
                to=recipient_list,
                headers=headers or {}
            )

            if html_message:
                email.attach_alternative(html_message, "text/html")

            if attachments:
                for filename, content, mimetype in attachments:
                    email.attach(filename, content, mimetype)

            count = email.send(fail_silently=fail_silently)
        else:
            # Use simple send_mail for plain text
            count = send_mail(
                subject=subject,
                message=message,
                from_email=from_email,
                recipient_list=recipient_list,
                fail_silently=fail_silently
            )

        logger.info(
            f"Email sent: '{subject}' to {len(recipient_list)} recipients"
        )
        return count

    except Exception as e:
        logger.error(f"Failed to send email '{subject}': {str(e)}")
        if not fail_silently:
            raise
        return 0


def send_security_alert(alert_title, alert_details, severity="medium", recipients=None):
    """
    Send security alert email with HookProbe branding.

    Args:
        alert_title (str): Title of the security alert
        alert_details (dict): Dictionary with alert details
        severity (str): Alert severity (critical, high, medium, low)
        recipients (list, optional): List of recipients. Defaults to SECURITY_TEAM_EMAILS.

    Returns:
        int: Number of emails sent
    """
    recipients = recipients or getattr(settings, 'SECURITY_TEAM_EMAILS', [])

    severity_colors = {
        'critical': '#dc2626',
        'high': '#f97316',
        'medium': '#eab308',
        'low': '#3b82f6'
    }

    context = {
        'alert_title': alert_title,
        'alert_details': alert_details,
        'severity': severity,
        'severity_color': severity_colors.get(severity, '#6b7280'),
        'dashboard_url': f"{settings.SITE_URL}/mssp/"
    }

    html_message = render_to_string('emails/security_alert.html', context)
    plain_message = strip_tags(html_message)

    return send_hookprobe_email(
        subject=f"[{severity.upper()}] HookProbe Security Alert: {alert_title}",
        message=plain_message,
        recipient_list=recipients,
        html_message=html_message,
        headers={
            'X-Priority': '1' if severity in ['critical', 'high'] else '3',
            'X-HookProbe-Alert-Type': 'security',
            'X-HookProbe-Severity': severity
        }
    )


def send_vulnerability_report(vulnerability, recipients=None):
    """
    Send vulnerability notification email.

    Args:
        vulnerability: Vulnerability model instance
        recipients (list, optional): List of recipients

    Returns:
        int: Number of emails sent
    """
    from apps.mssp_dashboard.models import Vulnerability

    recipients = recipients or [vulnerability.customer.email]

    context = {
        'vulnerability': vulnerability,
        'dashboard_url': f"{settings.SITE_URL}/mssp/vulnerabilities/{vulnerability.id}/",
        'affected_devices_count': vulnerability.affected_devices.count()
    }

    html_message = render_to_string('emails/vulnerability_report.html', context)
    plain_message = strip_tags(html_message)

    return send_hookprobe_email(
        subject=f"New Vulnerability Detected: {vulnerability.title}",
        message=plain_message,
        recipient_list=recipients,
        html_message=html_message,
        headers={
            'X-HookProbe-Vulnerability-ID': str(vulnerability.id),
            'X-HookProbe-CVE': vulnerability.cve_id or 'N/A',
            'X-HookProbe-Severity': vulnerability.severity
        }
    )


def send_playbook_execution_report(playbook_execution, recipients=None):
    """
    Send SOAR playbook execution report.

    Args:
        playbook_execution: PlaybookExecution model instance
        recipients (list, optional): List of recipients

    Returns:
        int: Number of emails sent
    """
    recipients = recipients or getattr(settings, 'SOC_TEAM_EMAILS', [])

    context = {
        'execution': playbook_execution,
        'playbook': playbook_execution.playbook,
        'dashboard_url': f"{settings.SITE_URL}/mssp/soar/"
    }

    html_message = render_to_string('emails/playbook_execution.html', context)
    plain_message = strip_tags(html_message)

    return send_hookprobe_email(
        subject=f"SOAR Playbook {playbook_execution.status.upper()}: {playbook_execution.playbook.name}",
        message=plain_message,
        recipient_list=recipients,
        html_message=html_message,
        headers={
            'X-HookProbe-Playbook-ID': str(playbook_execution.playbook.id),
            'X-HookProbe-Execution-Status': playbook_execution.status
        }
    )


def send_welcome_email(user):
    """
    Send welcome email to new user.

    Args:
        user: Django User model instance

    Returns:
        int: Number of emails sent
    """
    context = {
        'user': user,
        'login_url': f"{settings.SITE_URL}/mssp/",
        'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@hookprobe.com')
    }

    html_message = render_to_string('emails/welcome.html', context)
    plain_message = strip_tags(html_message)

    return send_hookprobe_email(
        subject="Welcome to HookProbe MSSP",
        message=plain_message,
        recipient_list=[user.email],
        html_message=html_message
    )


def send_password_reset_email(user, reset_url):
    """
    Send password reset email.

    Args:
        user: Django User model instance
        reset_url (str): Password reset URL with token

    Returns:
        int: Number of emails sent
    """
    context = {
        'user': user,
        'reset_url': reset_url,
        'expiry_hours': 24
    }

    html_message = render_to_string('emails/password_reset.html', context)
    plain_message = strip_tags(html_message)

    return send_hookprobe_email(
        subject="HookProbe Password Reset Request",
        message=plain_message,
        recipient_list=[user.email],
        html_message=html_message,
        headers={'X-HookProbe-Email-Type': 'password-reset'}
    )


# Email template context processors
def get_email_footer_context():
    """
    Get common footer context for all emails.

    Returns:
        dict: Footer context with company info
    """
    return {
        'company_name': 'HookProbe',
        'company_address': getattr(settings, 'COMPANY_ADDRESS', ''),
        'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@hookprobe.com'),
        'unsubscribe_url': f"{settings.SITE_URL}/account/unsubscribe/",
        'current_year': __import__('datetime').datetime.now().year
    }
