"""
IDS Event Parsers for Suricata EVE JSON and Zeek Logs

These parsers convert raw IDS output into normalized SecurityEvent objects.
"""

import json
import uuid
import logging
from datetime import datetime
from typing import Optional
from dataclasses import dataclass

from django.utils import timezone

logger = logging.getLogger(__name__)


@dataclass
class ParsedEvent:
    """Normalized event from any IDS source"""
    event_id: str
    source_type: str
    severity: str
    attack_type: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    description: str
    raw_data: dict
    timestamp: datetime

    # Classification hints for hybrid classifier
    signature_id: Optional[str] = None
    signature_name: Optional[str] = None
    classification: Optional[str] = None
    priority: Optional[int] = None


class SuricataParser:
    """
    Parse Suricata EVE JSON format.

    EVE JSON types handled:
    - alert: IDS alerts with signature matches
    - flow: Network flow summaries
    - http: HTTP transaction details
    - dns: DNS query/response
    - tls: TLS handshake info
    """

    # Suricata priority to severity mapping
    PRIORITY_TO_SEVERITY = {
        1: 'critical',  # High priority
        2: 'high',
        3: 'medium',
        4: 'low',
    }

    # Classification to severity (fallback)
    CLASSIFICATION_TO_SEVERITY = {
        'attempted-admin': 'critical',
        'attempted-user': 'high',
        'shellcode-detect': 'critical',
        'successful-admin': 'critical',
        'successful-user': 'high',
        'trojan-activity': 'critical',
        'unsuccessful-user': 'medium',
        'web-application-attack': 'high',
        'attempted-dos': 'high',
        'attempted-recon': 'medium',
        'bad-unknown': 'medium',
        'default-login-attempt': 'medium',
        'denial-of-service': 'critical',
        'misc-attack': 'medium',
        'network-scan': 'low',
        'not-suspicious': 'info',
        'protocol-command-decode': 'low',
        'string-detect': 'info',
        'suspicious-filename-detect': 'medium',
        'suspicious-login': 'medium',
        'system-call-detect': 'medium',
        'unusual-client-port-connection': 'low',
        'web-application-activity': 'info',
    }

    def parse(self, eve_json: dict) -> Optional[ParsedEvent]:
        """Parse a single Suricata EVE JSON event"""
        event_type = eve_json.get('event_type')

        if event_type == 'alert':
            return self._parse_alert(eve_json)
        elif event_type == 'flow':
            return self._parse_flow(eve_json)
        elif event_type == 'http':
            return self._parse_http(eve_json)
        elif event_type == 'dns':
            return self._parse_dns(eve_json)
        elif event_type == 'anomaly':
            return self._parse_anomaly(eve_json)
        else:
            # Log unhandled event types at debug level
            logger.debug(f"Unhandled Suricata event type: {event_type}")
            return None

    def _parse_alert(self, eve: dict) -> ParsedEvent:
        """Parse Suricata alert event"""
        alert = eve.get('alert', {})

        # Extract signature info
        signature_id = str(alert.get('signature_id', ''))
        signature_name = alert.get('signature', 'Unknown Alert')
        classification = alert.get('category', '')
        priority = alert.get('severity', 3)

        # Determine severity
        severity = self.PRIORITY_TO_SEVERITY.get(priority, 'medium')
        if classification and classification.lower() in self.CLASSIFICATION_TO_SEVERITY:
            severity = self.CLASSIFICATION_TO_SEVERITY[classification.lower()]

        # Build description
        description = f"[SID:{signature_id}] {signature_name}"
        if classification:
            description += f" ({classification})"

        return ParsedEvent(
            event_id=f"suricata-{eve.get('flow_id', uuid.uuid4().hex)}",
            source_type='suricata',
            severity=severity,
            attack_type=classification or 'unknown',
            src_ip=eve.get('src_ip', '0.0.0.0'),
            dst_ip=eve.get('dest_ip', '0.0.0.0'),
            src_port=eve.get('src_port'),
            dst_port=eve.get('dest_port'),
            protocol=eve.get('proto', 'unknown').lower(),
            description=description,
            raw_data=eve,
            timestamp=self._parse_timestamp(eve.get('timestamp')),
            signature_id=signature_id,
            signature_name=signature_name,
            classification=classification,
            priority=priority,
        )

    def _parse_flow(self, eve: dict) -> ParsedEvent:
        """Parse Suricata flow event (for anomaly detection)"""
        flow = eve.get('flow', {})

        # Check for suspicious flow patterns
        bytes_toserver = flow.get('bytes_toserver', 0)
        bytes_toclient = flow.get('bytes_toclient', 0)
        pkts_toserver = flow.get('pkts_toserver', 0)

        # Simple heuristic: large data exfil pattern
        severity = 'info'
        attack_type = 'flow-summary'
        if bytes_toclient > 10_000_000 and pkts_toserver < 100:
            severity = 'medium'
            attack_type = 'possible-data-exfil'

        return ParsedEvent(
            event_id=f"suricata-flow-{eve.get('flow_id', uuid.uuid4().hex)}",
            source_type='suricata',
            severity=severity,
            attack_type=attack_type,
            src_ip=eve.get('src_ip', '0.0.0.0'),
            dst_ip=eve.get('dest_ip', '0.0.0.0'),
            src_port=eve.get('src_port'),
            dst_port=eve.get('dest_port'),
            protocol=eve.get('proto', 'unknown').lower(),
            description=f"Flow: {bytes_toserver}B out, {bytes_toclient}B in",
            raw_data=eve,
            timestamp=self._parse_timestamp(eve.get('timestamp')),
        )

    def _parse_http(self, eve: dict) -> ParsedEvent:
        """Parse Suricata HTTP event for web attack patterns"""
        http = eve.get('http', {})

        hostname = http.get('hostname', '')
        url = http.get('url', '')
        method = http.get('http_method', 'GET')
        status = http.get('status', 0)
        user_agent = http.get('http_user_agent', '')

        # Simple web attack pattern detection
        severity = 'info'
        attack_type = 'http-request'

        # Check for suspicious patterns
        suspicious_patterns = [
            ('../', 'path-traversal'),
            ('..\\', 'path-traversal'),
            ('<script', 'xss-attempt'),
            ('UNION SELECT', 'sql-injection'),
            ("' OR '", 'sql-injection'),
            ('cmd=', 'command-injection'),
            ('exec(', 'code-injection'),
            ('/etc/passwd', 'lfi-attempt'),
            ('wp-admin', 'wordpress-probe'),
            ('phpmyadmin', 'phpmyadmin-probe'),
        ]

        url_lower = url.lower()
        for pattern, attack in suspicious_patterns:
            if pattern.lower() in url_lower:
                severity = 'high'
                attack_type = attack
                break

        return ParsedEvent(
            event_id=f"suricata-http-{eve.get('flow_id', uuid.uuid4().hex)}",
            source_type='suricata',
            severity=severity,
            attack_type=attack_type,
            src_ip=eve.get('src_ip', '0.0.0.0'),
            dst_ip=eve.get('dest_ip', '0.0.0.0'),
            src_port=eve.get('src_port'),
            dst_port=eve.get('dest_port'),
            protocol='http',
            description=f"{method} {hostname}{url[:100]}",
            raw_data=eve,
            timestamp=self._parse_timestamp(eve.get('timestamp')),
        )

    def _parse_dns(self, eve: dict) -> ParsedEvent:
        """Parse Suricata DNS event"""
        dns = eve.get('dns', {})

        query = dns.get('rrname', '')
        query_type = dns.get('rrtype', '')

        # Check for suspicious DNS patterns
        severity = 'info'
        attack_type = 'dns-query'

        # Suspicious TLDs and patterns
        suspicious_tlds = ['.ru', '.cn', '.tk', '.xyz', '.top', '.work']
        if any(query.endswith(tld) for tld in suspicious_tlds):
            severity = 'low'
            attack_type = 'suspicious-dns'

        # Very long subdomains (possible tunneling)
        if len(query) > 100:
            severity = 'medium'
            attack_type = 'dns-tunnel-suspect'

        return ParsedEvent(
            event_id=f"suricata-dns-{eve.get('flow_id', uuid.uuid4().hex)}",
            source_type='suricata',
            severity=severity,
            attack_type=attack_type,
            src_ip=eve.get('src_ip', '0.0.0.0'),
            dst_ip=eve.get('dest_ip', '0.0.0.0'),
            src_port=eve.get('src_port'),
            dst_port=eve.get('dest_port'),
            protocol='dns',
            description=f"DNS {query_type}: {query}",
            raw_data=eve,
            timestamp=self._parse_timestamp(eve.get('timestamp')),
        )

    def _parse_anomaly(self, eve: dict) -> ParsedEvent:
        """Parse Suricata anomaly event"""
        anomaly = eve.get('anomaly', {})

        return ParsedEvent(
            event_id=f"suricata-anomaly-{eve.get('flow_id', uuid.uuid4().hex)}",
            source_type='suricata',
            severity='medium',
            attack_type='protocol-anomaly',
            src_ip=eve.get('src_ip', '0.0.0.0'),
            dst_ip=eve.get('dest_ip', '0.0.0.0'),
            src_port=eve.get('src_port'),
            dst_port=eve.get('dest_port'),
            protocol=eve.get('proto', 'unknown').lower(),
            description=f"Anomaly: {anomaly.get('type', 'unknown')}",
            raw_data=eve,
            timestamp=self._parse_timestamp(eve.get('timestamp')),
        )

    def _parse_timestamp(self, ts_str: str) -> datetime:
        """Parse Suricata timestamp format"""
        if not ts_str:
            return timezone.now()
        try:
            # Suricata format: 2024-01-15T10:30:45.123456+0000
            return datetime.fromisoformat(ts_str.replace('+0000', '+00:00'))
        except (ValueError, TypeError):
            return timezone.now()


class ZeekParser:
    """
    Parse Zeek JSON logs.

    Log types handled:
    - conn.log: Connection summaries
    - http.log: HTTP requests
    - dns.log: DNS queries
    - ssl.log: SSL/TLS connections
    - notice.log: Zeek notices (alerts)
    - weird.log: Protocol anomalies
    """

    # Zeek notice types to severity
    NOTICE_TO_SEVERITY = {
        'SSL::Invalid_Server_Cert': 'medium',
        'HTTP::SQL_Injection_Attacker': 'critical',
        'HTTP::SQL_Injection_Victim': 'critical',
        'Scan::Port_Scan': 'medium',
        'Scan::Address_Scan': 'medium',
        'SSH::Password_Guessing': 'high',
        'SSH::Bruteforcing': 'critical',
        'Intel::Notice': 'high',
    }

    def parse(self, zeek_json: dict, log_type: str = 'conn') -> Optional[ParsedEvent]:
        """Parse a single Zeek JSON log entry"""
        if log_type == 'conn':
            return self._parse_conn(zeek_json)
        elif log_type == 'http':
            return self._parse_http(zeek_json)
        elif log_type == 'dns':
            return self._parse_dns(zeek_json)
        elif log_type == 'ssl':
            return self._parse_ssl(zeek_json)
        elif log_type == 'notice':
            return self._parse_notice(zeek_json)
        elif log_type == 'weird':
            return self._parse_weird(zeek_json)
        else:
            logger.debug(f"Unhandled Zeek log type: {log_type}")
            return None

    def _parse_conn(self, log: dict) -> ParsedEvent:
        """Parse Zeek conn.log entry"""
        # Connection state analysis
        conn_state = log.get('conn_state', '')
        service = log.get('service', '')
        duration = log.get('duration', 0)
        orig_bytes = log.get('orig_bytes', 0)
        resp_bytes = log.get('resp_bytes', 0)

        # Determine severity based on patterns
        severity = 'info'
        attack_type = 'connection'

        # Suspicious connection states
        suspicious_states = {
            'S0': ('low', 'connection-attempt-no-reply'),  # SYN, no reply
            'REJ': ('low', 'connection-rejected'),
            'RSTO': ('low', 'connection-reset-originator'),
            'RSTOS0': ('medium', 'connection-reset-syn'),
        }

        if conn_state in suspicious_states:
            severity, attack_type = suspicious_states[conn_state]

        # Large data transfer
        if resp_bytes > 50_000_000:  # 50MB
            severity = 'medium'
            attack_type = 'large-data-transfer'

        return ParsedEvent(
            event_id=f"zeek-conn-{log.get('uid', uuid.uuid4().hex)}",
            source_type='zeek',
            severity=severity,
            attack_type=attack_type,
            src_ip=log.get('id.orig_h', '0.0.0.0'),
            dst_ip=log.get('id.resp_h', '0.0.0.0'),
            src_port=log.get('id.orig_p'),
            dst_port=log.get('id.resp_p'),
            protocol=log.get('proto', 'unknown').lower(),
            description=f"Conn: {service or 'unknown'} state={conn_state} {orig_bytes}B→{resp_bytes}B",
            raw_data=log,
            timestamp=self._parse_timestamp(log.get('ts')),
        )

    def _parse_http(self, log: dict) -> ParsedEvent:
        """Parse Zeek http.log entry"""
        method = log.get('method', 'GET')
        host = log.get('host', '')
        uri = log.get('uri', '')
        status_code = log.get('status_code', 0)
        user_agent = log.get('user_agent', '')

        severity = 'info'
        attack_type = 'http-request'

        # Check for attack patterns
        uri_lower = uri.lower()
        attack_patterns = [
            ('../', 'path-traversal'),
            ('..\\', 'path-traversal'),
            ('%2e%2e', 'encoded-path-traversal'),
            ('union+select', 'sql-injection'),
            ('union%20select', 'sql-injection'),
            ('<script>', 'xss-attempt'),
            ('cmd=', 'command-injection'),
            ('exec(', 'code-injection'),
        ]

        for pattern, attack in attack_patterns:
            if pattern in uri_lower:
                severity = 'high'
                attack_type = attack
                break

        # Check for suspicious user agents
        suspicious_ua = ['sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab']
        if user_agent and any(ua in user_agent.lower() for ua in suspicious_ua):
            severity = 'high'
            attack_type = 'scanner-detected'

        return ParsedEvent(
            event_id=f"zeek-http-{log.get('uid', uuid.uuid4().hex)}",
            source_type='zeek',
            severity=severity,
            attack_type=attack_type,
            src_ip=log.get('id.orig_h', '0.0.0.0'),
            dst_ip=log.get('id.resp_h', '0.0.0.0'),
            src_port=log.get('id.orig_p'),
            dst_port=log.get('id.resp_p'),
            protocol='http',
            description=f"{method} {host}{uri[:80]} → {status_code}",
            raw_data=log,
            timestamp=self._parse_timestamp(log.get('ts')),
        )

    def _parse_dns(self, log: dict) -> ParsedEvent:
        """Parse Zeek dns.log entry"""
        query = log.get('query', '')
        qtype_name = log.get('qtype_name', '')
        rcode_name = log.get('rcode_name', '')

        severity = 'info'
        attack_type = 'dns-query'

        # Check for DGA-like domains (entropy-based would be better)
        if len(query) > 50 and query.count('.') < 3:
            severity = 'medium'
            attack_type = 'suspicious-dns-length'

        # TXT queries can be used for tunneling
        if qtype_name == 'TXT' and len(query) > 30:
            severity = 'medium'
            attack_type = 'dns-txt-tunnel-suspect'

        return ParsedEvent(
            event_id=f"zeek-dns-{log.get('uid', uuid.uuid4().hex)}",
            source_type='zeek',
            severity=severity,
            attack_type=attack_type,
            src_ip=log.get('id.orig_h', '0.0.0.0'),
            dst_ip=log.get('id.resp_h', '0.0.0.0'),
            src_port=log.get('id.orig_p'),
            dst_port=log.get('id.resp_p'),
            protocol='dns',
            description=f"DNS {qtype_name}: {query} → {rcode_name}",
            raw_data=log,
            timestamp=self._parse_timestamp(log.get('ts')),
        )

    def _parse_ssl(self, log: dict) -> ParsedEvent:
        """Parse Zeek ssl.log entry"""
        server_name = log.get('server_name', '')
        issuer = log.get('issuer', '')
        subject = log.get('subject', '')
        validation_status = log.get('validation_status', '')

        severity = 'info'
        attack_type = 'ssl-connection'

        # Check for certificate issues
        if validation_status and 'unable to get local issuer' in validation_status.lower():
            severity = 'low'
            attack_type = 'ssl-cert-unknown-issuer'

        if validation_status and 'self signed' in validation_status.lower():
            severity = 'low'
            attack_type = 'ssl-self-signed'

        if validation_status and 'expired' in validation_status.lower():
            severity = 'medium'
            attack_type = 'ssl-expired-cert'

        return ParsedEvent(
            event_id=f"zeek-ssl-{log.get('uid', uuid.uuid4().hex)}",
            source_type='zeek',
            severity=severity,
            attack_type=attack_type,
            src_ip=log.get('id.orig_h', '0.0.0.0'),
            dst_ip=log.get('id.resp_h', '0.0.0.0'),
            src_port=log.get('id.orig_p'),
            dst_port=log.get('id.resp_p'),
            protocol='tls',
            description=f"TLS to {server_name or 'unknown'} ({validation_status or 'ok'})",
            raw_data=log,
            timestamp=self._parse_timestamp(log.get('ts')),
        )

    def _parse_notice(self, log: dict) -> ParsedEvent:
        """Parse Zeek notice.log entry (alerts)"""
        note = log.get('note', '')
        msg = log.get('msg', '')

        # Map notice type to severity
        severity = self.NOTICE_TO_SEVERITY.get(note, 'medium')

        return ParsedEvent(
            event_id=f"zeek-notice-{log.get('uid', uuid.uuid4().hex)}",
            source_type='zeek',
            severity=severity,
            attack_type=note.replace('::', '-').lower(),
            src_ip=log.get('id.orig_h', log.get('src', '0.0.0.0')),
            dst_ip=log.get('id.resp_h', log.get('dst', '0.0.0.0')),
            src_port=log.get('id.orig_p'),
            dst_port=log.get('id.resp_p'),
            protocol=log.get('proto', 'unknown').lower(),
            description=f"[{note}] {msg}",
            raw_data=log,
            timestamp=self._parse_timestamp(log.get('ts')),
        )

    def _parse_weird(self, log: dict) -> ParsedEvent:
        """Parse Zeek weird.log entry (anomalies)"""
        name = log.get('name', '')
        addl = log.get('addl', '')

        return ParsedEvent(
            event_id=f"zeek-weird-{log.get('uid', uuid.uuid4().hex)}",
            source_type='zeek',
            severity='low',
            attack_type='protocol-anomaly',
            src_ip=log.get('id.orig_h', '0.0.0.0'),
            dst_ip=log.get('id.resp_h', '0.0.0.0'),
            src_port=log.get('id.orig_p'),
            dst_port=log.get('id.resp_p'),
            protocol=log.get('proto', 'unknown').lower(),
            description=f"Weird: {name} - {addl}",
            raw_data=log,
            timestamp=self._parse_timestamp(log.get('ts')),
        )

    def _parse_timestamp(self, ts) -> datetime:
        """Parse Zeek timestamp (Unix epoch float)"""
        if not ts:
            return timezone.now()
        try:
            return datetime.fromtimestamp(float(ts), tz=timezone.utc)
        except (ValueError, TypeError):
            return timezone.now()
