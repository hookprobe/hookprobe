#!/usr/bin/env python3
"""
HookProbe QSECBIT Security Scoring Engine

Calculates a security resilience score (0-100) based on:
- Threat detection metrics from Napse intents
- Network anomalies from XDP (high-rate IPs)
- Flow analysis from Napse flows
- Incident response metrics

Score Interpretation:
- 0-29: CRITICAL - Immediate action required
- 30-54: WARNING - Elevated risk, investigation needed
- 55-100: PROTECTED - Normal operations

Usage:
    python3 qsecbit_engine.py [--interval 60] [--vrf default]
"""

import os
import sys
import time
import argparse
import logging
import json
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlencode

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("Warning: requests library not installed")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [QSECBIT] %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)


class QSecBitEngine:
    """QSECBIT Security Scoring Engine"""

    def __init__(self, vrf: str = '', site_id: str = ''):
        self.vrf = vrf
        self.site_id = site_id

        # ClickHouse config
        self.ch_host = os.environ.get('CLICKHOUSE_HOST', '127.0.0.1')
        self.ch_port = os.environ.get('CLICKHOUSE_PORT', '8123')
        self.ch_db = os.environ.get('CLICKHOUSE_DB', 'hookprobe_ids')
        self.ch_user = os.environ.get('CLICKHOUSE_USER', 'ids')
        self.ch_password = os.environ.get('CLICKHOUSE_PASSWORD')

        if not self.ch_password:
            logger.error("CLICKHOUSE_PASSWORD environment variable is required")
            sys.exit(1)

        # Scoring weights (must sum to 100)
        self.weights = {
            'threat': 35,      # Napse intents
            'network': 25,     # XDP/network anomalies
            'detection': 25,   # Napse flow coverage
            'response': 15,    # Incident response metrics
        }

        # Previous score for trend calculation
        self.prev_score: Optional[int] = None

        # Load previous score from ClickHouse on startup
        self._load_previous_score()

    def _load_previous_score(self):
        """Load the most recent score from ClickHouse for trend calculation."""
        results = self._query_clickhouse(
            "SELECT score FROM qsecbit_scores ORDER BY timestamp DESC LIMIT 1",
            {}
        )
        if results:
            try:
                self.prev_score = int(results[0].get('score', 0))
                logger.info(f"Loaded previous score: {self.prev_score}")
            except (ValueError, TypeError):
                self.prev_score = None

    def _query_clickhouse(self, query: str, params: Dict[str, Any]) -> list:
        """Execute ClickHouse query with parameterized values and return results."""
        if not HAS_REQUESTS:
            return []

        try:
            # Build URL with params for parameterized queries
            url_params = {'database': self.ch_db}
            for key, value in params.items():
                url_params[f'param_{key}'] = str(value)

            url = f"http://{self.ch_host}:{self.ch_port}/?{urlencode(url_params)}"
            response = requests.post(
                url,
                data=query + " FORMAT JSONEachRow",
                auth=(self.ch_user, self.ch_password),
                timeout=10
            )

            if response.status_code != 200:
                logger.error(f"ClickHouse query failed: {response.text}")
                return []

            # Parse JSONEachRow format
            results = []
            for line in response.text.strip().split('\n'):
                if line:
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            return results

        except Exception as e:
            logger.error(f"ClickHouse query error: {e}")
            return []

    def _insert_clickhouse(self, query: str, params: Dict[str, Any]) -> bool:
        """Execute ClickHouse insert with parameterized values."""
        if not HAS_REQUESTS:
            return False

        try:
            url_params = {'database': self.ch_db}
            for key, value in params.items():
                url_params[f'param_{key}'] = str(value)

            url = f"http://{self.ch_host}:{self.ch_port}/?{urlencode(url_params)}"
            response = requests.post(
                url,
                data=query,
                auth=(self.ch_user, self.ch_password),
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"ClickHouse insert error: {e}")
            return False

    def calculate_threat_score(self, hours: int = 1) -> Tuple[int, Dict[str, int]]:
        """
        Calculate threat score based on Napse intent classifications.

        Scoring logic (v2 - rate-based, not raw counts):
        - Start at 100 (perfect)
        - Use UNIQUE SOURCE IPs per intent class (not raw event counts)
          - A single IP generating 100K events is 1 source, not 100K threats
        - DDoS requires 10+ distributed sources to count
        - Apply logarithmic scaling (diminishing returns on deductions)
        """
        # Count unique SOURCES per severity, not raw events
        # This prevents a single noisy IP from tanking the score
        query = """
            SELECT
                uniqIf(src_ip, severity = 1) as critical_sources,
                uniqIf(src_ip, severity = 2) as high_sources,
                uniqIf(src_ip, severity = 3) as medium_sources,
                uniqIf(src_ip, severity > 3 OR severity = 0) as low_sources,
                countIf(severity = 1) as critical,
                countIf(severity = 2) as high,
                countIf(severity = 3) as medium,
                countIf(severity > 3 OR severity = 0) as low,
                uniqIf(src_ip, intent_class = 'ddos') as ddos_sources
            FROM napse_intents
            WHERE timestamp >= now() - INTERVAL {hours:UInt32} HOUR
        """

        results = self._query_clickhouse(query, {'hours': hours})
        if not results:
            return 100, {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        r = results[0]
        try:
            critical_sources = int(r.get('critical_sources', 0))
            high_sources = int(r.get('high_sources', 0))
            medium_sources = int(r.get('medium_sources', 0))
            low_sources = int(r.get('low_sources', 0))
            critical = int(r.get('critical', 0))
            high = int(r.get('high', 0))
            medium = int(r.get('medium', 0))
            low = int(r.get('low', 0))
            ddos_sources = int(r.get('ddos_sources', 0))
        except (ValueError, TypeError):
            logger.warning(f"Invalid alert counts from ClickHouse: {r}")
            return 100, {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        # DDoS sanity check: if fewer than 10 sources, it's not a real DDoS
        # Discount the critical score accordingly
        if ddos_sources < 10:
            # Most "critical" events are probably DDoS false positives
            # Only count non-DDoS critical sources
            critical_sources = max(0, critical_sources - ddos_sources)

        # Calculate deductions using UNIQUE SOURCES (not raw counts)
        # This means 1 attacker IP = 1 deduction, not 100K deductions
        score = 100
        score -= min(critical_sources * 10, 50)   # Each critical source: -10 (max 50)
        score -= min(high_sources * 5, 30)         # Each high source: -5 (max 30)
        score -= min(medium_sources * 2, 20)       # Each medium source: -2 (max 20)
        score -= min(low_sources * 1, 10)          # Each low source: -1 (max 10)

        return max(0, score), {
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low
        }

    def calculate_network_score(self, hours: int = 1) -> Tuple[int, Dict[str, int]]:
        """
        Calculate network score based on XDP metrics.

        Scoring logic:
        - Start at 100
        - Deduct for high-rate IPs (potential DDoS/scanning): -10 per IP (max 50)
        - Deduct for traffic anomalies
        """
        query = """
            SELECT
                argMax(high_rate_ip_count, timestamp) as high_rate_ips,
                sum(delta_packets) as total_packets,
                sum(delta_bytes) as total_bytes
            FROM xdp_stats
            WHERE timestamp >= now() - INTERVAL {hours:UInt32} HOUR
        """

        results = self._query_clickhouse(query, {'hours': hours})
        if not results:
            return 100, {'high_rate_ips': 0, 'total_packets': 0}

        r = results[0]
        try:
            high_rate_ips = int(r.get('high_rate_ips', 0))
            total_packets = int(r.get('total_packets', 0))
        except (ValueError, TypeError):
            logger.warning(f"Invalid network metrics from ClickHouse: {r}")
            return 100, {'high_rate_ips': 0, 'total_packets': 0}

        # Calculate score
        # Only deduct for high-rate IPs if there are many of them (distributed attack)
        # A few high-rate IPs could be legitimate services (SSH, API clients)
        if high_rate_ips >= 10:
            score = 100 - min(high_rate_ips * 5, 40)  # Distributed high-rate = concern
        elif high_rate_ips >= 5:
            score = 100 - min(high_rate_ips * 3, 20)  # Moderate concern
        else:
            score = 100  # < 5 high-rate IPs = likely normal traffic

        # Additional deduction for extremely high packet rates
        pps = total_packets / (hours * 3600) if hours > 0 else 0
        if pps > 50000:  # 50k+ pps is genuinely concerning (was 10k)
            score -= min(int((pps - 50000) / 5000), 20)

        return max(0, score), {
            'high_rate_ips': high_rate_ips,
            'total_packets': total_packets
        }

    def calculate_detection_score(self, hours: int = 1) -> Tuple[int, Dict[str, int]]:
        """
        Calculate detection coverage score based on Napse flows.

        Higher score = better visibility into network traffic.
        """
        query = """
            SELECT
                count() as flows,
                uniqExact(src_ip) as unique_sources,
                uniqExact(dst_ip) as unique_dests,
                countIf(service != '') as identified_services
            FROM napse_flows
            WHERE timestamp >= now() - INTERVAL {hours:UInt32} HOUR
        """

        results = self._query_clickhouse(query, {'hours': hours})
        if not results:
            # No Napse flow data = reduced visibility
            return 50, {'flows': 0, 'unique_sources': 0}

        r = results[0]
        flows = int(r.get('flows', 0))
        unique_sources = int(r.get('unique_sources', 0))
        identified = int(r.get('identified_services', 0))

        # Detection score based on service identification rate
        if flows > 0:
            identification_rate = identified / flows
            score = int(50 + (identification_rate * 50))
        else:
            score = 50  # Baseline when no traffic

        # Bonus for good visibility (seeing many unique sources)
        if unique_sources > 10:
            score = min(100, score + 10)

        return min(100, score), {
            'flows': flows,
            'unique_sources': unique_sources,
            'identified_services': identified
        }

    def calculate_response_score(self, hours: int = 24) -> Tuple[int, Dict[str, int]]:
        """
        Calculate incident response score.

        Based on:
        - Open incidents (negative)
        - Blocked IoCs (positive)
        - XDP active defense blocks (positive — system is defending)
        - Response time (if available)
        """
        # Query open incidents
        incident_query = """
            SELECT
                count() as total,
                countIf(status = 'new' OR status = 'investigating') as open_incidents,
                countIf(status = 'resolved') as resolved
            FROM incidents
            WHERE created_at >= now() - INTERVAL {hours:UInt32} HOUR
        """

        # Query blocked IoCs - use last_seen (not updated_at which doesn't exist)
        ioc_query = """
            SELECT
                countIf(status = 'blocked') as blocked,
                countIf(status = 'active') as active
            FROM iocs
            WHERE last_seen >= now() - INTERVAL {hours:UInt32} HOUR
        """

        # Query XDP blocks from hydra_events (active defense)
        xdp_block_query = """
            SELECT
                uniqExact(src_ip) as blocked_ips,
                count() as blocked_events
            FROM hydra_events
            WHERE timestamp >= now() - INTERVAL {hours:UInt32} HOUR
              AND action IN ('drop', 'score_drop')
        """

        incident_results = self._query_clickhouse(incident_query, {'hours': hours})
        ioc_results = self._query_clickhouse(ioc_query, {'hours': hours})
        xdp_results = self._query_clickhouse(xdp_block_query, {'hours': hours})

        open_incidents = 0
        resolved = 0
        blocked_iocs = 0
        active_iocs = 0
        xdp_blocked_ips = 0
        xdp_blocked_events = 0

        if incident_results:
            r = incident_results[0]
            open_incidents = int(r.get('open_incidents', 0))
            resolved = int(r.get('resolved', 0))

        if ioc_results:
            r = ioc_results[0]
            blocked_iocs = int(r.get('blocked', 0))
            active_iocs = int(r.get('active', 0))

        if xdp_results:
            r = xdp_results[0]
            xdp_blocked_ips = int(r.get('blocked_ips', 0))
            xdp_blocked_events = int(r.get('blocked_events', 0))

        # Calculate score
        score = 100

        # Deduct for open incidents
        score -= min(open_incidents * 20, 60)

        # Bonus for resolved incidents
        if resolved > 0:
            score = min(100, score + min(resolved * 5, 20))

        # Deduct for unblocked active IoCs
        score -= min(active_iocs * 5, 30)

        # Bonus for blocked IoCs
        if blocked_iocs > 0:
            score = min(100, score + min(blocked_iocs * 2, 15))

        # Total blocked threats = IoC blocks + XDP blocks
        total_blocked = blocked_iocs + xdp_blocked_ips

        return max(0, min(100, score)), {
            'open_incidents': open_incidents,
            'blocked_iocs': total_blocked,
            'active_iocs': active_iocs
        }

    def calculate_overall_score(self) -> Dict[str, Any]:
        """Calculate the overall QSECBIT score."""

        # Calculate component scores
        threat_score, threat_metrics = self.calculate_threat_score(hours=1)
        network_score, network_metrics = self.calculate_network_score(hours=1)
        detection_score, detection_metrics = self.calculate_detection_score(hours=1)
        response_score, response_metrics = self.calculate_response_score(hours=24)

        # Weighted average
        overall = int(
            (threat_score * self.weights['threat'] +
             network_score * self.weights['network'] +
             detection_score * self.weights['detection'] +
             response_score * self.weights['response']) / 100
        )

        # Determine status
        if overall < 30:
            status = 'critical'
        elif overall < 55:
            status = 'warning'
        else:
            status = 'protected'

        # Calculate trend
        if self.prev_score is None:
            trend = 'stable'
            score_delta = 0
        else:
            score_delta = overall - self.prev_score
            if score_delta > 5:
                trend = 'improving'
            elif score_delta < -5:
                trend = 'degrading'
            else:
                trend = 'stable'

        self.prev_score = overall

        return {
            'score': overall,
            'status': status,
            'components': {
                'threat': threat_score,
                'network': network_score,
                'detection': detection_score,
                'response': response_score,
            },
            'metrics': {
                **threat_metrics,
                'high_rate_ips': network_metrics.get('high_rate_ips', 0),
                'blocked_threats': response_metrics.get('blocked_iocs', 0),
                'active_incidents': response_metrics.get('open_incidents', 0),
            },
            'trend': trend,
            'score_delta': score_delta,
            'timestamp': datetime.utcnow().isoformat(),
        }

    def store_score(self, score_data: Dict[str, Any]) -> bool:
        """Store the calculated score in ClickHouse using parameterized queries."""
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

        insert_sql = """
            INSERT INTO qsecbit_scores (
                timestamp, vrf, site_id, score, status,
                threat_score, network_score, detection_score, response_score,
                critical_alerts, high_alerts, medium_alerts, low_alerts,
                high_rate_ips, blocked_threats, active_incidents,
                score_delta, trend
            ) VALUES (
                {p_timestamp:String}, {p_vrf:String}, {p_site_id:String},
                {p_score:UInt8}, {p_status:String},
                {p_threat:UInt8}, {p_network:UInt8}, {p_detection:UInt8}, {p_response:UInt8},
                {p_critical:UInt32}, {p_high:UInt32}, {p_medium:UInt32}, {p_low:UInt32},
                {p_high_rate_ips:UInt32}, {p_blocked:UInt32}, {p_active_incidents:UInt32},
                {p_delta:Int16}, {p_trend:String}
            )
        """

        params = {
            'p_timestamp': timestamp,
            'p_vrf': self.vrf or 'unknown',
            'p_site_id': self.site_id or '',
            'p_score': score_data['score'],
            'p_status': score_data['status'],
            'p_threat': score_data['components']['threat'],
            'p_network': score_data['components']['network'],
            'p_detection': score_data['components']['detection'],
            'p_response': score_data['components']['response'],
            'p_critical': score_data['metrics'].get('critical', 0),
            'p_high': score_data['metrics'].get('high', 0),
            'p_medium': score_data['metrics'].get('medium', 0),
            'p_low': score_data['metrics'].get('low', 0),
            'p_high_rate_ips': score_data['metrics'].get('high_rate_ips', 0),
            'p_blocked': score_data['metrics'].get('blocked_threats', 0),
            'p_active_incidents': score_data['metrics'].get('active_incidents', 0),
            'p_delta': score_data['score_delta'],
            'p_trend': score_data['trend'],
        }

        return self._insert_clickhouse(insert_sql, params)

    def run_once(self) -> Dict[str, Any]:
        """Calculate and store score once."""
        score_data = self.calculate_overall_score()

        if self.store_score(score_data):
            logger.info(
                f"QSECBIT Score: {score_data['score']} ({score_data['status'].upper()}) "
                f"[T:{score_data['components']['threat']} "
                f"N:{score_data['components']['network']} "
                f"D:{score_data['components']['detection']} "
                f"R:{score_data['components']['response']}]"
            )
        else:
            logger.warning("Failed to store QSECBIT score")

        return score_data


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/reserved using the ipaddress module."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local
    except ValueError:
        return True  # Invalid IPs treated as private (skip them)


def auto_create_incidents(engine: QSecBitEngine):
    """
    Auto-create incidents from critical Napse intent classifications.

    Groups related intents into incidents for SOC review.
    """
    # Find critical intents that haven't been linked to incidents
    # This query uses no user-controlled input so parameterization is for consistency
    query = """
        SELECT
            intent_class,
            intent_class as category,
            IPv4NumToString(src_ip) as src_ip,
            IPv4NumToString(dst_ip) as dest_ip,
            count() as intent_count,
            max(timestamp) as last_seen,
            groupArray(community_id) as community_ids
        FROM napse_intents
        WHERE timestamp >= now() - INTERVAL 1 HOUR
          AND severity <= 2
        GROUP BY intent_class, src_ip, dst_ip
        HAVING intent_count >= 3
        LIMIT 10
    """

    results = engine._query_clickhouse(query, {})

    for r in results:
        intent_class = str(r.get('intent_class', ''))[:200]
        category = str(r.get('category', ''))[:100]
        src_ip = str(r.get('src_ip', ''))
        dest_ip = str(r.get('dest_ip', ''))
        intent_count = int(r.get('intent_count', 0))

        # Check if incident already exists for this intent class
        check_query = """
            SELECT id FROM incidents
            WHERE title = {p_title:String}
              AND created_at >= now() - INTERVAL 24 HOUR
            LIMIT 1
        """
        existing = engine._query_clickhouse(check_query, {'p_title': intent_class})

        if not existing:
            severity = 'critical' if intent_count > 10 else 'high'
            description = f'Auto-generated from {intent_count} Napse intent classifications. Class: {category}'

            insert_sql = """
                INSERT INTO incidents (
                    created_at, title, description, severity, status, category,
                    sources, src_ips, dest_ips, threat_score
                ) VALUES (
                    now64(3),
                    {p_title:String},
                    {p_desc:String},
                    {p_severity:String}, 'new', {p_category:String},
                    ['Napse'], [{p_src_ip:String}], [{p_dest_ip:String}],
                    {p_threat_score:UInt8}
                )
            """

            params = {
                'p_title': intent_class,
                'p_desc': description,
                'p_severity': severity,
                'p_category': category,
                'p_src_ip': src_ip,
                'p_dest_ip': dest_ip,
                'p_threat_score': min(intent_count * 10, 95),
            }

            if engine._insert_clickhouse(insert_sql, params):
                logger.info(f"Created incident: {intent_class[:50]}...")


def auto_create_iocs(engine: QSecBitEngine):
    """
    Auto-create IoCs from suspicious activity.

    Creates IoCs for:
    - High-rate source IPs
    - IPs with multiple intent classifications
    """
    # Find IPs with multiple intent types (potential attacker)
    query = """
        SELECT
            IPv4NumToString(src_ip) as ip,
            count() as total_intents,
            uniqExact(intent_class) as unique_intent_classes,
            groupArray(DISTINCT intent_class) as intent_classes
        FROM napse_intents
        WHERE timestamp >= now() - INTERVAL 1 HOUR
        GROUP BY src_ip
        HAVING unique_intent_classes >= 3 OR total_intents >= 10
        LIMIT 20
    """

    results = engine._query_clickhouse(query, {})

    for r in results:
        ip = str(r.get('ip', ''))
        if not ip or _is_private_ip(ip):
            continue  # Skip private/reserved IPs

        # Check if IoC already exists
        check_query = """
            SELECT id FROM iocs
            WHERE type = 'ip' AND value = {p_ip:String}
              AND created_at >= now() - INTERVAL 24 HOUR
            LIMIT 1
        """
        existing = engine._query_clickhouse(check_query, {'p_ip': ip})

        if not existing:
            intents = int(r.get('total_intents', 0))
            classes = int(r.get('unique_intent_classes', 0))
            risk = min(50 + intents * 2 + classes * 5, 95)
            confidence = min(40 + classes * 10, 90)

            insert_sql = """
                INSERT INTO iocs (
                    created_at, type, value, confidence, risk_score, threat_type,
                    status, sources, detection_count
                ) VALUES (
                    now64(3),
                    'ip', {p_ip:String}, {p_confidence:UInt8}, {p_risk:UInt8}, 'suspicious_activity',
                    'active', ['Napse'], {p_intents:UInt32}
                )
            """

            params = {
                'p_ip': ip,
                'p_confidence': confidence,
                'p_risk': risk,
                'p_intents': intents,
            }

            if engine._insert_clickhouse(insert_sql, params):
                logger.info(f"Created IoC: {ip} (risk: {risk}, intents: {intents})")


def main():
    parser = argparse.ArgumentParser(description='QSECBIT Security Scoring Engine')
    parser.add_argument('--interval', type=int, default=60,
                       help='Score calculation interval in seconds (default: 60)')
    parser.add_argument('--vrf', type=str, default='',
                       help='VRF/network segment filter')
    parser.add_argument('--site-id', type=str, default='',
                       help='Site ID filter')
    parser.add_argument('--once', action='store_true',
                       help='Calculate score once and exit')
    parser.add_argument('--auto-incidents', action='store_true',
                       help='Auto-create incidents from intents')
    parser.add_argument('--log-level', type=str, default='INFO',
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])
    args = parser.parse_args()

    logging.getLogger().setLevel(getattr(logging, args.log_level))

    engine = QSecBitEngine(vrf=args.vrf, site_id=args.site_id)

    logger.info("QSECBIT Security Scoring Engine started")
    logger.info(f"  Interval: {args.interval}s")
    logger.info(f"  VRF: {args.vrf or 'all'}")
    logger.info(f"  Auto-incidents: {args.auto_incidents}")

    if args.once:
        score = engine.run_once()
        print(json.dumps(score, indent=2))
        return

    while True:
        try:
            engine.run_once()

            if args.auto_incidents:
                auto_create_incidents(engine)
                auto_create_iocs(engine)

        except Exception as e:
            logger.error(f"Error in scoring loop: {e}")

        time.sleep(args.interval)


if __name__ == '__main__':
    main()
