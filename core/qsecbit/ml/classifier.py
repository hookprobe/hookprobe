"""
Qsecbit Unified - ML Attack Classifier

Machine learning-based attack classification using extracted network features.
Uses Random Forest for classification with signature-based fallback.

Author: HookProbe Team
License: Proprietary
Version: 5.0.0
"""

import math
import pickle
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any, Tuple
from collections import deque, defaultdict

import numpy as np

from ..threat_types import AttackType, ThreatSeverity


@dataclass
class NetworkFeatures:
    """
    Extracted features from network traffic for classification.

    50+ features covering multiple attack vectors.
    """
    # Packet statistics
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    avg_packet_size: float = 0.0
    packet_size_variance: float = 0.0

    # Protocol distribution
    tcp_ratio: float = 0.0
    udp_ratio: float = 0.0
    icmp_ratio: float = 0.0
    other_proto_ratio: float = 0.0

    # TCP flags analysis
    syn_ratio: float = 0.0
    syn_ack_ratio: float = 0.0
    fin_ratio: float = 0.0
    rst_ratio: float = 0.0
    push_ratio: float = 0.0

    # Connection patterns
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    unique_dst_ports: int = 0
    connections_per_src: float = 0.0

    # Port scan indicators
    port_scan_score: float = 0.0
    horizontal_scan_score: float = 0.0
    vertical_scan_score: float = 0.0

    # Timing features
    inter_arrival_time_avg: float = 0.0
    inter_arrival_time_std: float = 0.0
    burst_ratio: float = 0.0

    # DNS features
    dns_query_length_avg: float = 0.0
    dns_query_entropy_avg: float = 0.0
    dns_txt_query_ratio: float = 0.0

    # HTTP features
    http_request_rate: float = 0.0
    http_error_rate: float = 0.0
    http_post_ratio: float = 0.0

    # SSL/TLS features
    ssl_weak_version_ratio: float = 0.0
    ssl_self_signed_ratio: float = 0.0
    ssl_expired_ratio: float = 0.0

    # ARP features
    arp_request_rate: float = 0.0
    arp_reply_rate: float = 0.0
    arp_gratuitous_ratio: float = 0.0

    # ICMP features
    icmp_echo_request_rate: float = 0.0
    icmp_echo_reply_rate: float = 0.0
    icmp_unreachable_rate: float = 0.0

    # Behavioral features
    src_entropy: float = 0.0
    dst_entropy: float = 0.0
    port_entropy: float = 0.0

    # Session features
    half_open_connections: int = 0
    connection_duration_avg: float = 0.0
    connection_duration_std: float = 0.0

    # Energy features (from energy monitor)
    energy_anomaly_score: float = 0.0
    nic_power_spike: bool = False

    def to_vector(self) -> np.ndarray:
        """Convert features to numpy array for ML model."""
        return np.array([
            self.packets_per_second,
            self.bytes_per_second,
            self.avg_packet_size,
            self.packet_size_variance,
            self.tcp_ratio,
            self.udp_ratio,
            self.icmp_ratio,
            self.other_proto_ratio,
            self.syn_ratio,
            self.syn_ack_ratio,
            self.fin_ratio,
            self.rst_ratio,
            self.push_ratio,
            float(self.unique_src_ips),
            float(self.unique_dst_ips),
            float(self.unique_dst_ports),
            self.connections_per_src,
            self.port_scan_score,
            self.horizontal_scan_score,
            self.vertical_scan_score,
            self.inter_arrival_time_avg,
            self.inter_arrival_time_std,
            self.burst_ratio,
            self.dns_query_length_avg,
            self.dns_query_entropy_avg,
            self.dns_txt_query_ratio,
            self.http_request_rate,
            self.http_error_rate,
            self.http_post_ratio,
            self.ssl_weak_version_ratio,
            self.ssl_self_signed_ratio,
            self.ssl_expired_ratio,
            self.arp_request_rate,
            self.arp_reply_rate,
            self.arp_gratuitous_ratio,
            self.icmp_echo_request_rate,
            self.icmp_echo_reply_rate,
            self.icmp_unreachable_rate,
            self.src_entropy,
            self.dst_entropy,
            self.port_entropy,
            float(self.half_open_connections),
            self.connection_duration_avg,
            self.connection_duration_std,
            self.energy_anomaly_score,
            float(self.nic_power_spike),
        ])


class FeatureExtractor:
    """
    Extract features from network traffic data for ML classification.
    """

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds

        # Traffic tracking
        self.packets: deque = deque(maxlen=10000)
        self.connections: deque = deque(maxlen=5000)
        self.dns_queries: deque = deque(maxlen=1000)
        self.http_requests: deque = deque(maxlen=1000)
        self.arp_events: deque = deque(maxlen=500)

    def _calculate_entropy(self, values: List[Any]) -> float:
        """Calculate Shannon entropy of a distribution."""
        if not values:
            return 0.0

        freq = defaultdict(int)
        for v in values:
            freq[v] += 1

        entropy = 0.0
        n = len(values)
        for count in freq.values():
            p = count / n
            entropy -= p * math.log2(p)

        return entropy

    def add_packet(
        self,
        timestamp: datetime,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        size: int,
        flags: Optional[str] = None
    ):
        """Add a packet observation."""
        self.packets.append({
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'size': size,
            'flags': flags or ''
        })

    def add_dns_query(
        self,
        timestamp: datetime,
        query: str,
        qtype: str,
        src_ip: str
    ):
        """Add a DNS query observation."""
        entropy = self._calculate_entropy(list(query.split('.')[0])) if query else 0.0
        self.dns_queries.append({
            'timestamp': timestamp,
            'query': query,
            'qtype': qtype,
            'src_ip': src_ip,
            'length': len(query),
            'entropy': entropy
        })

    def add_http_request(
        self,
        timestamp: datetime,
        method: str,
        status_code: int,
        src_ip: str
    ):
        """Add an HTTP request observation."""
        self.http_requests.append({
            'timestamp': timestamp,
            'method': method,
            'status_code': status_code,
            'src_ip': src_ip
        })

    def extract_features(self) -> NetworkFeatures:
        """Extract features from accumulated traffic data."""
        features = NetworkFeatures()
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.window_seconds)

        # Filter to window
        recent_packets = [p for p in self.packets if p['timestamp'] > cutoff]
        recent_dns = [d for d in self.dns_queries if d['timestamp'] > cutoff]
        recent_http = [h for h in self.http_requests if h['timestamp'] > cutoff]

        if not recent_packets:
            return features

        # Packet statistics
        features.packets_per_second = len(recent_packets) / self.window_seconds
        total_bytes = sum(p['size'] for p in recent_packets)
        features.bytes_per_second = total_bytes / self.window_seconds
        sizes = [p['size'] for p in recent_packets]
        features.avg_packet_size = np.mean(sizes) if sizes else 0.0
        features.packet_size_variance = np.var(sizes) if len(sizes) > 1 else 0.0

        # Protocol distribution
        tcp_count = sum(1 for p in recent_packets if p['protocol'].lower() == 'tcp')
        udp_count = sum(1 for p in recent_packets if p['protocol'].lower() == 'udp')
        icmp_count = sum(1 for p in recent_packets if p['protocol'].lower() == 'icmp')
        total = len(recent_packets)

        features.tcp_ratio = tcp_count / total if total else 0.0
        features.udp_ratio = udp_count / total if total else 0.0
        features.icmp_ratio = icmp_count / total if total else 0.0
        features.other_proto_ratio = 1.0 - (features.tcp_ratio + features.udp_ratio + features.icmp_ratio)

        # TCP flags
        tcp_packets = [p for p in recent_packets if p['protocol'].lower() == 'tcp']
        if tcp_packets:
            tcp_total = len(tcp_packets)
            features.syn_ratio = sum(1 for p in tcp_packets if 'S' in p['flags'] and 'A' not in p['flags']) / tcp_total
            features.syn_ack_ratio = sum(1 for p in tcp_packets if 'S' in p['flags'] and 'A' in p['flags']) / tcp_total
            features.fin_ratio = sum(1 for p in tcp_packets if 'F' in p['flags']) / tcp_total
            features.rst_ratio = sum(1 for p in tcp_packets if 'R' in p['flags']) / tcp_total
            features.push_ratio = sum(1 for p in tcp_packets if 'P' in p['flags']) / tcp_total

        # Connection patterns
        src_ips = set(p['src_ip'] for p in recent_packets)
        dst_ips = set(p['dst_ip'] for p in recent_packets)
        dst_ports = set(p['dst_port'] for p in recent_packets)

        features.unique_src_ips = len(src_ips)
        features.unique_dst_ips = len(dst_ips)
        features.unique_dst_ports = len(dst_ports)
        features.connections_per_src = total / len(src_ips) if src_ips else 0.0

        # Port scan indicators
        ports_per_src = defaultdict(set)
        for p in recent_packets:
            ports_per_src[p['src_ip']].add(p['dst_port'])

        max_ports = max(len(ports) for ports in ports_per_src.values()) if ports_per_src else 0
        features.port_scan_score = min(1.0, max_ports / 100)

        # Entropy features
        features.src_entropy = self._calculate_entropy([p['src_ip'] for p in recent_packets])
        features.dst_entropy = self._calculate_entropy([p['dst_ip'] for p in recent_packets])
        features.port_entropy = self._calculate_entropy([p['dst_port'] for p in recent_packets])

        # DNS features
        if recent_dns:
            features.dns_query_length_avg = np.mean([d['length'] for d in recent_dns])
            features.dns_query_entropy_avg = np.mean([d['entropy'] for d in recent_dns])
            txt_count = sum(1 for d in recent_dns if d['qtype'] == 'TXT')
            features.dns_txt_query_ratio = txt_count / len(recent_dns)

        # HTTP features
        if recent_http:
            features.http_request_rate = len(recent_http) / self.window_seconds
            error_count = sum(1 for h in recent_http if h['status_code'] >= 400)
            features.http_error_rate = error_count / len(recent_http)
            post_count = sum(1 for h in recent_http if h['method'] == 'POST')
            features.http_post_ratio = post_count / len(recent_http)

        return features


class AttackClassifier:
    """
    ML-based attack classifier using Random Forest.

    Uses extracted network features to classify attack types with confidence scores.
    Falls back to signature-based detection when ML model is not available.
    """

    # Feature importance for rule-based classification (fallback)
    ATTACK_SIGNATURES = {
        AttackType.SYN_FLOOD: {
            'syn_ratio': (0.7, 1.0),
            'half_open_connections': (50, float('inf')),
        },
        AttackType.PORT_SCAN: {
            'port_scan_score': (0.5, 1.0),
            'unique_dst_ports': (30, float('inf')),
        },
        AttackType.UDP_FLOOD: {
            'udp_ratio': (0.8, 1.0),
            'packets_per_second': (1000, float('inf')),
        },
        AttackType.ICMP_FLOOD: {
            'icmp_ratio': (0.7, 1.0),
            'icmp_echo_request_rate': (100, float('inf')),
        },
        AttackType.DNS_TUNNELING: {
            'dns_query_length_avg': (40, float('inf')),
            'dns_query_entropy_avg': (3.5, float('inf')),
        },
        AttackType.HTTP_FLOOD: {
            'http_request_rate': (50, float('inf')),
        },
        AttackType.ARP_SPOOFING: {
            'arp_gratuitous_ratio': (0.3, 1.0),
        },
    }

    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.model_path = Path(model_path) if model_path else None
        self.feature_names = self._get_feature_names()

        # Load model if available
        if self.model_path and self.model_path.exists():
            self._load_model()

    def _get_feature_names(self) -> List[str]:
        """Get list of feature names in order."""
        return [
            'packets_per_second', 'bytes_per_second', 'avg_packet_size',
            'packet_size_variance', 'tcp_ratio', 'udp_ratio', 'icmp_ratio',
            'other_proto_ratio', 'syn_ratio', 'syn_ack_ratio', 'fin_ratio',
            'rst_ratio', 'push_ratio', 'unique_src_ips', 'unique_dst_ips',
            'unique_dst_ports', 'connections_per_src', 'port_scan_score',
            'horizontal_scan_score', 'vertical_scan_score', 'inter_arrival_time_avg',
            'inter_arrival_time_std', 'burst_ratio', 'dns_query_length_avg',
            'dns_query_entropy_avg', 'dns_txt_query_ratio', 'http_request_rate',
            'http_error_rate', 'http_post_ratio', 'ssl_weak_version_ratio',
            'ssl_self_signed_ratio', 'ssl_expired_ratio', 'arp_request_rate',
            'arp_reply_rate', 'arp_gratuitous_ratio', 'icmp_echo_request_rate',
            'icmp_echo_reply_rate', 'icmp_unreachable_rate', 'src_entropy',
            'dst_entropy', 'port_entropy', 'half_open_connections',
            'connection_duration_avg', 'connection_duration_std',
            'energy_anomaly_score', 'nic_power_spike'
        ]

    def _load_model(self):
        """Load pre-trained model from disk."""
        try:
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
        except Exception as e:
            print(f"Warning: Could not load ML model: {e}")
            self.model = None

    def classify(
        self,
        features: NetworkFeatures
    ) -> List[Tuple[AttackType, float]]:
        """
        Classify attack type from features.

        Returns:
            List of (AttackType, confidence) tuples, sorted by confidence descending
        """
        if self.model is not None:
            return self._classify_ml(features)
        else:
            return self._classify_rules(features)

    def _classify_ml(
        self,
        features: NetworkFeatures
    ) -> List[Tuple[AttackType, float]]:
        """Classify using ML model."""
        try:
            X = features.to_vector().reshape(1, -1)
            proba = self.model.predict_proba(X)[0]
            classes = self.model.classes_

            results = []
            for i, cls in enumerate(classes):
                attack_type = AttackType[cls] if isinstance(cls, str) else cls
                confidence = float(proba[i])
                if confidence > 0.1:  # Only include significant predictions
                    results.append((attack_type, confidence))

            results.sort(key=lambda x: x[1], reverse=True)
            return results

        except Exception:
            return self._classify_rules(features)

    def _classify_rules(
        self,
        features: NetworkFeatures
    ) -> List[Tuple[AttackType, float]]:
        """
        Rule-based classification (fallback when no ML model).

        Uses signature patterns to match attack types.
        """
        results = []
        feature_dict = features.__dict__

        for attack_type, signatures in self.ATTACK_SIGNATURES.items():
            match_count = 0
            total_signatures = len(signatures)

            for feature_name, (min_val, max_val) in signatures.items():
                if feature_name in feature_dict:
                    value = feature_dict[feature_name]
                    if min_val <= value <= max_val:
                        match_count += 1

            if match_count > 0:
                confidence = match_count / total_signatures * 0.8  # Cap at 0.8 for rule-based
                results.append((attack_type, confidence))

        results.sort(key=lambda x: x[1], reverse=True)
        return results

    def get_attack_probability(self, features: NetworkFeatures) -> float:
        """
        Get overall attack probability (for Qsecbit p_attack input).

        Returns single float between 0.0 and 1.0.
        """
        classifications = self.classify(features)

        if not classifications:
            return 0.0

        # Use highest confidence as attack probability
        # Weight by number of matched attack types
        max_confidence = classifications[0][1] if classifications else 0.0
        num_attacks = len([c for c in classifications if c[1] > 0.3])

        # Combine: max confidence + bonus for multiple attack types
        probability = min(1.0, max_confidence + num_attacks * 0.05)

        return probability
