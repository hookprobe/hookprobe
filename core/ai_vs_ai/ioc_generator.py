"""
IoC Generator

Generates Indicators of Compromise from LSTM threat predictions
and NAPSE alerts. Creates structured attack descriptions for AI consultation.

Author: HookProbe Team
Version: 1.0.0
License: AGPL-3.0
"""

import json
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict

from .models import (
    IoC,
    IoCType,
    ThreatSeverity,
    ThreatPrediction,
    get_mitre_mapping,
)


# Attack category descriptions for AI prompts
ATTACK_DESCRIPTIONS = {
    "port_scan": "Network reconnaissance scanning multiple ports to identify services",
    "address_scan": "Network reconnaissance scanning IP ranges to identify hosts",
    "syn_flood": "TCP SYN flood attack exhausting connection resources",
    "udp_flood": "UDP flood attack overwhelming network bandwidth",
    "icmp_flood": "ICMP flood attack (ping flood) for denial of service",
    "brute_force": "Credential attack attempting multiple passwords/usernames",
    "sql_injection": "Web attack injecting malicious SQL to manipulate database",
    "xss": "Cross-site scripting attack injecting malicious scripts",
    "dns_tunneling": "Data exfiltration or C2 communication via DNS queries",
    "malware_c2": "Malware command and control communication detected",
    "data_exfiltration": "Unauthorized data transfer to external destination",
    "privilege_escalation": "Attempt to gain higher privileges than authorized",
    "lateral_movement": "Movement between systems after initial compromise",
    "dos_attack": "Denial of service attack disrupting availability",
    "reconnaissance": "General reconnaissance and information gathering",
    "unknown": "Unknown or unclassified suspicious activity",
}

# Severity mapping based on attack category
ATTACK_SEVERITY = {
    "malware_c2": ThreatSeverity.CRITICAL,
    "data_exfiltration": ThreatSeverity.CRITICAL,
    "sql_injection": ThreatSeverity.HIGH,
    "privilege_escalation": ThreatSeverity.HIGH,
    "lateral_movement": ThreatSeverity.HIGH,
    "brute_force": ThreatSeverity.HIGH,
    "syn_flood": ThreatSeverity.MEDIUM,
    "udp_flood": ThreatSeverity.MEDIUM,
    "dos_attack": ThreatSeverity.MEDIUM,
    "dns_tunneling": ThreatSeverity.MEDIUM,
    "xss": ThreatSeverity.MEDIUM,
    "icmp_flood": ThreatSeverity.LOW,
    "port_scan": ThreatSeverity.LOW,
    "address_scan": ThreatSeverity.LOW,
    "reconnaissance": ThreatSeverity.INFO,
    "unknown": ThreatSeverity.LOW,
}


class IoCGenerator:
    """
    Generate IoCs from threat predictions and security events.

    Combines LSTM predictions with NAPSE alert analysis to create
    comprehensive IoCs for AI consultation and automated response.
    """

    def __init__(
        self,
        output_dir: Optional[Path] = None
    ):
        if output_dir and not isinstance(output_dir, Path):
            output_dir = Path(output_dir)

        self.output_dir = output_dir or Path(
            "/opt/hookprobe/fortress/data/ioc"
        )
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # IoC cache to avoid duplicates
        self._ioc_cache: Dict[str, IoC] = {}
        self._max_cache_size = 10000

    def from_prediction(
        self,
        prediction: ThreatPrediction,
        source_ip: Optional[str] = None,
        source_data: Optional[Dict[str, Any]] = None
    ) -> IoC:
        """
        Generate IoC from LSTM prediction.

        Args:
            prediction: ThreatPrediction from LSTM model
            source_ip: Source IP if available (will be anonymized)
            source_data: Additional context data

        Returns:
            IoC with attack description and MITRE mapping
        """
        attack_category = prediction.predicted_attack
        mitre = get_mitre_mapping(attack_category)

        # Determine IoC type based on attack
        ioc_type = self._determine_ioc_type(attack_category, source_data)

        # Get or create value
        value = self._extract_ioc_value(
            ioc_type, attack_category, source_ip, source_data
        )

        # Build attack description
        description = self._build_description(
            attack_category,
            prediction,
            source_data
        )

        ioc = IoC(
            ioc_id="",  # Will be auto-generated
            ioc_type=ioc_type,
            value=value,
            confidence=prediction.confidence,
            severity=ATTACK_SEVERITY.get(attack_category, ThreatSeverity.LOW),
            attack_category=attack_category,
            attack_description=description,
            attack_sequence=prediction.input_sequence.copy(),
            mitre_tactics=mitre["tactics"],
            mitre_techniques=mitre["techniques"],
            source_system="lstm",
            tags=self._generate_tags(attack_category, prediction),
            raw_evidence={
                "prediction": prediction.to_dict(),
                "anomaly_score": prediction.anomaly_score,
                "attack_intensity": prediction.attack_intensity,
            }
        )

        # Cache and return
        self._add_to_cache(ioc)
        return ioc

    def from_ids_alert(self, alert: Dict[str, Any]) -> Optional[IoC]:
        """
        Generate IoC from NAPSE IDS alert.

        Args:
            alert: NAPSE alert (EVE JSON compatible format)

        Returns:
            IoC or None if alert is not significant
        """
        if alert.get("event_type") != "alert":
            return None

        alert_data = alert.get("alert", {})
        severity_num = alert_data.get("severity", 3)

        # Map alert severity (1=high, 2=medium, 3=low)
        severity_map = {
            1: ThreatSeverity.HIGH,
            2: ThreatSeverity.MEDIUM,
            3: ThreatSeverity.LOW,
        }
        severity = severity_map.get(severity_num, ThreatSeverity.LOW)

        # Extract IoC value
        src_ip = self._anonymize_ip(alert.get("src_ip", "0.0.0.0"))
        category = alert_data.get("category", "unknown").lower().replace(" ", "_")

        # Map to our attack categories
        attack_category = self._map_alert_category(category)
        mitre = get_mitre_mapping(attack_category)

        ioc = IoC(
            ioc_id="",
            ioc_type=IoCType.ATTACK_SIGNATURE,
            value=f"sid:{alert_data.get('signature_id', 0)}",
            confidence=0.8,  # IDS signatures are high confidence
            severity=severity,
            attack_category=attack_category,
            attack_description=alert_data.get("signature", "Unknown signature"),
            attack_sequence=[category],
            mitre_tactics=mitre["tactics"],
            mitre_techniques=mitre["techniques"],
            source_system="napse",
            tags=[category, f"sid_{alert_data.get('signature_id')}"],
            raw_evidence={
                "signature_id": alert_data.get("signature_id"),
                "signature": alert_data.get("signature"),
                "src_ip_anon": src_ip,
                "dest_port": alert.get("dest_port"),
                "proto": alert.get("proto"),
            }
        )

        self._add_to_cache(ioc)
        return ioc

    def from_notice(self, notice: Dict[str, Any]) -> Optional[IoC]:
        """
        Generate IoC from NAPSE notice.

        Args:
            notice: NAPSE notice event

        Returns:
            IoC or None if notice is not significant
        """
        note_type = notice.get("note", "")
        if not note_type:
            return None

        # Map notice types to our categories
        category_map = {
            "Scan::Port_Scan": "port_scan",
            "Scan::Address_Scan": "address_scan",
            "SSL::Invalid_Server_Cert": "malware_c2",
            "DNS::External_Name": "dns_tunneling",
            "HTTP::SQL_Injection_Victim": "sql_injection",
        }

        attack_category = category_map.get(note_type, "reconnaissance")
        mitre = get_mitre_mapping(attack_category)

        src_ip = self._anonymize_ip(notice.get("src", "0.0.0.0"))

        ioc = IoC(
            ioc_id="",
            ioc_type=IoCType.BEHAVIOR_PATTERN,
            value=note_type,
            confidence=0.7,
            severity=ATTACK_SEVERITY.get(attack_category, ThreatSeverity.LOW),
            attack_category=attack_category,
            attack_description=notice.get("msg", "")[:200],
            attack_sequence=[attack_category],
            mitre_tactics=mitre["tactics"],
            mitre_techniques=mitre["techniques"],
            source_system="napse",
            tags=[note_type.replace("::", "_").lower()],
            raw_evidence={
                "note": note_type,
                "msg": notice.get("msg", "")[:500],
                "src_ip_anon": src_ip,
                "dest_port": notice.get("p"),
            }
        )

        self._add_to_cache(ioc)
        return ioc

    def aggregate_iocs(
        self,
        time_window_minutes: int = 60
    ) -> List[IoC]:
        """
        Aggregate recent IoCs, correlating related indicators.

        Args:
            time_window_minutes: Time window for aggregation

        Returns:
            List of aggregated IoCs with correlation
        """
        cutoff = datetime.now() - timedelta(minutes=time_window_minutes)
        recent_iocs = []

        for ioc in self._ioc_cache.values():
            try:
                ioc_time = datetime.fromisoformat(ioc.last_seen)
                if ioc_time >= cutoff:
                    recent_iocs.append(ioc)
            except (ValueError, TypeError):
                continue

        # Group by attack category
        category_groups = defaultdict(list)
        for ioc in recent_iocs:
            category_groups[ioc.attack_category].append(ioc)

        # Create aggregated IoCs for significant groups
        aggregated = []
        for category, iocs in category_groups.items():
            if len(iocs) >= 3:  # At least 3 related IoCs
                agg_ioc = self._aggregate_group(category, iocs)
                aggregated.append(agg_ioc)
            else:
                aggregated.extend(iocs)

        return aggregated

    def _aggregate_group(
        self,
        category: str,
        iocs: List[IoC]
    ) -> IoC:
        """Aggregate a group of related IoCs"""
        # Sort by confidence
        iocs.sort(key=lambda x: x.confidence, reverse=True)
        best = iocs[0]

        # Combine sequences
        all_sequences = []
        for ioc in iocs:
            all_sequences.extend(ioc.attack_sequence)

        # Aggregate evidence
        combined_evidence = {
            "aggregated_from": len(iocs),
            "sources": list(set(ioc.source_system for ioc in iocs)),
            "first_seen": min(ioc.first_seen for ioc in iocs),
            "last_seen": max(ioc.last_seen for ioc in iocs),
        }

        # Compute combined confidence
        avg_confidence = sum(ioc.confidence for ioc in iocs) / len(iocs)

        # Build aggregated description
        description = f"Aggregated {category} activity: {len(iocs)} related indicators detected. "
        description += f"Sources: {', '.join(combined_evidence['sources'])}. "
        description += best.attack_description

        return IoC(
            ioc_id="",
            ioc_type=best.ioc_type,
            value=f"aggregated_{category}_{len(iocs)}",
            confidence=min(avg_confidence * 1.1, 1.0),  # Boost for correlation
            severity=self._escalate_severity(best.severity, len(iocs)),
            attack_category=category,
            attack_description=description,
            attack_sequence=all_sequences[-20:],  # Last 20
            mitre_tactics=best.mitre_tactics,
            mitre_techniques=best.mitre_techniques,
            occurrence_count=len(iocs),
            source_system="aggregator",
            tags=best.tags + ["aggregated"],
            raw_evidence=combined_evidence,
        )

    def save_iocs(self, iocs: List[IoC], filename: Optional[str] = None) -> Path:
        """Save IoCs to file"""
        if not filename:
            filename = f"iocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        output_path = self.output_dir / filename
        data = [ioc.to_dict() for ioc in iocs]

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

        return output_path

    def _determine_ioc_type(
        self,
        attack_category: str,
        source_data: Optional[Dict]
    ) -> IoCType:
        """Determine appropriate IoC type for attack"""
        category_type_map = {
            "port_scan": IoCType.PORT_PATTERN,
            "address_scan": IoCType.IP_ADDRESS,
            "dns_tunneling": IoCType.DOMAIN,
            "malware_c2": IoCType.IP_ADDRESS,
            "sql_injection": IoCType.ATTACK_SIGNATURE,
            "xss": IoCType.ATTACK_SIGNATURE,
            "brute_force": IoCType.BEHAVIOR_PATTERN,
        }
        return category_type_map.get(attack_category, IoCType.BEHAVIOR_PATTERN)

    def _extract_ioc_value(
        self,
        ioc_type: IoCType,
        attack_category: str,
        source_ip: Optional[str],
        source_data: Optional[Dict]
    ) -> str:
        """Extract or generate IoC value"""
        if source_ip and ioc_type == IoCType.IP_ADDRESS:
            return self._anonymize_ip(source_ip)

        if source_data:
            if ioc_type == IoCType.DOMAIN and "domain" in source_data:
                return source_data["domain"]
            if ioc_type == IoCType.PORT_PATTERN and "ports" in source_data:
                return ",".join(str(p) for p in source_data["ports"][:10])

        # Generate pattern identifier
        return f"{attack_category}_pattern_{datetime.now().strftime('%H%M')}"

    def _build_description(
        self,
        attack_category: str,
        prediction: ThreatPrediction,
        source_data: Optional[Dict]
    ) -> str:
        """Build detailed attack description for AI prompt"""
        base_desc = ATTACK_DESCRIPTIONS.get(attack_category, "Unknown activity")

        parts = [base_desc]

        # Add prediction context
        if prediction.trend == "increasing":
            parts.append("Attack intensity is INCREASING.")
        elif prediction.trend == "decreasing":
            parts.append("Attack intensity is decreasing.")

        if prediction.is_anomalous:
            parts.append(f"Pattern is ANOMALOUS (score: {prediction.anomaly_score:.2f}).")

        # Add sequence context
        if len(prediction.input_sequence) > 1:
            recent = prediction.input_sequence[-3:]
            parts.append(f"Recent attack sequence: {' → '.join(recent)}.")

        # Add temporal context
        if prediction.time_to_next_attack is not None:
            if prediction.time_to_next_attack < 60:
                parts.append("Next attack expected IMMINENTLY.")
            elif prediction.time_to_next_attack < 300:
                parts.append("Next attack expected within 5 minutes.")

        # Add top predictions
        top_preds = prediction.get_top_predictions(2)
        if top_preds and len(top_preds) > 1:
            second_pred = top_preds[1]
            if second_pred[1] > 0.2:
                parts.append(f"Alternative prediction: {second_pred[0]} ({second_pred[1]:.0%}).")

        return " ".join(parts)

    def _generate_tags(
        self,
        attack_category: str,
        prediction: ThreatPrediction
    ) -> List[str]:
        """Generate tags for IoC"""
        tags = [attack_category]

        if prediction.is_anomalous:
            tags.append("anomalous")

        if prediction.trend == "increasing":
            tags.append("escalating")

        if prediction.confidence >= 0.9:
            tags.append("high_confidence")
        elif prediction.confidence <= 0.5:
            tags.append("low_confidence")

        return tags

    def _anonymize_ip(self, ip: str) -> str:
        """Anonymize IP address (keep network class only)"""
        if not ip or ip == "0.0.0.0":
            return "0.0.0.0"
        parts = ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.0.0"
        return "0.0.0.0"

    def _map_alert_category(self, category: str) -> str:
        """Map IDS alert category to our attack categories."""
        category_map = {
            "attempted-recon": "reconnaissance",
            "misc-attack": "dos_attack",
            "attempted-dos": "dos_attack",
            "attempted-admin": "privilege_escalation",
            "successful-admin": "privilege_escalation",
            "trojan-activity": "malware_c2",
            "a]_network-scan": "port_scan",
            "web-application-attack": "sql_injection",
            "not_suspicious": "unknown",
        }
        return category_map.get(category.lower(), "unknown")

    def _escalate_severity(
        self,
        base_severity: ThreatSeverity,
        count: int
    ) -> ThreatSeverity:
        """Escalate severity based on occurrence count"""
        severity_order = [
            ThreatSeverity.INFO,
            ThreatSeverity.LOW,
            ThreatSeverity.MEDIUM,
            ThreatSeverity.HIGH,
            ThreatSeverity.CRITICAL,
        ]

        current_idx = severity_order.index(base_severity)

        # Escalate for multiple occurrences
        if count >= 10:
            escalate = 2
        elif count >= 5:
            escalate = 1
        else:
            escalate = 0

        new_idx = min(current_idx + escalate, len(severity_order) - 1)
        return severity_order[new_idx]

    def _add_to_cache(self, ioc: IoC):
        """Add IoC to cache with LRU eviction"""
        if len(self._ioc_cache) >= self._max_cache_size:
            # Remove oldest entries
            oldest_keys = sorted(
                self._ioc_cache.keys(),
                key=lambda k: self._ioc_cache[k].last_seen
            )[:1000]
            for key in oldest_keys:
                del self._ioc_cache[key]

        self._ioc_cache[ioc.ioc_id] = ioc


def generate_ioc_from_attack_sequence(
    attack_sequence: List[str],
    source_ip: Optional[str] = None
) -> IoC:
    """
    Convenience function to generate IoC from attack sequence.

    Used by Fortress LSTM detector to create IoCs for defense orchestration.
    """
    # Create a mock prediction from sequence
    if not attack_sequence:
        attack_sequence = ["unknown"]

    prediction = ThreatPrediction(
        predicted_attack=attack_sequence[-1],
        confidence=0.7,
        input_sequence=attack_sequence,
        sequence_length=len(attack_sequence),
    )

    generator = IoCGenerator()
    return generator.from_prediction(prediction, source_ip)
