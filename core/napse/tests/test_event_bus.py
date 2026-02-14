"""
NAPSE Event Bus Tests

Tests the central event distribution system.

Author: HookProbe Team
License: Proprietary
"""

import time
import pytest
from core.napse.synthesis.event_bus import (
    NapseEventBus, EventType,
    ConnectionRecord, DNSRecord, HTTPRecord, TLSRecord,
    DHCPRecord, NapseAlert, NapseNotice, MDNSRecord,
)


class TestEventBus:
    """Test NapseEventBus event distribution."""

    def test_subscribe_and_emit(self):
        """Handlers receive events they subscribed to."""
        bus = NapseEventBus()
        received = []

        def handler(event_type, event):
            received.append((event_type, event))

        bus.subscribe(EventType.CONNECTION, handler)

        record = ConnectionRecord(
            ts=time.time(), uid="C1234", id_orig_h="10.0.0.1",
            id_orig_p=12345, id_resp_h="10.0.0.2", id_resp_p=80,
            proto="tcp",
        )
        bus.on_connection(record)

        assert len(received) == 1
        assert received[0][0] == EventType.CONNECTION
        assert received[0][1].uid == "C1234"

    def test_type_isolation(self):
        """Handlers only receive their subscribed event type."""
        bus = NapseEventBus()
        conn_count = []
        dns_count = []

        bus.subscribe(EventType.CONNECTION, lambda t, e: conn_count.append(1))
        bus.subscribe(EventType.DNS, lambda t, e: dns_count.append(1))

        bus.on_connection(ConnectionRecord(
            ts=time.time(), uid="C1", id_orig_h="10.0.0.1",
            id_orig_p=1, id_resp_h="10.0.0.2", id_resp_p=80, proto="tcp",
        ))
        bus.on_dns(DNSRecord(
            ts=time.time(), uid="D1", id_orig_h="10.0.0.1",
            id_orig_p=1, id_resp_h="8.8.8.8", id_resp_p=53,
            query="example.com",
        ))

        assert len(conn_count) == 1
        assert len(dns_count) == 1

    def test_global_handler(self):
        """Global handlers receive all events."""
        bus = NapseEventBus()
        all_events = []

        bus.subscribe_all(lambda t, e: all_events.append(t))

        bus.on_connection(ConnectionRecord(
            ts=time.time(), uid="C1", id_orig_h="10.0.0.1",
            id_orig_p=1, id_resp_h="10.0.0.2", id_resp_p=80, proto="tcp",
        ))
        bus.on_alert(NapseAlert(
            timestamp="2024-01-01T00:00:00Z",
            alert_signature="Test",
        ))

        assert len(all_events) == 2
        assert EventType.CONNECTION in all_events
        assert EventType.ALERT in all_events

    def test_stats_tracking(self):
        """Event bus tracks statistics correctly."""
        bus = NapseEventBus()
        bus.subscribe(EventType.DNS, lambda t, e: None)

        for _ in range(10):
            bus.on_dns(DNSRecord(
                ts=time.time(), uid="D1", id_orig_h="10.0.0.1",
                id_orig_p=1, id_resp_h="8.8.8.8", id_resp_p=53,
            ))

        stats = bus.get_stats()
        assert stats['events_received'] == 10
        assert stats['events_dispatched'] == 10

    def test_handler_error_isolation(self):
        """One handler error doesn't affect other handlers."""
        bus = NapseEventBus()
        good_results = []

        def bad_handler(t, e):
            raise ValueError("intentional error")

        def good_handler(t, e):
            good_results.append(1)

        bus.subscribe(EventType.DNS, bad_handler)
        bus.subscribe(EventType.DNS, good_handler)

        bus.on_dns(DNSRecord(
            ts=time.time(), uid="D1", id_orig_h="10.0.0.1",
            id_orig_p=1, id_resp_h="8.8.8.8", id_resp_p=53,
        ))

        assert len(good_results) == 1


class TestDataRecords:
    """Test NAPSE data record structures."""

    def test_connection_record_defaults(self):
        """ConnectionRecord has sensible defaults."""
        r = ConnectionRecord(
            ts=time.time(), uid="C1", id_orig_h="10.0.0.1",
            id_orig_p=12345, id_resp_h="10.0.0.2", id_resp_p=80,
            proto="tcp",
        )
        assert r.duration == 0.0
        assert r.orig_bytes == 0
        assert r.community_id == ""

    def test_dns_record_mdns(self):
        """DNSRecord supports mDNS extension fields."""
        r = DNSRecord(
            ts=time.time(), uid="D1", id_orig_h="10.0.0.1",
            id_orig_p=5353, id_resp_h="224.0.0.251", id_resp_p=5353,
            query="_airplay._tcp.local", is_mdns=True, ecosystem="apple",
        )
        assert r.is_mdns is True
        assert r.ecosystem == "apple"

    def test_tls_record_ja3(self):
        """TLSRecord carries JA3 hash and malware detection."""
        r = TLSRecord(
            ts=time.time(), uid="T1", id_orig_h="10.0.0.1",
            id_orig_p=50000, id_resp_h="1.2.3.4", id_resp_p=443,
            server_name="evil.com",
            ja3="72a589da586844d7f0818ce684948eea",
            is_malicious_ja3=True, malware_family="CobaltStrike",
        )
        assert r.is_malicious_ja3 is True
        assert r.malware_family == "CobaltStrike"

    def test_napse_alert_eve_compat(self):
        """NapseAlert has all fields needed for EVE JSON compatibility."""
        a = NapseAlert(
            timestamp="2024-01-15T10:30:00Z",
            src_ip="192.168.1.100",
            src_port=54321,
            dest_ip="10.0.0.1",
            dest_port=80,
            proto="tcp",
            alert_signature="NAPSE SQL Injection Attempt",
            alert_signature_id=1000007,
            alert_category="sql_injection",
            alert_severity=1,
            confidence=0.95,
        )
        assert a.alert_action == "alert"
        assert a.alert_gid == 1
        assert a.confidence == 0.95


class TestNoticeEmitter:
    """Test NAPSE notice generation."""

    def test_new_device_notice(self):
        """New DHCP device triggers New_Device notice."""
        from core.napse.synthesis.notice_emitter import NoticeEmitter

        emitter = NoticeEmitter()
        bus = NapseEventBus()
        emitter.register(bus)

        notices = []
        bus.subscribe(EventType.NOTICE, lambda t, e: notices.append(e))

        bus.on_dhcp(DHCPRecord(
            ts=time.time(), mac="aa:bb:cc:dd:ee:ff",
            hostname="iPhone", msg_type="ACK",
            client_addr="10.0.0.100",
        ))

        assert len(notices) == 1
        assert notices[0].note == "New_Device"

    def test_duplicate_device_suppressed(self):
        """Same MAC doesn't trigger duplicate New_Device notice."""
        from core.napse.synthesis.notice_emitter import NoticeEmitter

        emitter = NoticeEmitter()
        bus = NapseEventBus()
        emitter.register(bus)

        notices = []
        bus.subscribe(EventType.NOTICE, lambda t, e: notices.append(e))

        for _ in range(3):
            bus.on_dhcp(DHCPRecord(
                ts=time.time(), mac="aa:bb:cc:dd:ee:ff",
                hostname="iPhone", msg_type="ACK",
                client_addr="10.0.0.100",
            ))

        assert len(notices) == 1
