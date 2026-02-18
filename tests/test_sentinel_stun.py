"""
Tests for Sentinel AEGIS Pico Integration + Neuro STUN Parser.

Validates:
1. AegisPicoReceiver handles block_ip, update_signatures, dns_sinkhole
2. AegisPicoReceiver rejects empty/missing actions
3. STUN XOR-MAPPED-ADDRESS parsing (RFC 5389)
4. STUN MAPPED-ADDRESS fallback
5. STUN empty/short response defaults
"""

import struct

import pytest


# -----------------------------------------------------------------
# AegisPicoReceiver tests
# -----------------------------------------------------------------


class TestAegisPicoReceiver:
    """Test the mesh-to-Pico recommendation bridge."""

    def _make_receiver(self):
        from products.sentinel.lib.aegis_pico_integration import AegisPicoReceiver
        return AegisPicoReceiver()

    def test_handle_block_ip(self):
        receiver = self._make_receiver()
        result = receiver.handle_recommendation({"action": "block_ip", "target": "10.0.0.1"})
        assert result is True
        assert receiver.get_stats()["applied"] == 1

    def test_handle_update_signatures(self):
        receiver = self._make_receiver()
        result = receiver.handle_recommendation({
            "action": "update_signatures",
            "signatures": ["sig1", "sig2"],
        })
        assert result is True
        assert receiver.get_stats()["applied"] == 1

    def test_handle_dns_sinkhole(self):
        receiver = self._make_receiver()
        result = receiver.handle_recommendation({
            "action": "dns_sinkhole",
            "target": "malware.example.com",
        })
        assert result is True

    def test_reject_missing_action(self):
        receiver = self._make_receiver()
        result = receiver.handle_recommendation({"target": "10.0.0.1"})
        assert result is False
        assert receiver.get_stats()["applied"] == 0

    def test_reject_block_ip_no_target(self):
        receiver = self._make_receiver()
        result = receiver.handle_recommendation({"action": "block_ip"})
        assert result is False

    def test_received_count_increments(self):
        receiver = self._make_receiver()
        receiver.handle_recommendation({"action": "block_ip", "target": "1.2.3.4"})
        receiver.handle_recommendation({"action": "unknown_action"})
        assert receiver.get_stats()["received"] == 2


# -----------------------------------------------------------------
# STUN parser tests
# -----------------------------------------------------------------


def _build_stun_response(attr_type, ip_str, port, family=0x01):
    """Build a minimal STUN Binding Response with one attribute."""
    magic = 0x2112A442
    txn_id = b'\x00' * 12

    # STUN header
    msg_type = 0x0101  # Binding Success Response
    ip_parts = [int(x) for x in ip_str.split('.')]
    ip_int = (ip_parts[0] << 24) | (ip_parts[1] << 16) | (ip_parts[2] << 8) | ip_parts[3]

    if attr_type == 0x0020:  # XOR-MAPPED-ADDRESS
        xport = port ^ (magic >> 16)
        xip = ip_int ^ magic
        attr_value = struct.pack('>BBH I', 0, family, xport, xip)
    else:  # MAPPED-ADDRESS (0x0001)
        attr_value = struct.pack('>BBH 4s', 0, family, port,
                                 bytes(ip_parts))

    attr_header = struct.pack('>HH', attr_type, len(attr_value))
    attrs = attr_header + attr_value

    header = struct.pack('>HH I', msg_type, len(attrs), magic) + txn_id
    return header + attrs


class TestSTUNParser:
    """Test STUN XOR-MAPPED-ADDRESS parsing in nat_traversal.py."""

    def _make_client(self):
        import importlib.util, os
        spec = importlib.util.spec_from_file_location(
            "nat_traversal",
            os.path.join(os.path.dirname(__file__), "..", "core", "neuro", "network", "nat_traversal.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.STUNClient()

    def test_parse_xor_mapped_address(self):
        client = self._make_client()
        response = _build_stun_response(0x0020, "203.0.113.42", 12345)
        ip, port = client._parse_stun_response(response)
        assert ip == "203.0.113.42"
        assert port == 12345

    def test_parse_mapped_address_fallback(self):
        client = self._make_client()
        response = _build_stun_response(0x0001, "198.51.100.1", 54321)
        ip, port = client._parse_stun_response(response)
        assert ip == "198.51.100.1"
        assert port == 54321

    def test_parse_empty_returns_default(self):
        client = self._make_client()
        ip, port = client._parse_stun_response(b"")
        assert ip == "0.0.0.0"
        assert port == 0

    def test_parse_short_response_returns_default(self):
        client = self._make_client()
        ip, port = client._parse_stun_response(b"\x00" * 10)
        assert ip == "0.0.0.0"
        assert port == 0

    def test_parse_header_only_returns_default(self):
        """STUN header with no attributes returns default."""
        client = self._make_client()
        magic = 0x2112A442
        header = struct.pack('>HH I', 0x0101, 0, magic) + b'\x00' * 12
        ip, port = client._parse_stun_response(header)
        assert ip == "0.0.0.0"
        assert port == 0

    def test_xor_roundtrip_various_ips(self):
        """Verify XOR-MAPPED-ADDRESS roundtrip for several IPs."""
        client = self._make_client()
        test_cases = [
            ("1.2.3.4", 80),
            ("255.255.255.255", 65535),
            ("10.0.0.1", 443),
            ("192.168.1.1", 8080),
        ]
        for ip, port in test_cases:
            response = _build_stun_response(0x0020, ip, port)
            parsed_ip, parsed_port = client._parse_stun_response(response)
            assert parsed_ip == ip, f"IP mismatch for {ip}"
            assert parsed_port == port, f"Port mismatch for {port}"
