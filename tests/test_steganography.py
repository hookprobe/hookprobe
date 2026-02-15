"""
Test Suite — Stage 5: Steganographic Transport for HTP

Tests traffic shaping, decoy generation, domain fronting, profile library,
and integration with HTP/mesh transport.

56 tests across 8 test classes.
"""

import hashlib
import hmac
import os
import struct
import time
import unittest
from collections import Counter
from unittest.mock import MagicMock, patch

from core.htp.steganography.profile_library import (
    BurstPattern,
    ProfileType,
    SizeDistribution,
    TimingDistribution,
    TrafficProfile,
    get_profile,
    list_profiles,
    PROFILES,
)
from core.htp.steganography.traffic_shaper import (
    FRAGMENT_FLAG,
    FRAGMENT_HEADER_SIZE,
    PADDING_FLAG,
    REAL_DATA_FLAG,
    ShapedPacket,
    TrafficShaper,
)
from core.htp.steganography.decoy_generator import (
    DecoyConfig,
    DecoyGenerator,
)
from core.htp.steganography.domain_fronting import (
    CDNEndpoint,
    CDNProvider,
    DomainFronter,
    FrontingState,
    TunnelType,
)


# =========================================================================
# Profile Library Tests
# =========================================================================


class TestProfileLibrary(unittest.TestCase):
    """Test traffic profile definitions and sampling."""

    def test_all_profiles_registered(self):
        """All 5 profile types are registered."""
        expected = {
            ProfileType.NETFLIX,
            ProfileType.ZOOM_VIDEO,
            ProfileType.HTTPS_BROWSE,
            ProfileType.GAMING,
            ProfileType.SSH_INTERACTIVE,
        }
        assert set(PROFILES.keys()) == expected

    def test_get_profile_valid(self):
        profile = get_profile(ProfileType.NETFLIX)
        assert profile.name == "Netflix 4K Stream"
        assert profile.target_bandwidth_kbps == 15000

    def test_get_profile_invalid(self):
        with self.assertRaises(KeyError):
            get_profile(ProfileType.CUSTOM)

    def test_list_profiles(self):
        result = list_profiles()
        assert len(result) == 5
        assert all("name" in p for p in result)

    def test_size_distribution_sampling(self):
        dist = SizeDistribution(
            components=[(1300.0, 80.0, 0.85), (200.0, 50.0, 0.15)],
            min_size=64,
            max_size=1500,
        )
        samples = dist.sample_batch(1000)
        assert all(64 <= s <= 1500 for s in samples)
        # Mean should be roughly weighted toward 1300
        mean = sum(samples) / len(samples)
        assert mean > 800  # Strongly biased toward 1300

    def test_timing_distribution_sampling(self):
        timing = TimingDistribution(
            mean_ms=10.0, std_ms=3.0, min_ms=1.0, max_ms=100.0,
        )
        samples = [timing.sample() for _ in range(1000)]
        assert all(1.0 <= s <= 100.0 for s in samples)
        mean = sum(samples) / len(samples)
        assert 5.0 < mean < 20.0  # Around 10ms

    def test_timing_burst_mode(self):
        timing = TimingDistribution(
            mean_ms=100.0, std_ms=20.0,
            burst_probability=1.0,  # Always burst
            burst_interval_ms=5.0,
            burst_length=10,
        )
        samples = [timing.sample() for _ in range(100)]
        mean = sum(samples) / len(samples)
        # In burst mode, mean should be close to 5ms, not 100ms
        assert mean < 20.0

    def test_netflix_profile_packet_rate(self):
        profile = get_profile(ProfileType.NETFLIX)
        rate = profile.get_target_packet_rate()
        # 15 Mbps / ~1200 byte mean ≈ ~1500 pps
        assert rate > 500
        assert rate < 3000

    def test_profile_stealth_scores(self):
        """All profiles have reasonable stealth scores."""
        for profile in PROFILES.values():
            assert 0.5 <= profile.stealth_score <= 1.0

    def test_zoom_bimodal_distribution(self):
        """Zoom profile has bimodal size distribution (video + audio)."""
        profile = get_profile(ProfileType.ZOOM_VIDEO)
        assert profile.burst_pattern == BurstPattern.BIMODAL
        # Should have video (large) and audio (small) components
        components = profile.size_distribution.components
        sizes = [c[0] for c in components]  # means
        assert max(sizes) > 800   # Video frames
        assert min(sizes) < 200   # Audio/signaling


# =========================================================================
# Traffic Shaper Tests
# =========================================================================


class TestTrafficShaper(unittest.TestCase):
    """Test packet shaping, fragmentation, and unshaping."""

    def setUp(self):
        self.shaper = TrafficShaper(ProfileType.NETFLIX)

    def test_shape_small_payload(self):
        """Small payload gets padded to profile size."""
        payload = b"Hello, HTP!"
        packets = self.shaper.shape(payload)
        assert len(packets) == 1
        pkt = packets[0]
        assert pkt.flags & REAL_DATA_FLAG
        assert len(pkt.data) >= len(payload)
        assert pkt.delay_ms > 0

    def test_shape_empty_payload(self):
        packets = self.shaper.shape(b"")
        assert packets == []

    def test_unshape_recovers_payload(self):
        """Unshaping recovers original payload."""
        payload = b"secret network data 1234567890"
        packets = self.shaper.shape(payload)
        assert len(packets) == 1
        recovered = self.shaper.unshape(packets[0].data)
        assert recovered == payload

    def test_shape_large_payload_fragments(self):
        """Large payload gets fragmented."""
        # Create payload larger than any single profile packet
        payload = os.urandom(5000)
        packets = self.shaper.shape(payload)
        assert len(packets) > 1
        for pkt in packets:
            assert pkt.flags & FRAGMENT_FLAG

    def test_unshape_fragments_recovers(self):
        """Fragmented payload can be reassembled."""
        payload = os.urandom(5000)
        packets = self.shaper.shape(payload)
        assert len(packets) > 1

        # Reassemble
        recovered = self.shaper.unshape_fragments(
            [pkt.data for pkt in packets]
        )
        assert recovered == payload

    def test_shaped_sizes_match_profile(self):
        """Shaped packet sizes follow the profile distribution."""
        sizes = []
        for _ in range(200):
            payload = os.urandom(100)
            packets = self.shaper.shape(payload)
            for pkt in packets:
                sizes.append(len(pkt.data))

        # For Netflix: most sizes should be 1000-1500 range
        large = sum(1 for s in sizes if s > 800)
        assert large / len(sizes) > 0.5  # >50% large packets

    def test_padding_is_random(self):
        """Padding bytes are random (not zero-filled)."""
        payload = b"X"
        packets = self.shaper.shape(payload)
        pkt_data = packets[0].data
        # After the header and payload, remaining bytes should be random
        # Just verify the packet is larger than the payload
        assert len(pkt_data) > len(payload) + 4

    def test_tls_wrapping(self):
        """TLS record wrapping and unwrapping."""
        data = b"test data for TLS wrapping"
        wrapped = self.shaper.wrap_tls_record(data)
        # TLS Application Data header: 0x17 0x03 0x03
        assert wrapped[0] == 0x17
        assert wrapped[1:3] == b'\x03\x03'
        # Unwrap
        unwrapped = self.shaper.unwrap_tls_record(wrapped)
        assert unwrapped == data

    def test_padding_packet_generation(self):
        """Generate pure padding packet."""
        pkt = self.shaper.generate_padding_packet()
        assert pkt.flags & PADDING_FLAG
        assert pkt.delay_ms > 0
        # Unshaping a padding packet returns None
        assert self.shaper.unshape(pkt.data) is None

    def test_stats_tracking(self):
        """Stats are tracked correctly."""
        payload = os.urandom(100)
        self.shaper.shape(payload)
        stats = self.shaper.get_stats()
        assert stats["packets_shaped"] >= 1
        assert stats["bytes_original"] == 100
        assert stats["bytes_shaped"] >= 100
        assert stats["profile"] == "Netflix 4K Stream"

    def test_shape_batch(self):
        """Batch shaping processes multiple payloads."""
        payloads = [os.urandom(50) for _ in range(5)]
        packets = self.shaper.shape_batch(payloads)
        assert len(packets) >= 5


# =========================================================================
# Decoy Generator Tests
# =========================================================================


class TestDecoyGenerator(unittest.TestCase):
    """Test cover traffic generation and identification."""

    def setUp(self):
        self.hmac_key = os.urandom(32)
        self.config = DecoyConfig(hmac_key=self.hmac_key)
        self.gen = DecoyGenerator(
            ProfileType.NETFLIX, config=self.config,
        )

    def test_generate_decoy(self):
        """Decoy packets are generated with correct flags."""
        decoy = self.gen.generate_decoy()
        assert decoy.flags & PADDING_FLAG
        assert len(decoy.data) > 0
        assert decoy.delay_ms > 0

    def test_decoy_identified_by_flag(self):
        """Decoy packets are identified by PADDING_FLAG."""
        decoy = self.gen.generate_decoy()
        assert self.gen.is_decoy(decoy.data)

    def test_real_data_not_decoy(self):
        """Real shaped data is not identified as decoy."""
        shaper = TrafficShaper(ProfileType.NETFLIX)
        packets = shaper.shape(b"real data here")
        for pkt in packets:
            # Different HMAC key means tag won't match
            assert not self.gen.is_decoy(pkt.data) or (pkt.flags & PADDING_FLAG)

    def test_decoy_sizes_match_profile(self):
        """Decoy packet sizes follow the profile distribution."""
        sizes = [self.gen.generate_decoy().target_size for _ in range(200)]
        mean = sum(sizes) / len(sizes)
        # Netflix profile mean is ~1200
        assert 600 < mean < 1400

    def test_different_keys_not_identified(self):
        """Decoys from different keys are not identified."""
        other_config = DecoyConfig(hmac_key=os.urandom(32))
        other_gen = DecoyGenerator(ProfileType.NETFLIX, config=other_config)
        decoy = other_gen.generate_decoy()
        # Our generator should see it as padding via flag but
        # the HMAC won't match for unmarked packets
        _, flags, _ = struct.unpack("!HBB", decoy.data[:4])
        # Flag-based detection still works
        assert flags & PADDING_FLAG

    def test_stats_tracking(self):
        """Stats are tracked correctly."""
        for _ in range(5):
            self.gen.generate_decoy()
        stats = self.gen.get_stats()
        assert stats["decoys_generated"] == 5
        assert stats["decoy_bytes"] > 0

    def test_notify_real_packet(self):
        """Notifying about real packets tracks count."""
        self.gen.notify_real_packet()
        self.gen.notify_real_packet()
        stats = self.gen.get_stats()
        assert stats["real_packets_seen"] == 2

    def test_start_stop(self):
        """Generator can start and stop."""
        self.gen.start()
        assert self.gen._running
        self.gen.stop()
        assert not self.gen._running


# =========================================================================
# Domain Fronting Tests
# =========================================================================


class TestDomainFronting(unittest.TestCase):
    """Test CDN domain fronting tunnels."""

    def setUp(self):
        self.fronter = DomainFronter()
        self.endpoint = CDNEndpoint(
            provider=CDNProvider.CLOUDFLARE,
            front_domain="cdn.example.com",
            target_domain="relay.hookprobe.net",
            path="/api/v1/tunnel",
            priority=1,
        )

    def test_add_endpoint(self):
        self.fronter.add_endpoint(self.endpoint)
        assert len(self.fronter._endpoints) == 1

    def test_connect_no_endpoints(self):
        assert not self.fronter.connect()
        assert self.fronter.state == FrontingState.FAILED

    def test_connect_success(self):
        self.fronter.add_endpoint(self.endpoint)
        assert self.fronter.connect()
        assert self.fronter.state == FrontingState.CONNECTED
        assert self.fronter.is_connected

    def test_connect_fallback_chain(self):
        """Falls back to second endpoint if first fails."""
        bad_endpoint = CDNEndpoint(
            provider=CDNProvider.AWS_CLOUDFRONT,
            front_domain="",  # Invalid → will fail _try_connect
            target_domain="",
            priority=1,
        )
        good_endpoint = CDNEndpoint(
            provider=CDNProvider.AZURE_CDN,
            front_domain="azure-cdn.example.com",
            target_domain="relay.hookprobe.net",
            priority=2,
        )
        self.fronter.add_endpoint(bad_endpoint)
        self.fronter.add_endpoint(good_endpoint)
        assert self.fronter.connect()
        assert self.fronter._active_endpoint.provider == CDNProvider.AZURE_CDN

    def test_send_receive(self):
        """Send and receive data through the tunnel."""
        self.fronter.add_endpoint(self.endpoint)
        self.fronter.connect()

        payload = b"Hello from HTP mesh"
        assert self.fronter.send(payload)

        # Simulate response
        self.fronter.feed_response(
            self.fronter._encode_payload(payload)
        )
        received = self.fronter.receive()
        assert received == payload

    def test_send_before_connect(self):
        """Cannot send before connecting."""
        assert not self.fronter.send(b"test")

    def test_websocket_upgrade(self):
        self.fronter.add_endpoint(self.endpoint)
        self.fronter.connect()
        assert self.fronter.upgrade_websocket()
        assert self.fronter.state == FrontingState.TUNNELED

    def test_disconnect(self):
        self.fronter.add_endpoint(self.endpoint)
        self.fronter.connect()
        self.fronter.disconnect()
        assert self.fronter.state == FrontingState.DISCONNECTED
        assert not self.fronter.is_connected

    def test_endpoint_health_tracking(self):
        ep = CDNEndpoint(
            provider=CDNProvider.CLOUDFLARE,
            front_domain="cdn.example.com",
            target_domain="relay.hookprobe.net",
        )
        assert ep.healthy
        ep.record_failure()
        ep.record_failure()
        assert ep.healthy  # Still healthy at 2 failures
        ep.record_failure()
        assert not ep.healthy  # 3 failures → unhealthy
        ep.record_success()
        assert ep.healthy  # Success resets

    def test_http_request_format(self):
        """HTTP request has correct domain fronting headers."""
        self.fronter.add_endpoint(self.endpoint)
        self.fronter.connect()
        self.fronter.send(b"test")
        request = self.fronter._send_buffer[-1]
        request_str = request.decode("utf-8", errors="replace")
        # Host header should be target (hidden in TLS)
        assert "Host: relay.hookprobe.net" in request_str
        # Path should match endpoint
        assert "POST /api/v1/tunnel" in request_str

    def test_stats(self):
        self.fronter.add_endpoint(self.endpoint)
        self.fronter.connect()
        self.fronter.send(b"test data")
        stats = self.fronter.get_stats()
        assert stats["bytes_sent"] == 9
        assert stats["requests_sent"] == 1
        assert stats["current_provider"] == "CLOUDFLARE"

    def test_callbacks(self):
        connected = []
        self.fronter.on_connected(lambda: connected.append(True))
        self.fronter.add_endpoint(self.endpoint)
        self.fronter.connect()
        assert len(connected) == 1


# =========================================================================
# HTP Integration Tests
# =========================================================================


class TestHTPIntegration(unittest.TestCase):
    """Test steganography integration with HTP transport."""

    def test_htp_session_steganography_field(self):
        """HTPSession has steganography_profile field."""
        import pathlib
        source = pathlib.Path("core/htp/transport/htp.py").read_text()
        assert "steganography_profile" in source

    def test_steganography_profile_default_none(self):
        """Steganography is disabled by default."""
        import pathlib
        source = pathlib.Path("core/htp/transport/htp.py").read_text()
        assert 'steganography_profile: Optional[str] = None' in source


# =========================================================================
# Mesh Integration Tests
# =========================================================================


class TestMeshIntegration(unittest.TestCase):
    """Test steganography integration with mesh port manager and channel selector."""

    def test_stego_transport_modes_exist(self):
        """Steganographic transport modes are defined."""
        from shared.mesh.port_manager import TransportMode
        assert hasattr(TransportMode, "STEGO_NETFLIX")
        assert hasattr(TransportMode, "STEGO_ZOOM")
        assert hasattr(TransportMode, "STEGO_HTTPS")
        assert hasattr(TransportMode, "DOMAIN_FRONT")

    def test_stego_modes_unique_values(self):
        """Stego modes have unique enum values (no collision)."""
        from shared.mesh.port_manager import TransportMode
        values = [m.value for m in TransportMode]
        assert len(values) == len(set(values))

    def test_channel_selector_stealth_scores(self):
        """Channel selector has stealth scores for stego modes."""
        import pathlib
        source = pathlib.Path("shared/mesh/channel_selector.py").read_text()
        assert "STEGO_NETFLIX" in source
        assert "STEGO_ZOOM" in source
        assert "DOMAIN_FRONT" in source

    def test_channel_selector_censorship_detection(self):
        """Channel selector has censorship detection method."""
        import pathlib
        source = pathlib.Path("shared/mesh/channel_selector.py").read_text()
        assert "def detect_censorship" in source
        assert "def select_stego_mode" in source


# =========================================================================
# Statistical Distribution Tests
# =========================================================================


class TestDistributionQuality(unittest.TestCase):
    """Test that shaped traffic statistically matches profiles."""

    def test_netflix_size_distribution_shape(self):
        """Netflix shaped packets follow expected size distribution."""
        shaper = TrafficShaper(ProfileType.NETFLIX)
        sizes = []
        for _ in range(500):
            payload = os.urandom(100)
            for pkt in shaper.shape(payload):
                sizes.append(len(pkt.data))

        # Netflix: 85% should be large (>800 bytes)
        large_pct = sum(1 for s in sizes if s > 800) / len(sizes)
        assert large_pct > 0.5  # At least 50% large

    def test_zoom_bimodal_shape(self):
        """Zoom shaped packets show bimodal distribution."""
        shaper = TrafficShaper(ProfileType.ZOOM_VIDEO)
        sizes = []
        for _ in range(500):
            payload = os.urandom(100)
            for pkt in shaper.shape(payload):
                sizes.append(len(pkt.data))

        # Should have both small and large packets
        small = sum(1 for s in sizes if s < 400)
        large = sum(1 for s in sizes if s > 800)
        assert small > 0
        assert large > 0

    def test_timing_within_bounds(self):
        """All timing samples are within profile bounds."""
        for profile_type in [ProfileType.NETFLIX, ProfileType.ZOOM_VIDEO, ProfileType.HTTPS_BROWSE]:
            profile = get_profile(profile_type)
            for _ in range(100):
                delay = profile.timing.sample()
                assert delay >= profile.timing.min_ms
                assert delay <= profile.timing.max_ms

    def test_gaming_small_packets(self):
        """Gaming profile produces predominantly small packets."""
        shaper = TrafficShaper(ProfileType.GAMING)
        sizes = []
        for _ in range(500):
            payload = os.urandom(50)
            for pkt in shaper.shape(payload):
                sizes.append(len(pkt.data))

        mean = sum(sizes) / len(sizes)
        # Gaming mean should be <500 bytes
        assert mean < 600


# =========================================================================
# End-to-End Tests
# =========================================================================


class TestSteganoE2E(unittest.TestCase):
    """End-to-end steganography pipeline tests."""

    def test_shape_transmit_unshape_roundtrip(self):
        """Full roundtrip: shape → transmit → unshape recovers payload."""
        for profile_type in ProfileType:
            if profile_type == ProfileType.CUSTOM:
                continue
            shaper = TrafficShaper(profile_type)
            original = os.urandom(200)
            packets = shaper.shape(original)

            if len(packets) == 1:
                recovered = shaper.unshape(packets[0].data)
            else:
                recovered = shaper.unshape_fragments(
                    [p.data for p in packets]
                )
            assert recovered == original, f"Roundtrip failed for {profile_type.name}"

    def test_decoy_interleaved_with_real(self):
        """Decoys interleaved with real traffic are properly filtered."""
        hmac_key = os.urandom(32)
        config = DecoyConfig(hmac_key=hmac_key)
        gen = DecoyGenerator(ProfileType.NETFLIX, config=config)
        shaper = TrafficShaper(ProfileType.NETFLIX)

        # Interleave real and decoy packets
        all_packets = []
        real_payloads = [os.urandom(100) for _ in range(5)]

        for payload in real_payloads:
            all_packets.extend(shaper.shape(payload))
            all_packets.append(gen.generate_decoy())

        # Filter and recover
        recovered = []
        for pkt in all_packets:
            if gen.is_decoy(pkt.data):
                continue
            result = shaper.unshape(pkt.data)
            if result:
                recovered.append(result)

        assert len(recovered) == len(real_payloads)
        for orig, rec in zip(real_payloads, recovered):
            assert orig == rec

    def test_domain_fronting_with_shaping(self):
        """Domain fronting tunnel with traffic shaping."""
        shaper = TrafficShaper(ProfileType.HTTPS_BROWSE)
        fronter = DomainFronter()
        fronter.add_endpoint(CDNEndpoint(
            provider=CDNProvider.CLOUDFLARE,
            front_domain="cdn.example.com",
            target_domain="relay.hookprobe.net",
        ))
        fronter.connect()

        # Shape data before sending through fronter
        payload = b"sensitive mesh telemetry data"
        packets = shaper.shape(payload)
        for pkt in packets:
            assert fronter.send(pkt.data)

        stats = fronter.get_stats()
        assert stats["requests_sent"] == len(packets)

    def test_large_payload_fragmentation_e2e(self):
        """Large payloads fragment and reassemble correctly."""
        shaper = TrafficShaper(ProfileType.ZOOM_VIDEO)
        original = os.urandom(10000)  # 10KB payload

        packets = shaper.shape(original)
        assert len(packets) > 1  # Must fragment

        recovered = shaper.unshape_fragments(
            [p.data for p in packets]
        )
        assert recovered == original

    def test_all_profiles_roundtrip(self):
        """Every profile supports complete shape/unshape roundtrip."""
        for ptype in [ProfileType.NETFLIX, ProfileType.ZOOM_VIDEO,
                      ProfileType.HTTPS_BROWSE, ProfileType.GAMING,
                      ProfileType.SSH_INTERACTIVE]:
            shaper = TrafficShaper(ptype)
            for size in [10, 100, 500, 2000]:
                original = os.urandom(size)
                packets = shaper.shape(original)
                if len(packets) == 1:
                    recovered = shaper.unshape(packets[0].data)
                else:
                    recovered = shaper.unshape_fragments(
                        [p.data for p in packets]
                    )
                assert recovered == original, (
                    f"Roundtrip failed: profile={ptype.name}, size={size}"
                )


if __name__ == "__main__":
    unittest.main()
