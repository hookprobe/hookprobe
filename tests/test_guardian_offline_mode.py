#!/usr/bin/env python3
"""
Tests for Guardian Offline WiFi Mode

Tests the WiFi channel scanner and offline mode manager functionality
for busy environments where Guardian needs to start AP without WAN.

Author: HookProbe Team
Version: 1.0.0
License: MIT
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
from dataclasses import dataclass

# Add guardian lib to path
guardian_lib = Path(__file__).parent.parent / 'products' / 'guardian' / 'lib'
sys.path.insert(0, str(guardian_lib))


# =============================================================================
# WiFi Channel Scanner Tests
# =============================================================================

class TestWiFiChannelScanner:
    """Tests for WiFiChannelScanner"""

    def test_import_scanner(self):
        """Test that scanner module can be imported"""
        from wifi_channel_scanner import WiFiChannelScanner, Band, DetectedNetwork
        assert WiFiChannelScanner is not None
        assert Band is not None
        assert DetectedNetwork is not None

    def test_scanner_initialization(self):
        """Test scanner initialization with different interfaces"""
        from wifi_channel_scanner import WiFiChannelScanner

        scanner = WiFiChannelScanner(interface="wlan0")
        assert scanner.interface == "wlan0"

        scanner2 = WiFiChannelScanner(interface="wlan1")
        assert scanner2.interface == "wlan1"

    def test_freq_to_channel_2_4ghz(self):
        """Test frequency to channel conversion for 2.4GHz"""
        from wifi_channel_scanner import WiFiChannelScanner, Band

        scanner = WiFiChannelScanner()

        # Test 2.4GHz channels
        channel, band = scanner._freq_to_channel(2412)
        assert channel == 1
        assert band == Band.BAND_2_4GHZ

        channel, band = scanner._freq_to_channel(2437)
        assert channel == 6
        assert band == Band.BAND_2_4GHZ

        channel, band = scanner._freq_to_channel(2462)
        assert channel == 11
        assert band == Band.BAND_2_4GHZ

    def test_freq_to_channel_5ghz(self):
        """Test frequency to channel conversion for 5GHz"""
        from wifi_channel_scanner import WiFiChannelScanner, Band

        scanner = WiFiChannelScanner()

        # Test 5GHz channels
        channel, band = scanner._freq_to_channel(5180)
        assert channel == 36
        assert band == Band.BAND_5GHZ

        channel, band = scanner._freq_to_channel(5240)
        assert channel == 48
        assert band == Band.BAND_5GHZ

        channel, band = scanner._freq_to_channel(5745)
        assert channel == 149
        assert band == Band.BAND_5GHZ

    def test_channel_to_freq(self):
        """Test channel to frequency conversion"""
        from wifi_channel_scanner import WiFiChannelScanner, Band

        scanner = WiFiChannelScanner()

        # 2.4GHz
        assert scanner._channel_to_freq(1, Band.BAND_2_4GHZ) == 2412
        assert scanner._channel_to_freq(6, Band.BAND_2_4GHZ) == 2437
        assert scanner._channel_to_freq(11, Band.BAND_2_4GHZ) == 2462

        # 5GHz
        assert scanner._channel_to_freq(36, Band.BAND_5GHZ) == 5180
        assert scanner._channel_to_freq(149, Band.BAND_5GHZ) == 5745

    def test_parse_iwlist_output(self):
        """Test parsing of iwlist scan output"""
        from wifi_channel_scanner import WiFiChannelScanner

        scanner = WiFiChannelScanner()

        # Mock iwlist output
        iwlist_output = """
wlan0     Scan completed :
          Cell 01 - Address: AA:BB:CC:DD:EE:FF
                    Channel:6
                    Frequency:2.437 GHz (Channel 6)
                    Quality=70/100  Signal level=-40 dBm
                    Encryption key:on
                    ESSID:"TestNetwork"
                    IE: IEEE 802.11i/WPA2 Version 1
          Cell 02 - Address: 11:22:33:44:55:66
                    Channel:1
                    Frequency:2.412 GHz (Channel 1)
                    Quality=50/100  Signal level=-60 dBm
                    Encryption key:off
                    ESSID:"OpenNetwork"
"""
        networks = scanner._parse_iwlist_scan(iwlist_output)

        assert len(networks) == 2

        # Check first network
        net1 = networks[0]
        assert net1.ssid == "TestNetwork"
        assert net1.channel == 6
        assert net1.signal_strength == -40
        assert net1.security == "WPA2"

        # Check second network
        net2 = networks[1]
        assert net2.ssid == "OpenNetwork"
        assert net2.channel == 1
        assert net2.security == "Open"

    def test_channel_score_calculation(self):
        """Test channel scoring algorithm"""
        from wifi_channel_scanner import WiFiChannelScanner, Band, DetectedNetwork

        scanner = WiFiChannelScanner()

        # Add mock networks on channel 6
        scanner.channel_usage[6] = [
            DetectedNetwork(
                ssid="Net1", bssid="AA:BB:CC:DD:EE:FF",
                channel=6, frequency=2437, signal_strength=-40,
                signal_quality=70, security="WPA2", band=Band.BAND_2_4GHZ
            ),
            DetectedNetwork(
                ssid="Net2", bssid="11:22:33:44:55:66",
                channel=6, frequency=2437, signal_strength=-50,
                signal_quality=60, security="WPA2", band=Band.BAND_2_4GHZ
            )
        ]

        # Calculate score for channel 6 (congested)
        score_6 = scanner._calculate_single_channel_score(6, Band.BAND_2_4GHZ)
        assert score_6.channel == 6
        assert score_6.networks_count == 2
        assert score_6.is_non_overlapping is True

        # Calculate score for channel 1 (empty)
        score_1 = scanner._calculate_single_channel_score(1, Band.BAND_2_4GHZ)
        assert score_1.channel == 1
        assert score_1.networks_count == 0
        assert score_1.is_non_overlapping is True

        # Empty channel should have lower (better) score than congested
        assert score_1.score < score_6.score

    def test_non_overlapping_channel_preference(self):
        """Test that non-overlapping channels (1, 6, 11) are preferred"""
        from wifi_channel_scanner import WiFiChannelScanner

        scanner = WiFiChannelScanner()

        # Verify non-overlapping channels
        assert 1 in scanner.NON_OVERLAPPING_2_4GHZ
        assert 6 in scanner.NON_OVERLAPPING_2_4GHZ
        assert 11 in scanner.NON_OVERLAPPING_2_4GHZ

        # Verify channels 2-5, 7-10 are NOT non-overlapping
        for ch in [2, 3, 4, 5, 7, 8, 9, 10]:
            assert ch not in scanner.NON_OVERLAPPING_2_4GHZ

    @patch('subprocess.run')
    def test_scan_with_no_networks(self, mock_run):
        """Test scan behavior when no networks are detected"""
        from wifi_channel_scanner import WiFiChannelScanner

        # Mock empty scan result
        mock_run.return_value = MagicMock(
            stdout="wlan0     Scan completed :\n",
            returncode=0
        )

        scanner = WiFiChannelScanner()
        result = scanner.scan()

        # Should return default recommendations
        assert result.recommended_channel_2_4 == 1
        assert result.recommended_channel_5 == 36
        assert result.error is not None  # Should indicate no networks


# =============================================================================
# Offline Mode Manager Tests
# =============================================================================

class TestOfflineModeManager:
    """Tests for OfflineModeManager"""

    def test_import_manager(self):
        """Test that manager module can be imported"""
        from offline_mode_manager import (
            OfflineModeManager, OfflineState,
            OfflineModeConfig, OfflineModeState
        )
        assert OfflineModeManager is not None
        assert OfflineState is not None
        assert OfflineModeConfig is not None
        assert OfflineModeState is not None

    def test_manager_initialization(self):
        """Test manager initialization with default config"""
        from offline_mode_manager import OfflineModeManager, OfflineState

        manager = OfflineModeManager()

        assert manager.config.enabled is True
        assert manager.config.default_ssid == "HookProbe-Guardian"
        assert manager.state.state == OfflineState.INITIALIZING

    def test_custom_config(self):
        """Test manager with custom configuration"""
        from offline_mode_manager import OfflineModeManager, OfflineModeConfig

        config = OfflineModeConfig(
            default_ssid="MyCustomAP",
            default_channel_2_4=11,
            ap_ip="10.0.0.1"
        )

        manager = OfflineModeManager(config=config)

        assert manager.config.default_ssid == "MyCustomAP"
        assert manager.config.default_channel_2_4 == 11
        assert manager.config.ap_ip == "10.0.0.1"

    def test_offline_state_enum(self):
        """Test offline state enumeration values"""
        from offline_mode_manager import OfflineState

        assert OfflineState.INITIALIZING.value == "initializing"
        assert OfflineState.SCANNING.value == "scanning"
        assert OfflineState.AP_STARTING.value == "ap_starting"
        assert OfflineState.OFFLINE_READY.value == "offline_ready"
        assert OfflineState.CONNECTING_WAN.value == "connecting_wan"
        assert OfflineState.ONLINE.value == "online"
        assert OfflineState.ERROR.value == "error"

    def test_generate_hostapd_config_2_4ghz(self):
        """Test hostapd config generation for 2.4GHz"""
        from offline_mode_manager import OfflineModeManager

        manager = OfflineModeManager()
        config = manager.generate_hostapd_config(
            channel=6,
            ssid="TestAP",
            password="testpass123"
        )

        assert "channel=6" in config
        assert "ssid=TestAP" in config
        assert "wpa_passphrase=testpass123" in config
        assert "hw_mode=g" in config  # 2.4GHz
        assert manager.state.current_channel == 6
        assert manager.state.current_band == "2.4GHz"

    def test_generate_hostapd_config_5ghz(self):
        """Test hostapd config generation for 5GHz"""
        from offline_mode_manager import OfflineModeManager

        manager = OfflineModeManager()
        config = manager.generate_hostapd_config(
            channel=36,
            ssid="TestAP5G",
            password="testpass123"
        )

        assert "channel=36" in config
        assert "ssid=TestAP5G" in config
        assert "hw_mode=a" in config  # 5GHz
        assert manager.state.current_channel == 36
        assert manager.state.current_band == "5GHz"

    def test_generate_dnsmasq_config(self):
        """Test dnsmasq config generation"""
        from offline_mode_manager import OfflineModeManager

        manager = OfflineModeManager()
        config = manager.generate_dnsmasq_config()

        assert "interface=br0" in config
        assert "dhcp-range=" in config
        assert manager.config.ap_ip in config
        # Captive portal detection
        assert "captive.apple.com" in config
        assert "connectivitycheck.gstatic.com" in config

    def test_state_to_dict(self):
        """Test state serialization to dictionary"""
        from offline_mode_manager import OfflineModeState, OfflineState

        state = OfflineModeState()
        state.state = OfflineState.OFFLINE_READY
        state.current_channel = 11
        state.ap_ssid = "TestSSID"
        state.ap_running = True

        state_dict = state.to_dict()

        assert state_dict['state'] == "offline_ready"
        assert state_dict['current_channel'] == 11
        assert state_dict['ap_ssid'] == "TestSSID"
        assert state_dict['ap_running'] is True

    def test_get_status(self):
        """Test status retrieval"""
        from offline_mode_manager import OfflineModeManager, OfflineState

        manager = OfflineModeManager()
        manager.state.state = OfflineState.OFFLINE_READY
        manager.state.ap_running = True
        manager.state.ap_ssid = "TestAP"
        manager.state.current_channel = 6

        status = manager.get_status()

        assert status['state'] == "offline_ready"
        assert status['ap']['running'] is True
        assert status['ap']['ssid'] == "TestAP"
        assert status['ap']['channel'] == 6
        assert status['wan']['connected'] is False

    @patch('subprocess.run')
    def test_check_wan_connectivity_success(self, mock_run):
        """Test WAN connectivity check when connected"""
        from offline_mode_manager import OfflineModeManager

        # Mock successful connectivity
        mock_run.side_effect = [
            MagicMock(stdout="default via 192.168.1.1 dev eth0", returncode=0),
            MagicMock(stdout="", returncode=0)  # Ping success
        ]

        manager = OfflineModeManager()
        result = manager.check_wan_connectivity()

        assert result is True

    @patch('subprocess.run')
    def test_check_wan_connectivity_failure(self, mock_run):
        """Test WAN connectivity check when disconnected"""
        from offline_mode_manager import OfflineModeManager

        # Mock no default route
        mock_run.return_value = MagicMock(stdout="", returncode=1)

        manager = OfflineModeManager()
        result = manager.check_wan_connectivity()

        assert result is False


# =============================================================================
# Integration Tests (with mocking)
# =============================================================================

class TestOfflineModeIntegration:
    """Integration tests for offline mode flow"""

    @patch('subprocess.run')
    def test_scan_and_select_channel_mocked(self, mock_run):
        """Test the full scan and select channel flow"""
        from offline_mode_manager import OfflineModeManager

        # Mock iwlist scan output with congested channel 6
        mock_scan = """
wlan0     Scan completed :
          Cell 01 - Address: AA:BB:CC:DD:EE:FF
                    Channel:6
                    Frequency:2.437 GHz
                    Quality=80/100  Signal level=-30 dBm
                    Encryption key:on
                    ESSID:"StrongNetwork6"
                    IE: IEEE 802.11i/WPA2 Version 1
          Cell 02 - Address: 11:22:33:44:55:66
                    Channel:6
                    Frequency:2.437 GHz
                    Quality=70/100  Signal level=-40 dBm
                    Encryption key:on
                    ESSID:"AnotherNetwork6"
                    IE: IEEE 802.11i/WPA2 Version 1
          Cell 03 - Address: AA:11:BB:22:CC:33
                    Channel:1
                    Frequency:2.412 GHz
                    Quality=30/100  Signal level=-70 dBm
                    Encryption key:on
                    ESSID:"WeakNetwork1"
                    IE: IEEE 802.11i/WPA2 Version 1
"""
        mock_run.return_value = MagicMock(stdout=mock_scan, returncode=0)

        manager = OfflineModeManager()
        channel, score, networks = manager.scan_and_select_channel()

        # Should detect 3 networks
        assert networks == 3

        # Should prefer channel 1 or 11 over congested channel 6
        assert channel in [1, 11]

    def test_offline_mode_state_transitions(self):
        """Test state machine transitions"""
        from offline_mode_manager import OfflineModeManager, OfflineState

        manager = OfflineModeManager()

        # Initial state
        assert manager.state.state == OfflineState.INITIALIZING

        # Simulate scanning
        manager.state.state = OfflineState.SCANNING
        assert manager.state.state == OfflineState.SCANNING

        # Simulate AP starting
        manager.state.state = OfflineState.AP_STARTING
        assert manager.state.state == OfflineState.AP_STARTING

        # Simulate offline ready
        manager.state.state = OfflineState.OFFLINE_READY
        assert manager.state.state == OfflineState.OFFLINE_READY

        # Simulate connecting WAN
        manager.state.state = OfflineState.CONNECTING_WAN
        assert manager.state.state == OfflineState.CONNECTING_WAN

        # Simulate online
        manager.state.state = OfflineState.ONLINE
        assert manager.state.state == OfflineState.ONLINE


# =============================================================================
# Channel Selection Algorithm Tests
# =============================================================================

class TestChannelSelectionAlgorithm:
    """Detailed tests for the channel selection algorithm"""

    def test_adjacent_channel_interference_calculation(self):
        """Test that adjacent channel interference is calculated correctly"""
        from wifi_channel_scanner import WiFiChannelScanner, Band, DetectedNetwork

        scanner = WiFiChannelScanner()

        # Add network on channel 5 (adjacent to channel 6)
        scanner.channel_usage[5] = [
            DetectedNetwork(
                ssid="Adjacent", bssid="AA:BB:CC:DD:EE:FF",
                channel=5, frequency=2432, signal_strength=-50,
                signal_quality=60, security="WPA2", band=Band.BAND_2_4GHZ
            )
        ]

        # Score for channel 6 should include adjacent interference from ch5
        score = scanner._calculate_single_channel_score(6, Band.BAND_2_4GHZ)

        assert score.adjacent_interference > 0

    def test_empty_channel_best_score(self):
        """Test that completely empty channel gets best score"""
        from wifi_channel_scanner import WiFiChannelScanner, Band, DetectedNetwork

        scanner = WiFiChannelScanner()

        # Congest channel 6
        scanner.channel_usage[6] = [
            DetectedNetwork(
                ssid=f"Net{i}", bssid=f"AA:BB:CC:DD:EE:{i:02X}",
                channel=6, frequency=2437, signal_strength=-30,
                signal_quality=80, security="WPA2", band=Band.BAND_2_4GHZ
            )
            for i in range(5)
        ]

        scores = scanner._calculate_channel_scores()

        # Channel 1 or 11 should have better (lower) score than 6
        score_1 = scores[1].score
        score_6 = scores[6].score
        score_11 = scores[11].score

        assert score_1 < score_6 or score_11 < score_6

    def test_dfs_channel_penalty(self):
        """Test that DFS channels receive penalty"""
        from wifi_channel_scanner import WiFiChannelScanner, Band

        scanner = WiFiChannelScanner()

        # DFS channel (52)
        dfs_score = scanner._calculate_single_channel_score(52, Band.BAND_5GHZ)
        assert dfs_score.is_dfs is True

        # Non-DFS channel (36)
        non_dfs_score = scanner._calculate_single_channel_score(36, Band.BAND_5GHZ)
        assert non_dfs_score.is_dfs is False

        # DFS should have higher (worse) score due to penalty
        # (assuming both channels are empty)
        assert dfs_score.score > non_dfs_score.score


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
