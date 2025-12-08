#!/usr/bin/env python3
"""
WiFi Channel Scanner - Intelligent Channel Selection for Guardian

Scans the RF environment to detect congestion and select the optimal
channel for AP operation. Critical for busy environments like coffee shops,
airports, and hotels.

Features:
- 2.4GHz and 5GHz channel scanning
- Adjacent channel interference detection
- Non-overlapping channel preference (1, 6, 11 for 2.4GHz)
- Signal strength weighted scoring
- DFS channel awareness for 5GHz
- Real-time congestion analysis

Author: HookProbe Team
Version: 1.0.0
License: AGPL-3.0 - see LICENSE in this directory
"""

import subprocess
import re
import logging
import shlex
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Union
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class Band(Enum):
    """WiFi frequency bands"""
    BAND_2_4GHZ = "2.4GHz"
    BAND_5GHZ = "5GHz"


@dataclass
class DetectedNetwork:
    """Represents a detected WiFi network"""
    ssid: str
    bssid: str
    channel: int
    frequency: int  # MHz
    signal_strength: int  # dBm (negative value)
    signal_quality: int  # 0-100 percentage
    security: str
    band: Band
    channel_width: int = 20  # MHz (20, 40, 80, 160)


@dataclass
class ChannelScore:
    """Channel congestion score"""
    channel: int
    band: Band
    frequency: int
    score: float  # Lower is better (less congestion)
    networks_count: int
    total_signal: int  # Sum of all network signals (weighted)
    adjacent_interference: float
    is_dfs: bool = False
    is_non_overlapping: bool = False


@dataclass
class ScanResult:
    """Complete scan result"""
    networks: List[DetectedNetwork]
    channel_scores: Dict[int, ChannelScore]
    recommended_channel_2_4: int
    recommended_channel_5: Optional[int]
    scan_timestamp: str
    interface: str
    error: Optional[str] = None


class WiFiChannelScanner:
    """
    Scans WiFi environment and recommends optimal channels.

    Usage:
        scanner = WiFiChannelScanner(interface="wlan0")
        result = scanner.scan()
        print(f"Best 2.4GHz channel: {result.recommended_channel_2_4}")
    """

    # 2.4GHz channels (1-14, most regions 1-13 or 1-11)
    CHANNELS_2_4GHZ = list(range(1, 14))

    # 2.4GHz non-overlapping channels (best choices)
    NON_OVERLAPPING_2_4GHZ = [1, 6, 11]

    # 5GHz channels (varies by region, these are common)
    CHANNELS_5GHZ_UNII1 = [36, 40, 44, 48]  # UNII-1 (indoor)
    CHANNELS_5GHZ_UNII2 = [52, 56, 60, 64]  # UNII-2A (DFS)
    CHANNELS_5GHZ_UNII2E = [100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144]  # UNII-2C (DFS)
    CHANNELS_5GHZ_UNII3 = [149, 153, 157, 161, 165]  # UNII-3

    # DFS channels require radar detection
    DFS_CHANNELS = CHANNELS_5GHZ_UNII2 + CHANNELS_5GHZ_UNII2E

    # Channel overlap width for 2.4GHz (each channel affects ±2 channels)
    CHANNEL_OVERLAP_WIDTH = 2

    def __init__(self, interface: str = "wlan0"):
        self.interface = interface
        self.networks: List[DetectedNetwork] = []
        self.channel_usage: Dict[int, List[DetectedNetwork]] = defaultdict(list)

    def _run_command(self, cmd: Union[str, List[str]], timeout: int = 30) -> Tuple[str, bool]:
        """Run command safely without shell=True to prevent command injection"""
        try:
            # Convert string to list for safe execution
            if isinstance(cmd, str):
                cmd_list = shlex.split(cmd)
            else:
                cmd_list = cmd

            result = subprocess.run(
                cmd_list, capture_output=True,
                text=True, timeout=timeout
            )
            return result.stdout.strip(), result.returncode == 0
        except subprocess.TimeoutExpired:
            logger.warning(f"Command timed out: {cmd}")
            return "", False
        except Exception as e:
            logger.error(f"Command failed: {e}")
            return str(e), False

    def _freq_to_channel(self, freq_mhz: int) -> Tuple[int, Band]:
        """Convert frequency to channel number and band"""
        if 2400 <= freq_mhz <= 2500:
            # 2.4GHz: Channel = (freq - 2407) / 5
            channel = (freq_mhz - 2407) // 5
            return max(1, min(14, channel)), Band.BAND_2_4GHZ
        elif 5150 <= freq_mhz <= 5850:
            # 5GHz: Various formulas based on UNII band
            if freq_mhz < 5250:
                channel = (freq_mhz - 5000) // 5
            else:
                channel = (freq_mhz - 5000) // 5
            return channel, Band.BAND_5GHZ
        else:
            return 0, Band.BAND_2_4GHZ

    def _channel_to_freq(self, channel: int, band: Band) -> int:
        """Convert channel to frequency in MHz"""
        if band == Band.BAND_2_4GHZ:
            return 2407 + (channel * 5)
        else:  # 5GHz
            return 5000 + (channel * 5)

    def _parse_iwlist_scan(self, output: str) -> List[DetectedNetwork]:
        """Parse iwlist scan output"""
        networks = []
        current = {}

        for line in output.split('\n'):
            line = line.strip()

            # New cell = new network
            if 'Cell ' in line and 'Address:' in line:
                if current.get('bssid'):
                    networks.append(self._create_network(current))
                current = {}
                # Extract BSSID
                match = re.search(r'Address:\s*([0-9A-Fa-f:]+)', line)
                if match:
                    current['bssid'] = match.group(1).upper()

            elif 'ESSID:' in line:
                match = re.search(r'ESSID:"([^"]*)"', line)
                current['ssid'] = match.group(1) if match else ""

            elif 'Frequency:' in line:
                match = re.search(r'Frequency:(\d+\.?\d*)\s*GHz', line)
                if match:
                    freq_ghz = float(match.group(1))
                    current['frequency'] = int(freq_ghz * 1000)
                # Also extract channel if present
                match = re.search(r'Channel[:\s]*(\d+)', line)
                if match:
                    current['channel'] = int(match.group(1))

            elif 'Channel:' in line:
                match = re.search(r'Channel:\s*(\d+)', line)
                if match:
                    current['channel'] = int(match.group(1))

            elif 'Quality=' in line:
                # Quality=70/100 or Quality=56/70
                match = re.search(r'Quality[=:](\d+)/(\d+)', line)
                if match:
                    num, denom = int(match.group(1)), int(match.group(2))
                    current['signal_quality'] = int((num / denom) * 100)

                # Signal level=-XX dBm
                match = re.search(r'Signal level[=:](-?\d+)\s*dBm', line)
                if match:
                    current['signal_strength'] = int(match.group(1))
                else:
                    # Alternative format: Signal level=XX/100
                    match = re.search(r'Signal level[=:](\d+)/(\d+)', line)
                    if match:
                        num, denom = int(match.group(1)), int(match.group(2))
                        # Convert to approximate dBm (-90 to -30)
                        current['signal_strength'] = -90 + int((num / denom) * 60)

            elif 'Encryption key:' in line:
                current['encrypted'] = 'on' in line.lower()

            elif 'IE: IEEE 802.11i/WPA2' in line:
                current['security'] = 'WPA2'
            elif 'IE: WPA Version' in line:
                if current.get('security') != 'WPA2':
                    current['security'] = 'WPA'
            elif 'WPA3' in line or 'SAE' in line:
                current['security'] = 'WPA3'

        # Don't forget the last network
        if current.get('bssid'):
            networks.append(self._create_network(current))

        return networks

    def _parse_iw_scan(self, output: str) -> List[DetectedNetwork]:
        """Parse iw scan output (alternative to iwlist)"""
        networks = []
        current = {}

        for line in output.split('\n'):
            line = line.strip()

            if line.startswith('BSS '):
                if current.get('bssid'):
                    networks.append(self._create_network(current))
                current = {}
                match = re.search(r'BSS\s+([0-9a-fA-F:]+)', line)
                if match:
                    current['bssid'] = match.group(1).upper()

            elif 'SSID:' in line:
                current['ssid'] = line.split('SSID:')[1].strip()

            elif 'freq:' in line:
                match = re.search(r'freq:\s*(\d+)', line)
                if match:
                    current['frequency'] = int(match.group(1))

            elif 'signal:' in line:
                match = re.search(r'signal:\s*(-?\d+\.?\d*)', line)
                if match:
                    current['signal_strength'] = int(float(match.group(1)))

            elif 'RSN:' in line or 'WPA:' in line:
                if 'RSN:' in line:
                    current['security'] = 'WPA2'
                else:
                    current['security'] = current.get('security', 'WPA')

        if current.get('bssid'):
            networks.append(self._create_network(current))

        return networks

    def _create_network(self, data: dict) -> DetectedNetwork:
        """Create DetectedNetwork from parsed data"""
        freq = data.get('frequency', 2437)
        channel, band = self._freq_to_channel(freq)

        # Use provided channel if available and valid
        if 'channel' in data:
            channel = data['channel']
            if channel <= 14:
                band = Band.BAND_2_4GHZ
            else:
                band = Band.BAND_5GHZ

        return DetectedNetwork(
            ssid=data.get('ssid', ''),
            bssid=data.get('bssid', ''),
            channel=channel,
            frequency=freq,
            signal_strength=data.get('signal_strength', -90),
            signal_quality=data.get('signal_quality', 0),
            security=data.get('security', 'Open' if not data.get('encrypted') else 'WPA'),
            band=band
        )

    def scan(self) -> ScanResult:
        """
        Perform RF environment scan and analyze channel congestion.

        Returns:
            ScanResult with networks, channel scores, and recommendations
        """
        from datetime import datetime

        self.networks = []
        self.channel_usage = defaultdict(list)

        # Try iwlist first (more common on Raspberry Pi)
        output, success = self._run_command(
            f'sudo iwlist {self.interface} scan 2>/dev/null',
            timeout=30
        )

        if success and output:
            self.networks = self._parse_iwlist_scan(output)
        else:
            # Fallback to iw (newer but may require newer kernel)
            output, success = self._run_command(
                f'sudo iw dev {self.interface} scan 2>/dev/null',
                timeout=30
            )
            if success and output:
                self.networks = self._parse_iw_scan(output)

        # If still no networks, return error result
        if not self.networks:
            logger.warning("No networks detected - using default channel recommendations")
            return ScanResult(
                networks=[],
                channel_scores={},
                recommended_channel_2_4=1,  # Default to channel 1 if no congestion data
                recommended_channel_5=36,
                scan_timestamp=datetime.now().isoformat(),
                interface=self.interface,
                error="No networks detected or scan failed"
            )

        # Build channel usage map
        for network in self.networks:
            self.channel_usage[network.channel].append(network)

        # Calculate scores for all channels
        channel_scores = self._calculate_channel_scores()

        # Find best channels
        best_2_4 = self._find_best_channel(channel_scores, Band.BAND_2_4GHZ)
        best_5 = self._find_best_channel(channel_scores, Band.BAND_5GHZ)

        return ScanResult(
            networks=self.networks,
            channel_scores=channel_scores,
            recommended_channel_2_4=best_2_4,
            recommended_channel_5=best_5,
            scan_timestamp=datetime.now().isoformat(),
            interface=self.interface
        )

    def _calculate_channel_scores(self) -> Dict[int, ChannelScore]:
        """Calculate congestion score for each channel"""
        scores = {}

        # Calculate 2.4GHz channel scores
        for channel in self.CHANNELS_2_4GHZ:
            if channel > 11:  # Skip channels 12-14 for US compliance
                continue

            score = self._calculate_single_channel_score(channel, Band.BAND_2_4GHZ)
            scores[channel] = score

        # Calculate 5GHz channel scores (non-DFS first for simplicity)
        for channel in self.CHANNELS_5GHZ_UNII1 + self.CHANNELS_5GHZ_UNII3:
            score = self._calculate_single_channel_score(channel, Band.BAND_5GHZ)
            scores[channel] = score

        return scores

    def _calculate_single_channel_score(self, channel: int, band: Band) -> ChannelScore:
        """
        Calculate congestion score for a single channel.

        Score formula:
        - Base: Number of networks on this channel × signal weight
        - Adjacent: Networks on adjacent channels × overlap factor
        - Bonus: -10 for non-overlapping channels (1, 6, 11)

        Lower score = better channel
        """
        direct_networks = self.channel_usage.get(channel, [])
        networks_count = len(direct_networks)

        # Signal strength contribution (stronger signals = more interference)
        # Convert dBm to positive weight (-30 dBm = 70, -90 dBm = 10)
        total_signal = 0
        for net in direct_networks:
            # Normalize signal: stronger = higher weight
            weight = max(0, 100 + net.signal_strength)  # -30 -> 70, -90 -> 10
            total_signal += weight

        # Adjacent channel interference (2.4GHz only)
        adjacent_interference = 0.0
        if band == Band.BAND_2_4GHZ:
            for adj_offset in range(-self.CHANNEL_OVERLAP_WIDTH, self.CHANNEL_OVERLAP_WIDTH + 1):
                if adj_offset == 0:
                    continue  # Skip self

                adj_channel = channel + adj_offset
                if adj_channel < 1 or adj_channel > 14:
                    continue

                adj_networks = self.channel_usage.get(adj_channel, [])

                # Overlap factor decreases with distance
                overlap_factor = 1.0 - (abs(adj_offset) * 0.3)

                for net in adj_networks:
                    weight = max(0, 100 + net.signal_strength) * overlap_factor
                    adjacent_interference += weight

        # Calculate final score
        score = total_signal + (adjacent_interference * 0.5)

        # Bonus for non-overlapping channels
        is_non_overlapping = channel in self.NON_OVERLAPPING_2_4GHZ
        if is_non_overlapping:
            score -= 20  # Prefer non-overlapping channels

        # Check if DFS channel
        is_dfs = channel in self.DFS_CHANNELS
        if is_dfs:
            score += 50  # Penalize DFS channels (require radar detection)

        return ChannelScore(
            channel=channel,
            band=band,
            frequency=self._channel_to_freq(channel, band),
            score=score,
            networks_count=networks_count,
            total_signal=total_signal,
            adjacent_interference=adjacent_interference,
            is_dfs=is_dfs,
            is_non_overlapping=is_non_overlapping
        )

    def _find_best_channel(self, scores: Dict[int, ChannelScore], band: Band) -> int:
        """Find the best (lowest score) channel for given band"""
        band_scores = [s for s in scores.values() if s.band == band]

        if not band_scores:
            # Return defaults
            return 1 if band == Band.BAND_2_4GHZ else 36

        # Sort by score (ascending) then by non-overlapping preference
        band_scores.sort(key=lambda x: (x.score, not x.is_non_overlapping))

        return band_scores[0].channel

    def get_channel_recommendation_report(self, scan_result: ScanResult) -> str:
        """Generate human-readable channel recommendation report"""
        lines = [
            "=" * 60,
            "WiFi Channel Analysis Report",
            "=" * 60,
            f"Scan Time: {scan_result.scan_timestamp}",
            f"Interface: {scan_result.interface}",
            f"Networks Detected: {len(scan_result.networks)}",
            "",
            "--- 2.4GHz Channel Analysis ---",
        ]

        # 2.4GHz channels
        for ch in self.NON_OVERLAPPING_2_4GHZ:
            score = scan_result.channel_scores.get(ch)
            if score:
                indicator = " <-- RECOMMENDED" if ch == scan_result.recommended_channel_2_4 else ""
                lines.append(
                    f"  Channel {ch:2d}: Score {score.score:6.1f} | "
                    f"Networks: {score.networks_count:2d} | "
                    f"Adjacent: {score.adjacent_interference:5.1f}{indicator}"
                )

        lines.extend([
            "",
            "--- 5GHz Channel Analysis ---",
        ])

        # 5GHz channels (non-DFS)
        for ch in self.CHANNELS_5GHZ_UNII1 + self.CHANNELS_5GHZ_UNII3:
            score = scan_result.channel_scores.get(ch)
            if score:
                indicator = " <-- RECOMMENDED" if ch == scan_result.recommended_channel_5 else ""
                lines.append(
                    f"  Channel {ch:3d}: Score {score.score:6.1f} | "
                    f"Networks: {score.networks_count:2d}{indicator}"
                )

        lines.extend([
            "",
            "--- Recommendations ---",
            f"  2.4GHz: Channel {scan_result.recommended_channel_2_4}",
            f"  5GHz:   Channel {scan_result.recommended_channel_5 or 'N/A'}",
            "=" * 60,
        ])

        return "\n".join(lines)


# CLI interface
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="WiFi Channel Scanner")
    parser.add_argument('-i', '--interface', default='wlan0', help='WiFi interface')
    parser.add_argument('-j', '--json', action='store_true', help='JSON output')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    scanner = WiFiChannelScanner(interface=args.interface)
    result = scanner.scan()

    if args.json:
        import json
        output = {
            'networks': [
                {
                    'ssid': n.ssid,
                    'bssid': n.bssid,
                    'channel': n.channel,
                    'frequency': n.frequency,
                    'signal_strength': n.signal_strength,
                    'signal_quality': n.signal_quality,
                    'security': n.security,
                    'band': n.band.value
                }
                for n in result.networks
            ],
            'channel_scores': {
                str(ch): {
                    'score': s.score,
                    'networks_count': s.networks_count,
                    'adjacent_interference': s.adjacent_interference,
                    'is_non_overlapping': s.is_non_overlapping
                }
                for ch, s in result.channel_scores.items()
            },
            'recommended_channel_2_4': result.recommended_channel_2_4,
            'recommended_channel_5': result.recommended_channel_5,
            'scan_timestamp': result.scan_timestamp,
            'error': result.error
        }
        print(json.dumps(output, indent=2))
    else:
        print(scanner.get_channel_recommendation_report(result))
