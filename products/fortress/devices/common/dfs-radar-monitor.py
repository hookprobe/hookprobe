#!/usr/bin/env python3
"""
DFS Radar Monitor - Listens for radar events from hostapd and triggers channel switch.

This daemon monitors hostapd_cli for DFS-RADAR-DETECTED events and:
1. Logs the radar event to the DFS database
2. Gets the best alternative channel from DFS intelligence
3. Triggers a Channel Switch Announcement (CSA) via hostapd_cli

Usage:
    python3 dfs-radar-monitor.py --interface wlan0
    python3 dfs-radar-monitor.py --interface wlan0 --dry-run

Author: HookProbe Team
Version: 1.0.0
License: AGPL-3.0
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# Configuration
DFS_API_URL = os.environ.get("DFS_API_URL", "http://localhost:8767")
DFS_DB_PATH = os.environ.get("DFS_DB_PATH", "/var/lib/hookprobe/dfs_intelligence.db")
LOG_FILE = Path("/var/log/fortress/dfs-radar-monitor.log")
STATE_FILE = Path("/var/lib/fortress/dfs/radar_monitor_state.json")
HOSTAPD_CTRL = "/var/run/hostapd"

# Ensure directories exist
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


def check_hostapd_cli() -> bool:
    """Check if hostapd_cli is available."""
    try:
        result = subprocess.run(
            ["which", "hostapd_cli"],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def get_hostapd_status(interface: str) -> dict:
    """Get current hostapd status."""
    try:
        result = subprocess.run(
            ["hostapd_cli", "-i", interface, "status"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            status = {}
            for line in result.stdout.strip().split("\n"):
                if "=" in line:
                    key, value = line.split("=", 1)
                    status[key] = value
            return status
    except Exception as e:
        logger.error(f"Failed to get hostapd status: {e}")
    return {}


def get_current_channel(interface: str) -> Optional[int]:
    """Get current operating channel from hostapd."""
    status = get_hostapd_status(interface)
    try:
        return int(status.get("channel", 0))
    except (ValueError, TypeError):
        return None


def log_radar_event(channel: int) -> bool:
    """Log radar event to DFS intelligence."""
    timestamp = datetime.now().isoformat()

    # Try API first
    try:
        import requests
        response = requests.post(
            f"{DFS_API_URL}/radar",
            json={"channel": channel, "timestamp": timestamp},
            timeout=5
        )
        if response.ok:
            logger.info(f"Radar event logged to API: channel {channel}")
            return True
    except Exception as e:
        logger.debug(f"API unavailable: {e}")

    # Try Python module directly
    try:
        # Add shared/wireless to path
        sys.path.insert(0, "/opt/hookprobe/shared/wireless")
        from dfs_intelligence import DFSDatabase, RadarEvent

        db = DFSDatabase(DFS_DB_PATH)
        event = RadarEvent(
            channel=channel,
            timestamp=datetime.fromisoformat(timestamp),
            duration_ms=0,  # Unknown duration
            cac_failed=False
        )
        db.record_radar_event(event)
        logger.info(f"Radar event logged to DB: channel {channel}")
        return True
    except Exception as e:
        logger.debug(f"Python module unavailable: {e}")

    # Fallback: log to file
    try:
        events_file = STATE_FILE.parent / "radar_events.jsonl"
        with open(events_file, "a") as f:
            f.write(json.dumps({
                "channel": channel,
                "timestamp": timestamp
            }) + "\n")
        logger.info(f"Radar event logged to file: channel {channel}")
        return True
    except Exception as e:
        logger.error(f"Failed to log radar event: {e}")
        return False


def get_best_alternative_channel(current_channel: int, prefer_dfs: bool = False) -> Optional[int]:
    """Get best alternative channel from DFS intelligence."""

    # Try API first
    try:
        import requests
        response = requests.post(
            f"{DFS_API_URL}/best",
            json={"prefer_dfs": prefer_dfs, "exclude_channel": current_channel},
            timeout=5
        )
        if response.ok:
            data = response.json()
            channel = data.get("channel") or data.get("best_channel")
            if channel and channel != current_channel:
                logger.info(f"Best channel from API: {channel}")
                return int(channel)
    except Exception as e:
        logger.debug(f"API unavailable: {e}")

    # Try shell script
    try:
        result = subprocess.run(
            ["/opt/hookprobe/fortress/bin/dfs-channel-selector.sh", "best"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            channel = int(result.stdout.strip())
            if channel != current_channel:
                logger.info(f"Best channel from selector: {channel}")
                return channel
    except Exception as e:
        logger.debug(f"Shell selector unavailable: {e}")

    # Fallback: use safe non-DFS channels
    safe_channels = [36, 40, 44, 48, 149, 153, 157, 161, 165]
    for ch in safe_channels:
        if ch != current_channel:
            logger.info(f"Best channel (fallback): {ch}")
            return ch

    return None


def trigger_channel_switch(interface: str, new_channel: int, csa_count: int = 5) -> bool:
    """Trigger Channel Switch Announcement via hostapd_cli."""
    try:
        # Use CHAN_SWITCH command
        # Format: CHAN_SWITCH <cs_count> <freq> [sec_channel_offset=X] [center_freq1=X] [bandwidth=X] [ht|vht]
        # We'll use a simpler approach: update config and reload

        logger.info(f"Triggering channel switch to {new_channel} with {csa_count} CSA beacons")

        # Send CSA via hostapd_cli
        freq = channel_to_freq(new_channel)
        if not freq:
            logger.error(f"Unknown frequency for channel {new_channel}")
            return False

        result = subprocess.run(
            ["hostapd_cli", "-i", interface, "chan_switch", str(csa_count), str(freq)],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0 and "OK" in result.stdout:
            logger.info(f"Channel switch initiated: {new_channel} (freq: {freq})")
            return True
        else:
            logger.warning(f"CSA command returned: {result.stdout.strip()} {result.stderr.strip()}")

            # Fallback: reload hostapd with new config
            return reload_hostapd_with_new_channel(interface, new_channel)

    except Exception as e:
        logger.error(f"Failed to trigger channel switch: {e}")
        return False


def channel_to_freq(channel: int) -> Optional[int]:
    """Convert WiFi channel number to frequency in MHz."""
    # 2.4GHz
    if 1 <= channel <= 13:
        return 2412 + (channel - 1) * 5
    if channel == 14:
        return 2484

    # 5GHz
    if 36 <= channel <= 64:
        return 5180 + (channel - 36) * 5
    if 100 <= channel <= 144:
        return 5500 + (channel - 100) * 5
    if 149 <= channel <= 165:
        return 5745 + (channel - 149) * 5

    return None


def reload_hostapd_with_new_channel(interface: str, new_channel: int) -> bool:
    """Update hostapd config and reload (fallback method)."""
    try:
        config_files = [
            f"/etc/hostapd/fortress-{interface}.conf",
            f"/etc/hostapd/fortress.conf",
            "/etc/hostapd/hostapd.conf"
        ]

        config_file = None
        for cf in config_files:
            if os.path.exists(cf):
                config_file = cf
                break

        if not config_file:
            logger.error("No hostapd config file found")
            return False

        # Read config
        with open(config_file, "r") as f:
            config = f.read()

        # Update channel
        import re
        config = re.sub(r"^channel=\d+", f"channel={new_channel}", config, flags=re.MULTILINE)

        # Write back
        with open(config_file, "w") as f:
            f.write(config)

        # Reload hostapd
        subprocess.run(
            ["hostapd_cli", "-i", interface, "reload"],
            capture_output=True,
            timeout=10
        )

        logger.info(f"Hostapd reloaded with channel {new_channel}")
        return True

    except Exception as e:
        logger.error(f"Failed to reload hostapd: {e}")
        return False


def monitor_hostapd_events(interface: str, dry_run: bool = False):
    """Monitor hostapd for DFS events."""
    logger.info(f"Starting DFS radar monitor on {interface} (dry_run={dry_run})")

    if not check_hostapd_cli():
        logger.error("hostapd_cli not found")
        sys.exit(1)

    ctrl_path = f"{HOSTAPD_CTRL}/{interface}"
    if not os.path.exists(ctrl_path):
        logger.warning(f"Hostapd control interface not found: {ctrl_path}")
        logger.info("Waiting for hostapd to start...")

    # Wait for hostapd
    while not os.path.exists(ctrl_path):
        time.sleep(5)
        if os.path.exists(ctrl_path):
            logger.info("Hostapd control interface available")
            break

    # Start monitoring using hostapd_cli in attach mode
    logger.info("Attaching to hostapd events...")

    try:
        process = subprocess.Popen(
            ["hostapd_cli", "-i", interface, "-a", "/dev/stdin"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
    except Exception as e:
        logger.error(f"Failed to start hostapd_cli: {e}")
        # Fall back to polling mode
        logger.info("Falling back to polling mode...")
        monitor_polling_mode(interface, dry_run)
        return

    # Monitor output
    try:
        while True:
            line = process.stdout.readline()
            if not line:
                break

            line = line.strip()
            if not line:
                continue

            logger.debug(f"Event: {line}")

            # Check for DFS events
            if "DFS-RADAR-DETECTED" in line:
                handle_radar_detected(interface, line, dry_run)
            elif "DFS-CAC-START" in line:
                logger.info(f"CAC started: {line}")
            elif "DFS-CAC-COMPLETED" in line:
                logger.info(f"CAC completed: {line}")
            elif "DFS-NOP-FINISHED" in line:
                logger.info(f"NOP finished: {line}")

    except KeyboardInterrupt:
        logger.info("Monitor stopped by user")
    except Exception as e:
        logger.error(f"Monitor error: {e}")
    finally:
        process.terminate()


def monitor_polling_mode(interface: str, dry_run: bool = False):
    """Monitor hostapd by polling status (fallback mode)."""
    logger.info("Running in polling mode (less responsive)")

    last_channel = None

    while True:
        try:
            current_channel = get_current_channel(interface)

            if current_channel and last_channel and current_channel != last_channel:
                # Channel changed - might be radar
                logger.warning(f"Channel changed: {last_channel} -> {current_channel}")
                # Log as potential radar on old channel
                log_radar_event(last_channel)

            last_channel = current_channel
            time.sleep(5)

        except KeyboardInterrupt:
            break
        except Exception as e:
            logger.error(f"Polling error: {e}")
            time.sleep(10)


def handle_radar_detected(interface: str, event_line: str, dry_run: bool):
    """Handle DFS-RADAR-DETECTED event."""
    logger.warning(f"RADAR DETECTED: {event_line}")

    # Parse channel from event
    current_channel = get_current_channel(interface)
    if not current_channel:
        logger.error("Could not determine current channel")
        return

    # Log radar event
    log_radar_event(current_channel)

    # Get best alternative channel
    new_channel = get_best_alternative_channel(current_channel, prefer_dfs=False)
    if not new_channel:
        logger.error("No alternative channel available!")
        return

    logger.info(f"Selected alternative channel: {new_channel}")

    if dry_run:
        logger.info(f"DRY RUN: Would switch to channel {new_channel}")
        return

    # Trigger channel switch
    success = trigger_channel_switch(interface, new_channel)
    if success:
        logger.info(f"Successfully switched to channel {new_channel}")

        # Save state
        try:
            with open(STATE_FILE, "w") as f:
                json.dump({
                    "last_radar_channel": current_channel,
                    "new_channel": new_channel,
                    "timestamp": datetime.now().isoformat(),
                    "interface": interface
                }, f)
        except Exception:
            pass
    else:
        logger.error("Failed to switch channels!")


def main():
    parser = argparse.ArgumentParser(
        description="DFS Radar Monitor - Automatic radar detection and channel switching"
    )
    parser.add_argument(
        "-i", "--interface",
        default="wlan0",
        help="WiFi interface to monitor (default: wlan0)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Don't actually switch channels, just log"
    )
    parser.add_argument(
        "--poll",
        action="store_true",
        help="Use polling mode instead of event monitoring"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.poll:
        monitor_polling_mode(args.interface, args.dry_run)
    else:
        monitor_hostapd_events(args.interface, args.dry_run)


if __name__ == "__main__":
    main()
