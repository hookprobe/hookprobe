"""
AIOCHI Bubble API Client
Wrapper for calling the aiochi-bubble container REST API.

This replaces direct imports of ecosystem_bubble, clickhouse_graph, etc.
All bubble logic is now consolidated in the aiochi-bubble container.
"""

import logging
import os
import time
import requests
from typing import List, Dict, Optional, Any

logger = logging.getLogger(__name__)

# AIOCHI Bubble API endpoint
# In container: Use environment variable pointing to aiochi-bubble container
# On host: Falls back to localhost:8070
AIOCHI_BUBBLE_URL = os.environ.get("AIOCHI_BUBBLE_URL", "http://localhost:8070")
API_TIMEOUT = 5  # seconds

# Retry settings for container readiness
MAX_READY_RETRIES = 3
RETRY_DELAY_BASE = 1.0  # seconds (exponential backoff)


class AIOCHIBubbleClient:
    """Client for aiochi-bubble container API."""

    def __init__(self, base_url: str = AIOCHI_BUBBLE_URL):
        self.base_url = base_url.rstrip('/')

    def _get(self, endpoint: str) -> Optional[Dict]:
        """Make GET request to API."""
        try:
            url = f"{self.base_url}{endpoint}"
            response = requests.get(url, timeout=API_TIMEOUT)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"AIOCHI bubble API error: {e}")
            return None

    def _put(self, endpoint: str, data: Dict) -> Optional[Dict]:
        """Make PUT request to API."""
        try:
            url = f"{self.base_url}{endpoint}"
            response = requests.put(url, json=data, timeout=API_TIMEOUT)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"AIOCHI bubble API error: {e}")
            return None

    def get_health(self) -> Optional[Dict]:
        """Get health status of bubble manager."""
        return self._get("/health")

    def get_status(self) -> Optional[Dict]:
        """Get detailed status."""
        return self._get("/status")

    def list_bubbles(self) -> List[Dict]:
        """Get all ecosystem bubbles."""
        result = self._get("/api/bubbles")
        return result.get("bubbles", []) if result else []

    def get_bubble(self, bubble_id: str) -> Optional[Dict]:
        """Get a specific bubble by ID."""
        return self._get(f"/api/bubbles/{bubble_id}")

    def list_devices(self) -> List[Dict]:
        """Get all devices with bubble assignments."""
        result = self._get("/api/devices")
        return result.get("devices", []) if result else []

    def move_device(self, mac: str, bubble_id: str) -> bool:
        """Move a device to a different bubble."""
        result = self._put(f"/api/devices/{mac}/bubble", {"bubble_id": bubble_id})
        return result.get("success", False) if result else False

    def get_affinity(self, mac1: str, mac2: str) -> float:
        """Get affinity score between two devices."""
        result = self._get(f"/api/affinity/{mac1}/{mac2}")
        return result.get("affinity", 0.0) if result else 0.0


# Singleton instance
_client: Optional[AIOCHIBubbleClient] = None


def get_aiochi_bubble_client() -> AIOCHIBubbleClient:
    """Get singleton AIOCHI bubble client."""
    global _client
    if _client is None:
        _client = AIOCHIBubbleClient()
    return _client


# Compatibility functions for existing code
def get_ecosystem_bubbles() -> List[Dict]:
    """Get all ecosystem bubbles (compatibility wrapper)."""
    return get_aiochi_bubble_client().list_bubbles()


def get_bubble_manager():
    """Get bubble manager (returns API client for compatibility)."""
    return get_aiochi_bubble_client()


def is_aiochi_available() -> bool:
    """Check if AIOCHI bubble container is available."""
    client = get_aiochi_bubble_client()
    health = client.get_health()
    return health is not None and health.get("status") in ("running", "starting", "waiting_for_zeek")


# ==============================================================================
# D2D Communication Tracking (Device Coloring)
# ==============================================================================

class D2DCommunicationClient:
    """
    Client for D2D communication tracking and device coloring.

    Fetches communication cluster data from aiochi-bubble container.
    Each cluster gets a unique color for visual identification in the UI.

    Includes retry logic for container startup race conditions after reboot.
    """

    def __init__(self, base_url: str = AIOCHI_BUBBLE_URL):
        self.base_url = base_url.rstrip('/')
        self._color_cache: Dict[str, Dict] = {}
        self._cache_timestamp: Optional[float] = None
        self._cache_ttl = 30  # Cache for 30 seconds
        self._last_ready_check: Optional[float] = None
        self._container_ready: bool = False

    def _get(self, endpoint: str) -> Optional[Dict]:
        """Make GET request to API."""
        try:
            url = f"{self.base_url}{endpoint}"
            response = requests.get(url, timeout=API_TIMEOUT)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.debug(f"D2D API request failed: {e}")
            return None

    def _is_container_ready(self, force_check: bool = False) -> bool:
        """
        Check if aiochi-bubble container is fully ready.

        Only returns True when status is 'running' (not 'starting' or 'waiting_for_zeek').
        Caches result for 10 seconds to avoid excessive health checks.
        """
        now = time.time()

        # Use cached result if recent and not forcing
        if not force_check and self._last_ready_check is not None:
            if now - self._last_ready_check < 10:
                return self._container_ready

        # Check container health
        health = self._get("/health")
        self._last_ready_check = now

        if health is None:
            self._container_ready = False
            return False

        status = health.get("status", "")
        # Only consider "running" as fully ready
        self._container_ready = status == "running"

        if not self._container_ready:
            logger.debug(f"D2D container not ready yet: status={status}")

        return self._container_ready

    def _wait_for_ready(self, max_wait: float = 5.0) -> bool:
        """
        Wait for container to become ready with exponential backoff.

        Args:
            max_wait: Maximum time to wait in seconds

        Returns:
            True if container became ready, False if timeout
        """
        start = time.time()
        attempt = 0

        while time.time() - start < max_wait:
            if self._is_container_ready(force_check=True):
                return True

            # Exponential backoff: 0.5s, 1s, 2s...
            delay = min(RETRY_DELAY_BASE * (2 ** attempt), max_wait - (time.time() - start))
            if delay > 0:
                time.sleep(delay)
            attempt += 1

        return False

    def _is_cache_valid(self) -> bool:
        """Check if color cache is still valid."""
        if self._cache_timestamp is None:
            return False
        return (time.time() - self._cache_timestamp) < self._cache_ttl

    def get_all_device_colors(self, force_refresh: bool = False) -> Dict[str, Dict]:
        """
        Get cluster colors for all devices.

        Includes retry logic for post-reboot container startup race conditions.

        Returns:
            Dict mapping MAC -> {cluster_id, color, ecosystem, device_count}
        """
        # Return cached data if valid
        if not force_refresh and self._is_cache_valid() and self._color_cache:
            return self._color_cache

        # Check if container is ready, wait briefly if not
        if not self._is_container_ready():
            # On first load after reboot, wait for container to be ready
            if not self._wait_for_ready(max_wait=3.0):
                logger.warning("D2D container not ready after waiting, returning stale cache")
                # Don't cache the failure - return stale cache without updating timestamp
                return self._color_cache if self._color_cache else {}

        # Container is ready, fetch fresh data
        result = self._get("/api/devices")

        # If request failed, don't update cache timestamp (allow retry on next call)
        if not result:
            logger.debug("D2D API request failed, returning stale cache")
            return self._color_cache if self._color_cache else {}

        # Check for API error response
        if "error" in result:
            logger.debug(f"D2D API returned error: {result.get('error')}")
            return self._color_cache if self._color_cache else {}

        devices = result.get("devices", [])

        # Build new cache from successful response
        new_cache = {}
        for device in devices:
            mac = device.get("mac", "").upper()
            if mac:
                new_cache[mac] = {
                    "cluster_id": device.get("cluster_id"),
                    "cluster_color": device.get("cluster_color"),
                    "ecosystem": device.get("ecosystem", "unknown"),
                    "last_seen": device.get("last_seen"),
                }

        # Update cache with successful data
        self._color_cache = new_cache
        self._cache_timestamp = time.time()
        logger.debug(f"D2D color cache updated with {len(new_cache)} devices")

        return self._color_cache

    def get_device_cluster_color(self, mac: str) -> Optional[Dict]:
        """
        Get the cluster color for a specific device.

        Args:
            mac: Device MAC address

        Returns:
            Dict with cluster_id, color, ecosystem, or None if not found
        """
        mac = mac.upper().replace("-", ":")

        # Check cache first
        if self._is_cache_valid() and mac in self._color_cache:
            return self._color_cache[mac]

        # Fetch from API
        result = self._get(f"/api/devices/{mac}")
        if not result or "error" in result:
            return None

        return {
            "cluster_id": result.get("cluster_id"),
            "cluster_color": result.get("cluster_color"),
            "ecosystem": result.get("ecosystem", "unknown"),
            "communicates_with": result.get("communicates_with", []),
        }

    def get_communication_clusters(self) -> List[Dict]:
        """
        Get all communication clusters with their colors.

        Returns:
            List of clusters, each with:
            - cluster_id: Unique identifier
            - color: Hex color code
            - devices: List of MACs in cluster
            - device_count: Number of devices
        """
        # Check if container is ready, wait briefly if not
        if not self._is_container_ready():
            if not self._wait_for_ready(max_wait=3.0):
                logger.debug("D2D container not ready for clusters request")
                return []

        result = self._get("/api/communication/clusters")
        if not result or "error" in result:
            return []

        return result.get("clusters", [])

    def get_communication_graph(self) -> Dict:
        """
        Get full communication graph for visualization.

        Returns:
            Dict with:
            - nodes: List of devices with colors
            - edges: List of communication links with strength
        """
        # Check if container is ready, wait briefly if not
        if not self._is_container_ready():
            if not self._wait_for_ready(max_wait=3.0):
                logger.debug("D2D container not ready for graph request")
                return {"nodes": [], "edges": []}

        result = self._get("/api/communication/graph")
        if not result or "error" in result:
            return {"nodes": [], "edges": []}

        return result

    def get_stats(self) -> Dict:
        """Get D2D tracking statistics."""
        result = self._get("/api/stats")
        if not result:
            return {}
        return result


# Singleton instance
_d2d_client: Optional[D2DCommunicationClient] = None


def get_d2d_client() -> D2DCommunicationClient:
    """Get singleton D2D communication client."""
    global _d2d_client
    if _d2d_client is None:
        _d2d_client = D2DCommunicationClient()
    return _d2d_client


def get_device_colors() -> Dict[str, Dict]:
    """Get D2D cluster colors for all devices (convenience function)."""
    return get_d2d_client().get_all_device_colors()


def get_device_cluster_color(mac: str) -> Optional[Dict]:
    """Get D2D cluster color for a specific device (convenience function)."""
    return get_d2d_client().get_device_cluster_color(mac)
