"""
HookProbe MSSP API Client

Connects to hookprobe-com MSSP dashboard API for node management,
telemetry, QSecBit scoring, and fleet operations.

Usage:
    from hookprobe import HookProbeClient

    client = HookProbeClient(
        base_url="https://mssp.hookprobe.com",
        api_key="hp_..."
    )

    # List nodes
    nodes = client.list_nodes()

    # Get node details
    node = client.get_node("node-uuid")

    # Submit telemetry
    client.heartbeat(node_id="...", qsecbit=87, system={...})

    # Get QSecBit score
    score = client.get_qsecbit("node-uuid")
"""

import json
import logging
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)


class HookProbeError(Exception):
    """Base exception for HookProbe SDK errors."""
    def __init__(self, message: str, status_code: int = 0):
        super().__init__(message)
        self.status_code = status_code


class HookProbeClient:
    """Client for the HookProbe MSSP Dashboard API.

    Args:
        base_url: MSSP dashboard URL (e.g., "https://mssp.hookprobe.com")
        api_key: API key for authentication (X-API-Key header)
        timeout: Request timeout in seconds (default: 30)
    """

    def __init__(self, base_url: str = "https://mssp.hookprobe.com",
                 api_key: str = "", timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _request(self, method: str, path: str,
                 data: Optional[Dict] = None) -> Any:
        """Make an authenticated API request."""
        url = f"{self.base_url}{path}"
        headers = {
            "Content-Type": "application/json",
            "X-API-Key": self.api_key,
        }

        body = json.dumps(data).encode("utf-8") if data else None
        req = Request(url, data=body, headers=headers, method=method)

        try:
            with urlopen(req, timeout=self.timeout) as resp:
                response_data = resp.read().decode("utf-8")
                if response_data:
                    return json.loads(response_data)
                return None
        except HTTPError as e:
            body = e.read().decode("utf-8", errors="ignore")[:500]
            raise HookProbeError(f"API error {e.code}: {body}", e.code)
        except URLError as e:
            raise HookProbeError(f"Connection error: {e.reason}")

    # --- Node Management ---

    def list_nodes(self, site_slug: Optional[str] = None) -> List[Dict]:
        """List all nodes, optionally filtered by site."""
        path = f"/api/sites/{site_slug}/fleet" if site_slug else "/api/nodes"
        return self._request("GET", path) or []

    def get_node(self, node_id: str) -> Dict:
        """Get node details including telemetry and QSecBit score."""
        return self._request("GET", f"/api/nodes/{node_id}") or {}

    def get_qsecbit(self, node_id: str) -> Dict:
        """Get QSecBit score breakdown for a node."""
        return self._request("GET", f"/api/nodes/qsecbit?nodeId={node_id}") or {}

    # --- Telemetry ---

    def heartbeat(self, node_id: str, qsecbit: Optional[int] = None,
                  system: Optional[Dict] = None,
                  network: Optional[Dict] = None,
                  security: Optional[Dict] = None) -> Dict:
        """Submit node heartbeat with telemetry data."""
        payload: Dict[str, Any] = {"nodeId": node_id}
        if qsecbit is not None:
            payload["qsecbit"] = qsecbit
        if system:
            payload["system"] = system
        if network:
            payload["network"] = network
        if security:
            payload["security"] = security
        return self._request("POST", "/api/nodes/heartbeat", payload) or {}

    def submit_telemetry(self, node_id: str, telemetry_type: str,
                         data: Dict) -> Dict:
        """Submit specific telemetry data (system, network, security, fim, auth)."""
        return self._request("POST", "/api/nodes/telemetry", {
            "nodeId": node_id,
            "type": telemetry_type,
            "data": data,
        }) or {}

    # --- Threat Intelligence ---

    def get_incidents(self, limit: int = 20) -> List[Dict]:
        """Get recent security incidents."""
        return self._request("GET", f"/api/xsoc/incidents?limit={limit}") or []

    def get_iocs(self, limit: int = 50) -> List[Dict]:
        """Get indicators of compromise."""
        return self._request("GET", f"/api/xsoc/iocs?limit={limit}") or []

    def get_verdicts(self, limit: int = 20) -> List[Dict]:
        """Get SENTINEL ML verdicts."""
        return self._request("GET", f"/api/xsoc/hydra/verdicts?limit={limit}") or []

    # --- Health ---

    def health(self) -> str:
        """Check MSSP dashboard health."""
        try:
            req = Request(f"{self.base_url}/health")
            with urlopen(req, timeout=5) as resp:
                return resp.read().decode("utf-8").strip()
        except Exception as e:
            return f"unhealthy: {e}"

    def __repr__(self) -> str:
        return f"HookProbeClient(base_url='{self.base_url}')"
