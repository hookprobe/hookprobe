"""
MSSP Bootstrap — First-Boot Provisioning

Handles the provision → claim code → API key delivery flow for all
HookProbe products. Called once on first boot; subsequent boots read
the API key from /etc/hookprobe/node.conf.

Flow:
    1. Check if already provisioned (node.conf has API_KEY)
    2. Collect device fingerprint
    3. POST /api/nodes/provision → receive claim code
    4. Display claim code for user to enter in dashboard
    5. Poll GET /api/nodes/provision/status until claimed
    6. Write API_KEY + MSSP_URL to /etc/hookprobe/node.conf
    7. Return API key for immediate use
"""

import hashlib
import json
import logging
import os
import platform
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

CONFIG_PATH = Path("/etc/hookprobe/node.conf")
POLL_INTERVAL = 5  # seconds between status polls
MAX_POLL_TIME = 900  # 15 minutes max wait for claim


class MSSPBootstrap:
    """First-boot provisioning for HookProbe products."""

    def __init__(
        self,
        product_type: str,
        mssp_url: str = "",
        config_path: Optional[Path] = None,
    ):
        self._product_type = product_type
        self._config_path = config_path or CONFIG_PATH
        self._mssp_url = (
            mssp_url
            or os.environ.get("MSSP_URL", "")
            or self._read_config("MSSP_URL")
            or "https://mssp.hookprobe.com"
        )

    def provision_if_needed(self) -> str:
        """Return API key — from config if already provisioned, or bootstrap fresh.

        Returns empty string if provisioning fails or times out.
        """
        # Already provisioned?
        existing_key = self._read_config("API_KEY")
        if existing_key:
            logger.info("Already provisioned (API_KEY found in %s)", self._config_path)
            return existing_key

        logger.info("No API_KEY found — starting provisioning for %s", self._product_type)

        # Collect fingerprint
        fingerprint = self._get_fingerprint()
        hostname = platform.node()

        # POST /api/nodes/provision
        provision_data = {
            "hostname": hostname,
            "nodeType": self._product_type,
            "fingerprint": fingerprint,
        }

        resp = self._post("/api/nodes/provision", provision_data)
        if not resp or not resp.get("success"):
            error = resp.get("error", "Unknown error") if resp else "No response"
            logger.error("Provisioning failed: %s", error)
            return ""

        data = resp.get("data", {})
        status = data.get("status")

        # Already registered — need to check if we have the key
        if status == "already_registered":
            logger.warning(
                "Device already registered (node %s) but no local API_KEY. "
                "Re-provision or manually set API_KEY in %s",
                data.get("existingNodeId", "?"),
                self._config_path,
            )
            return ""

        provision_id = data.get("provisionId", "")
        claim_code = data.get("claimCode", "")

        if not provision_id or not claim_code:
            logger.error("Invalid provision response: %s", data)
            return ""

        # Display claim code
        self._display_claim_code(claim_code)

        # Poll for claim
        api_key = self._poll_for_claim(provision_id)
        if not api_key:
            logger.error("Provisioning timed out — claim code was not entered in dashboard")
            return ""

        # Write config
        self._write_config(api_key)
        logger.info("Provisioning complete — API key written to %s", self._config_path)
        return api_key

    # ------------------------------------------------------------------
    # Fingerprint
    # ------------------------------------------------------------------

    @staticmethod
    def _get_fingerprint() -> dict:
        """Collect device fingerprint matching dashboard's hashFingerprint()."""
        machine_id = ""
        try:
            machine_id = Path("/etc/machine-id").read_text().strip()
        except Exception:
            pass

        hostname = platform.node()

        mac_addresses = []
        try:
            result = os.popen("ip -o link show | awk -F'\\\\s+' '{print $2, $(NF-2)}'")
            for line in result.read().splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    iface = parts[0].rstrip(":")
                    mac = parts[1]
                    if iface != "lo" and mac != "00:00:00:00:00:00":
                        mac_addresses.append(mac)
        except Exception:
            pass

        return {
            "machineId": machine_id,
            "hostname": hostname,
            "macAddresses": sorted(mac_addresses),
        }

    # ------------------------------------------------------------------
    # Claim code display
    # ------------------------------------------------------------------

    def _display_claim_code(self, code: str) -> None:
        """Print claim code prominently so the user can enter it in the dashboard."""
        separator = "=" * 60
        msg = (
            f"\n{separator}\n"
            f"  HOOKPROBE {self._product_type.upper()} — CLAIM CODE\n"
            f"{separator}\n\n"
            f"  Enter this code in the HookProbe dashboard to claim this node:\n\n"
            f"       {code}\n\n"
            f"  Dashboard: {self._mssp_url}\n"
            f"  Code expires in 15 minutes.\n"
            f"\n{separator}\n"
        )
        # Print to stdout AND log
        print(msg)
        logger.info("Claim code: %s (enter in dashboard at %s)", code, self._mssp_url)

    # ------------------------------------------------------------------
    # Polling
    # ------------------------------------------------------------------

    def _poll_for_claim(self, provision_id: str) -> str:
        """Poll provision/status until claimed or timeout. Returns API key or empty."""
        start = time.time()
        attempt = 0

        while time.time() - start < MAX_POLL_TIME:
            attempt += 1
            try:
                url = f"{self._mssp_url.rstrip('/')}/api/nodes/provision/status?id={provision_id}"
                req = urllib.request.Request(url, method="GET", headers={
                    "Accept": "application/json",
                    "User-Agent": f"HookProbe-Bootstrap/{self._product_type}",
                })
                with urllib.request.urlopen(req, timeout=10) as resp:
                    body = json.loads(resp.read())

                data = body.get("data", {})
                if data.get("claimed"):
                    api_key = data.get("apiKey", "")
                    if api_key:
                        return api_key
                    logger.warning("Claimed but no apiKey in response")
                    return ""

                # Not claimed yet — continue polling
                if attempt % 12 == 0:  # Every ~60 seconds
                    logger.info(
                        "Waiting for claim code to be entered in dashboard... (%ds elapsed)",
                        int(time.time() - start),
                    )

            except Exception as e:
                logger.debug("Poll error (attempt %d): %s", attempt, e)

            time.sleep(POLL_INTERVAL)

        return ""

    # ------------------------------------------------------------------
    # Config file
    # ------------------------------------------------------------------

    def _read_config(self, key: str) -> str:
        """Read a value from the node config file."""
        # Check environment first
        val = os.environ.get(key)
        if val:
            return val

        try:
            if self._config_path.exists():
                for line in self._config_path.read_text().splitlines():
                    line = line.strip()
                    if line.startswith(f"{key}="):
                        return line.split("=", 1)[1].strip().strip("'\"")
        except Exception:
            pass
        return ""

    def _write_config(self, api_key: str) -> None:
        """Write API_KEY and MSSP_URL to node.conf."""
        self._config_path.parent.mkdir(parents=True, exist_ok=True)

        # Read existing config
        existing_lines: list = []
        if self._config_path.exists():
            existing_lines = self._config_path.read_text().splitlines()

        # Update or add keys
        updated = {"API_KEY": api_key, "MSSP_URL": self._mssp_url}
        written_keys: set = set()
        new_lines: list = []

        for line in existing_lines:
            key_part = line.split("=", 1)[0].strip() if "=" in line else ""
            if key_part in updated:
                new_lines.append(f"{key_part}={updated[key_part]}")
                written_keys.add(key_part)
            else:
                new_lines.append(line)

        for key, val in updated.items():
            if key not in written_keys:
                new_lines.append(f"{key}={val}")

        self._config_path.write_text("\n".join(new_lines) + "\n")

    # ------------------------------------------------------------------
    # HTTP helper
    # ------------------------------------------------------------------

    def _post(self, path: str, payload: dict) -> Optional[dict]:
        """POST JSON to MSSP API."""
        url = f"{self._mssp_url.rstrip('/')}{path}"
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, method="POST", headers={
            "Content-Type": "application/json",
            "User-Agent": f"HookProbe-Bootstrap/{self._product_type}",
        })
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read())
                return body
            except Exception:
                logger.error("Provision HTTP %d", e.code)
                return None
        except Exception as e:
            logger.error("Provision request error: %s", e)
            return None
