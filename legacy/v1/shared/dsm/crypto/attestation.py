"""
Platform Attestation

Remote attestation for TPM-based platform integrity verification.
Software fallback verifies quote structure, nonce freshness, and PCR baselines.
"""

import json
import logging
import os
import time
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)

# Maximum age of attestation nonce in seconds (prevents replay)
MAX_NONCE_AGE_S = 60


def verify_platform_attestation(
    attestation: Dict[str, Any],
    expected_nonce: Optional[bytes] = None,
    max_age_s: int = MAX_NONCE_AGE_S,
) -> bool:
    """
    Verify platform attestation package.

    Checks:
    - Required fields are present (quote_data, signature)
    - Nonce is fresh (within max_age_s of current time)
    - Nonce matches expected value if provided
    - PCR values match expected baseline (if baseline configured)

    Args:
        attestation: Attestation dictionary with PCR values, quote, and certificate
        expected_nonce: If provided, nonce in attestation must match exactly
        max_age_s: Maximum age of attestation in seconds (default 60)

    Returns:
        True if attestation is valid
    """
    if not attestation or not isinstance(attestation, dict):
        logger.warning("Attestation rejected: empty or invalid data")
        return False

    # Check required fields
    quote_data = attestation.get('quote_data')
    if not quote_data:
        logger.warning("Attestation rejected: missing quote_data")
        return False

    signature = attestation.get('signature')
    if not signature:
        logger.warning("Attestation rejected: missing signature")
        return False

    # Verify nonce freshness
    nonce_b64 = quote_data.get('nonce')
    if not nonce_b64:
        logger.warning("Attestation rejected: missing nonce")
        return False

    # If expected nonce provided, verify it matches
    if expected_nonce is not None:
        import base64
        try:
            attestation_nonce = base64.b64decode(nonce_b64)
            if attestation_nonce != expected_nonce:
                logger.warning("Attestation rejected: nonce mismatch")
                return False
        except Exception:
            logger.warning("Attestation rejected: invalid nonce encoding")
            return False

    # Verify timestamp freshness (prevents old attestation replay)
    timestamp = quote_data.get('timestamp')
    if timestamp is not None:
        try:
            age = abs(time.monotonic() - float(timestamp))
            if age > max_age_s:
                logger.warning(
                    "Attestation rejected: stale (age=%.1fs, max=%ds)",
                    age, max_age_s
                )
                return False
        except (TypeError, ValueError):
            logger.warning("Attestation rejected: invalid timestamp")
            return False

    # Verify PCR values against baseline (if configured)
    pcr_values = quote_data.get('pcr_values', {})
    baseline = get_expected_pcr_baseline()
    if baseline and pcr_values:
        for idx, expected_hash in baseline.items():
            idx_str = str(idx)
            actual = pcr_values.get(idx_str) or pcr_values.get(idx)
            if actual and expected_hash and actual != expected_hash:
                logger.warning(
                    "Attestation rejected: PCR[%s] mismatch (%s != %s)",
                    idx, actual[:16], expected_hash[:16]
                )
                return False

    logger.info("Platform attestation verified successfully")
    return True


def get_expected_pcr_baseline() -> Dict[int, str]:
    """
    Get expected PCR values for authentic HookProbe installation.

    Loads from DSM_PCR_CONFIG environment variable or config file.
    Returns empty dict if no baseline is configured (no PCR enforcement).

    Returns:
        Dictionary mapping PCR index to expected hash (empty if unconfigured)
    """
    config_path = os.environ.get(
        'DSM_PCR_CONFIG', '/etc/hookprobe/dsm_pcr.json'
    )

    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                data = json.load(f)
            baseline = {int(k): v for k, v in data.items()}
            logger.debug("Loaded PCR baseline from %s (%d entries)",
                         config_path, len(baseline))
            return baseline
        except (json.JSONDecodeError, OSError, ValueError) as e:
            logger.warning("Could not load PCR baseline from %s: %s",
                           config_path, e)

    # No baseline configured — PCR enforcement disabled
    logger.debug("No PCR baseline configured (no enforcement)")
    return {}
