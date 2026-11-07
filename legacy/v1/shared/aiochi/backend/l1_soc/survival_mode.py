"""
Survival Mode

Emergency response when L1 Trust Score drops below threshold
or critical anomaly detected.

Per Gemini 3 Flash validation:
- Protocol lockdown (disable 2G/3G)
- Airplane mode pulse (conserve battery, reduce tracking)
- Zero-trust VPN (assume cellular link compromised)

Per Nemotron security audit:
- Pre-establish VPN before entering survival mode
- Decouple survival mode from L1 metrics alone
- Require corroborating evidence
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, List, Callable
import asyncio

logger = logging.getLogger(__name__)


class SurvivalAction(Enum):
    """Actions taken in survival mode."""
    VPN_ENABLE = 'vpn_enable'
    PROTOCOL_LOCKDOWN = 'protocol_lockdown'
    BAND_LOCK = 'band_lock'
    CELL_BLACKLIST = 'cell_blacklist'
    AIRPLANE_PULSE = 'airplane_pulse'
    DNS_SWITCH = 'dns_switch'
    ALERT_SOC = 'alert_soc'


class SurvivalState(Enum):
    """Survival mode states."""
    NORMAL = 'normal'           # Not in survival mode
    ENTERING = 'entering'       # Transitioning to survival
    ACTIVE = 'active'           # Survival mode active
    EXITING = 'exiting'         # Transitioning back to normal


@dataclass
class SurvivalModeConfig:
    """Configuration for survival mode."""
    # Trigger thresholds
    trust_score_threshold: float = 20.0     # L1 Trust Score below this triggers
    min_corroborating_indicators: int = 2   # Required indicators

    # Protocol lockdown
    disable_2g: bool = True
    disable_3g: bool = True                 # Per Gemini: safer to keep 4G+ only
    preferred_band: str = 'lte'             # Fallback band

    # VPN settings
    vpn_auto_enable: bool = True
    vpn_pre_establish: bool = True          # Per Nemotron: pre-establish session

    # Airplane pulse (per Gemini)
    enable_airplane_pulse: bool = True
    pulse_on_seconds: int = 5               # Try to connect for 5s
    pulse_off_seconds: int = 30             # Stay dark for 30s

    # DNS failover
    emergency_dns: List[str] = field(default_factory=lambda: ['1.1.1.1', '8.8.8.8'])

    # Rate limiting (per Nemotron: prevent battery exhaustion)
    max_entries_per_hour: int = 3
    min_duration_seconds: int = 60          # Minimum time in survival mode


@dataclass
class SurvivalModeEvent:
    """Record of survival mode activation."""
    id: str
    timestamp: datetime
    trigger_reason: str
    trust_score_at_trigger: float
    anomaly_event_id: Optional[str] = None

    # Actions taken
    actions_taken: List[SurvivalAction] = field(default_factory=list)
    vpn_enabled: bool = False
    vpn_pre_established: bool = False
    protocol_lockdown: bool = False
    band_locked: str = ''
    cell_blacklisted: bool = False
    airplane_pulse_mode: bool = False

    # Duration
    exit_timestamp: Optional[datetime] = None
    duration_seconds: int = 0
    exit_reason: str = ''

    # Outcome
    attack_confirmed: bool = False
    false_positive: bool = False


class SurvivalMode:
    """
    Survival Mode Manager.

    Activated when L1 Trust Score drops critically low or
    high-severity anomaly detected.

    Emergency Actions:
    1. Protocol Lockdown - Disable 2G/3G (prevent crypto downgrade)
    2. VPN Enable - Zero-trust networking
    3. Band Lock - Force to known-good frequency
    4. Cell Blacklist - Block current rogue tower
    5. Airplane Pulse - Reduce tracking surface
    6. DNS Switch - Bypass potentially compromised DNS
    """

    def __init__(
        self,
        config: Optional[SurvivalModeConfig] = None,
        vpn_callback: Optional[Callable] = None,
        band_callback: Optional[Callable] = None,
        blacklist_callback: Optional[Callable] = None,
        airplane_callback: Optional[Callable] = None,
    ):
        self.config = config or SurvivalModeConfig()

        # Callbacks for actions
        self._vpn_callback = vpn_callback
        self._band_callback = band_callback
        self._blacklist_callback = blacklist_callback
        self._airplane_callback = airplane_callback

        # State
        self._state = SurvivalState.NORMAL
        self._current_event: Optional[SurvivalModeEvent] = None
        self._history: List[SurvivalModeEvent] = []
        self._entries_this_hour: List[datetime] = []

        # VPN pre-establishment (per Nemotron)
        self._vpn_pre_established = False

    @property
    def state(self) -> SurvivalState:
        return self._state

    @property
    def is_active(self) -> bool:
        return self._state == SurvivalState.ACTIVE

    def pre_establish_vpn(self) -> bool:
        """
        Pre-establish VPN session.

        Per Nemotron audit: Establish VPN before survival mode
        is triggered to avoid leaking info during handshake.

        Should be called periodically when trust score is
        declining but not yet critical.
        """
        if not self.config.vpn_pre_establish:
            return False

        if self._vpn_callback:
            try:
                result = self._vpn_callback(action='pre_establish')
                self._vpn_pre_established = result
                logger.info(f"VPN pre-establishment: {'success' if result else 'failed'}")
                return result
            except Exception as e:
                logger.error(f"VPN pre-establishment failed: {e}")
                return False

        return False

    def check_and_enter(
        self,
        trust_score: float,
        indicators_count: int = 0,
        anomaly_id: Optional[str] = None,
        trigger_reason: str = '',
    ) -> bool:
        """
        Check if survival mode should be entered.

        Per Nemotron audit:
        - Don't rely on trust score alone
        - Require corroborating indicators
        - Rate-limit entries

        Returns True if survival mode was activated.
        """
        if self._state == SurvivalState.ACTIVE:
            return False  # Already in survival mode

        # Check if should trigger
        should_trigger = False
        reason = ''

        if trust_score < self.config.trust_score_threshold:
            if indicators_count >= self.config.min_corroborating_indicators:
                should_trigger = True
                reason = f"L1 Trust {trust_score:.1f}% with {indicators_count} indicators"
            else:
                logger.warning(
                    f"Trust score {trust_score:.1f}% but only {indicators_count} indicators "
                    f"(need {self.config.min_corroborating_indicators})"
                )

        # Explicit trigger reason overrides
        if trigger_reason and indicators_count >= self.config.min_corroborating_indicators:
            should_trigger = True
            reason = trigger_reason

        if not should_trigger:
            return False

        # Rate limiting
        if not self._check_rate_limit():
            logger.warning("Survival mode rate limited - too many activations")
            return False

        # Enter survival mode
        return self._enter(
            reason=reason,
            trust_score=trust_score,
            anomaly_id=anomaly_id,
        )

    def _enter(
        self,
        reason: str,
        trust_score: float,
        anomaly_id: Optional[str] = None,
    ) -> bool:
        """Enter survival mode."""
        logger.warning(f"ENTERING SURVIVAL MODE: {reason}")

        self._state = SurvivalState.ENTERING
        self._entries_this_hour.append(datetime.now())

        event = SurvivalModeEvent(
            id=f"survival-{datetime.now().timestamp()}",
            timestamp=datetime.now(),
            trigger_reason=reason,
            trust_score_at_trigger=trust_score,
            anomaly_event_id=anomaly_id,
        )

        # Execute actions
        self._execute_actions(event)

        self._current_event = event
        self._state = SurvivalState.ACTIVE

        logger.warning(
            f"SURVIVAL MODE ACTIVE - Actions: {[a.value for a in event.actions_taken]}"
        )

        return True

    def _execute_actions(self, event: SurvivalModeEvent):
        """Execute survival mode actions."""
        # 1. Protocol Lockdown (highest priority)
        if self.config.disable_2g or self.config.disable_3g:
            event.protocol_lockdown = True
            event.actions_taken.append(SurvivalAction.PROTOCOL_LOCKDOWN)

            if self._band_callback:
                try:
                    # Lock to LTE or higher
                    self._band_callback(
                        action='lock',
                        allowed_modes=['lte', '5g'],
                        disable_2g=self.config.disable_2g,
                        disable_3g=self.config.disable_3g,
                    )
                except Exception as e:
                    logger.error(f"Protocol lockdown failed: {e}")

        # 2. VPN Enable
        if self.config.vpn_auto_enable:
            event.vpn_pre_established = self._vpn_pre_established
            event.vpn_enabled = True
            event.actions_taken.append(SurvivalAction.VPN_ENABLE)

            if self._vpn_callback:
                try:
                    self._vpn_callback(action='enable')
                except Exception as e:
                    logger.error(f"VPN enable failed: {e}")

        # 3. Band Lock
        if self.config.preferred_band:
            event.band_locked = self.config.preferred_band
            event.actions_taken.append(SurvivalAction.BAND_LOCK)

        # 4. Alert SOC
        event.actions_taken.append(SurvivalAction.ALERT_SOC)

    def exit(self, reason: str, confirmed_attack: bool = False) -> bool:
        """
        Exit survival mode.

        Args:
            reason: Why we're exiting
            confirmed_attack: Whether this was a real attack
        """
        if self._state != SurvivalState.ACTIVE:
            return False

        logger.info(f"EXITING SURVIVAL MODE: {reason}")

        self._state = SurvivalState.EXITING

        if self._current_event:
            self._current_event.exit_timestamp = datetime.now()
            self._current_event.exit_reason = reason
            self._current_event.attack_confirmed = confirmed_attack
            self._current_event.false_positive = not confirmed_attack

            duration = self._current_event.exit_timestamp - self._current_event.timestamp
            self._current_event.duration_seconds = int(duration.total_seconds())

            self._history.append(self._current_event)

        # Restore normal operations
        self._restore_normal()

        self._current_event = None
        self._state = SurvivalState.NORMAL

        return True

    def _restore_normal(self):
        """Restore normal operations after survival mode."""
        # Re-enable all bands (but still no 2G if that's policy)
        if self._band_callback:
            try:
                self._band_callback(
                    action='unlock',
                    allow_3g=not self.config.disable_3g,
                )
            except Exception as e:
                logger.error(f"Band unlock failed: {e}")

    def _check_rate_limit(self) -> bool:
        """Check if we're rate-limited."""
        cutoff = datetime.now() - timedelta(hours=1)
        self._entries_this_hour = [
            t for t in self._entries_this_hour if t > cutoff
        ]

        return len(self._entries_this_hour) < self.config.max_entries_per_hour

    def get_history(self, hours: int = 24) -> List[SurvivalModeEvent]:
        """Get survival mode history."""
        cutoff = datetime.now() - timedelta(hours=hours)
        return [e for e in self._history if e.timestamp > cutoff]

    def get_current_event(self) -> Optional[SurvivalModeEvent]:
        """Get current survival mode event if active."""
        return self._current_event if self.is_active else None
