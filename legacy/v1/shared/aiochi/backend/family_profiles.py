"""
AIOCHI Family Profiles
Per-user dashboard customization with persona-aware narratives.

Each family member can have their own profile with:
- Assigned device bubbles
- Persona (parent, gamer, worker, kid)
- Custom quick actions
- Notification preferences
- Dashboard theme
"""

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class Persona(str, Enum):
    """User personas for narrative customization."""
    PARENT = "parent"       # Safety-focused, simplified
    GAMER = "gamer"         # Performance-focused, latency alerts
    WORKER = "worker"       # Productivity-focused, uptime priority
    KID = "kid"             # Fun, educational, limited info
    PRIVACY = "privacy"     # Security-focused, detailed
    TECH = "tech"           # Technical details, full access


class ProfileTheme(str, Enum):
    """Dashboard color themes."""
    DEFAULT = "default"     # Blue (#4fc3f7)
    DARK = "dark"           # Dark blue (#16213e)
    GREEN = "green"         # Success green (#81c784)
    PURPLE = "purple"       # Purple (#ba68c8)
    ORANGE = "orange"       # Warning orange (#ffb74d)
    RED = "red"             # Alert red (#e57373)


@dataclass
class NotificationPreferences:
    """Push notification preferences per profile."""
    security_alerts: bool = True
    device_events: bool = True
    performance_alerts: bool = True
    quiet_hours_enabled: bool = False
    quiet_hours_start: Optional[str] = "22:00"  # HH:MM
    quiet_hours_end: Optional[str] = "07:00"
    critical_override: bool = True  # Always notify on critical


@dataclass
class QuickActionConfig:
    """Quick action configuration for a profile."""
    action_id: str
    visible: bool = True
    pinned: bool = False
    custom_label: Optional[str] = None


@dataclass
class FamilyProfile:
    """Individual family member profile."""
    id: str
    name: str
    persona: Persona = Persona.PARENT
    avatar_emoji: str = "👤"
    theme: ProfileTheme = ProfileTheme.DEFAULT
    assigned_bubbles: List[str] = field(default_factory=list)  # Bubble IDs
    quick_actions: List[QuickActionConfig] = field(default_factory=list)
    notifications: NotificationPreferences = field(default_factory=NotificationPreferences)
    pin_code: Optional[str] = None  # 4-digit PIN for kid profiles
    is_admin: bool = False
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_active: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        data['persona'] = self.persona.value
        data['theme'] = self.theme.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FamilyProfile':
        """Create from dictionary."""
        data = data.copy()
        data['persona'] = Persona(data.get('persona', 'parent'))
        data['theme'] = ProfileTheme(data.get('theme', 'default'))

        # Convert nested objects
        if 'notifications' in data and isinstance(data['notifications'], dict):
            data['notifications'] = NotificationPreferences(**data['notifications'])
        else:
            data['notifications'] = NotificationPreferences()

        if 'quick_actions' in data:
            data['quick_actions'] = [
                QuickActionConfig(**qa) if isinstance(qa, dict) else qa
                for qa in data['quick_actions']
            ]

        return cls(**data)


class FamilyProfileManager:
    """
    Manages family profiles for AIOCHI.

    Profiles are stored in a JSON file and provide:
    - Per-user dashboard customization
    - Persona-aware narrative generation
    - Device bubble assignments
    - Notification preferences
    """

    DEFAULT_PROFILES_PATH = Path("/etc/hookprobe/aiochi/profiles.json")

    def __init__(self, profiles_path: Optional[Path] = None):
        self.profiles_path = profiles_path or self.DEFAULT_PROFILES_PATH
        self._profiles: Dict[str, FamilyProfile] = {}
        self._load_profiles()

    def _load_profiles(self) -> None:
        """Load profiles from JSON file."""
        if self.profiles_path.exists():
            try:
                with open(self.profiles_path, 'r') as f:
                    data = json.load(f)
                    for profile_data in data.get('profiles', []):
                        profile = FamilyProfile.from_dict(profile_data)
                        self._profiles[profile.id] = profile
                logger.info(f"Loaded {len(self._profiles)} family profiles")
            except Exception as e:
                logger.error(f"Failed to load profiles: {e}")
                self._create_default_profiles()
        else:
            self._create_default_profiles()

    def _save_profiles(self) -> None:
        """Save profiles to JSON file."""
        try:
            self.profiles_path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                'version': '1.0',
                'updated_at': datetime.now().isoformat(),
                'profiles': [p.to_dict() for p in self._profiles.values()]
            }
            with open(self.profiles_path, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info(f"Saved {len(self._profiles)} family profiles")
        except Exception as e:
            logger.error(f"Failed to save profiles: {e}")

    def _create_default_profiles(self) -> None:
        """Create default family profiles."""
        defaults = [
            FamilyProfile(
                id="admin",
                name="Admin",
                persona=Persona.TECH,
                avatar_emoji="🔧",
                theme=ProfileTheme.DEFAULT,
                is_admin=True,
                quick_actions=[
                    QuickActionConfig("pause_kids", visible=True, pinned=True),
                    QuickActionConfig("game_mode", visible=True),
                    QuickActionConfig("privacy_mode", visible=True, pinned=True),
                    QuickActionConfig("guest_lockdown", visible=True),
                ]
            ),
            FamilyProfile(
                id="parent",
                name="Parent",
                persona=Persona.PARENT,
                avatar_emoji="👨‍👩‍👧‍👦",
                theme=ProfileTheme.GREEN,
                quick_actions=[
                    QuickActionConfig("pause_kids", visible=True, pinned=True),
                    QuickActionConfig("privacy_mode", visible=True),
                    QuickActionConfig("guest_lockdown", visible=True),
                ]
            ),
            FamilyProfile(
                id="gamer",
                name="Gamer",
                persona=Persona.GAMER,
                avatar_emoji="🎮",
                theme=ProfileTheme.PURPLE,
                quick_actions=[
                    QuickActionConfig("game_mode", visible=True, pinned=True,
                                     custom_label="BOOST!"),
                ]
            ),
            FamilyProfile(
                id="kid",
                name="Kid",
                persona=Persona.KID,
                avatar_emoji="🧒",
                theme=ProfileTheme.ORANGE,
                pin_code="0000",  # Should be changed
                quick_actions=[],  # Kids don't see quick actions
                notifications=NotificationPreferences(
                    security_alerts=False,  # Simplified for kids
                    device_events=False,
                    performance_alerts=False,
                )
            ),
        ]

        for profile in defaults:
            self._profiles[profile.id] = profile

        self._save_profiles()
        logger.info("Created default family profiles")

    def get_profile(self, profile_id: str) -> Optional[FamilyProfile]:
        """Get a profile by ID."""
        return self._profiles.get(profile_id)

    def get_all_profiles(self) -> List[FamilyProfile]:
        """Get all profiles."""
        return list(self._profiles.values())

    def create_profile(self, profile: FamilyProfile) -> bool:
        """Create a new profile."""
        if profile.id in self._profiles:
            logger.warning(f"Profile {profile.id} already exists")
            return False

        self._profiles[profile.id] = profile
        self._save_profiles()
        return True

    def update_profile(self, profile_id: str, updates: Dict[str, Any]) -> bool:
        """Update an existing profile."""
        if profile_id not in self._profiles:
            logger.warning(f"Profile {profile_id} not found")
            return False

        profile = self._profiles[profile_id]

        # Apply updates
        for key, value in updates.items():
            if hasattr(profile, key):
                if key == 'persona':
                    value = Persona(value)
                elif key == 'theme':
                    value = ProfileTheme(value)
                elif key == 'notifications' and isinstance(value, dict):
                    value = NotificationPreferences(**value)
                setattr(profile, key, value)

        self._save_profiles()
        return True

    def delete_profile(self, profile_id: str) -> bool:
        """Delete a profile."""
        if profile_id not in self._profiles:
            return False

        # Prevent deleting admin
        if self._profiles[profile_id].is_admin:
            logger.warning("Cannot delete admin profile")
            return False

        del self._profiles[profile_id]
        self._save_profiles()
        return True

    def set_active(self, profile_id: str) -> bool:
        """Mark a profile as active (last used)."""
        if profile_id in self._profiles:
            self._profiles[profile_id].last_active = datetime.now().isoformat()
            self._save_profiles()
            return True
        return False

    def verify_pin(self, profile_id: str, pin: str) -> bool:
        """Verify PIN for kid profiles."""
        profile = self._profiles.get(profile_id)
        if not profile or not profile.pin_code:
            return True  # No PIN required
        return profile.pin_code == pin

    def get_narrative_config(self, profile_id: str) -> Dict[str, Any]:
        """Get narrative configuration for a profile's persona."""
        profile = self._profiles.get(profile_id)
        if not profile:
            profile = self._profiles.get('parent', FamilyProfile(id='default', name='Default'))

        # Persona-specific narrative styles
        configs = {
            Persona.PARENT: {
                'tone': 'reassuring',
                'detail_level': 'simple',
                'emoji_enabled': True,
                'focus': ['safety', 'family'],
                'hide_technical': True,
            },
            Persona.GAMER: {
                'tone': 'energetic',
                'detail_level': 'medium',
                'emoji_enabled': True,
                'focus': ['performance', 'latency'],
                'hide_technical': False,
            },
            Persona.WORKER: {
                'tone': 'professional',
                'detail_level': 'medium',
                'emoji_enabled': False,
                'focus': ['uptime', 'reliability'],
                'hide_technical': False,
            },
            Persona.KID: {
                'tone': 'fun',
                'detail_level': 'minimal',
                'emoji_enabled': True,
                'focus': ['positive'],
                'hide_technical': True,
                'hide_threats': True,  # Don't scare kids
            },
            Persona.PRIVACY: {
                'tone': 'serious',
                'detail_level': 'detailed',
                'emoji_enabled': False,
                'focus': ['security', 'privacy'],
                'hide_technical': False,
            },
            Persona.TECH: {
                'tone': 'technical',
                'detail_level': 'full',
                'emoji_enabled': False,
                'focus': ['all'],
                'hide_technical': False,
                'show_raw_data': True,
            },
        }

        return configs.get(profile.persona, configs[Persona.PARENT])
