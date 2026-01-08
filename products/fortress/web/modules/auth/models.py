"""
Fortress User Model

JSON-based user storage for MVP. Can be migrated to SQLite/PostgreSQL later.
"""

import json
import hashlib
import logging
import os
import re
from pathlib import Path
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict

import bcrypt
from flask_login import UserMixin

# Security: Logger for admin setup events
logger = logging.getLogger(__name__)


# Maximum users for Fortress (small business platform)
MAX_USERS = 5


class UserRole(Enum):
    """User roles for access control."""
    ADMIN = "admin"           # Full access
    OPERATOR = "operator"     # Manage devices, view reports
    VIEWER = "viewer"         # Read-only dashboard access


@dataclass
class User(UserMixin):
    """User model for Fortress authentication."""

    id: str                   # Username (unique identifier)
    password_hash: str        # bcrypt hash
    role: str                 # UserRole value
    email: Optional[str] = None
    display_name: Optional[str] = None
    created_at: Optional[str] = None
    last_login: Optional[str] = None
    is_active: bool = True

    # Class-level storage path
    _storage_path: Path = Path('/etc/hookprobe/users.json')

    def get_id(self) -> str:
        """Return the user ID for Flask-Login."""
        return self.id

    @property
    def is_admin(self) -> bool:
        """Check if user has admin role."""
        return self.role == UserRole.ADMIN.value

    @property
    def is_operator(self) -> bool:
        """Check if user has operator role or higher."""
        return self.role in (UserRole.ADMIN.value, UserRole.OPERATOR.value)

    def check_password(self, password: str) -> bool:
        """Verify password against stored hash."""
        try:
            return bcrypt.checkpw(
                password.encode('utf-8'),
                self.password_hash.encode('utf-8')
            )
        except Exception:
            return False

    def set_password(self, password: str) -> None:
        """Set a new password (hashed)."""
        self.password_hash = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

    def update_last_login(self) -> None:
        """Update last login timestamp."""
        self.last_login = datetime.now().isoformat()
        self.save()

    def save(self) -> bool:
        """Save user to storage."""
        users = self._load_all_users()
        users[self.id] = {
            'password_hash': self.password_hash,
            'role': self.role,
            'email': self.email,
            'display_name': self.display_name,
            'created_at': self.created_at,
            'last_login': self.last_login,
            'is_active': self.is_active
        }
        return self._save_all_users(users)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (excluding password)."""
        return {
            'id': self.id,
            'role': self.role,
            'email': self.email,
            'display_name': self.display_name,
            'created_at': self.created_at,
            'last_login': self.last_login,
            'is_active': self.is_active
        }

    @classmethod
    def get(cls, user_id: str) -> Optional['User']:
        """Load a user by ID."""
        users = cls._load_all_users()
        if user_id in users:
            data = users[user_id]
            return cls(
                id=user_id,
                password_hash=data.get('password_hash', ''),
                role=data.get('role', UserRole.VIEWER.value),
                email=data.get('email'),
                display_name=data.get('display_name'),
                created_at=data.get('created_at'),
                last_login=data.get('last_login'),
                is_active=data.get('is_active', True)
            )
        return None

    @classmethod
    def authenticate(cls, username: str, password: str) -> Optional['User']:
        """Authenticate a user by username and password."""
        user = cls.get(username)
        if user and user.is_active and user.check_password(password):
            user.update_last_login()
            return user
        return None

    @classmethod
    def create(cls, username: str, password: str, role: str = UserRole.VIEWER.value,
               email: str = None, display_name: str = None) -> Optional['User']:
        """Create a new user.

        Enforces MAX_USERS limit (5 users for small business platform).
        Returns None if user exists or max users reached.
        """
        if cls.get(username):
            return None  # User already exists

        # Check max users limit
        users = cls._load_all_users()
        if len(users) >= MAX_USERS:
            return None  # Max users reached

        user = cls(
            id=username,
            password_hash='',
            role=role,
            email=email,
            display_name=display_name or username,
            created_at=datetime.now().isoformat(),
            is_active=True
        )
        user.set_password(password)
        user.save()
        return user

    @classmethod
    def can_create_user(cls) -> bool:
        """Check if a new user can be created (under MAX_USERS limit)."""
        users = cls._load_all_users()
        return len(users) < MAX_USERS

    @classmethod
    def user_count(cls) -> int:
        """Get current user count."""
        return len(cls._load_all_users())

    @classmethod
    def get_all(cls) -> list:
        """Get all users (without passwords)."""
        users = cls._load_all_users()
        return [
            cls(
                id=user_id,
                password_hash='',  # Don't expose hash
                role=data.get('role', UserRole.VIEWER.value),
                email=data.get('email'),
                display_name=data.get('display_name'),
                created_at=data.get('created_at'),
                last_login=data.get('last_login'),
                is_active=data.get('is_active', True)
            )
            for user_id, data in users.items()
        ]

    @classmethod
    def delete(cls, user_id: str) -> bool:
        """Delete a user."""
        users = cls._load_all_users()
        if user_id in users:
            del users[user_id]
            return cls._save_all_users(users)
        return False

    @classmethod
    def _load_all_users(cls) -> Dict[str, Any]:
        """Load all users from storage."""
        try:
            if cls._storage_path.exists():
                with open(cls._storage_path, 'r') as f:
                    data = json.load(f)
                    return data.get('users', {})
        except Exception:
            pass
        return {}

    @classmethod
    def _save_all_users(cls, users: Dict[str, Any]) -> bool:
        """Save all users to storage."""
        try:
            cls._storage_path.parent.mkdir(parents=True, exist_ok=True)
            with open(cls._storage_path, 'w') as f:
                json.dump({'users': users, 'version': '1.0'}, f, indent=2)
            cls._storage_path.chmod(0o600)
            return True
        except Exception:
            return False

    @staticmethod
    def _is_strong_password(password: str) -> bool:
        """
        Validate password strength requirements:
        - Minimum 12 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character
        """
        if len(password) < 12:
            return False
        if not re.search(r"[a-z]", password):
            return False
        if not re.search(r"[A-Z]", password):
            return False
        if not re.search(r"\d", password):
            return False
        if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]", password):
            return False
        return True

    @classmethod
    def ensure_admin_exists(cls) -> None:
        """
        Ensure at least one admin user exists for initial setup.

        Security: Reads admin password from FORTRESS_ADMIN_PASSWORD environment
        variable. Will NOT create an admin with a hardcoded or weak password.
        """
        users = cls._load_all_users()
        has_admin = any(
            u.get('role') == UserRole.ADMIN.value
            for u in users.values()
        )

        if has_admin:
            return  # Admin already exists

        # Security: Get password from environment variable only
        admin_password = os.environ.get('FORTRESS_ADMIN_PASSWORD')

        # Defense in depth: Clear environment variable after reading
        if admin_password and 'FORTRESS_ADMIN_PASSWORD' in os.environ:
            del os.environ['FORTRESS_ADMIN_PASSWORD']

        if not admin_password:
            logger.warning(
                "SECURITY: No FORTRESS_ADMIN_PASSWORD set. "
                "Admin user not created. Set env var during installation."
            )
            return

        if not cls._is_strong_password(admin_password):
            logger.error(
                "SECURITY: FORTRESS_ADMIN_PASSWORD does not meet strength "
                "requirements (min 12 chars, mixed case, digit, special char). "
                "Admin user not created."
            )
            return

        # Create admin with secure password from environment
        cls.create(
            username=os.environ.get('FORTRESS_ADMIN_USER', 'admin'),
            password=admin_password,
            role=UserRole.ADMIN.value,
            display_name='Administrator'
        )
        logger.info("Initial admin user created successfully.")
