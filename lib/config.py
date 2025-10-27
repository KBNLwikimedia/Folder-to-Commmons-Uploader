"""
Configuration module for Folder-to-Commons-Uploader.

Provides centralized settings management and constants.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional


# ============================================================================
# Constants
# ============================================================================

# API Configuration
API_TIMEOUT = 30
COMMONS_API = "https://commons.wikimedia.org/w/api.php"

# Application Configuration
CHECK_LOOP_INTERVAL_SEC = 6
READ_CHUNK = 1024 * 1024
THUMB_MAX = (300, 300)

# File readiness defaults
DEFAULT_FILE_READY_MIN_STABLE_SECS = 1.0
DEFAULT_FILE_READY_MAX_WAIT_SECS = 6.0
DEFAULT_FILE_READY_POLL_INTERVAL = 0.5


# ============================================================================
# Default Settings
# ============================================================================

DEFAULT_SETTINGS = {
    "watch_folder": "files-to-be-uploaded",
    "processed_files_db": "data/processed_files.json",
    "author": "",
    "copyright": "",
    "source": "",
    "own_work": True,
    "default_categories": [],
    "enable_duplicate_check": True,
    "check_scaled_variants": False,
    "fuzzy_threshold": 10,
    "block_duplicate_uploads": True,
    "file_ready_min_stable_secs": DEFAULT_FILE_READY_MIN_STABLE_SECS,
    "file_ready_max_wait_secs": DEFAULT_FILE_READY_MAX_WAIT_SECS,
    "file_ready_poll_interval": DEFAULT_FILE_READY_POLL_INTERVAL,
}


# ============================================================================
# Settings Management
# ============================================================================

def _strip_quotes(s: Optional[str]) -> Optional[str]:
    """Strip surrounding quotes from environment variable values."""
    if s is None:
        return None
    s = s.strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    return s


def load_settings(settings_file: str = "settings.json") -> Dict[str, Any]:
    """
    Load settings from JSON file.

    If the file doesn't exist, creates it with default settings.
    Missing keys are filled with defaults.

    Args:
        settings_file: Path to settings JSON file

    Returns:
        Dictionary of settings
    """
    p = Path(settings_file)

    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as f:
            json.dump(DEFAULT_SETTINGS, f, indent=2)
        return DEFAULT_SETTINGS.copy()

    try:
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"⚠️  Failed to load settings from {p} ({e}); using defaults.")
        data = DEFAULT_SETTINGS.copy()
        with p.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    # Fill in any missing keys with defaults
    for k, v in DEFAULT_SETTINGS.items():
        data.setdefault(k, v)

    return data


def save_settings(settings: Dict[str, Any], settings_file: str = "settings.json") -> None:
    """
    Save settings to JSON file atomically.

    Uses a temporary file and atomic replace to prevent corruption.

    Args:
        settings: Dictionary of settings to save
        settings_file: Path to settings JSON file
    """
    p = Path(settings_file)
    p.parent.mkdir(parents=True, exist_ok=True)

    tmp = p.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)

    tmp.replace(p)


def get_commons_credentials() -> tuple[Optional[str], Optional[str], str]:
    """
    Get Wikimedia Commons credentials from environment variables.

    Reads from .env file if available (via python-dotenv).

    Returns:
        Tuple of (username, password, user_agent)
    """
    username = _strip_quotes(os.getenv("COMMONS_USERNAME"))
    password = _strip_quotes(os.getenv("COMMONS_PASSWORD"))
    user_agent = _strip_quotes(os.getenv("COMMONS_USER_AGENT")) or \
        "Folder-to-Commons-Uploader/1.0 (contact: unknown)"

    return username, password, user_agent


def is_upload_enabled() -> bool:
    """
    Check if upload functionality is enabled.

    Returns:
        True if both username and password are configured
    """
    username, password, _ = get_commons_credentials()
    return bool(username and password)
