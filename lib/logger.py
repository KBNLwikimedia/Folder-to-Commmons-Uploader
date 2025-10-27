"""
Logging module for Folder-to-Commons-Uploader.

Provides centralized logging configuration with proper formatting.
"""

import logging
import sys
from pathlib import Path
from typing import Optional


# Default log format
DEFAULT_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
SIMPLE_FORMAT = "%(levelname)s: %(message)s"


def setup_logger(
    name: str,
    level: int = logging.INFO,
    log_file: Optional[Path] = None,
    console: bool = True,
    format_string: Optional[str] = None,
) -> logging.Logger:
    """
    Set up a logger with optional file and console handlers.

    Args:
        name: Logger name
        level: Logging level (default: INFO)
        log_file: Optional path to log file
        console: Whether to log to console (default: True)
        format_string: Custom format string (default: DEFAULT_FORMAT)

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Remove existing handlers to avoid duplicates
    logger.handlers.clear()

    # Use custom format or default
    formatter = logging.Formatter(format_string or DEFAULT_FORMAT)

    # Console handler
    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # File handler
    if log_file:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance by name.

    If the logger hasn't been set up yet, it will use Python's default configuration.

    Args:
        name: Logger name

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


# Pre-configured loggers for different modules
def get_app_logger() -> logging.Logger:
    """Get logger for Flask app."""
    return get_logger("app")


def get_monitor_logger() -> logging.Logger:
    """Get logger for folder monitor."""
    return get_logger("monitor")


def get_checker_logger() -> logging.Logger:
    """Get logger for Commons duplicate checker."""
    return get_logger("checker")
