"""
Status constants and utilities for Folder-to-Commons-Uploader.

Defines status values for Commons duplicate checking and file processing.
"""

from enum import Enum


class CommonsCheckStatus:
    """Status values for Commons duplicate checking."""

    # File has not been checked yet
    PENDING = "PENDING"

    # Check is currently in progress
    IN_PROGRESS = "IN_PROGRESS"
    CHECKING = "CHECKING"  # Alias for IN_PROGRESS

    # File does not exist on Commons
    NOT_ON_COMMONS = "NOT_ON_COMMONS"

    # File exists with exact SHA-1 match
    EXACT_MATCH = "EXACT_MATCH"

    # File appears to be a scaled variant (perceptual hash match)
    POSSIBLE_SCALED_VARIANT = "POSSIBLE_SCALED_VARIANT"

    # File with same name but different content exists
    EXISTS_DIFFERENT_CONTENT = "EXISTS_DIFFERENT_CONTENT"

    # Error occurred during checking
    ERROR = "ERROR"

    @classmethod
    def all_statuses(cls) -> tuple:
        """Get all valid status values."""
        return (
            cls.PENDING,
            cls.IN_PROGRESS,
            cls.CHECKING,
            cls.NOT_ON_COMMONS,
            cls.EXACT_MATCH,
            cls.POSSIBLE_SCALED_VARIANT,
            cls.EXISTS_DIFFERENT_CONTENT,
            cls.ERROR,
        )

    @classmethod
    def is_safe_to_upload(cls, status: str) -> bool:
        """
        Check if a file with given status is safe to upload.

        Args:
            status: Commons check status

        Returns:
            True if safe to upload (file not on Commons)
        """
        return status == cls.NOT_ON_COMMONS

    @classmethod
    def is_duplicate(cls, status: str) -> bool:
        """
        Check if status indicates a duplicate file.

        Args:
            status: Commons check status

        Returns:
            True if file is duplicate or scaled variant
        """
        return status in (cls.EXACT_MATCH, cls.POSSIBLE_SCALED_VARIANT)

    @classmethod
    def is_checking(cls, status: str) -> bool:
        """
        Check if status indicates check is in progress.

        Args:
            status: Commons check status

        Returns:
            True if check is pending or in progress
        """
        return status in (cls.PENDING, cls.CHECKING, cls.IN_PROGRESS, "")

    @classmethod
    def is_error(cls, status: str) -> bool:
        """
        Check if status indicates an error occurred.

        Args:
            status: Commons check status

        Returns:
            True if error status
        """
        return status == cls.ERROR


def map_status_to_ui_key(status: str) -> str:
    """
    Map Commons check status to UI filter key.

    Args:
        status: Commons check status

    Returns:
        UI filter key (duplicate, scaled, safe, checking, conflict, error)
    """
    if status == CommonsCheckStatus.EXACT_MATCH:
        return "duplicate"
    if status == CommonsCheckStatus.POSSIBLE_SCALED_VARIANT:
        return "scaled"
    if status == CommonsCheckStatus.EXISTS_DIFFERENT_CONTENT:
        return "conflict"
    if status == CommonsCheckStatus.NOT_ON_COMMONS:
        return "safe"
    if status in (CommonsCheckStatus.CHECKING, CommonsCheckStatus.PENDING, CommonsCheckStatus.IN_PROGRESS, ""):
        return "checking"
    if status == CommonsCheckStatus.ERROR:
        return "error"
    return "unknown"
