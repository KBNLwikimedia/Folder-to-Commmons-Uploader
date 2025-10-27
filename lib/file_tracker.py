"""
File tracking module for Folder-to-Commons-Uploader.

Provides thread-safe tracking of processed files with atomic JSON I/O.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class FileTracker:
    """
    Thread-safe tracker for processed files and Commons check results.

    Stores file metadata including:
    - Detection timestamp
    - Local SHA-1 hash
    - Commons duplicate check status and results
    - Upload status
    - Category information
    """

    def __init__(self, db_path: Path | str):
        """
        Initialize FileTracker with a database path.

        Args:
            db_path: Path to the JSON database file
        """
        self.db_path = Path(db_path)
        self.lock = threading.Lock()
        self.processed_files: Dict[str, Dict[str, Any]] = self._load()

    def _load(self) -> Dict[str, Dict[str, Any]]:
        """Load processed files from JSON database."""
        if not self.db_path.exists():
            return {}

        try:
            with self.db_path.open("r", encoding="utf-8") as f:
                text = f.read().strip()
                if not text:
                    return {}

                data = json.loads(text)

                # Handle legacy list format
                if isinstance(data, list):
                    return {str(p): self._create_file_record(p) for p in data}

                if isinstance(data, dict):
                    return data

        except Exception as e:
            print(f"⚠️  Failed to load {self.db_path} ({e}); using empty database.")

        return {}

    def _atomic_save(self) -> None:
        """Atomically save processed files to JSON database using temp file."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.db_path.with_suffix(".tmp")

        with tmp.open("w", encoding="utf-8") as f:
            json.dump(self.processed_files, f, indent=2)

        tmp.replace(self.db_path)

    def _create_file_record(self, file_path: str, **kwargs) -> Dict[str, Any]:
        """
        Create a new file record with default values.

        Args:
            file_path: Path to the file
            **kwargs: Optional overrides for record fields

        Returns:
            Dictionary containing file metadata
        """
        return {
            "file_path": str(file_path),
            "detected_at": kwargs.get("detected_at", datetime.now(timezone.utc).isoformat()),
            "sha1_local": kwargs.get("sha1_local", ""),
            "commons_check_status": kwargs.get("commons_check_status", "PENDING"),
            "commons_matches": kwargs.get("commons_matches", []),
            "checked_at": kwargs.get("checked_at", ""),
            "check_details": kwargs.get("check_details", ""),
            "category": kwargs.get("category", None),
            "uploaded": kwargs.get("uploaded", False),
        }

    def get_all_files(self) -> List[Dict[str, Any]]:
        """
        Get all tracked files.

        Returns:
            List of file records
        """
        with self.lock:
            return list(self.processed_files.values())

    def get_record(self, file_path: Path | str) -> Optional[Dict[str, Any]]:
        """
        Get a specific file record.

        Args:
            file_path: Path to the file

        Returns:
            File record or None if not found
        """
        with self.lock:
            return self.processed_files.get(str(file_path))

    def is_processed(self, file_path: Path | str) -> bool:
        """
        Check if a file has been processed.

        Args:
            file_path: Path to the file

        Returns:
            True if file is in the database
        """
        with self.lock:
            return str(file_path) in self.processed_files

    def update_record(self, file_path: Path | str, updates: Dict[str, Any]) -> None:
        """
        Update an existing record or create a new one.

        Args:
            file_path: Path to the file
            updates: Dictionary of fields to update
        """
        with self.lock:
            key = str(file_path)
            rec = self.processed_files.get(key)

            if rec is None:
                rec = self._create_file_record(key)
                self.processed_files[key] = rec

            rec.update(updates)
            self._atomic_save()

    def mark_processed(self, file_path: Path | str, **kwargs) -> None:
        """
        Mark a file as processed with optional metadata.

        Args:
            file_path: Path to the file
            **kwargs: Metadata fields to set
        """
        key = str(file_path)
        with self.lock:
            if key in self.processed_files:
                self.processed_files[key].update(kwargs)
            else:
                self.processed_files[key] = self._create_file_record(key, **kwargs)
            self._atomic_save()

    def update_commons_check(self, file_path: Path | str, check_result: Dict[str, Any]) -> None:
        """
        Update Commons duplicate check results for a file.

        Args:
            file_path: Path to the file
            check_result: Check result dictionary from commons_duplicate_checker
        """
        key = str(file_path)
        with self.lock:
            if key not in self.processed_files:
                self.processed_files[key] = self._create_file_record(key)

            rec = self.processed_files[key]
            rec.update({
                "sha1_local": check_result.get("sha1_local", rec.get("sha1_local", "")),
                "commons_check_status": check_result.get("status", rec.get("commons_check_status", "ERROR")),
                "commons_matches": check_result.get("matches", rec.get("commons_matches", [])),
                "checked_at": check_result.get("checked_at", datetime.now(timezone.utc).isoformat()),
                "check_details": check_result.get("details", rec.get("check_details", "")),
            })
            self._atomic_save()
