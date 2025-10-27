#!/usr/bin/env python3
"""
Folder-to-Commons-Uploader - Folder Monitor
Monitors a folder for new files and tracks them for upload to Wikimedia Commons.

Improvements for Windows / large files
--------------------------------------
• Uses PollingObserver on Windows for robustness.
• Waits until a new file is 'ready' (stable size & openable) before Commons check.
• Duplicate check runs in a background thread to avoid blocking the watchdog event.
"""

from __future__ import annotations

import json
import os
import sys
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any

# --- Watchdog: prefer polling on Windows to avoid kernel watcher edge-cases ---
if os.name == "nt":
    from watchdog.observers.polling import PollingObserver as Observer
else:
    from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Import Commons duplicate checker
try:
    from lib.commons_duplicate_checker import check_file_on_commons, build_session
except ImportError:
    print("Warning: Could not import commons_duplicate_checker. Duplicate checking disabled.")
    check_file_on_commons = None
    build_session = None


# -----------------------
# Helpers
# -----------------------

def extract_category_from_path(file_path: Path | str, watch_folder: Path | str) -> Optional[str]:
    """
    Extract category from directory name if file is in a subdirectory starting with 'category_' (case-insensitive).
    Returns 'Binnenhofrenovatie' for '.../category_Binnenhofrenovatie/2022...jpg'
    """
    file_path = Path(file_path)
    watch_folder = Path(watch_folder)
    try:
        rel = file_path.relative_to(watch_folder)
        if len(rel.parts) > 1:
            parent = rel.parts[0]
            if parent.lower().startswith("category_"):
                core = parent[9:]
                return core or None
    except (ValueError, IndexError):
        pass
    return None


def load_settings(settings_file: str = "settings.json") -> Dict[str, Any]:
    p = Path(settings_file)
    if not p.exists():
        print(f"Error: Settings file not found: {p}")
        sys.exit(1)
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


# -----------------------
# File readiness gate
# -----------------------

def is_file_ready(
    path: Path,
    min_stable_secs: float = 1.0,
    max_wait_secs: float = 120.0,
    poll_interval: float = 0.5,
) -> bool:
    """
    A file is considered 'ready' when:
      1) it exists and is a file,
      2) its size is stable for at least `min_stable_secs`,
      3) it can be opened for reading (binary).

    Returns True if ready within `max_wait_secs`, else False.
    """
    deadline = time.time() + max_wait_secs
    last_size = None
    last_change_time = time.time()

    while time.time() < deadline:
        if not path.exists() or not path.is_file():
            time.sleep(poll_interval)
            continue

        try:
            size = path.stat().st_size
        except Exception:
            time.sleep(poll_interval)
            continue

        now = time.time()
        if last_size is None or size != last_size:
            last_size = size
            last_change_time = now
        else:
            # size unchanged
            if (now - last_change_time) >= min_stable_secs:
                # try opening
                try:
                    with path.open("rb") as f:
                        _ = f.read(1)
                    return True
                except Exception:
                    # still locked; keep waiting
                    pass

        time.sleep(poll_interval)

    return False


# -----------------------
# Tracker
# -----------------------

class FileTracker:
    """Tracks processed files and Commons-check results."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self._lock = threading.Lock()
        self.processed_files: Dict[str, Dict[str, Any]] = self._load()

    def _load(self) -> Dict[str, Dict[str, Any]]:
        if self.db_path.exists():
            with self.db_path.open('r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, list):
                return {str(p): self._create_file_record(p) for p in data}
            if isinstance(data, dict):
                return data
        return {}

    def _save(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.db_path.open('w', encoding='utf-8') as f:
            json.dump(self.processed_files, f, indent=2)

    def _create_file_record(self, file_path: str, **kwargs) -> Dict[str, Any]:
        return {
            "file_path": str(file_path),
            "detected_at": kwargs.get("detected_at", datetime.now(timezone.utc).isoformat()),
            "sha1_local": kwargs.get("sha1_local", ""),
            "commons_check_status": kwargs.get("commons_check_status", "PENDING"),
            "commons_matches": kwargs.get("commons_matches", []),
            "checked_at": kwargs.get("checked_at", ""),
            "check_details": kwargs.get("check_details", ""),
            "category": kwargs.get("category", None),
        }

    def is_processed(self, file_path: Path) -> bool:
        with self._lock:
            return str(file_path) in self.processed_files

    def mark_processed(self, file_path: Path, **kwargs) -> None:
        key = str(file_path)
        with self._lock:
            if key in self.processed_files:
                self.processed_files[key].update(kwargs)
            else:
                self.processed_files[key] = self._create_file_record(key, **kwargs)
            self._save()

    def update_commons_check(self, file_path: Path | str, check_result: Dict[str, Any]) -> None:
        key = str(file_path)
        with self._lock:
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
            self._save()

    def get_file_record(self, file_path: Path | str) -> Optional[Dict[str, Any]]:
        return self.processed_files.get(str(file_path))

    def get_all_files(self) -> list[Dict[str, Any]]:
        with self._lock:
            return list(self.processed_files.values())


# -----------------------
# Event handler
# -----------------------

class NewFileHandler(FileSystemEventHandler):
    """Handles file system events with a readiness gate and background check."""

    def __init__(self, tracker: FileTracker, watch_folder: Path, settings: Dict[str, Any], commons_session=None):
        self.tracker = tracker
        self.watch_folder = Path(watch_folder)
        self.settings = settings
        self.commons_session = commons_session

        # Readiness params (can be overridden in settings.json)
        self.min_stable_secs = float(self.settings.get("file_ready_min_stable_secs", 1.0))
        self.max_wait_secs = float(self.settings.get("file_ready_max_wait_secs", 120.0))
        self.poll_interval = float(self.settings.get("file_ready_poll_interval", 0.5))

    def on_created(self, event):
        if event.is_directory:
            return

        file_path = Path(event.src_path)
        if file_path.suffix.lower() not in ('.jpg', '.jpeg'):
            return

        if self.tracker.is_processed(file_path):
            return

        # Log basic facts (guard against transient stat errors)
        print(f"[NEW FILE DETECTED] {file_path.name}")
        print(f"  - Full path: {file_path}")
        try:
            st = file_path.stat()
            print(f"  - Size: {st.st_size} bytes")
            print(f"  - Created: {time.ctime(st.st_ctime)}")
        except Exception as e:
            print(f"  - (stat pending: {e})")

        category = extract_category_from_path(file_path, self.watch_folder)
        if category:
            print(f"  - Category: {category}")

        # Mark tracked immediately (status=PENDING)
        self.tracker.mark_processed(file_path, category=category, commons_check_status="PENDING")

        # Fire a background worker to wait-until-ready and then run duplicate check
        threading.Thread(
            target=self._ready_then_check,
            args=(file_path,),
            daemon=True
        ).start()

    def _ready_then_check(self, file_path: Path) -> None:
        """Wait for the file to be readable, then run Commons duplicate check."""
        # If duplicate checking is disabled or unavailable, just leave status PENDING/disabled
        if not (self.settings.get('enable_duplicate_check', False) and check_file_on_commons):
            self.tracker.update_commons_check(file_path, {
                "status": "DISABLED",
                "details": "Duplicate checking disabled or module unavailable.",
            })
            print("  - Duplicate check: DISABLED or unavailable.\n")
            return

        print(f"  - Waiting for file to be ready (max {self.max_wait_secs}s)…")
        ready = is_file_ready(
            path=file_path,
            min_stable_secs=self.min_stable_secs,
            max_wait_secs=self.max_wait_secs,
            poll_interval=self.poll_interval,
        )

        if not ready:
            print("  - File not ready within deadline; leaving status PENDING. Will be retried on next run.\n")
            self.tracker.update_commons_check(file_path, {
                "status": "PENDING",
                "details": f"File not readable yet after {self.max_wait_secs}s; likely still being written.",
            })
            return

        print("  - File is ready. Checking for duplicates on Wikimedia Commons…")
        try:
            # Mark 'in progress' to avoid UI saying PENDING forever
            self.tracker.update_commons_check(file_path, {
                "status": "IN_PROGRESS",
                "details": "Running Commons duplicate check…",
            })

            result = check_file_on_commons(
                file_path,
                session=self.commons_session,
                check_scaled=self.settings.get('check_scaled_variants', False),
                fuzzy_threshold=self.settings.get('fuzzy_threshold', 10),
            )

            self.tracker.update_commons_check(file_path, result)

            # Console summary
            status = result.get("status", "ERROR")
            if status == "EXACT_MATCH":
                matches = result.get("matches", [])
                print("  - ⚠️  DUPLICATE FOUND: File already exists on Commons!")
                for m in matches[:3]:
                    print(f"    • {m.get('url','N/A')}")
                if len(matches) > 3:
                    print(f"    • … and {len(matches)-3} more")
            elif status == "POSSIBLE_SCALED_VARIANT":
                matches = result.get("matches", [])
                print("  - ⚠️  Possible scaled variant found on Commons")
                if matches:
                    print(f"    • {matches[0].get('url','N/A')}")
            elif status == "EXISTS_DIFFERENT_CONTENT":
                print("  - ⚠️  File with same name but different content exists on Commons")
            elif status == "NOT_ON_COMMONS":
                print("  - ✓ File not found on Commons — safe to upload")
            else:
                print(f"  - Status: {status}")
                if result.get("error"):
                    print(f"    Error: {result.get('error')}")

            print(f"  - SHA-1: {result.get('sha1_local', '')}\n")

        except Exception as e:
            self.tracker.update_commons_check(file_path, {
                "status": "ERROR",
                "details": f"{type(e).__name__}: {e}",
            })
            print(f"  - Error checking Commons: {e}\n")


# -----------------------
# Scan existing
# -----------------------

def scan_existing_files(watch_folder: Path, tracker: FileTracker) -> None:
    """Recursive scan; mark new JPEGs as tracked (PENDING)."""
    watch_folder.mkdir(parents=True, exist_ok=True)
    print(f"Scanning existing files in: {watch_folder}")
    count = 0
    for p in watch_folder.rglob('*'):
        if p.is_file() and p.suffix.lower() in ('.jpg', '.jpeg'):
            if not tracker.is_processed(p):
                category = extract_category_from_path(p, watch_folder)
                tracker.mark_processed(p, category=category, commons_check_status="PENDING")
                count += 1
    if count:
        print(f"Marked {count} existing file(s) as present.\n")


# -----------------------
# Main
# -----------------------

def main():
    print("=" * 60)
    print("Folder-to-Commons-Uploader - Folder Monitor")
    print("=" * 60)
    print()

    settings = load_settings()
    watch_folder = Path(settings['watch_folder']).resolve()
    db_path = Path(settings['processed_files_db']).resolve()

    print(f"Watch folder: {watch_folder}")
    print(f"Tracking database: {db_path}")

    if settings.get('enable_duplicate_check', False):
        print("Duplicate checking: ENABLED")
        if settings.get('check_scaled_variants', False):
            print(f"  - Scaled variant detection: ENABLED (threshold={settings.get('fuzzy_threshold', 10)})")
        else:
            print("  - Scaled variant detection: DISABLED")
    else:
        print("Duplicate checking: DISABLED")
    print()

    tracker = FileTracker(db_path)

    # Build Commons API session if duplicate checking is enabled
    commons_session = None
    if settings.get('enable_duplicate_check', False) and build_session:
        try:
            print("Initializing Commons API session…")
            commons_session = build_session()
            print("Commons API session: ready.")
        except Exception as e:
            print(f"Commons session init failed: {e}")

    # Initial scan
    scan_existing_files(watch_folder, tracker)

    # Watcher
    handler = NewFileHandler(tracker, watch_folder, settings, commons_session)
    observer = Observer()
    observer.schedule(handler, str(watch_folder), recursive=True)
    observer.start()

    print("Monitoring started. Press Ctrl+C to stop.")
    print(f"Watching for new JPEG files in: {watch_folder}\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping monitor…")
        observer.stop()
        observer.join()
        print("Monitor stopped.")


if __name__ == '__main__':
    main()
