#!/usr/bin/env python3
"""
Commons Duplicate Checker
Checks if a file already exists on Wikimedia Commons using SHA-1 hash matching.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from PIL import Image
from io import BytesIO
from urllib.parse import quote


# =========================
# Config
# =========================

COMMONS_API = "https://commons.wikimedia.org/w/api.php"
USER_AGENT = "Folder-to-Commons-Uploader - Duplicate Commons Checker - Contact: github.com/kbnlwikimedia"
TIMEOUT_SECS = 20
RETRIES_TOTAL = 5
RETRIES_BACKOFF = 0.6
ALLIMAGES_LIMIT = "500"

# Scaled-variant detection defaults
FUZZY_DEFAULT_THRESHOLD = 10
FUZZY_DEFAULT_THUMB_WIDTH = 256


# =========================
# HTTP session
# =========================

def build_session() -> requests.Session:
    """Build HTTP session with retry logic"""
    s = requests.Session()
    retry = Retry(
        total=RETRIES_TOTAL,
        connect=RETRIES_TOTAL,
        read=RETRIES_TOTAL,
        status=RETRIES_TOTAL,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET"}),
        backoff_factor=RETRIES_BACKOFF,
        raise_on_status=False,
    )
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})
    return s


# =========================
# Local hashing
# =========================

def sha1_hex(path: Path, chunk_size: int = 8 * 1024 * 1024) -> str:
    """Return SHA-1 hex digest of file bytes."""
    h = hashlib.sha1()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def commons_file_url_from_title(title: str) -> str:
    """
    Build a canonical Commons URL from a MediaWiki title like 'File:Foo bar.jpg'.
    - Replaces spaces with underscores
    - Percent-encodes other characters safely
    """
    t = (title or "").strip().replace(" ", "_")
    return f"https://commons.wikimedia.org/wiki/{quote(t, safe=':/')}"


# =========================
# Perceptual hash (dHash) for scaled detection
# =========================

def image_dhash(img: Image.Image, hash_size: int = 8) -> int:
    """Compute perceptual dHash of an image"""
    from PIL import ImageOps
    img = ImageOps.exif_transpose(img)
    img = img.convert("L").resize((hash_size + 1, hash_size), Image.BILINEAR)
    w, h = img.size
    bits = 0
    bit_index = 0
    px = img.load()
    for y in range(h):
        for x in range(w - 1):
            if px[x, y] > px[x + 1, y]:
                bits |= (1 << bit_index)
            bit_index += 1
    return bits


def dhash_from_path(path: Path) -> Optional[int]:
    """Compute dHash from file path"""
    try:
        with Image.open(path) as im:
            return image_dhash(im, hash_size=8)
    except Exception:
        return None


def dhash_from_bytes(data: bytes) -> Optional[int]:
    """Compute dHash from image bytes"""
    try:
        with Image.open(BytesIO(data)) as im:
            return image_dhash(im, hash_size=8)
    except Exception:
        return None


def hamming_distance(a: int, b: int) -> int:
    """Calculate Hamming distance between two integers"""
    return (a ^ b).bit_count()


# =========================
# Commons API helpers
# =========================

def list_allimages_by_sha1_hex(session: requests.Session, sha1_hex: str) -> List[str]:
    """Return *all* File: titles on Commons that have exactly this SHA-1 (hex)."""
    titles: List[str] = []
    params: Dict[str, str] = {
        "action": "query",
        "format": "json",
        "list": "allimages",
        "aisha1": sha1_hex.lower(),
        "aiprop": "sha1|timestamp|user|mime|size|url",
        "ailimit": ALLIMAGES_LIMIT,
    }
    cont = None
    while True:
        if cont:
            params.update(cont)
        r = session.get(COMMONS_API, params=params, timeout=TIMEOUT_SECS)
        r.raise_for_status()
        data = r.json()
        ai = (data.get("query") or {}).get("allimages") or []
        for item in ai:
            t = item.get("title")
            if t:
                titles.append(str(t))
        cont = data.get("continue")
        if not cont:
            break
    return titles


def get_remote_sha1_hex_for_title(session: requests.Session, title: str) -> str:
    """Return hex SHA-1 for current version of File:title ('' if page missing)."""
    r = session.get(
        COMMONS_API,
        params={
            "action": "query",
            "format": "json",
            "formatversion": "2",
            "prop": "imageinfo",
            "iiprop": "sha1",
            "titles": title,
        },
        timeout=TIMEOUT_SECS,
    )
    r.raise_for_status()
    data = r.json()
    pages = (data.get("query") or {}).get("pages") or []
    if not pages:
        return ""
    page = pages[0]
    if page.get("missing"):
        return ""
    info = page.get("imageinfo") or []
    if not info:
        return ""
    return (info[0].get("sha1") or "").lower()


def get_thumb_urls_for_titles(session: requests.Session, titles: List[str], width: int) -> Dict[str, str]:
    """Fetch thumbnail URLs for a batch of File: titles (thumb or original)."""
    urls: Dict[str, str] = {}
    for i in range(0, len(titles), 50):
        chunk = titles[i : i + 50]
        if not chunk:
            continue
        r = session.get(
            COMMONS_API,
            params={
                "action": "query",
                "format": "json",
                "formatversion": "2",
                "prop": "imageinfo",
                "iiprop": "url",
                "iiurlwidth": str(width),
                "titles": "|".join(chunk),
            },
            timeout=TIMEOUT_SECS,
        )
        r.raise_for_status()
        data = r.json()
        pages = (data.get("query") or {}).get("pages") or []
        for p in pages:
            t = p.get("title")
            info = p.get("imageinfo") or []
            if t and info:
                u = info[0].get("thumburl") or info[0].get("url")
                if u:
                    urls[str(t)] = str(u)
    return urls


# =========================
# Main checking function
# =========================

def check_file_on_commons(
    file_path: Path,
    session: Optional[requests.Session] = None,
    check_scaled: bool = False,
    fuzzy_threshold: int = FUZZY_DEFAULT_THRESHOLD,
    fuzzy_thumb_width: int = FUZZY_DEFAULT_THUMB_WIDTH,
) -> Dict[str, Any]:
    """
    Check if a single file exists on Wikimedia Commons.

    Args:
        file_path: Path to the file to check
        session: Optional requests.Session (will create one if not provided)
        check_scaled: Whether to check for scaled variants using perceptual hashing
        fuzzy_threshold: Hamming distance threshold for scaled variant detection
        fuzzy_thumb_width: Thumbnail width for scaled variant comparison

    Returns:
        Dictionary with keys:
            - status: str - One of: NOT_ON_COMMONS, EXACT_MATCH, POSSIBLE_SCALED_VARIANT, EXISTS_DIFFERENT_CONTENT, ERROR
            - sha1_local: str - Local file SHA-1 hash
            - matches: list - List of matching files on Commons (if any)
            - details: str - Human-readable details
            - error: str - Error message (if status is ERROR)
            - checked_at: str - ISO timestamp of check
    """

    # Create session if not provided
    if session is None:
        session = build_session()

    result = {
        "status": "ERROR",
        "sha1_local": "",
        "matches": [],
        "details": "",
        "error": "",
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }

    # Validate file exists
    if not file_path.exists():
        result["error"] = f"File not found: {file_path}"
        result["details"] = "File does not exist"
        return result

    # Compute local SHA-1
    try:
        sha_hex = sha1_hex(file_path)
        result["sha1_local"] = sha_hex
    except Exception as e:
        result["error"] = f"Failed to compute SHA-1: {e}"
        result["details"] = "Error computing file hash"
        return result

    # Check for exact hash match on Commons
    try:
        titles = list_allimages_by_sha1_hex(session, sha_hex)
    except requests.RequestException as e:
        result["error"] = f"API error searching by SHA-1: {e}"
        result["details"] = "Network error communicating with Commons API"
        return result

    # Exact match found
    if titles:
        result["status"] = "EXACT_MATCH"
        result["matches"] = [
            {
                "title": t,
                "url": commons_file_url_from_title(t),
                "sha1_remote": sha_hex,
                "match_type": "exact"
            }
            for t in titles
        ]
        result["details"] = f"Found {len(titles)} exact match(es) on Commons"
        return result

    # No exact match - check if file exists by title with different content
    title_candidate = f"File:{file_path.name.replace(' ', '_')}"
    try:
        remote_hex = get_remote_sha1_hex_for_title(session, title_candidate)
    except requests.RequestException as e:
        result["error"] = f"API error checking by title: {e}"
        result["details"] = "Network error checking file by name"
        return result

    if remote_hex:
        # File with this name exists but different content
        result["status"] = "EXISTS_DIFFERENT_CONTENT"
        result["matches"] = [
            {
                "title": title_candidate,
                "url": commons_file_url_from_title(title_candidate),
                "sha1_remote": remote_hex,
                "match_type": "name_only"
            }
        ]
        result["details"] = f"File exists on Commons with same name but different content"
        return result

    # Check for scaled variants if requested
    if check_scaled:
        try:
            # Check by title first (faster)
            thumb_map = get_thumb_urls_for_titles(session, [title_candidate], fuzzy_thumb_width)
            url = thumb_map.get(title_candidate)
            if url:
                resp = session.get(url, timeout=TIMEOUT_SECS)
                if resp.ok:
                    local_dh = dhash_from_path(file_path)
                    remote_dh = dhash_from_bytes(resp.content)
                    if local_dh is not None and remote_dh is not None:
                        dist = hamming_distance(local_dh, remote_dh)
                        if dist <= fuzzy_threshold:
                            # Possible scaled variant found
                            try:
                                remote_hex_scaled = get_remote_sha1_hex_for_title(session, title_candidate)
                            except requests.RequestException:
                                remote_hex_scaled = ""

                            result["status"] = "POSSIBLE_SCALED_VARIANT"
                            result["matches"] = [
                                {
                                    "title": title_candidate,
                                    "url": commons_file_url_from_title(title_candidate),
                                    "sha1_remote": remote_hex_scaled or "",
                                    "match_type": "scaled_variant",
                                    "hamming_distance": dist
                                }
                            ]
                            result["details"] = f"Possible scaled variant found (dHash distance={dist})"
                            return result
        except Exception:
            # Scaled variant detection failed, but that's okay - continue
            pass

    # No match found
    result["status"] = "NOT_ON_COMMONS"
    result["details"] = "File not found on Wikimedia Commons"
    return result


# =========================
# Convenience function
# =========================

def check_file(file_path: str | Path, **kwargs) -> Dict[str, Any]:
    """
    Convenience function to check a file on Commons.

    Usage:
        result = check_file('/path/to/image.jpg')
        if result['status'] == 'EXACT_MATCH':
            print(f"File already on Commons: {result['matches'][0]['url']}")
        elif result['status'] == 'NOT_ON_COMMONS':
            print("File not found on Commons - safe to upload")
    """
    return check_file_on_commons(Path(file_path), **kwargs)
