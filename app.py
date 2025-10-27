#!/usr/bin/env python3
"""
Folder → Commons Uploader - Flask app

• Lists images from processed_files.json (produced by monitor.py or a similar process)
• Background checker (optional) updates Commons duplicate status via SHA-1
• Index page: tiles, filters, “More details”, upload UI for “Safe to upload”
• Detail page:
    LEFT  = local-only info (name, subfolder, EXIF-first Created, size, dimensions, local SHA-1)
    RIGHT = Commons info (status, file link, remote SHA-1, categories) + Suggested filename/category + Upload

Requires:
    - templates/index.html (existing in your repo)
    - templates/file_detail.html (included below)
    - templates/settings.html (existing)
    - commons_duplicate_checker.py (or lib/commons_duplicate_checker.py)

.env:
    COMMONS_USERNAME=...
    COMMONS_PASSWORD=...
    COMMONS_USER_AGENT=Optional UA string
"""

from __future__ import annotations

import io
import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional

from flask import (
    Flask, render_template, jsonify, request, redirect, url_for, flash, send_file
)
from PIL import Image, ExifTags
import requests
from dotenv import load_dotenv

# ---------- Import shared modules ----------
from lib.config import (
    load_settings, save_settings, get_commons_credentials, is_upload_enabled,
    API_TIMEOUT, COMMONS_API, CHECK_LOOP_INTERVAL_SEC, THUMB_MAX
)
from lib.file_tracker import FileTracker
from lib.status import CommonsCheckStatus, map_status_to_ui_key
from lib.logger import get_app_logger

# ---------- Try to import the checker from either location ----------
try:
    from lib.commons_duplicate_checker import check_file_on_commons, build_session
except Exception:
    try:
        from commons_duplicate_checker import check_file_on_commons, build_session
    except Exception:
        check_file_on_commons = None
        build_session = None
        logger = get_app_logger()
        logger.warning("commons_duplicate_checker not found: duplicate checking disabled.")

# ---------- Flask ----------
app = Flask(__name__)
app.secret_key = "dev-secret-key-change-in-production"

# ---------- Logger ----------
logger = get_app_logger()

# ---------- ENV (upload credentials) ----------
load_dotenv()
COMMONS_USERNAME, COMMONS_PASSWORD, COMMONS_USER_AGENT = get_commons_credentials()
UPLOAD_ENABLED = is_upload_enabled()

# ---------- Path/URL helpers ----------
def relref_from_local(local_path: Path, watch_folder: Path) -> str:
    return local_path.resolve().relative_to(watch_folder.resolve()).as_posix()

def local_from_relref(relref: str, watch_folder: Path) -> Path:
    posix = PurePosixPath(relref)
    safe = Path(*posix.parts)
    abs_path = (watch_folder / safe).resolve()
    if not str(abs_path).startswith(str(watch_folder.resolve())):
        raise FileNotFoundError("Ref outside watch folder")
    return abs_path

def get_category_from_path(local_path: Path, watch_folder: Path) -> str:
    try:
        rel = local_path.resolve().relative_to(watch_folder.resolve())
    except Exception:
        return ""
    parts = rel.parts
    if len(parts) > 1 and parts[0].lower().startswith("category_"):
        return parts[0][9:]  # after 'category_'
    return ""

def suggest_filename(local_path: Path, category_slug: str) -> str:
    # Simple suggestion: "<Category> <base>.jpg"
    stem = local_path.stem.replace("_", " ")
    ext = local_path.suffix.lower() or ".jpg"
    prefix = category_slug.strip()
    if prefix:
        return f"{prefix} {stem}{ext}"
    return f"{stem}{ext}"

# ---------- Image helpers ----------
def image_dimensions(path: Path) -> Dict[str, Optional[int]]:
    try:
        with Image.open(path) as im:
            return {"width": int(im.width), "height": int(im.height)}
    except Exception:
        return {"width": None, "height": None}

def read_exif_selected(path: Path) -> Dict[str, Any]:
    try:
        with Image.open(path) as im:
            exif = im.getexif()
            if not exif:
                return {}
            rev = {ExifTags.TAGS.get(k, str(k)): v for k, v in exif.items()}
            def _clean(v):
                if isinstance(v, bytes):
                    try:
                        t = v.decode("utf-8", "ignore").strip()
                        return t if t else None
                    except Exception:
                        return None
                if isinstance(v, tuple) and len(v) == 2 and all(isinstance(x, int) for x in v):
                    if v[1] != 0:
                        return f"{v[0]}/{v[1]}"
                return v
            keys = ["DateTimeOriginal", "DateTime", "DateTimeDigitized",
                    "FNumber", "ExposureTime", "ISOSpeedRatings", "FocalLength", "Make", "Model"]
            out = {}
            for k in keys:
                if k in rev:
                    val = _clean(rev[k])
                    if val:
                        out[k] = val
            return out
    except Exception:
        return {}

def exif_best_created_string(path: Path) -> Optional[str]:
    """Return human-friendly created time from EXIF if present; else None."""
    try:
        with Image.open(path) as im:
            ex = im.getexif()
            if not ex:
                return None
            for tag in (36867, 36868, 306):  # DateTimeOriginal, DateTimeDigitized, DateTime
                v = ex.get(tag)
                if not v:
                    continue
                if isinstance(v, bytes):
                    try:
                        v = v.decode("utf-8", "ignore").strip()
                    except Exception:
                        continue
                v = str(v).strip()
                # Normalize "YYYY:MM:DD HH:MM:SS" → "YYYY-MM-DD HH:MM:SS"
                if len(v) >= 19 and v[4] == ":" and v[7] == ":":
                    v = f"{v[0:4]}-{v[5:7]}-{v[8:10]} {v[11:19]}"
                return v
    except Exception:
        return None
    return None

# ---------- Status mapping for UI ----------
def map_status_key(rec_status: str, uploaded: bool) -> str:
    """Map status to UI key, with upload override."""
    if uploaded:
        return "uploaded"
    return map_status_to_ui_key(rec_status)

def primary_remote_from_matches(matches: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not matches:
        return None
    m = matches[0]
    return {
        "title": m.get("title") or m.get("filetitle") or m.get("name"),
        "url": m.get("url"),
        "sha1_hex": m.get("sha1_hex") or m.get("sha1"),
        "sha1_base36": m.get("sha1_base36"),
    }

# ---------- Enrich remote info (SHA-1 + categories) ----------
def fetch_commons_fileinfo_and_categories(title: str) -> tuple[Optional[str], list[dict]]:
    """
    Fetch SHA-1 (hex) and non-hidden categories for a Commons file title.
    Returns (sha1_hex, categories) where categories are dicts with 'title'.
    """
    try:
        r = requests.get(
            COMMONS_API,
            params={
                "action": "query",
                "format": "json",
                "formatversion": "2",
                "redirects": "1",
                "titles": title,                    # e.g., "File:Example.jpg"
                "prop": "imageinfo|categories",
                "iiprop": "sha1",
                "clshow": "!hidden",
                "cllimit": "500",
            },
            headers={"User-Agent": COMMONS_USER_AGENT},
            timeout=API_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        pages = (data.get("query") or {}).get("pages") or []
        if not pages:
            return None, []
        pg = pages[0]
        sha1_hex = None
        ii = (pg.get("imageinfo") or [])
        if ii:
            sha1_hex = (ii[0] or {}).get("sha1")
        cats = (pg.get("categories") or [])
        return sha1_hex, cats
    except Exception:
        return None, []

# ---------- Background Commons checker ----------
_checker_thread = None
_stop_checker = threading.Event()

def commons_checker_loop():
    logger.info("Commons checker loop: started.")
    settings = load_settings()
    if not (settings.get("enable_duplicate_check") and check_file_on_commons and build_session):
        logger.info("Duplicate checker disabled by settings or missing module.")
        return
    session = build_session()

    tracker = FileTracker(Path(settings["processed_files_db"]))
    watch_folder = Path(settings["watch_folder"]).resolve()

    while not _stop_checker.is_set():
        try:
            files = tracker.get_all_files()
            for rec in files:
                status = rec.get("commons_check_status", CommonsCheckStatus.PENDING)
                uploaded = rec.get("uploaded", False)
                if uploaded:
                    continue
                if CommonsCheckStatus.is_checking(status):
                    p = Path(rec["file_path"])
                    if not p.exists():
                        continue
                    try:
                        result = check_file_on_commons(
                            p,
                            session=session,
                            check_scaled=settings.get("check_scaled_variants", False),
                            fuzzy_threshold=int(settings.get("fuzzy_threshold", 10)),
                        )
                        tracker.update_record(
                            p,
                            {
                                "sha1_local": result.get("sha1_local", "") or rec.get("sha1_local", ""),
                                "commons_check_status": result.get("status", CommonsCheckStatus.ERROR),
                                "commons_matches": result.get("matches", []),
                                "checked_at": result.get("checked_at", datetime.now(timezone.utc).isoformat()),
                                "check_details": result.get("details", ""),
                            },
                        )
                    except Exception as e:
                        logger.error(f"Error checking {p.name}: {e}")
                        tracker.update_record(
                            p,
                            {"commons_check_status": CommonsCheckStatus.ERROR, "check_details": f"{e}"},
                        )
            _stop_checker.wait(CHECK_LOOP_INTERVAL_SEC)
        except Exception as e:
            logger.error(f"Checker loop error: {e}")
            _stop_checker.wait(CHECK_LOOP_INTERVAL_SEC)

def start_checker_thread():
    global _checker_thread
    if _checker_thread and _checker_thread.is_alive():
        return
    _checker_thread = threading.Thread(target=commons_checker_loop, daemon=True)
    _checker_thread.start()

# ---------- UI assembly ----------
def gather_files_for_ui(settings: Dict[str, Any]) -> List[Dict[str, Any]]:
    tracker = FileTracker(Path(settings["processed_files_db"]))
    watch_folder = Path(settings["watch_folder"]).resolve()
    items = []

    for rec in tracker.get_all_files():
        p = Path(rec["file_path"])
        if not p.exists():
            continue

        try:
            stat = p.stat()
            size_mb = round(stat.st_size / (1024 * 1024), 2)
        except Exception:
            size_mb = 0.0

        dims = image_dimensions(p)
        category_slug = rec.get("category") or get_category_from_path(p, watch_folder) or \
                        (settings.get("default_categories")[0] if settings.get("default_categories") else "")

        relref = relref_from_local(p, watch_folder)
        suggested_name = suggest_filename(p, category_slug)

        status = rec.get("commons_check_status", CommonsCheckStatus.PENDING)
        status_key = map_status_key(status, rec.get("uploaded", False))
        matches = rec.get("commons_matches", [])
        remote_primary = primary_remote_from_matches(matches)

        items.append({
            "name": p.name,
            "path": str(p),
            "relative_path": relref,
            "size_mb": size_mb,
            "created": datetime.fromtimestamp(p.stat().st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
            "dimensions": dims,
            "sha1_local": rec.get("sha1_local", ""),
            "commons_check_status": status,
            "status_key": status_key,
            "upload_suggestion": {
                "suggested_filename": suggested_name,
                "category_slug": category_slug,
            },
            "remote_primary": remote_primary,
            "urls": {
                "detail": url_for("file_detail", ref=relref),
                "thumb": url_for("serve_thumbnail", ref=relref),
                "image": url_for("serve_image", ref=relref),
            },
        })
    items.sort(key=lambda x: x["created"], reverse=True)
    return items

# ---------- Routes ----------
@app.route("/")
def index():
    settings = load_settings()
    files = gather_files_for_ui(settings)
    return render_template(
        "index.html",
        files=files,
        total_files=len(files),
        upload_enabled=UPLOAD_ENABLED,
        settings=settings,
    )

@app.route("/file/<path:ref>")
def file_detail(ref: str):
    settings = load_settings()
    watch_folder = Path(settings["watch_folder"]).resolve()
    path = local_from_relref(ref, watch_folder)
    if not path.exists():
        return "File not found", 404

    tracker = FileTracker(Path(settings["processed_files_db"]))
    rec = tracker.get_record(path) or {}
    status = rec.get("commons_check_status", "PENDING")
    status_key = map_status_key(status, rec.get("uploaded", False))
    matches = rec.get("commons_matches", [])
    remote_primary = primary_remote_from_matches(matches)

    # Enrich duplicates (remote SHA-1 + categories)
    remote_categories = []
    if remote_primary and remote_primary.get("title"):
        sha1_hex, cats = fetch_commons_fileinfo_and_categories(remote_primary["title"])
        if sha1_hex and not remote_primary.get("sha1_hex"):
            remote_primary["sha1_hex"] = sha1_hex
        for c in cats:
            t = c.get("title")
            if t:
                remote_categories.append({
                    "title": t,
                    "url": f"https://commons.wikimedia.org/wiki/{t.replace(' ', '_')}"
                })

    dims = image_dimensions(path)
    size_mb = round(path.stat().st_size / (1024 * 1024), 2)
    exif = read_exif_selected(path)
    created_exif = exif_best_created_string(path)

    category_slug = rec.get("category") or get_category_from_path(path, watch_folder) or \
                    (settings.get("default_categories")[0] if settings.get("default_categories") else "")
    suggested_name = suggest_filename(path, category_slug)
    relref = relref_from_local(path, watch_folder)

    file_dict = {
        "name": path.name,
        "path": str(path),
        "relative_path": relref,
        "size_mb": size_mb,
        "created": datetime.fromtimestamp(path.stat().st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
        "created_exif": created_exif,
        "dimensions": dims,
        "sha1_local": rec.get("sha1_local", ""),
        "commons_check_status": status,
        "status_key": status_key,
        "upload_suggestion": {
            "suggested_filename": suggested_name,
            "category_slug": category_slug,
        },
        "remote_primary": remote_primary,
        "urls": {"image": url_for("serve_image", ref=relref)},
    }

    return render_template(
        "file_detail.html",
        file=file_dict,
        exif=exif,
        remote_categories=remote_categories,
        upload_enabled=UPLOAD_ENABLED,
    )

@app.route("/image/<path:ref>")
def serve_image(ref: str):
    settings = load_settings()
    watch_folder = Path(settings["watch_folder"]).resolve()
    path = local_from_relref(ref, watch_folder)
    if not path.exists() or not path.is_file():
        return "Image not found", 404
    return send_file(str(path), mimetype="image/jpeg")

@app.route("/thumbnail/<path:ref>")
def serve_thumbnail(ref: str):
    settings = load_settings()
    watch_folder = Path(settings["watch_folder"]).resolve()
    path = local_from_relref(ref, watch_folder)
    if not path.exists() or not path.is_file():
        return "Image not found", 404
    try:
        with Image.open(path) as im:
            im.thumbnail(THUMB_MAX)
            bio = io.BytesIO()
            im.save(bio, "JPEG", quality=85)
            bio.seek(0)
            return send_file(bio, mimetype="image/jpeg")
    except Exception as e:
        return f"Thumbnail error: {e}", 500

# ---------- Upload helpers ----------
def commons_api_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": COMMONS_USER_AGENT})
    return s

def commons_login_and_token(s: requests.Session) -> str:
    r = s.get(COMMONS_API,
              params={"action": "query", "meta": "tokens", "type": "login", "format": "json"},
              timeout=API_TIMEOUT)
    r.raise_for_status()
    login_token = r.json()["query"]["tokens"]["logintoken"]
    r = s.post(COMMONS_API,
               data={
                   "action": "clientlogin",
                   "username": COMMONS_USERNAME,
                   "password": COMMONS_PASSWORD,
                   "loginreturnurl": "https://example.com/",
                   "logintoken": login_token,
                   "format": "json",
               },
               timeout=API_TIMEOUT)
    r.raise_for_status()
    data = r.json()
    if data.get("clientlogin", {}).get("status") != "PASS":
        raise RuntimeError(f"Login failed: {json.dumps(data)}")
    r = s.get(COMMONS_API,
              params={"action": "query", "meta": "tokens", "format": "json"},
              timeout=API_TIMEOUT)
    r.raise_for_status()
    return r.json()["query"]["tokens"]["csrftoken"]

def make_upload_text(category_slug: str, settings: Dict[str, Any]) -> str:
    cats = []
    if category_slug:
        cats.append(f"[[Category:{category_slug}]]")
    for c in settings.get("default_categories", []):
        if c and c != category_slug:
            cats.append(f"[[Category:{c}]]")
    desc = "{{Information|description=Uploaded via Folder-to-Commons-Uploader}}"
    return desc + ("\n" + "\n".join(cats) if cats else "")

@app.route("/api/upload", methods=["POST"])
def api_upload():
    if not UPLOAD_ENABLED:
        return jsonify(ok=False, error="Upload disabled: set COMMONS_USERNAME and COMMONS_PASSWORD in .env"), 400

    data = request.get_json(force=True)
    ref = data.get("filename")
    target = data.get("target")
    category_slug = data.get("category_slug", "")

    settings = load_settings()
    watch_folder = Path(settings["watch_folder"]).resolve()
    try:
        local_path = local_from_relref(ref, watch_folder)
    except Exception as e:
        return jsonify(ok=False, error=f"Bad filename ref: {e}"), 400

    if not local_path.exists():
        return jsonify(ok=False, error="Local file not found"), 404

    s = commons_api_session()
    try:
        token = commons_login_and_token(s)
        text = make_upload_text(category_slug, settings)
        with local_path.open("rb") as f:
            r = s.post(
                COMMONS_API,
                data={
                    "action": "upload",
                    "filename": target,
                    "format": "json",
                    "ignorewarnings": "1",
                    "token": token,
                    "text": text,
                },
                files={"file": (local_path.name, f, "image/jpeg")},
                timeout=API_TIMEOUT,
            )
        r.raise_for_status()
        j = r.json()
        if "upload" not in j or j["upload"].get("result") != "Success":
            return jsonify(ok=False, error=j), 400

        # Mark uploaded in DB
        tracker = FileTracker(Path(settings["processed_files_db"]))
        tracker.update_record(local_path, {"uploaded": True})

        title = j["upload"]["filename"]
        url = f"https://commons.wikimedia.org/wiki/File:{title.replace(' ', '_')}"
        return jsonify(ok=True, title=title, url=url)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500

@app.route("/api/bulk-upload", methods=["POST"])
def api_bulk_upload():
    if not UPLOAD_ENABLED:
        return jsonify(ok=False, error="Upload disabled"), 400

    settings = load_settings()
    tracker = FileTracker(Path(settings["processed_files_db"]))
    watch_folder = Path(settings["watch_folder"]).resolve()
    files = tracker.get_all_files()

    safe_items: List[Path] = []
    for rec in files:
        if rec.get("uploaded"):
            continue
        if CommonsCheckStatus.is_safe_to_upload(rec.get("commons_check_status", "")):
            p = Path(rec["file_path"])
            if p.exists():
                safe_items.append(p)

    s = commons_api_session()
    try:
        token = commons_login_and_token(s)
    except Exception as e:
        return jsonify(ok=False, error=f"Auth failed: {e}"), 500

    uploaded_count = 0
    for p in safe_items:
        rrec = tracker.get_record(p) or {}
        cat = rrec.get("category") or get_category_from_path(p, watch_folder) or \
              (settings.get("default_categories")[0] if settings.get("default_categories") else "")
        fname = suggest_filename(p, cat)
        text = make_upload_text(cat, settings)
        try:
            with p.open("rb") as f:
                r = s.post(
                    COMMONS_API,
                    data={
                        "action": "upload",
                        "filename": fname,
                        "format": "json",
                        "ignorewarnings": "1",
                        "token": token,
                        "text": text,
                    },
                    files={"file": (p.name, f, "image/jpeg")},
                    timeout=API_TIMEOUT,
                )
            r.raise_for_status()
            j = r.json()
            if j.get("upload", {}).get("result") == "Success":
                uploaded_count += 1
                tracker.update_record(p, {"uploaded": True})
        except Exception as e:
            logger.error(f"Bulk upload failed for {p.name}: {e}")

    return jsonify(ok=True, requested=len(safe_items), uploaded=uploaded_count)

# ---------- Settings UI ----------
@app.route("/settings", methods=["GET", "POST"])
def settings_view():
    if request.method == "POST":
        s = load_settings()
        s["watch_folder"] = request.form.get("watch_folder", s["watch_folder"])
        s["processed_files_db"] = request.form.get("processed_files_db", s["processed_files_db"])
        s["author"] = request.form.get("author", s["author"])
        s["copyright"] = request.form.get("copyright", s["copyright"])
        s["source"] = request.form.get("source", s["source"])
        s["own_work"] = request.form.get("own_work") == "on"

        cats = request.form.get("default_categories", "")
        s["default_categories"] = [c.strip() for c in cats.split(",") if c.strip()]

        s["enable_duplicate_check"] = request.form.get("enable_duplicate_check") == "on"
        s["check_scaled_variants"] = request.form.get("check_scaled_variants") == "on"
        try:
            s["fuzzy_threshold"] = int(request.form.get("fuzzy_threshold", s["fuzzy_threshold"]))
        except Exception:
            pass

        save_settings(s)
        flash("Settings saved.", "success")
        return redirect(url_for("settings_view"))

    s = load_settings()
    return render_template("settings.html", settings=s, upload_enabled=UPLOAD_ENABLED)

# ---------- App start ----------
if __name__ == "__main__":
    start_checker_thread()
    app.run(debug=True, host="0.0.0.0", port=5001)
