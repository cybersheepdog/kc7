"""
DB + config backup / restore for disaster recovery and moving an instance between
hosts (#38, "Access & resilience").

Backup produces a single ``.zip`` snapshot containing every scenario config file
(``app/game_configs/**``) and a copy of the live SQLite database. Restore re-applies
the config files immediately (each path strictly confined to the config root — no
traversal) and, optionally, *stages* the database file to be swapped in atomically on
the next startup.

Why staging for the DB: overwriting the live SQLite file while SQLAlchemy holds open
connections can corrupt it. Instead, restore writes the uploaded DB bytes to
``<db>.pending-restore``; ``apply_pending_db_restore`` (called once at startup, before
any connection is opened) backs up the current DB and moves the pending file into
place. Config restore is safe to apply live and takes effect on the next game start /
config read.

Admin-only and audited at the route layer. Dependency-light (stdlib only).
"""

import io
import os
import shutil
import zipfile
from datetime import datetime

CONFIG_ARC_PREFIX = "configs/"
DB_ARCNAME = "database/app.db"
MANIFEST_ARCNAME = "MANIFEST.txt"
PENDING_SUFFIX = ".pending-restore"


def _project_root():
    """Absolute path to the repo root (this file is app/server/modules/backup/backup.py)."""
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))


def _config_root():
    """Absolute path to app/game_configs (matches scenario_admin's relative convention)."""
    return os.path.abspath(os.path.join(_project_root(), "app", "game_configs"))


def db_file_path():
    """
    Authoritative absolute path to the live SQLite DB, read from the configured engine
    so backup and restore always agree with what the app actually uses. Returns None
    for non-file (e.g. in-memory) databases.
    """
    try:
        from app import db  # lazy: avoid circular import at module load
        path = db.engine.url.database
    except Exception:
        return None
    if not path or path == ":memory:":
        return None
    return path if os.path.isabs(path) else os.path.abspath(os.path.join(_project_root(), path))


def _iter_config_files():
    root = _config_root()
    if not os.path.isdir(root):
        return
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            yield full, rel


def build_backup_archive():
    """
    Build an in-memory .zip snapshot. Returns (bytes, suggested_filename).
    Includes every config file plus a copy of the live DB (if present).
    """
    buf = io.BytesIO()
    n_configs = 0
    db_included = False
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for full, rel in _iter_config_files():
            try:
                zf.write(full, CONFIG_ARC_PREFIX + rel)
                n_configs += 1
            except Exception as e:
                print(f"backup: skipped config {rel}: {e}")

        db_path = db_file_path()
        if db_path and os.path.exists(db_path):
            try:
                # copy first so we archive a consistent snapshot, not a file being written
                with open(db_path, "rb") as fh:
                    zf.writestr(DB_ARCNAME, fh.read())
                db_included = True
            except Exception as e:
                print(f"backup: could not include DB: {e}")

        manifest = (
            "KC7 backup\n"
            f"created: {datetime.now().isoformat(timespec='seconds')}\n"
            f"config_files: {n_configs}\n"
            f"database_included: {db_included}\n"
        )
        zf.writestr(MANIFEST_ARCNAME, manifest)

    buf.seek(0)
    fname = "kc7-backup-" + datetime.now().strftime("%Y%m%d-%H%M%S") + ".zip"
    return buf.getvalue(), fname


def _safe_config_target(arcname):
    """
    Resolve a ``configs/...`` archive member to an absolute path strictly inside the
    config root. Returns the path, or None if the member should be skipped (not a
    config entry, or a traversal attempt).
    """
    if not arcname.startswith(CONFIG_ARC_PREFIX):
        return None
    rel = arcname[len(CONFIG_ARC_PREFIX):]
    if not rel or rel.endswith("/"):
        return None
    root = _config_root()
    full = os.path.abspath(os.path.join(root, rel))
    if full != root and not full.startswith(root + os.sep):
        return None  # path traversal — refuse
    return full


def inspect_archive(data):
    """
    Validate that ``data`` is a usable backup zip and summarize it without writing
    anything. Returns {"ok": bool, "config_files": int, "has_db": bool, "error": str|None}.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
    except Exception as e:
        return {"ok": False, "config_files": 0, "has_db": False, "error": f"not a valid zip: {e}"}
    configs = [n for n in names if n.startswith(CONFIG_ARC_PREFIX) and not n.endswith("/")]
    has_db = DB_ARCNAME in names
    if not configs and not has_db:
        return {"ok": False, "config_files": 0, "has_db": False,
                "error": "archive contains no KC7 config or database entries"}
    return {"ok": True, "config_files": len(configs), "has_db": has_db, "error": None}


def restore_from_archive(data, include_db=False):
    """
    Apply a backup zip. Config files are written immediately (path-guarded). If
    ``include_db`` and the archive carries a DB, the DB bytes are staged to
    ``<db>.pending-restore`` for an atomic swap on next startup (the live file is never
    overwritten here). Returns a summary dict.
    """
    result = {"restored_configs": 0, "skipped": [], "db_staged": False, "errors": []}
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception as e:
        result["errors"].append(f"not a valid zip: {e}")
        return result

    with zf:
        for name in zf.namelist():
            if name.endswith("/"):
                continue
            if name.startswith(CONFIG_ARC_PREFIX):
                target = _safe_config_target(name)
                if not target:
                    result["skipped"].append(name)
                    continue
                try:
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with zf.open(name) as src, open(target, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    result["restored_configs"] += 1
                except Exception as e:
                    result["errors"].append(f"{name}: {e}")

        if include_db and DB_ARCNAME in zf.namelist():
            db_path = db_file_path()
            if not db_path:
                result["errors"].append("cannot stage DB restore: no file-based database configured")
            else:
                try:
                    pending = db_path + PENDING_SUFFIX
                    with zf.open(DB_ARCNAME) as src, open(pending, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    result["db_staged"] = True
                except Exception as e:
                    result["errors"].append(f"DB staging failed: {e}")

    return result


def apply_pending_db_restore():
    """
    Called once at startup BEFORE any DB connection is opened. If a staged DB exists at
    ``<db>.pending-restore``, back up the current DB to ``<db>.bak-<timestamp>`` and move
    the staged file into place. Returns a status message, or None if nothing was staged.
    Best-effort: any failure is reported and leaves the live DB untouched.
    """
    db_path = db_file_path()
    if not db_path:
        return None
    pending = db_path + PENDING_SUFFIX
    if not os.path.exists(pending):
        return None
    try:
        if os.path.exists(db_path):
            backup_copy = db_path + ".bak-" + datetime.now().strftime("%Y%m%d-%H%M%S")
            shutil.copy2(db_path, backup_copy)
        os.replace(pending, db_path)  # atomic on the same filesystem
        return f"restored database from staged backup (previous copy kept alongside {os.path.basename(db_path)})"
    except Exception as e:
        return f"pending DB restore FAILED, live database left unchanged: {e}"
