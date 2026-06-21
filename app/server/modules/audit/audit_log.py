"""
Admin-action audit log (#37).

A tiny helper to record privileged actions (game start/stop, user/role changes, config
changes, deletions) to the ``AdminAudit`` table for accountability. The single entry
point ``record_admin_action`` reads the acting admin from the Flask-Login session and is
**fully guarded** — auditing must never break the action it is recording, so any failure
here is swallowed (and printed) rather than raised.
"""


def record_admin_action(action, target=None, detail=None):
    """
    Append an audit entry for the current admin user. Best-effort: returns the created
    AdminAudit (or None on failure) and never raises.

      action  — short verb.noun, e.g. "game.start", "user.edit", "config.save"
      target  — what was acted on (a username, filename, challenge name, ...)
      detail  — freeform extra context
    """
    try:
        from app.server.models import db, AdminAudit
        from flask import request
        from flask_login import current_user

        uid, uname = None, "?"
        try:
            if getattr(current_user, "is_authenticated", False):
                uid = getattr(current_user, "id", None) or getattr(current_user, "user_id", None)
                uname = getattr(current_user, "username", None) or getattr(current_user, "email", None) or "?"
        except Exception:
            pass

        ip = None
        try:
            ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        except Exception:
            pass

        entry = AdminAudit(actor_user_id=uid, actor_username=uname, action=action,
                           target=target, detail=detail, ip=ip)
        db.session.add(entry)
        db.session.commit()
        return entry
    except Exception as e:
        print(f"audit: failed to record {action!r}: {e}")
        try:
            from app.server.models import db
            db.session.rollback()
        except Exception:
            pass
        return None


def recent_actions(limit=200, action_prefix=None):
    """Return recent audit entries (newest first) as dicts, optionally filtered by an
    action prefix like 'user.' or 'game.'. Best-effort: returns [] on failure."""
    try:
        from app.server.models import AdminAudit
        q = AdminAudit.query
        if action_prefix:
            q = q.filter(AdminAudit.action.like(action_prefix + "%"))
        rows = q.order_by(AdminAudit.id.desc()).limit(min(int(limit), 1000)).all()
        return [r.to_dict() for r in rows]
    except Exception as e:
        print(f"audit: failed to read log: {e}")
        return []
