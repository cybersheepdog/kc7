"""
Challenge hints & gating (#32).

Pure evaluation of whether a challenge is currently locked for a given player, based on
its optional ``ChallengeGating`` rules:

  - **timed unlock**: locked until ``unlock_at``.
  - **prerequisite**: locked until the player has solved ``prerequisite_id``.

A challenge with no gating rules is never locked — so existing challenges are unaffected.
``evaluate`` is pure (plain values in, a dict out) so it is fully unit-testable; callers
pass the player's solved-challenge id set and the current time.
"""


def evaluate(gating, solved_ids, now, prereq_name=None):
    """
    gating       : an object/dict with .unlock_at and .prerequisite_id (or None for an
                   ungated challenge).
    solved_ids   : set of challenge ids the player has already solved.
    now          : current datetime.
    prereq_name  : optional display name of the prerequisite challenge.

    Returns {"locked": bool, "reason": None|"time"|"prereq",
             "unlock_at": datetime|None, "prerequisite_id": int|None,
             "message": str|None}.
    """
    if gating is None:
        return {"locked": False, "reason": None, "unlock_at": None,
                "prerequisite_id": None, "message": None}

    unlock_at = _get(gating, "unlock_at")
    prereq_id = _get(gating, "prerequisite_id")
    solved_ids = solved_ids or set()

    # timed unlock takes precedence (it's the more visible "not yet" reason)
    if unlock_at is not None and now is not None and now < unlock_at:
        return {"locked": True, "reason": "time", "unlock_at": unlock_at,
                "prerequisite_id": prereq_id,
                "message": "Unlocks at %s" % unlock_at.strftime("%Y-%m-%d %H:%M")}

    if prereq_id and prereq_id not in solved_ids:
        label = prereq_name or ("challenge #%s" % prereq_id)
        return {"locked": True, "reason": "prereq", "unlock_at": unlock_at,
                "prerequisite_id": prereq_id,
                "message": "Solve \"%s\" first" % label}

    return {"locked": False, "reason": None, "unlock_at": unlock_at,
            "prerequisite_id": prereq_id, "message": None}


def hint_state(gating, revealed, hint_text=None):
    """
    Summarize a challenge's hint for display.
    gating   : ChallengeGating or None.  revealed : bool (this player already paid).
    Returns {"has_hint": bool, "cost": int, "revealed": bool, "text": str|None}.
    """
    if gating is None or not _get(gating, "hint"):
        return {"has_hint": False, "cost": 0, "revealed": False, "text": None}
    return {
        "has_hint": True,
        "cost": int(_get(gating, "hint_cost") or 0),
        "revealed": bool(revealed),
        "text": (hint_text if revealed else None),
    }


def _get(obj, attr):
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(attr)
    return getattr(obj, attr, None)
