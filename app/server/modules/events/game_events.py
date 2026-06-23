"""
Live event ticker (#54).

Records notable in-game moments (first blood, badge unlock, rank-up) and formats them for
a scoreboard ticker. The formatting is **spoiler-aware**: in a discovery game, naming the
challenge or even its category reveals which TTPs are in play, so a facilitator 'reveal
level' controls what's shown. Standings-movement and badge/rank events carry no case
content and are always safe.

Reveal levels (config ``EVENT_TICKER_REVEAL``):
  - ``off``        — ticker disabled.
  - ``standings``  — badges, rank-ups, and *generic* "drew first blood!" (no names). Default.
  - ``category``   — the above, plus "first blood in <category>".
  - ``full``       — the above, plus "first blood on '<challenge name>'".

``EVENT_TICKER_FIRSTBLOOD_AFTER_N`` optionally withholds the challenge/category name on a
first-blood event until N teams have solved that challenge (so it's no longer a spoiler).

The ``format_event`` function is PURE (no DB) and unit-tested; the record/query helpers are
thin impure wrappers.
"""

REVEAL_LEVELS = ("off", "standings", "category", "full")


def format_event(ev: dict, reveal: str, solve_count: int = 0, firstblood_after_n: int = 0):
    """
    PURE. Turn an event dict into {"icon", "text", "kind"} for display, honoring the
    reveal level and the first-blood name-gate. Returns None when the event should be
    hidden at this reveal level.
    """
    reveal = (reveal or "standings").lower()
    if reveal == "off":
        return None

    kind = ev.get("kind")
    who = ev.get("username") or "Someone"

    if kind == "badge":
        name = ev.get("detail") or "a"
        return {"kind": "badge", "icon": "medal", "text": f"{who} earned the {name} badge"}

    if kind == "rankup":
        title = ev.get("detail") or "a new rank"
        return {"kind": "rankup", "icon": "up", "text": f"{who} reached {title}"}

    if kind == "first_blood":
        # A name (challenge or category) may only be shown at category/full level AND once
        # the challenge has enough solves to no longer be a spoiler.
        name_ok = reveal in ("category", "full") and solve_count >= max(0, int(firstblood_after_n or 0))
        if name_ok and reveal == "full" and ev.get("challenge_name"):
            return {"kind": "first_blood", "icon": "blood",
                    "text": f"{who} drew first blood on “{ev['challenge_name']}”!"}
        if name_ok and ev.get("category"):
            return {"kind": "first_blood", "icon": "blood",
                    "text": f"{who} drew first blood in {ev['category']}!"}
        # safe fallback — carries no case content
        return {"kind": "first_blood", "icon": "blood", "text": f"{who} drew first blood!"}

    return None


# ---------------------------------------------------------------------------
# Impure helpers
# ---------------------------------------------------------------------------
def record_event(kind, username=None, team_name=None, challenge_name=None,
                 category=None, challenge_id=None, detail=None, round_id=None):
    """Best-effort: persist a GameEvent. Never raises (can't break the scoring path)."""
    try:
        from app.server.models import db, GameEvent
        db.session.add(GameEvent(
            kind=kind, username=username, team_name=team_name,
            challenge_name=challenge_name, category=category,
            challenge_id=challenge_id, detail=detail, round_id=round_id))
        db.session.commit()
    except Exception as e:
        print("record_event skipped:", e)


def recent_feed(limit=20):
    """
    Build the formatted ticker feed (newest first) at the configured reveal level.
    Returns {"reveal": str, "events": [{"icon","text","kind"}...]}.
    """
    from flask import current_app
    from app.server.models import GameEvent, Solve

    reveal = (current_app.config.get("EVENT_TICKER_REVEAL", "standings") or "standings").lower()
    if reveal not in REVEAL_LEVELS:
        reveal = "standings"
    if reveal == "off":
        return {"reveal": "off", "events": []}
    after_n = int(current_app.config.get("EVENT_TICKER_FIRSTBLOOD_AFTER_N", 0) or 0)

    rows = (GameEvent.query.order_by(GameEvent.created_at.desc())
            .limit(max(1, min(int(limit or 20), 50))).all())

    out = []
    for r in rows:
        ev = r.to_dict()
        solve_count = 0
        if ev["kind"] == "first_blood" and ev.get("challenge_id") and reveal in ("category", "full"):
            try:
                solve_count = Solve.query.filter_by(challenge_id=ev["challenge_id"]).count()
            except Exception:
                solve_count = 0
        formatted = format_event(ev, reveal, solve_count=solve_count, firstblood_after_n=after_n)
        if formatted:
            formatted["created_at"] = ev.get("created_at")
            out.append(formatted)
    return {"reveal": reveal, "events": out}
