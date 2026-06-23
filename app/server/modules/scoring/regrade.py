"""
Re-grade past submissions after an answer fix (#31).

When an admin corrects a challenge's accepted answers (e.g. it was too strict, or had a
typo), players who submitted a now-correct answer *before* the fix were unfairly marked
wrong. This finds those players — the earliest now-correct attempt by anyone who doesn't
already have a solve — so the caller can retroactively credit them.

``find_regrade_candidates`` is pure: it takes plain attempt dicts and an injected
``matches_fn`` (the scoreboard's normalizer-backed matcher), so it's fully unit-testable.
"""

import datetime as _dt

_FAR_FUTURE = _dt.datetime.max


def find_regrade_candidates(attempts, solved_user_ids, accepted_answer, matches_fn):
    """
    attempts        : iterable of dicts with keys user_id, username, submitted, attempted_at(datetime|None)
    solved_user_ids : ids of users who ALREADY have a solve for this challenge (skipped)
    accepted_answer : the (updated) accepted-answer string
    matches_fn      : callable(submitted, accepted) -> bool

    Returns a list (sorted by attempt time, earliest first) of one entry per uncredited
    user who has a now-correct attempt:
        {user_id, username, submitted, attempted_at}
    """
    solved = set(solved_user_ids or [])
    earliest = {}
    for a in attempts or []:
        uid = a.get("user_id")
        if uid is None or uid in solved:
            continue
        if not matches_fn(a.get("submitted"), accepted_answer):
            continue
        at = a.get("attempted_at")
        cur = earliest.get(uid)
        if cur is None or _before(at, cur["attempted_at"]):
            earliest[uid] = {
                "user_id": uid,
                "username": a.get("username"),
                "submitted": a.get("submitted"),
                "attempted_at": at,
            }
    return sorted(earliest.values(), key=lambda c: c["attempted_at"] or _FAR_FUTURE)


def _before(a, b):
    """True if datetime a is strictly earlier than b (None is treated as 'latest')."""
    if a is None:
        return False
    if b is None:
        return True
    return a < b
