"""
Analyst rank titles (#53).

A pure ladder mapping a player's score to a flavorful cybersecurity-career title, with
progress toward the next rank. No DB and no side effects, so it's fully unit-testable and
safe to call from the profile page, the leaderboard payload, or anywhere else. Purely
cosmetic — it never affects scoring or ordering.
"""

# (min_score, title), ascending by min_score. The top entry has no "next" rank.
RANK_LADDER = [
    (0,     "Recruit"),
    (100,   "Analyst I"),
    (300,   "Analyst II"),
    (600,   "SOC Analyst"),
    (1000,  "Incident Responder"),
    (1750,  "Threat Hunter"),
    (2750,  "Senior Threat Hunter"),
    (4000,  "SOC Lead"),
    (6000,  "Principal Analyst"),
    (9000,  "Cyber Sentinel"),
]


def rank_for_score(score) -> dict:
    """
    Return rank info for a score::

        {level, title, min, next_title, next_at, to_next, progress_pct}

    ``progress_pct`` is 0–100 *within the current band* (100 once at the top rank).
    Negative / None scores are treated as 0.
    """
    s = max(0, int(score or 0))
    idx = 0
    for i, (mn, _title) in enumerate(RANK_LADDER):
        if s >= mn:
            idx = i
        else:
            break

    mn, title = RANK_LADDER[idx]
    if idx + 1 < len(RANK_LADDER):
        next_at, next_title = RANK_LADDER[idx + 1]
        span = next_at - mn
        to_next = max(0, next_at - s)
        progress = int(round(100 * (s - mn) / span)) if span > 0 else 100
        progress = max(0, min(100, progress))
    else:
        next_at, next_title, to_next, progress = None, None, 0, 100

    return {
        "level":        idx + 1,
        "title":        title,
        "min":          mn,
        "next_title":   next_title,
        "next_at":      next_at,
        "to_next":      to_next,
        "progress_pct": progress,
    }


def title_for_score(score) -> str:
    """Just the title string for a score (convenience for the leaderboard payload)."""
    return rank_for_score(score)["title"]
