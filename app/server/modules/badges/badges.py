"""
Achievement badges (gamification).

Players earn badges for milestones derived entirely from data the game already records
(``Solve``, ``MitigationAward``, ``AnswerAttempt``, ``HintReveal`` + ``Challenge``), plus
facilitators can grant discretionary badges by hand. The catalog lives in code (versioned,
no seeding); only *awards* are persisted, in the ``UserBadge`` side-table — so this adds one
table that auto-creates with ``db.create_all`` and changes nothing about existing scoring.

Design mirrors the rest of the codebase: a PURE predicate layer over a plain ``stats`` dict
(unit-testable with no DB) wrapped by an impure layer that gathers stats and writes awards.
Awarding is idempotent and best-effort, so it can never break a solve.
"""

from dataclasses import dataclass, field
from typing import Callable, Optional


# Tier -> ring color for the medallion art (also used by the UI).
TIERS = {
    "bronze":   "#cd7f32",
    "silver":   "#9aa4ad",
    "gold":     "#e0a528",
    "platinum": "#3fc1b0",
    "special":  "#7e57c2",
    "crimson":  "#e0506e",
}


@dataclass
class Badge:
    slug: str
    name: str
    description: str
    tier: str = "bronze"
    manual: bool = False
    predicate: Optional[Callable[[dict], bool]] = None
    sort: int = 0

    @property
    def icon(self) -> str:
        return f"{self.slug}.svg"


# ---------------------------------------------------------------------------
# Catalog. Auto badges carry a pure predicate over a stats dict; manual badges
# (granted by a facilitator) have predicate=None and manual=True.
# ---------------------------------------------------------------------------
BADGES = [
    # -- solve-count milestones --
    Badge("first_steps", "First steps", "Solve your first challenge.", "bronze",
          predicate=lambda s: s["solve_count"] >= 1, sort=10),
    Badge("apprentice", "Apprentice", "Solve 5 challenges.", "bronze",
          predicate=lambda s: s["solve_count"] >= 5, sort=11),
    Badge("analyst", "Analyst", "Solve 10 challenges.", "silver",
          predicate=lambda s: s["solve_count"] >= 10, sort=12),
    Badge("threat_hunter", "Threat hunter", "Solve 25 challenges.", "gold",
          predicate=lambda s: s["solve_count"] >= 25, sort=13),

    # -- first blood --
    Badge("first_blood", "First blood", "Be the first to solve a challenge.", "crimson",
          predicate=lambda s: s["first_blood_count"] >= 1, sort=20),
    Badge("quick_draw", "Quick draw", "Take first blood on 3 challenges.", "crimson",
          predicate=lambda s: s["first_blood_count"] >= 3, sort=21),

    # -- category mastery --
    Badge("specialist", "Specialist", "Solve every challenge in a category.", "silver",
          predicate=lambda s: s["categories_mastered"] >= 1, sort=30),
    Badge("full_spectrum", "Full spectrum", "Master every category.", "platinum",
          predicate=lambda s: s["total_categories"] > 0
          and s["categories_mastered"] >= s["total_categories"], sort=31),

    # -- completion --
    Badge("clean_sweep", "Clean sweep", "Solve every challenge in the game.", "platinum",
          predicate=lambda s: s["full_clear"], sort=40),
    Badge("flawless", "Flawless", "Clear the whole game with no wrong answers.", "platinum",
          predicate=lambda s: s["full_clear"] and s["wrong_attempts_total"] == 0, sort=41),

    # -- speed & precision --
    Badge("speed_demon", "Speed demon", "Solve a challenge while the time bonus is high.", "gold",
          predicate=lambda s: s["speed_solves"] >= 1, sort=50),
    Badge("sharpshooter", "Sharpshooter", "Solve 5 challenges with no wrong guesses.", "silver",
          predicate=lambda s: s["clean_solves"] >= 5, sort=51),
    Badge("purist", "Purist", "Solve 10 challenges without revealing a hint.", "gold",
          predicate=lambda s: s["no_hint_solves"] >= 10, sort=52),

    # -- indicator hunting --
    Badge("bloodhound", "Bloodhound", "Find 10 malicious indicators.", "silver",
          predicate=lambda s: s["indicators_found"] >= 10, sort=60),

    # -- fun / flavor --
    Badge("night_owl", "Night owl", "Solve a challenge between midnight and 4am.", "special",
          predicate=lambda s: s["night_solve"], sort=70),
    Badge("early_bird", "Early bird", "Solve a challenge between 5 and 8am.", "special",
          predicate=lambda s: s["early_solve"], sort=71),
    Badge("comeback_kid", "Comeback kid", "Solve a challenge after 3+ wrong tries.", "special",
          predicate=lambda s: s["comeback"], sort=72),
    Badge("on_fire", "On fire", "Solve 3 challenges within 10 minutes.", "special",
          predicate=lambda s: s["hot_streak"], sort=73),

    # -- kill chain / ATT&CK --
    Badge("full_kill_chain", "Full kill chain", "Solve a challenge in every category.", "gold",
          predicate=lambda s: s["all_categories_covered"] and s["total_categories"] >= 3, sort=100),
    Badge("mitre_maven", "MITRE maven", "Cover 8 distinct ATT&CK techniques.", "gold",
          predicate=lambda s: s["attack_techniques"] >= 8, sort=101),
    Badge("attribution_ace", "Attribution ace", "Solve an attribution challenge.", "silver",
          predicate=lambda s: s["attribution_solved"], sort=102),

    # -- indicator-type diversity --
    Badge("four_of_a_kind", "Four of a kind", "Find a domain, IP, email and hash indicator.", "gold",
          predicate=lambda s: s["four_types"], sort=110),
    Badge("hash_slinger", "Hash slinger", "Find 10 file-hash indicators.", "silver",
          predicate=lambda s: s["ind_hash"] >= 10, sort=111),
    Badge("dns_detective", "DNS detective", "Find 10 domain indicators.", "silver",
          predicate=lambda s: s["ind_domain"] >= 10, sort=112),

    # -- score milestones --
    Badge("century", "Century", "Reach 100 points.", "bronze",
          predicate=lambda s: s["score"] >= 100, sort=120),
    Badge("high_roller", "High roller", "Reach 1,000 points.", "silver",
          predicate=lambda s: s["score"] >= 1000, sort=121),
    Badge("five_figures", "Five figures", "Reach 10,000 points.", "gold",
          predicate=lambda s: s["score"] >= 10000, sort=122),

    # -- rank / competitive --
    Badge("podium", "Podium", "Reach the top 3 on the leaderboard.", "gold",
          predicate=lambda s: 1 <= s["rank"] <= 3, sort=130),
    Badge("champion", "Champion", "Reach #1 on the leaderboard.", "platinum",
          predicate=lambda s: s["rank"] == 1, sort=131),
    Badge("king_of_hill", "King of the hill", "Lead with at least double the runner-up's score.", "platinum",
          predicate=lambda s: s["rank_dominant"], sort=132),
    Badge("giant_killer", "Giant killer", "Take first blood on the highest-value challenge.", "crimson",
          predicate=lambda s: s["giant_killer"], sort=133),

    # -- team --
    Badge("carry", "Carry", "Be the top scorer on your team.", "gold",
          predicate=lambda s: s["team_top"], sort=140),
    Badge("backbone", "Backbone", "Every member of your team has solved something.", "silver",
          predicate=lambda s: s["team_backbone"], sort=141),
    Badge("dream_team", "Dream team", "Your team collectively clears a category.", "platinum",
          predicate=lambda s: s["team_dreamteam"], sort=142),

    # -- timing & consistency --
    Badge("weekend_warrior", "Weekend warrior", "Solve a challenge on a weekend.", "special",
          predicate=lambda s: s["weekend_solve"], sort=150),
    Badge("lightning_round", "Lightning round", "Solve 5 challenges within an hour.", "gold",
          predicate=lambda s: s["lightning"], sort=151),
    Badge("marathoner", "Marathoner", "Solve challenges on 3 different days.", "silver",
          predicate=lambda s: s["distinct_days"] >= 3, sort=152),
    Badge("opening_act", "Opening act", "Solve within the first hour of the game.", "special",
          predicate=lambda s: s["opening_act"], sort=153),

    # -- flavor / funny --
    Badge("ghost", "Ghost", "Clear the whole game without revealing a hint.", "platinum",
          predicate=lambda s: s["ghost"], sort=160),
    Badge("sniper", "Sniper", "Solve 10 challenges with no wrong guesses.", "gold",
          predicate=lambda s: s["clean_solves"] >= 10, sort=161),
    Badge("persistent", "Persistent", "Solve a challenge after 10+ wrong tries.", "special",
          predicate=lambda s: s["persistent"], sort=162),
    Badge("phoenix", "Phoenix", "Solve 5 challenges you'd previously answered wrong.", "special",
          predicate=lambda s: s["phoenix_count"] >= 5, sort=163),
    Badge("clutch", "Clutch", "Solve in the final minutes of a timed game.", "crimson",
          predicate=lambda s: s["clutch"], sort=164),

    # -- manual / discretionary (granted by a facilitator) --
    Badge("mvp", "MVP", "Most valuable player — awarded by a facilitator.", "gold",
          manual=True, sort=200),
    Badge("good_sport", "Good sportsmanship", "Awarded by a facilitator for great conduct.", "special",
          manual=True, sort=201),
    Badge("team_player", "Team player", "Awarded by a facilitator for lifting the team.", "special",
          manual=True, sort=202),
]

BADGES_BY_SLUG = {b.slug: b for b in BADGES}
MANUAL_BADGES = [b for b in BADGES if b.manual]

# Every key a predicate may read — used to build a safe default stats dict so a
# missing metric never throws (it just means "not earned").
STAT_KEYS = (
    "solve_count", "first_blood_count", "categories_mastered", "total_categories",
    "full_clear", "wrong_attempts_total", "speed_solves", "clean_solves",
    "no_hint_solves", "indicators_found", "night_solve", "early_solve",
    "comeback", "hot_streak",
    # second wave
    "score", "rank", "rank_dominant", "ind_domain", "ind_ip", "ind_email", "ind_hash",
    "four_types", "all_categories_covered", "attack_techniques", "attribution_solved",
    "giant_killer", "team_top", "team_backbone", "team_dreamteam", "weekend_solve",
    "lightning", "distinct_days", "opening_act", "ghost", "persistent", "phoenix_count",
    "clutch",
)

# Keys whose default must be False (everything else defaults to 0).
_BOOL_STAT_KEYS = (
    "full_clear", "night_solve", "early_solve", "comeback", "hot_streak",
    "rank_dominant", "four_types", "all_categories_covered", "attribution_solved",
    "giant_killer", "team_top", "team_backbone", "team_dreamteam", "weekend_solve",
    "lightning", "opening_act", "ghost", "persistent", "clutch",
)


def empty_stats() -> dict:
    """A zero/false-filled stats dict, so predicates are always safe to evaluate."""
    d = {k: 0 for k in STAT_KEYS}
    for k in _BOOL_STAT_KEYS:
        d[k] = False
    return d


def classify_indicator(value: str) -> str:
    """Best-effort indicator type: 'hash' | 'ip' | 'email' | 'domain'."""
    import re
    v = (value or "").strip().lower()
    if not v:
        return "domain"
    h = v.replace(" ", "")
    if re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", h):
        return "hash"
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", v.replace("[.]", ".")):
        return "ip"
    if "@" in v or "[at]" in v:
        return "email"
    return "domain"


def badges_earned_from_stats(stats: dict) -> set:
    """PURE: slugs of all auto badges whose predicate is satisfied by ``stats``."""
    s = empty_stats()
    s.update(stats or {})
    earned = set()
    for b in BADGES:
        if b.manual or not b.predicate:
            continue
        try:
            if b.predicate(s):
                earned.add(b.slug)
        except Exception:
            pass
    return earned


# ---------------------------------------------------------------------------
# Impure layer: gather stats from the DB, evaluate, persist awards.
# ---------------------------------------------------------------------------
SPEED_BONUS_RATIO = 1.5   # points_awarded >= 1.5x base value == solved while bonus was high
COMEBACK_WRONG = 3        # wrong tries before a solve to count as a "comeback"
HOT_STREAK_N = 3          # solves...
HOT_STREAK_MINUTES = 10   # ...within this many minutes


def compute_user_stats(user_id: int) -> dict:
    """IMPURE: build the stats dict for one user from recorded game data."""
    from app.server.models import (
        Solve, Challenge, MitigationAward, AnswerAttempt, HintReveal,
    )

    stats = empty_stats()

    solves = Solve.query.filter_by(user_id=user_id).all()
    stats["solve_count"] = len(solves)

    # challenge catalog (exclude round-scoped? keep all) → totals per category
    all_challenges = Challenge.query.all()
    total_challenges = len(all_challenges)
    cat_totals = {}
    for c in all_challenges:
        cat = (c.category or "General")
        cat_totals[cat] = cat_totals.get(cat, 0) + 1
    stats["total_categories"] = len([c for c, n in cat_totals.items() if n > 0])

    if total_challenges and stats["solve_count"] >= total_challenges:
        stats["full_clear"] = True

    # per-category solved counts + value/time lookups
    chal_by_id = {c.id: c for c in all_challenges}
    cat_solved = {}
    speed_solves = 0
    solve_times = []
    for sv in solves:
        ch = chal_by_id.get(sv.challenge_id)
        cat = (ch.category if ch else "General") or "General"
        cat_solved[cat] = cat_solved.get(cat, 0) + 1
        base = (ch.value if ch else 0) or 0
        if base and (sv.points_awarded or 0) >= SPEED_BONUS_RATIO * base:
            speed_solves += 1
        if sv.solved_at:
            solve_times.append(sv.solved_at)
    stats["speed_solves"] = speed_solves
    stats["categories_mastered"] = sum(
        1 for cat, total in cat_totals.items() if total > 0 and cat_solved.get(cat, 0) >= total
    )

    # first blood: challenges where this user's solve is the earliest of all
    fb = 0
    solved_ids = {sv.challenge_id for sv in solves}
    for cid in solved_ids:
        earliest = (Solve.query.filter_by(challenge_id=cid)
                    .order_by(Solve.solved_at.asc()).first())
        if earliest and earliest.user_id == user_id:
            fb += 1
    stats["first_blood_count"] = fb

    # attempts: wrong totals, clean solves, comebacks
    attempts = AnswerAttempt.query.filter_by(user_id=user_id).all()
    wrong_by_chal = {}
    wrong_total = 0
    for a in attempts:
        if not a.correct:
            wrong_by_chal[a.challenge_id] = wrong_by_chal.get(a.challenge_id, 0) + 1
            wrong_total += 1
    stats["wrong_attempts_total"] = wrong_total
    stats["clean_solves"] = sum(1 for sv in solves if wrong_by_chal.get(sv.challenge_id, 0) == 0)
    stats["comeback"] = any(wrong_by_chal.get(sv.challenge_id, 0) >= COMEBACK_WRONG for sv in solves)

    # no-hint solves
    hinted = {hr.challenge_id for hr in HintReveal.query.filter_by(user_id=user_id).all()}
    stats["no_hint_solves"] = sum(1 for sv in solves if sv.challenge_id not in hinted)

    # indicators found
    stats["indicators_found"] = MitigationAward.query.filter_by(user_id=user_id).count()

    # time-of-day flavor + hot streak
    for t in solve_times:
        h = t.hour
        if 0 <= h < 4:
            stats["night_solve"] = True
        if 5 <= h < 8:
            stats["early_solve"] = True
    stats["hot_streak"] = _has_hot_streak(solve_times, HOT_STREAK_N, HOT_STREAK_MINUTES)

    # ---- second-wave metrics ----
    from app.server.models import db, Users, GameSession
    import re as _re

    me = db.session.get(Users, user_id)
    stats["score"] = int((me.score if me else 0) or 0)

    # leaderboard rank among players who have scored
    scored = sorted([u for u in Users.query.all() if (u.score or 0) > 0],
                    key=lambda u: (u.score or 0), reverse=True)
    rank = next((i for i, u in enumerate(scored, start=1) if u.id == user_id), 0)
    stats["rank"] = rank
    if rank == 1:
        top = scored[0].score or 0
        second = scored[1].score if len(scored) >= 2 else 0
        stats["rank_dominant"] = top > 0 and top >= 2 * (second or 0)

    # indicator types
    for ma in MitigationAward.query.filter_by(user_id=user_id).all():
        stats["ind_" + classify_indicator(ma.indicator)] += 1
    stats["four_types"] = all(stats["ind_" + t] >= 1 for t in ("domain", "ip", "email", "hash"))

    # full kill chain: every category has at least one solve
    stats["all_categories_covered"] = bool(cat_totals) and all(
        cat_solved.get(c, 0) >= 1 for c in cat_totals)

    # distinct ATT&CK techniques across solved challenges (parsed from text)
    tech = set()
    for cid in solved_ids:
        ch = chal_by_id.get(cid)
        if ch:
            blob = " ".join([ch.name or "", ch.category or "", ch.description or ""])
            tech.update(m.upper() for m in _re.findall(r"\bT\d{4}(?:\.\d{3})?\b", blob))
    stats["attack_techniques"] = len(tech)

    # attribution challenge solved
    stats["attribution_solved"] = any(
        chal_by_id.get(cid) and "attribution" in
        ((chal_by_id[cid].category or "") + " " + (chal_by_id[cid].name or "")).lower()
        for cid in solved_ids)

    # giant killer: first blood on the highest-value challenge
    if all_challenges:
        top_ch = max(all_challenges, key=lambda c: (c.value or 0))
        if (top_ch.value or 0) > 0:
            fb = Solve.query.filter_by(challenge_id=top_ch.id).order_by(Solve.solved_at.asc()).first()
            stats["giant_killer"] = bool(fb and fb.user_id == user_id)

    # team metrics
    if me and me.team:
        members = list(me.team.members)
        if len(members) >= 2:
            my_score = me.score or 0
            stats["team_top"] = my_score > 0 and my_score == max((m.score or 0) for m in members)
            member_ids = [m.id for m in members]
            stats["team_backbone"] = all(
                Solve.query.filter_by(user_id=mid).count() >= 1 for mid in member_ids)
            team_solved_ids = set()
            for mid in member_ids:
                team_solved_ids.update(s.challenge_id for s in Solve.query.filter_by(user_id=mid).all())
            tcat = {}
            for cid in team_solved_ids:
                ch = chal_by_id.get(cid)
                c = (ch.category if ch else "General") or "General"
                tcat[c] = tcat.get(c, 0) + 1
            stats["team_dreamteam"] = any(
                tcat.get(c, 0) >= tot for c, tot in cat_totals.items() if tot > 0)

    # timing & consistency
    stats["weekend_solve"] = any(t.weekday() >= 5 for t in solve_times)
    stats["distinct_days"] = len({t.date() for t in solve_times})
    stats["lightning"] = _has_hot_streak(solve_times, 5, 60)
    if solve_times:
        first_overall = Solve.query.order_by(Solve.solved_at.asc()).first()
        if first_overall and first_overall.solved_at:
            base0 = first_overall.solved_at
            stats["opening_act"] = any(0 <= (t - base0).total_seconds() <= 3600 for t in solve_times)

    # flavor
    stats["ghost"] = stats["full_clear"] and len(hinted) == 0
    stats["persistent"] = any(wrong_by_chal.get(sv.challenge_id, 0) >= 10 for sv in solves)
    stats["phoenix_count"] = sum(1 for sv in solves if wrong_by_chal.get(sv.challenge_id, 0) >= 1)

    sess = db.session.get(GameSession, 1)
    if sess and getattr(sess, "uses_timer", False) and getattr(sess, "end_time", None):
        et = sess.end_time
        stats["clutch"] = any(0 <= (et - t).total_seconds() <= 600 for t in solve_times)

    return stats


def _has_hot_streak(times, n, minutes) -> bool:
    """True if any window of ``minutes`` contains at least ``n`` solves."""
    ts = sorted(t for t in times if t is not None)
    if len(ts) < n:
        return False
    span = minutes * 60
    for i in range(len(ts) - n + 1):
        if (ts[i + n - 1] - ts[i]).total_seconds() <= span:
            return True
    return False


def evaluate_and_award(user) -> list:
    """
    IMPURE: compute the user's stats, award any newly-earned auto badges (idempotent),
    and return the list of newly-earned Badge objects (for an earn toast). Best-effort:
    any failure is swallowed so it can never break the solve that triggered it.
    """
    try:
        from app.server.models import db, UserBadge
        stats = compute_user_stats(user.id)
        earned = badges_earned_from_stats(stats)
        existing = {ub.slug for ub in UserBadge.query.filter_by(user_id=user.id).all()}
        new = [s for s in earned if s not in existing]
        if not new:
            return []
        for slug in new:
            db.session.add(UserBadge(user_id=user.id, slug=slug, awarded_by=None))
        db.session.commit()
        return [BADGES_BY_SLUG[s] for s in new if s in BADGES_BY_SLUG]
    except Exception as e:
        print("badge evaluation skipped:", e)
        return []


def award_manual(user_id: int, slug: str, admin_username: str) -> bool:
    """Grant a badge by hand (admin). Returns True if newly granted."""
    from app.server.models import db, UserBadge
    badge = BADGES_BY_SLUG.get(slug)
    if not badge:
        return False
    if UserBadge.query.filter_by(user_id=user_id, slug=slug).first():
        return False
    db.session.add(UserBadge(user_id=user_id, slug=slug, awarded_by=admin_username or "admin"))
    db.session.commit()
    return True


def revoke_badge(user_id: int, slug: str) -> bool:
    """Remove a badge award. Returns True if one was removed."""
    from app.server.models import db, UserBadge
    ub = UserBadge.query.filter_by(user_id=user_id, slug=slug).first()
    if not ub:
        return False
    db.session.delete(ub)
    db.session.commit()
    return True


def get_user_badges(user_id: int) -> dict:
    """
    For display: {"earned": [...], "locked": [...], "earned_count", "total"} where each
    entry carries the catalog metadata (+ earned_at / awarded_by for earned ones). Locked
    entries hide manual badges (you can't "work toward" those).
    """
    from app.server.models import UserBadge
    awards = {ub.slug: ub for ub in UserBadge.query.filter_by(user_id=user_id).all()}
    earned, locked = [], []
    for b in sorted(BADGES, key=lambda x: x.sort):
        meta = {
            "slug": b.slug, "name": b.name, "description": b.description,
            "tier": b.tier, "icon": b.icon, "manual": b.manual,
            "color": TIERS.get(b.tier, "#888"),
        }
        if b.slug in awards:
            a = awards[b.slug]
            meta["earned_at"] = a.earned_at
            meta["awarded_by"] = a.awarded_by
            earned.append(meta)
        elif not b.manual:
            locked.append(meta)
    return {
        "earned": earned, "locked": locked,
        "earned_count": len(earned), "total": len(BADGES),
    }
