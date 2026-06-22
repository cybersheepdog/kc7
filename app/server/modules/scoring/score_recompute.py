"""
Score reconciliation — rebuild authoritative scores from the source-of-truth records
and surface any drift from the stored running totals.

Why this exists
---------------
``Users.score`` and ``Team.score`` are denormalized running counters. If a challenge's
value is changed, a solve is deleted, or an answer is corrected, those counters can
silently desync from reality. ``Solve.points_awarded`` is a clean per-solve record of
*challenge* points, so the challenge-points portion of every score is exactly
recomputable from it.

Important caveat (indicator/mitigation points)
----------------------------------------------
Indicator (mitigation) points are NOT individually recorded — they are only folded into
the running totals (and the team's ``_mitigations`` blob stores the submitted strings,
not points or timestamps, and not per user). So this module does a **non-destructive
reconciliation**: it reports the recomputed challenge points next to the stored score.
The ``delta`` (stored - challenge_points) is expected to equal each entity's indicator
points for consistent data; a *negative* delta — or one that can't be explained by
indicator scoring — flags a genuine desync.

A fully destructive rebuild that also restores indicator points exactly requires adding
per-award indicator records (a small schema addition) — tracked as a follow-up.

This module is pure: it operates on plain record objects (anything exposing the small
set of attributes used below), so it is fast and unit-testable without a database.
"""


def challenge_points_by_user(solves) -> dict:
    """Sum Solve.points_awarded per user_id."""
    out = {}
    for s in solves:
        out[s.user_id] = out.get(s.user_id, 0) + (getattr(s, "points_awarded", 0) or 0)
    return out


def indicator_points_by_user(awards) -> dict:
    """Sum MitigationAward.points_awarded per user_id."""
    out = {}
    for a in awards or []:
        out[a.user_id] = out.get(a.user_id, 0) + (getattr(a, "points_awarded", 0) or 0)
    return out


def _adjustments_by_target(adjustments):
    """Split manual ScoreAdjustment deltas into ({user_id: delta}, {team_id: delta}) (#30)."""
    uadj, tadj = {}, {}
    for adj in adjustments or []:
        delta = getattr(adj, "delta", 0) or 0
        ttype = getattr(adj, "target_type", None)
        tid = getattr(adj, "target_id", None)
        if tid is None:
            continue
        if ttype == "user":
            uadj[tid] = uadj.get(tid, 0) + delta
        elif ttype == "team":
            tadj[tid] = tadj.get(tid, 0) + delta
    return uadj, tadj


def latest_solve_time_by_user(solves) -> dict:
    """Most recent solved_at per user_id (None-safe)."""
    out = {}
    for s in solves:
        t = getattr(s, "solved_at", None)
        if t is None:
            continue
        if s.user_id not in out or t > out[s.user_id]:
            out[s.user_id] = t
    return out


def reconcile(users, teams, solves, awards=None, adjustments=None) -> dict:
    """
    Compare stored scores to the totals recomputed from source-of-truth records:
    challenge points from Solve, plus indicator points from MitigationAward (if
    available — these are only recorded for games run after award-logging shipped).

    Parameters (duck-typed):
      users  : objects with .id, .username, .score, .team_id
      teams  : objects with .id, .name, .score
      solves : objects with .user_id, .points_awarded, (optional) .solved_at
      awards : objects with .user_id, .points_awarded (optional)

    Returns a structured report with per-user and per-team rows and a summary.
    """
    cp_by_user = challenge_points_by_user(solves)
    ip_by_user = indicator_points_by_user(awards)
    uadj, tadj = _adjustments_by_target(adjustments)
    has_awards = bool(awards)

    user_rows = []
    team_recomputed = {}
    for u in users:
        ucp = cp_by_user.get(u.id, 0)
        uip = ip_by_user.get(u.id, 0)
        uaj = uadj.get(u.id, 0)
        recomputed = ucp + uip + uaj
        stored = u.score or 0
        user_rows.append({
            "user_id": u.id,
            "username": u.username,
            "stored_score": stored,
            "challenge_points": ucp,
            "indicator_points": uip,
            "adjustment_points": uaj,
            "recomputed_total": recomputed,
            "delta": stored - recomputed,
        })
        if getattr(u, "team_id", None) is not None:
            team_recomputed[u.team_id] = team_recomputed.get(u.team_id, 0) + recomputed

    team_rows = []
    for t in teams:
        # team total = sum of members' recomputed (incl. their user adjustments) + any
        # team-level manual adjustments.
        tr = team_recomputed.get(t.id, 0) + tadj.get(t.id, 0)
        stored = t.score or 0
        team_rows.append({
            "team_id": t.id,
            "name": t.name,
            "stored_score": stored,
            "challenge_points": tr,  # kept for column compatibility; equals recomputed total
            "recomputed_total": tr,
            "delta": stored - tr,
        })

    negative_users = [r for r in user_rows if r["delta"] < 0]
    negative_teams = [r for r in team_rows if r["delta"] < 0]

    return {
        "users": user_rows,
        "teams": team_rows,
        "summary": {
            "user_count": len(user_rows),
            "team_count": len(team_rows),
            "users_with_delta": sum(1 for r in user_rows if r["delta"] != 0),
            "teams_with_delta": sum(1 for r in team_rows if r["delta"] != 0),
            "users_with_negative_delta": len(negative_users),
            "teams_with_negative_delta": len(negative_teams),
            "likely_desync": bool(negative_users or negative_teams),
            "has_indicator_awards": has_awards,
            "note": (
                "delta = stored_score - recomputed_total, where recomputed_total = "
                "challenge points (from Solve) + indicator points (from MitigationAward). "
                + ("Indicator awards ARE recorded for this game, so a non-zero delta "
                   "indicates a real desync (deleted solve/award, changed challenge value)."
                   if has_awards else
                   "No indicator awards are recorded (game pre-dates award logging), so a "
                   "POSITIVE delta is expected — it reflects unrecorded indicator points. "
                   "A NEGATIVE delta still indicates a definite desync.")
            ),
        },
    }


def format_reconciliation_text(report: dict) -> str:
    """Render a reconciliation report as a readable plain-text table."""
    s = report.get("summary", {})
    lines = []
    lines.append("=" * 72)
    lines.append("SCORE RECONCILIATION (challenge points recomputed from Solve records)")
    lines.append("=" * 72)
    lines.append(f"Users: {s.get('user_count', 0)}   Teams: {s.get('team_count', 0)}")
    lines.append(f"With non-zero delta -> users: {s.get('users_with_delta', 0)}, "
                 f"teams: {s.get('teams_with_delta', 0)}")
    if s.get("likely_desync"):
        lines.append("  ** LIKELY DESYNC DETECTED (negative delta present) — review below **")
    lines.append("")

    def _table(title, rows, name_key):
        out = [title, "-" * 72,
               f"{'name':<22}{'stored':>9}{'recomputed':>12}{'delta':>9}"]
        for r in sorted(rows, key=lambda x: x["delta"]):
            flag = "  <-- desync" if r["delta"] < 0 else ""
            out.append(f"{str(r[name_key])[:22]:<22}{r['stored_score']:>9}"
                       f"{r['recomputed_total']:>12}{r['delta']:>9}{flag}")
        out.append("")
        return out

    lines += _table("TEAMS", report.get("teams", []), "name")
    lines += _table("PLAYERS", report.get("users", []), "username")
    lines.append("Note: " + s.get("note", ""))
    return "\n".join(lines)


def _latest_time_by_user(records, attr: str) -> dict:
    """Most recent value of `attr` per user_id across records (None-safe)."""
    out = {}
    for r in records or []:
        t = getattr(r, attr, None)
        if t is None:
            continue
        if r.user_id not in out or t > out[r.user_id]:
            out[r.user_id] = t
    return out


def compute_rebuild(users, teams, solves, awards=None, adjustments=None) -> dict:
    """
    Compute the authoritative ``score`` and ``last_score_time`` for every user and team
    purely from the source-of-truth records (Solve + MitigationAward). Pure — mutates
    nothing; the caller applies the result.

    Returns:
      {
        "users": {user_id: {"score": int, "last_score_time": datetime|None}},
        "teams": {team_id: {"score": int, "last_score_time": datetime|None}},
      }

    Score = challenge points (Solve) + indicator points (MitigationAward).
    last_score_time = the most recent of the user's solve/award times; a team's is the
    latest across its members. Entities with no records rebuild to score 0 / time None.
    """
    cp = challenge_points_by_user(solves)
    ip = indicator_points_by_user(awards)
    uadj, tadj = _adjustments_by_target(adjustments)
    latest_solve = _latest_time_by_user(solves, "solved_at")
    latest_award = _latest_time_by_user(awards, "awarded_at")

    user_out = {}
    team_score = {}
    team_time = {}
    for u in users:
        uid = u.id
        score = cp.get(uid, 0) + ip.get(uid, 0) + uadj.get(uid, 0)
        times = [t for t in (latest_solve.get(uid), latest_award.get(uid)) if t is not None]
        last = max(times) if times else None
        user_out[uid] = {"score": score, "last_score_time": last}

        tid = getattr(u, "team_id", None)
        if tid is not None:
            team_score[tid] = team_score.get(tid, 0) + score
            if last is not None:
                prev = team_time.get(tid)
                if prev is None or last > prev:
                    team_time[tid] = last

    team_out = {}
    for t in teams:
        # add team-level manual adjustments on top of the members' sum
        team_out[t.id] = {"score": team_score.get(t.id, 0) + tadj.get(t.id, 0),
                          "last_score_time": team_time.get(t.id)}

    return {"users": user_out, "teams": team_out}
