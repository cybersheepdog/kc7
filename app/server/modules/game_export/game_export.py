"""
Game-state export (#36).

Snapshots a finished (or in-progress) event into a portable record: final standings,
per-challenge solve stats, and the full solve log — so a facilitator can keep results
for the record book or reload them for review after a reset.

``build_export`` is pure (plain dicts/lists in, a JSON-serializable dict out) so it's
unit-testable; ``gather_export`` pulls the live rows from the DB. ``standings_csv``
renders the team + player standings as CSV for spreadsheet-friendly archiving.
"""

import io
import csv


def build_export(company, teams, players, challenges, solves, generated_at=None):
    """
    company    : {name, domain, activity_start_date, activity_end_date} | {}
    teams      : [{name, score}]
    players    : [{username, team, score}]
    challenges : [{id, name, category, value, round}]
    solves     : [{challenge_id, challenge, username, team, points, solved_at}]  (solved_at iso str)
    Returns a JSON-serializable export dict.
    """
    company = company or {}
    teams = list(teams or [])
    players = list(players or [])
    challenges = list(challenges or [])
    solves = list(solves or [])

    team_standings = [{"rank": i, "name": t.get("name"), "score": t.get("score") or 0}
                      for i, t in enumerate(sorted(teams, key=lambda t: -(t.get("score") or 0)), 1)]

    player_standings = sorted(players, key=lambda p: -(p.get("score") or 0))
    player_standings = [{"rank": i, "username": p.get("username"),
                         "team": p.get("team"), "score": p.get("score") or 0}
                        for i, p in enumerate(player_standings, 1)]

    # per-challenge solve stats
    solves_by_chal = {}
    for s in solves:
        solves_by_chal.setdefault(s.get("challenge_id"), []).append(s)
    challenge_stats = []
    for ch in challenges:
        rows = solves_by_chal.get(ch.get("id"), [])
        first = min((r.get("solved_at") for r in rows if r.get("solved_at")), default=None)
        challenge_stats.append({
            "name": ch.get("name"),
            "category": ch.get("category"),
            "value": ch.get("value") or 0,
            "round": ch.get("round"),
            "solves": len(rows),
            "first_solved_at": first,
        })

    return {
        "meta": {
            "generated_at": generated_at,
            "company": company,
            "totals": {
                "teams": len(teams),
                "players": len(players),
                "challenges": len(challenges),
                "solves": len(solves),
            },
        },
        "team_standings": team_standings,
        "player_standings": player_standings,
        "challenge_stats": challenge_stats,
        "solve_log": sorted(
            [{"solved_at": s.get("solved_at"), "challenge": s.get("challenge"),
              "username": s.get("username"), "team": s.get("team"),
              "points": s.get("points") or 0} for s in solves],
            key=lambda s: s.get("solved_at") or ""),
    }


def standings_csv(export):
    """Render the team and player standings of an export dict as CSV text."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["TEAM STANDINGS"])
    w.writerow(["rank", "team", "score"])
    for t in export.get("team_standings", []):
        w.writerow([t["rank"], t["name"], t["score"]])
    w.writerow([])
    w.writerow(["PLAYER STANDINGS"])
    w.writerow(["rank", "username", "team", "score"])
    for p in export.get("player_standings", []):
        w.writerow([p["rank"], p["username"], p["team"], p["score"]])
    return buf.getvalue()


def gather_export():
    """Assemble the export dict from the live DB (excludes the admin team, id=1)."""
    from datetime import datetime
    from app.server.models import Team, Users, Challenge, Solve, GameRound
    from app.server.modules.organization.Company import Company

    company = {}
    try:
        c = Company.query.first()
        if c:
            company = {"name": c.name, "domain": c.domain,
                       "activity_start_date": c.activity_start_date,
                       "activity_end_date": c.activity_end_date}
    except Exception:
        company = {}

    teams = [{"name": t.name, "score": t.score or 0}
             for t in Team.query.filter(Team.id != 1).all()]

    players = []
    player_team = {}
    for u in Users.query.filter(Users.team_id != 1).all():
        tname = u.team.name if u.team else "--"
        players.append({"username": u.username, "team": tname, "score": u.score or 0})
        player_team[u.id] = (u.username, tname)

    round_names = {r.id: r.name for r in GameRound.query.all()}
    challenges = [{"id": c.id, "name": c.name, "category": c.category, "value": c.value,
                   "round": round_names.get(c.round_id)}
                  for c in Challenge.query.all()]
    chal_names = {c["id"]: c["name"] for c in challenges}

    solves = []
    for s in Solve.query.all():
        if s.user_id not in player_team:
            continue  # skip admin/unknown
        uname, tname = player_team[s.user_id]
        solves.append({
            "challenge_id": s.challenge_id,
            "challenge": chal_names.get(s.challenge_id),
            "username": uname, "team": tname,
            "points": s.points_awarded or 0,
            "solved_at": s.solved_at.isoformat() if s.solved_at else None,
        })

    return build_export(company, teams, players, challenges, solves,
                        generated_at=datetime.now().isoformat(timespec="seconds"))
