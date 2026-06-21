"""
Facilitator analytics (#34).

Aggregates the Solve / AnswerAttempt logs into the metrics a facilitator wants while
running an event — beyond the live feed and the team standings:

  - per-challenge **solve rate** (distinct solvers / players) and attempts-per-solver,
  - **by-category** rollup,
  - **difficulty calibration**: challenges nobody solved, plus too-hard / too-easy bands,
  - **engagement**: how many players are active vs. idle, and how many have solved anything.

``compute_analytics`` is pure (plain lists in, a metrics dict out) so it is fully
unit-testable; the admin route gathers the live rows and adds ADX ingestion health.
"""

# Solve-rate bands (% of players who solved) used for difficulty calibration.
_TOO_HARD_PCT = 15
_TOO_EASY_PCT = 85


def _pct(n, d):
    return round(n / d * 100, 1) if d else 0.0


def compute_analytics(challenges, solves, attempts, total_players):
    """
    challenges    : [{id, name, category, value}]
    solves        : [{challenge_id, user_id}]   (one row per distinct solve)
    attempts      : [{challenge_id, user_id, correct}]
    total_players : int — registered non-admin players (denominator for solve rate)

    Returns a metrics dict (see keys below).
    """
    challenges = challenges or []
    solves = solves or []
    attempts = attempts or []
    total_players = int(total_players or 0)

    # index solves/attempts by challenge
    solvers_by_chal = {}      # cid -> set(user_id)
    for s in solves:
        solvers_by_chal.setdefault(s.get("challenge_id"), set()).add(s.get("user_id"))
    attempts_by_chal = {}     # cid -> count
    for a in attempts:
        attempts_by_chal[a.get("challenge_id")] = attempts_by_chal.get(a.get("challenge_id"), 0) + 1

    # --- per challenge ---
    per_challenge = []
    for ch in challenges:
        cid = ch.get("id")
        solvers = len(solvers_by_chal.get(cid, ()))
        atts = attempts_by_chal.get(cid, 0)
        per_challenge.append({
            "id": cid,
            "name": ch.get("name", "?"),
            "category": ch.get("category") or "General",
            "value": ch.get("value", 0) or 0,
            "solvers": solvers,
            "attempts": atts,
            "solve_rate": _pct(solvers, total_players),
            "attempts_per_solver": round(atts / solvers, 1) if solvers else None,
        })
    # hardest first (lowest solve rate), then most-attempted
    per_challenge.sort(key=lambda c: (c["solve_rate"], -c["attempts"]))

    # --- by category ---
    cat = {}
    for c in per_challenge:
        d = cat.setdefault(c["category"], {"category": c["category"], "challenges": 0,
                                           "solvers": 0, "attempts": 0, "rate_sum": 0.0})
        d["challenges"] += 1
        d["solvers"] += c["solvers"]
        d["attempts"] += c["attempts"]
        d["rate_sum"] += c["solve_rate"]
    by_category = []
    for d in cat.values():
        d["avg_solve_rate"] = round(d["rate_sum"] / d["challenges"], 1) if d["challenges"] else 0.0
        d.pop("rate_sum", None)
        by_category.append(d)
    by_category.sort(key=lambda d: d["avg_solve_rate"])

    # --- difficulty calibration ---
    unsolved = [c["name"] for c in per_challenge if c["solvers"] == 0]
    too_hard = [c["name"] for c in per_challenge if 0 < c["solve_rate"] < _TOO_HARD_PCT]
    too_easy = [c["name"] for c in per_challenge if c["solve_rate"] > _TOO_EASY_PCT]

    # --- engagement ---
    active_users = {a.get("user_id") for a in attempts}
    solver_users = {s.get("user_id") for s in solves}
    active = len(active_users)
    solvers_n = len(solver_users)
    idle = max(0, total_players - active)

    return {
        "totals": {
            "players": total_players,
            "challenges": len(challenges),
            "solves": len(solves),
            "attempts": len(attempts),
        },
        "engagement": {
            "active": active,
            "idle": idle,
            "solvers": solvers_n,
            "active_pct": _pct(active, total_players),
            "solver_pct": _pct(solvers_n, total_players),
        },
        "per_challenge": per_challenge,
        "by_category": by_category,
        "calibration": {
            "unsolved": unsolved,
            "too_hard": too_hard,
            "too_easy": too_easy,
        },
    }
