"""
KQL query-log analysis for the facilitator live-query view (#52a).

Pure functions over a list of query-log dicts — no DB — so they're unit-testable. They
surface the signals a facilitator cares about during an event:

  - per-player volume and error rate (a high error rate with real volume = a stuck player),
  - "shared" queries: the same query text run by two or more different players (a soft
    answer-sharing signal, complementing the existing anti-cheat surfacing in #26).
"""


def _norm(q: str) -> str:
    return " ".join((q or "").strip().lower().split())


def summarize_queries(logs, stuck_min_total: int = 5, stuck_error_pct: int = 50) -> dict:
    """
    PURE. ``logs`` is a list of dicts with at least ``username``, ``query``, ``success``.
    Returns::

        {
          "per_user": [{username, total, errors, error_rate, stuck}...],   # busiest first
          "shared":   [{query, users:[...], count}...],                    # most-shared first
          "total": int,
        }
    """
    per = {}
    by_query = {}
    for entry in (logs or []):
        u = entry.get("username") or "?"
        slot = per.setdefault(u, {"total": 0, "errors": 0})
        slot["total"] += 1
        if not entry.get("success"):
            slot["errors"] += 1
        q = _norm(entry.get("query"))
        if q:
            by_query.setdefault(q, set()).add(u)

    per_user = []
    for u, s in per.items():
        rate = int(round(100 * s["errors"] / s["total"])) if s["total"] else 0
        per_user.append({
            "username": u, "total": s["total"], "errors": s["errors"],
            "error_rate": rate,
            "stuck": s["total"] >= stuck_min_total and rate >= stuck_error_pct,
        })
    per_user.sort(key=lambda x: (-x["total"], x["username"]))

    shared = [{"query": q, "users": sorted(us), "count": len(us)}
              for q, us in by_query.items() if len(us) >= 2]
    shared.sort(key=lambda x: (-x["count"], x["query"]))

    return {"per_user": per_user, "shared": shared[:25], "total": len(logs or [])}
