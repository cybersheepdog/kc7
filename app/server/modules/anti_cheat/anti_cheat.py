"""
Anti-cheat surfacing (#26).

Every challenge submission is logged in ``AnswerAttempt``. This module looks over a
window of recent attempts and surfaces *suspicious patterns* an instructor would want to
eyeball on the live feed — it never accuses or penalizes automatically, it just flags
things worth a look.

Three heuristics, all derived purely from the attempt log (who / what / when / correct):

  1. **Shared answer across teams** — the same (normalized) answer string submitted by
     two or more *different teams* within a short window. Answer-sharing's clearest tell.
  2. **Fast copy** — a team submits the correct answer to a challenge within seconds of a
     *different* team's correct solve of the same challenge (too fast to have worked it
     out independently).
  3. **Burst solving** — a single user racks up many correct solves within a tiny window
     (faster than a human could read the questions — automation or a fed answer key).

``analyze_attempts`` is pure: it takes a list of plain attempt dicts and returns a list
of flag dicts, so it is fully unit-testable. The ``normalize`` callable lets the caller
pass the scoring normalizer (#21) so defang/format variants of the same answer match.
"""


def _norm(normalize, s):
    if normalize is None:
        return (s or "").strip().lower()
    try:
        return normalize(s)
    except Exception:
        return (s or "").strip().lower()


def _secs(a, b):
    """Absolute seconds between two datetimes (a, b)."""
    return abs((a - b).total_seconds())


def analyze_attempts(
    attempts,
    normalize=None,
    *,
    shared_window_s=180,
    fast_copy_s=60,
    burst_count=4,
    burst_window_s=30,
    min_answer_len=4,
    max_flags=50,
):
    """
    attempts: iterable of dicts with keys:
        id, user, team, challenge_id, challenge, submitted, correct (bool), at (datetime)
    Returns: list of flag dicts {type, severity, title, detail, challenge, teams, at}
             sorted by severity (high first) then most-recent.
    """
    items = [a for a in (attempts or []) if a.get("at") is not None]
    flags = []

    # --- 1. Shared answer string across teams -------------------------------------
    # group by (challenge_id, normalized answer)
    groups = {}
    for a in items:
        norm = _norm(normalize, a.get("submitted"))
        if len(norm) < min_answer_len:
            continue
        groups.setdefault((a.get("challenge_id"), norm), []).append(a)

    for (cid, norm), grp in groups.items():
        teams = {a.get("team") for a in grp}
        if len(teams) < 2:
            continue
        # is there a cross-team pair within the window?
        grp_sorted = sorted(grp, key=lambda a: a["at"])
        hit = None
        for i in range(len(grp_sorted)):
            for j in range(i + 1, len(grp_sorted)):
                if grp_sorted[i].get("team") != grp_sorted[j].get("team") and \
                        _secs(grp_sorted[i]["at"], grp_sorted[j]["at"]) <= shared_window_s:
                    hit = (grp_sorted[i], grp_sorted[j])
                    break
            if hit:
                break
        if not hit:
            continue
        any_correct = any(a.get("correct") for a in grp)
        involved = sorted(teams)
        latest = max(grp, key=lambda a: a["at"])
        flags.append({
            "type": "shared_answer",
            "severity": "high" if any_correct else "medium",
            "title": "Same answer from multiple teams",
            "detail": 'Teams %s submitted the same answer "%s" on "%s" within %ds.' % (
                ", ".join(involved), latest.get("submitted"), latest.get("challenge"),
                shared_window_s),
            "challenge": latest.get("challenge"),
            "teams": involved,
            "at": latest["at"],
        })

    # --- 2. Fast copy: correct soon after another team's correct ------------------
    by_chal = {}
    for a in items:
        if a.get("correct"):
            by_chal.setdefault(a.get("challenge_id"), []).append(a)
    for cid, corrects in by_chal.items():
        corrects.sort(key=lambda a: a["at"])
        for k in range(1, len(corrects)):
            cur = corrects[k]
            # earliest prior correct by a different team
            for p in range(k):
                prev = corrects[p]
                if prev.get("team") != cur.get("team"):
                    dt = _secs(cur["at"], prev["at"])
                    if dt <= fast_copy_s:
                        flags.append({
                            "type": "fast_copy",
                            "severity": "high",
                            "title": "Suspiciously fast solve",
                            "detail": '%s (%s) solved "%s" %ds after %s — possible copy.' % (
                                cur.get("user"), cur.get("team"), cur.get("challenge"),
                                int(dt), prev.get("team")),
                            "challenge": cur.get("challenge"),
                            "teams": sorted({cur.get("team"), prev.get("team")}),
                            "at": cur["at"],
                        })
                    break  # only compare to the first prior different-team solve

    # --- 3. Burst solving by a single user ---------------------------------------
    by_user = {}
    for a in items:
        if a.get("correct"):
            by_user.setdefault(a.get("user"), []).append(a)
    for user, corrects in by_user.items():
        corrects.sort(key=lambda a: a["at"])
        n = len(corrects)
        flagged_until = None  # avoid overlapping duplicate burst flags for same user
        for i in range(n):
            j = i + burst_count - 1
            if j < n and _secs(corrects[j]["at"], corrects[i]["at"]) <= burst_window_s:
                if flagged_until is not None and corrects[i]["at"] <= flagged_until:
                    continue
                window = corrects[i:j + 1]
                flagged_until = corrects[j]["at"]
                flags.append({
                    "type": "burst",
                    "severity": "high" if burst_count >= 5 else "medium",
                    "title": "Burst of rapid solves",
                    "detail": '%s (%s) got %d correct in %ds — faster than reading the questions.' % (
                        user, window[0].get("team"), len(window),
                        int(_secs(corrects[j]["at"], corrects[i]["at"]))),
                    "challenge": None,
                    "teams": [window[0].get("team")],
                    "at": corrects[j]["at"],
                })

    # sort: high severity first, then most recent
    sev_rank = {"high": 0, "medium": 1, "low": 2}
    flags.sort(key=lambda f: (sev_rank.get(f["severity"], 3), -f["at"].timestamp()))
    return flags[:max_flags]
