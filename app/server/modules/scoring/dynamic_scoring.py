"""
Optional dynamic / first-blood scoring (CTFd-style).

Two pure helpers, off by default (gated by config). They give an alternative to the
flat per-challenge value:

  - dynamic_value():  a challenge is worth more while few teams have solved it and
    decays toward a floor as more teams solve it — rewarding rare/hard solves.
  - first_blood_bonus():  an extra reward for the first team to solve a challenge.

Pure functions (stdlib only), so they are trivially unit-testable and reusable.
"""


def dynamic_value(initial: int, prior_solves: int, minimum: int = 50, decay: int = 20) -> int:
    """
    CTFd-style quadratic decay.

      value(s) = ((minimum - initial) / decay^2) * s^2 + initial

    where ``s`` = number of teams/users who have ALREADY solved the challenge
    (``prior_solves``). At s=0 the value is ``initial``; it decreases as more solve it
    and reaches ``minimum`` at s=``decay``, clamped to ``minimum`` beyond that.

    Robust to odd inputs: a non-positive ``decay`` or ``minimum >= initial`` disables
    decay (returns ``initial``).
    """
    initial = int(initial)
    minimum = int(minimum)
    prior_solves = max(0, int(prior_solves))
    decay = int(decay)

    if decay <= 0 or minimum >= initial:
        return initial

    value = ((minimum - initial) / float(decay ** 2)) * (prior_solves ** 2) + initial
    value = int(round(value))
    # clamp into [minimum, initial]
    return max(minimum, min(initial, value))


def first_blood_bonus(base_points: int, bonus_pct: float) -> int:
    """Extra points for the first solver: ``base_points * bonus_pct/100`` (rounded)."""
    try:
        pct = float(bonus_pct)
    except (TypeError, ValueError):
        return 0
    if pct <= 0:
        return 0
    return int(round(int(base_points) * (pct / 100.0)))


def award_for_solve(initial: int, prior_solves: int, minimum: int = 50, decay: int = 20,
                    first_blood_pct: float = 0) -> dict:
    """
    Convenience: compute the points a solver earns under dynamic scoring.
    Returns {base, first_blood, total, is_first_blood}.
    """
    base = dynamic_value(initial, prior_solves, minimum=minimum, decay=decay)
    is_fb = prior_solves == 0
    fb = first_blood_bonus(base, first_blood_pct) if is_fb else 0
    return {"base": base, "first_blood": fb, "total": base + fb, "is_first_blood": is_fb}
