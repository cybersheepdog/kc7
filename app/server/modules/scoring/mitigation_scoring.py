"""
Mitigation (indicator) submission scoring with optional precision controls (#23).

By default indicator scoring only ever *adds* points for correct new indicators, which
invites spraying the box. This pure helper computes the award and an optional penalty for
wrong new indicators, so a facilitator can add friction when they want (both knobs default
to 0 = no penalty). Pure → unit-testable.
"""


def score_submission(correct_count, wrong_count, points_per_correct, wrong_penalty=0):
    """
    Returns {"earned", "penalty", "net"} for one submission.
      earned  = correct_count * points_per_correct
      penalty = wrong_count * wrong_penalty   (0 by default → no penalty)
      net     = earned - penalty              (may be negative; the caller decides)
    All inputs are coerced to non-negative ints.
    """
    correct_count = max(0, int(correct_count or 0))
    wrong_count = max(0, int(wrong_count or 0))
    points_per_correct = max(0, int(points_per_correct or 0))
    wrong_penalty = max(0, int(wrong_penalty or 0))

    earned = correct_count * points_per_correct
    penalty = wrong_count * wrong_penalty
    return {"earned": earned, "penalty": penalty, "net": earned - penalty}
