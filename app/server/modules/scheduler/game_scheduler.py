"""
Scheduled game start/stop (#29).

A lightweight background scheduler that can auto-launch data generation and/or auto-stop
scoring at admin-set times, for unattended events. It is **opt-in** — the daemon thread
only starts when ``GAME_SCHEDULER_ENABLED`` is set (default off, so by default nothing
runs and behavior is unchanged) — and **data-gated**: it acts only on the legs an admin
has explicitly enabled in the ``ScheduledGame`` row, and each leg fires once
(``*_fired_at``).

``due_actions`` is pure (it inspects a schedule object + the current time + whether a game
is already running) so the firing logic is unit-testable without threads or a database.
"""

import threading
import time as _time
from datetime import datetime

_started = False


def due_actions(sched, now, game_running):
    """
    Return the list of actions ("start"/"stop") that are due to fire.
      - "start": start_enabled, start_at reached, not already fired, AND no game running.
      - "stop":  stop_enabled, stop_at reached, not already fired.
    Returns [] for a missing schedule.
    """
    actions = []
    if sched is None:
        return actions
    if (getattr(sched, "start_enabled", False) and getattr(sched, "start_at", None)
            and getattr(sched, "start_fired_at", None) is None
            and now >= sched.start_at and not game_running):
        actions.append("start")
    if (getattr(sched, "stop_enabled", False) and getattr(sched, "stop_at", None)
            and getattr(sched, "stop_fired_at", None) is None
            and now >= sched.stop_at):
        actions.append("stop")
    return actions


def _tick(app):
    """One scheduler iteration, inside an app context. Fully guarded."""
    from app.server.models import db, ScheduledGame, GameSession
    with app.app_context():
        try:
            sched = db.session.get(ScheduledGame, 1)
            if not sched:
                return
            try:
                from app.server.game_functions import GAME_PROGRESS
                running = bool(GAME_PROGRESS.get("running"))
            except Exception:
                GAME_PROGRESS = {}
                running = False

            actions = due_actions(sched, datetime.now(), running)
            for action in actions:
                if action == "start":
                    from app.server.views import _run_game_in_background
                    threading.Thread(target=_run_game_in_background, args=(app,), daemon=True).start()
                    sched.start_fired_at = datetime.now()
                    print("game scheduler: auto-started data generation")
                elif action == "stop":
                    try:
                        GAME_PROGRESS["cancel_requested"] = True
                    except Exception:
                        pass
                    gs = db.session.get(GameSession, 1)
                    if gs:
                        gs.state = False
                        gs.uses_timer = True          # stop scoring at the scheduled time
                        gs.end_time = datetime.now()
                    sched.stop_fired_at = datetime.now()
                    print("game scheduler: auto-stopped game (scoring closed)")
            if actions:
                db.session.commit()
        except Exception as e:
            print("game scheduler tick error:", e)
            try:
                db.session.rollback()
            except Exception:
                pass


def start_scheduler(app, interval=30):
    """Start the scheduler daemon thread once. No-op if already started."""
    global _started
    if _started:
        return
    _started = True

    def _loop():
        while True:
            _time.sleep(max(5, int(interval)))
            _tick(app)

    threading.Thread(target=_loop, daemon=True).start()
    print("game scheduler started (interval %ss)" % interval)
