"""
GUI-managed game settings (feature flags).

The opt-in feature flags in config.py can only be changed by editing the file and
restarting — and worse, they live in ``ProductionConfig`` while the app loads
``DevelopmentConfig`` by default, so an edit in the wrong class silently does nothing.

This module lets an admin toggle them from ``/admin/settings``. Overrides are stored in
the ``app_settings`` table, loaded into ``current_app.config`` at startup, and written
live on save — so existing ``current_app.config.get(...)`` reads and ``{% if config.X %}``
nav gates pick them up with **no restart** and regardless of which config class loaded.

Secrets (e.g. the KQL viewer principal's client secret) are deliberately NOT exposed here.

The ``Flag`` spec list drives the form, the type coercion, and the persistence; ``coerce``
is pure and unit-tested.
"""

from dataclasses import dataclass, field


@dataclass
class Flag:
    name: str
    label: str
    group: str
    type: str                 # "bool" | "int" | "choice"
    default: object
    help: str = ""
    choices: tuple = ()
    minv: int = None
    maxv: int = None
    note: str = ""            # extra caveat shown in the UI


FLAGS = [
    # --- Scoring ---
    Flag("DYNAMIC_SCORING_ENABLED", "Dynamic / first-blood scoring", "Scoring", "bool", False,
         "Challenge value decays as more teams solve it; the first solver earns a bonus."),
    Flag("DYNAMIC_SCORING_MINIMUM", "Dynamic scoring floor", "Scoring", "int", 50,
         "Lowest value a challenge decays toward.", minv=0, maxv=100000),
    Flag("DYNAMIC_SCORING_DECAY", "Dynamic scoring decay", "Scoring", "int", 20,
         "Solves after which the floor is reached.", minv=1, maxv=100000),
    Flag("FIRST_BLOOD_BONUS_PCT", "First-blood bonus %", "Scoring", "int", 0,
         "Percent bonus for the first solver.", minv=0, maxv=500),
    Flag("MITIGATION_WRONG_PENALTY", "Wrong-indicator penalty", "Scoring", "int", 0,
         "Points deducted per wrong indicator (0 = off).", minv=0, maxv=100000),
    Flag("MITIGATION_RATE_LIMIT_SECONDS", "Indicator submit throttle (s)", "Scoring", "int", 0,
         "Minimum seconds between a player's indicator submissions.", minv=0, maxv=3600),
    Flag("MITIGATION_DECOY_PENALTY", "Decoy extra penalty", "Scoring", "int", 0,
         "Extra points deducted for flagging a known-benign decoy.", minv=0, maxv=100000),

    # --- Realism ---
    Flag("CAMPAIGN_MODE_ENABLED", "Campaign / kill-chain mode", "Realism", "bool", False,
         "Thread an actor's post-compromise stages through one pinned host + C2."),
    Flag("INFRA_REUSE_ENABLED", "Actor-consistent infrastructure", "Realism", "bool", False,
         "Draw each actor's IPs from stable owned ranges for attribution."),
    Flag("INFRA_REUSE_PREFIX_COUNT", "Infra ranges per actor", "Realism", "int", 3,
         "How many /16 ranges each actor reuses.", minv=1, maxv=16),
    Flag("TECHNIQUE_ALERTS_ENABLED", "Per-technique EDR alerts", "Realism", "bool", False,
         "Each advanced technique can trip a SecurityAlert with realistic fidelity."),

    # --- Live UX ---
    Flag("LIVE_SCORE_SSE_ENABLED", "Live scoreboard push (SSE)", "Live UX", "bool", False,
         "Push leaderboard updates over SSE; falls back to polling.",
         note="Needs a threaded / multi-worker server."),
    Flag("LEADERBOARD_CACHE_SECONDS", "Leaderboard cache (s)", "Live UX", "int", 2,
         "Seconds to cache the computed leaderboard (0 = off).", minv=0, maxv=60),
    Flag("EVENT_TICKER_REVEAL", "Event ticker reveal level", "Live UX", "choice", "standings",
         "What the live event ticker shows.",
         choices=("off", "standings", "category", "full"),
         note="'standings' is spoiler-safe; 'category'/'full' reveal which TTPs are in play."),
    Flag("EVENT_TICKER_FIRSTBLOOD_AFTER_N", "First-blood name gate", "Live UX", "int", 0,
         "Withhold a first-blood challenge/category name until N teams have solved it.",
         minv=0, maxv=1000),

    # --- Tools / ADX ---
    Flag("ADX_DEBUG_MODE", "ADX debug mode (don't upload)", "Tools & ADX", "bool", False,
         "Print generated data instead of uploading to Azure Data Explorer."),
    Flag("EMBEDDED_KQL_ENABLED", "In-app KQL console", "Tools & ADX", "bool", False,
         "Read-only KQL query console for players (and the facilitator Query Feed).",
         note="Configure a viewer-only AAD principal (KQL_VIEWER_CLIENT_ID/SECRET) before real use."),
    Flag("EMBEDDED_KQL_MAX_ROWS", "KQL row cap", "Tools & ADX", "int", 5000,
         "Max rows returned per console query.", minv=1, maxv=100000),
    Flag("EMBEDDED_KQL_TIMEOUT_SECONDS", "KQL query timeout (s)", "Tools & ADX", "int", 45,
         "Per-query server timeout.", minv=1, maxv=600),
    Flag("EMBEDDED_KQL_RATE_LIMIT_SECONDS", "KQL submit throttle (s)", "Tools & ADX", "int", 2,
         "Minimum seconds between a player's queries.", minv=0, maxv=3600),

    # --- Safety ---
    Flag("ALLOW_REAL_INDICATORS", "Allow real indicators", "Safety", "bool", False,
         "Don't defang indicators. Only with confirmed-inert IOCs."),
    Flag("ALLOW_REAL_C2_INFRASTRUCTURE", "Allow real C2 infrastructure", "Safety", "bool", False,
         "Permit real C2 infrastructure. Keep off unless sinkholed/synthetic."),

    # --- Scheduler ---
    Flag("GAME_SCHEDULER_ENABLED", "Background scheduler", "Scheduler", "bool", False,
         "Auto start/stop the game at scheduled times.",
         note="Takes effect on the next app restart (the scheduler thread starts at boot)."),
    Flag("GAME_SCHEDULER_INTERVAL_SECONDS", "Scheduler interval (s)", "Scheduler", "int", 30,
         "How often the scheduler checks for due actions.", minv=5, maxv=3600),
]

FLAGS_BY_NAME = {f.name: f for f in FLAGS}


def coerce(flag: "Flag", raw):
    """PURE. Convert a raw form/DB value to the flag's typed value, clamped/validated."""
    if flag.type == "bool":
        if isinstance(raw, bool):
            return raw
        return str(raw).strip().lower() in ("1", "true", "on", "yes")
    if flag.type == "int":
        try:
            v = int(str(raw).strip())
        except (TypeError, ValueError):
            return flag.default
        if flag.minv is not None:
            v = max(flag.minv, v)
        if flag.maxv is not None:
            v = min(flag.maxv, v)
        return v
    if flag.type == "choice":
        s = str(raw).strip().lower()
        return s if s in flag.choices else flag.default
    return str(raw)


def load_overrides_into_config(app) -> None:
    """Startup: apply any stored overrides onto app.config (best-effort)."""
    try:
        from app.server.models import AppSetting
        for row in AppSetting.query.all():
            f = FLAGS_BY_NAME.get(row.key)
            if f is not None:
                app.config[row.key] = coerce(f, row.value)
    except Exception as e:
        print("settings overrides not loaded:", e)


def current_values() -> dict:
    """Effective value per flag (config override if set, else the spec default)."""
    from flask import current_app
    return {f.name: current_app.config.get(f.name, f.default) for f in FLAGS}


def apply_from_form(form) -> list:
    """
    Persist + live-apply submitted settings. Returns the list of changed flag names.
    Checkboxes (bool) are present only when checked, so absence == False.
    """
    from flask import current_app
    from app.server.models import db, AppSetting
    changed = []
    for f in FLAGS:
        if f.type == "bool":
            raw = (f.name in form)
        else:
            if f.name not in form:
                continue
            raw = form.get(f.name)
        val = coerce(f, raw)
        sval = str(val)
        row = AppSetting.query.filter_by(key=f.name).first()
        if row is None:
            db.session.add(AppSetting(key=f.name, value=sval))
        else:
            row.set_value(sval)
        current_app.config[f.name] = val
        changed.append(f.name)
    db.session.commit()
    return changed
