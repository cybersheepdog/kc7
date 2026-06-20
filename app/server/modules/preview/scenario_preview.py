"""
Scenario preview — a dry-run pre-flight for authors.

Before committing to a full (and slow) game generation, this reports — *without
executing the pipeline* — what a scenario will produce:

  - per actor: the ATT&CK techniques that will fire (id / name / phase), the ADX tables
    they populate, the number of active days the actor runs (its activity window ∩ its
    working days ∩ the company window), and an APPROXIMATE event-volume ballpark.
  - scenario-wide: the union of tables that will contain data, and totals.

It reads the YAML configs and uses the attack registry as the source of truth for which
tables each technique writes. Dependency-free (only PyYAML + the registry), so it is
fast, safe to import anywhere, and unit-testable. It pairs with the config validator
as a "validate + preview" pre-flight.

The exact tables and active-day counts are precise; the event *volumes* are deliberately
coarse (generators randomize counts) and labelled approximate.
"""

import glob
import os
from datetime import date, timedelta

from app.server.modules.attacks.attack_registry import get_spec


# Approximate events generated per active day, per attack. Coarse by design — the
# generators randomize these — used only to flag "trickle vs flood", never as exact counts.
_APPROX_DAILY_EVENTS = {
    "email:phishing": 5,
    "email:malware_delivery": 5,
    "delivery:supply_chain": 4,
    "watering_hole:malware_delivery": 15,
    "watering_hole:phishing": 15,
    "identity:password_spray": 100,
    "identity:kerberoasting": 7,
    "recon:browsing": 5,
    "discovery:automated_recon": 9,
    "execution:psexec_lateral": 6,
    "evasion:log_clearing": 5,
    "persistence:scheduled_task": 1,
    "persistence:registry_run": 1,
    "cloud:session_hijacking": 3,
    "cloud:token_theft": 3,
    "cloud:exfiltration_via_storage": 15,
}

_DEFAULT_WORKING_DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
_WEEKDAY_NAMES = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

# Matches game_functions: ~10% chance an actor takes a day off
_SKIP_RATE = 0.10


def _load_yaml(path):
    import yaml
    with open(path, "r") as fh:
        return yaml.safe_load(fh)


def _parse_date(value):
    try:
        return date.fromisoformat(str(value))
    except (ValueError, TypeError):
        return None


def _count_active_days(start: date, end: date, working_days) -> int:
    """Number of days in [start, end] whose weekday is in working_days."""
    if not start or not end or start > end:
        return 0
    working = set(working_days or _DEFAULT_WORKING_DAYS)
    days = 0
    d = start
    while d <= end:
        if _WEEKDAY_NAMES[d.weekday()] in working:
            days += 1
        d += timedelta(days=1)
    return days


def preview_scenario(actor_dir: str = "app/game_configs/actors",
                     company_path: str = "app/game_configs/company.yaml",
                     malware_dir: str = "app/game_configs/malware") -> dict:
    """Build a structured preview of what the scenario will generate."""
    company = {}
    if os.path.exists(company_path):
        company = _load_yaml(company_path) or {}

    company_start = _parse_date(company.get("activity_start_date"))
    company_end = _parse_date(company.get("activity_end_date"))
    employees = company.get("count_employees")

    actors = []
    scenario_tables = []  # ordered union

    for path in sorted(glob.glob(os.path.join(actor_dir, "*.yaml"))):
        cfg = _load_yaml(path) or {}
        if not isinstance(cfg, dict):
            continue

        # actor window clipped to the company window
        a_start = _parse_date(cfg.get("activity_start_date")) or company_start
        a_end = _parse_date(cfg.get("activity_end_date")) or company_end
        eff_start = max(x for x in [a_start, company_start] if x) if (a_start and company_start) else (a_start or company_start)
        eff_end = min(x for x in [a_end, company_end] if x) if (a_end and company_end) else (a_end or company_end)
        working_days = cfg.get("working_days") or _DEFAULT_WORKING_DAYS
        active_days = _count_active_days(eff_start, eff_end, working_days)
        expected_active_days = round(active_days * (1 - _SKIP_RATE))

        techniques = []
        actor_tables = []
        unknown_attacks = []
        approx_per_day = 0
        for attack in cfg.get("attacks", []) or []:
            spec = get_spec(attack)
            if not spec:
                unknown_attacks.append(attack)
                continue
            techniques.append({
                "attack": attack,
                "attack_id": spec.attack_id,
                "attack_name": spec.attack_name,
                "phase": spec.phase,
                "tables": list(spec.tables),
            })
            for t in spec.tables:
                if t not in actor_tables:
                    actor_tables.append(t)
                if t not in scenario_tables:
                    scenario_tables.append(t)
            approx_per_day += _APPROX_DAILY_EVENTS.get(attack, 5)

        actors.append({
            "name": cfg.get("name", os.path.basename(path)),
            "window": {
                "start": eff_start.isoformat() if eff_start else None,
                "end": eff_end.isoformat() if eff_end else None,
            },
            "working_days": list(working_days),
            "active_days": active_days,
            "expected_active_days": expected_active_days,
            "techniques": techniques,
            "tables": actor_tables,
            "unknown_attacks": unknown_attacks,
            "approx_events_per_active_day": approx_per_day,
            "approx_total_events": approx_per_day * expected_active_days,
        })

    total_days = 0
    if company_start and company_end and company_end >= company_start:
        total_days = (company_end - company_start).days + 1

    return {
        "company": {
            "name": company.get("name"),
            "domain": company.get("domain"),
            "employees": employees,
            "start": company_start.isoformat() if company_start else None,
            "end": company_end.isoformat() if company_end else None,
            "total_days": total_days,
        },
        "actor_count": len(actors),
        "actors": actors,
        "scenario_tables": scenario_tables,
        "approx_total_events": sum(a["approx_total_events"] for a in actors),
        "disclaimer": ("Tables and active-day counts are exact; event volumes are "
                       "approximate (generators randomize counts) and exclude the Default "
                       "actor's background noise."),
    }


def format_preview_text(preview: dict) -> str:
    """Render a preview dict as a readable plain-text report."""
    c = preview.get("company", {})
    lines = []
    lines.append("=" * 70)
    lines.append("SCENARIO DRY-RUN PREVIEW")
    lines.append("=" * 70)
    lines.append(f"Company : {c.get('name')} ({c.get('domain')})")
    lines.append(f"Window  : {c.get('start')} to {c.get('end')}  ({c.get('total_days')} days)")
    lines.append(f"Employees: {c.get('employees')}   Malicious actors: {preview.get('actor_count')}")
    lines.append("")
    lines.append("Tables that will contain data across the scenario:")
    lines.append("  " + (", ".join(preview.get("scenario_tables", [])) or "(none)"))
    lines.append("")

    for a in preview.get("actors", []):
        lines.append("-" * 70)
        lines.append(f"ACTOR: {a['name']}")
        lines.append(f"  Active: ~{a['expected_active_days']} of {a['active_days']} working days "
                     f"({a['window']['start']} → {a['window']['end']})")
        lines.append(f"  Techniques ({len(a['techniques'])}):")
        for t in a["techniques"]:
            lines.append(f"    - [{t['attack_id']}] {t['attack_name']}  ·  {t['phase']}")
            lines.append(f"        {t['attack']} → {', '.join(t['tables'])}")
        if a["unknown_attacks"]:
            lines.append(f"  ⚠ Unknown attacks (not in registry): {', '.join(a['unknown_attacks'])}")
        lines.append(f"  Tables: {', '.join(a['tables']) or '(none)'}")
        lines.append(f"  Approx volume: ~{a['approx_events_per_active_day']}/active day "
                     f"≈ ~{a['approx_total_events']:,} events total")
        lines.append("")

    lines.append("-" * 70)
    lines.append(f"Approx malicious events across scenario: ~{preview.get('approx_total_events', 0):,}")
    lines.append(f"Note: {preview.get('disclaimer')}")
    return "\n".join(lines)


if __name__ == "__main__":
    # CLI pre-flight: python -m app.server.modules.preview.scenario_preview
    print(format_preview_text(preview_scenario()))
