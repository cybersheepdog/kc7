"""
Scenario template library (#35, the safe half).

Package a whole scenario — the company profile, the actor and malware configs, the realism
content pack, and the challenge set — into a single named, portable bundle that can be
saved, listed, downloaded/shared, and re-loaded later. This gives an operator a library of
ready-to-run scenarios to clone from, without touching the running game's single-company /
single-session assumptions (true simultaneous multi-tenancy is a separate, larger effort).

``build_bundle`` / ``bundle_summary`` are pure (plain data in, plain data out) so they're
unit-testable; the rest reads/writes the config files + the challenge table. Loading a
template writes each config through the existing validator (via ``scenario_admin``), so an
invalid bundle is rejected per-file rather than corrupting the scenario.
"""

import json
import os
import re
import glob

TEMPLATE_DIR = "app/game_configs/scenario_templates"
_COMPANY_PATH = "app/game_configs/company.yaml"
_CONTENT_PACK_PATH = "app/game_configs/content_packs/realism.yaml"


# --- pure ---------------------------------------------------------------------
def build_bundle(name, company, actors, malware, content_pack, challenges, created_at=None):
    """
    company       : dict (company.yaml) | None
    actors        : {filename: dict}
    malware       : {filename: dict}
    content_pack  : dict | None
    challenges    : [{name, category, description, answer, value, round}]
    Returns a JSON-serializable bundle dict.
    """
    return {
        "name": name,
        "created_at": created_at,
        "company": company or None,
        "actors": dict(actors or {}),
        "malware": dict(malware or {}),
        "content_pack": content_pack or None,
        "challenges": list(challenges or []),
    }


def bundle_summary(bundle):
    """Short counts for listing a template."""
    bundle = bundle or {}
    return {
        "name": bundle.get("name"),
        "created_at": bundle.get("created_at"),
        "company": (bundle.get("company") or {}).get("name") if bundle.get("company") else None,
        "actors": len(bundle.get("actors") or {}),
        "malware": len(bundle.get("malware") or {}),
        "challenges": len(bundle.get("challenges") or []),
        "has_content_pack": bool(bundle.get("content_pack")),
    }


def safe_template_name(name):
    leaf = os.path.basename(str(name or "").strip().replace("\\", "/"))
    leaf = re.sub(r"[^A-Za-z0-9_.-]", "_", leaf).lstrip(".")
    if leaf.lower().endswith(".json"):
        leaf = leaf[:-5]
    return leaf or "template"


def _template_path(name):
    base = os.path.abspath(TEMPLATE_DIR)
    full = os.path.abspath(os.path.join(base, safe_template_name(name) + ".json"))
    if os.path.dirname(full) != base:
        raise ValueError("invalid template name")
    return full


# --- impure (config files + DB) ----------------------------------------------
def _load_yaml(path):
    import yaml
    with open(path, "r") as fh:
        return yaml.safe_load(fh)


def capture_current(name):
    """Snapshot the live scenario configs + challenges into a saved template. Returns the summary."""
    from datetime import datetime
    from app.server.models import Challenge, GameRound

    company = None
    if os.path.exists(_COMPANY_PATH):
        try:
            company = _load_yaml(_COMPANY_PATH)
        except Exception:
            company = None

    actors = {}
    for p in sorted(glob.glob("app/game_configs/actors/*.yaml")):
        try:
            actors[os.path.basename(p)] = _load_yaml(p)
        except Exception:
            pass
    malware = {}
    for p in sorted(glob.glob("app/game_configs/malware/*.yaml")):
        try:
            malware[os.path.basename(p)] = _load_yaml(p)
        except Exception:
            pass

    content_pack = None
    if os.path.exists(_CONTENT_PACK_PATH):
        try:
            content_pack = _load_yaml(_CONTENT_PACK_PATH)
        except Exception:
            content_pack = None

    round_names = {r.id: r.name for r in GameRound.query.all()}
    challenges = [{
        "name": c.name, "category": c.category, "description": c.description,
        "answer": c.answer, "value": c.value,
        "round": round_names.get(c.round_id),
    } for c in Challenge.query.all()]

    bundle = build_bundle(name, company, actors, malware, content_pack, challenges,
                          created_at=datetime.now().strftime("%Y-%m-%d %H:%M"))
    os.makedirs(TEMPLATE_DIR, exist_ok=True)
    with open(_template_path(name), "w") as fh:
        json.dump(bundle, fh, indent=2)
    return bundle_summary(bundle)


def list_templates():
    out = []
    for p in sorted(glob.glob(os.path.join(TEMPLATE_DIR, "*.json"))):
        try:
            with open(p) as fh:
                out.append(bundle_summary(json.load(fh)))
        except Exception:
            pass
    return out


def read_template(name):
    with open(_template_path(name)) as fh:
        return json.load(fh)


def delete_template(name):
    p = _template_path(name)
    if os.path.exists(p):
        os.remove(p)
        return True
    return False


def save_bundle(bundle):
    """Persist a bundle dict (e.g. an uploaded one). Returns the saved name."""
    name = safe_template_name(bundle.get("name") or "imported")
    bundle["name"] = name
    os.makedirs(TEMPLATE_DIR, exist_ok=True)
    with open(_template_path(name), "w") as fh:
        json.dump(bundle, fh, indent=2)
    return name


def apply_template(name, create_challenges=True):
    """
    Write a template's configs to disk (validated) and optionally create its challenges.
    Returns {ok, errors, written, challenges_added}. Best-effort: valid items are applied,
    invalid ones are reported.
    """
    import yaml
    from app.server.modules.scenario_admin import scenario_admin as sa

    bundle = read_template(name)
    errors, written = [], []

    # company.yaml — written directly (confined to game_configs)
    if bundle.get("company"):
        try:
            with open(_COMPANY_PATH, "w") as fh:
                yaml.safe_dump(bundle["company"], fh, sort_keys=False)
            written.append("company.yaml")
        except Exception as e:
            errors.append("company.yaml: %s" % e)

    # actors + malware + content pack — through the validator
    for fname, cfg in (bundle.get("actors") or {}).items():
        errs = sa.save_file("actor", fname, yaml.safe_dump(cfg, sort_keys=False))
        errors += ["actor %s: %s" % (fname, e) for e in (errs or [])]
        if not errs:
            written.append("actor/%s" % fname)
    for fname, cfg in (bundle.get("malware") or {}).items():
        errs = sa.save_file("malware", fname, yaml.safe_dump(cfg, sort_keys=False))
        errors += ["malware %s: %s" % (fname, e) for e in (errs or [])]
        if not errs:
            written.append("malware/%s" % fname)
    if bundle.get("content_pack"):
        errs = sa.save_file("content_pack", "realism.yaml",
                            yaml.safe_dump(bundle["content_pack"], sort_keys=False))
        errors += ["content_pack: %s" % e for e in (errs or [])]
        if not errs:
            written.append("content_packs/realism.yaml")

    # challenges — create non-duplicates (by name)
    added = 0
    if create_challenges:
        from app.server.models import db, Challenge, GameRound
        existing = {c.name for c in Challenge.query.all()}
        round_by_name = {r.name: r.id for r in GameRound.query.all()}
        for ch in bundle.get("challenges") or []:
            if ch.get("name") in existing:
                continue
            db.session.add(Challenge(
                name=ch.get("name"), category=ch.get("category") or "General",
                description=ch.get("description") or "", answer=ch.get("answer") or "",
                value=ch.get("value") or 100,
                round_id=round_by_name.get(ch.get("round")),
            ))
            added += 1
        db.session.commit()

    return {"ok": not errors, "errors": errors, "written": written, "challenges_added": added}
