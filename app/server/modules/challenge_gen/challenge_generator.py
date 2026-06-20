"""
Auto-generate challenge questions + answers from the scenario's ground truth (#11).

The engine knows the truth at generation time: each actor's malicious IPs, domains,
sender addresses, malware families/hashes, attribution, and the techniques it used. This
module turns those facts into ready-made `Challenge` rows so an instructor doesn't have
to hand-author them.

``build_challenges`` is pure — it takes plain fact dicts and returns challenge dicts —
so it is fully unit-testable. A thin caller gathers the live facts from the DB / configs.

Answers are deterministic strings; where several values are valid (e.g. any of the
actor's malicious IPs), they're joined with `;` (the existing multi-accept format), and
the scoreboard normalizer (#21) handles defang/format variations on submission.
"""

# cap how many values go into a single multi-accept answer (keeps answers sane)
_ANSWER_CAP = 100

# attack strings that imply the actor sends email (so a sender-address question makes sense)
_EMAIL_ATTACKS = {"email:phishing", "email:malware_delivery", "delivery:supply_chain",
                  "watering_hole:phishing"}


def _join(values):
    seen = []
    for v in values:
        v = ("" if v is None else str(v)).strip()
        if v and v not in seen:
            seen.append(v)
        if len(seen) >= _ANSWER_CAP:
            break
    return " ; ".join(seen)


def build_challenges(actors, malware_by_name=None, get_spec=None) -> "list[dict]":
    """
    Build challenge dicts from scenario facts.

    actors: list of dicts, each with keys:
        name (str), attribution (str|None), aliases (list[str]),
        domains (list[str]), ips (list[str]), sender_emails (list[str]),
        malware (list[str]), attacks (list[str])
    malware_by_name: {family_name: {"hashes": [...]}}
    get_spec: callable(attack_str) -> object with .attack_id/.attack_name, or None.
              Defaults to the attack registry.

    Returns a list of {name, category, description, answer, value} dicts (de-duped by name).
    """
    if get_spec is None:
        from app.server.modules.attacks.attack_registry import get_spec as _gs
        get_spec = _gs
    malware_by_name = malware_by_name or {}

    challenges = []
    seen_techniques = set()

    for actor in actors or []:
        name = actor.get("name") or "the actor"
        ips = actor.get("ips") or []
        domains = actor.get("domains") or []
        senders = actor.get("sender_emails") or []
        attacks = actor.get("attacks") or []
        mw_names = actor.get("malware") or []

        # Attribution
        attribution = actor.get("attribution")
        aliases = actor.get("aliases") or []
        if attribution or aliases:
            accepted = [name] + ([attribution] if attribution else []) + list(aliases)
            challenges.append({
                "name": f"Attribution — {name}",
                "category": "Attribution",
                "description": "Based on the techniques, tooling, and infrastructure, "
                               "which threat actor is responsible for this campaign?",
                "answer": _join(accepted),
                "value": 300,
            })

        # Command & control / malicious IPs
        if ips:
            challenges.append({
                "name": f"Malicious IP — {name}",
                "category": "Command & Control",
                "description": f"Identify a command-and-control / malicious IP address used by {name}.",
                "answer": _join(ips),
                "value": 200,
            })

        # Malicious domains
        if domains:
            challenges.append({
                "name": f"Malicious domain — {name}",
                "category": "Infrastructure",
                "description": f"Identify a malicious domain operated by {name}.",
                "answer": _join(domains),
                "value": 150,
            })

        # Phishing sender addresses
        if senders and any(a in _EMAIL_ATTACKS for a in attacks):
            challenges.append({
                "name": f"Phishing sender — {name}",
                "category": "Email",
                "description": f"What email address did {name} use to send phishing?",
                "answer": _join(senders),
                "value": 150,
            })

        # Malware family + hashes
        for mw in mw_names:
            challenges.append({
                "name": f"Malware family — {name}",
                "category": "Malware",
                "description": f"What malware family did {name} deploy?",
                "answer": str(mw),
                "value": 100,
            })
            hashes = (malware_by_name.get(mw) or {}).get("hashes") or []
            if hashes:
                challenges.append({
                    "name": f"Malware hash — {mw}",
                    "category": "Malware",
                    "description": f"Provide a SHA256 hash of the {mw} payload.",
                    "answer": _join(hashes),
                    "value": 200,
                })

        # MITRE ATT&CK technique ids (one per distinct technique across the scenario)
        for attack in attacks:
            spec = get_spec(attack)
            if not spec or attack in seen_techniques:
                continue
            seen_techniques.add(attack)
            challenges.append({
                "name": f"ATT&CK — {spec.attack_name}",
                "category": "MITRE ATT&CK",
                "description": f"Which MITRE ATT&CK technique ID corresponds to "
                               f"\"{spec.attack_name}\" observed in this intrusion?",
                "answer": spec.attack_id,
                "value": 100,
            })

    # de-dup by challenge name (keep first)
    out = []
    seen_names = set()
    for c in challenges:
        if c["name"] in seen_names:
            continue
        seen_names.add(c["name"])
        out.append(c)
    return out


def gather_scenario_facts():
    """
    Collect actor + malware facts from the live DB / YAML configs / generated malware.
    Most facts (IPs, domains, malware hashes) only exist after a game has been generated,
    so this is best called post-generation. Lazy-imports app modules. Returns
    (actors, malware_by_name) suitable for ``build_challenges``.
    """
    import glob
    import yaml
    from app.server.modules.actors.Actor import Actor

    # attribution metadata lives in the YAML configs (not the DB model)
    attribution_by_name = {}
    for path in glob.glob("app/game_configs/actors/*.yaml"):
        try:
            cfg = yaml.safe_load(open(path)) or {}
            if isinstance(cfg, dict) and cfg.get("name"):
                attribution_by_name[cfg["name"]] = cfg
        except Exception:
            pass

    actors = []
    for a in Actor.query.filter(Actor.name != "Default").all():
        cfg = attribution_by_name.get(a.name, {})
        actors.append({
            "name": a.name,
            "attribution": cfg.get("attribution"),
            "aliases": cfg.get("aliases") or [],
            "ips": list(getattr(a, "ips_list", []) or []),
            "domains": list(getattr(a, "domains_list", []) or []),
            "sender_emails": Actor.string_to_list(a.sender_emails) if a.sender_emails else [],
            "malware": a.get_malware_names(),
            "attacks": a.get_attacks(),
        })

    malware_by_name = {}
    try:
        from app.server.game_functions import MALWARE_OBJECTS
        for mw in MALWARE_OBJECTS:
            malware_by_name[mw.name] = {"hashes": list(getattr(mw, "hashes", []) or [])}
    except Exception:
        pass

    return actors, malware_by_name
