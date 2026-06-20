"""
Intel-pack ingestion (#43).

An *intel pack* is a portable YAML bundle of real-world threat intelligence for a
scenario actor — a real group's name/aliases, its MITRE ATT&CK group id, the technique
ids it uses, and (optionally) historical malware hashes and indicators with provenance.
The importer maps a pack onto a game **actor config**: it carries the attribution
metadata (#40) and selects the subset of the group's techniques the game can actually
generate (via the registry's ATT&CK reverse lookup); other technique ids are skipped.

Safety (#39) is enforced:
  - a pack MUST declare provenance (``source`` and/or ``provenance_url``);
  - real indicators are **defanged** for storage/display unless ``allow_real`` is set;
  - malware hashes are carried as strings only (never payloads — seed files stay EICAR);
  - the resulting config is run through the config validator before it is used.

Pure where it can be (parse/validate/map); ``import_pack`` returns plain dicts so callers
(an admin route) can preview before writing anything.

Pack format (YAML):

    pack_name: "APT29 emulation pack"
    source: "MITRE ATT&CK G0016 + abuse.ch ThreatFox"
    provenance_url: "https://attack.mitre.org/groups/G0016/"
    actor:
      name: CozyBearEmu
      attribution: APT29
      aliases: ["Cozy Bear", "Midnight Blizzard"]
      attack_group_id: G0016
      origin: "Russia (SVR)"
      motivation: Espionage
      attack_ids: [T1566.002, T1558.003, T1021.002, T1070.001]
      activity_start_date: "2023-03-01"
      activity_end_date: "2023-03-31"
      activity_start_hour: 9
      workday_length_hours: 8
    indicators:                 # historical / sinkholed / defanged — never live C2
      domains: ["historical-c2.example.com"]
      ips: ["198.51.100.23"]
    malware:                    # hashes are strings only, with provenance
      - name: wellmess
        hashes: ["<sha256>"]
        source: "abuse.ch MalwareBazaar"
"""

import re

_GROUP_ID_PATTERN = re.compile(r"^G\d{4}$")


def parse_pack(yaml_text: str) -> dict:
    """Parse intel-pack YAML text into a dict (raises ValueError on bad YAML)."""
    import yaml
    try:
        data = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        raise ValueError(f"intel pack: could not parse YAML ({e})")
    if not isinstance(data, dict):
        raise ValueError("intel pack: top level must be a mapping")
    return data


def validate_pack(pack: dict) -> "list[str]":
    """Validate an intel pack's structure + safety requirements. Returns error strings."""
    from app.server.modules.attacks.attack_registry import is_valid_attack_id

    errors = []
    if not pack.get("pack_name"):
        errors.append("missing 'pack_name'")
    if not (pack.get("source") or pack.get("provenance_url")):
        errors.append("missing provenance — set 'source' and/or 'provenance_url' "
                      "(every pack must record where its intel came from)")

    actor = pack.get("actor")
    if not isinstance(actor, dict):
        errors.append("missing 'actor' section")
        return errors

    if not actor.get("name"):
        errors.append("actor: missing 'name'")
    gid = actor.get("attack_group_id")
    if gid and not _GROUP_ID_PATTERN.match(str(gid)):
        errors.append(f"actor: attack_group_id '{gid}' is not a valid MITRE ATT&CK group id (e.g. G0016)")
    for tid in actor.get("attack_ids", []) or []:
        if not is_valid_attack_id(str(tid)):
            errors.append(f"actor: '{tid}' is not a valid MITRE ATT&CK technique id (e.g. T1566.002)")
    return errors


def pack_to_actor_config(pack: dict) -> "tuple[dict, list]":
    """
    Map a pack onto a game actor config dict. Returns (config, notes). Notes record
    technique ids that the game doesn't implement (and were skipped). Assumes the pack
    has already passed ``validate_pack``.
    """
    from app.server.modules.attacks.attack_registry import attacks_for_attack_id

    actor = pack.get("actor") or {}
    notes = []

    # ATT&CK technique ids -> the game attack strings that can generate them
    attacks = []
    for tid in actor.get("attack_ids", []) or []:
        mapped = attacks_for_attack_id(str(tid))
        if mapped:
            for a in mapped:
                if a not in attacks:
                    attacks.append(a)
        else:
            notes.append(f"technique {tid} has no game implementation — skipped")

    config = {
        "name": actor.get("name"),
        "attribution": actor.get("attribution"),
        "aliases": list(actor.get("aliases") or []),
        "attack_group_id": actor.get("attack_group_id"),
        "origin": actor.get("origin"),
        "motivation": actor.get("motivation"),
        "attacks": attacks,
    }
    # carry timing if provided (otherwise the author fills it in before saving)
    for k in ("activity_start_date", "activity_end_date", "activity_start_hour",
              "workday_length_hours"):
        if actor.get(k) is not None:
            config[k] = actor[k]

    # drop empty optional keys so the config stays clean
    config = {k: v for k, v in config.items() if v not in (None, [], "")}
    return config, notes


def import_pack(yaml_text: str, allow_real: bool = False) -> dict:
    """
    Parse + validate a pack and produce a previewable result:
      {ok, errors, warnings, notes, actor_config, indicators, malware}
    Indicators are defanged unless ``allow_real`` is True. Nothing is written here —
    the caller decides whether to save the actor_config (via scenario_admin).
    """
    from app.server.modules.safety.safety import defang

    result = {"ok": False, "errors": [], "warnings": [], "notes": [],
              "actor_config": None, "indicators": {}, "malware": []}
    try:
        pack = parse_pack(yaml_text)
    except ValueError as e:
        result["errors"] = [str(e)]
        return result

    errors = validate_pack(pack)
    if errors:
        result["errors"] = errors
        return result

    config, notes = pack_to_actor_config(pack)
    result["actor_config"] = config
    result["notes"] = notes
    if not config.get("attacks"):
        result["warnings"].append("no techniques mapped to game-implemented attacks — "
                                   "the imported actor will have an empty 'attacks' list")

    # Indicators: defanged for display unless real indicators are explicitly allowed.
    indicators = pack.get("indicators") or {}
    out_ind = {}
    for key in ("domains", "ips", "urls"):
        vals = indicators.get(key) or []
        out_ind[key] = list(vals) if allow_real else [defang(v) for v in vals]
    result["indicators"] = out_ind
    if (out_ind.get("domains") or out_ind.get("ips") or out_ind.get("urls")) and not allow_real:
        result["warnings"].append("indicators are shown defanged (ALLOW_REAL_INDICATORS is off)")

    # Malware: hashes are strings only.
    for mw in pack.get("malware") or []:
        result["malware"].append({
            "name": mw.get("name"),
            "hashes": list(mw.get("hashes") or []),
            "source": mw.get("source"),
        })

    result["ok"] = True
    return result
