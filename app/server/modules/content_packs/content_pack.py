"""
Editable realism content packs (#4).

The advanced-attack generators draw their realism content — discovery commands, Kerberos
SPNs, internal server names, cloud apps, geo locations, etc. — from constants in
``attack_constants.py``. This module lets a **YAML content pack** override any of those
lists *without touching code*, so a non-developer can extend or localize the realism.

Safety: the in-code constants stay as the **defaults/fallback**. ``apply_overrides`` only
replaces a constant when the pack supplies a present, well-formed, non-empty value — a
missing pack, a missing key, or a malformed value leaves the default untouched. Setting
the ``KC7_DISABLE_CONTENT_PACK`` env var forces defaults (a kill switch).

Pack location: ``app/game_configs/content_packs/realism.yaml`` (override the path for tests).
"""

import os

DEFAULT_PACK_PATH = "app/game_configs/content_packs/realism.yaml"

# Canonical content-pack schema (single source of truth for the loader, the override
# mapping in attack_constants.py, and the editor validator).
#   PACK_LIST_KEYS : yaml_key -> CONSTANT_NAME for lists of strings
#   PACK_PAIR_KEYS : yaml_key -> CONSTANT_NAME for lists of [text, text] pairs
PACK_LIST_KEYS = {
    "discovery_commands": "DISCOVERY_COMMANDS",
    "discovery_parent_processes": "DISCOVERY_PARENT_PROCESSES",
    "high_value_spns": "HIGH_VALUE_SPNS",
    "domain_controllers": "DOMAIN_CONTROLLERS",
    "internal_servers": "INTERNAL_SERVERS",
    "psexec_service_binaries": "PSEXEC_SERVICE_BINARIES",
    "pre_clearing_commands": "PRE_CLEARING_COMMANDS",
    "scheduled_task_commands": "SCHEDULED_TASK_COMMANDS",
    "registry_run_commands": "REGISTRY_RUN_COMMANDS",
    "persistence_payload_locations": "PERSISTENCE_PAYLOAD_LOCATIONS",
    "persistence_payload_names": "DEFAULT_PERSISTENCE_PAYLOAD_NAMES",
    "cloud_applications": "CLOUD_APPLICATIONS",
    "cloud_storage_buckets": "CLOUD_STORAGE_BUCKETS",
    "cloud_storage_object_keys": "CLOUD_STORAGE_OBJECT_KEYS",
}
PACK_PAIR_KEYS = {
    "home_locations": "HOME_LOCATIONS",
    "impossible_travel_locations": "IMPOSSIBLE_TRAVEL_LOCATIONS",
    "hands_on_keyboard_commands": "HANDS_ON_KEYBOARD_COMMANDS",
}


def validate_pack_content(cfg) -> "list[str]":
    """
    Validate a parsed content-pack dict for the editor (#4 GUI). Returns error strings.
    Catches typo'd keys (with a suggestion) and wrong value shapes. Unknown keys are
    flagged but empty/omitted keys are fine (they keep the in-code default).
    """
    import difflib
    if not isinstance(cfg, dict):
        return ["The content pack must be a YAML mapping (key: list-of-values)."]
    known = set(PACK_LIST_KEYS) | set(PACK_PAIR_KEYS)
    errors = []
    for key, val in cfg.items():
        if key not in known:
            sug = difflib.get_close_matches(key, known, n=1)
            hint = f" (did you mean '{sug[0]}'?)" if sug else ""
            errors.append(f"unknown content-pack key '{key}'{hint}")
            continue
        if key in PACK_LIST_KEYS:
            if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
                errors.append(f"'{key}' must be a list of text lines")
        else:
            ok = isinstance(val, list) and all(
                isinstance(x, (list, tuple)) and len(x) >= 2
                and isinstance(x[0], str) and isinstance(x[1], str) for x in val)
            if not ok:
                errors.append(f"'{key}' must be a list of [text, text] pairs")
    return errors


def load_pack_dict(path=None):
    """Read the content pack YAML into a dict. Returns {} if absent/disabled/malformed."""
    if os.environ.get("KC7_DISABLE_CONTENT_PACK"):
        return {}
    path = path or DEFAULT_PACK_PATH
    try:
        if not os.path.exists(path):
            return {}
        import yaml
        with open(path, "r") as fh:
            data = yaml.safe_load(fh) or {}
        return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f"content_pack: failed to load {path}: {e}")
        return {}


def apply_overrides(globals_dict, simple_map, pair_map=None, path=None):
    """
    Overlay a content pack onto module globals.

    simple_map : {yaml_key: CONSTANT_NAME} for lists of strings.
    pair_map   : {yaml_key: CONSTANT_NAME} for lists of 2-element pairs, each converted to
                 a tuple (e.g. (city, country) or (process_name, commandline)).

    A constant is overridden only when the pack provides a present, non-empty list of the
    right shape. Returns the number of constants overridden.
    """
    pack = load_pack_dict(path)
    if not pack:
        return 0

    n = 0
    for yk, const in (simple_map or {}).items():
        v = pack.get(yk)
        if isinstance(v, list) and v and all(isinstance(x, str) for x in v):
            globals_dict[const] = list(v)
            n += 1

    for yk, const in (pair_map or {}).items():
        v = pack.get(yk)
        if not (isinstance(v, list) and v):
            continue
        pairs = []
        for x in v:
            if isinstance(x, (list, tuple)) and len(x) >= 2 \
                    and isinstance(x[0], str) and isinstance(x[1], str):
                pairs.append((x[0], x[1]))
        # only override if every item was a valid pair (don't silently drop bad data)
        if pairs and len(pairs) == len(v):
            globals_dict[const] = pairs
            n += 1
    return n
