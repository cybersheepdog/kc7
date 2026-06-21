"""
Dependency-free validation for the game's YAML scenario configs (actors, company,
malware).

Goal: when a scenario designer makes a mistake — a typo'd attack string like
``remote_exploit`` instead of a real technique, an unknown field, a missing required
value, or a watering-hole actor with no domains — the engine should say *exactly*
where and what, **at startup, before it ever talks to Azure**, instead of failing
deep inside generation.

Design notes:
  - No external dependency (no pydantic/cerberus). Pure stdlib, so importing this
    module can never break an environment that hasn't installed an extra package.
  - Valid field names and required fields are derived from the real constructors via
    ``inspect``, so this validator cannot drift out of sync if a constructor changes.
  - Attack strings and their required actor-config fields are validated against the
    single source of truth in ``attack_registry``.
  - Validators return a list of human-readable error strings; ``validate_or_raise``
    aggregates them and raises ``ConfigValidationError``.
"""

import inspect
import glob
import os
from datetime import date
from difflib import get_close_matches

from app.server.modules.attacks.attack_registry import (
    is_known_attack,
    all_attack_strings,
    get_spec,
    is_valid_attack_id,
    assert_attack_ids_wellformed,
)


class ConfigValidationError(Exception):
    """Raised when one or more game configs fail validation."""
    pass


def validate_attack_ids(ids, source: str = "config") -> "list[str]":
    """
    Validate a list of MITRE ATT&CK technique ids (e.g. for a future actor-declared
    `attack_ids` / emulated-technique field). Returns a list of error strings.
    Ready for the attribution work (#40); not yet wired to any config field.
    """
    errors = []
    if ids is None:
        return errors
    if not isinstance(ids, list):
        return [f"{source}: 'attack_ids' should be a list, got {type(ids).__name__}"]
    for tid in ids:
        if not isinstance(tid, str) or not is_valid_attack_id(tid):
            errors.append(f"{source}: '{tid}' is not a valid MITRE ATT&CK technique id "
                          f"(expected like T1566 or T1558.003)")
    return errors


# Fields that should be lists when present (shared across config types)
_LIST_FIELDS = {
    "attacks", "domain_themes", "sender_themes", "subjects", "tlds", "file_names",
    "file_extensions", "malware", "recon_search_terms", "watering_hole_domains",
    "watering_hole_target_roles", "sender_domains", "working_days",
    "post_exploit_commands", "partners", "filenames", "paths", "recon_processes",
    "c2_processes", "aliases",
}
# Attribution fields that should be plain strings when present
_STRING_FIELDS = {"attribution", "attack_group_id", "origin", "motivation", "report_url"}
# A well-formed MITRE ATT&CK *group* id, e.g. G0016
_ATTACK_GROUP_PATTERN = __import__("re").compile(r"^G\d{4}$")
# Fields that should be ints when present
_INT_FIELDS = {
    "activity_start_hour", "workday_length_hours", "effectiveness",
    "count_init_passive_dns", "count_init_email", "count_init_browsing",
    "max_wave_size", "count_employees", "domain_depth",
}
# Fields that should be booleans when present
_BOOL_FIELDS = {"spoofs_email", "generates_infrastructure"}
# Fields that should be ISO date strings when present
_DATE_FIELDS = {"activity_start_date", "activity_end_date"}


def _constructor_fields(cls):
    """
    Inspect ``cls.__init__`` and return (known_fields, required_fields, has_var_kw).
    has_var_kw is True if the constructor accepts **kwargs (then unknown-key checks
    are skipped, since any key could be valid).
    """
    sig = inspect.signature(cls.__init__)
    known, required, has_var_kw = set(), set(), False
    for name, p in sig.parameters.items():
        if name == "self":
            continue
        if p.kind == p.VAR_KEYWORD:
            has_var_kw = True
            continue
        if p.kind == p.VAR_POSITIONAL:
            continue
        known.add(name)
        if p.default is inspect.Parameter.empty:
            required.add(name)
    return known, required, has_var_kw


def _check_types(config: dict) -> "list[str]":
    """Light primitive type checks for any recognized fields that are present."""
    errors = []
    for key, value in config.items():
        if key in _LIST_FIELDS:
            if not isinstance(value, list):
                errors.append(f"field '{key}' should be a list, got {type(value).__name__}")
        elif key in _BOOL_FIELDS:
            if not isinstance(value, bool):
                errors.append(f"field '{key}' should be true/false, got {type(value).__name__}")
        elif key in _INT_FIELDS:
            # bool is a subclass of int — reject it explicitly for int fields
            if not isinstance(value, int) or isinstance(value, bool):
                errors.append(f"field '{key}' should be a whole number, got {type(value).__name__}")
        elif key in _STRING_FIELDS:
            if value is not None and not isinstance(value, str):
                errors.append(f"field '{key}' should be text, got {type(value).__name__}")
        elif key in _DATE_FIELDS:
            if not isinstance(value, str):
                errors.append(f"field '{key}' should be a date string 'YYYY-MM-DD', got {type(value).__name__}")
            else:
                try:
                    date.fromisoformat(value)
                except ValueError:
                    errors.append(f"field '{key}' is not a valid 'YYYY-MM-DD' date: {value!r}")
    return errors


def _check_known_and_required(config: dict, cls, label: str) -> "list[str]":
    """Check for unknown keys (with did-you-mean) and missing required keys."""
    errors = []
    known, required, has_var_kw = _constructor_fields(cls)

    if not has_var_kw:
        for key in config:
            if key not in known:
                suggestion = get_close_matches(key, known, n=1)
                hint = f" (did you mean '{suggestion[0]}'?)" if suggestion else ""
                errors.append(f"unknown {label} field '{key}'{hint}")

    for req in sorted(required):
        if req not in config or config.get(req) in (None, ""):
            errors.append(f"missing required {label} field '{req}'")

    return errors


def validate_actor_config(config: dict, source: str = "actor", actor_cls=None) -> "list[str]":
    """Validate a single actor config dict. Returns a list of error strings."""
    errors = []

    if not isinstance(config, dict):
        return [f"{source}: config is not a mapping/dictionary"]

    if actor_cls is None:
        from app.server.modules.actors.Actor import Actor as actor_cls

    errors += _check_known_and_required(config, actor_cls, "actor")
    errors += _check_types(config)

    # Validate attack strings and their required fields
    attacks = config.get("attacks", [])
    if isinstance(attacks, list):
        for attack in attacks:
            if not isinstance(attack, str):
                errors.append(f"attack entry should be a string, got {type(attack).__name__}: {attack!r}")
                continue
            if not is_known_attack(attack):
                suggestion = get_close_matches(attack, all_attack_strings(), n=1)
                hint = f" (did you mean '{suggestion[0]}'?)" if suggestion else ""
                errors.append(f"unknown attack type '{attack}'{hint}")
                continue
            # Hard cross-reference checks: required actor fields for this attack
            spec = get_spec(attack)
            for rf in spec.required_fields:
                if not config.get(rf):
                    errors.append(
                        f"attack '{attack}' requires a non-empty '{rf}' field on the actor"
                    )

    # Attribution metadata (#40): validate the MITRE ATT&CK *group* id format if present
    group_id = config.get("attack_group_id")
    if group_id and not _ATTACK_GROUP_PATTERN.match(str(group_id)):
        errors.append(f"attack_group_id '{group_id}' is not a valid MITRE ATT&CK group id "
                      f"(expected like G0016)")

    # Attribution report link (#45/#46): if present, must look like a URL
    report_url = config.get("report_url")
    if report_url and not str(report_url).lower().startswith(("http://", "https://")):
        errors.append(f"report_url '{report_url}' should be a URL starting with http:// or https://")

    return [f"{source}: {e}" for e in errors]


def validate_company_config(config: dict, source: str = "company.yaml", company_cls=None) -> "list[str]":
    """Validate the company config dict. Returns a list of error strings."""
    if not isinstance(config, dict):
        return [f"{source}: config is not a mapping/dictionary"]

    if company_cls is None:
        from app.server.modules.organization.Company import Company as company_cls

    errors = _check_known_and_required(config, company_cls, "company")
    errors += _check_types(config)
    return [f"{source}: {e}" for e in errors]


def validate_malware_config(config: dict, source: str = "malware", malware_cls=None) -> "list[str]":
    """Validate a single malware config dict. Returns a list of error strings."""
    if not isinstance(config, dict):
        return [f"{source}: config is not a mapping/dictionary"]

    if malware_cls is None:
        from app.server.modules.file.malware import Malware as malware_cls

    errors = _check_known_and_required(config, malware_cls, "malware")
    errors += _check_types(config)
    return [f"{source}: {e}" for e in errors]


def validate_all_game_configs(
    actor_dir: str = "app/game_configs/actors",
    company_path: str = "app/game_configs/company.yaml",
    malware_dir: str = "app/game_configs/malware",
) -> "list[str]":
    """
    Read and validate every scenario config file. Returns an aggregated list of
    error strings (empty list == everything is valid).

    Also cross-checks that every actor's referenced malware name has a matching
    malware config file.
    """
    import yaml

    def _load(path):
        with open(path, "r") as fh:
            return yaml.safe_load(fh)

    errors = []

    # Registry self-checks (fail fast if the attack registry itself is malformed —
    # e.g. a new technique was added with a typo'd MITRE ATT&CK id, or the registry and
    # the AttackTypes enum drifted out of sync).
    try:
        assert_attack_ids_wellformed()
    except AssertionError as e:
        errors.append(f"attack_registry: {e}")
    try:
        from app.server.modules.attacks.attack_registry import assert_registry_matches_enum
        assert_registry_matches_enum()
    except AssertionError as e:
        errors.append(f"attack_registry: {e}")
    except Exception:
        # AttackTypes import problems shouldn't abort config validation
        pass

    # Company
    if os.path.exists(company_path):
        try:
            errors += validate_company_config(_load(company_path), os.path.basename(company_path))
        except Exception as e:
            errors.append(f"{os.path.basename(company_path)}: could not parse YAML ({e})")
    else:
        errors.append(f"{company_path}: company config file not found")

    # Malware (collect known names for cross-reference)
    known_malware_names = set()
    for path in sorted(glob.glob(os.path.join(malware_dir, "*.yaml"))):
        src = os.path.basename(path)
        try:
            cfg = _load(path)
        except Exception as e:
            errors.append(f"{src}: could not parse YAML ({e})")
            continue
        if cfg and isinstance(cfg, dict) and cfg.get("name"):
            known_malware_names.add(cfg["name"])
        errors += validate_malware_config(cfg, src)

    # Actors
    for path in sorted(glob.glob(os.path.join(actor_dir, "*.yaml"))):
        src = os.path.basename(path)
        try:
            cfg = _load(path)
        except Exception as e:
            errors.append(f"{src}: could not parse YAML ({e})")
            continue
        errors += validate_actor_config(cfg, src)
        # cross-reference: each referenced malware should have a config
        if isinstance(cfg, dict):
            for mw in cfg.get("malware", []) or []:
                if mw not in known_malware_names:
                    errors.append(f"{src}: references malware '{mw}' but no matching malware config was found")

    return errors


def validate_or_raise(**kwargs) -> None:
    """
    Validate all game configs and raise ConfigValidationError with an aggregated,
    human-readable message if anything is wrong.
    """
    errors = validate_all_game_configs(**kwargs)
    if errors:
        raise ConfigValidationError(
            "Game config validation failed — fix these before starting the game:\n  - "
            + "\n  - ".join(errors)
        )
