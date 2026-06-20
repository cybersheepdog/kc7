"""
Backend for the "Manage Scenario" admin GUI (#3).

Lets an admin list / read / create / edit / clone / delete the scenario content that
was previously hand-edited YAML on disk — actor and malware configs. Every save runs
through the existing config validator first, so an invalid config is rejected with
clear errors and never written.

Security: this is admin-only, but it writes files, so filenames are strictly
sanitized and every resolved path is confined to its configured directory (no path
traversal).

The file-ops are dependency-light (PyYAML + stdlib); validation lazily imports the
validator. Helpers accept an optional ``dirs`` override so they're unit-testable
against temp directories.
"""

import glob
import os
import re

# kind -> default directory holding that kind's YAML configs
KIND_DIRS = {
    "actor": "app/game_configs/actors",
    "malware": "app/game_configs/malware",
}


def _dir_for(kind: str, dirs=None) -> str:
    mapping = dirs or KIND_DIRS
    if kind not in mapping:
        raise ValueError(f"unknown scenario kind: {kind!r}")
    return mapping[kind]


def _safe_path(kind: str, name: str, dirs=None) -> str:
    """
    Resolve ``name`` to a .yaml path strictly inside the kind's directory. Strips any
    path components, sanitizes to a safe filename, forces a .yaml extension, and
    verifies the final path is contained in the base dir. Raises ValueError otherwise.
    """
    base = os.path.abspath(_dir_for(kind, dirs))
    # take only the final component, then sanitize
    leaf = os.path.basename(str(name or "").strip().replace("\\", "/"))
    leaf = re.sub(r"[^A-Za-z0-9_.-]", "_", leaf)
    leaf = leaf.lstrip(".") or "untitled"           # no leading dots / empty
    if not leaf.lower().endswith(".yaml"):
        leaf += ".yaml"
    full = os.path.abspath(os.path.join(base, leaf))
    if full != os.path.join(base, leaf) and not full.startswith(base + os.sep):
        raise ValueError("invalid path")
    if os.path.dirname(full) != base:
        raise ValueError("invalid path")
    return full


def _summarize(kind: str, cfg: dict) -> str:
    if not isinstance(cfg, dict):
        return "(unparseable)"
    if kind == "actor":
        attacks = cfg.get("attacks") or []
        attribution = cfg.get("attribution")
        s = f"{len(attacks)} attack(s)"
        if attribution:
            s += f" · {attribution}"
        return s
    if kind == "malware":
        return f"{len(cfg.get('filenames') or [])} file(s), {len(cfg.get('c2_processes') or [])} C2 cmd(s)"
    return ""


def list_files(dirs=None) -> "list[dict]":
    """List every actor and malware config with a short summary."""
    import yaml
    out = []
    mapping = dirs or KIND_DIRS
    for kind, directory in mapping.items():
        for path in sorted(glob.glob(os.path.join(directory, "*.yaml"))):
            name = os.path.basename(path)
            summary = ""
            try:
                with open(path, "r") as fh:
                    summary = _summarize(kind, yaml.safe_load(fh) or {})
            except Exception:
                summary = "(could not parse)"
            out.append({"kind": kind, "name": name, "summary": summary})
    return out


def read_file(kind: str, name: str, dirs=None) -> str:
    """Return the raw YAML text of a config file."""
    path = _safe_path(kind, name, dirs)
    if not os.path.exists(path):
        raise FileNotFoundError(name)
    with open(path, "r") as fh:
        return fh.read()


def validate_content(kind: str, cfg: dict) -> "list[str]":
    """Validate a parsed config dict for the given kind. Returns error strings."""
    from app.server.modules.config_validation.config_validator import (
        validate_actor_config, validate_malware_config,
    )
    if kind == "actor":
        return validate_actor_config(cfg, source="(editor)")
    if kind == "malware":
        return validate_malware_config(cfg, source="(editor)")
    return [f"unknown scenario kind: {kind}"]


def save_file(kind: str, name: str, content: str, dirs=None, run_validation: bool = True) -> "list[str]":
    """
    Validate and write a config file. Returns a list of error strings; an empty list
    means it was saved. If validation fails, nothing is written.
    """
    import yaml
    try:
        path = _safe_path(kind, name, dirs)
    except ValueError as e:
        return [f"invalid filename: {e}"]

    try:
        cfg = yaml.safe_load(content)
    except yaml.YAMLError as e:
        return [f"YAML parse error: {e}"]

    if not isinstance(cfg, dict):
        return ["The config must be a YAML mapping (key: value pairs)."]

    if run_validation:
        errors = validate_content(kind, cfg)
        if errors:
            return errors

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)
    return []


def delete_file(kind: str, name: str, dirs=None) -> bool:
    """Delete a config file. Returns True if a file was removed."""
    path = _safe_path(kind, name, dirs)
    if os.path.exists(path):
        os.remove(path)
        return True
    return False


def clone_content(kind: str, name: str, dirs=None) -> str:
    """
    Return the source file's YAML with its `name:` field suffixed `_copy`, ready to be
    edited and saved under a new filename. Falls back to the raw content if the name
    line can't be found.
    """
    content = read_file(kind, name, dirs)
    # bump the top-level `name:` value so the clone is distinct
    new_content, n = re.subn(
        r'(?m)^(\s*name\s*:\s*)(["\']?)(.*?)(["\']?)\s*$',
        lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}_copy{m.group(4)}",
        content, count=1,
    )
    return new_content if n else content
