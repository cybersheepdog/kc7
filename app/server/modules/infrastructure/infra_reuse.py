"""
Actor-consistent infrastructure reuse (#44) — the core attribution enabler.

Real threat actors reuse hosting infrastructure: their C2 servers cluster in the same
ASN / network ranges across campaigns, which is exactly how analysts pivot from one
intrusion to another and attribute both to one actor. By default this game mints every
actor IP with ``fake.ipv4_public()`` — fully random across the whole IPv4 space — so an
actor's infrastructure has no recognizable network neighborhood and nothing to cluster on.

This module gives each actor a small, STABLE set of "owned" /16 network ranges, derived
deterministically from the actor's name (so they recur across campaigns and re-runs).
``actor_ip_address`` then draws addresses inside those ranges. The function is purely
additive and is only consulted when ``INFRA_REUSE_ENABLED`` is on (see config.py); with
it off, callers keep their original random behavior.

Determinism is keyed on ``actor.name`` only, so the same actor always owns the same
ranges — that stability is the fingerprint. Domains are already actor-consistent (stable
per-actor TLDs + theme words) and malware hashes are already reused per family, so IP
ranges were the missing piece.
"""

import hashlib

# First octets that are NOT publicly routable (or are special-use) — avoid them so the
# generated ranges look like real internet hosting space.
_RESERVED_FIRST_OCTETS = {0, 10, 100, 127, 169, 172, 192, 198, 203}


def _seed_int(text: str) -> int:
    return int(hashlib.md5(text.encode("utf-8")).hexdigest(), 16)


def _public_first_octet(value: int) -> int:
    """Map an arbitrary int onto a first octet in 1..223 that isn't special-use."""
    octet = 1 + (value % 223)               # 1..223 (keeps clear of 224+ multicast/reserved)
    if octet in _RESERVED_FIRST_OCTETS:
        octet += 1                          # nudge off a reserved /8 (neighbors are safe)
    return octet


def actor_ip_prefixes(actor, count=None):
    """
    Return the actor's stable list of "/16" prefixes as (a, b) octet pairs. Deterministic
    in ``actor.name``; the same actor always yields the same ranges. ``count`` defaults to
    INFRA_REUSE_PREFIX_COUNT (or 3 outside an app context).
    """
    name = getattr(actor, "name", None) or "actor"
    if count is None:
        count = _prefix_count()
    prefixes = []
    i = 0
    # walk salted hashes until we have `count` distinct prefixes
    while len(prefixes) < max(1, count) and i < count * 8:
        h = _seed_int(f"{name}:asn:{i}")
        a = _public_first_octet(h & 0xFF)
        b = (h >> 8) & 0xFF
        pair = (a, b)
        if pair not in prefixes:
            prefixes.append(pair)
        i += 1
    return prefixes


def _prefix_count(default=3):
    try:
        from flask import current_app
        return int(current_app.config.get("INFRA_REUSE_PREFIX_COUNT", default))
    except Exception:
        return default


def actor_ip_address(actor, existing=None, _rng=None):
    """
    Build an IP address string inside one of the actor's stable ranges, avoiding any
    address already in ``existing`` (the actor's current IPs). Returns None if it can't
    (so the caller falls back to its default random generator). ``_rng`` is injectable
    for deterministic tests.
    """
    import random as _random
    rng = _rng or _random

    prefixes = actor_ip_prefixes(actor)
    if not prefixes:
        return None

    if existing is None:
        try:
            existing = set(getattr(actor, "ips_list", []) or [])
        except Exception:
            existing = set()
    else:
        existing = set(existing)

    # try a handful of times to find a free host within the stable ranges
    for _ in range(24):
        a, b = rng.choice(prefixes)
        addr = "%d.%d.%d.%d" % (a, b, rng.randint(0, 255), rng.randint(1, 254))
        if addr not in existing:
            return addr
    return None


def actor_infrastructure_fingerprint(actor):
    """
    A small, human-readable summary of the actor's stable infrastructure fingerprint —
    its owned /16 ranges and its TLD set. Useful for the scenario preview, auto-generated
    challenges, and attribution scoring (#45).
    """
    ranges = ["%d.%d.0.0/16" % (a, b) for (a, b) in actor_ip_prefixes(actor)]
    try:
        tlds = list(getattr(actor, "tld_values", []) or [])
    except Exception:
        tlds = []
    return {"network_ranges": ranges, "tlds": tlds}
