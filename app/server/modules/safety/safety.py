"""
Safety controls for using real-world threat intelligence in the game.

The attribution work lets actors emulate real threat groups, which raises a safety
question: real *live* C2 infrastructure must never be shippable in game telemetry (a
player could browse to it or blocklist it on a real network), and real malware must
never be written to disk. This module centralizes the guardrails:

  - EICAR_TEST_STRING — the single source of truth for seed-file content. Seed
    "malware" files contain only the harmless EICAR antivirus test string, never a real
    payload. ``seed_file_content_is_inert()`` verifies that invariant.
  - defang() — render a real indicator inertly for display (hxxp://, [.], [at]) so it
    can't be accidentally clicked or auto-blocklisted.
  - check_safety_invariants() — advisory pre-flight: warns when the "allow real
    infrastructure" toggles are on, so an operator is reminded to keep IOCs inert.

Pure / dependency-free.
"""

import re

# The standard EICAR antivirus test string — universally recognized as harmless.
EICAR_TEST_STRING = r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

# A stable fragment to detect EICAR content without depending on exact surrounding bytes.
_EICAR_SIGNATURE = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"


def seed_file_content_is_inert(content: str) -> bool:
    """True if seed-file content is the harmless EICAR test string (not real malware)."""
    return bool(content) and _EICAR_SIGNATURE in content


def defang(indicator: str) -> str:
    """
    Render an indicator inertly for safe display:
      http:// -> hxxp://,  https:// -> hxxps://,  .  -> [.],  @ -> [at]
    Idempotent-ish and conservative — only touches the tokens that make an IOC
    'clickable'/'blocklistable'. Leaves already-defanged input alone.
    """
    if not indicator:
        return ""
    s = str(indicator)
    if "[.]" in s or "hxxp" in s:        # looks already defanged
        return s
    s = s.replace("https://", "hxxps://").replace("http://", "hxxp://")
    s = s.replace("ftp://", "fxp://")
    s = s.replace("@", "[at]")
    s = s.replace(".", "[.]")
    return s


def check_safety_invariants(config) -> "list[str]":
    """
    Advisory pre-flight checks (warnings, not hard errors). ``config`` is a mapping
    (e.g. Flask app.config). Returns human-readable warnings to surface to operators.
    """
    warnings = []
    try:
        getter = config.get
    except AttributeError:
        return warnings

    if getter("ALLOW_REAL_C2_INFRASTRUCTURE", False):
        warnings.append(
            "ALLOW_REAL_C2_INFRASTRUCTURE is enabled — ensure actor infrastructure uses "
            "synthetic, sinkholed, or defanged indicators only; never live C2 a player "
            "could reach or blocklist on a real network."
        )
    if getter("ALLOW_REAL_INDICATORS", False):
        warnings.append(
            "ALLOW_REAL_INDICATORS is enabled — real indicators are permitted. Use real "
            "hashes only as indicator strings (never real payloads; seed files stay EICAR), "
            "and attach provenance (source + report URL) to each real IOC."
        )
    return warnings
