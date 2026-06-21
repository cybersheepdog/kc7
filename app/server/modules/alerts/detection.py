"""
Per-technique detection fidelity (#15).

The engine already models alert true/false-positive rates for malware-on-host and
user-reported email (TP_RATE_HOST_ALERTS, FP_RATE_*). This module extends that idea to
the advanced techniques: each one carries a *detection profile* — a probability that a
single execution trips a SecurityAlert, plus the severity of that alert.

The point is realism and teaching value. Some techniques are loud: a PsExec service
install (7045), an impossible-travel cloud sign-in, or a storage bucket flipped public
and mass-read are the kind of thing a SOC's tooling lights up on. Others are
deliberately quiet: Kerberoasting and event-log clearing are classic low-signal /
evasive actions. Wiring those differing rates in gives players authentic visibility
gaps — some intrusion steps they can catch on an alert, others they must reconstruct
from raw telemetry.

Everything here is gated by ``TECHNIQUE_ALERTS_ENABLED`` (off by default): with the flag
off, ``generate_technique_alert`` is a no-op and no technique-detection alerts are
emitted, so default behavior is unchanged.
"""

import random as _random


# (detection_rate, severity) per attack string.
#   detection_rate = probability ONE execution of the technique trips a SecurityAlert.
#   severity       = "high" | "med" | "low"
# Techniques not listed here default to (0.0, "med") — i.e. they never self-alert.
DETECTION_PROFILES = {
    # --- Loud / high-signal: tooling usually catches these ---
    "execution:psexec_lateral":       (0.60, "high"),  # 7045 service install over SMB
    "cloud:session_hijacking":        (0.60, "high"),  # impossible-travel sign-in
    "cloud:exfiltration_via_storage": (0.70, "high"),  # bucket made public + mass reads

    # --- Medium: noisy enough to sometimes alert ---
    "discovery:automated_recon":      (0.30, "med"),   # dense process-exec burst
    "persistence:scheduled_task":     (0.35, "med"),   # schtasks.exe /create
    "persistence:registry_run":       (0.35, "med"),   # reg add ...\Run
    "exfiltration:email_collection":  (0.25, "med"),   # bulk mailbox download

    # --- Quiet: the deliberate visibility gaps players must work around ---
    "hands_on_keyboard:operator":     (0.15, "low"),   # living-off-the-land commands
    "evasion:log_clearing":           (0.05, "low"),   # the whole point is to go dark
    "identity:kerberoasting":         (0.02, "low"),   # notoriously low-signal
}

_DEFAULT_PROFILE = (0.0, "med")


def get_detection_profile(attack: str) -> tuple:
    """Return (detection_rate, severity) for an attack string; (0.0, 'med') if unlisted."""
    return DETECTION_PROFILES.get(attack, _DEFAULT_PROFILE)


def _default_description(attack: str, where: str) -> str:
    try:
        from app.server.modules.attacks.attack_registry import get_spec
        spec = get_spec(attack)
        if spec is not None:
            return (f"{spec.attack_name} ({spec.attack_id}) — suspicious activity "
                    f"detected on {where}.")
    except Exception:
        pass
    return f"Suspicious activity ({attack}) detected on {where}."


def generate_technique_alert(time, attack, hostname=None, username=None,
                             details=None, app_config=None, _rng=None) -> bool:
    """
    Maybe emit a SecurityAlert representing detection of ``attack``, per its detection
    profile. Gated by TECHNIQUE_ALERTS_ENABLED (off by default -> no-op). Returns True
    iff an alert was emitted. ``app_config`` / ``_rng`` are injectable for tests.
    """
    cfg = app_config
    if cfg is None:
        try:
            from flask import current_app
            cfg = current_app.config
        except Exception:
            return False

    try:
        if not cfg.get("TECHNIQUE_ALERTS_ENABLED"):
            return False
    except Exception:
        return False

    rate, severity = get_detection_profile(attack)
    if rate <= 0:
        return False

    rng = _rng or _random
    if rng.random() >= rate:
        return False

    where = hostname or username or "the environment"
    description = details or _default_description(attack, where)
    technique_id = _technique_id(attack)

    from app.server.modules.alerts.alerts import SecurityAlert
    from app.server.modules.alerts.alerts_controller import send_alert_to_azure
    send_alert_to_azure(
        SecurityAlert(time=time, alert_type="EDR", severity=severity,
                      description=description, hostname=hostname or "",
                      username=username or "", technique_id=technique_id)
    )
    return True


def _technique_id(attack: str) -> str:
    """The MITRE ATT&CK id for an attack string (via the registry), or '' if unknown."""
    try:
        from app.server.modules.attacks.attack_registry import get_spec
        spec = get_spec(attack)
        if spec is not None:
            return spec.attack_id
    except Exception:
        pass
    return ""
