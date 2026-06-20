"""
Attack registry — a single source of truth describing every adversary technique
the game can generate.

Each attack string (e.g. "identity:kerberoasting") maps to an ``AttackSpec`` that
records its kill-chain phase, MITRE ATT&CK mapping, a human description, the ADX
tables it writes to, and the actor-config fields it requires to function.

This registry is intentionally dependency-free (it imports nothing heavy), so it can
power:
  - config validation (which attack strings are valid; what fields they require),
  - documentation / the admin GUI (phase, ATT&CK id, description, tables),
  - dry-run previews (which tables an actor's attacks will populate).

The canonical list of attack *strings* still lives in ``AttackTypes`` (utils.py),
which the dispatch loop uses. ``assert_registry_matches_enum()`` checks the two stay
in sync so a new enum member can't be added without a registry entry (and vice-versa).
"""

import re
from dataclasses import dataclass, field


# A well-formed MITRE ATT&CK technique id: T#### with an optional .### sub-technique
# (e.g. T1566, T1558.003). Used to validate the registry and any actor-declared ids.
ATTACK_ID_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")


# Kill-chain phase labels (kept as plain strings for easy display/grouping)
class Phase:
    DELIVERY          = "Delivery / Initial Access"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY         = "Discovery"
    LATERAL_MOVEMENT  = "Lateral Movement"
    DEFENSE_EVASION   = "Defense Evasion"
    PERSISTENCE       = "Persistence"
    CLOUD             = "Cloud"


@dataclass(frozen=True)
class AttackSpec:
    """Metadata describing one adversary technique."""
    attack: str                              # the attack string, e.g. "email:phishing"
    phase: str                               # kill-chain phase (see Phase)
    attack_id: str                           # MITRE ATT&CK technique id, e.g. "T1558.003"
    attack_name: str                         # MITRE ATT&CK technique name
    description: str                         # short human-readable summary
    tables: tuple = ()                       # ADX tables this technique writes to
    required_fields: tuple = ()              # actor-config fields that MUST be present/non-empty
    recommended_fields: tuple = ()           # fields that improve realism but are not required


# ---------------------------------------------------------------------------
# The registry. Order is roughly kill-chain order for nicer display.
# ---------------------------------------------------------------------------
ATTACK_REGISTRY = {

    # --- Delivery / Initial Access ---
    "email:phishing": AttackSpec(
        attack="email:phishing",
        phase=Phase.DELIVERY,
        attack_id="T1566.002",
        attack_name="Phishing: Spearphishing Link",
        description="Credential-phishing emails sent to employees.",
        tables=("Email", "OutboundBrowsing", "AuthenticationEvents"),
        recommended_fields=("sender_themes", "subjects", "sender_domains"),
    ),
    "email:malware_delivery": AttackSpec(
        attack="email:malware_delivery",
        phase=Phase.DELIVERY,
        attack_id="T1566.001",
        attack_name="Phishing: Spearphishing Attachment",
        description="Emails delivering a malicious file or link that drops a payload.",
        tables=("Email", "OutboundBrowsing", "FileCreationEvents", "ProcessEvents"),
        recommended_fields=("malware", "file_names", "subjects"),
    ),
    "delivery:supply_chain": AttackSpec(
        attack="delivery:supply_chain",
        phase=Phase.DELIVERY,
        attack_id="T1199",
        attack_name="Trusted Relationship",
        description="Phishing from compromised partner/vendor email addresses.",
        tables=("Email",),
        recommended_fields=("sender_themes", "subjects"),
    ),
    "watering_hole:malware_delivery": AttackSpec(
        attack="watering_hole:malware_delivery",
        phase=Phase.DELIVERY,
        attack_id="T1189",
        attack_name="Drive-by Compromise",
        description="Malware served from a compromised website to targeted roles.",
        tables=("OutboundBrowsing", "FileCreationEvents", "ProcessEvents"),
        required_fields=("watering_hole_domains",),
        recommended_fields=("watering_hole_target_roles", "malware"),
    ),
    "watering_hole:phishing": AttackSpec(
        attack="watering_hole:phishing",
        phase=Phase.DELIVERY,
        attack_id="T1189",
        attack_name="Drive-by Compromise",
        description="Credential phishing via a compromised website to targeted roles.",
        tables=("OutboundBrowsing", "AuthenticationEvents"),
        required_fields=("watering_hole_domains",),
        recommended_fields=("watering_hole_target_roles",),
    ),

    # --- Credential Access ---
    "identity:password_spray": AttackSpec(
        attack="identity:password_spray",
        phase=Phase.CREDENTIAL_ACCESS,
        attack_id="T1110.003",
        attack_name="Brute Force: Password Spraying",
        description="Password spray against employee accounts on the mail server.",
        tables=("AuthenticationEvents",),
    ),
    "identity:kerberoasting": AttackSpec(
        attack="identity:kerberoasting",
        phase=Phase.CREDENTIAL_ACCESS,
        attack_id="T1558.003",
        attack_name="Steal or Forge Kerberos Tickets: Kerberoasting",
        description="RC4 Kerberos service-ticket requests (Event ID 4769) for high-value SPNs.",
        tables=("SecurityEvents", "AuthenticationEvents"),
        recommended_fields=("watering_hole_target_roles",),
    ),

    # --- Discovery ---
    "recon:browsing": AttackSpec(
        attack="recon:browsing",
        phase=Phase.DISCOVERY,
        attack_id="T1593",
        attack_name="Search Open Websites/Domains",
        description="External reconnaissance browsing against the company's web presence.",
        tables=("InboundBrowsing",),
        recommended_fields=("recon_search_terms",),
    ),
    "discovery:automated_recon": AttackSpec(
        attack="discovery:automated_recon",
        phase=Phase.DISCOVERY,
        attack_id="T1087",
        attack_name="Account Discovery (host/domain enumeration burst)",
        description="Dense burst of host/domain discovery commands from cmd.exe/powershell.exe.",
        tables=("ProcessEvents",),
        recommended_fields=("watering_hole_target_roles",),
    ),

    # --- Lateral Movement ---
    "execution:psexec_lateral": AttackSpec(
        attack="execution:psexec_lateral",
        phase=Phase.LATERAL_MOVEMENT,
        attack_id="T1021.002",
        attack_name="Remote Services: SMB/Windows Admin Shares",
        description="PsExec service-binary push over SMB to Admin$ (Event ID 7045), hop by hop.",
        tables=("ProcessEvents", "SecurityEvents", "AuthenticationEvents"),
        recommended_fields=("watering_hole_target_roles",),
    ),

    # --- Defense Evasion ---
    "evasion:log_clearing": AttackSpec(
        attack="evasion:log_clearing",
        phase=Phase.DEFENSE_EVASION,
        attack_id="T1070.001",
        attack_name="Indicator Removal: Clear Windows Event Logs",
        description="Security/System event-log clearing (Event ID 1102/104) creating a blind spot.",
        tables=("ProcessEvents", "SecurityEvents"),
        recommended_fields=("watering_hole_target_roles",),
    ),

    # --- Persistence ---
    "persistence:scheduled_task": AttackSpec(
        attack="persistence:scheduled_task",
        phase=Phase.PERSISTENCE,
        attack_id="T1053.005",
        attack_name="Scheduled Task/Job: Scheduled Task",
        description="schtasks.exe scheduled-task that re-launches the payload.",
        tables=("ProcessEvents",),
        recommended_fields=("malware",),
    ),
    "persistence:registry_run": AttackSpec(
        attack="persistence:registry_run",
        phase=Phase.PERSISTENCE,
        attack_id="T1547.001",
        attack_name="Boot or Logon Autostart Execution: Registry Run Keys",
        description="Run/RunOnce registry key that re-launches the payload at logon.",
        tables=("ProcessEvents",),
        recommended_fields=("malware",),
    ),

    # --- Cloud ---
    "cloud:session_hijacking": AttackSpec(
        attack="cloud:session_hijacking",
        phase=Phase.CLOUD,
        attack_id="T1539",
        attack_name="Steal Web Session Cookie",
        description="Stolen session replayed from another country (impossible travel).",
        tables=("CloudSignInLogs",),
        recommended_fields=("watering_hole_target_roles",),
    ),
    "cloud:token_theft": AttackSpec(
        attack="cloud:token_theft",
        phase=Phase.CLOUD,
        attack_id="T1528",
        attack_name="Steal Application Access Token",
        description="Stolen access token replayed from another country (impossible travel).",
        tables=("CloudSignInLogs",),
        recommended_fields=("watering_hole_target_roles",),
    ),
    "cloud:exfiltration_via_storage": AttackSpec(
        attack="cloud:exfiltration_via_storage",
        phase=Phase.CLOUD,
        attack_id="T1530",
        attack_name="Data from Cloud Storage",
        description="Storage bucket flipped public, then mass object reads to external IPs.",
        tables=("CloudSignInLogs", "CloudStorageLogs"),
        recommended_fields=("watering_hole_target_roles",),
    ),
}


# ---------------------------------------------------------------------------
# Accessors
# ---------------------------------------------------------------------------
def get_spec(attack: str) -> AttackSpec:
    """Return the AttackSpec for an attack string, or None if unknown."""
    return ATTACK_REGISTRY.get(attack)


def is_known_attack(attack: str) -> bool:
    return attack in ATTACK_REGISTRY


def all_attack_strings() -> "list[str]":
    return list(ATTACK_REGISTRY.keys())


def attacks_by_phase() -> "dict[str, list[AttackSpec]]":
    grouped = {}
    for spec in ATTACK_REGISTRY.values():
        grouped.setdefault(spec.phase, []).append(spec)
    return grouped


def tables_for_attacks(attacks: "list[str]") -> "list[str]":
    """Union of ADX tables written by the given attacks (deduped, stable order)."""
    seen = []
    for a in attacks:
        spec = ATTACK_REGISTRY.get(a)
        if spec:
            for t in spec.tables:
                if t not in seen:
                    seen.append(t)
    return seen


def assert_registry_matches_enum() -> None:
    """
    Verify the registry and the AttackTypes enum are in sync.
    Imported lazily so this module stays dependency-free until the check is called.
    Raises AssertionError listing any mismatch.
    """
    from app.server.utils import AttackTypes

    enum_values = {a.value for a in AttackTypes}
    registry_values = set(ATTACK_REGISTRY.keys())

    missing_from_registry = enum_values - registry_values
    missing_from_enum = registry_values - enum_values

    problems = []
    if missing_from_registry:
        problems.append(f"AttackTypes members with no registry entry: {sorted(missing_from_registry)}")
    if missing_from_enum:
        problems.append(f"Registry entries with no AttackTypes member: {sorted(missing_from_enum)}")
    assert not problems, "; ".join(problems)


# ---------------------------------------------------------------------------
# MITRE ATT&CK id validation
# ---------------------------------------------------------------------------
def is_valid_attack_id(value: str) -> bool:
    """True if value is a well-formed MITRE ATT&CK technique id (e.g. T1566, T1558.003)."""
    return bool(ATTACK_ID_PATTERN.match(value or ""))


def known_attack_ids() -> set:
    """The set of MITRE ATT&CK technique ids referenced by the registry."""
    return {spec.attack_id for spec in ATTACK_REGISTRY.values()}


def assert_attack_ids_wellformed() -> None:
    """
    Verify every registry entry carries a well-formed ATT&CK technique id. Catches typos
    like 'T155.003' or '1558.003' when a technique is added. Dependency-free.
    Raises AssertionError listing any offenders.
    """
    bad = [f"{spec.attack} -> {spec.attack_id!r}"
           for spec in ATTACK_REGISTRY.values()
           if not is_valid_attack_id(spec.attack_id)]
    assert not bad, "Malformed MITRE ATT&CK technique id(s) in registry: " + "; ".join(bad)
