"""
Auto-generated game guide & instructor key (#12).

Assembles a guide straight from the scenario's configuration / ground truth — company
profile, actor cast, per-actor campaign timeline, the techniques in play (with MITRE
ATT&CK IDs), and learning objectives — in two variants:

  - player intel brief  (include_answers=False): sets the scene and lists what skills
    the exercise practises, WITHOUT giving away attribution, indicators, or answers.
  - instructor key       (include_answers=True): adds the full threat landscape
    (attribution, ATT&CK techniques, timeline), the indicators of compromise, and the
    challenge answer key.

Because it is generated from config every time, it can't drift the way a hand-maintained
``summary.txt`` does. Output is Markdown (dependency-free, unlike the ReportLab PDF in
``scenario_document.py``, which this complements).

``build_game_guide`` is pure (plain dicts in, Markdown string out) so it is unit-testable;
``gather_guide_facts`` pulls the live facts from the DB + configs.
"""

# What skill a player practises by investigating each technique. Keyed by attack string.
LEARNING_OBJECTIVES = {
    "email:phishing":                 "Identify credential-phishing emails and the sender domains/links they use.",
    "email:malware_delivery":         "Trace a malicious attachment from email through to host execution.",
    "delivery:supply_chain":          "Spot phishing that arrives from a trusted or compromised partner.",
    "watering_hole:malware_delivery": "Trace drive-by malware served from a compromised website.",
    "watering_hole:phishing":         "Trace credential phishing served from a watering-hole site.",
    "identity:password_spray":        "Detect password spraying across many accounts in the auth logs.",
    "identity:kerberoasting":         "Detect Kerberoasting from RC4 service-ticket requests (Event ID 4769).",
    "recon:browsing":                 "Spot external reconnaissance against the company's web presence.",
    "discovery:automated_recon":      "Recognize bursts of host/domain discovery commands.",
    "execution:psexec_lateral":       "Follow lateral movement via PsExec service installs (7045) over SMB.",
    "evasion:log_clearing":           "Recognize event-log clearing (1102/104) and pivot around the blind spot.",
    "persistence:scheduled_task":     "Find scheduled-task persistence created with schtasks.exe.",
    "persistence:registry_run":       "Find Run/RunOnce registry-key persistence.",
    "hands_on_keyboard:operator":     "Reconstruct an operator's hands-on-keyboard activity on a host.",
    "exfiltration:email_collection":  "Trace stolen-credential mailbox access and bulk mail exfiltration.",
    "cloud:session_hijacking":        "Catch impossible-travel sign-ins from a stolen session.",
    "cloud:token_theft":              "Catch a stolen access token replayed from another country.",
    "cloud:exfiltration_via_storage": "Detect a storage bucket flipped public and then mass-read.",
}

# Kill-chain order for laying out an actor's campaign timeline.
_PHASE_ORDER = [
    "Delivery / Initial Access",
    "Credential Access",
    "Discovery",
    "Execution / Hands-on-Keyboard",
    "Lateral Movement",
    "Defense Evasion",
    "Persistence",
    "Collection / Exfiltration",
    "Cloud",
]


def _techniques_for(attacks, get_spec):
    """[{id,name,phase}] for the actor's attacks, in kill-chain order, de-duped."""
    techs, seen = [], set()
    for atk in attacks or []:
        spec = get_spec(atk)
        if not spec or atk in seen:
            continue
        seen.add(atk)
        techs.append({"id": spec.attack_id, "name": spec.attack_name, "phase": spec.phase})
    techs.sort(key=lambda t: (_PHASE_ORDER.index(t["phase"]) if t["phase"] in _PHASE_ORDER else 99,
                              t["id"]))
    return techs


def _objectives_for(attacks):
    """Distinct learning objectives for a set of attacks, stable order."""
    out = []
    for atk in attacks or []:
        obj = LEARNING_OBJECTIVES.get(atk)
        if obj and obj not in out:
            out.append(obj)
    return out


def build_game_guide(company, actors, challenges, include_answers=False, get_spec=None) -> str:
    """
    Render the guide as Markdown.

    company    : {name, domain, count_employees, activity_start_date, activity_end_date}
    actors     : [{name, attribution, aliases, attack_group_id, report_url,
                   activity_start_date, activity_end_date, attacks,
                   ips, domains, sender_emails, malware}]
    challenges : [{name, category, value, description, answer}]  (used for the answer key)
    include_answers : False -> player intel brief; True -> instructor key.
    """
    if get_spec is None:
        from app.server.modules.attacks.attack_registry import get_spec as _gs
        get_spec = _gs
    company = company or {}
    actors = actors or []
    challenges = challenges or []

    L = []
    variant = "Instructor Key" if include_answers else "Player Intel Brief"
    title = company.get("name") or "KC7"
    L.append("# %s — Threat Investigation Guide" % title)
    L.append("**%s**" % variant)
    L.append("")

    # --- Scenario brief (config-generated narrative; no summary.txt dependence) ---
    L.append("## Scenario brief")
    window = "%s to %s" % (company.get("activity_start_date", "?"),
                           company.get("activity_end_date", "?"))
    L.append("You are investigating suspicious activity in the environment of "
             "**%s** (`%s`), an organization of roughly %s employees, over the activity "
             "window **%s**. Work the telemetry in Azure Data Explorer to uncover what "
             "happened and answer the challenges." % (
                 company.get("name", "the company"), company.get("domain", "—"),
                 company.get("count_employees", "—"), window))
    L.append("")
    L.append("- **Adversaries in play:** %d" % len(actors))
    L.append("- **Challenges:** %d" % len(challenges))
    L.append("")

    # --- Learning objectives (union across all actors' techniques) ---
    all_attacks = []
    for a in actors:
        for atk in a.get("attacks") or []:
            if atk not in all_attacks:
                all_attacks.append(atk)
    objectives = _objectives_for(all_attacks)
    if objectives:
        L.append("## Learning objectives")
        L.append("By the end of this exercise you should be able to:")
        for o in objectives:
            L.append("- %s" % o)
        L.append("")

    # --- Actor cast ---
    if include_answers:
        L.append("## Threat landscape (instructor reference)")
        for a in actors:
            heading = a.get("name", "Unknown actor")
            bits = []
            if a.get("attribution"):
                bits.append(a["attribution"])
            if a.get("aliases"):
                bits.append("aka " + ", ".join(a["aliases"]))
            if a.get("attack_group_id"):
                bits.append(a["attack_group_id"])
            if bits:
                heading += "  —  " + " · ".join(bits)
            L.append("### %s" % heading)

            # campaign timeline
            aw = "%s to %s" % (a.get("activity_start_date", "?"), a.get("activity_end_date", "?"))
            techs = _techniques_for(a.get("attacks"), get_spec)
            L.append("**Campaign window:** %s" % aw)
            if techs:
                phases = []
                for t in techs:
                    if t["phase"] not in phases:
                        phases.append(t["phase"])
                L.append("")
                L.append("**Kill-chain path:** " + " → ".join(phases))
                L.append("")
                L.append("| ATT&CK | Technique | Phase |")
                L.append("| --- | --- | --- |")
                for t in techs:
                    L.append("| %s | %s | %s |" % (t["id"], t["name"], t["phase"]))
            # indicators of compromise
            iocs = []
            if a.get("ips"):
                iocs.append("**IPs:** " + ", ".join(a["ips"][:20]))
            if a.get("domains"):
                iocs.append("**Domains:** " + ", ".join(a["domains"][:20]))
            if a.get("sender_emails"):
                iocs.append("**Phishing senders:** " + ", ".join(a["sender_emails"][:20]))
            if a.get("malware"):
                iocs.append("**Malware:** " + ", ".join(a["malware"]))
            if iocs:
                L.append("")
                L.append("**Indicators of compromise**  ")
                for i in iocs:
                    L.append("- " + i)
            L.append("")
    else:
        # player view: set expectations without spoiling attribution / IOCs
        L.append("## What you'll investigate")
        L.append("Adversary activity in this scenario spans the following stages — your job "
                 "is to find the evidence for each in the logs:")
        phases = []
        for t in _techniques_for(all_attacks, get_spec):
            if t["phase"] not in phases:
                phases.append(t["phase"])
        for p in phases:
            L.append("- %s" % p)
        L.append("")

    # --- Challenges ---
    L.append("## Challenges")
    if include_answers:
        L.append("_Accepted answers in **bold**; `;`-separated alternatives are all accepted "
                 "(case-insensitive, with indicator normalization)._")
    by_cat, order = {}, []
    for ch in challenges:
        cat = ch.get("category") or "General"
        if cat not in by_cat:
            by_cat[cat] = []
            order.append(cat)
        by_cat[cat].append(ch)
    total = 0
    for cat in order:
        L.append("")
        L.append("### %s" % cat)
        for ch in by_cat[cat]:
            pts = ch.get("value", 0) or 0
            total += pts
            L.append("- **%s** (%d pts) — %s" % (ch.get("name", "Untitled"), pts,
                                                 ch.get("description", "")))
            if include_answers:
                ans = " ; ".join(s.strip() for s in str(ch.get("answer") or "").split(";") if s.strip())
                L.append("  - **Answer:** %s" % (ans or "—"))
    if not challenges:
        L.append("")
        L.append("_No challenges defined yet — run a game and auto-generate challenges first._")
    L.append("")
    L.append("---")
    L.append("_%d challenge(s) · %d total points._" % (len(challenges), total))
    return "\n".join(L)


def gather_guide_facts():
    """
    Collect (company, actors, challenges) from the live DB / configs for the guide.
    Reuses the #11 fact gatherer for IOCs/attribution and challenge generation.
    Returns (company_dict, actor_dicts, challenge_dicts).
    """
    from app.server.modules.organization.Company import Company
    from app.server.modules.actors.Actor import Actor
    from app.server.modules.challenge_gen.challenge_generator import (
        gather_scenario_facts, build_challenges,
    )

    company = Company.query.first()
    company_dict = {}
    if company:
        company_dict = {
            "name": company.name,
            "domain": company.domain,
            "count_employees": company.count_employees,
            "activity_start_date": company.activity_start_date,
            "activity_end_date": company.activity_end_date,
        }

    actor_facts, malware_by_name = gather_scenario_facts()
    # add per-actor activity window (not part of the #11 facts) for the timeline
    window_by_name = {}
    for a in Actor.query.filter(Actor.name != "Default").all():
        window_by_name[a.name] = (getattr(a, "activity_start_date", None),
                                  getattr(a, "activity_end_date", None))
    for af in actor_facts:
        start, end = window_by_name.get(af.get("name"), (None, None))
        af["activity_start_date"] = start
        af["activity_end_date"] = end

    challenges = build_challenges(actor_facts, malware_by_name=malware_by_name)
    return company_dict, actor_facts, challenges
