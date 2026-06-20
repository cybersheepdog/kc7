"""
Scenario document generator.

Assembles the scenario framing (company profile, the actors in play and their ATT&CK
techniques) plus the challenge set into a polished PDF, in two variants:

  - player packet      (include_answers=False): narrative + questions, no answers
  - instructor key     (include_answers=True):  adds the threat landscape (actors +
                       ATT&CK techniques) and the accepted answer(s) for each challenge

Design:
  - ``build_scenario_pdf(scenario, include_answers)`` is pure: it takes a plain dict
    (no DB / Flask imports) and returns PDF bytes. This makes it unit-testable and
    reusable from a CLI as well as the admin route.
  - ``build_scenario_dict(round_id)`` pulls the dict from the live models + attack
    registry (lazy imports, only used by the route).
  - ReportLab is imported lazily inside ``build_scenario_pdf`` and guarded, so a missing
    package surfaces a clear message instead of breaking app import.

ReportLab note: never use Unicode sub/superscript glyphs (they render as black boxes);
not needed here.
"""

from io import BytesIO
from xml.sax.saxutils import escape


class PdfDependencyMissing(RuntimeError):
    """Raised when the optional PDF library is not installed."""
    pass


def _para(text, style):
    """Escape arbitrary text and wrap it in a ReportLab Paragraph."""
    from reportlab.platypus import Paragraph
    return Paragraph(escape("" if text is None else str(text)), style)


def build_scenario_pdf(scenario: dict, include_answers: bool = False) -> bytes:
    """
    Render a scenario dict to PDF bytes.

    scenario = {
        "title": str,
        "generated_at": str,
        "company": {"name","domain","activity_start_date","activity_end_date",
                    "count_employees", ...},
        "narrative": str,                # optional
        "actors": [{"name": str,
                    "attribution": str,  # optional (e.g. "APT29 / Cozy Bear")
                    "techniques": [{"id","name","phase"}]}],
        "challenges": [{"name","category","value","description","answer","round"}],
    }
    """
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle, HRFlowable,
        )
    except ImportError as e:
        raise PdfDependencyMissing(
            "PDF export requires the 'reportlab' package. Install it with: "
            "pip install reportlab"
        ) from e

    scenario = scenario or {}
    company = scenario.get("company") or {}
    actors = scenario.get("actors") or []
    challenges = scenario.get("challenges") or []

    # ---- styles ----
    styles = getSampleStyleSheet()
    h1 = styles["Heading1"]
    h2 = styles["Heading2"]
    h3 = styles["Heading3"]
    body = styles["BodyText"]
    title_style = ParagraphStyle("kc7title", parent=styles["Title"], fontSize=24, spaceAfter=6)
    banner_style = ParagraphStyle(
        "kc7banner", parent=styles["Title"], fontSize=13, textColor=colors.HexColor("#b00020"),
        spaceBefore=2, spaceAfter=18,
    )
    small = ParagraphStyle("kc7small", parent=body, fontSize=8, textColor=colors.grey)
    q_style = ParagraphStyle("kc7q", parent=body, spaceBefore=2, spaceAfter=2)
    ans_style = ParagraphStyle(
        "kc7ans", parent=body, textColor=colors.HexColor("#0b6b3a"), leftIndent=10, spaceAfter=8,
    )

    story = []

    # ---- title / banner ----
    story.append(_para(scenario.get("title") or "KC7 Cybersecurity Scenario", title_style))
    variant = "INSTRUCTOR ANSWER KEY" if include_answers else "PLAYER CHALLENGE PACKET"
    story.append(_para(variant, banner_style))
    if scenario.get("generated_at"):
        story.append(_para("Generated " + str(scenario["generated_at"]), small))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 14))

    # ---- scenario brief ----
    story.append(_para("Scenario Brief", h2))
    if company:
        rows = [
            ["Organization", company.get("name", "—")],
            ["Domain", company.get("domain", "—")],
            ["Employees", str(company.get("count_employees", "—"))],
            ["Activity window",
             f"{company.get('activity_start_date', '?')} to {company.get('activity_end_date', '?')}"],
        ]
        t = Table([[_para(k, body), _para(v, body)] for k, v in rows], colWidths=[1.6 * inch, 4.4 * inch])
        t.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#dddddd")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f4f4f4")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t)
        story.append(Spacer(1, 10))
    if scenario.get("narrative"):
        story.append(_para(scenario["narrative"], body))
        story.append(Spacer(1, 8))

    # ---- threat landscape (instructor key only — would otherwise give away attribution) ----
    if include_answers and actors:
        story.append(Spacer(1, 6))
        story.append(_para("Threat Landscape (instructor reference)", h2))
        for actor in actors:
            heading = actor.get("name", "Unknown actor")
            if actor.get("attribution"):
                heading += f"  —  {actor['attribution']}"
            story.append(_para(heading, h3))
            techs = actor.get("techniques") or []
            if techs:
                header = [_para("ATT&CK", small), _para("Technique", small), _para("Phase", small)]
                data = [header] + [
                    [_para(tt.get("id", ""), body), _para(tt.get("name", ""), body), _para(tt.get("phase", ""), body)]
                    for tt in techs
                ]
                tbl = Table(data, colWidths=[0.9 * inch, 3.3 * inch, 1.8 * inch])
                tbl.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eeeeee")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#dddddd")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]))
                story.append(tbl)
            story.append(Spacer(1, 8))

    story.append(PageBreak())

    # ---- challenges, grouped by category ----
    story.append(_para("Challenges", h1))
    if include_answers:
        story.append(_para("Accepted answers are shown in green. Multiple accepted answers are "
                           "separated by semicolons; answers are matched case-insensitively and "
                           "with indicator normalization (defang / scheme / trailing slash).", small))
    story.append(Spacer(1, 8))

    grouped = {}
    order = []
    for ch in challenges:
        cat = ch.get("category") or "General"
        if cat not in grouped:
            grouped[cat] = []
            order.append(cat)
        grouped[cat].append(ch)

    if not challenges:
        story.append(_para("No challenges are defined for this scenario yet.", body))

    total_points = 0
    for cat in order:
        story.append(_para(cat, h2))
        for ch in grouped[cat]:
            pts = ch.get("value", 0) or 0
            total_points += pts
            rnd = ch.get("round")
            rnd_txt = f"  ·  Round: {rnd}" if rnd else ""
            story.append(_para(f"<b>{escape(str(ch.get('name','Untitled')))}</b>  "
                               f"<font color='#666666'>({pts} pts{escape(rnd_txt)})</font>",
                               q_style))
            if ch.get("description"):
                story.append(_para(ch["description"], q_style))
            if include_answers:
                ans = ch.get("answer") or ""
                accepted = " ; ".join(a.strip() for a in str(ans).split(";") if a.strip())
                story.append(_para("Answer: " + (accepted or "—"), ans_style))
            else:
                story.append(_para("Answer: ______________________________", q_style))
            story.append(Spacer(1, 4))
        story.append(Spacer(1, 6))

    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))
    story.append(_para(f"{len(challenges)} challenge(s) · {total_points} total points", small))

    # ---- build ----
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        leftMargin=0.9 * inch, rightMargin=0.9 * inch,
        topMargin=0.8 * inch, bottomMargin=0.8 * inch,
        title=(scenario.get("title") or "KC7 Scenario"),
    )
    doc.build(story)
    return buf.getvalue()


def build_scenario_dict(round_id=None) -> dict:
    """
    Assemble a scenario dict from the live models + attack registry.
    Lazy-imports app modules so this file stays import-light.
    """
    import os
    from datetime import datetime

    from app.server.models import Challenge, GameRound
    from app.server.modules.organization.Company import Company
    from app.server.modules.actors.Actor import Actor
    from app.server.modules.attacks.attack_registry import get_spec

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

    # Attribution metadata lives in the YAML configs (not the DB model) — load it by name.
    import glob
    import yaml
    attribution_by_name = {}
    for path in glob.glob("app/game_configs/actors/*.yaml"):
        try:
            with open(path) as fh:
                cfg = yaml.safe_load(fh) or {}
            if isinstance(cfg, dict) and cfg.get("name"):
                attribution_by_name[cfg["name"]] = cfg
        except Exception:
            pass

    # Actors + their ATT&CK techniques (from the registry)
    actors = []
    for actor in Actor.query.filter(Actor.name != "Default").all():
        techniques = []
        for attack in actor.get_attacks():
            spec = get_spec(attack)
            if spec:
                techniques.append({"id": spec.attack_id, "name": spec.attack_name, "phase": spec.phase})
        cfg = attribution_by_name.get(actor.name, {})
        attribution = None
        if cfg.get("attribution") or cfg.get("aliases"):
            akas = (" / " + " / ".join(cfg.get("aliases") or [])) if cfg.get("aliases") else ""
            motiv = (" — " + cfg["motivation"]) if cfg.get("motivation") else ""
            attribution = (cfg.get("attribution") or actor.name) + akas + motiv
        actors.append({"name": actor.name, "attribution": attribution, "techniques": techniques})

    # Challenges (optionally scoped to a round)
    q = Challenge.query
    if round_id not in (None, "", "-1"):
        q = q.filter(Challenge.round_id == int(round_id))
    challenges = []
    for ch in q.all():
        rnd_name = None
        if ch.round_id:
            rnd = GameRound.query.get(ch.round_id)
            rnd_name = rnd.name if rnd else None
        challenges.append({
            "name": ch.name,
            "category": ch.category,
            "value": ch.value,
            "description": ch.description,
            "answer": ch.answer,
            "round": rnd_name,
        })

    # Narrative: prefer a live summary file if present
    narrative = ""
    summary_path = "app/game_configs/summary.txt"
    if os.path.exists(summary_path):
        try:
            with open(summary_path, "r") as fh:
                narrative = fh.read().strip()
        except Exception:
            narrative = ""

    title = f"{company_dict.get('name', 'KC7')} — Threat Investigation Scenario"
    return {
        "title": title,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "company": company_dict,
        "narrative": narrative,
        "actors": actors,
        "challenges": challenges,
    }
