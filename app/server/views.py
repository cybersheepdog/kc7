
import json
import random
import threading
import yaml
from datetime import datetime
from flask_login import login_required, current_user
from flask_security import roles_required

from flask import Blueprint, request, render_template, \
    flash, g, session, redirect, url_for, abort, current_app, jsonify
from sqlalchemy import asc
from sqlalchemy.sql.expression import func, select

# Import module models (i.e. Company, Employee, Actor, DNSRecord)
from app.server.models import db, Team, Users, Roles, GameSession, Report, Challenge, Solve, AnswerAttempt, GameRound, Participation, MaliciousIndicator, ADXConfig
from app.server.modules.audit.audit_log import record_admin_action
from app.server.modules.organization.Company import Company, Employee
from app.server.modules.clock.Clock import Clock
from app.server.modules.logging.uploadLogs import LogUploader
from app.server.modules.email.email_controller import gen_email
from app.server.modules.infrastructure.DNSRecord import DNSRecord
from app.server.modules.infrastructure.Infrastructure import Domain, IP
from app.server.modules.outbound_browsing.browsing_controller import *
from app.server.modules.outbound_browsing.browsing_controller import browse_random_website
from app.server.modules.infrastructure.passiveDNS_controller import *
from app.server.utils import *

from app.server.game_functions import *

POINTS_PER_INDICATOR = 100       # base score per correct new malicious indicator
TIME_BONUS_WINDOW_HOURS = 24.0   # over this many real hours the speed bonus decays to zero


def calculate_time_weighted_points(base_points, game_session):
    """
    Returns base_points plus a speed bonus that decays linearly over
    TIME_BONUS_WINDOW_HOURS of real-world time since the game started.
    At t=0:  2x base_points (full bonus).
    At t=24h: 1x base_points (no bonus).
    """
    try:
        if not game_session or not game_session.start_time:
            return base_points
        raw = game_session.start_time
        if isinstance(raw, str):
            game_start = datetime.fromisoformat(str(raw).split(".")[0])
        elif isinstance(raw, datetime):
            game_start = raw
        else:
            return base_points
        elapsed_hours = (datetime.now() - game_start).total_seconds() / 3600.0
        decay = max(0.0, 1.0 - elapsed_hours / TIME_BONUS_WINDOW_HOURS)
        return base_points + int(base_points * decay)
    except Exception as e:
        print("calculate_time_weighted_points: " + str(e))
        return base_points


def calculate_round_time_weighted_points(base_points, game_round, solved_at=None):
    """
    Per-challenge time-weighted scoring within a round's time window.

    Each challenge is scored independently: the earlier within the round
    window it is answered, the higher the points.

    At t=start_time:  2x base_points (full bonus).
    At t=end_time:    1x base_points (no bonus).
    Linear decay in between.

    Falls back to base_points if the round has no timer or no start_time.
    """
    try:
        if not game_round or not game_round.uses_timer:
            return base_points
        if not game_round.start_time or not game_round.end_time:
            return base_points
        now = solved_at or datetime.now()
        window_secs = (game_round.end_time - game_round.start_time).total_seconds()
        if window_secs <= 0:
            return base_points
        elapsed_secs = (now - game_round.start_time).total_seconds()
        fraction = max(0.0, min(1.0, elapsed_secs / window_secs))
        decay = 1.0 - fraction          # 1.0 at start, 0.0 at end
        return base_points + int(base_points * decay)
    except Exception as e:
        print("calculate_round_time_weighted_points: " + str(e))
        return base_points


def get_malicious_indicators():
    """
    Build and return the complete set of ground-truth malicious indicators
    (lowercase) that players should be blocking.
    Sources: actor domains, IPs, sender emails, malware hashes.
    """
    indicators = set()

    try:
        malicious_actors = Actor.query.filter(Actor.name != "Default").all()
        for actor in malicious_actors:
            for domain in actor.domains:
                indicators.add(domain.name.lower())
            for ip in actor.ips:
                indicators.add(ip.address.lower())
            for email in Actor.string_to_list(actor.sender_emails):
                if email:
                    indicators.add(email.lower())
    except Exception as e:
        print("get_malicious_indicators: error querying actors -- " + str(e))

    try:
        from app.server.game_functions import MALWARE_OBJECTS
        for malware in MALWARE_OBJECTS:
            for hash_val in malware.hashes:
                if hash_val:
                    indicators.add(hash_val.lower())
    except Exception as e:
        print("get_malicious_indicators: error reading malware hashes -- " + str(e))

    # Third source: manually-seeded indicators from admin form
    try:
        seeded = MaliciousIndicator.query.all()
        for ind in seeded:
            indicators.add(ind.value.lower())
    except Exception as e:
        print("get_malicious_indicators: error reading seeded indicators -- " + str(e))

    return indicators


# Define the blueprint: main, set its url prefix: app.url/
main = Blueprint("main", __name__)


@main.route("/")
def home():
    if current_user.is_authenticated:
        return render_template("main/score.html")
    return redirect(url_for("auth.login"))


@main.route("/admin/manage_game")
@roles_required("Admin")
@login_required
def manage_game():
    """Manage the state of the game."""
    current_session = db.session.get(GameSession, 1)
    game_state = current_session.state

    if current_user.username == "admin" and current_user.check_password("admin"):
        flash(
            "Security warning: you are using the default admin password (admin). "
            "Please change it or set KC7_ADMIN_PASSWORD before going live.",
            "warning"
        )

    return render_template("admin/manage_game.html", game_state=game_state,
                           game_session=current_session,
                           now=datetime.now())


@main.route("/admin/manage_database")
@roles_required("Admin")
@login_required
def manage_database():
    perms = []
    adx_error = None
    try:
        log_uploader = LogUploader()
        perms = log_uploader.get_user_permissions()
    except Exception as e:
        adx_error = str(e)
        print("manage_database: ADX unavailable --", adx_error)
    return render_template("admin/manage_database.html", perms=perms, adx_error=adx_error)


def _run_game_in_background(app):
    """Run start_game() in a background thread with its own app context."""
    with app.app_context():
        start_game()


@main.route("/admin/start_game", methods=["GET"])
@roles_required("Admin")
@login_required
def call_start():
    """Spawn a background thread to run the game. Returns immediately."""
    from app.server.game_functions import GAME_PROGRESS
    if GAME_PROGRESS.get("running"):
        return jsonify({"STATE": True, "message": "Game is already running"})

    app = current_app._get_current_object()
    thread = threading.Thread(target=_run_game_in_background, args=(app,), daemon=True)
    thread.start()
    record_admin_action("game.start", detail="Started data generation")
    return jsonify({"STATE": True})


@main.route("/admin/game_status", methods=["GET"])
@roles_required("Admin")
@login_required
def game_status():
    """Returns current progress of the game generation loop for the admin UI."""
    from app.server.game_functions import GAME_PROGRESS

    progress_pct = 0
    if GAME_PROGRESS.get("start_date") and GAME_PROGRESS.get("end_date") and GAME_PROGRESS.get("current_date"):
        from datetime import date
        try:
            start   = date.fromisoformat(GAME_PROGRESS["start_date"])
            end     = date.fromisoformat(GAME_PROGRESS["end_date"])
            current = date.fromisoformat(GAME_PROGRESS["current_date"])
            total_days = (end - start).days or 1
            elapsed_days = (current - start).days
            progress_pct = min(100, int(elapsed_days / total_days * 100))
        except Exception:
            pass

    # live per-table ingested-row counts from the active uploader (#28)
    table_counts = {}
    try:
        from app.server.game_functions import LOG_UPLOADER
        table_counts = dict(LOG_UPLOADER.row_counts)
    except Exception:
        table_counts = {}

    return jsonify({
        "running":      GAME_PROGRESS.get("running", False),
        "complete":     GAME_PROGRESS.get("complete", False),
        "cancelled":    GAME_PROGRESS.get("cancelled", False),
        "current_date": GAME_PROGRESS.get("current_date"),
        "start_date":   GAME_PROGRESS.get("start_date"),
        "end_date":     GAME_PROGRESS.get("end_date"),
        "error":        GAME_PROGRESS.get("error"),
        "progress_pct": progress_pct,
        "log":          GAME_PROGRESS.get("log", [])[-15:],
        "table_counts": table_counts,
    })


@main.route("/admin/stop_game", methods=["GET"])
@roles_required("Admin")
@login_required
def stop_game():
    print("Stopping the game")
    # Ask a running generation loop to halt at the next day boundary (#28)
    from app.server.game_functions import GAME_PROGRESS
    GAME_PROGRESS["cancel_requested"] = True
    current_session = db.session.get(GameSession, 1)
    current_session.state = False
    db.session.commit()
    record_admin_action("game.stop", detail="Requested generation halt")
    flash("The game has been Stopped")
    return jsonify({"STATE": current_session.state})


@main.route("/admin/restart_game", methods=["GET"])
@roles_required("Admin")
@login_required
def restart_game():
    print("Restarting the game")
    current_session = db.session.get(GameSession, 1)
    current_session.state = False
    current_session.start_time = datetime.now()

    teams = Team.query.all()
    for team in teams:
        print("Resetting team scores")
        team.score = 0
        team.last_score_time = None
        print("Resetting team mitigations")
        team._mitigations = ""

    for user in Users.query.all():
        user.score = 0
        user.last_score_time = None

    db.session.query(Solve).delete()
    db.session.query(DNSRecord).delete()
    db.session.query(Actor).delete()
    db.session.query(Employee).delete()
    db.session.query(Company).delete()
    db.session.commit()
    record_admin_action("game.restart", detail="Reset game: cleared scores, solves, and generated data")
    flash("The game has been reset", "success")

    return jsonify({"STATE": current_session.state})


@main.route("/admin/teams")
@roles_required("Admin")
@login_required
def manage_teams():
    team_list = Team.query.all()
    return render_template("admin/manage_teams.html", teams=team_list)


@main.route("/admin/users")
@roles_required("Admin")
@login_required
def manage_users():
    user_list = Users.query.order_by(Users.username).all()
    team_list = Team.query.order_by(Team.name).all()
    role_list = Roles.query.all()
    return render_template("admin/manage_users.html",
                           users=user_list, teams=team_list, roles=role_list)


@main.route("/mitigations")
@login_required
def mitigations():
    """Users can view and apply mitigations from this page."""
    return render_template("main/mitigations.html")


@main.route("/getDenyList", methods=["GET"])
@login_required
def get_deny_list():
    """Return the team deny list."""
    return jsonify(current_user.team._mitigations)


@main.route("/updateDenyList", methods=["POST"])
@login_required
def update_deny_list():
    """
    Score newly submitted indicators against the ground-truth malicious set.
    Points are time-weighted: up to 2x base points at game start, decaying over 24h.
    Both the individual player and their team are credited with the same points.
    Returns: success, points_earned, total_score, user_score, correct_indicators.
    """
    try:
        deny_list = request.form["dlist"]

        # Reject scoring if the session timer has expired
        _gs = db.session.get(GameSession, 1)
        if _gs and _gs.uses_timer and _gs.end_time and datetime.now() > _gs.end_time:
            return jsonify(success=False, points_earned=0, total_score=current_user.team.score or 0,
                           user_score=current_user.score or 0, correct_indicators=[],
                           timer_expired=True)

        newline = chr(10)
        new_indicators = set(x.strip().lower() for x in deny_list.split(newline) if x.strip())

        try:
            old_raw = current_user.team._mitigations or "[]"
            old_indicators = set(x.lower() for x in __import__('json').loads(old_raw))
        except (ValueError, TypeError):
            old_indicators = set()

        newly_added = new_indicators - old_indicators
        # Normalize both sides (refang, strip URL scheme/trailing slash, etc.) so a
        # defanged submission like "bad[.]com" or "hxxp://bad.com/" still scores.
        # Normalizing both sides can only add matches, never drop a previously-correct one.
        from app.server.modules.scoring.answer_matching import normalize_answer
        malicious = get_malicious_indicators()
        malicious_normalized = {normalize_answer(m) for m in malicious}
        correct_new = [ind for ind in newly_added if normalize_answer(ind) in malicious_normalized]

        game_session = db.session.get(GameSession, 1)
        points_per_correct = calculate_time_weighted_points(POINTS_PER_INDICATOR, game_session)
        points_earned = len(correct_new) * points_per_correct

        now = datetime.now()
        if points_earned > 0:
            current_user.score = (current_user.score or 0) + points_earned
            current_user.last_score_time = now
            current_user.team.score = (current_user.team.score or 0) + points_earned
            # Tie-break consistency: update on every score (same rule as players) so
            # equal team scores rank by who reached that total first.
            current_user.team.last_score_time = now
            # Record each correct indicator as a per-award row so scores stay exactly
            # recomputable (the indicator equivalent of a Solve record).
            from app.server.models import MitigationAward
            for _ind in correct_new:
                db.session.add(MitigationAward(
                    user_id=current_user.id,
                    team_id=current_user.team_id,
                    indicator=_ind,
                    points_awarded=points_per_correct,
                ))
            print("User " + current_user.username + " +" + str(points_earned) + " pts, "
                  + str(len(correct_new)) + " indicators @ " + str(points_per_correct))

        display_list = [x.strip() for x in deny_list.split(chr(10)) if x.strip()]
        current_user.team._mitigations = json.dumps(display_list)
        db.session.commit()

        return jsonify(
            success=current_user.team._mitigations,
            points_earned=points_earned,
            total_score=current_user.team.score,
            user_score=current_user.score,
            correct_indicators=correct_new,
        )
    except Exception as e:
        print(e)
        return jsonify(success=False, points_earned=0, total_score=0, user_score=0, correct_indicators=[])


@main.route("/updatePermissions", methods=["POST"])
@roles_required("Admin")
@login_required
def update_permissions():
    """Update ADX user permissions."""
    try:
        permissions_list = request.form["plist"]
        log_uploader = LogUploader()
        user_strings = [x for x in permissions_list.split(chr(10)) if x]
        for user_string in user_strings:
            log_uploader.add_user_permissions(user_string)
        return jsonify(success=True)
    except Exception as e:
        print(e)
        flash("Error updating ADX Permissions: ", "error")
        return jsonify(success=False)


@login_required
@main.route("/deluser", methods=["GET", "POST"])
def deluser():
    """Delete a user."""
    try:
        user_id = request.form["user_id"]
        user = db.session.get(Users, int(user_id))
        db.session.delete(user)
        db.session.commit()
        flash("User removed!", "success")
    except Exception as e:
        print("Error: %s" % e)
        flash("Failed to remove user", "error")
    return redirect(url_for("main.manage_users"))


@login_required
@roles_required("Admin")
@main.route("/admin/edit_user", methods=["POST"])
def edit_user():
    """Edit a user: password reset, role toggle, team change."""
    try:
        user_id   = int(request.form.get("user_id", 0))
        new_pass  = request.form.get("new_password", "").strip()
        new_role  = request.form.get("role", "").strip()        # "Admin" or "Player"
        new_team  = request.form.get("team_id", "").strip()     # team id or ""

        user = db.session.get(Users, user_id)
        if not user:
            flash("User not found.", "error")
            return redirect(url_for("main.manage_users"))

        # --- Password reset ---
        if new_pass:
            user.set_password(new_pass)

        # --- Role toggle ---
        if new_role in ("Admin", "Player"):
            admin_role  = Roles.query.filter_by(name="Admin").first()
            player_role = Roles.query.filter_by(name="Player").first()
            if new_role == "Admin":
                if admin_role and admin_role not in user.roles:
                    user.roles.append(admin_role)
                if player_role and player_role in user.roles:
                    user.roles.remove(player_role)
            else:
                if player_role and player_role not in user.roles:
                    user.roles.append(player_role)
                if admin_role and admin_role in user.roles:
                    user.roles.remove(admin_role)

        # --- Team assignment ---
        if new_team == "0" or new_team == "":
            user.team_id = None
        else:
            team = db.session.get(Team, int(new_team))
            if team:
                user.team_id = team.id

        db.session.commit()
        changes = []
        if new_pass:
            changes.append("password reset")
        if new_role in ("Admin", "Player"):
            changes.append(f"role={new_role}")
        changes.append("team=" + (new_team or "none"))
        record_admin_action("user.edit", target=user.username, detail="; ".join(changes))
        flash(f"User '{user.username}' updated.", "success")
    except Exception as e:
        db.session.rollback()
        print("edit_user error:", e)
        flash("Failed to update user: " + str(e), "error")
    return redirect(url_for("main.manage_users"))


@main.route("/admin/add_user", methods=["POST"])
@login_required
@roles_required("Admin")
def add_user():
    """Admin-side user creation."""
    username  = request.form.get("username",  "").strip()
    email     = request.form.get("email",     "").strip()
    password  = request.form.get("password",  "").strip()
    role_name = request.form.get("role",      "Player").strip()
    team_id   = request.form.get("team_id",   "").strip()

    if not username or not email or not password:
        flash("Username, email, and password are all required.", "error")
        return redirect(url_for("main.manage_users"))

    if Users.query.filter_by(username=username).first():
        flash(f"Username '{username}' is already taken.", "error")
        return redirect(url_for("main.manage_users"))

    if Users.query.filter_by(email=email).first():
        flash(f"Email '{email}' is already registered.", "error")
        return redirect(url_for("main.manage_users"))

    try:
        team = db.session.get(Team, int(team_id)) if team_id else None
        new_user = Users(username=username, password=password, email=email, team=team)

        role = Roles.query.filter_by(name=role_name).first()
        if role:
            new_user.roles = [role]

        db.session.add(new_user)
        db.session.commit()
        record_admin_action("user.create", target=username, detail=f"role={role_name}")
        flash(f"User '{username}' created successfully.", "success")
    except Exception as e:
        db.session.rollback()
        print("add_user error:", e)
        flash("Failed to create user: " + str(e), "error")

    return redirect(url_for("main.manage_users"))


@login_required
@main.route("/delreport", methods=["GET", "POST"])
def delreport():
    """Delete a report."""
    try:
        report_id = request.form["report_id"]
        report = db.session.get(Report, int(report_id))
        db.session.delete(report)
        db.session.commit()
        flash("Report removed!", "success")
    except Exception as e:
        print("Error: %s" % e)
        flash("Failed to remove report", "error")
    return redirect(url_for("main.reports"))


@main.route("/teams")
@login_required
def teams():
    team_list = Team.query.filter(Team.id != 1).all()
    return render_template("main/teams.html", teams=team_list)


@login_required
@main.route("/delteam", methods=["GET", "POST"])
def delteam():
    """Delete a team."""
    try:
        team_id = request.form["team_id"]
        team = db.session.get(Team, int(team_id))
        db.session.delete(team)
        db.session.commit()
        flash("Team removed!", "success")
    except Exception as e:
        print("Error: %s" % e)
        flash("Failed to remove team", "error")
    return redirect(url_for("main.manage_teams"))


@main.route("/create_team", methods=["POST"])
@login_required
@roles_required("Admin")
def create_team():
    try:
        team_name = request.form["team_name"]
        team = Team(name=team_name, score=0)
        db.session.add(team)
        db.session.commit()
    except Exception as e:
        print("Failed to create team.", e)
        flash("Could not create this team!", "error")
    flash("Added a new team", "success")
    return redirect(url_for("main.manage_teams"))


@main.route("/admin/import_teams_csv", methods=["POST"])
@login_required
@roles_required("Admin")
def import_teams_csv():
    """Admin: bulk-create teams from a CSV file.
    Expected column (header optional): name
    Skips teams whose names already exist.
    """
    import csv, io
    try:
        f = request.files.get("csv_file")
        if not f or not f.filename:
            flash("No file selected.", "error")
            return redirect(url_for("main.manage_teams"))

        stream  = io.StringIO(f.stream.read().decode("utf-8-sig"), newline=None)
        reader  = csv.reader(stream)
        added   = 0
        skipped = 0

        existing = {t.name.lower() for t in Team.query.all()}

        for i, row in enumerate(reader):
            if not row:
                continue
            name = row[0].strip()
            if not name:
                continue
            if i == 0 and name.lower() == "name":
                continue   # skip header
            if name.lower() in existing:
                skipped += 1
                continue
            db.session.add(Team(name=name, score=0))
            existing.add(name.lower())
            added += 1

        db.session.commit()
        flash(f"Imported {added} team(s). Skipped {skipped} duplicate(s).", "success")
    except Exception as e:
        db.session.rollback()
        print("import_teams_csv error:", e)
        flash("CSV import failed: " + str(e), "error")
    return redirect(url_for("main.manage_teams"))


@main.route("/admin/import_users_csv", methods=["POST"])
@login_required
@roles_required("Admin")
def import_users_csv():
    """Admin: bulk-create users from a CSV file.
    Expected columns (header optional):
        username, email, password, team[, role]
    - team: matched by name (case-insensitive); created if it doesn't exist.
    - role: 'Admin' or 'Player' (default: Player).
    Skips rows where username or email already exists.
    """
    import csv, io
    try:
        f = request.files.get("csv_file")
        if not f or not f.filename:
            flash("No file selected.", "error")
            return redirect(url_for("main.manage_users"))

        stream  = io.StringIO(f.stream.read().decode("utf-8-sig"), newline=None)
        reader  = csv.reader(stream)

        # Pre-load lookups
        team_map  = {t.name.lower(): t for t in Team.query.all()}
        role_map  = {r.name.lower(): r for r in Roles.query.all()}
        existing_users  = {u.username.lower() for u in Users.query.all()}
        existing_emails = {u.email.lower() for u in Users.query.all()}

        added   = 0
        skipped = 0

        for i, row in enumerate(reader):
            if len(row) < 4:
                skipped += 1
                continue
            cols = [c.strip() for c in row]
            username, email, password, team_name = cols[:4]
            role_name = cols[4] if len(cols) >= 5 else "Player"

            # Skip header
            if i == 0 and username.lower() == "username":
                continue

            if not username or not email or not password:
                skipped += 1
                continue
            if username.lower() in existing_users or email.lower() in existing_emails:
                skipped += 1
                continue

            # Resolve or create team
            team = None
            if team_name:
                key = team_name.lower()
                if key not in team_map:
                    new_team = Team(name=team_name, score=0)
                    db.session.add(new_team)
                    db.session.flush()   # get the id
                    team_map[key] = new_team
                team = team_map[team_name.lower()]

            # Resolve role
            role = role_map.get(role_name.lower()) or role_map.get("player")

            new_user = Users(username=username, password=password,
                             email=email, team=team)
            if role:
                new_user.roles = [role]
            db.session.add(new_user)

            existing_users.add(username.lower())
            existing_emails.add(email.lower())
            added += 1

        db.session.commit()
        flash(f"Imported {added} user(s). Skipped {skipped} row(s).", "success")
    except Exception as e:
        db.session.rollback()
        print("import_users_csv error:", e)
        flash("CSV import failed: " + str(e), "error")
    return redirect(url_for("main.manage_users"))


# Short, process-wide cache for the leaderboard payload (#27). With live auto-refresh
# (#24) many clients poll /get_score and each SSE connection re-queries every few
# seconds; caching the computed result for a couple of seconds collapses all of that to
# at most one DB read per TTL, regardless of how many viewers are watching. A leaderboard
# that's a second or two stale is fine for a scoreboard.
_LEADERBOARD_CACHE = {"at": 0.0, "data": None}


def _leaderboard_payload(use_cache=True):
    """Cached wrapper around _compute_leaderboard (see #27)."""
    import time as _time
    ttl = 2
    if use_cache:
        try:
            ttl = float(current_app.config.get("LEADERBOARD_CACHE_SECONDS", 2) or 0)
        except Exception:
            ttl = 2
        if ttl > 0:
            c = _LEADERBOARD_CACHE
            if c["data"] is not None and (_time.time() - c["at"]) < ttl:
                return c["data"]
    data = _compute_leaderboard()
    if use_cache and ttl > 0:
        _LEADERBOARD_CACHE["data"] = data
        _LEADERBOARD_CACHE["at"] = _time.time()
    return data


def _compute_leaderboard():
    """
    Compute the leaderboard data for both teams and individual players.
    Excludes the admin team (id=1) and its members.
    Ranking: higher score first; ties broken by who first scored (earlier wins).
    Shared by /get_score (poll) and /score_stream (SSE push) so both rank identically.
    """
    # Team leaderboard
    teams = db.session.query(Team).filter(Team.id != 1).all()
    team_data = [
        {
            "name":  t.name,
            "score": t.score or 0,
            "time":  t.last_score_time.isoformat() if t.last_score_time else None,
        }
        for t in teams
    ]
    team_data.sort(key=lambda x: (-x["score"], x["time"] or "9999-99-99"))

    SCORES = {
        "teams":  [t["name"]  for t in team_data],
        "scores": [t["score"] for t in team_data],
    }

    # Individual leaderboard.
    # Eager-load each player's team to avoid an N+1 query: p.team.name below would
    # otherwise lazy-load the team once per player on every leaderboard poll.
    from sqlalchemy.orm import joinedload
    players = db.session.query(Users).options(joinedload(Users.team)).filter(Users.team_id != 1).all()
    player_data = [
        {
            "username": p.username,
            "team":     p.team.name if p.team else "--",
            "score":    p.score or 0,
            "time":     p.last_score_time.isoformat() if p.last_score_time else None,
        }
        for p in players
    ]
    player_data.sort(key=lambda x: (-x["score"], x["time"] or "9999-99-99"))

    INDIVIDUAL = {
        "players": [p["username"] for p in player_data],
        "scores":  [p["score"]   for p in player_data],
        "teams":   [p["team"]    for p in player_data],
    }

    return {"SCORES": SCORES, "INDIVIDUAL": INDIVIDUAL}


@main.route("/get_score", methods=["GET"])
def get_score():
    """Return leaderboard data as JSON (poll endpoint; the scoreboard polls this)."""
    try:
        payload = _leaderboard_payload()
        return jsonify(SCORES=payload["SCORES"], INDIVIDUAL=payload["INDIVIDUAL"])
    except Exception as e:
        print(e)
        abort(404)


@main.route("/score_stream", methods=["GET"])
def score_stream():
    """
    Server-Sent Events stream that PUSHES leaderboard updates so the room sees movement
    in near-real-time instead of waiting for the next poll (#24).

    Opt-in via LIVE_SCORE_SSE_ENABLED (default off) because a long-lived SSE connection
    needs a threaded/multi-worker server (gunicorn, or Flask run(threaded=True)). When the
    flag is off this returns 204 so the browser's EventSource errors and the scoreboard
    transparently falls back to the existing /get_score polling — nothing is lost.

    The stream only emits when the data actually changes (heartbeats keep the connection
    alive otherwise), reads fresh-committed data each tick, and self-terminates after a
    bounded lifetime so connections recycle (EventSource auto-reconnects).
    """
    if not current_app.config.get("LIVE_SCORE_SSE_ENABLED"):
        return ("", 204)

    from flask import Response, stream_with_context
    import json as _json
    import time as _time

    poll_seconds = float(current_app.config.get("LIVE_SCORE_SSE_POLL_SECONDS", 3) or 3)
    max_lifetime = float(current_app.config.get("LIVE_SCORE_SSE_MAX_SECONDS", 120) or 120)

    @stream_with_context
    def gen():
        last = None
        started = _time.time()
        # advise the client how soon to reconnect after we self-close
        yield "retry: 3000\n\n"
        while _time.time() - started < max_lifetime:
            payload = None
            try:
                # end any open transaction so we read other requests' committed scores
                db.session.remove()
                payload = _leaderboard_payload()
            except Exception as e:
                print(f"score_stream: {e}")
            if payload is not None:
                data = _json.dumps(payload)
                if data != last:
                    last = data
                    yield f"data: {data}\n\n"
                else:
                    yield ": heartbeat\n\n"
            _time.sleep(poll_seconds)

    return Response(
        gen(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # disable proxy buffering (nginx) so events flush
            "Connection": "keep-alive",
        },
    )


def _score_breakdown_payload():
    """
    Richer leaderboard analytics from the Solve log (#25):
      - categories: the challenge categories present, sorted;
      - teams: per-team solved-count by category (progress by kill-chain phase/category);
      - timeline: per-team cumulative score over time (minutes since the first solve),
        for a score-over-time line chart;
      - first_blood: the earliest solve in the game (team, player, challenge, time).
    Admin team (id=1) is excluded. Purely additive — independent of /get_score.
    """
    from app.server.models import Solve, Challenge
    from sqlalchemy.orm import joinedload

    solves = (
        db.session.query(Solve)
        .options(joinedload(Solve.user).joinedload(Users.team), joinedload(Solve.challenge))
        .join(Challenge, Solve.challenge_id == Challenge.id)
        .order_by(Solve.solved_at.asc())
        .all()
    )
    # keep only solves by non-admin players with a known team
    solves = [s for s in solves
              if s.user and s.user.team and s.user.team.id != 1 and s.solved_at is not None]

    categories = sorted({(s.challenge.category if s.challenge else "General") or "General"
                         for s in solves})

    teams = {}            # name -> {"by_category": {...}, "score": int}
    timeline = {}         # name -> list[[minutes, cumulative]]
    cum = {}              # name -> running total
    first_blood = None

    t0 = solves[0].solved_at if solves else None
    for s in solves:
        tname = s.user.team.name
        cat = (s.challenge.category if s.challenge else "General") or "General"
        pts = s.points_awarded or 0

        t = teams.setdefault(tname, {"by_category": {c: 0 for c in categories}, "score": 0})
        t["by_category"][cat] = t["by_category"].get(cat, 0) + 1
        t["score"] += pts

        cum[tname] = cum.get(tname, 0) + pts
        minutes = round((s.solved_at - t0).total_seconds() / 60.0, 2) if t0 else 0
        timeline.setdefault(tname, []).append([minutes, cum[tname]])

        if first_blood is None:
            first_blood = {
                "team": tname,
                "player": s.user.username,
                "challenge": s.challenge.name if s.challenge else "?",
                "category": cat,
                "at": s.solved_at.isoformat(),
            }

    teams_out = [{"name": n, "by_category": d["by_category"], "score": d["score"]}
                 for n, d in teams.items()]
    teams_out.sort(key=lambda x: -x["score"])
    timeline_out = [{"name": n, "points": pts} for n, pts in timeline.items()]

    return {
        "categories": categories,
        "teams": teams_out,
        "timeline": timeline_out,
        "first_blood": first_blood,
    }


@main.route("/score_breakdown", methods=["GET"])
def score_breakdown():
    """Leaderboard analytics for the scoreboard's Progress view (#25)."""
    try:
        return jsonify(_score_breakdown_payload())
    except Exception as e:
        print(f"score_breakdown: {e}")
        # Never break the scoreboard page; return an empty-but-valid shape.
        return jsonify({"categories": [], "teams": [], "timeline": [], "first_blood": None})


@main.route("/getPermissionsList", methods=["GET"])
@roles_required("Admin")
@login_required
def get_permissions_list():
    """Return the current ADX database user list as a JSON array."""
    try:
        log_uploader = LogUploader()
        perms = log_uploader.get_user_permissions()
        return jsonify(perms)
    except Exception as e:
        print(e)
        return jsonify([])


@main.route("/reports")
@login_required
def reports():
    """Show phishing reports submitted by simulated employees."""
    report_list = Report.query.filter_by(team_id=current_user.team_id).all()
    return render_template("main/reports.html", reports=report_list)


# ---------------------------------------------------------------------------
# Challenge / Q&A system
# ---------------------------------------------------------------------------

@main.route("/challenges")
@login_required
def challenges():
    """Player-facing challenges page."""
    # Only show challenges not assigned to any round
    all_challenges = Challenge.query.filter_by(round_id=None).order_by(Challenge.category, Challenge.name).all()

    # Build set of challenge IDs already solved by this user
    solved_ids = {
        s.challenge_id
        for s in Solve.query.filter_by(user_id=current_user.id).all()
    }

    # Group by category
    from collections import defaultdict
    by_category = defaultdict(list)
    for ch in all_challenges:
        by_category[ch.category].append(ch)

    categories = sorted(by_category.keys())
    return render_template(
        "main/challenges.html",
        by_category=by_category,
        categories=categories,
        solved_ids=solved_ids,
    )


@main.route("/submit_answer", methods=["POST"])
@login_required
def submit_answer():
    """
    Check a player's answer to a challenge.
    Awards time-weighted points on first correct solve; duplicate solves are rejected.
    Returns JSON: {correct, already_solved, points_earned, user_score, team_score, message}
    """
    try:
        challenge_id = int(request.form["challenge_id"])
        submitted    = request.form.get("answer", "").strip()

        challenge = db.session.get(Challenge, challenge_id)
        if not challenge:
            return jsonify(correct=False, message="Challenge not found.")

        # Reject if global session timer OR per-round timer has expired
        _gs = db.session.get(GameSession, 1)
        _global_expired = bool(_gs and _gs.uses_timer and _gs.end_time and datetime.now() > _gs.end_time)
        _round_expired = False
        if challenge.round_id:
            _rnd = db.session.get(GameRound, challenge.round_id)
            if _rnd and _rnd.uses_timer and _rnd.end_time and datetime.now() > _rnd.end_time:
                _round_expired = True
        if _global_expired or _round_expired:
            return jsonify(correct=False, already_solved=False, points_earned=0,
                           user_score=current_user.score or 0,
                           team_score=current_user.team.score or 0,
                           message="This session has ended. No more answers can be submitted.",
                           timer_expired=True)

        # Reject duplicate solve
        existing = Solve.query.filter_by(
            challenge_id=challenge_id, user_id=current_user.id
        ).first()
        if existing:
            return jsonify(
                correct=True,
                already_solved=True,
                points_earned=0,
                user_score=current_user.score or 0,
                team_score=current_user.team.score or 0,
                message="You already solved this challenge.",
            )

        if not challenge.check_answer(submitted):
            _attempt = AnswerAttempt(challenge_id=challenge_id,
                                     user_id=current_user.id,
                                     submitted=submitted, correct=False)
            db.session.add(_attempt)
            db.session.commit()
            return jsonify(correct=False, already_solved=False, points_earned=0,
                           user_score=current_user.score or 0,
                           team_score=current_user.team.score or 0,
                           message="Incorrect answer. Try again!")

        # Correct and first solve -- award points
        # Optional dynamic / first-blood scoring (off by default): value decays as more
        # teams solve a challenge, and the first solver earns a bonus. When disabled,
        # the existing time-weighted scoring is used unchanged.
        # Round challenges: score based on how early within the round window.
        # Global challenges: score based on global session elapsed time.
        now = datetime.now()
        if current_app.config.get("DYNAMIC_SCORING_ENABLED"):
            from app.server.modules.scoring.dynamic_scoring import award_for_solve
            prior_solves = Solve.query.filter_by(challenge_id=challenge_id).count()
            points_earned = award_for_solve(
                challenge.value, prior_solves,
                minimum=current_app.config.get("DYNAMIC_SCORING_MINIMUM", 50),
                decay=current_app.config.get("DYNAMIC_SCORING_DECAY", 20),
                first_blood_pct=current_app.config.get("FIRST_BLOOD_BONUS_PCT", 0),
            )["total"]
        elif challenge.round_id:
            _rnd_for_score = db.session.get(GameRound, challenge.round_id)
            points_earned = calculate_round_time_weighted_points(
                challenge.value, _rnd_for_score, solved_at=now
            )
        else:
            game_session  = db.session.get(GameSession, 1)
            points_earned = calculate_time_weighted_points(challenge.value, game_session)

        current_user.score = (current_user.score or 0) + points_earned
        current_user.last_score_time = now
        current_user.team.score = (current_user.team.score or 0) + points_earned
        # Tie-break: equal scores are ranked by who REACHED that score first — i.e. the
        # most recent scoring event, earlier wins. Update on every score so teams use the
        # same rule as individual players (previously teams kept only their FIRST score time).
        current_user.team.last_score_time = now

        solve = Solve(
            challenge_id=challenge_id,
            user_id=current_user.id,
            points_awarded=points_earned,
        )
        db.session.add(solve)
        _attempt = AnswerAttempt(challenge_id=challenge_id,
                                 user_id=current_user.id,
                                 submitted=submitted, correct=True)
        db.session.add(_attempt)
        db.session.commit()

        print("Challenge solve: user=" + current_user.username
              + " challenge=" + challenge.name
              + " +" + str(points_earned) + " pts")

        return jsonify(
            correct=True,
            already_solved=False,
            points_earned=points_earned,
            user_score=current_user.score,
            team_score=current_user.team.score,
            message="Correct! +" + str(points_earned) + " points!",
        )
    except Exception as e:
        print("submit_answer error: " + str(e))
        return jsonify(correct=False, already_solved=False, points_earned=0,
                       user_score=0, team_score=0, message="Server error.")


@main.route("/admin/manage_challenges")
@roles_required("Admin")
@login_required
def manage_challenges():
    """Admin: view, add, delete, and bulk-import challenges."""
    challenge_list = Challenge.query.order_by(Challenge.category, Challenge.name).all()
    round_list = GameRound.query.order_by(GameRound.name).all()

    # Solve counts per challenge: {challenge_id: count}
    from sqlalchemy import func as sqlfunc
    solve_counts_raw = db.session.query(Solve.challenge_id, sqlfunc.count(Solve.id))\
        .group_by(Solve.challenge_id).all()
    solve_counts = {ch_id: cnt for ch_id, cnt in solve_counts_raw}

    # Total non-admin player count (for % calculation)
    total_players = Users.query.filter(Users.team_id != 1).count()

    return render_template(
        "admin/manage_challenges.html",
        challenges=challenge_list,
        rounds=round_list,
        solve_counts=solve_counts,
        total_players=total_players,
    )


@main.route("/admin/add_challenge", methods=["POST"])
@roles_required("Admin")
@login_required
def add_challenge():
    """Admin: add a single challenge."""
    try:
        round_id_str = request.form.get("round_id", "").strip()
        ch = Challenge(
            name        = request.form["name"].strip(),
            category    = request.form.get("category", "General").strip() or "General",
            description = request.form["description"].strip(),
            answer      = request.form["answer"].strip(),
            value       = int(request.form.get("value", 100)),
            round_id    = int(round_id_str) if round_id_str else None,
        )
        db.session.add(ch)
        db.session.commit()
        flash("Challenge added: " + ch.name, "success")
    except Exception as e:
        print("add_challenge error: " + str(e))
        flash("Failed to add challenge: " + str(e), "error")
    return redirect(url_for("main.manage_challenges"))



@main.route("/admin/edit_challenge", methods=["POST"])
@roles_required("Admin")
@login_required
def edit_challenge():
    """Admin: update an existing challenge."""
    try:
        challenge_id = int(request.form["challenge_id"])
        ch = db.session.get(Challenge, challenge_id)
        if not ch:
            flash("Challenge not found.", "error")
            return redirect(url_for("main.manage_challenges"))
        ch.name        = request.form["name"].strip()
        ch.category    = request.form.get("category", "General").strip() or "General"
        ch.description = request.form["description"].strip()
        ch.answer      = request.form["answer"].strip()
        ch.value       = int(request.form.get("value", 100))
        round_id_str   = request.form.get("round_id", "").strip()
        ch.round_id    = int(round_id_str) if round_id_str else None
        db.session.commit()
        flash("Challenge updated: " + ch.name, "success")
    except Exception as e:
        print("edit_challenge error: " + str(e))
        flash("Failed to update challenge: " + str(e), "error")
    return redirect(url_for("main.manage_challenges"))

@main.route("/admin/delete_challenge", methods=["POST"])
@roles_required("Admin")
@login_required
def delete_challenge():
    """Admin: delete a challenge and all its solve records."""
    try:
        challenge_id = int(request.form["challenge_id"])
        Solve.query.filter_by(challenge_id=challenge_id).delete()
        ch = db.session.get(Challenge, challenge_id)
        ch_name = ch.name if ch else str(challenge_id)
        if ch:
            db.session.delete(ch)
        db.session.commit()
        record_admin_action("challenge.delete", target=ch_name)
        flash("Challenge deleted.", "success")
    except Exception as e:
        print("delete_challenge error: " + str(e))
        flash("Failed to delete challenge.", "error")
    return redirect(url_for("main.manage_challenges"))


@main.route("/admin/mass_delete_challenges", methods=["POST"])
@roles_required("Admin")
@login_required
def mass_delete_challenges():
    """Admin: delete multiple challenges at once."""
    try:
        ids = request.form.getlist("challenge_ids")
        if not ids:
            flash("No challenges selected.", "warning")
            return redirect(url_for("main.manage_challenges"))
        ids = [int(i) for i in ids]
        Solve.query.filter(Solve.challenge_id.in_(ids)).delete(synchronize_session=False)
        AnswerAttempt.query.filter(AnswerAttempt.challenge_id.in_(ids)).delete(synchronize_session=False)
        Challenge.query.filter(Challenge.id.in_(ids)).delete(synchronize_session=False)
        db.session.commit()
        record_admin_action("challenge.mass_delete", detail="Deleted %d challenge(s)" % len(ids))
        flash("Deleted " + str(len(ids)) + " challenge(s).", "success")
    except Exception as e:
        print("mass_delete_challenges error: " + str(e))
        flash("Mass delete failed: " + str(e), "error")
    return redirect(url_for("main.manage_challenges"))


@main.route("/admin/import_challenges_csv", methods=["POST"])
@roles_required("Admin")
@login_required
def import_challenges_csv():
    """
    Admin: bulk-import challenges from a CSV file.
    Expected columns (with or without header):
        name, value, description, answer, category[, round]
    The optional 6th column 'round' is matched by name against existing GameRounds.
    A fallback round can also be selected from the form dropdown.
    """
    import csv, io
    try:
        f = request.files.get("csv_file")
        if not f or not f.filename:
            flash("No file selected.", "error")
            return redirect(url_for("main.manage_challenges"))

        # Optional fallback round from the form dropdown
        fallback_round_id_str = request.form.get("default_round_id", "").strip()
        fallback_round_id = int(fallback_round_id_str) if fallback_round_id_str else None

        # Build a lookup map: lowercase round name → id
        round_map = {r.name.lower(): r.id for r in GameRound.query.all()}

        stream  = io.StringIO(f.stream.read().decode("utf-8-sig"), newline=None)
        reader  = csv.reader(stream)
        added   = 0
        skipped = 0

        for i, row in enumerate(reader):
            if len(row) < 5:
                skipped += 1
                continue
            cols = [c.strip() for c in row]
            name, value, description, answer, category = cols[:5]
            # Skip header row
            if i == 0 and name.lower() == "name":
                continue

            # Resolve round: column 6 takes priority, then fallback dropdown
            round_id = fallback_round_id
            if len(cols) >= 6 and cols[5]:
                round_id = round_map.get(cols[5].lower(), fallback_round_id)

            try:
                ch = Challenge(
                    name=name,
                    value=int(value) if value.isdigit() else 100,
                    description=description,
                    answer=answer,
                    category=category or "General",
                    round_id=round_id,
                )
                db.session.add(ch)
                added += 1
            except Exception:
                skipped += 1

        db.session.commit()
        flash("Imported " + str(added) + " challenge(s). Skipped " + str(skipped) + " row(s).", "success")
    except Exception as e:
        print("import_challenges_csv error: " + str(e))
        flash("CSV import failed: " + str(e), "error")
    return redirect(url_for("main.manage_challenges"))


# ---------------------------------------------------------------------------
# Session timer management
# ---------------------------------------------------------------------------

@main.route("/admin/set_session_timer", methods=["POST"])
@roles_required("Admin")
@login_required
def set_session_timer():
    """Admin: set the session end time and optionally enable the timer."""
    try:
        end_time_str = request.form.get("end_time", "").strip()
        game_session = db.session.get(GameSession, 1)
        if not game_session:
            flash("Game session not found.", "error")
            return redirect(url_for("main.manage_game"))
        if end_time_str:
            game_session.end_time = datetime.strptime(end_time_str, "%Y-%m-%dT%H:%M")
            game_session.uses_timer = True
            db.session.commit()
            flash("Session timer set to " + end_time_str + " and enabled.", "success")
        else:
            flash("Please provide a valid end date/time.", "error")
    except Exception as e:
        print("set_session_timer error: " + str(e))
        flash("Failed to set timer: " + str(e), "error")
    return redirect(url_for("main.manage_game"))


@main.route("/admin/toggle_session_timer", methods=["POST"])
@roles_required("Admin")
@login_required
def toggle_session_timer():
    """Admin: enable or disable the session timer without changing the end time."""
    try:
        game_session = db.session.get(GameSession, 1)
        if not game_session:
            flash("Game session not found.", "error")
            return redirect(url_for("main.manage_game"))
        game_session.uses_timer = not bool(game_session.uses_timer)
        db.session.commit()
        state = "enabled" if game_session.uses_timer else "disabled"
        flash("Session timer " + state + ".", "success")
    except Exception as e:
        print("toggle_session_timer error: " + str(e))
        flash("Failed to toggle timer: " + str(e), "error")
    return redirect(url_for("main.manage_game"))


# ---------------------------------------------------------------------------
# Named game rounds — player routes
# ---------------------------------------------------------------------------

@main.route("/rounds")
@login_required
def rounds():
    """Player dashboard: shows rounds they've joined and a join form."""
    my_participations = Participation.query.filter_by(user_id=current_user.id).all()
    my_round_ids = {p.round_id for p in my_participations}
    my_rounds = [db.session.get(GameRound, rid) for rid in my_round_ids if db.session.get(GameRound, rid)]
    my_rounds.sort(key=lambda r: r.name)
    return render_template("main/rounds.html", my_rounds=my_rounds)


@main.route("/rounds/join", methods=["POST"])
@login_required
def join_round():
    """Player joins a game round via password code."""
    try:
        code = request.form.get("password", "").strip()
        game_round = GameRound.query.filter_by(password=code).first()
        if not game_round:
            flash("Invalid join code. Please try again.", "error")
            return redirect(url_for("main.rounds"))

        existing = Participation.query.filter_by(
            round_id=game_round.id, user_id=current_user.id
        ).first()
        if existing:
            flash("You have already joined \"" + game_round.name + "\".", "info")
            return redirect(url_for("main.round_challenges", round_id=game_round.id))

        db.session.add(Participation(round_id=game_round.id, user_id=current_user.id))
        db.session.commit()
        flash("Welcome to \"" + game_round.name + "\"!", "success")
        return redirect(url_for("main.round_challenges", round_id=game_round.id))
    except Exception as e:
        print("join_round error: " + str(e))
        flash("Could not join round: " + str(e), "error")
        return redirect(url_for("main.rounds"))


@main.route("/rounds/<int:round_id>/challenges")
@login_required
def round_challenges(round_id):
    """Show challenges for a specific round (registered players only)."""
    game_round = db.session.get(GameRound, round_id)
    if not game_round:
        abort(404)

    # Only registered participants can view
    participation = Participation.query.filter_by(
        round_id=round_id, user_id=current_user.id
    ).first()
    if not participation:
        flash("You need to join this round first.", "error")
        return redirect(url_for("main.rounds"))

    all_challenges = Challenge.query.filter_by(round_id=round_id)\
        .order_by(Challenge.category, Challenge.name).all()

    solved_ids = {
        s.challenge_id
        for s in Solve.query.filter_by(user_id=current_user.id).all()
    }

    from collections import defaultdict
    by_category = defaultdict(list)
    for ch in all_challenges:
        by_category[ch.category].append(ch)
    categories = sorted(by_category.keys())

    # Per-round score for current user
    from sqlalchemy import func as sqlfunc
    user_round_score = db.session.query(sqlfunc.sum(Solve.points_awarded))\
        .join(Challenge, Solve.challenge_id == Challenge.id)\
        .filter(Challenge.round_id == round_id)\
        .filter(Solve.user_id == current_user.id)\
        .scalar() or 0

    return render_template(
        "main/round_challenges.html",
        game_round=game_round,
        by_category=by_category,
        categories=categories,
        solved_ids=solved_ids,
        user_round_score=user_round_score,
        now=datetime.now(),
    )


@main.route("/rounds/<int:round_id>/rankings")
@login_required
def round_rankings(round_id):
    """Per-round leaderboard (registered players only)."""
    game_round = db.session.get(GameRound, round_id)
    if not game_round:
        abort(404)

    participation = Participation.query.filter_by(
        round_id=round_id, user_id=current_user.id
    ).first()
    if not participation:
        flash("You need to join this round first.", "error")
        return redirect(url_for("main.rounds"))

    from sqlalchemy import func as sqlfunc
    participant_ids = [p.user_id for p in game_round.participants.all()]
    players = Users.query.filter(
        Users.id.in_(participant_ids),
        Users.team_id != 1        # exclude admin team
    ).all()

    # --- Individual leaderboard ---
    player_data = []
    for p in players:
        round_score = db.session.query(sqlfunc.sum(Solve.points_awarded))\
            .join(Challenge, Solve.challenge_id == Challenge.id)\
            .filter(Challenge.round_id == round_id)\
            .filter(Solve.user_id == p.id)\
            .scalar() or 0
        first_solve = db.session.query(sqlfunc.min(Solve.solved_at))\
            .join(Challenge, Solve.challenge_id == Challenge.id)\
            .filter(Challenge.round_id == round_id)\
            .filter(Solve.user_id == p.id)\
            .scalar()
        player_data.append({
            "username": p.username,
            "team":     p.team.name if p.team else "--",
            "team_id":  p.team_id,
            "score":    round_score,
            "first_solve": first_solve.isoformat() if first_solve else "9999",
        })
    player_data.sort(key=lambda x: (-x["score"], x["first_solve"]))

    # --- Team leaderboard (aggregate participant scores per team) ---
    team_scores = {}   # team_id -> {name, score, first_solve}
    for p in players:
        if not p.team_id:
            continue
        team_name = p.team.name if p.team else "--"
        if p.team_id not in team_scores:
            team_scores[p.team_id] = {"name": team_name, "score": 0, "first_solve": "9999"}

        round_score = db.session.query(sqlfunc.sum(Solve.points_awarded))\
            .join(Challenge, Solve.challenge_id == Challenge.id)\
            .filter(Challenge.round_id == round_id)\
            .filter(Solve.user_id == p.id)\
            .scalar() or 0
        first_solve = db.session.query(sqlfunc.min(Solve.solved_at))\
            .join(Challenge, Solve.challenge_id == Challenge.id)\
            .filter(Challenge.round_id == round_id)\
            .filter(Solve.user_id == p.id)\
            .scalar()

        team_scores[p.team_id]["score"] += round_score
        if first_solve:
            fs_str = first_solve.isoformat()
            if fs_str < team_scores[p.team_id]["first_solve"]:
                team_scores[p.team_id]["first_solve"] = fs_str

    team_data = sorted(team_scores.values(), key=lambda x: (-x["score"], x["first_solve"]))

    return render_template(
        "main/round_rankings.html",
        game_round=game_round,
        player_data=player_data,
        team_data=team_data,
        current_team=current_user.team.name if current_user.team else None,
    )


# ---------------------------------------------------------------------------
# Player profile page
# ---------------------------------------------------------------------------

@main.route("/profile")
@login_required
def profile_self():
    """Redirect to current user's own profile."""
    return redirect(url_for("main.profile", username=current_user.username))


@main.route("/profile/<username>")
@login_required
def profile(username):
    """Per-player profile and stats page.

    The player can only view their own profile.
    Admins can view any player's profile.
    """
    is_admin = current_user.has_role("Admin")
    if not is_admin and username != current_user.username:
        abort(403)

    target = Users.query.filter_by(username=username).first_or_404()

    from sqlalchemy import func as sqlfunc

    # --- Solve history ---
    solves = (
        db.session.query(Solve, Challenge)
        .join(Challenge, Solve.challenge_id == Challenge.id)
        .filter(Solve.user_id == target.id)
        .order_by(Solve.solved_at.desc())
        .all()
    )

    # --- Global rank (by total score, excluding admin team) ---
    all_scores = db.session.query(Users.id, Users.score)\
        .filter(Users.team_id != 1)\
        .order_by(Users.score.desc())\
        .all()
    rank = next((i + 1 for i, row in enumerate(all_scores) if row[0] == target.id), None)
    total_players = len(all_scores)

    # --- Challenges solved count ---
    total_solved = len(solves)
    total_challenges = Challenge.query.count()

    # --- Per-round participation with score ---
    round_ids = db.session.query(Participation.round_id)\
        .filter(Participation.user_id == target.id).all()
    round_ids = [r[0] for r in round_ids]

    round_stats = []
    for rid in round_ids:
        gr = db.session.get(GameRound, rid)
        if not gr:
            continue
        r_score = db.session.query(sqlfunc.sum(Solve.points_awarded))\
            .join(Challenge, Solve.challenge_id == Challenge.id)\
            .filter(Challenge.round_id == rid, Solve.user_id == target.id)\
            .scalar() or 0
        r_solved = db.session.query(sqlfunc.count(Solve.id))\
            .join(Challenge, Solve.challenge_id == Challenge.id)\
            .filter(Challenge.round_id == rid, Solve.user_id == target.id)\
            .scalar() or 0
        r_total = Challenge.query.filter_by(round_id=rid).count()
        round_stats.append({
            "round": gr,
            "score": r_score,
            "solved": r_solved,
            "total": r_total,
        })

    return render_template(
        "main/profile.html",
        target=target,
        solves=solves,
        rank=rank,
        total_players=total_players,
        total_solved=total_solved,
        total_challenges=total_challenges,
        round_stats=round_stats,
        is_own_profile=(target.id == current_user.id),
    )


# ---------------------------------------------------------------------------
# Named game rounds — admin routes
# ---------------------------------------------------------------------------

@main.route("/admin/rounds")
@roles_required("Admin")
@login_required
def manage_rounds():
    """Admin: list and manage all game rounds."""
    round_list = GameRound.query.order_by(GameRound.created_at.desc()).all()
    return render_template("admin/manage_rounds.html", rounds=round_list, now=datetime.now())


@main.route("/admin/rounds/create", methods=["POST"])
@roles_required("Admin")
@login_required
def create_round():
    """Admin: create a new named game round."""
    try:
        name     = request.form["name"].strip()
        password = request.form["password"].strip()
        if not name or not password:
            flash("Name and join code are required.", "error")
            return redirect(url_for("main.manage_rounds"))
        if GameRound.query.filter_by(password=password).first():
            flash("That join code is already in use. Choose a different one.", "error")
            return redirect(url_for("main.manage_rounds"))
        gr = GameRound(name=name, password=password)
        db.session.add(gr)
        db.session.commit()
        flash("Round \"" + name + "\" created. Join code: " + password, "success")
    except Exception as e:
        print("create_round error: " + str(e))
        flash("Failed to create round: " + str(e), "error")
    return redirect(url_for("main.manage_rounds"))


@main.route("/admin/rounds/delete", methods=["POST"])
@roles_required("Admin")
@login_required
def delete_round():
    """Admin: delete a round and unassign its challenges (challenges are kept, just unlinked)."""
    try:
        round_id = int(request.form["round_id"])
        gr = db.session.get(GameRound, round_id)
        if gr:
            # Unlink challenges so they aren't deleted
            Challenge.query.filter_by(round_id=round_id).update({"round_id": None})
            Participation.query.filter_by(round_id=round_id).delete()
            db.session.delete(gr)
            db.session.commit()
            flash("Round deleted. Its challenges are now global.", "success")
    except Exception as e:
        print("delete_round error: " + str(e))
        flash("Failed to delete round: " + str(e), "error")
    return redirect(url_for("main.manage_rounds"))


@main.route("/admin/rounds/<int:round_id>/set_timer", methods=["POST"])
@roles_required("Admin")
@login_required
def set_round_timer(round_id):
    """Admin: set end time on a specific game round and enable its timer."""
    try:
        gr = db.session.get(GameRound, round_id)
        if not gr:
            flash("Round not found.", "error")
            return redirect(url_for("main.manage_rounds"))
        start_time_str = request.form.get("start_time", "").strip()
        end_time_str   = request.form.get("end_time", "").strip()
        if end_time_str:
            gr.end_time   = datetime.strptime(end_time_str, "%Y-%m-%dT%H:%M")
            gr.start_time = datetime.strptime(start_time_str, "%Y-%m-%dT%H:%M") \
                            if start_time_str else datetime.now()
            gr.uses_timer = True
            db.session.commit()
            flash("Timer set for \"" + gr.name + "\" and enabled.", "success")
        else:
            flash("Please provide a valid end date/time.", "error")
    except Exception as e:
        print("set_round_timer error: " + str(e))
        flash("Failed to set timer: " + str(e), "error")
    return redirect(url_for("main.manage_rounds"))


@main.route("/admin/rounds/<int:round_id>/toggle_timer", methods=["POST"])
@roles_required("Admin")
@login_required
def toggle_round_timer(round_id):
    """Admin: enable or disable the timer for a specific game round."""
    try:
        gr = db.session.get(GameRound, round_id)
        if not gr:
            flash("Round not found.", "error")
            return redirect(url_for("main.manage_rounds"))
        gr.uses_timer = not bool(gr.uses_timer)
        # Record start_time when timer is first enabled
        if gr.uses_timer and not gr.start_time:
            gr.start_time = datetime.now()
        db.session.commit()
        state = "enabled" if gr.uses_timer else "disabled"
        flash("Timer " + state + " for \"" + gr.name + "\".", "success")
    except Exception as e:
        print("toggle_round_timer error: " + str(e))
        flash("Failed to toggle timer: " + str(e), "error")
    return redirect(url_for("main.manage_rounds"))


# ---------------------------------------------------------------------------
# CSV export routes (admin)
# ---------------------------------------------------------------------------

import csv as _csv
import io as _io


def _csv_response(filename, rows, headers):
    """Build a CSV HTTP response from a list of dicts."""
    output = _io.StringIO()
    writer = _csv.DictWriter(output, fieldnames=headers, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    from flask import Response
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@main.route("/admin/export/users")
@roles_required("Admin")
@login_required
def export_users_csv():
    """Download all non-admin users as a CSV."""
    users = Users.query.filter(Users.team_id != 1).order_by(Users.username).all()
    rows = []
    for u in users:
        rows.append({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "team": u.team.name if u.team else "",
            "role": ", ".join(r.name for r in u.roles),
            "score": u.score or 0,
        })
    return _csv_response("users.csv", rows, ["id", "username", "email", "team", "role", "score"])


@main.route("/admin/export/teams")
@roles_required("Admin")
@login_required
def export_teams_csv():
    """Download all non-admin teams as a CSV."""
    teams = Team.query.filter(Team.id != 1).order_by(Team.name).all()
    rows = []
    for t in teams:
        rows.append({
            "id": t.id,
            "name": t.name,
            "members": t.members.count(),
            "score": t.score or 0,
        })
    return _csv_response("teams.csv", rows, ["id", "name", "members", "score"])


@main.route("/admin/export/round/<int:round_id>/results")
@roles_required("Admin")
@login_required
def export_round_results_csv(round_id):
    """Download per-round solve log as a CSV."""
    gr = db.session.get(GameRound, round_id)
    if not gr:
        abort(404)

    solves = (
        db.session.query(Solve, Challenge, Users)
        .join(Challenge, Solve.challenge_id == Challenge.id)
        .join(Users, Solve.user_id == Users.id)
        .filter(Challenge.round_id == round_id)
        .filter(Users.team_id != 1)
        .order_by(Solve.solved_at)
        .all()
    )

    rows = []
    for solve, ch, user in solves:
        rows.append({
            "username": user.username,
            "team": user.team.name if user.team else "",
            "challenge": ch.name,
            "category": ch.category,
            "points_awarded": solve.points_awarded,
            "solved_at": solve.solved_at.strftime("%Y-%m-%d %H:%M:%S"),
        })

    safe_name = "".join(c if c.isalnum() or c in "._- " else "_" for c in gr.name)
    return _csv_response(
        f"round_{safe_name}_results.csv",
        rows,
        ["username", "team", "challenge", "category", "points_awarded", "solved_at"],
    )


@main.route("/admin/export/round/<int:round_id>/scores")
@roles_required("Admin")
@login_required
def export_round_scores_csv(round_id):
    """Download per-round player score summary as a CSV."""
    from sqlalchemy import func as sqlfunc
    gr = db.session.get(GameRound, round_id)
    if not gr:
        abort(404)

    participant_ids = [p.user_id for p in gr.participants.all()]
    players = Users.query.filter(
        Users.id.in_(participant_ids),
        Users.team_id != 1
    ).all()

    rows = []
    for p in players:
        r_score = db.session.query(sqlfunc.sum(Solve.points_awarded))\
            .join(Challenge, Solve.challenge_id == Challenge.id)\
            .filter(Challenge.round_id == round_id, Solve.user_id == p.id)\
            .scalar() or 0
        r_solved = db.session.query(sqlfunc.count(Solve.id))\
            .join(Challenge, Solve.challenge_id == Challenge.id)\
            .filter(Challenge.round_id == round_id, Solve.user_id == p.id)\
            .scalar() or 0
        rows.append({
            "username": p.username,
            "team": p.team.name if p.team else "",
            "score": r_score,
            "challenges_solved": r_solved,
        })

    rows.sort(key=lambda x: -x["score"])
    safe_name = "".join(c if c.isalnum() or c in "._- " else "_" for c in gr.name)
    return _csv_response(
        f"round_{safe_name}_scores.csv",
        rows,
        ["username", "team", "score", "challenges_solved"],
    )


@main.route("/admin/export/scenario_pdf")
@roles_required("Admin")
@login_required
def export_scenario_pdf():
    """
    Download the scenario as a PDF.
      ?answers=1   -> instructor answer key (answers + threat landscape)
      (default)    -> player challenge packet (questions only, no answers)
      ?round_id=N  -> scope challenges to a single round
    reportlab is imported lazily and guarded, so a missing package surfaces a
    friendly message instead of breaking the app.
    """
    from flask import Response
    from app.server.modules.reporting.scenario_document import (
        build_scenario_dict, build_scenario_pdf, PdfDependencyMissing,
    )

    include_answers = request.args.get("answers", "0") in ("1", "true", "yes", "on")
    round_id = request.args.get("round_id")
    try:
        scenario = build_scenario_dict(round_id=round_id)
        pdf_bytes = build_scenario_pdf(scenario, include_answers=include_answers)
    except PdfDependencyMissing as e:
        flash(str(e), "error")
        return redirect(url_for("main.manage_challenges"))
    except Exception as e:
        print("export_scenario_pdf error: " + str(e))
        flash("Could not generate scenario PDF: " + str(e), "error")
        return redirect(url_for("main.manage_challenges"))

    kind = "answer_key" if include_answers else "player_packet"
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment; filename=kc7_scenario_" + kind + ".pdf"},
    )


@main.route("/admin/game_guide")
@roles_required("Admin")
@login_required
def game_guide():
    """
    Auto-generated game guide & instructor key, in Markdown (#12) — generated from the
    scenario config every time, so it can't drift like a hand-edited summary.
      ?variant=instructor -> full instructor key (attribution, ATT&CK, timeline, IOCs, answers)
      (default)           -> player intel brief (scene + objectives, no spoilers)
      ?download=1         -> download as a .md file instead of viewing inline
    """
    from flask import Response
    from app.server.modules.reporting.game_guide import gather_guide_facts, build_game_guide

    instructor = request.args.get("variant", "player") == "instructor"
    try:
        company, actors, challenges = gather_guide_facts()
        md = build_game_guide(company, actors, challenges, include_answers=instructor)
    except Exception as e:
        print("game_guide error: " + str(e))
        flash("Could not generate the game guide: " + str(e), "error")
        return redirect(url_for("main.manage_challenges"))

    headers = {}
    if request.args.get("download") in ("1", "true", "yes", "on"):
        fname = "kc7_%s_guide.md" % ("instructor" if instructor else "player")
        headers["Content-Disposition"] = "attachment; filename=" + fname
    return Response(md, mimetype="text/markdown; charset=utf-8", headers=headers)


@main.route("/admin/preview_scenario")
@roles_required("Admin")
@login_required
def preview_scenario_route():
    """
    Dry-run pre-flight: report what the current scenario configs will generate
    (techniques, ADX tables, active days, approximate volume) WITHOUT running the
    pipeline. ?format=json for the structured dict; otherwise a plain-text report.
    """
    from flask import Response
    from app.server.modules.preview.scenario_preview import preview_scenario, format_preview_text
    try:
        pv = preview_scenario()
    except Exception as e:
        print("preview_scenario error: " + str(e))
        return jsonify(error=str(e)), 500
    if request.args.get("format") == "json":
        return jsonify(pv)
    return Response(format_preview_text(pv), mimetype="text/plain")


@main.route("/admin/test_answer")
@roles_required("Admin")
@login_required
def test_answer():
    """
    Preview how a submitted answer grades, including normalization/defang, before
    publishing a challenge. Params:
      answer=<submitted value>
      and either  challenge_id=<id>  or  accepted=<;-separated accepted answers>
    Returns a JSON explanation (normalized forms + which accepted answer matched).
    """
    from app.server.modules.scoring.answer_matching import explain_match

    submitted = request.args.get("answer", "")
    accepted = request.args.get("accepted")
    challenge_id = request.args.get("challenge_id")

    if challenge_id:
        try:
            ch = db.session.get(Challenge, int(challenge_id))
        except (ValueError, TypeError):
            return jsonify(error="challenge_id must be an integer"), 400
        if not ch:
            return jsonify(error="Challenge not found"), 404
        accepted = ch.answer

    if accepted is None:
        return jsonify(error="Provide either challenge_id or accepted"), 400

    return jsonify(explain_match(submitted, accepted))


@main.route("/admin/score_audit")
@roles_required("Admin")
@login_required
def score_audit():
    """
    Score reconciliation, and optionally a destructive rebuild.

    Default (read-only): recompute each player's/team's totals from the Solve +
    MitigationAward records and compare to the stored running totals to surface any
    desync. ?format=json for the structured report; otherwise a plain-text table.

    ?apply=1 : DESTRUCTIVE — overwrite every player's/team's stored ``score`` and
    ``last_score_time`` with the values recomputed from records. Use after editing/
    deleting challenges or answers to bring standings back in sync.
    """
    from flask import Response
    from app.server.modules.scoring.score_recompute import (
        reconcile, format_reconciliation_text, compute_rebuild,
    )
    from app.server.models import MitigationAward

    users = Users.query.filter(Users.team_id != 1).all()
    teams = Team.query.filter(Team.id != 1).all()
    solves = Solve.query.all()
    awards = MitigationAward.query.all()

    if request.args.get("apply") == "1":
        target = compute_rebuild(users, teams, solves, awards)
        changes = []
        for u in users:
            tgt = target["users"].get(u.id) or {"score": 0, "last_score_time": None}
            if (u.score or 0) != tgt["score"]:
                changes.append("player %s: %s -> %s" % (u.username, u.score or 0, tgt["score"]))
            u.score = tgt["score"]
            u.last_score_time = tgt["last_score_time"]
        for tm in teams:
            tgt = target["teams"].get(tm.id) or {"score": 0, "last_score_time": None}
            if (tm.score or 0) != tgt["score"]:
                changes.append("team %s: %s -> %s" % (tm.name, tm.score or 0, tgt["score"]))
            tm.score = tgt["score"]
            tm.last_score_time = tgt["last_score_time"]
        db.session.commit()
        print("Score rebuild applied: %d change(s) across %d players, %d teams"
              % (len(changes), len(users), len(teams)))
        report = reconcile(users, teams, solves, awards)  # should now show all-zero deltas
        if request.args.get("format") == "json":
            return jsonify(applied=True, changes=changes, report=report)
        body = ("SCORE REBUILD APPLIED — %d change(s):\n  %s\n\n%s"
                % (len(changes), "\n  ".join(changes) or "(no changes)",
                   format_reconciliation_text(report)))
        return Response(body, mimetype="text/plain")

    report = reconcile(users, teams, solves, awards)
    if request.args.get("format") == "json":
        return jsonify(report)
    return Response(format_reconciliation_text(report), mimetype="text/plain")


@main.route("/admin/run_history")
@roles_required("Admin")
@login_required
def run_history():
    """
    Generation run history: when each game was generated, how long it took, whether it
    succeeded, and the scenario window. ?format=json for the raw data.
    """
    from flask import Response
    from app.server.models import GameRunLog

    def _counts(raw):
        try:
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    runs = GameRunLog.query.order_by(GameRunLog.id.desc()).limit(50).all()
    data = [{
        "id": r.id,
        "started_at": r.started_at.strftime("%Y-%m-%d %H:%M:%S") if r.started_at else None,
        "finished_at": r.finished_at.strftime("%Y-%m-%d %H:%M:%S") if r.finished_at else None,
        "duration_seconds": r.duration_seconds,
        "status": r.status,
        "game_start_date": r.game_start_date,
        "game_end_date": r.game_end_date,
        "days_generated": r.days_generated,
        "table_counts": _counts(r.table_counts),
        "error": r.error,
    } for r in runs]

    if request.args.get("format") == "json":
        return jsonify(runs=data)

    lines = ["GENERATION RUN HISTORY (most recent first)", "=" * 78]
    if not data:
        lines.append("(no runs recorded yet)")
    for d in data:
        dur = (str(d["duration_seconds"]) + "s") if d["duration_seconds"] is not None else "—"
        window = "%s..%s" % (d["game_start_date"] or "?", d["game_end_date"] or "?")
        total_rows = sum(d["table_counts"].values()) if d["table_counts"] else 0
        lines.append("#%-4s %-19s %-9s window=%-24s days=%-4s dur=%-7s rows=%s"
                     % (d["id"], d["started_at"] or "?", d["status"], window,
                        d["days_generated"] if d["days_generated"] is not None else "—",
                        dur, "{:,}".format(total_rows) if total_rows else "—"))
        if d["table_counts"]:
            per = ", ".join("%s=%s" % (t, c) for t, c in sorted(d["table_counts"].items()))
            lines.append("       tables: " + per)
        if d["error"]:
            lines.append("       error: " + d["error"])
    return Response("\n".join(lines), mimetype="text/plain")


# ---------------------------------------------------------------------------
# Manage Scenario — author actor / malware configs from the UI (#3)
# ---------------------------------------------------------------------------

def _scenario_starter(kind):
    if kind == "malware":
        return ("name: newmalware\n"
                "filenames:\n  - example.exe\n"
                "paths:\n  - C:\\ProgramData\\\n"
                "recon_processes:\n  - name: cmd.exe\n    process: cmd.exe /c whoami\n"
                "c2_processes:\n  - name: rundll32.exe\n    process: rundll32.exe {ip_address}:443\n")
    return ("name: NewActor\n"
            "activity_start_date: \"2023-03-01\"\n"
            "activity_end_date: \"2023-03-15\"\n"
            "activity_start_hour: 9\n"
            "workday_length_hours: 8\n"
            "attacks:\n  - email:phishing\n")


@main.route("/admin/manage_scenario")
@roles_required("Admin")
@login_required
def manage_scenario():
    """List actor/malware configs and edit/clone them in an in-browser YAML editor."""
    from app.server.modules.scenario_admin import scenario_admin as sa
    files = sa.list_files()

    kind = request.args.get("kind") or "actor"
    name = request.args.get("name")
    is_clone = request.args.get("clone") == "1"
    editor = {"kind": "actor", "name": "", "content": _scenario_starter("actor")}

    if name:
        try:
            content = sa.clone_content(kind, name) if is_clone else sa.read_file(kind, name)
            editor = {"kind": kind, "name": ("" if is_clone else name), "content": content}
        except Exception as e:
            flash("Could not load %s: %s" % (name, e), "error")
    elif kind in ("actor", "malware") and request.args.get("new") == "1":
        editor = {"kind": kind, "name": "", "content": _scenario_starter(kind)}

    return render_template("admin/manage_scenario.html", files=files, editor=editor, errors=[])


@main.route("/admin/scenario/save", methods=["POST"])
@roles_required("Admin")
@login_required
def scenario_save():
    from app.server.modules.scenario_admin import scenario_admin as sa
    kind = request.form.get("kind", "actor")
    name = (request.form.get("name") or "").strip()
    content = request.form.get("content", "")

    errors = ["Please provide a file name."] if not name else sa.save_file(kind, name, content)
    if errors:
        return render_template("admin/manage_scenario.html",
                               files=sa.list_files(),
                               editor={"kind": kind, "name": name, "content": content},
                               errors=errors)

    record_admin_action("config.save", target="%s/%s" % (kind, name), detail="Saved scenario config")
    flash("Saved %s config '%s'." % (kind, name), "success")
    return redirect(url_for("main.manage_scenario", kind=kind,
                            name=name if name.endswith(".yaml") else name + ".yaml"))


@main.route("/admin/scenario/delete", methods=["POST"])
@roles_required("Admin")
@login_required
def scenario_delete():
    from app.server.modules.scenario_admin import scenario_admin as sa
    kind = request.form.get("kind", "actor")
    name = request.form.get("name", "")
    try:
        if sa.delete_file(kind, name):
            record_admin_action("config.delete", target="%s/%s" % (kind, name), detail="Deleted scenario config")
            flash("Deleted %s." % name, "success")
        else:
            flash("%s not found." % name, "error")
    except Exception as e:
        flash("Delete failed: %s" % e, "error")
    return redirect(url_for("main.manage_scenario"))


@main.route("/admin/generate_challenges", methods=["GET", "POST"])
@roles_required("Admin")
@login_required
def generate_challenges():
    """
    Auto-generate challenges from the scenario's ground truth (#11): malicious IPs,
    domains, sender addresses, malware families/hashes, attribution, and ATT&CK ids.
    GET previews (text, or ?format=json); POST creates the non-duplicate ones.
    Best run after a game has generated (most facts only exist post-generation).
    """
    from flask import Response
    from app.server.modules.challenge_gen.challenge_generator import (
        gather_scenario_facts, build_challenges,
    )

    actors, malware_by_name = gather_scenario_facts()
    proposed = build_challenges(actors, malware_by_name=malware_by_name)

    if request.method == "GET":
        if request.args.get("format") == "json":
            return jsonify(count=len(proposed), challenges=proposed)
        lines = ["AUTO-GENERATED CHALLENGES — preview (%d proposed)" % len(proposed), "=" * 72,
                 "Use the 'Auto-generate' button on Manage Challenges (or POST here) to create them.",
                 "Already-existing challenge names are skipped on create.", ""]
        for c in proposed:
            lines.append("[%3d] %-18s %s" % (c["value"], c["category"], c["name"]))
            lines.append("        Q: " + c["description"])
            lines.append("        A: " + (c["answer"][:120] + ("…" if len(c["answer"]) > 120 else "")))
        if not proposed:
            lines.append("(no facts available yet — run a game first so the ground truth exists)")
        return Response("\n".join(lines), mimetype="text/plain")

    # POST — create the non-duplicate challenges
    existing = {c.name for c in Challenge.query.all()}
    added = 0
    for c in proposed:
        if c["name"] in existing:
            continue
        db.session.add(Challenge(name=c["name"], category=c["category"],
                                 description=c["description"], answer=c["answer"], value=c["value"]))
        added += 1
    db.session.commit()
    if added:
        record_admin_action("challenge.generate", detail="Auto-generated %d challenge(s)" % added)
    flash("Auto-generated %d challenge(s) from the scenario ground truth (%d already existed)."
          % (added, len(proposed) - added), "success")
    return redirect(url_for("main.manage_challenges"))


# ---------------------------------------------------------------------------
# Intel-pack ingestion (admin) — #43
# ---------------------------------------------------------------------------
@main.route("/admin/import_intel_pack", methods=["POST"])
@roles_required("Admin")
@login_required
def import_intel_pack():
    """
    Import an uploaded intel pack (YAML). action=preview returns a text preview of the
    resulting actor config; action=apply saves it via scenario_admin (which validates).
    Real indicators are defanged unless ALLOW_REAL_INDICATORS is on.
    """
    from flask import Response
    from app.server.modules.intel_packs.intel_pack import import_pack
    import yaml as _yaml

    f = request.files.get("pack_file")
    if not f or not f.filename:
        flash("No intel pack selected.", "danger")
        return redirect(url_for("main.manage_scenario"))
    try:
        text = f.stream.read().decode("utf-8-sig")
    except Exception as e:
        flash("Could not read intel pack: %s" % e, "danger")
        return redirect(url_for("main.manage_scenario"))

    allow_real = bool(current_app.config.get("ALLOW_REAL_INDICATORS"))
    res = import_pack(text, allow_real=allow_real)
    if res["errors"]:
        flash("Intel pack invalid: " + "; ".join(res["errors"]), "danger")
        return redirect(url_for("main.manage_scenario"))

    cfg = res["actor_config"]
    if request.form.get("action") == "apply":
        from app.server.modules.scenario_admin import scenario_admin as _sa
        name = (cfg.get("name") or "imported") + ".yaml"
        content = _yaml.safe_dump(cfg, sort_keys=False)
        errs = _sa.save_file("actor", name, content)
        if errs:
            flash("Imported config failed validation: " + "; ".join(errs), "danger")
            return redirect(url_for("main.manage_scenario"))
        record_admin_action("config.import_intel_pack", target="actor/%s" % name,
                             detail="Imported %d techniques" % len(cfg.get("attacks", [])))
        msg = "Imported intel pack -> actor '%s' (%d techniques)." % (
            cfg.get("name"), len(cfg.get("attacks", [])))
        if res["notes"]:
            msg += " Skipped: " + "; ".join(res["notes"])
        flash(msg, "success")
        return redirect(url_for("main.manage_scenario", kind="actor", name=name))

    # preview (text/plain)
    lines = ["INTEL PACK PREVIEW", "=" * 60, "",
             "Resulting actor config (YAML):", "",
             _yaml.safe_dump(cfg, sort_keys=False)]
    if res["notes"]:
        lines += ["Notes:"] + ["  - " + n for n in res["notes"]] + [""]
    if res["warnings"]:
        lines += ["Warnings:"] + ["  - " + w for w in res["warnings"]] + [""]
    ind = res.get("indicators") or {}
    if any(ind.get(k) for k in ("domains", "ips", "urls")):
        lines += ["Indicators (%s):" % ("REAL" if allow_real else "defanged")]
        for k in ("domains", "ips", "urls"):
            if ind.get(k):
                lines.append("  %s: %s" % (k, ", ".join(ind[k])))
        lines.append("")
    if res.get("malware"):
        lines += ["Malware (hashes are strings only):"]
        for mw in res["malware"]:
            lines.append("  %s: %s (%s)" % (mw.get("name"), ", ".join(mw.get("hashes") or []), mw.get("source")))
    return Response("\n".join(lines), mimetype="text/plain")


# ---------------------------------------------------------------------------
# Malicious indicator seeding (admin)
# ---------------------------------------------------------------------------

import re as _re


def _detect_itype(value):
    """Auto-detect indicator type from its value."""
    v = value.strip()
    if _re.match(r'^\d{1,3}(\.\d{1,3}){3}$', v):
        return 'ip'
    if '@' in v and '.' in v.split('@')[-1]:
        return 'email'
    if _re.match(r'^[0-9a-fA-F]{32}$', v) or \
       _re.match(r'^[0-9a-fA-F]{40}$', v) or \
       _re.match(r'^[0-9a-fA-F]{56}$', v) or \
       _re.match(r'^[0-9a-fA-F]{64}$', v):
        return 'hash'
    return 'domain'


@main.route("/admin/manage_indicators")
@login_required
@roles_required("Admin")
def manage_indicators():
    """Admin: view and manage seeded malicious indicators."""
    indicators = MaliciousIndicator.query.order_by(MaliciousIndicator.added_at.desc()).all()
    counts = {
        'domain': MaliciousIndicator.query.filter_by(itype='domain').count(),
        'ip':     MaliciousIndicator.query.filter_by(itype='ip').count(),
        'email':  MaliciousIndicator.query.filter_by(itype='email').count(),
        'hash':   MaliciousIndicator.query.filter_by(itype='hash').count(),
    }
    return render_template("admin/manage_indicators.html", indicators=indicators, counts=counts)


@main.route("/admin/add_indicator", methods=["POST"])
@login_required
@roles_required("Admin")
def add_indicator():
    """Admin: add a single malicious indicator."""
    try:
        value = request.form.get("value", "").strip()
        itype = request.form.get("itype", "auto").strip()
        if not value:
            flash("Indicator value is required.", "error")
            return redirect(url_for("main.manage_indicators"))
        if itype == "auto":
            itype = _detect_itype(value)
        # Skip duplicates
        existing = MaliciousIndicator.query.filter_by(value=value).first()
        if existing:
            flash(f"Indicator already exists: {value}", "info")
            return redirect(url_for("main.manage_indicators"))
        ind = MaliciousIndicator(value=value, itype=itype)
        db.session.add(ind)
        db.session.commit()
        flash(f"Added indicator: {value} ({itype})", "success")
    except Exception as e:
        print("add_indicator error:", e)
        flash("Failed to add indicator: " + str(e), "error")
    return redirect(url_for("main.manage_indicators"))


@main.route("/admin/delete_indicator", methods=["POST"])
@login_required
@roles_required("Admin")
def delete_indicator():
    """Admin: remove a single malicious indicator."""
    try:
        ind_id = int(request.form["indicator_id"])
        ind = db.session.get(MaliciousIndicator, ind_id)
        if ind:
            db.session.delete(ind)
            db.session.commit()
            flash("Indicator removed.", "success")
    except Exception as e:
        print("delete_indicator error:", e)
        flash("Failed to delete indicator: " + str(e), "error")
    return redirect(url_for("main.manage_indicators"))


@main.route("/admin/bulk_add_indicators", methods=["POST"])
@login_required
@roles_required("Admin")
def bulk_add_indicators():
    """Admin: add many indicators from a textarea (one per line, optional ,type)."""
    try:
        raw = request.form.get("indicators", "")
        lines = [l.strip() for l in raw.splitlines() if l.strip()]
        added = skipped = 0
        for line in lines:
            parts = line.split(",", 1)
            value = parts[0].strip()
            itype = parts[1].strip() if len(parts) == 2 else "auto"
            if not value:
                continue
            if itype == "auto":
                itype = _detect_itype(value)
            if MaliciousIndicator.query.filter_by(value=value).first():
                skipped += 1
                continue
            db.session.add(MaliciousIndicator(value=value, itype=itype))
            added += 1
        db.session.commit()
        flash(f"Added {added} indicator(s). {skipped} duplicate(s) skipped.", "success")
    except Exception as e:
        print("bulk_add_indicators error:", e)
        flash("Failed to bulk-add indicators: " + str(e), "error")
    return redirect(url_for("main.manage_indicators"))


@main.route("/admin/clear_indicators", methods=["POST"])
@login_required
@roles_required("Admin")
def clear_indicators():
    """Admin: delete all malicious indicators."""
    try:
        count = MaliciousIndicator.query.delete()
        db.session.commit()
        flash(f"Cleared {count} indicator(s).", "success")
    except Exception as e:
        print("clear_indicators error:", e)
        flash("Failed to clear indicators: " + str(e), "error")
    return redirect(url_for("main.manage_indicators"))


@main.route("/admin/import_indicators_csv", methods=["POST"])
@login_required
@roles_required("Admin")
def import_indicators_csv():
    """Admin: upload a CSV file of malicious indicators."""
    try:
        f = request.files.get("csv_file")
        if not f or not f.filename:
            flash("No file uploaded.", "error")
            return redirect(url_for("main.manage_indicators"))
        import csv as _csv2
        import io as _io2
        reader = _csv2.reader(_io2.StringIO(f.read().decode("utf-8", errors="ignore")))
        added = skipped = 0
        for row in reader:
            if not row:
                continue
            value = row[0].strip()
            if not value or value.lower() in ("value", "indicator"):
                continue  # header row
            itype = row[1].strip() if len(row) > 1 else "auto"
            if itype not in ("domain", "ip", "email", "hash"):
                itype = _detect_itype(value)
            if MaliciousIndicator.query.filter_by(value=value).first():
                skipped += 1
                continue
            db.session.add(MaliciousIndicator(value=value, itype=itype))
            added += 1
        db.session.commit()
        flash(f"Imported {added} indicator(s). {skipped} duplicate(s) skipped.", "success")
    except Exception as e:
        print("import_indicators_csv error:", e)
        flash("Failed to import CSV: " + str(e), "error")
    return redirect(url_for("main.manage_indicators"))


# ---------------------------------------------------------------------------
# ADX configuration (admin)
# ---------------------------------------------------------------------------

@main.route("/admin/adx_config", methods=["GET", "POST"])
@login_required
@roles_required("Admin")
def adx_config():
    """Show and save ADX connection settings."""
    cfg = ADXConfig.query.get(1)
    if not cfg:
        cfg = ADXConfig()
        cfg.id = 1
        db.session.add(cfg)
        db.session.commit()

    if request.method == "POST":
        cfg.cluster_uri   = request.form.get("cluster_uri",   "").strip()
        cfg.ingest_uri    = request.form.get("ingest_uri",    "").strip()
        cfg.database      = request.form.get("database",      "").strip()
        cfg.tenant_id     = request.form.get("tenant_id",     "").strip()
        cfg.client_id     = request.form.get("client_id",     "").strip()
        new_secret        = request.form.get("client_secret", "").strip()
        if new_secret:          # only overwrite if a new value was entered
            cfg.client_secret = new_secret
        db.session.commit()
        flash("ADX configuration saved.", "success")
        return redirect(url_for("main.adx_config"))

    return render_template("admin/manage_adx_config.html", cfg=cfg)


@main.route("/admin/adx_test")
@login_required
@roles_required("Admin")
def adx_test():
    """Quick connectivity test — returns JSON."""
    try:
        lu = LogUploader()
        perms = lu.get_user_permissions()
        return jsonify(success=True, message=f"Connected. {len(perms)} principal(s) found.")
    except Exception as e:
        return jsonify(success=False, message=str(e))


# ---------------------------------------------------------------------------
# Live answer feed (admin)
# ---------------------------------------------------------------------------

@main.route("/admin/live_dashboard")
@login_required
@roles_required("Admin")
def live_dashboard():
    """Admin live feed dashboard — shows all challenge submissions in real time."""
    round_list = GameRound.query.order_by(GameRound.name).all()
    return render_template("admin/live_dashboard.html", rounds=round_list)


@main.route("/admin/audit_log")
@login_required
@roles_required("Admin")
def audit_log():
    """Admin-action audit trail (#37): privileged actions for accountability."""
    from app.server.modules.audit.audit_log import recent_actions
    prefix = (request.args.get("action") or "").strip() or None
    entries = recent_actions(limit=300, action_prefix=prefix)
    # distinct action prefixes for the filter dropdown (e.g. game, user, config, challenge)
    categories = sorted({(e["action"].split(".")[0]) for e in recent_actions(limit=1000)})
    return render_template("admin/audit_log.html", entries=entries,
                           categories=categories, current=prefix or "")


@main.route("/admin/live_feed")
@login_required
@roles_required("Admin")
def live_feed():
    """JSON polling endpoint for the live answer feed.

    Query params:
        since   (int)  — only return rows with id > since (default 0)
        round_id (int) — -1=all, 0=global only, >0=specific round
        limit   (int)  — max rows to return (default 100)
    """
    try:
        since    = int(request.args.get("since",    0))
        limit    = min(int(request.args.get("limit", 100)), 500)
        round_id = request.args.get("round_id", "-1")

        q = db.session.query(AnswerAttempt, Challenge, Users)\
            .join(Challenge, AnswerAttempt.challenge_id == Challenge.id)\
            .join(Users, AnswerAttempt.user_id == Users.id)\
            .filter(AnswerAttempt.id > since)\
            .filter(Users.team_id != 1)

        if round_id not in ("-1", "", None):
            rid = int(round_id)
            if rid == 0:
                q = q.filter(Challenge.round_id == None)
            elif rid > 0:
                q = q.filter(Challenge.round_id == rid)

        rows_raw = q.order_by(AnswerAttempt.id.desc()).limit(limit).all()

        rows = []
        max_id = since
        for attempt, ch, user in rows_raw:
            if attempt.id > max_id:
                max_id = attempt.id
            rows.append({
                "id":           attempt.id,
                "attempted_at": attempt.attempted_at.strftime("%Y-%m-%d %H:%M:%S"),
                "username":     user.username,
                "team":         user.team.name if user.team else "—",
                "challenge":    ch.name,
                "category":     ch.category,
                "submitted":    attempt.submitted,
                "correct":      bool(attempt.correct),
                "round_id":     ch.round_id,
            })

        # Stats (all time, matching round filter)
        sq = db.session.query(AnswerAttempt)\
            .join(Challenge, AnswerAttempt.challenge_id == Challenge.id)\
            .join(Users, AnswerAttempt.user_id == Users.id)\
            .filter(Users.team_id != 1)
        if round_id not in ("-1", "", None):
            rid = int(round_id)
            if rid == 0:
                sq = sq.filter(Challenge.round_id == None)
            elif rid > 0:
                sq = sq.filter(Challenge.round_id == rid)
        total   = sq.count()
        correct = sq.filter(AnswerAttempt.correct == True).count()
        pct     = round(correct / total * 100, 1) if total else 0

        # Anti-cheat surfacing (#26): scan a recent window of attempts for suspicious
        # patterns (shared answers across teams, fast copies, burst solving). Best-effort
        # — any failure here must never break the feed.
        flags = []
        try:
            recent_q = db.session.query(AnswerAttempt, Challenge, Users)\
                .join(Challenge, AnswerAttempt.challenge_id == Challenge.id)\
                .join(Users, AnswerAttempt.user_id == Users.id)\
                .filter(Users.team_id != 1)
            if round_id not in ("-1", "", None):
                rid = int(round_id)
                if rid == 0:
                    recent_q = recent_q.filter(Challenge.round_id == None)
                elif rid > 0:
                    recent_q = recent_q.filter(Challenge.round_id == rid)
            recent_raw = recent_q.order_by(AnswerAttempt.id.desc()).limit(500).all()
            attempts = [{
                "id": a.id, "user": u.username,
                "team": u.team.name if u.team else "—",
                "challenge_id": a.challenge_id, "challenge": c.name,
                "submitted": a.submitted, "correct": bool(a.correct),
                "at": a.attempted_at,
            } for a, c, u in recent_raw]

            from app.server.modules.anti_cheat.anti_cheat import analyze_attempts
            from app.server.modules.scoring.answer_matching import normalize_answer
            raw_flags = analyze_attempts(attempts, normalize=normalize_answer)
            for f in raw_flags:
                flags.append({
                    "type": f["type"], "severity": f["severity"],
                    "title": f["title"], "detail": f["detail"],
                    "challenge": f.get("challenge"), "teams": f.get("teams", []),
                    "at": f["at"].strftime("%Y-%m-%d %H:%M:%S") if f.get("at") else "",
                })
        except Exception as e:
            print("live_feed anti-cheat error:", e)

        return jsonify(rows=rows, max_id=max_id, flags=flags, stats={
            "total": total, "correct": correct, "pct": pct
        })
    except Exception as e:
        print("live_feed error:", e)
        return jsonify(rows=[], max_id=since, flags=[], stats={"total": 0, "correct": 0, "pct": 0})
