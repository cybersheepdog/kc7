
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
    return render_template("main/score.html")


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

    return jsonify({
        "running":      GAME_PROGRESS.get("running", False),
        "complete":     GAME_PROGRESS.get("complete", False),
        "current_date": GAME_PROGRESS.get("current_date"),
        "start_date":   GAME_PROGRESS.get("start_date"),
        "end_date":     GAME_PROGRESS.get("end_date"),
        "error":        GAME_PROGRESS.get("error"),
        "progress_pct": progress_pct,
    })


@main.route("/admin/stop_game", methods=["GET"])
@roles_required("Admin")
@login_required
def stop_game():
    print("Stopping the game")
    current_session = db.session.get(GameSession, 1)
    current_session.state = False
    db.session.commit()
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
        malicious = get_malicious_indicators()
        correct_new = [ind for ind in newly_added if ind in malicious]

        game_session = db.session.get(GameSession, 1)
        points_per_correct = calculate_time_weighted_points(POINTS_PER_INDICATOR, game_session)
        points_earned = len(correct_new) * points_per_correct

        now = datetime.now()
        if points_earned > 0:
            current_user.score = (current_user.score or 0) + points_earned
            current_user.last_score_time = now
            current_user.team.score = (current_user.team.score or 0) + points_earned
            if current_user.team.last_score_time is None:
                current_user.team.last_score_time = now
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
            from flask_security import hash_password
            user.password = hash_password(new_pass)

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
    team_list = Team.query.all()
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


@main.route("/get_score", methods=["GET"])
def get_score():
    """
    Return leaderboard data for both teams and individual players.
    Excludes the admin team (id=1) and its members.
    Ranking: higher score first; ties broken by who first scored (earlier wins).
    """
    try:
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

        # Individual leaderboard
        players = db.session.query(Users).filter(Users.team_id != 1).all()
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

        return jsonify(SCORES=SCORES, INDIVIDUAL=INDIVIDUAL)
    except Exception as e:
        print(e)
        abort(404)


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
        game_session  = db.session.get(GameSession, 1)
        points_earned = calculate_time_weighted_points(challenge.value, game_session)

        now = datetime.now()
        current_user.score = (current_user.score or 0) + points_earned
        current_user.last_score_time = now
        current_user.team.score = (current_user.team.score or 0) + points_earned
        if current_user.team.last_score_time is None:
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
    return render_template("admin/manage_challenges.html", challenges=challenge_list, rounds=round_list)


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
        if ch:
            db.session.delete(ch)
        db.session.commit()
        flash("Challenge deleted.", "success")
    except Exception as e:
        print("delete_challenge error: " + str(e))
        flash("Failed to delete challenge.", "error")
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
    players = Users.query.filter(Users.id.in_(participant_ids)).all()

    player_data = []
    for p in players:
        round_score = db.session.query(sqlfunc.sum(Solve.points_awarded))\
            .join(Challenge, Solve.challenge_id == Challenge.id)\
            .filter(Challenge.round_id == round_id)\
            .filter(Solve.user_id == p.id)\
            .scalar() or 0
        # tiebreak: first solve time in this round
        first_solve = db.session.query(sqlfunc.min(Solve.solved_at))\
            .join(Challenge, Solve.challenge_id == Challenge.id)\
            .filter(Challenge.round_id == round_id)\
            .filter(Solve.user_id == p.id)\
            .scalar()
        player_data.append({
            "username": p.username,
            "team": p.team.name if p.team else "--",
            "score": round_score,
            "first_solve": first_solve.isoformat() if first_solve else "9999",
        })

    player_data.sort(key=lambda x: (-x["score"], x["first_solve"]))

    return render_template(
        "main/round_rankings.html",
        game_round=game_round,
        player_data=player_data,
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
        end_time_str = request.form.get("end_time", "").strip()
        if end_time_str:
            gr.end_time   = datetime.strptime(end_time_str, "%Y-%m-%dT%H:%M")
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
        db.session.commit()
        state = "enabled" if gr.uses_timer else "disabled"
        flash("Timer " + state + " for \"" + gr.name + "\".", "success")
    except Exception as e:
        print("toggle_round_timer error: " + str(e))
        flash("Failed to toggle timer: " + str(e), "error")
    return redirect(url_for("main.manage_rounds"))


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


@main.route("/admin/live_dashboard")
@login_required
@roles_required("Admin")
def live_dashboard():
    """Admin live feed dashboard — shows all challenge submissions in real time."""
    round_list = GameRound.query.order_by(GameRound.name).all()
    return render_template("admin/live_dashboard.html", rounds=round_list)


@main.route("/admin/live_feed")
@login_required
@roles_required("Admin")
def live_feed():
    """
    JSON feed of recent AnswerAttempts for the live dashboard.
    ?since=<id>   — only return attempts with id > since (for incremental polling)
    ?round_id=<n> — filter to challenges belonging to this round (0 = global only, -1 = all)
    ?limit=<n>    — max rows to return (default 200)
    """
    since    = int(request.args.get("since",    0))
    round_id = request.args.get("round_id", "-1")   # "-1" means all rounds
    limit    = min(int(request.args.get("limit", 200)), 500)

    q = AnswerAttempt.query.filter(AnswerAttempt.id > since)

    if round_id != "-1":
        rid = int(round_id)
        # join to filter by challenge.round_id
        q = q.join(Challenge, AnswerAttempt.challenge_id == Challenge.id)
        if rid == 0:
            q = q.filter(Challenge.round_id == None)
        else:
            q = q.filter(Challenge.round_id == rid)

    attempts = q.order_by(AnswerAttempt.id.desc()).limit(limit).all()

    rows = [a.to_dict() for a in attempts]

    # Stats for the whole filtered set (not just this page)
    stats_q = AnswerAttempt.query
    if round_id != "-1":
        rid = int(round_id)
        stats_q = stats_q.join(Challenge, AnswerAttempt.challenge_id == Challenge.id)
        if rid == 0:
            stats_q = stats_q.filter(Challenge.round_id == None)
        else:
            stats_q = stats_q.filter(Challenge.round_id == rid)
    total      = stats_q.count()
    correct_ct = stats_q.filter(AnswerAttempt.correct == True).count()
    max_id     = db.session.query(sqlfunc.max(AnswerAttempt.id)).scalar() or 0

    return jsonify(
        rows=rows,
        max_id=max_id,
        stats=dict(total=total, correct=correct_ct,
                   pct=round(100 * correct_ct / total, 1) if total else 0),
    )


@main.route("/admin/manage_indicators")
@roles_required("Admin")
@login_required
def manage_indicators():
    """Admin: view and manage manually-seeded malicious indicators."""
    indicators = MaliciousIndicator.query.order_by(
        MaliciousIndicator.itype, MaliciousIndicator.value
    ).all()
    counts = {
        'domain': sum(1 for i in indicators if i.itype == 'domain'),
        'ip':     sum(1 for i in indicators if i.itype == 'ip'),
        'email':  sum(1 for i in indicators if i.itype == 'email'),
        'hash':   sum(1 for i in indicators if i.itype == 'hash'),
    }
    return render_template("admin/manage_indicators.html",
                           indicators=indicators, counts=counts)


@main.route("/admin/add_indicator", methods=["POST"])
@roles_required("Admin")
@login_required
def add_indicator():
    """Admin: add a single indicator."""
    try:
        value = request.form.get("value", "").strip().lower()
        itype = request.form.get("itype", "").strip().lower()
        if not value:
            flash("Indicator value is required.", "error")
            return redirect(url_for("main.manage_indicators"))
        if itype not in ("domain", "ip", "email", "hash"):
            itype = _detect_itype(value)
        if MaliciousIndicator.query.filter_by(value=value).first():
            flash("Indicator already exists: " + value, "info")
            return redirect(url_for("main.manage_indicators"))
        db.session.add(MaliciousIndicator(value=value, itype=itype))
        db.session.commit()
        flash("Added " + itype + ": " + value, "success")
    except Exception as e:
        print("add_indicator error: " + str(e))
        flash("Failed to add indicator: " + str(e), "error")
    return redirect(url_for("main.manage_indicators"))


@main.route("/admin/delete_indicator", methods=["POST"])
@roles_required("Admin")
@login_required
def delete_indicator():
    """Admin: delete a single indicator."""
    try:
        ind_id = int(request.form["indicator_id"])
        ind = db.session.get(MaliciousIndicator, ind_id)
        if ind:
            db.session.delete(ind)
            db.session.commit()
            flash("Indicator removed.", "success")
    except Exception as e:
        print("delete_indicator error: " + str(e))
        flash("Failed to delete indicator.", "error")
    return redirect(url_for("main.manage_indicators"))


@main.route("/admin/bulk_add_indicators", methods=["POST"])
@roles_required("Admin")
@login_required
def bulk_add_indicators():
    """
    Admin: add multiple indicators at once from a textarea (one per line).
    Type is auto-detected per line. Duplicates are silently skipped.
    """
    try:
        raw     = request.form.get("indicators", "")
        lines   = [l.strip().lower() for l in raw.splitlines() if l.strip()]
        added   = 0
        skipped = 0
        for line in lines:
            # Support optional  "value,type" format
            if ',' in line:
                parts = [p.strip() for p in line.split(',', 1)]
                value = parts[0]
                itype = parts[1] if parts[1] in ("domain", "ip", "email", "hash") else _detect_itype(value)
            else:
                value = line
                itype = _detect_itype(value)
            if not value:
                continue
            if MaliciousIndicator.query.filter_by(value=value).first():
                skipped += 1
                continue
            db.session.add(MaliciousIndicator(value=value, itype=itype))
            added += 1
        db.session.commit()
        flash("Added " + str(added) + " indicator(s). Skipped " + str(skipped) + " duplicate(s).", "success")
    except Exception as e:
        print("bulk_add_indicators error: " + str(e))
        flash("Bulk add failed: " + str(e), "error")
    return redirect(url_for("main.manage_indicators"))


@main.route("/admin/import_indicators_csv", methods=["POST"])
@roles_required("Admin")
@login_required
def import_indicators_csv():
    """
    Admin: import indicators from a CSV file.
    Expected columns: value[, type]  — type column is optional; auto-detected if absent.
    """
    import csv, io
    try:
        f = request.files.get("csv_file")
        if not f or not f.filename:
            flash("No file selected.", "error")
            return redirect(url_for("main.manage_indicators"))
        stream = io.StringIO(f.stream.read().decode("utf-8-sig"), newline=None)
        reader = csv.reader(stream)
        added   = 0
        skipped = 0
        for i, row in enumerate(reader):
            if not row:
                continue
            value = row[0].strip().lower()
            if not value or (i == 0 and value in ("value", "indicator", "ioc")):
                continue   # skip header
            itype = row[1].strip().lower() if len(row) > 1 else ""
            if itype not in ("domain", "ip", "email", "hash"):
                itype = _detect_itype(value)
            if MaliciousIndicator.query.filter_by(value=value).first():
                skipped += 1
                continue
            db.session.add(MaliciousIndicator(value=value, itype=itype))
            added += 1
        db.session.commit()
        flash("Imported " + str(added) + " indicator(s). Skipped " + str(skipped) + " duplicate(s).", "success")
    except Exception as e:
        print("import_indicators_csv error: " + str(e))
        flash("CSV import failed: " + str(e), "error")
    return redirect(url_for("main.manage_indicators"))


@main.route("/admin/clear_indicators", methods=["POST"])
@roles_required("Admin")
@login_required
def clear_indicators():
    """Admin: remove ALL manually-seeded indicators."""
    try:
        count = MaliciousIndicator.query.count()
        MaliciousIndicator.query.delete()
        db.session.commit()
        flash("Cleared " + str(count) + " indicator(s).", "success")
    except Exception as e:
        print("clear_indicators error: " + str(e))
        flash("Failed to clear indicators: " + str(e), "error")
    return redirect(url_for("main.manage_indicators"))
