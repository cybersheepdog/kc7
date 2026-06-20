
# Import flask dependencies
from flask import Blueprint, request, render_template, \
                  flash, g, session, redirect, url_for, current_app
from flask_login import logout_user, current_user, login_required
from flask_security import login_user
from itsdangerous import URLSafeTimedSerializer

from app.server.models import *
from app.server.auth.forms import EmailForm, PasswordForm
from app.server.utils import *


# Define the blueprint: 'auth', set its url prefix: app.url/auth
auth = Blueprint('auth', __name__)


def _get_ts():
    """Return a URLSafeTimedSerializer using the app's secret key."""
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'])


def send_email(subject, recipient, html):
    """
    Stub email sender.  Wire up Flask-Mail + a real mail config to enable.
    For now we log the attempt and flash a friendly message.
    """
    print(f"[send_email] Would send '{subject}' to {recipient}")
    flash("Email sending is not configured on this server. "
          "Ask your admin to reset your password manually.", "warning")


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('auth/login.html')

    username = request.form['username']
    password = request.form['password']
    remember_me = False
    if 'remember_me' in request.form:
        remember_me = True
    registered_user = Users.query.filter_by(username=username).first()
    if (registered_user is not None) and (registered_user.check_password(password)):
        login_user(registered_user, remember=remember_me)
        flash('Logged in successfully', 'success')
        return redirect(request.args.get('next') or url_for('main.home'))
    else:
        flash('Username or Password is invalid', 'error')
    return redirect(url_for('auth.login'))


@auth.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.home'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        teams = Team.query.all()
        return render_template('auth/register.html', teams=teams)
    username = request.form['username']
    password = request.form['password']
    email = request.form['email']
    team_id = request.form['team_id']

    username_exists, email_exists = False, False
    try:
        username_exists = Users.query.filter_by(username=username).first()
        email_exists = Users.query.filter_by(email=email).first()
    except:
        pass

    if username_exists or email_exists:
        flash("Sorry, an account with this username or email already exists", "error")
    else:
        try:
            print("team id is %s" % team_id)
            team = db.session.get(Team, int(team_id))
            user = Users(username, password, email, team=team)
            db.session.add(user)
            db.session.commit()
            flash('User successfully registered', "success")
        except Exception as e:
            print("failed to create user: %s" % e)
            flash("Oops, something went wrong in creating your account", "error")

    return redirect(url_for('auth.login'))


@auth.route('/reset', methods=["GET", "POST"])
def reset():
    form = EmailForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        # Always show the same message whether the email exists or not
        # (prevents user enumeration)
        if user:
            subject = "Password reset requested"
            token = _get_ts().dumps(user.email, salt='recover-key')
            recover_url = url_for('auth.reset_with_token', token=token, _external=True)
            html = render_template('email/recover.html', recover_url=recover_url)
            send_email(subject, user.email, html)
        flash('If that email is registered, a reset link has been sent.', "success")
        return redirect(url_for('main.home'))
    return render_template('auth/reset.html', form=form)


@auth.route('/reset/<token>', methods=["GET", "POST"])
def reset_with_token(token):
    try:
        email = _get_ts().loads(token, salt="recover-key", max_age=86400)
    except:
        abort(404)

    form = PasswordForm()

    if form.validate_on_submit():
        user = Users.query.filter_by(email=email).first_or_404()
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Password reset successfully. Please log in.", "success")
        return redirect(url_for('auth.login'))

    return render_template('auth/reset_with_token.html', form=form, token=token)
