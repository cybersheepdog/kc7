from datetime import date
from datetime import datetime
import sys, os, time
import requests

from flask_sqlalchemy import SQLAlchemy

from flask import Flask, render_template, g
from flask_login import LoginManager, current_user
from flask_security import Security, SQLAlchemyUserDatastore



application = Flask(
            __name__,
            template_folder="client/templates",
            static_folder="client/static"
        )

# aws likes 'application' but I want to use 'app'
# this is a hack to make us both happy
# azure may want the same
app = application

# Import Configurations from config.py
# Depends on the environment (e.g. production, dev, testing...)
#export APPLICATION_SETTINGS='config.DevelopmentConfig' to set config
#app.config.from_object(os.environ['APPLICATION_SETTINGS'])
app.config.from_object('config.DevelopmentConfig')
app.config.from_object('config.ActivityVolumeSettings')

# Define the database object which is imported
# by modules and views
db = SQLAlchemy(app)

# Import a module / component using its blueprint handler variable (mod_auth)
from app.server.views import main
from app.server.auth.auth_views import auth
from app.server.models import Users, Team, Roles, GameSession, GameRound, Participation

# Register blueprint(s)
app.register_blueprint(main)
app.register_blueprint(auth)

# login manager to be used for authentication
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'

# Flask-Security datastore (must be set up before first request handling)
user_datastore = SQLAlchemyUserDatastore(db=db, user_model=Users, role_model=Roles)
security = Security(app, user_datastore)


def _run_db_migrations():
    """
    Add columns introduced after initial table creation.
    SQLite supports ALTER TABLE ... ADD COLUMN; we swallow the error if the
    column already exists so this is safe to call on every startup.
    """
    stmts = [
        "ALTER TABLE users ADD COLUMN score INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE users ADD COLUMN last_score_time DATETIME",
        "ALTER TABLE teams ADD COLUMN last_score_time DATETIME",
        "ALTER TABLE game_session ADD COLUMN uses_timer BOOLEAN NOT NULL DEFAULT 0",
        "ALTER TABLE game_session ADD COLUMN end_time DATETIME",
        "ALTER TABLE challenges ADD COLUMN round_id INTEGER REFERENCES game_rounds(id)",
        "ALTER TABLE game_rounds ADD COLUMN start_time DATETIME",
        "ALTER TABLE users ADD COLUMN fs_uniquifier VARCHAR(64)",
        "ALTER TABLE roles ADD COLUMN description VARCHAR(255)",
        "ALTER TABLE roles ADD COLUMN permissions TEXT",
    ]
    try:
        with db.engine.connect() as conn:
            for stmt in stmts:
                try:
                    conn.execute(db.text(stmt))
                    conn.commit()
                except Exception:
                    pass  # column already exists -- safe to ignore
    except Exception as e:
        print(f"DB migration error: {e}")


def _seed_db():
    """Ensure the minimum required rows exist (admin team, role, user, game session)."""
    # Populate fs_uniquifier for any existing users missing it (required by flask-security-too 4+)
    import uuid as _uuid
    for u in Users.query.filter(Users.fs_uniquifier == None).all():
        u.fs_uniquifier = str(_uuid.uuid4())
    db.session.commit()

    # Admin team
    if not Team.query.first():
        print("Creating admins team")
        db.session.add(Team(name='admins', score=0))
        db.session.commit()

    # Admin role
    if not Roles.query.first():
        admin_role = Roles(name='Admin')
        db.session.add(admin_role)
        db.session.commit()
    else:
        admin_role = Roles.query.first()

    # Admin user
    admin_team = db.session.get(Team, 1)
    if not Users.query.first():
        admin_password = app.config.get('ADMIN_PASSWORD', 'admin')
        if admin_password == 'admin':
            print("WARNING: using default admin password. "
                  "Set KC7_ADMIN_PASSWORD env var before first run.")
        admin_user = Users(
            username='admin',
            email='admin@logstream.com',
            password=admin_password,
            team=admin_team
        )
        admin_user.roles = [admin_role]
        db.session.add(admin_user)
        db.session.commit()

    # Game session singleton
    if not GameSession.query.all():
        try:
            current_session = GameSession(state=True, start_time=datetime.now())
            db.session.add(current_session)
            db.session.commit()
            print("Created a new game session!")
        except Exception as e:
            print("Failed to create a game session: %s" % e)


# Build the database, run migrations, and seed initial data — all inside an
# explicit app context so Flask-SQLAlchemy / Flask-Security work correctly.
with app.app_context():
    db.create_all()
    _run_db_migrations()
    _seed_db()


# Jinja2 custom filters
@app.template_filter('format_number')
def format_number(value):
    """Add thousands-separator commas to an integer."""
    try:
        return "{:,}".format(int(value))
    except (ValueError, TypeError):
        return value


# HTTP error handling
@app.errorhandler(404)
def not_found(error):
    return render_template('auth/404.html'), 404


@login_manager.user_loader
def load_user(user_id):
    # Flask-Security-Too 4+ stores fs_uniquifier (UUID string) in the session,
    # not the integer PK. Try uniquifier first, fall back to integer PK.
    user = Users.query.filter_by(fs_uniquifier=user_id).first()
    if user:
        return user
    try:
        return db.session.get(Users, int(user_id))
    except (ValueError, TypeError):
        return None



@app.before_request
def before_request():
    g.user = current_user
