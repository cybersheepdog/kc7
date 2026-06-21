import random
import string
import json
import datetime
from faker import Faker
from faker.providers import internet
from flask_security import RoleMixin, UserMixin
# Import password / encryption helper tools
from werkzeug.security import check_password_hash, generate_password_hash
from flask import jsonify

# Import the database object (db) from the main application module
# We will define this inside /app/__init__.py in the next sections.
from app import db
from app.server.modules.helpers.word_generator import WordGenerator

# instantiate faker
fake = Faker()
fake.add_provider(internet)

wordGenerator = WordGenerator()

# Define a base model for other database tables to inherit
class Base(db.Model):

    __abstract__    = True

    id              = db.Column(db.Integer, primary_key=True)

    def __init__(self, id, name, domain):

        self.id = id

    @staticmethod
    def string_to_list(field_value_as_str:str) -> "list[str]":
        """
        Converts a long string into a unique list by splitting on space
        removes any empty string values from list
        """
        vals = field_value_as_str.split("~")
        return list(set([f for f in vals if f!='']))


##########################################################
# The following classes are specific to user autentication
###########################################################

class AuthBase(db.Model):

    __abstract__    = True
    id              = db.Column(db.Integer, primary_key=True)


class Team(AuthBase):

    __tablename__   = "teams"

    name                    = db.Column(db.String(50), nullable=False)
    score                   = db.Column(db.Integer, nullable=False)
    _mitigations            = db.Column(db.Text)
    security_awareness      = db.Column(db.Float, nullable=False)
    last_score_time         = db.Column(db.DateTime, nullable=True)

    def __init__(self, name, score, _mitigations="", security_awareness=.25):

        self.name = name
        self.score = score
        self._mitigations = _mitigations
        self.security_awareness = security_awareness
        self.last_score_time = None

    def __repr__(self):
        return '<Team %r>' % self.name


class Users(AuthBase, RoleMixin):

    __tablename__   = "users"
    id              = db.Column('user_id', db.Integer, primary_key=True)
    active = db.Column('is_active', db.Boolean(), nullable=False, server_default='1')

    username        = db.Column('username', db.String(50), unique=True, index=True)
    password        = db.Column('pw_hash', db.String(150))
    fs_uniquifier   = db.Column(db.String(64), unique=True, nullable=True)
    email           = db.Column('email', db.String(50), unique=True, index=True)
    registered_on   = db.Column('registered_on', db.DateTime)
    score           = db.Column(db.Integer, default=0, nullable=False, server_default='0')
    last_score_time = db.Column(db.DateTime, nullable=True)

    team_id = db.Column(db.Integer, db.ForeignKey('teams.id'))
    team = db.relationship('Team', backref=db.backref('members', lazy='dynamic'))

    roles = db.relationship('Roles', secondary='user_roles', backref='users', lazy=True)

    def __init__(self, username, password, email, team):
        import uuid as _uuid
        self.username = username
        self.set_password(password)
        self.email = email
        self.registered_on = datetime.datetime.now()
        self.team = team
        self.score = 0
        self.last_score_time = None
        self.active = True
        self.fs_uniquifier = str(_uuid.uuid4())

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        if not self.password:
            return False
        try:
            return check_password_hash(self.password, password)
        except ValueError:
            # Hash is in flask-security format (bcrypt/argon2) from a previous
            # password reset bug. Try flask-security's verifier and, if it
            # passes, re-save in werkzeug format so future logins work normally.
            try:
                from flask_security.utils import verify_password as _fs_verify
                if _fs_verify(password, self.password):
                    self.set_password(password)
                    db.session.commit()
                    return True
            except Exception:
                pass
            return False

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        # Flask-Security-Too 4+ requires get_id() to return fs_uniquifier
        return self.fs_uniquifier

    def has_role(self, role):
        return role in self.get_roles()

    def get_roles(self):
        return [role.name for role in self.roles]

    def __repr__(self):
        return '<User %r>' % (self.username)


# Define the Role data-model
class Roles(AuthBase):
    __tablename__ = 'roles'
    id          = db.Column(db.Integer(), primary_key=True)
    name        = db.Column(db.String(50), unique=True)
    description = db.Column(db.String(255), nullable=True)
    permissions = db.Column(db.Text, nullable=True)  # comma-separated, required by flask-security-too

    def get_permissions(self):
        """Return a set of permissions for this role (required by flask-security-too)."""
        if self.permissions:
            return set(p.strip() for p in self.permissions.split(',') if p.strip())
        return set()


# Define the UserRoles association table
class UserRoles(AuthBase):
    __tablename__ = 'user_roles'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.user_id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('roles.id', ondelete='CASCADE'))


class Report(AuthBase):

    """
        A report object is generated by company employees
        Each report belongs to a team and is generated
        based on the security awareness of the company
    """
    __tablename__   = "report"

    subject                = db.Column(db.String(50), nullable=False)
    sender                 = db.Column(db.String(50), nullable=False)
    recipient              = db.Column(db.String(50), nullable=False)
    time                   = db.Column(db.String(50), nullable=False)

    team_id                = db.Column(db.Integer, db.ForeignKey('teams.id'))
    team                   = db.relationship('Team', backref=db.backref('reports', lazy='dynamic'))

    def __init__(self, subject, sender, recipient, time, team):

        self.subject = subject
        self.sender = sender
        self.recipient = recipient
        self.time = time
        self.team = team

    def __repr__(self):
        return '<Report %r>' % self.id


##########################################################
# The following classes are specific to game sessions
###########################################################

# Define the Role data-model
class GameSession(Base):
    id              = db.Column(db.Integer(), primary_key=True)
    state           = db.Column(db.Boolean)
    start_time      = db.Column(db.String(50)) #should be given as a timestamp float
    seed_date       = db.Column(db.String(50))
    time_multiplier = db.Column(db.Integer())
    uses_timer      = db.Column(db.Boolean, default=False, nullable=False, server_default="0")
    end_time        = db.Column(db.DateTime, nullable=True)

    def __init__(self, state, start_time, seed_date="2023-02-01", time_multiplier=1000):
        self.state = False
        self.seed_date = seed_date    # starting date for the game
        self.start_time = start_time  # real life start time of game
        self.time_multiplier = time_multiplier


##########################################################
# Challenge / Q&A system
##########################################################

class Challenge(AuthBase):
    """A question-and-answer challenge that players can solve for points."""
    __tablename__ = "challenges"

    name        = db.Column(db.String(100), nullable=False)
    category    = db.Column(db.String(50),  nullable=False, default="General")
    description = db.Column(db.Text,        nullable=False)
    answer      = db.Column(db.Text,        nullable=False)   # semicolon-separated for multiple accepted answers
    value       = db.Column(db.Integer,     nullable=False,   default=100)
    round_id    = db.Column(db.Integer, db.ForeignKey('game_rounds.id'), nullable=True)
    round       = db.relationship('GameRound', backref=db.backref('challenges', lazy='dynamic'))

    def __init__(self, name, category, description, answer, value=100, round_id=None):
        self.name        = name
        self.category    = category
        self.description = description
        self.answer      = answer
        self.value       = int(value)
        self.round_id    = round_id

    def check_answer(self, submitted):
        """
        Case-insensitive; supports multiple accepted answers separated by ';'.
        Answers are normalized (refanged, URL scheme/trailing slash stripped, etc.)
        on both sides before comparison, so structurally-identical indicators such as
        'http://bad.com', 'bad.com', 'bad.com/' and 'hxxp://bad[.]com' all match.
        Normalizing both sides can only add matches, never reject a previously-correct
        answer.
        """
        from app.server.modules.scoring.answer_matching import answer_matches
        return answer_matches(submitted, self.answer)

    def __repr__(self):
        return '<Challenge %r>' % self.name


class Solve(AuthBase):
    """Records that a specific user solved a specific challenge."""
    __tablename__  = "solves"
    __table_args__ = (
        db.UniqueConstraint('challenge_id', 'user_id', name='uq_solve_challenge_user'),
    )

    challenge_id    = db.Column(db.Integer, db.ForeignKey('challenges.id'),    nullable=False)
    user_id         = db.Column(db.Integer, db.ForeignKey('users.user_id'),    nullable=False)
    solved_at       = db.Column(db.DateTime, nullable=False)
    points_awarded  = db.Column(db.Integer,  nullable=False, default=0)

    challenge = db.relationship('Challenge', backref=db.backref('solves', lazy='dynamic'))
    user      = db.relationship('Users',     backref=db.backref('solves',     lazy='dynamic'))

    def __init__(self, challenge_id, user_id, points_awarded):
        self.challenge_id   = challenge_id
        self.user_id        = user_id
        self.solved_at      = datetime.datetime.now()
        self.points_awarded = points_awarded

    def __repr__(self):
        return '<Solve challenge=%r user=%r>' % (self.challenge_id, self.user_id)


class ChallengeGating(AuthBase):
    """
    Optional hint + unlock rules for a challenge (#32). Kept in a SEPARATE table (not new
    columns on `challenges`) so it auto-creates cleanly; a challenge with no row here
    behaves exactly as before — no hint, never locked.
    """
    __tablename__ = "challenge_gating"

    challenge_id    = db.Column(db.Integer, db.ForeignKey('challenges.id'), nullable=False, unique=True)
    hint            = db.Column(db.Text, nullable=True)
    hint_cost       = db.Column(db.Integer, nullable=False, default=0)
    unlock_at       = db.Column(db.DateTime, nullable=True)                       # timed unlock
    prerequisite_id = db.Column(db.Integer, db.ForeignKey('challenges.id'), nullable=True)  # unlocks after this is solved

    challenge    = db.relationship('Challenge', foreign_keys=[challenge_id],
                                   backref=db.backref('gating', uselist=False))
    prerequisite = db.relationship('Challenge', foreign_keys=[prerequisite_id])

    def __init__(self, challenge_id, hint=None, hint_cost=0, unlock_at=None, prerequisite_id=None):
        self.challenge_id    = challenge_id
        self.hint            = hint or None
        self.hint_cost       = int(hint_cost or 0)
        self.unlock_at       = unlock_at
        self.prerequisite_id = prerequisite_id or None


class HintReveal(AuthBase):
    """Records that a user revealed a challenge's hint (so the cost is charged once)."""
    __tablename__  = "hint_reveals"
    __table_args__ = (
        db.UniqueConstraint('challenge_id', 'user_id', name='uq_hint_challenge_user'),
    )

    challenge_id = db.Column(db.Integer, db.ForeignKey('challenges.id'), nullable=False)
    user_id      = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    cost         = db.Column(db.Integer, nullable=False, default=0)
    revealed_at  = db.Column(db.DateTime, nullable=False)

    def __init__(self, challenge_id, user_id, cost=0):
        self.challenge_id = challenge_id
        self.user_id      = user_id
        self.cost         = int(cost or 0)
        self.revealed_at  = datetime.datetime.now()


class MitigationAward(AuthBase):
    """
    Records each correct indicator (mitigation) award.

    Indicator scoring credits both the submitting user and their team the same points,
    but historically only the running totals were updated — there was no per-award
    record, which made scores impossible to recompute exactly. This row is the
    source-of-truth for indicator points (the equivalent of ``Solve`` for challenges).
    """
    __tablename__ = "mitigation_awards"

    user_id        = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    team_id        = db.Column(db.Integer, nullable=True)
    indicator      = db.Column(db.String(500), nullable=False)
    points_awarded = db.Column(db.Integer, nullable=False, default=0)
    awarded_at     = db.Column(db.DateTime, nullable=False)

    def __init__(self, user_id, team_id, indicator, points_awarded):
        self.user_id        = user_id
        self.team_id        = team_id
        self.indicator      = (indicator or "")[:500]
        self.points_awarded = points_awarded
        self.awarded_at     = datetime.datetime.now()

    def __repr__(self):
        return '<MitigationAward user=%r indicator=%r>' % (self.user_id, self.indicator)


class GameRunLog(AuthBase):
    """
    A record of each data-generation run, for facilitator observability — when a game
    was generated, how long it took, whether it succeeded, and the scenario window.
    """
    __tablename__ = "game_run_logs"

    started_at      = db.Column(db.DateTime, nullable=False)
    finished_at     = db.Column(db.DateTime, nullable=True)
    status          = db.Column(db.String(20), nullable=False, default="running")  # running|complete|error
    error           = db.Column(db.String(500), nullable=True)
    game_start_date = db.Column(db.String(50), nullable=True)
    game_end_date   = db.Column(db.String(50), nullable=True)
    days_generated  = db.Column(db.Integer, nullable=True)
    table_counts    = db.Column(db.Text, nullable=True)  # JSON: {table: rows_ingested}

    def __init__(self, status="running"):
        self.started_at = datetime.datetime.now()
        self.status = status

    @property
    def duration_seconds(self):
        if self.finished_at and self.started_at:
            return int((self.finished_at - self.started_at).total_seconds())
        return None

    def __repr__(self):
        return '<GameRunLog %r %r>' % (self.started_at, self.status)



##########################################################
# Live answer attempt log (all submissions, right or wrong)
##########################################################

class AnswerAttempt(AuthBase):
    """Logs every challenge submission so admins can see live activity."""
    __tablename__ = "answer_attempts"

    challenge_id = db.Column(db.Integer, db.ForeignKey('challenges.id'), nullable=False)
    user_id      = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    submitted    = db.Column(db.String(500), nullable=False)
    correct      = db.Column(db.Boolean, nullable=False, default=False)
    attempted_at = db.Column(db.DateTime, nullable=False)

    challenge = db.relationship('Challenge', backref=db.backref('attempts', lazy='dynamic'))
    user      = db.relationship('Users',     backref=db.backref('attempts', lazy='dynamic'))

    def __init__(self, challenge_id, user_id, submitted, correct):
        self.challenge_id = challenge_id
        self.user_id      = user_id
        self.submitted    = submitted[:500]
        self.correct      = correct
        self.attempted_at = datetime.datetime.now()

    def to_dict(self):
        return {
            'id':           self.id,
            'attempted_at': self.attempted_at.strftime('%Y-%m-%d %H:%M:%S'),
            'username':     self.user.username  if self.user      else '?',
            'team':         self.user.team.name if (self.user and self.user.team) else '—',
            'challenge':    self.challenge.name if self.challenge else '?',
            'category':     self.challenge.category if self.challenge else '?',
            'round_id':     self.challenge.round_id if self.challenge else None,
            'submitted':    self.submitted,
            'correct':      self.correct,
        }

    def __repr__(self):
        return '<AnswerAttempt challenge=%r user=%r correct=%r>' % (
            self.challenge_id, self.user_id, self.correct)


class AdminAudit(AuthBase):
    """Append-only audit trail of privileged admin actions (#37)."""
    __tablename__ = "admin_audit"

    actor_user_id  = db.Column(db.Integer, nullable=True)   # admin who acted (nullable: may be system)
    actor_username = db.Column(db.String(150), nullable=False, default="?")  # denormalized for display
    action         = db.Column(db.String(80),  nullable=False)  # e.g. "game.start", "user.edit"
    target         = db.Column(db.String(200), nullable=True)   # what was acted on
    detail         = db.Column(db.String(500), nullable=True)   # freeform context
    ip             = db.Column(db.String(64),  nullable=True)
    created_at     = db.Column(db.DateTime,    nullable=False)

    def __init__(self, actor_user_id, actor_username, action, target=None, detail=None, ip=None):
        self.actor_user_id  = actor_user_id
        self.actor_username = (actor_username or "?")[:150]
        self.action         = (action or "?")[:80]
        self.target         = (target or None) and str(target)[:200]
        self.detail         = (detail or None) and str(detail)[:500]
        self.ip             = (ip or None) and str(ip)[:64]
        self.created_at     = datetime.datetime.now()

    def to_dict(self):
        return {
            "id":         self.id,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S") if self.created_at else "",
            "actor":      self.actor_username,
            "action":     self.action,
            "target":     self.target or "",
            "detail":     self.detail or "",
            "ip":         self.ip or "",
        }

    def __repr__(self):
        return '<AdminAudit %r by %r>' % (self.action, self.actor_username)


##########################################################
# Named game rounds with player registration
##########################################################

class GameRound(AuthBase):
    """
    A named Q&A session that players join via a password code.
    Challenges can be assigned to a round; scoring still rolls up
    to the global user.score / team.score leaderboard.
    """
    __tablename__ = "game_rounds"

    name       = db.Column(db.String(100), nullable=False)
    password   = db.Column(db.String(50),  unique=True, nullable=False)
    created_at = db.Column(db.DateTime,    nullable=False)
    uses_timer = db.Column(db.Boolean,     default=False, nullable=False, server_default="0")
    start_time = db.Column(db.DateTime,    nullable=True)
    end_time   = db.Column(db.DateTime,    nullable=True)

    def __init__(self, name, password):
        self.name       = name
        self.password   = password
        self.created_at = datetime.datetime.now()
        self.uses_timer = False
        self.start_time = None
        self.end_time   = None

    @property
    def is_expired(self):
        return bool(self.uses_timer and self.end_time and
                    datetime.datetime.now() > self.end_time)

    @property
    def participant_count(self):
        return Participation.query.filter_by(round_id=self.id).count()

    @property
    def challenge_count(self):
        return self.challenges.count()

    def __repr__(self):
        return '<GameRound %r>' % self.name


class Participation(AuthBase):
    """Records that a user has joined a specific game round."""
    __tablename__  = "participation"
    __table_args__ = (
        db.UniqueConstraint('round_id', 'user_id', name='uq_participation_round_user'),
    )

    round_id  = db.Column(db.Integer, db.ForeignKey('game_rounds.id',   ondelete='CASCADE'), nullable=False)
    user_id   = db.Column(db.Integer, db.ForeignKey('users.user_id',    ondelete='CASCADE'), nullable=False)
    joined_at = db.Column(db.DateTime, nullable=False)

    round = db.relationship('GameRound', backref=db.backref('participants', lazy='dynamic'))
    user  = db.relationship('Users',     backref=db.backref('participations', lazy='dynamic'))

    def __init__(self, round_id, user_id):
        self.round_id  = round_id
        self.user_id   = user_id
        self.joined_at = datetime.datetime.now()

    def __repr__(self):
        return '<Participation round=%r user=%r>' % (self.round_id, self.user_id)


##########################################################
# Manually-seeded malicious indicators for scoring
##########################################################

class MaliciousIndicator(AuthBase):
    """
    Admin-seeded indicators used by get_malicious_indicators() for scoring.
    Allows the app to score player submissions against a pre-existing ADX
    dataset without requiring a local start_game() run.
    """
    __tablename__ = "malicious_indicators"

    value    = db.Column(db.String(255), unique=True, nullable=False, index=True)
    itype    = db.Column(db.String(20),  nullable=False)   # 'domain' | 'ip' | 'email' | 'hash'
    added_at = db.Column(db.DateTime,   nullable=False)

    def __init__(self, value, itype):
        self.value    = value.strip().lower()
        self.itype    = itype.strip().lower()
        self.added_at = datetime.datetime.now()

    def __repr__(self):
        return '<MaliciousIndicator %r type=%r>' % (self.value, self.itype)


##########################################################
# ADX connection configuration (singleton, stored in DB)
##########################################################

class ADXConfig(AuthBase):
    """
    Stores Azure Data Explorer connection settings so admins can configure
    the cluster through the GUI rather than editing config.py.
    Only one row (id=1) is ever used.
    """
    __tablename__ = "adx_config"

    cluster_uri  = db.Column(db.String(255), nullable=True)   # e.g. https://mycluster.eastus.kusto.windows.net
    ingest_uri   = db.Column(db.String(255), nullable=True)   # e.g. https://ingest-mycluster.eastus.kusto.windows.net
    database     = db.Column(db.String(100), nullable=True)
    tenant_id    = db.Column(db.String(100), nullable=True)
    client_id    = db.Column(db.String(100), nullable=True)
    client_secret = db.Column(db.String(255), nullable=True)

    @property
    def is_configured(self):
                return all([self.cluster_uri, self.database, self.tenant_id,
                    self.client_id, self.client_secret])

    def __repr__(self):
        return '<ADXConfig cluster=%r>' % self.cluster_uri
