import os

# to set vars automatically in dev
# source ./set_config.py 


# in production check this out
# https://devcenter.heroku.com/articles/config-vars#managing-config-vars

class BaseConfig(object):
    DEBUG = False
    TESTING = False
    
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DATABASE_CONNECT_OPTIONS = {}

    # Application threads. A common general assumption is
    # using 2 per available processor cores - to handle
    # incoming requests using one and performing background
    # operations using the other.
    THREADS_PER_PAGE = 2

    SQLALCHEMY_DATABASE_URI = 'sqlite:///flaskr.db'
    
    # Secret key for signing cookies and sessions.
    # Set the KC7_SECRET_KEY environment variable in production.
    # Falls back to a random key in dev (sessions won't survive restarts without a fixed value).
    SECRET_KEY = os.environ.get('KC7_SECRET_KEY') or os.urandom(32)

    # Required by flask-security-too for token/email operations.
    # Set KC7_SECURITY_SALT in production to a long random string.
    SECURITY_PASSWORD_SALT = os.environ.get('KC7_SECURITY_SALT', 'kc7-default-salt-change-in-prod')

    ################################
    # AZURE ENVIRONMENT VARIABLES
    # FOLLOW THE README TO REPLACE THESE VALUES
    ################################

    # Override the seeded admin password via environment variable (default: 'admin').
    # Set KC7_ADMIN_PASSWORD before first run to avoid using the default credentials.
    ADMIN_PASSWORD = os.environ.get('KC7_ADMIN_PASSWORD', 'admin')

    AAD_TENANT_ID = "{YOUR TENANT ID}" #https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-how-to-find-tenant
    KUSTO_URI = "https://{clustername}.eastus.kusto.windows.net"
    KUSTO_INGEST_URI =  "https://ingest-{clustername}.eastus.kusto.windows.net"
    DATABASE = "SecurityLogs"

    # Register an azure application and generate secrets
    # give the app permission to edit your azure data explorer cluster
    # App secret can only be seen right after creation
    CLIENT_ID = "{YOUR REGISTERED APP CLIENT ID}" 
    CLIENT_SECRET = "{YOUR RESTERED APP CLIENT SECRET}"
    

class DevelopmentConfig(BaseConfig):
    DEBUG = True
    TESTING = True

    ADX_DEBUG_MODE=True   # Set to True if you don't want to write to Azure

    SQLALCHEMY_DATABASE_URI = 'sqlite:///flaskr.db'


class TestingConfig(BaseConfig):
    DEBUG = False
    TESTING = True

    
class ProductionConfig(BaseConfig):
    DEBUG = False
    #SQLALCHEMY_DATABASE_URI = os.environ['DATABASE_URL_HERE']

    # --- Optional dynamic / first-blood scoring (off by default) ---
    # When enabled, a challenge's value decays as more teams solve it (CTFd-style) and
    # the first solver earns a bonus. When disabled, the existing time-weighted scoring
    # is used unchanged, so leaving these as-is preserves current behavior.
    DYNAMIC_SCORING_ENABLED = False
    DYNAMIC_SCORING_MINIMUM = 50      # floor a challenge's value decays toward
    DYNAMIC_SCORING_DECAY = 20        # number of solves after which the floor is reached
    FIRST_BLOOD_BONUS_PCT = 0         # percent bonus for the first solver (0 = no bonus)

    # --- Real-world intel safety toggles (default OFF) ---
    # Guardrails for using real threat-intel in scenarios. Keep these OFF unless you
    # have ensured indicators are inert: synthetic, sinkholed, or defanged — never live
    # C2 a player could reach, and real malware hashes only as strings (seed files stay
    # EICAR). See app/server/modules/safety/safety.py.
    ALLOW_REAL_INDICATORS = False
    ALLOW_REAL_C2_INFRASTRUCTURE = False

    # --- Campaign / kill-chain mode (off by default) ---
    # When enabled, an actor's post-compromise stages (kerberoasting, lateral movement,
    # log clearing, persistence, cloud) thread through ONE pinned compromised host and
    # C2 IP per actor, turning scattered events into a single huntable intrusion. When
    # disabled, each technique picks its own victim/IP as before.
    CAMPAIGN_MODE_ENABLED = False

    # --- Actor-consistent infrastructure reuse (off by default) — #44 ---
    # When enabled, each non-default actor's IPs are drawn from a small, stable set of
    # "owned" network ranges (ASN-like /16 prefixes) deterministically seeded from the
    # actor's name, instead of being scattered randomly across the whole IPv4 space.
    # The result is that an actor's infrastructure clusters in the same recognizable
    # ranges across campaigns and re-runs — a pivotable fingerprint that lets two
    # separate intrusions be attributed to one actor. When disabled, IPs are random as
    # before. Domains (stable per-actor TLDs/themes) and malware hashes (stable per
    # family) are already actor-consistent. See modules/infrastructure/infra_reuse.py.
    INFRA_REUSE_ENABLED = False
    INFRA_REUSE_PREFIX_COUNT = 3

    # --- Per-technique detection fidelity (off by default) — #15 ---
    # When enabled, each advanced technique can trip a SecurityAlert with a probability
    # and severity drawn from its detection profile (see modules/alerts/detection.py):
    # loud techniques (PsExec service install, impossible-travel sign-in, public-bucket
    # exfil) alert often; deliberately quiet ones (Kerberoasting, log clearing) rarely
    # do — giving players authentic visibility gaps to work around. When disabled, no
    # technique-detection alerts are emitted and behavior is unchanged.
    TECHNIQUE_ALERTS_ENABLED = False

    # --- Live scoreboard push via Server-Sent Events (off by default) — #24 ---
    # When enabled, the leaderboard receives pushed updates over an SSE stream
    # (/score_stream) so the room sees scoring movement in near-real-time instead of
    # waiting for the next poll. Requires a threaded / multi-worker server (gunicorn, or
    # Flask run(threaded=True)) since the connection is long-lived. When disabled, the
    # scoreboard transparently falls back to polling /get_score (unchanged behavior).
    LIVE_SCORE_SSE_ENABLED = False
    LIVE_SCORE_SSE_POLL_SECONDS = 3      # how often the stream checks for changes
    LIVE_SCORE_SSE_MAX_SECONDS = 120     # stream lifetime before the client reconnects

    # Seconds to cache the computed leaderboard so many concurrent pollers / SSE
    # connections collapse to one DB read per window (#27). Set 0 to disable caching.
    LEADERBOARD_CACHE_SECONDS = 2

    # --- Scheduled game start/stop (off by default) — #29 ---
    # When enabled, a background scheduler auto-launches data generation and/or auto-stops
    # scoring at the times an admin sets on /admin/schedule_game (for unattended events).
    # Off by default: no scheduler thread runs and behavior is unchanged. Best for a
    # single-process deployment; for multi-worker setups prefer an external cron.
    GAME_SCHEDULER_ENABLED = False
    GAME_SCHEDULER_INTERVAL_SECONDS = 30

class ActivityVolumeSettings(BaseConfig):
    ACTOR_SKIPS_DAY_RATE = 0.1
    RATE_USER_AUTHS_FROM_WORK = 0.7

    RATE_DOMAIN_RESOLVES_TO_NEW_IP = 0.2
    RATE_USER_BROWSE_TO_PARTNER_DOMAIN_RANDOM = 0.05

    FP_RATE_EMAIL_ALERTS = 0.1
    TP_RATE_EMAIL_ALERTS = 0.2

    TP_RATE_HOST_ALERTS = 0.1
    FP_RATE_HOST_ALERTS = 0.001

    RATE_ACTOR_SKIPS_HANDS_ON_KEYBOARD = 0.1