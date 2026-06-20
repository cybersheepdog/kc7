import glob
from flask_security import roles_required

from flask import Blueprint, request, render_template, \
                  flash, g, session, redirect, url_for, abort, current_app, jsonify
from sqlalchemy import asc
from  sqlalchemy.sql.expression import func, select
from datetime import datetime, date, time, timedelta

# Module-level progress tracker — updated by start_game() and read by /admin/game_status
GAME_PROGRESS = {
    "running": False,
    "complete": False,
    "current_date": None,   # ISO string of the day currently being processed
    "start_date": None,     # ISO string of the first game day
    "end_date": None,       # ISO string of the last game day
    "error": None,          # set if start_game() raises an exception
    "cancel_requested": False,  # set by /admin/stop_game to halt a running generation
    "cancelled": False,         # set when a run was halted before finishing
    "log": [],                  # capped list of recent progress lines (streamed to UI)
}

# Import module models (i.e. Company, Employee, Actor, DNSRecord)
from app.server.models import db, GameSession
from app.server.modules.organization.Company import Company, Employee
from app.server.modules.infrastructure.DNSRecord import DNSRecord
from app.server.modules.logging.uploadLogs import LogUploader
from app.server.modules.email.email_controller import gen_email, gen_actor_email
from app.server.modules.outbound_browsing.browsing_controller import *
from app.server.modules.infrastructure.passiveDNS_controller import *
from app.server.modules.organization.company_controller import create_company
from app.server.modules.outbound_browsing.browsing_controller import browse_random_website
from app.server.modules.inbound_browsing.inbound_browsing_controller import gen_inbound_browsing_activity
from app.server.modules.authentication.auth_controller import auth_random_user_to_mail_server, actor_password_spray
from app.server.modules.helpers.config_helper import read_config_from_yaml
from app.server.modules.endpoints.endpoint_controller import gen_system_files_on_host, gen_user_files_on_host, gen_system_processes_on_host
from app.server.modules.advanced_attacks.advanced_attacks_controller import (
    actor_kerberoasting,
    actor_psexec_lateral,
    actor_clears_logs,
    actor_automated_recon,
    actor_cloud_session_hijacking,
    actor_cloud_exfil_via_storage,
    actor_establishes_persistence,
)
from app.server.modules.file.malware import Malware
from app.server.modules.helpers.config_helper import load_malware_obj_from_yaml_by_file, read_list_from_file

from app.server.utils import *
from app.server.modules.file.vt_seed_files import FILES_MALICIOUS_VT_SEED_HASHES
from app.server.utils import AttackTypes


# ---------------------------------------------------------------------------
# Registry-driven attack dispatch (#2)
# A single declarative table replaces the old hardcoded if-chain. Each entry is
# (trigger attack-strings, handler). The handler runs once if the actor has ANY of its
# triggers — preserving the original collapse behavior where the several email attack
# types share ONE gen_actor_email call and the two cloud-session types share one call.
# Order matches the original if-chain. Adding a technique is now a one-line entry here.
# ---------------------------------------------------------------------------
ATTACK_DISPATCH = [
    ((AttackTypes.PHISHING_VIA_EMAIL.value,
      AttackTypes.MALWARE_VIA_EMAIL.value,
      AttackTypes.SUPPLY_CHAIN_VIA_EMAIL.value),
     lambda actor, cd, employees: gen_actor_email(employees, actor, start_date=cd)),

    ((AttackTypes.PASSWORD_SPRAY.value,),
     lambda actor, cd, employees: actor_password_spray(
         actor=actor, start_date=cd, num_employees=random.randint(5, 50), num_passwords=5)),

    ((AttackTypes.MALWARE_VIA_WATERING_HOLE.value,),
     lambda actor, cd, employees: actor_stages_watering_hole(
         actor=actor, start_date=cd, num_employees=random.randint(5, 10), link_type="malware_delivery")),

    ((AttackTypes.PHISHING_VIA_WATERING_HOLE.value,),
     lambda actor, cd, employees: actor_stages_watering_hole(
         actor=actor, start_date=cd, num_employees=random.randint(5, 10), link_type="phishing")),

    ((AttackTypes.RECONNAISSANCE_VIA_BROWSING.value,),
     lambda actor, cd, employees: gen_inbound_browsing_activity(
         actor=actor, start_date=cd, num_inbound_browsing_events=random.randint(0, 10))),

    ((AttackTypes.KERBEROASTING.value,),
     lambda actor, cd, employees: actor_kerberoasting(actor=actor, start_date=cd)),

    ((AttackTypes.PSEXEC_LATERAL.value,),
     lambda actor, cd, employees: actor_psexec_lateral(actor=actor, start_date=cd)),

    ((AttackTypes.AUTOMATED_RECON.value,),
     lambda actor, cd, employees: actor_automated_recon(actor=actor, start_date=cd)),

    ((AttackTypes.LOG_CLEARING.value,),
     lambda actor, cd, employees: actor_clears_logs(actor=actor, start_date=cd)),

    ((AttackTypes.CLOUD_SESSION_HIJACKING.value,
      AttackTypes.CLOUD_TOKEN_THEFT.value),
     lambda actor, cd, employees: actor_cloud_session_hijacking(actor=actor, start_date=cd)),

    ((AttackTypes.CLOUD_EXFIL_VIA_STORAGE.value,),
     lambda actor, cd, employees: actor_cloud_exfil_via_storage(actor=actor, start_date=cd)),

    ((AttackTypes.PERSISTENCE_SCHEDULED_TASK.value,),
     lambda actor, cd, employees: actor_establishes_persistence(
         actor=actor, start_date=cd, mechanism="scheduled_task")),

    ((AttackTypes.PERSISTENCE_REGISTRY_RUN.value,),
     lambda actor, cd, employees: actor_establishes_persistence(
         actor=actor, start_date=cd, mechanism="registry_run")),
]


def dispatch_actor_attacks(actor, current_date, employees):
    """
    Run the generators for the attacks this actor has, in canonical order. A handler
    fires once if the actor has ANY of its trigger attack strings — this preserves the
    original collapse behavior (multiple email types -> one email send; the two
    cloud-session types -> one call), so no technique double-fires.
    """
    attacks = set(actor.get_attacks())

    # Campaign mode (#6, off by default): pin one compromised host + C2 IP for this
    # actor so its post-compromise stages thread into a single huntable intrusion.
    campaign_on = False
    try:
        campaign_on = bool(current_app.config.get("CAMPAIGN_MODE_ENABLED"))
    except Exception:
        campaign_on = False
    if campaign_on:
        from app.server.modules.advanced_attacks.advanced_attacks_controller import (
            build_campaign, set_active_campaign, init_campaign_clock,
        )
        set_active_campaign(build_campaign(actor))
        init_campaign_clock(actor, current_date)

    try:
        for triggers, handler in ATTACK_DISPATCH:
            if attacks.intersection(triggers):
                handler(actor, current_date, employees)
                if campaign_on:
                    # dwell before the next kill-chain stage (#8)
                    from app.server.modules.advanced_attacks.advanced_attacks_controller import advance_campaign_clock
                    advance_campaign_clock(actor)
    finally:
        if campaign_on:
            from app.server.modules.advanced_attacks.advanced_attacks_controller import clear_active_campaign
            clear_active_campaign()


def assert_dispatch_covers_enum():
    """Every AttackTypes member must be wired into the dispatch table (no forgotten
    technique). Raises AssertionError listing any gaps."""
    covered = set()
    for triggers, _ in ATTACK_DISPATCH:
        covered.update(triggers)
    missing = {a.value for a in AttackTypes} - covered
    assert not missing, f"AttackTypes not wired into dispatch: {sorted(missing)}"


def _record_run_start():
    """Open a generation run-history record. Best-effort — never raises (#28)."""
    try:
        from app.server.models import GameRunLog
        run = GameRunLog(status="running")
        db.session.add(run)
        db.session.commit()
        return run.id
    except Exception as e:
        print("run-history: failed to record start: " + str(e))
        return None


def _record_run_finish(run_id, status, error=None, start_date=None, end_date=None,
                       days=None, table_counts=None):
    """Close out a run-history record. Best-effort — never raises (#28)."""
    if run_id is None:
        return
    try:
        import datetime as _dt
        import json as _json
        from app.server.models import GameRunLog
        run = db.session.get(GameRunLog, run_id)
        if run:
            run.status = status
            run.finished_at = _dt.datetime.now()
            if error is not None:
                run.error = str(error)[:500]
            if start_date is not None:
                run.game_start_date = str(start_date)
            if end_date is not None:
                run.game_end_date = str(end_date)
            if days is not None:
                run.days_generated = days
            if table_counts:
                run.table_counts = _json.dumps(table_counts)
            db.session.commit()
    except Exception as e:
        print("run-history: failed to record finish: " + str(e))


def _uploader_row_counts():
    """Return a snapshot of per-table rows sent by the active LOG_UPLOADER, or None."""
    try:
        return dict(LOG_UPLOADER.row_counts)
    except Exception:
        return None


def _progress_log(message: str, cap: int = 60):
    """Print a progress line and append it to the capped streamed-log buffer (#28)."""
    try:
        print(message)
        log = GAME_PROGRESS.setdefault("log", [])
        log.append(message)
        if len(log) > cap:
            del log[:len(log) - cap]
    except Exception:
        pass


def start_game() -> None:
    """
    This function call starts the game

    1. Get the game session
    2. Generate starter data
    3. Iterate day-by-day to generate activity
    """
    global GAME_PROGRESS
    GAME_PROGRESS["running"] = True
    GAME_PROGRESS["complete"] = False
    GAME_PROGRESS["error"] = None
    GAME_PROGRESS["current_date"] = None
    GAME_PROGRESS["start_date"] = None
    GAME_PROGRESS["end_date"] = None
    GAME_PROGRESS["cancel_requested"] = False
    GAME_PROGRESS["cancelled"] = False
    GAME_PROGRESS["log"] = []

    run_id = None  # generation run-history record id (#28)

    try:
        print("Starting the game...")

        # Validate scenario configs BEFORE touching Azure, so a typo in an actor /
        # company / malware YAML fails fast with a clear message instead of crashing
        # deep inside generation. Valid configs are unaffected.
        from app.server.modules.config_validation.config_validator import validate_or_raise
        validate_or_raise()
        print("Game configs validated OK.")

        # Open a run-history record (best-effort; never aborts generation)
        run_id = _record_run_start()

        # instantiate a logUploader. This instance is used by all other modules to send logs to azure
        # we use a singular instances in order to queue up muliple rows of logs and send them all at once
        global LOG_UPLOADER
        LOG_UPLOADER = LogUploader(queue_limit=10000)
        LOG_UPLOADER.create_tables(reset=True)

        global MALWARE_OBJECTS
        MALWARE_OBJECTS = create_malware()

        global LEGIT_DOMAINS # Legit domains from Alexa top 1M
        LEGIT_DOMAINS = read_list_from_file('app/server/modules/helpers/alexa_top100k.txt')

        # The is current game session
        # This data object tracks whether or not the game is currently running
        # It allows us to start/stop/restart the game from the views
        current_session = db.session.get(GameSession, 1)
        current_session.state = True
        db.session.commit()

        print(f"Game started at {current_session.start_time}")
        # run startup functions
        employees = Employee.query.all()
        actors = Actor.query.all()
        if not (employees or actors):
            employees, actors = init_setup()

        print("initialization complete...")

        # This is where the action happens
        # Iterate through each day in the loop
        # You can customize the length of the game in the company.yaml config file
        company = db.session.get(Company, 1)
        start_date = date.fromisoformat(company.activity_start_date)
        end_date = date.fromisoformat(company.activity_end_date)
        current_date = start_date

        GAME_PROGRESS["start_date"] = start_date.isoformat()
        GAME_PROGRESS["end_date"] = end_date.isoformat()

        days_done = 0
        while current_date <= end_date:
            # Allow an admin to halt a long run mid-generation (#28)
            if GAME_PROGRESS.get("cancel_requested"):
                GAME_PROGRESS["cancelled"] = True
                break
            GAME_PROGRESS["current_date"] = current_date.isoformat()
            _progress_log(f"Day {current_date}: generating activity for {len(actors)} actor(s)...")

            for actor in actors:
                if actor.is_default_actor:
                    # Default actor is used to create noise
                    generate_activity_new(actor, current_date, employees, num_passive_dns=200)
                else:
                    # generate activity of actors defined in actor config
                    generate_activity_new(actor,
                                      current_date,
                                      employees,
                                      num_passive_dns=random.randint(5, 10),
                                      num_email=random.randint(0, 3)
                    )

            current_date += timedelta(days=1)
            days_done += 1

        if GAME_PROGRESS.get("cancelled"):
            _progress_log(f"Generation cancelled by admin after {days_done} day(s).")
            _record_run_finish(run_id, "cancelled", start_date=start_date, end_date=end_date,
                               days=days_done, table_counts=_uploader_row_counts())
        else:
            _progress_log("Done running!")
            GAME_PROGRESS["complete"] = True
            _record_run_finish(run_id, "complete", start_date=start_date, end_date=end_date,
                               days=(end_date - start_date).days + 1,
                               table_counts=_uploader_row_counts())

    except Exception as e:
        print(f"start_game() failed: {e}")
        GAME_PROGRESS["error"] = str(e)
        _record_run_finish(run_id, "error", error=e, table_counts=_uploader_row_counts())
        raise
    finally:
        GAME_PROGRESS["running"] = False
        # Mark game session as stopped in DB
        try:
            current_session = db.session.get(GameSession, 1)
            current_session.state = False
            db.session.commit()
        except Exception:
            pass

    # count_cycles = 10
    # for i in range(count_cycles):
    #     # generate the activity
    #     print("##########################################")
    #     print(f"## Running cycle {i+1} of the game...")
    #     print("##########################################")
    #     for actor in actors: 
    #         if actor.name == "Default":
    #             # Default actor is used to create noise
    #             generate_activity(actor, employees) 
    #         else:
    #             # generate activity of actors defined in actor config
    #             # num_email is actually number of emails waves sent
    #             # waves contain multiple emails
    #             # TODO: abstract this out to the actor / make this more elegant
    #             generate_activity(actor, 
    #                               employees, 
    #                               num_passive_dns=random.randint(5, 10), 
    #                               num_email=random.randint(0, 3), 
    #                             ) 



    # ##########################################
    # # deg statements to help time tracking
    # # on average, one cycle=one day in game
    # game_start_time = get_time()
    # game_end_time =  get_time()
    # days_elapse_in_game = (game_end_time - game_start_time) /(60*60*24)
    # print(f"Game started at {Clock.from_timestamp_to_string(game_start_time)}")
    # print(f"Game ended at {Clock.from_timestamp_to_string(game_end_time)}")
    # print(f"{days_elapse_in_game} days elapsed in the game")
    # # print(f"Ran {count_cycles} cycles...")
    # ##########################################


def init_setup():
    """
    These actions are conducted at the start of a new game session

    Create company
    Create default actor
    Create Malicious Actors
    Create first batch of legit passive DNS
    Create first batch of malicious passive DNS
    """
    employees = Employee.query.all()
    actors = Actor.query.all()

    # only create employees for the company or actors 
    # if they do not already exist
    if not employees:
        create_company()
        print("making employees")
        employees = Employee.query.all()
        print(f"made {len(employees)} employees")
    if not actors:
        create_actors()
        actors = Actor.query.all()

    return employees, actors


def generate_activity_new(actor: Actor, 
                        current_date: date, 
                        employees: list, 
                        num_passive_dns:int=30, 
                        num_email:int=10, 
                        num_random_browsing_per_employee:int=20, 
                        num_auth_events_per_employee:int=10,
                        num_random_inbound_browsing:int=100,
                        count_of_user_endpoint_events=5,
                        count_of_system_endpoint_events=10) -> None:
    """
    Given an actor, generates one cycle of activity for users in the orgs 
    based on the attack types that they have defined

    The Default actor is used to represent normal company activities
    """

    # Activity will be generated for 20% of employees each day
    percent_employees_to_generate_activity_daily = 0.10 #percent

    # Generate legit activity for default actor
    if actor.is_default_actor:
            gen_passive_dns                     (actor, current_date, num_passive_dns)

            gen_email                           (employees=employees,
                                                partners=get_company().get_partners(),
                                                actor=actor,
                                                count_emails_per_user=num_email,
                                                percent_employees_to_generate=percent_employees_to_generate_activity_daily,
                                                start_date=current_date)
            
            browse_random_website               (employees=employees, 
                                                actor=actor, 
                                                count_browsing=num_random_browsing_per_employee, 
                                                percent_employees_to_generate=percent_employees_to_generate_activity_daily, 
                                                start_date=current_date)
            
            auth_random_user_to_mail_server     (employees=employees, 
                                                num_auth_events_per_user=num_auth_events_per_employee, 
                                                percent_employees_to_generate=percent_employees_to_generate_activity_daily,
                                                start_date=current_date, 
                                                start_hour=actor.activity_start_hour, 
                                                day_length_hours=actor.workday_length_hours)
            
            gen_inbound_browsing_activity       (actor=actor, 
                                                start_date=current_date, 
                                                num_inbound_browsing_events=num_random_inbound_browsing)
            
            gen_system_files_on_host            (start_date=current_date, 
                                                start_hour=actor.activity_start_hour, 
                                                workday_length_hours=actor.workday_length_hours,
                                                percent_employees_to_generate=percent_employees_to_generate_activity_daily, 
                                                count_of_events_per_user=count_of_system_endpoint_events)
            
            gen_user_files_on_host              (start_date=current_date, 
                                                start_hour=actor.activity_start_hour, 
                                                workday_length_hours=actor.workday_length_hours, 
                                                percent_employees_to_generate=percent_employees_to_generate_activity_daily,
                                                count_of_events_per_user=count_of_user_endpoint_events)
            
            gen_system_processes_on_host        (start_date=current_date, 
                                                start_hour=actor.activity_start_hour, 
                                                workday_length_hours=actor.workday_length_hours, 
                                                percent_employees_to_generate=count_of_system_endpoint_events)
            
            return
    
    # Generate activity for malicious actors

    if date.fromisoformat(actor.activity_start_date) <= current_date <= date.fromisoformat(actor.activity_end_date) and\
        Clock.weekday_to_string(current_date.weekday()) in actor.working_days_list:
        # There's a 10% chance the actor will take the day off
        if random.random() <= current_app.config['ACTOR_SKIPS_DAY_RATE']:
            print(f"Actor {actor} is randomly taking a day off today: {current_date}!")
            return
        print(f"Generating activity for actor {actor.name}")
        # Generate passive dns
        gen_passive_dns(actor, current_date, num_passive_dns)

<<<<<<< HEAD
        # Send emails (phishing, malware delivery, or supply-chain via compromised partners)
        if AttackTypes.PHISHING_VIA_EMAIL.value in actor.get_attacks()\
        or AttackTypes.MALWARE_VIA_EMAIL.value in actor.get_attacks()\
        or AttackTypes.SUPPLY_CHAIN_VIA_EMAIL.value in actor.get_attacks():
            gen_actor_email(employees,
                      actor,
                      start_date=current_date
            )

        # Malicious Activity; Conduct Password Spray Attack
        if AttackTypes.PASSWORD_SPRAY.value in actor.get_attacks():
            actor_password_spray(
                actor=actor, 
                start_date=current_date,
                num_employees=random.randint(5, 50),
                num_passwords=5
            )

        # Watering hole attack
        if AttackTypes.MALWARE_VIA_WATERING_HOLE.value in actor.get_attacks():
            actor_stages_watering_hole(
                actor=actor,
                start_date=current_date, 
                num_employees=random.randint(5, 10),
                link_type="malware_delivery"
            )

        # Watering hole attack — credential phishing variant (drive-by to a fake login)
        if AttackTypes.PHISHING_VIA_WATERING_HOLE.value in actor.get_attacks():
            actor_stages_watering_hole(
                actor=actor,
                start_date=current_date,
                num_employees=random.randint(5, 10),
                link_type="phishing"
            )
        
        # Recon activity
        if AttackTypes.RECONNAISSANCE_VIA_BROWSING.value in actor.get_attacks():
            gen_inbound_browsing_activity(actor=actor,
                                          start_date=current_date,
                                          num_inbound_browsing_events=random.randint(0,10))

        # Lateral movement & local privilege escalation
        if AttackTypes.KERBEROASTING.value in actor.get_attacks():
            actor_kerberoasting(actor=actor, start_date=current_date)

        if AttackTypes.PSEXEC_LATERAL.value in actor.get_attacks():
            actor_psexec_lateral(actor=actor, start_date=current_date)

        # Defense evasion & discovery
        if AttackTypes.AUTOMATED_RECON.value in actor.get_attacks():
            actor_automated_recon(actor=actor, start_date=current_date)

        if AttackTypes.LOG_CLEARING.value in actor.get_attacks():
            actor_clears_logs(actor=actor, start_date=current_date)

        # Modern cloud infrastructure attacks
        if AttackTypes.CLOUD_SESSION_HIJACKING.value in actor.get_attacks()\
        or AttackTypes.CLOUD_TOKEN_THEFT.value in actor.get_attacks():
            actor_cloud_session_hijacking(actor=actor, start_date=current_date)

        if AttackTypes.CLOUD_EXFIL_VIA_STORAGE.value in actor.get_attacks():
            actor_cloud_exfil_via_storage(actor=actor, start_date=current_date)

        # Advanced persistence mechanisms
        if AttackTypes.PERSISTENCE_SCHEDULED_TASK.value in actor.get_attacks():
            actor_establishes_persistence(actor=actor, start_date=current_date, mechanism="scheduled_task")

        if AttackTypes.PERSISTENCE_REGISTRY_RUN.value in actor.get_attacks():
            actor_establishes_persistence(actor=actor, start_date=current_date, mechanism="registry_run")
=======
        # Dispatch the actor's configured attacks (registry-driven; see ATTACK_DISPATCH).
        dispatch_actor_attacks(actor, current_date, employees)
>>>>>>> roadmap

def create_actors() -> None:
    """
    Create a malicious actor in the game and adds them to the database
    Actors are read in from yaml files in the actor_configs folder

    TODO: there should be some validation of actor configs prior to creation
    """
    company = db.session.get(Company, 1) # TODO: This works because we only have one company

    # Instantiate a default actor - this actor should always exist
    # the default actor is used to generate background noise in the game
    default_actor = Actor(
        name = "Default",  # Dont change the name!
        effectiveness = 99,
        count_init_passive_dns=500, 
        count_init_email= 5000, 
        count_init_browsing=5000,
        domain_themes = wordGenerator.get_words(1000),
        sender_themes = wordGenerator.get_words(1000),
        activity_start_date=company.activity_start_date,
        activity_end_date=company.activity_end_date,
        activity_start_hour=company.activity_start_hour,
        workday_length_hours=company.workday_length_hours,
        working_days=company.working_days_list
    )

    # load add default_actor
    actors = [default_actor]

    # use yaml configs to load other actors
    # read yaml file for each new actor, load json from yaml
    actor_configs = glob.glob("app/game_configs/actors/*.yaml") 
    for file in actor_configs:
        actor_config = read_config_from_yaml(file)
        # use dictionary value to instantiate actor
        if actor_config:
            # print(f"adding actor: {actor_config}")
            # use dict to instantiate the actor
            actors.append(
                Actor(**actor_config)
            )


    # add all the actors to the database
    try:
        for actor in actors:
            db.session.add(actor)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print("Failed to create actor %s" % e)
        
def create_malware() -> "list[Malware]":
    """
    Load all malware configs from YAML and configure a list of Malware objects
    """
    malware_objects = []
    malware_configs = glob.glob(f"app/game_configs/malware/*.yaml")
    for path in malware_configs:
        malware_objects.append(load_malware_obj_from_yaml_by_file(path))
    
    malware_objects = assign_hash_to_malware(malware_objects)
    return malware_objects

def assign_hash_to_malware(malware_objects: "list[Malware]") -> "list[Malware]":
    """
    Take all available VT hashes and assign them to malware families 
    there should be a 1-1 mapping of hash to malware family
    """
    # Look through available hashes and assign them to malware families via a round robin
    while FILES_MALICIOUS_VT_SEED_HASHES:
        for malware_object in malware_objects:
            if not FILES_MALICIOUS_VT_SEED_HASHES:
                break
            # take a hash and remove it from our list of hashes
            hash = FILES_MALICIOUS_VT_SEED_HASHES.pop()
            malware_object.hashes.append(hash) # TODO: This might not work!!
   
    return malware_objects

