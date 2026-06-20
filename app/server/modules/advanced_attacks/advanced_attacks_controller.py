"""
Generators for advanced adversary techniques.

Each function below produces a small, internally-correlated chain of telemetry for
one attack type and is dispatched from game_functions.generate_activity_new when the
matching AttackType is present on an actor. The functions follow the same conventions
as the existing controllers (password spray, watering hole, etc.):

  - pick targeted employees (optionally by the actor's watering_hole_target_roles)
  - derive timing from the actor's working hours via Clock
  - emit events through the existing upload helpers / LOG_UPLOADER queue

Telemetry produced:
  - identity:kerberoasting          -> SecurityEvents (4769) + AuthenticationEvents
  - execution:psexec_lateral        -> ProcessEvents + SecurityEvents (7045) + AuthenticationEvents
  - evasion:log_clearing            -> ProcessEvents + SecurityEvents (1102/104)
  - discovery:automated_recon       -> ProcessEvents (burst)
  - cloud:session_hijacking/token   -> CloudSignInLogs (impossible travel)
  - cloud:exfiltration_via_storage  -> CloudSignInLogs + CloudStorageLogs
  - persistence:scheduled_task/run  -> ProcessEvents
"""

import random
import uuid
from datetime import date

from faker import Faker

from app.server.modules.clock.Clock import Clock
from app.server.modules.endpoints.processes import Process
from app.server.modules.endpoints.file_creation_event import File
from app.server.modules.endpoints.endpoint_controller import create_process_on_host
from app.server.modules.endpoints.security_event import SecurityEvent
from app.server.modules.cloud.cloud_events import CloudSignInEvent, CloudStorageEvent
from app.server.modules.authentication.authenticationEvent import AuthenticationEvent
from app.server.modules.authentication.auth_controller import upload_auth_event_to_azure
from app.server.modules.organization.Company import Employee
from app.server.modules.actors.Actor import Actor
from app.server.utils import get_employees, get_company
from app.server.modules.advanced_attacks.attack_constants import *

fake = Faker()


# ---------------------------------------------------------------------------
# Campaign context (#6)
# Pins ONE compromised host (employee) and ONE C2 IP for an actor's post-compromise
# stages so kerberoasting -> lateral movement -> evasion -> persistence -> cloud all
# thread to the same host/infrastructure — a single huntable intrusion instead of
# scattered events. Inert unless a campaign is set active (campaign mode is off by
# default); when inactive, the helpers below behave exactly as before.
# ---------------------------------------------------------------------------
_ACTIVE_CAMPAIGN = None


def set_active_campaign(campaign):
    global _ACTIVE_CAMPAIGN
    _ACTIVE_CAMPAIGN = campaign


def clear_active_campaign():
    global _ACTIVE_CAMPAIGN
    _ACTIVE_CAMPAIGN = None


def build_campaign(actor):
    """
    Pin a single compromised host and C2 IP for this actor. Deterministic per actor
    (derived from the actor name) so the same host/C2 thread across every day of the
    activity window into one multi-day intrusion. Returns a dict.
    """
    import hashlib
    import uuid
    candidates = get_employees(roles_list=actor.watering_hole_target_roles_list)
    host = None
    if candidates:
        candidates = sorted(candidates, key=lambda e: getattr(e, "username", "") or "")
        idx = int(hashlib.md5(actor.name.encode("utf-8")).hexdigest(), 16) % len(candidates)
        host = candidates[idx]
    ip_list = sorted(getattr(actor, "ips_list", []) or [])
    if ip_list:
        idx2 = int(hashlib.md5((actor.name + "c2").encode("utf-8")).hexdigest(), 16) % len(ip_list)
        c2_ip = ip_list[idx2]
    else:
        c2_ip = fake.ipv4_public()
    return {"host": host, "c2_ip": c2_ip, "session_id": str(uuid.uuid4()), "clock": None}


def init_campaign_clock(actor, start_date):
    """Start the active campaign's clock at the day's base time (call once per day)."""
    camp = _ACTIVE_CAMPAIGN
    if camp is not None:
        camp["clock"] = Clock.generate_bimodal_timestamp(
            start_date=start_date,
            start_hour=actor.activity_start_hour,
            day_length=actor.workday_length_hours,
        ).timestamp()


def advance_campaign_clock(actor):
    """
    Advance the active campaign's clock by a randomized in-working-hours dwell so each
    kill-chain stage occurs *after* the previous one — event-driven timing (#8) that
    makes the intrusion unfold over time instead of all-at-once.
    """
    camp = _ACTIVE_CAMPAIGN
    if camp is not None and camp.get("clock") is not None:
        camp["clock"] = Clock.delay_time_in_working_hours(
            start_time=camp["clock"],
            factor="hours",
            workday_start_hour=actor.activity_start_hour,
            workday_length_hours=actor.workday_length_hours,
            working_days_of_week=actor.working_days_list,
        )


# ---------------------------------------------------------------------------
# Generic upload helpers
# ---------------------------------------------------------------------------
def _upload(event, table_name: str) -> None:
    """Queue a single event (object with .stringify()) for upload to ADX."""
    from app.server.game_functions import LOG_UPLOADER
    LOG_UPLOADER.send_request(data=event.stringify(), table_name=table_name)


def _targeted_employees(actor: Actor, count: int) -> "list[Employee]":
    """
    Pick employees for the actor to operate against.
    Uses the actor's watering_hole_target_roles if defined, otherwise any employee.
    When a campaign is active, the pinned compromised host is returned so every
    post-compromise stage operates against the same victim (#6).
    """
    roles = actor.watering_hole_target_roles_list
    camp = _ACTIVE_CAMPAIGN
    if camp is not None and camp.get("host") is not None:
        host = camp["host"]
        if count <= 1:
            return [host]
        return [host] + list(get_employees(roles_list=roles, count=count - 1))
    return get_employees(roles_list=roles, count=count)


def _base_time(actor: Actor, start_date: date) -> float:
    # In a campaign, stages share the campaign clock (which the dispatch advances with
    # dwell between stages), so the kill chain unfolds in order over time (#6/#8).
    camp = _ACTIVE_CAMPAIGN
    if camp is not None and camp.get("clock") is not None:
        return camp["clock"]
    return Clock.generate_bimodal_timestamp(
        start_date=start_date,
        start_hour=actor.activity_start_hour,
        day_length=actor.workday_length_hours
    ).timestamp()


def _working_hours_delay(actor: Actor, time: float, factor: str = "hours") -> float:
    return Clock.delay_time_in_working_hours(
        start_time=time,
        factor=factor,
        workday_start_hour=actor.activity_start_hour,
        workday_length_hours=actor.workday_length_hours,
        working_days_of_week=actor.working_days_list
    )


def _actor_ip(actor: Actor) -> str:
    # When a campaign is active, reuse its pinned C2 IP so all stages share infra (#6).
    camp = _ACTIVE_CAMPAIGN
    if camp is not None and camp.get("c2_ip"):
        return camp["c2_ip"]
    ips = actor.get_ips(count_of_ips=1)
    if ips:
        return ips[0]
    # Fall back to a public IP if the actor has no infrastructure yet
    return fake.ipv4_public()


# ---------------------------------------------------------------------------
# 1. Lateral movement & local privilege escalation
# ---------------------------------------------------------------------------
def actor_kerberoasting(actor: Actor, start_date: date, num_spns: int = None) -> None:
    """
    A single compromised user suddenly requests Kerberos service tickets (4769) for
    several high-value SPNs using RC4 encryption within a short window, then performs
    an administrative login onto a different server.
    """
    domain = get_company().domain
    compromised = _targeted_employees(actor, count=1)[0]
    dc = random.choice(DOMAIN_CONTROLLERS)

    if num_spns is None:
        num_spns = random.randint(4, 8)

    spns = random.sample(HIGH_VALUE_SPNS, k=min(num_spns, len(HIGH_VALUE_SPNS)))
    time = _base_time(actor, start_date)

    for spn in spns:
        service_name = spn.replace("{domain}", domain)
        _upload(
            SecurityEvent(
                timestamp=time,
                event_id="4769",
                event_type="Kerberos Service Ticket Operation",
                hostname=dc,
                username=compromised.username,
                src_ip=compromised.ip_addr,
                service_name=service_name,
                ticket_encryption_type=KERBEROAST_ENCRYPTION_TYPE,
                ticket_options=KERBEROAST_TICKET_OPTIONS,
                details=f"A Kerberos service ticket was requested for {service_name}"
            ),
            table_name="SecurityEvents"
        )
        # tickets are requested in a tight burst (a few seconds apart)
        time = Clock.increment_time(time, random.randint(1, 5))

    # Immediately followed by an administrative login onto a different server
    target_server = random.choice(INTERNAL_SERVERS)
    login_time = _working_hours_delay(actor, time, factor="minutes")
    auth_event = AuthenticationEvent(
        timestamp=login_time,
        hostname=target_server,
        src_ip=compromised.ip_addr,
        user_agent=compromised.user_agent,
        username=compromised.username,
        result="Successful Login",
        password=f"{compromised.username}2023"
    )
    upload_auth_event_to_azure(auth_event)


def actor_psexec_lateral(actor: Actor, start_date: date, num_hops: int = None) -> None:
    """
    A source workstation pushes a service binary to one or more destination servers'
    Admin$ shares over SMB (445), creating a new service (7045) on each, mapping the
    hop-by-hop lateral movement path.
    """
    source = _targeted_employees(actor, count=1)[0]
    if num_hops is None:
        num_hops = random.randint(1, 3)

    destinations = random.sample(INTERNAL_SERVERS, k=min(num_hops, len(INTERNAL_SERVERS)))
    domain = get_company().domain.split(".")[0]
    time = _base_time(actor, start_date)
    cmd_hash = File.get_random_sha256()

    for dest in destinations:
        service_binary = random.choice(PSEXEC_SERVICE_BINARIES)

        # 1) psexec.exe executes on the source workstation
        psexec_cmd = (
            f"psexec.exe \\\\{dest} -u {domain}\\administrator -p ******** "
            f"-c -f -d C:\\Windows\\{service_binary} cmd.exe"
        )
        create_process_on_host(
            hostname=source.hostname,
            timestamp=time,
            parent_process_name="cmd.exe",
            parent_process_hash=cmd_hash,
            process=Process(process_name="psexec.exe", process_commandline=psexec_cmd),
            username=source.username
        )

        # 2) service binary lands on the destination's Admin$ share -> 7045
        service_time = Clock.increment_time(time, random.randint(2, 20))
        _upload(
            SecurityEvent(
                timestamp=service_time,
                event_id="7045",
                event_type="A new service was installed in the system",
                hostname=dest,
                username=f"{domain}\\administrator",
                src_ip=source.ip_addr,
                target_server=dest,
                service_name=service_binary,
                details=(
                    f"Service binary {service_binary} written to \\\\{dest}\\Admin$ "
                    f"over SMB (445) from {source.ip_addr}; service set to start on demand"
                )
            ),
            table_name="SecurityEvents"
        )

        # 3) administrative auth onto the destination server
        auth_time = Clock.increment_time(service_time, random.randint(1, 10))
        upload_auth_event_to_azure(
            AuthenticationEvent(
                timestamp=auth_time,
                hostname=dest,
                src_ip=source.ip_addr,
                user_agent=source.user_agent,
                username=f"{domain}\\administrator",
                result="Successful Login",
                password="administrator2023"
            )
        )

        # next hop happens a little later in the workday
        time = _working_hours_delay(actor, auth_time, factor="minutes")


# ---------------------------------------------------------------------------
# 2. Defense evasion & discovery
# ---------------------------------------------------------------------------
def actor_clears_logs(actor: Actor, start_date: date) -> None:
    """
    The actor performs a few sensitive actions, then clears the security/system event
    logs (1102 / 104), creating a deliberate blind spot in the host's history.
    """
    host = _targeted_employees(actor, count=1)[0]
    time = _base_time(actor, start_date)
    cmd_hash = File.get_random_sha256()

    # The "what happened right before the lights went out" activity
    for commandline in random.sample(PRE_CLEARING_COMMANDS, k=random.randint(2, len(PRE_CLEARING_COMMANDS))):
        process_name = commandline.split(" ")[0]
        if not process_name.endswith(".exe"):
            process_name = process_name + ".exe"
        create_process_on_host(
            hostname=host.hostname,
            timestamp=time,
            parent_process_name="cmd.exe",
            parent_process_hash=cmd_hash,
            process=Process(process_name=process_name, process_commandline=commandline),
            username=host.username
        )
        time = Clock.increment_time(time, random.randint(5, 90))

    # wevtutil clears the logs
    create_process_on_host(
        hostname=host.hostname,
        timestamp=time,
        parent_process_name="cmd.exe",
        parent_process_hash=cmd_hash,
        process=Process(
            process_name="wevtutil.exe",
            process_commandline="wevtutil.exe cl Security"
        ),
        username=host.username
    )

    # Event ID 1102: the audit/security log was cleared
    _upload(
        SecurityEvent(
            timestamp=Clock.increment_time(time, 1),
            event_id="1102",
            event_type="The audit log was cleared",
            hostname=host.hostname,
            username=host.username,
            details="The audit log was cleared. This creates a gap in host visibility."
        ),
        table_name="SecurityEvents"
    )
    # Event ID 104: a System event log was cleared
    _upload(
        SecurityEvent(
            timestamp=Clock.increment_time(time, 2),
            event_id="104",
            event_type="The System log file was cleared",
            hostname=host.hostname,
            username=host.username,
            details="The System event log was cleared."
        ),
        table_name="SecurityEvents"
    )


def actor_automated_recon(actor: Actor, start_date: date) -> None:
    """
    A dense burst of host/domain discovery commands executed within a few seconds,
    spawned by cmd.exe / powershell.exe -- behavior a normal office worker never shows.
    """
    host = _targeted_employees(actor, count=1)[0]
    parent = random.choice(DISCOVERY_PARENT_PROCESSES)
    parent_hash = File.get_random_sha256()

    time = _base_time(actor, start_date)
    commands = random.sample(DISCOVERY_COMMANDS, k=random.randint(6, min(12, len(DISCOVERY_COMMANDS))))

    for commandline in commands:
        process_name = commandline.split(" ")[0]
        if not process_name.endswith(".exe"):
            process_name = process_name + ".exe"
        create_process_on_host(
            hostname=host.hostname,
            timestamp=time,
            parent_process_name=parent,
            parent_process_hash=parent_hash,
            process=Process(process_name=process_name, process_commandline=commandline),
            username=host.username
        )
        # keep the whole burst inside roughly a 5-second window
        time = Clock.increment_time(time, 1)


# ---------------------------------------------------------------------------
# 3. Modern cloud infrastructure attacks
# ---------------------------------------------------------------------------
def actor_cloud_session_hijacking(actor: Actor, start_date: date) -> None:
    """
    Session hijacking / token theft shown as "impossible travel": the same user and
    session_id signs in from the user's home location and then, minutes later, from a
    different country.
    """
    user = _targeted_employees(actor, count=1)[0]
    session_id = str(uuid.uuid4())
    home_city, home_country = random.choice(HOME_LOCATIONS)
    away_city, away_country = random.choice(IMPOSSIBLE_TRAVEL_LOCATIONS)
    actor_ip = _actor_ip(actor)

    # Legitimate-looking sign-in from the user's home location
    time = _base_time(actor, start_date)
    _upload(
        CloudSignInEvent(
            timestamp=time,
            username=user.email_addr,
            application=random.choice(CLOUD_APPLICATIONS),
            src_ip=user.home_ip_addr,
            city=home_city,
            country=home_country,
            session_id=session_id,
            result="Success",
            user_agent=user.home_ua
        ),
        table_name="CloudSignInLogs"
    )

    # ~10 minutes later the stolen session token is replayed from another country
    hijack_time = Clock.increment_time(time, random.randint(300, 900))
    for _ in range(random.randint(1, 3)):
        _upload(
            CloudSignInEvent(
                timestamp=hijack_time,
                username=user.email_addr,
                application=random.choice(["Office 365 SharePoint Online", "AWS S3 Console", "Azure Portal"]),
                src_ip=actor_ip,
                city=away_city,
                country=away_country,
                session_id=session_id,
                result="Success",
                user_agent=fake.firefox()
            ),
            table_name="CloudSignInLogs"
        )
        hijack_time = Clock.increment_time(hijack_time, random.randint(30, 300))


def actor_cloud_exfil_via_storage(actor: Actor, start_date: date) -> None:
    """
    A compromised cloud-admin account flips an internal storage bucket to be publicly
    accessible (a config change), followed by a burst of object reads served to
    external, unauthenticated IP addresses.
    """
    admin = _targeted_employees(actor, count=1)[0]
    actor_ip = _actor_ip(actor)
    bucket = random.choice(CLOUD_STORAGE_BUCKETS)

    # 1) compromised admin signs in
    time = _base_time(actor, start_date)
    away_city, away_country = random.choice(IMPOSSIBLE_TRAVEL_LOCATIONS)
    _upload(
        CloudSignInEvent(
            timestamp=time,
            username=admin.email_addr,
            application="AWS S3 Console",
            src_ip=actor_ip,
            city=away_city,
            country=away_country,
            session_id=str(uuid.uuid4()),
            result="Success",
            user_agent=fake.firefox()
        ),
        table_name="CloudSignInLogs"
    )

    # 2) configuration change: make the bucket public
    config_time = Clock.increment_time(time, random.randint(30, 300))
    _upload(
        CloudStorageEvent(
            timestamp=config_time,
            operation="PutBucketAcl",
            bucket_name=bucket,
            object_key="",
            requester_id=admin.email_addr,
            requester_ip=actor_ip,
            is_public="true",
            bytes_transferred="0",
            result="Success"
        ),
        table_name="CloudStorageLogs"
    )

    # 3) burst of mass reads to external, unauthenticated IPs
    read_time = Clock.increment_time(config_time, random.randint(30, 300))
    for _ in range(random.randint(8, 20)):
        external_ip = fake.ipv4_public()
        object_key = random.choice(CLOUD_STORAGE_OBJECT_KEYS)
        _upload(
            CloudStorageEvent(
                timestamp=read_time,
                operation="GetObject",
                bucket_name=bucket,
                object_key=object_key,
                requester_id="anonymous",
                requester_ip=external_ip,
                is_public="true",
                bytes_transferred=str(random.randint(500000, 50000000)),
                result="Success"
            ),
            table_name="CloudStorageLogs"
        )
        read_time = Clock.increment_time(read_time, random.randint(1, 30))


# ---------------------------------------------------------------------------
# 4. Advanced persistence mechanisms
# ---------------------------------------------------------------------------
def actor_establishes_persistence(actor: Actor, start_date: date, mechanism: str = "scheduled_task") -> None:
    """
    Establish persistence so that killing the running C2 process is not enough.
    mechanism:
      - "scheduled_task" -> schtasks.exe /create (re-launches the payload on a schedule)
      - "registry_run"   -> reg.exe add ...\\Run (re-launches the payload at logon)
    """
    host = _targeted_employees(actor, count=1)[0]

    malware_names = actor.get_malware_names()
    if malware_names:
        payload_name = random.choice(malware_names)
        if not payload_name.endswith(".exe"):
            payload_name = payload_name + ".exe"
    else:
        payload_name = random.choice(DEFAULT_PERSISTENCE_PAYLOAD_NAMES)

    payload_path = random.choice(PERSISTENCE_PAYLOAD_LOCATIONS).replace(
        "{username}", host.username).replace("{payload_name}", payload_name)

    if mechanism == "registry_run":
        commandline = random.choice(REGISTRY_RUN_COMMANDS)
        process_name = "reg.exe"
    else:
        commandline = random.choice(SCHEDULED_TASK_COMMANDS)
        process_name = "schtasks.exe"

    commandline = commandline.replace("{payload_path}", payload_path).replace("{payload_name}", payload_name)

    time = _working_hours_delay(actor, _base_time(actor, start_date), factor="minutes")
    create_process_on_host(
        hostname=host.hostname,
        timestamp=time,
        parent_process_name="cmd.exe",
        parent_process_hash=File.get_random_sha256(),
        process=Process(process_name=process_name, process_commandline=commandline),
        username=host.username
    )
