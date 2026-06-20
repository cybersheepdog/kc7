# KC7 — A Cybersecurity Game
[![Build Status](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue.svg)](https://shields.io/)
![Maintenance](https://img.shields.io/maintenance/yes/2026.svg?style=flat-square)
[![GitHub last commit](https://img.shields.io/github/last-commit/cybersheepdog/kc7.svg?style=flat-square)](https://github.com/cybersheepdog/kc7/commit/master)
![GitHub](https://img.shields.io/github/license/cybersheepdog/kc7)

Since this has not been updated in quite some time I am picking it up and adding to the great work done by all the contributors listed below.

KC7 is a cybersecurity training platform that lets players learn threat investigation and threat-intelligence skills using realistic simulated data. Players use **KQL (Kusto Query Language)** inside **Azure Data Explorer** to triage logs and uncover attacker activity across a fictitious company's environment spanning the full Cyber Kill Chain.

---
## 👨🏽‍🎓 Who is this for?

- High school and college students interested in cybersecurity
- Anyone looking to reskill or change careers into the field
- Security professionals who want to level up their pivoting and analysis skills

---

## 🚀 Getting Started

### Requirements

- Python 3.10+
- Git

### Installation

```bash
git clone https://github.com/cybersheepdog/kc7.git
cd kc7
python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Running the app

```bash
python app.py
```

Then open `http://127.0.0.1:8889/login` and log in with `admin` / `admin`.

> **Security note:** Change the default admin password before exposing the app to any network.
> Set the `KC7_ADMIN_PASSWORD` environment variable before the first run to override the default.

---

## ⚙️ Configuration

### Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `KC7_SECRET_KEY` | Flask session signing key | Random (sessions won't survive restarts) |
| `KC7_SECURITY_SALT` | flask-security-too token salt | `kc7-default-salt-change-in-prod` |
| `KC7_ADMIN_PASSWORD` | Password for the seeded admin account | `admin` |

### Azure Data Explorer (ADX)

ADX credentials can be configured two ways:

**Option 1 — Admin GUI (recommended):**
Log in as admin → Admin Central → **ADX Configuration**. Enter your cluster URI, ingest URI, database name, tenant ID, client ID, and client secret. Settings are stored in the database and take effect immediately — no restart required.

**Option 2 — `config.py`:**
Edit the `BaseConfig` class directly:

```python
AAD_TENANT_ID    = "your-tenant-id"
KUSTO_URI        = "https://yourcluster.eastus.kusto.windows.net"
KUSTO_INGEST_URI = "https://ingest-yourcluster.eastus.kusto.windows.net"
DATABASE         = "SecurityLogs"
CLIENT_ID        = "your-client-id"
CLIENT_SECRET    = "your-client-secret"
```

> GUI settings always take priority over `config.py` values.

---

## 🎮 Game Features

### For Players

#### Mitigations (Indicator Scoring)
Players submit malicious indicators — domains, IPs, email addresses, and file hashes — discovered through KQL investigation in ADX. Each correct submission earns points with **time-weighted scoring**: submitting earlier in a session earns more (up to 2× base value in the first 24 hours).

#### Challenges (Q&A)
Players answer written questions that test their analysis and knowledge. Challenges are grouped by category and show point value and description. Answers are case-insensitive and support multiple accepted values separated by semicolons.

Answers are also **normalized before comparison** 🆕, so structurally-identical indicators are accepted no matter how a player formats them: `http://bad.com`, `bad.com`, and `bad.com/` all match, and analyst-style *defanged* notation is understood (`hxxp://bad[.]com`, `1[.]2[.]3[.]4`, `user[at]evil.com`). The same normalization is applied to indicator (mitigation) submissions. It only ever *adds* matches — every answer the old exact-match logic accepted is still accepted — and Windows file paths / registry keys are left intact.

#### Rounds (Named Game Sessions)
Players join named rounds using a password code. Each round has its own scoped challenge set and separate leaderboard, making it easy to run isolated sessions for different groups or events.

#### Leaderboard
The Teams page shows a ranked leaderboard with a horizontal bar chart, split across Teams and Players tabs. Rankings are sorted by score with tie-breaking by earliest score time.

#### Expanded Threat Coverage 🆕
Scenarios now span the **full Cyber Kill Chain**, so investigations go far beyond the initial phishing email. Players hunt adversaries through:

- **Credential access** — password spray and **Kerberoasting** (RC4 service-ticket requests).
- **Discovery** — bursts of host/domain reconnaissance commands a normal user never runs.
- **Lateral movement** — **PsExec** service-binary pushes over SMB, mapping the hop-by-hop path between machines.
- **Defense evasion** — **security/system event-log clearing** that leaves a deliberate blind spot to pivot around.
- **Persistence** — **scheduled tasks** and **Run/RunOnce registry** keys that re-launch malware after a reboot.
- **Cloud attacks** — **session/token hijacking** (impossible-travel sign-ins) and **exfiltration via public storage buckets**.

This activity surfaces across new endpoint and cloud log sources (`SecurityEvents`, `CloudSignInLogs`, `CloudStorageLogs`) alongside the existing tables — see [Simulated Telemetry](#-simulated-telemetry-adx-tables).

---

### For Admins

#### Manage Game (`/admin/manage_game`)
- Start, stop, and restart the game
- Background data generation with live progress bar
- **Session Timer** — set an end date/time after which no new points can be scored from either indicators or challenges. Enabled and disabled independently of the end time.

#### Manage Users (`/admin/users`)
- View all users with their role, team, and score
- **Add users** directly — set username, email, password, role, and team in one form
- **Edit users** via modal — reset password, toggle Admin/Player role, change or remove team assignment
- Delete users

#### Manage Teams (`/admin/teams`)
- View all teams with member count, mitigations, and score
- Create and delete teams

#### Manage Challenges (`/admin/manage_challenges`)
- Create challenges with name, category, description, answer(s), point value, and optional round assignment
- Edit and delete challenges inline via modal
- Import challenges in bulk via CSV upload
- Global challenges (no round assigned) appear to all players; round-scoped challenges appear only to that round's participants

#### Manage Rounds (`/admin/rounds`)
- Create named rounds with a password join code
- Set and toggle per-round timers independently of the global session timer
- Delete rounds

#### Malicious Indicators (`/admin/manage_indicators`)
- Manually seed the indicator list used to score player mitigation submissions
- Supports domains, IPs, email addresses, and file hashes — type is auto-detected on entry
- Single add, bulk paste, or CSV import
- Summary cards show counts by indicator type
- Particularly useful when running against a pre-existing ADX dataset where the app hasn't generated the game data locally

#### ADX Configuration (`/admin/adx_config`)
- Configure Azure Data Explorer connection settings through the GUI
- **Test Connection** button validates credentials live without leaving the page
- Settings stored in the database, override `config.py` values

#### ADX Permissions (`/admin/manage_database`)
- Grant players viewer access to the ADX database so they can run KQL queries directly in the Azure Data Explorer web UI (`dataexplorer.azure.com`)

#### Live Answer Feed (`/admin/live_dashboard`)
- Real-time feed of all challenge answer submissions — both correct and incorrect
- Auto-polls every 4 seconds
- Filter by round and by correct/incorrect result
- Running stats: total attempts, correct count, success rate
- Pause/resume without losing buffered data

#### Adversary Techniques (Actor Configs) 🆕
Each malicious actor is defined by a YAML file in `app/game_configs/actors/`. The actor's `attacks:` list controls which techniques it carries out during data generation — add or remove a technique string to change what telemetry the scenario produces. No code changes are needed to re-mix techniques across actors.

```yaml
# app/game_configs/actors/BluePhoenix.yaml
attacks:
  - email:malware_delivery
  - identity:kerberoasting        # 🆕
  - execution:psexec_lateral      # 🆕
  - evasion:log_clearing          # 🆕
  - persistence:scheduled_task    # 🆕
  - persistence:registry_run      # 🆕
```

Available techniques, grouped by kill-chain phase, with their MITRE ATT&CK mapping (🆕 = newly added):

| Phase | Technique string | MITRE ATT&CK | What it generates |
|---|---|---|---|
| Delivery / Initial Access | `email:phishing` | T1566.002 | Credential-phishing emails |
| | `email:malware_delivery` | T1566.001 | Emails delivering a malicious file/link |
| | `delivery:supply_chain` | T1199 | Phishing from compromised partner/vendor addresses |
| | `watering_hole:malware_delivery` | T1189 | Malware served from a compromised website |
| | `watering_hole:phishing` | T1189 | Credential phishing via a compromised website |
| Credential Access | `identity:password_spray` | T1110.003 | Password spray against employee accounts |
| | `identity:kerberoasting` 🆕 | T1558.003 | RC4 Kerberos service-ticket requests (Event ID 4769) |
| Discovery | `recon:browsing` | T1593 | External reconnaissance browsing |
| | `discovery:automated_recon` 🆕 | T1087 | Dense burst of host/domain discovery commands |
| Lateral Movement | `execution:psexec_lateral` 🆕 | T1021.002 | PsExec service-binary push over SMB (Event ID 7045) |
| Defense Evasion | `evasion:log_clearing` 🆕 | T1070.001 | Security/System event-log clearing (Event ID 1102 / 104) |
| Persistence | `persistence:scheduled_task` 🆕 | T1053.005 | `schtasks.exe` scheduled-task persistence |
| | `persistence:registry_run` 🆕 | T1547.001 | `Run` / `RunOnce` registry persistence |
| Cloud | `cloud:session_hijacking` 🆕 | T1539 | Impossible-travel session/token replay |
| | `cloud:token_theft` 🆕 | T1528 | Alias of session hijacking (token replay) |
| | `cloud:exfiltration_via_storage` 🆕 | T1530 | Public storage bucket + mass object reads |

> These technique strings, their ATT&CK mappings, and the log tables each one writes are defined centrally in `app/server/modules/attacks/attack_registry.py` — the single source of truth used for validation and documentation.

#### Scenario Config Validation 🆕
When a game starts, every actor / company / malware YAML is validated **before any Azure connection is made**. If a config has a problem, generation stops immediately with a clear, aggregated message naming the file and field — instead of failing deep inside data generation. It catches:

- Unknown or misspelled fields, with a "did you mean?" suggestion.
- Invalid `attacks:` entries — e.g. `remote_exploit` instead of a real technique string — again with a suggestion.
- Missing required fields and wrong value types (a date that isn't `YYYY-MM-DD`, an `attacks` value that isn't a list, etc.).
- Hard cross-references — a watering-hole technique with no `watering_hole_domains`, or a `malware:` name with no matching malware config.

Validation is dependency-free and additive: valid configs behave exactly as before.

> Tip: a single actor can combine techniques across phases to tell a connected intrusion story. See [`ROADMAP.md`](ROADMAP.md) for planned work on kill-chain campaigns and auto-generated challenges/guides.

---

## 🗄️ Data Model

| Table | Purpose |
|---|---|
| `users` | Player accounts with score and role |
| `teams` | Teams with aggregate score |
| `roles` / `user_roles` | Admin / Player role assignments |
| `game_session` | Singleton tracking game state and global timer |
| `challenges` | Q&A challenges (global or round-scoped) |
| `solves` | First-solve records with points awarded |
| `answer_attempts` | Every challenge submission (correct and incorrect) |
| `game_rounds` | Named password-protected game sessions |
| `participations` | Player ↔ round membership |
| `malicious_indicators` | Admin-seeded indicators for scoring |
| `adx_config` | GUI-managed ADX connection settings |

> These are the application's own SQLite tables. The simulated security logs that **players query in KQL** are separate and live in Azure Data Explorer — see below.

---

## 🛰️ Simulated Telemetry (ADX Tables)

When the game runs, it generates realistic security logs and ingests them into Azure Data Explorer. These are the tables players investigate with KQL (🆕 = added with the expanded threat coverage):

| Table | What it captures |
|---|---|
| `Employees` | Company directory — usernames, hostnames, IPs, roles |
| `PassiveDns` | Domain → IP resolutions for actor and legitimate infrastructure |
| `OutboundBrowsing` | Employees browsing out to websites (proxy-style web logs) |
| `InboundBrowsing` | Requests hitting the company's own sites (recon, email exfil) |
| `Email` | Inbound/outbound email, including phishing and malware delivery |
| `AuthenticationEvents` | Logins to the mail server and internal servers (password spray, lateral movement) |
| `FileCreationEvents` | Files written to endpoints (downloads, dropped payloads) |
| `ProcessEvents` | Process execution — recon bursts, persistence, hands-on-keyboard activity |
| `SecurityEvents` 🆕 | Windows event log — Kerberos `4769`, service install `7045`, log clear `1102`/`104` |
| `CloudSignInLogs` 🆕 | Cloud identity sign-ins with city/country for impossible-travel detection |
| `CloudStorageLogs` 🆕 | Cloud storage ACL changes and object reads (storage exfil) |
| `SecurityAlerts` | Simulated EDR/email alerts, including realistic false positives |

New tables are created automatically on game start (registered in `LogUploader.CUSTOM_TYPES`); no manual ADX schema setup is required.

---

## 🔐 Security Notes

- Default credentials are `admin` / `admin` — **change before exposing to any network**
- Set `KC7_SECRET_KEY` to a fixed value in production so sessions survive app restarts
- Set `KC7_SECURITY_SALT` to a long random string in production
- ADX client secrets entered via the GUI are stored in the local SQLite database

---
# Deprecated

## 📖 Background

[Read the origin story](https://mem.ai/p/nlIjcw3yPTbb0DNDfPAI)

## 👯 Contributors

Simeon Kakpovi, Greg Schloemer, Alton Henley, Andre Murrell, Emily Hacker, Matthew Kennedy, Justin Carroll, Syeda Sani-e-Zehra, Stuti Kanodia, Helton Wernik. Logo by David Hardman.

## Follow us

https://twitter.com/KC7cyber

---

*Previously Cyber Data Maker — https://github.com/kkneomis/cyber_data_maker*
