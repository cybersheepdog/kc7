# KC7 — A Cybersecurity Game

[![Build Status](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue.svg)](https://shields.io/)
![Maintenance](https://img.shields.io/maintenance/yes/2026.svg?style=flat-square)
[![GitHub last commit](https://img.shields.io/github/last-commit/cybersheepdog/kc7.svg?style=flat-square)](https://github.com/cybersheepdog/kc7/commit/master)
![GitHub](https://img.shields.io/github/license/cybersheepdog/kc7)

KC7 is a cybersecurity training platform that lets players learn threat investigation and threat-intelligence skills using realistic simulated data. Players use **KQL (Kusto Query Language)** inside **Azure Data Explorer** to triage logs and uncover attacker activity across a fictitious company's environment spanning the full Cyber Kill Chain.

Get started at http://kc7cyber.com/modules

<img width="1378" alt="KC7 screenshot" src="https://github.com/KC7-Foundation/kc7/assets/9474932/e913abab-373f-45d0-9485-8005fde3c73e">

---

## 📖 Background

[Read the origin story](https://mem.ai/p/nlIjcw3yPTbb0DNDfPAI)

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

#### Rounds (Named Game Sessions)
Players join named rounds using a password code. Each round has its own scoped challenge set and separate leaderboard, making it easy to run isolated sessions for different groups or events.

#### Leaderboard
The Teams page shows a ranked leaderboard with a horizontal bar chart, split across Teams and Players tabs. Rankings are sorted by score with tie-breaking by earliest score time.

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

---

## 🔐 Security Notes

- Default credentials are `admin` / `admin` — **change before exposing to any network**
- Set `KC7_SECRET_KEY` to a fixed value in production so sessions survive app restarts
- Set `KC7_SECURITY_SALT` to a long random string in production
- ADX client secrets entered via the GUI are stored in the local SQLite database

---

# Deprecated

## 🤠 How to Contribute

See the [wiki](https://github.com/cybersheepdog/kc7/wiki) for codebase structure and contribution guidelines.

## 👯 Contributors

Simeon Kakpovi, Greg Schloemer, Alton Henley, Andre Murrell, Emily Hacker, Matthew Kennedy, Justin Carroll, Syeda Sani-e-Zehra, Stuti Kanodia, Helton Wernik. Logo by David Hardman.

## Follow us

https://twitter.com/KC7cyber

---

*Previously Cyber Data Maker — https://github.com/kkneomis/cyber_data_maker*
