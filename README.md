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

### Headless CLI 🆕

For reproducible runs, CI, and scripted scenarios, `kc7_cli.py` drives the same generation pipeline without the web server:

```bash
python kc7_cli.py validate     # validate every scenario config (offline; exits non-zero on errors — CI-friendly)
python kc7_cli.py preview      # dry run: what the current scenario will generate (offline)
python kc7_cli.py generate     # run a full generation headlessly
python kc7_cli.py generate --no-azure -y   # generate everything WITHOUT uploading to Azure (offline dry-run)
```

`validate` and `preview` need no Azure or network. `generate` runs the real pipeline and respects `ADX_DEBUG_MODE`; `--no-azure` forces it on (generate all telemetry, upload nothing — a complete offline dry-run), `--azure` forces a real upload, and `-y/--yes` skips the confirmation prompt. On completion it prints a per-table row-count summary.

> **Security note:** Change the default admin password before exposing the app to any network.
> Set the `KC7_ADMIN_PASSWORD` environment variable before the first run to override the default.
> If you log in with the default `admin` password, the app now **requires you to set a new one** before you can do anything else 🆕 — so a fresh install can't be left on default credentials by accident.

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

### Feature flags 🆕

Optional behaviors are **off / zero by default**, so leaving them alone preserves the original behavior. The easiest way to change them is the **Game Settings** admin page 🆕 (`/admin/settings`, Admin Central): grouped toggles and inputs that save to the database and **apply live — no restart**, overriding the `config.py` defaults. (Secrets like ADX credentials stay out of that page — they're under ADX Configuration.)

You can also set them in `config.py` directly: they're defined in the `ProductionConfig` class. Note that the app loads `DevelopmentConfig` by default, so a value set only in `ProductionConfig` won't take effect in a default run — which is exactly the trap the Game Settings page avoids, since DB overrides apply regardless of which config class is active.

| Flag | What it enables | Default |
|---|---|---|
| `ADX_DEBUG_MODE` | Print generated data instead of uploading to ADX | `True` in dev, off otherwise |
| `DYNAMIC_SCORING_ENABLED` | CTFd-style value decay as more teams solve (`DYNAMIC_SCORING_MINIMUM` / `DYNAMIC_SCORING_DECAY`) + first-blood bonus (`FIRST_BLOOD_BONUS_PCT`) | off |
| `MITIGATION_WRONG_PENALTY` | Deduct points per wrong indicator (reconcilable) | `0` |
| `MITIGATION_RATE_LIMIT_SECONDS` | Throttle rapid indicator resubmissions | `0` |
| `MITIGATION_DECOY_PENALTY` | Extra point cost for flagging a known-benign decoy indicator (decoys are recognized + explained regardless) | `0` |
| `EVENT_TICKER_REVEAL` | Live event ticker reveal level: `off` / `standings` (spoiler-safe) / `category` / `full` | `standings` |
| `EVENT_TICKER_FIRSTBLOOD_AFTER_N` | Withhold a first-blood challenge/category name until N teams have solved it | `0` |
| `EMBEDDED_KQL_ENABLED` | In-app read-only KQL query console (`/kql`); off = players use the ADX portal | `False` |
| `KQL_VIEWER_CLIENT_ID` / `KQL_VIEWER_CLIENT_SECRET` | Dedicated viewer-only AAD principal for the console (recommended) | _(falls back to `CLIENT_ID`/`SECRET`)_ |
| `EMBEDDED_KQL_MAX_ROWS` / `_TIMEOUT_SECONDS` / `_RATE_LIMIT_SECONDS` | Console row cap, per-query timeout, per-player throttle | `5000` / `45` / `2` |
| `LEADERBOARD_CACHE_SECONDS` | Cache the computed leaderboard for N seconds | `2` |
| `LIVE_SCORE_SSE_ENABLED` | Push live scoreboard updates over SSE (`LIVE_SCORE_SSE_POLL_SECONDS` / `_MAX_SECONDS`); falls back to polling | off |
| `GAME_SCHEDULER_ENABLED` | Background scheduler for auto game start/stop (`GAME_SCHEDULER_INTERVAL_SECONDS`) | off |
| `CAMPAIGN_MODE_ENABLED` | Thread post-compromise stages through one pinned host + C2 per actor | off |
| `INFRA_REUSE_ENABLED` | Draw each actor's IPs from stable "owned" ranges (`INFRA_REUSE_PREFIX_COUNT`) | off |
| `TECHNIQUE_ALERTS_ENABLED` | Per-technique EDR `SecurityAlerts` with realistic detection rates | off |
| `ALLOW_REAL_INDICATORS` / `ALLOW_REAL_C2_INFRASTRUCTURE` | Real-intel safety toggles — keep off unless IOCs are confirmed inert | off |

> The `KC7_DISABLE_CONTENT_PACK` environment variable (any value) makes the generator ignore the realism content pack and use the built-in defaults.

---

## 🎮 Game Features

### For Players

#### Mitigations (Indicator Scoring)
Players submit malicious indicators — domains, IPs, email addresses, and file hashes — discovered through KQL investigation in ADX. Each correct submission earns points with **time-weighted scoring**: submitting earlier in a session earns more (up to 2× base value in the first 24 hours). For higher-stakes events you can optionally discourage guessing 🆕: set `MITIGATION_WRONG_PENALTY` in `config.py` to deduct points for each wrong indicator (recorded as a reconcilable adjustment), and/or `MITIGATION_RATE_LIMIT_SECONDS` to throttle rapid resubmissions. Both default to 0 (off), so casual play is unaffected.

**Red-herring decoys** 🆕 — to train real triage instinct, admins can seed **decoy indicators** (Admin Central → Malicious Indicators): known-benign-but-suspicious items like a legitimate partner mail server, a sinkholed IP, or a dual-use admin tool's hash, each with a short reason. When a player flags a decoy, instead of a generic "wrong" they're told it's a **known-benign decoy and *why*** — so they learn to discriminate real IOCs from noise. Decoys count as wrong answers; `MITIGATION_DECOY_PENALTY` (default 0) adds an optional extra point cost. With no decoys seeded, behavior is unchanged.

#### Challenges (Q&A)
Players answer written questions that test their analysis and knowledge. Challenges are grouped by category and show point value and description. Answers are case-insensitive and support multiple accepted values separated by semicolons.

Answers are also **normalized before comparison** 🆕, so structurally-identical indicators are accepted no matter how a player formats them: `http://bad.com`, `bad.com`, and `bad.com/` all match, and analyst-style *defanged* notation is understood (`hxxp://bad[.]com`, `1[.]2[.]3[.]4`, `user[at]evil.com`). The same normalization is applied to indicator (mitigation) submissions. It only ever *adds* matches — every answer the old exact-match logic accepted is still accepted — and Windows file paths / registry keys are left intact.

**Scoring** is time-weighted by default (earlier solves earn more). Optionally 🆕, **dynamic / first-blood scoring** can be enabled in `config.py` (`DYNAMIC_SCORING_ENABLED`): a challenge's value then decays as more teams solve it (CTFd-style, tunable via `DYNAMIC_SCORING_MINIMUM` / `DYNAMIC_SCORING_DECAY`) and the first solver earns a `FIRST_BLOOD_BONUS_PCT` bonus. It's off by default, so existing scoring is unchanged unless you turn it on.

#### Achievement badges 🆕
Players earn collectible **badges** — each with its own unique medallion graphic — as they play, à la classic CTFs. A "Badge unlocked!" toast pops the moment one is earned, and **My badges** (in the sidebar) shows a shelf of what's been collected plus the greyed-out ones still to chase. The **scoreboard** shows a badge-count chip next to each player that links to their public showcase (`/u/<name>/badges`). Badges are derived entirely from data the game already records, so they cost nothing extra and don't touch scoring:

There are **46 badges** out of the box, across these families:

- **Milestones** — First steps, Apprentice, Analyst, Threat hunter (1 / 5 / 10 / 25 solves).
- **First blood** — First blood (be first to solve) and Quick draw (3 first-bloods).
- **Mastery** — Specialist (clear a category), Full spectrum (every category), Clean sweep (every challenge), Flawless (clean sweep with zero wrong answers).
- **Kill chain & ATT&CK** — Full kill chain (one solve in every category), MITRE maven (8 distinct ATT&CK techniques), Attribution ace (solve an attribution challenge).
- **Skill** — Speed demon (solve while the time bonus is high), Sharpshooter (5 no-wrong-guess solves), Sniper (10), Purist (10 solves with no hints), Bloodhound (10 indicators).
- **Indicators** — Four of a kind (a domain, IP, email and hash), Hash slinger (10 hashes), DNS detective (10 domains).
- **Score** — Century, High roller, Five figures (100 / 1,000 / 10,000 points).
- **Leaderboard** — Podium (top 3), Champion (#1), King of the hill (lead by 2×), Giant killer (first blood on the highest-value challenge).
- **Team** — Carry (top scorer on your team), Backbone (every teammate solves something), Dream team (your team collectively clears a category).
- **Timing** — Weekend warrior, Lightning round (5 solves in an hour), Marathoner (3 different days), Opening act (within the first hour).
- **Flavor** — Night owl, Early bird, Comeback kid, On fire (3 in 10 min), Ghost (full clear, no hints ever), Persistent (solve after 10+ wrong tries), Phoenix (5 solves you'd previously gotten wrong), Clutch (final minutes of a timed game).
- **Discretionary** (granted by a facilitator) — MVP, Good sportsmanship, Team player.

The badge **catalog lives in code** (`app/server/modules/badges/badges.py`); only awards are stored, in a `UserBadge` side-table that auto-creates with no migration. Facilitators grant/revoke the discretionary badges from **Admin Central → Badges** (`/admin/badges`), and every manual grant is written to the Audit Log. To add a new badge, drop an SVG in `static/images/badges/` and add one catalog entry with a predicate.

#### In-app KQL Query Console 🆕 (opt-in)
Instead of bouncing to the Azure Data Explorer portal, players can investigate the `SecurityLogs` data from inside the app: a **Query Console** (`/kql`, in the sidebar) with a KQL editor (Run / Ctrl+Enter), a clickable **tables &amp; columns** sidebar (built from the game's own table schemas — click to insert), schema-based **autocomplete suggestions** (Tab to accept), a **Recent** dropdown that re-runs your past queries, and a results grid where **clicking a cell copies it or saves it straight to your investigation notebook** as an IOC — so query → pivot → stash is one loop. It is **read-only and locked down**: a pure, tested validator blocks control commands (anything starting with `.`, even after a `;`), cross-database `cluster()` / `database()` queries, and `externaldata`; execution goes through the query endpoint with a per-query server timeout, a hard row cap, and a per-player rate limit.

This is **off by default** (`EMBEDDED_KQL_ENABLED`); when off, players use the ADX portal exactly as before. Turn it on only with a **least-privilege, viewer-only AAD principal** configured (`KQL_VIEWER_CLIENT_ID` / `KQL_VIEWER_CLIENT_SECRET`) — that least-privilege identity is the primary safeguard, with the in-app validator and caps as defense in depth.

When the console is enabled, facilitators get a **Query Feed** 🆕 (`/admin/query_feed`, in Admin Central and the Facilitator menu; read-only, so Observers see it too): a live view of who ran what, with per-player volume and error rate, and integrity flags — **stuck** players (high error rate, may need help) and **shared** queries (the same query run by multiple players, a soft answer-sharing signal). It auto-refreshes during an event, and a **round picker** scopes the feed to a single round's participants (`?round=<id>`).

#### Investigation Notebook 🆕
Every player gets a private **investigation notebook** (`/notebook`, in the sidebar) — the analyst workspace the game was missing. It's a three-pane scratchpad: **Notes** for findings, **Indicators** for stashing IOCs as you pivot (the type — domain / IP / email / hash — is auto-detected and each has a one-click copy button), and a **Timeline** for reconstructing the intrusion (events sort by the time you enter). Add/remove entries inline without leaving the page. It's completely private to each player and has **no effect on scoring** — purely a place to think. Stored in a `notebook_entries` side-table scoped to the user.

#### Rounds (Named Game Sessions)
Players join named rounds using a password code. Each round has its own scoped challenge set and separate leaderboard, making it easy to run isolated sessions for different groups or events.

#### Leaderboard
The Teams page shows a ranked leaderboard with a horizontal bar chart, split across Teams, Players, and **Progress** tabs. Rankings are sorted by score with tie-breaking by earliest score time, and the live Teams/Players views now show **rank-movement deltas** (▲/▼ since the last update, "NEW" on first appearance). The board refreshes itself automatically: by default it polls every 10 seconds, and a pulsing **LIVE** badge shows it's updating. For near-real-time **push** updates (so a whole room sees movement the instant a score lands), enable `LIVE_SCORE_SSE_ENABLED` 🆕 in `config.py` — the page then streams updates over Server-Sent Events (`/score_stream`) and automatically falls back to polling if the stream is unavailable. (SSE needs a threaded/multi-worker server such as gunicorn or `flask run` with threading.) Each player row also shows a 🆕 **badge-count chip** that links to that player's badge showcase (`/u/<name>/badges`), and an 🆕 **analyst rank title** beneath the name (see below).

**Analyst ranks** 🆕 — players climb a flavorful career ladder as their score grows (Recruit → Analyst I/II → SOC Analyst → Incident Responder → Threat Hunter → … → Cyber Sentinel). The current title shows on the scoreboard and on each player's **profile**, where a progress bar counts down the points to the next rank. It's purely cosmetic — it never affects scoring or standings.

**Big-screen / spectator mode** 🆕 — the **Big screen** button on the leaderboard opens a standalone, full-screen board (`/scoreboard/big`) designed for projecting at live events: Teams and Players top-10 side by side with medals, rank titles, a pulsing LIVE indicator and clock, auto-refreshing every few seconds. It has no sidebar or navigation and reads the same public leaderboard data, so it can run on a kiosk/projection machine without logging in.

**Live event ticker** 🆕 — a feed of notable moments (first blood, badge unlocks, rank-ups) shows on the scoreboard and along the bottom of the big-screen view. Because naming a challenge or category would spoil which TTPs are in play, a facilitator **reveal level** (`EVENT_TICKER_REVEAL` in `config.py`) controls what's shown: the default `standings` is spoiler-safe (badges, rank-ups, and a generic "drew first blood!" with no names), while `category` and `full` progressively reveal more, and `off` disables it. `EVENT_TICKER_FIRSTBLOOD_AFTER_N` can withhold a challenge/category name until that many teams have solved it. Events are recorded best-effort and never affect scoring.

The **Progress** tab 🆕 adds richer analytics drawn from the solve log (`/score_breakdown`): a **score-over-time** line chart per team (cumulative score by minutes since the first solve), a **progress-by-category** table showing how many challenges each team has cracked in each category (Attribution, Command & Control, Malware, MITRE ATT&CK, …), and a **first-blood** banner calling out who drew first blood and on which challenge.

#### Appearance / Theme 🆕
The app ships with a refreshed light theme by default. From their **profile page**, each user can toggle between the **Default (Light)** look and a **Cyber (Dark)** SOC-style theme (dark surfaces, cyan accent, monospace touches). The choice is remembered via a cookie and applied across every page — server-side, so there's no flash on load. It's a presentation-only override (a `theme-cyber` body class enabling `kc7-dark.css`); no game logic or data is affected.

#### Expanded Threat Coverage 🆕
Scenarios now span the **full Cyber Kill Chain**, so investigations go far beyond the initial phishing email. Players hunt adversaries through:

- **Credential access** — password spray and **Kerberoasting** (RC4 service-ticket requests).
- **Discovery** — bursts of host/domain reconnaissance commands a normal user never runs.
- **Lateral movement** — **PsExec** service-binary pushes over SMB, mapping the hop-by-hop path between machines.
- **Defense evasion** — **security/system event-log clearing** that leaves a deliberate blind spot to pivot around.
- **Persistence** — **scheduled tasks** and **Run/RunOnce registry** keys that re-launch malware after a reboot.
- **Hands-on-keyboard** — an operator's **interactive post-exploitation commands** (collection, archive/staging, beaconing) run on a compromised host through C2.
- **Data exfiltration** — **stolen-credential mailbox access** followed by bulk mail download over the web.
- **Cloud attacks** — **session/token hijacking** (impossible-travel sign-ins) and **exfiltration via public storage buckets**.

**Campaign mode** 🆕 (optional, `CAMPAIGN_MODE_ENABLED` in `config.py`, off by default): when enabled, an actor's post-compromise stages (Kerberoasting → lateral movement → log clearing → persistence → cloud) all thread through **one pinned compromised host and one C2 IP** per actor, stable across the whole activity window — and they **unfold in order over time**, each stage dwelling a randomized number of working hours after the previous one rather than all happening at once. Together that turns scattered events into a single intrusion players can pivot through and attribute. With it off, each technique picks its own victim/IP and timing as before.

**Infrastructure reuse** 🆕 (optional, `INFRA_REUSE_ENABLED` in `config.py`, off by default): the attribution enabler. When enabled, each actor's IPs are drawn from a small, **stable set of "owned" network ranges** (ASN-like /16 prefixes) seeded deterministically from the actor's name, instead of being scattered randomly across the whole IPv4 space. So the actor's infrastructure clusters in the same recognizable ranges across campaigns and re-runs — a pivotable fingerprint that lets players link two separate intrusions to one actor. (Domains already share stable per-actor TLDs/themes and malware families already reuse their hashes, so IP ranges were the missing piece.) With it off, IPs are random as before.

**Per-technique detection fidelity** 🆕 (optional, `TECHNIQUE_ALERTS_ENABLED` in `config.py`, off by default): when enabled, each advanced technique can trip a `SecurityAlert` with a probability and severity set by its **detection profile**. Loud techniques light up the SOC (PsExec service install, impossible-travel sign-in, public-bucket exfil — high severity, frequent); deliberately quiet ones rarely do (Kerberoasting, event-log clearing — low, rare). The effect is authentic **visibility gaps**: players catch some intrusion steps on an alert and must reconstruct the quiet ones from raw telemetry. With it off, no technique-detection alerts are emitted.

**Behavioral realism** 🆕 — beyond the techniques themselves, the generated data is shaped to read like a real environment: in campaign mode the same compromised host, C2 IP, and a **deterministic stolen session ID** thread across `ProcessEvents` / `SecurityEvents` / `AuthenticationEvents` / cloud logs, so an intrusion is one pivotable story rather than scattered events; C2 and operator activity carry **timing jitter** (and cloud exfil runs **low-and-slow**) instead of firing on a predictable clock; and normal hosts emit **coherent parent→child process trees** (e.g. `explorer.exe → chrome.exe`, `services.exe → svchost.exe → …`) so malicious process chains have believable background to be hunted out of.

This activity surfaces across new endpoint and cloud log sources (`SecurityEvents`, `CloudSignInLogs`, `CloudStorageLogs`) alongside the existing tables — see [Simulated Telemetry](#-simulated-telemetry-adx-tables).

---

### For Admins

#### Manage Game (`/admin/manage_game`)
- Start, stop, and restart the game — **Stop** cancels a run mid-generation 🆕
- Background data generation with a live progress bar and a **streamed progress log** 🆕
- **Session Timer** — set an end date/time after which no new points can be scored from either indicators or challenges. Enabled and disabled independently of the end time.
- **Scenario & Scoring Tools** panel 🆕 — one-click links to the Scenario Preview (dry run), the Scenario PDF exports (player packet / instructor answer key), the Score Audit, and the **Run History**.
- **Export Game** 🆕 (`/admin/export_game`) — download a snapshot of the full game state for your records or to archive a finished event: final team and player standings, per-challenge solve stats (how many solved each and when it was first solved), and the complete solve log, as **JSON** (or `?format=csv` for spreadsheet-friendly standings). It's read-only, so exporting never affects a running game.
- **Schedule Game** 🆕 (`/admin/schedule_game`) — for unattended events, set a time to auto-start data generation and/or auto-stop the game (closing scoring). Opt-in: enable `GAME_SCHEDULER_ENABLED` in `config.py` to run the background scheduler (off by default, so no extra thread runs otherwise); each leg arms independently and fires once. The page warns if the scheduler isn't enabled. Best for a single-process deployment — for multi-worker setups, use an external cron instead.
- **Run History** (`/admin/run_history`) 🆕 — a log of each data-generation run: when it started/finished, how long it took, success / error / **cancelled**, the scenario window, and **per-table ingested-row counts**. Plain text, or `?format=json`.

#### Scenario Story Wizard (`/admin/scenario_wizard`) 🆕
- The fastest way to stand up a new scenario: pick an **archetype** (espionage, ransomware, insider, or supply-chain), give the actor a name, timeline, and a few optional attribution details, and the wizard scaffolds a **consistent, validated** actor config — with a coherent technique chain and all the fields those techniques require — plus an optional linked malware config.
- It saves everything through the same config validator as hand-authored configs (so a scaffold can never be invalid), then points you to one-click **auto-generate challenges** and **game guide** to finish the scenario. Linked from the Manage Game tools panel.

#### Scenario Templates (`/admin/scenario_templates`) 🆕
- Save a whole scenario — the company profile, every actor and malware config, the realism content pack, and the challenge set — as a single named **template** bundle, then load it back later to spin the same scenario up again. Keep a library to clone from.
- **Load** writes the configs (each through the validator) and adds the challenges; it doesn't start a game or touch live scores, so you review and then start when ready. **Download/upload** bundles as JSON to share scenarios between instances. Every save/load/delete is audited.
- (This is the "save/clone a whole scenario" half of multi-scenario support. For running parallel cohorts in one dataset, use **Rounds**, which already scope challenges and leaderboards.)

#### Manage Scenario (`/admin/manage_scenario`) 🆕
- Author the **scenario content** — actor and malware configs — from the browser instead of hand-editing YAML files on disk.
- Lists every config with a quick summary, and lets you **edit, clone, or delete** them in an in-browser YAML editor. Clone is the fastest way to spin up a new actor from an existing one.
- **Every save is validated first** (unknown fields with "did you mean?", invalid attack strings, missing/typed fields, attribution/ATT&CK checks) — invalid configs are rejected with inline errors and never written. Filenames are sanitized and writes are confined to the config directories.
- **Import intel pack** 🆕 — upload a YAML *intel pack* describing a real threat group (name, aliases, MITRE ATT&CK group id `G####`, and the group's technique ids) and the importer maps it onto a validated actor config: it carries the attribution metadata and keeps the subset of techniques the game can actually generate (the rest are noted). **Preview** shows the resulting config; **Import & save** writes it through the validator. Built safely — a pack must declare **provenance**, real indicators are shown **defanged** unless `ALLOW_REAL_INDICATORS` is on, and malware hashes are carried as strings only. Sample pack: `app/game_configs/intel_packs/apt29_emulation.yaml`.

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
- **Answer Tester** 🆕 — an inline form to preview how an answer grades (with normalization / defang) before publishing a challenge
- **Auto-generate** 🆕 (`/admin/generate_challenges`) — build a challenge set straight from the scenario's ground truth (malicious IPs, domains, phishing senders, malware families/hashes, attribution + aliases, and MITRE ATT&CK technique IDs). "Preview auto-gen" shows the proposed Q&A; "Auto-generate" creates the non-duplicate ones. Run it after generating a game, since most facts only exist once the data has been produced.
- **Attribution challenges** 🆕 — the capstone of the set. For each attributed actor it asks players to name the threat actor and accepts the emulated name, the real group name, any alias, **or** the MITRE ATT&CK group ID (`G####`). The prompt is evidence-grounded — it names the actual techniques observed in the intrusion, so players attribute from TTP and infrastructure overlap rather than guessing — and, when the actor config carries a `report_url` (intel packs supply this from their provenance link automatically), it cites the referenced report for corroboration.
- **Re-grade** 🆕 (`/admin/regrade_challenge`) — after fixing a challenge's accepted answers (too strict, a typo), retroactively credit players who submitted a now-correct answer earlier but were marked wrong. A "Re-grade" button per challenge previews exactly who would be credited and how many points, then applies it — each is scored at their original attempt time (so an early submission keeps its speed bonus), the change is audited, and it's fully reconcilable by the Score Audit.
- **Answer tester** 🆕 (`/admin/answer_tester`) — before publishing a challenge, confirm it grades the way you expect. Pick a challenge (or paste accepted answers), enter a trial submission, and see whether it would be marked **correct or wrong**, with a per-alternate breakdown showing each accepted answer's normalized form and which one matched. It uses the exact same defang/normalization the live scoreboard uses, so `hxxp://1[.]2[.]3[.]4/` correctly matches `1.2.3.4`.
- **Hints & gating** 🆕 (`/admin/challenge_gating`) — optionally give a challenge a **hint** (revealing it costs the player and their team a configurable number of points, charged once), a **timed unlock** (it can't be answered until a set time), and/or a **prerequisite** (it stays locked until another challenge is solved). Players see a lock badge with the reason and a "Reveal hint" button. It's all stored in side-tables, so any challenge you don't configure behaves exactly as before.

#### Scenario PDF Export (`/admin/export/scenario_pdf`) 🆕
- One-click export of the scenario as a polished PDF, generated from the live game data (company profile, the actors in play with their ATT&CK techniques, and the challenge set) — so it never drifts out of sync.
- Two variants: a **player challenge packet** (questions only) and an **instructor answer key** (`?answers=1`, which adds the accepted answers and a threat-landscape/attribution reference). Answers and the attribution section appear **only** in the instructor key.
- Scope to a single round with `?round_id=N`.
- Requires the optional `reportlab` package; if it isn't installed the export shows a friendly "install reportlab" message instead of failing.

#### Game Guide & Instructor Key (`/admin/game_guide`) 🆕
- A **Markdown** guide generated from the scenario config every time, so — like the PDF — it can't drift out of sync, with no extra dependencies (no `reportlab` needed).
- **Player intel brief** (default): sets the scene from the company profile, lists the kill-chain stages in play, and spells out per-technique **learning objectives** — with no attribution, indicators, or answers given away.
- **Instructor key** (`?variant=instructor`): adds attribution (aliases + ATT&CK group ID), a per-actor **campaign timeline** with the ordered kill-chain path and ATT&CK technique table, the indicators of compromise, and the full challenge **answer key**.
- Add `?download=1` to save it as a `.md` file. Both variants are linked from the Manage Game tools panel.

#### Scenario Dry-Run Preview (`/admin/preview_scenario`) 🆕
- A pre-flight that reports what the current scenario will generate **without running the pipeline** — for each actor: the ATT&CK techniques that will fire, the ADX tables they populate, the number of active days, and an approximate event volume; plus the scenario-wide table union.
- Lets an author sanity-check a scenario (and pair it with config validation) before committing to a full, slow generation run.
- Plain-text report by default; add `?format=json` for the structured data. Also runnable headlessly: `python -m app.server.modules.preview.scenario_preview`.

#### Score Audit (`/admin/score_audit`) 🆕
- A non-destructive reconciliation that recomputes each player's and team's totals from the source-of-truth records — **challenge** points from `Solve` plus **indicator** points from `MitigationAward` — and compares them to the stored running totals, to surface any desync (a deleted solve, a changed challenge value, a corrected answer).
- Plain-text table by default; `?format=json` for structured data. A **negative delta** always flags a real desync. Indicator awards are now recorded per submission, so for games run since that change the recompute is **exact** (any non-zero delta is a desync); for older games a positive delta just reflects unrecorded historical indicator points.
- Read-only by default. Add `?apply=1` to perform a **destructive rebuild**: overwrite every player's and team's stored score and last-score time with the values recomputed from the `Solve` + `MitigationAward` records (use after editing/deleting challenges or answers to resync standings). It returns the list of changes applied.

#### Manual Score Adjustments (`/admin/score_adjust`) 🆕
- Add or subtract points from a team or player (negative to subtract), with a reason — for awarding a bonus, applying a penalty, or correcting a mistake. Each adjustment is written to the Audit Log.
- Adjustments are recorded in their own ledger and **folded into the Score Audit's rebuild**, so a `?apply=1` recompute preserves them instead of wiping them. (A player's adjustment also credits their team, mirroring how a solve does.) **Hint-cost deductions** (from challenge gating) are folded into the rebuild the same way, so a recompute no longer erases them either.

#### Answer Tester (`/admin/test_answer`) 🆕
- Preview how a submitted answer would grade **before** publishing a challenge, including normalization/defang. Returns a JSON explanation: the normalized submitted value, and for each accepted answer its normalized form and whether it matches.
- Params: `answer=<value>` plus either `challenge_id=<id>` or `accepted=<;-separated answers>`. Example: `?answer=hxxp://bad[.]com/&accepted=bad.com` reports a match against `bad.com`.

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
- **Decoy (red-herring) indicators** 🆕 — seed known-benign-but-suspicious indicators with a reason; flagging one teaches the player it's benign (see *Mitigations* under For Players)

#### Game Settings (`/admin/settings`) 🆕
- Toggle the optional feature flags from the GUI instead of editing `config.py` — grouped switches and inputs for scoring (dynamic/first-blood, indicator penalties), realism (campaign mode, infra reuse, technique alerts), live UX (SSE scoreboard, event-ticker reveal level), tools (the in-app KQL console + caps, ADX debug mode), and safety toggles.
- Saves to the `app_settings` table and **applies immediately — no restart** (overrides are loaded onto the running config and re-applied at boot). Admin-only and audited.
- Secrets (ADX credentials, the KQL viewer principal) are intentionally **not** exposed here; they stay under ADX Configuration / `config.py`.

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
- **Integrity flags** 🆕 — an advisory panel that surfaces suspicious patterns from the submission log: the **same answer from multiple teams** in a tight window (defang-aware, so `1.2.3.4` and `1[.]2[.]3[.]4` count as the same), a **suspiciously fast solve** landing seconds after another team's correct answer, and **burst solving** (one player getting many correct answers faster than the questions can be read). These are leads worth a look, not proof — the system never auto-penalizes.

#### Facilitator Analytics (`/admin/analytics`) 🆕
- A facilitator's-eye view built from the solve/attempt logs, beyond the live feed and team standings.
- **Solve rates** per challenge (sorted hardest-first) and per category, with an attempts-per-solver "friction" figure.
- **Difficulty calibration** — challenges nobody has solved, plus too-hard (<15% solved) and too-easy (>85%) bands, so you can spot a broken or trivial challenge at a glance.
- **Engagement** — how many players are active vs. idle, and how many have solved at least one challenge.
- **ADX ingestion health** — rows ingested per table, queue depth, and the last error from the generation run.

#### Audit Log (`/admin/audit_log`) 🆕
- An append-only record of privileged admin actions, for accountability when multiple staff run an event.
- Captures **who** did **what**, to which **target**, with detail, IP, and timestamp — across game start/stop/restart, user create/edit (including role and team changes), scenario config save/delete, intel-pack import, challenge generate/delete/regrade, score adjustments, badge grant/revoke, and backup download/restore.
- Read-only view, newest-first, with a category filter (game / user / config / challenge). Logging is best-effort and never blocks the action it records.

#### Badges (`/admin/badges`) 🆕
- See every player's badge count, and grant or revoke the **discretionary** badges (MVP, Good sportsmanship, Team player) by hand — the rest are earned automatically as players solve challenges and find indicators.
- Each grant/revoke is written to the Audit Log. Player names link to their public badge showcase. See **Achievement badges** under *For Players* for the full catalog.

#### Facilitator roles: Observer & Grader (`/admin/users`) 🆕
Besides **Admin** and **Player**, you can grant two narrower roles from Manage Users, so you can give event staff exactly the access they need and nothing more:

- **Observer** — read-only access to the monitoring views (Analytics, Live Answer Feed, Run History, Audit Log). Cannot start/stop the game, change the scenario or config, manage users, grade, or take backups.
- **Grader** — everything an Observer can see, plus the grading actions: regrade a challenge, adjust a score, and the answer tester. Still cannot touch game/scenario/config control or backups.

Admin keeps full access exactly as before, and Players remain locked out of all admin routes — the new roles only *add* a middle tier (implemented by widening just those specific routes to `roles_accepted`). Roles are never assigned automatically; an Admin grants them. Observer/Grader users get a dedicated **Facilitator** sidebar menu showing only their permitted pages.

**In-app role guides** 🆕 — each non-player role has a built-in guide that covers only what's specific to that role, linked from the top of its sidebar menu: Admin (`/guide/admin`), Observer (`/guide/observer`), and Grader (`/guide/grader`).

#### Backup & Restore (`/admin/backup`) 🆕
- **Download** a single `.zip` snapshot of the whole instance — every scenario config (actors, malware, company profile, content/intel packs, gameplay) plus a copy of the database (users, teams, challenges, scores, solves). Use it for disaster recovery or to migrate the game to another host.
- **Restore** from an uploaded snapshot: config files are re-applied immediately (each path strictly confined to the config directory — traversal attempts are refused), and you can optionally restore the **database** too. The DB is never overwritten under live connections — it's *staged* and swapped in atomically on the next restart, and your current database is automatically copied aside first, so a restore is reversible. Admin-only; every download and restore is written to the Audit Log.

#### Adversary Techniques (Actor Configs) 🆕
Each malicious actor is defined by a YAML file in `app/game_configs/actors/`. The actor's `attacks:` list controls which techniques it carries out during data generation — add or remove a technique string to change what telemetry the scenario produces. No code changes are needed to re-mix techniques across actors.

**Realism content pack** 🆕 — the building blocks the techniques draw from (discovery commands, Kerberos SPNs, internal server names, persistence/log-clearing commands, cloud apps, storage buckets, impossible-travel locations, …) live in an editable YAML pack at `app/game_configs/content_packs/realism.yaml`, so you can extend or localize the realism without touching code. The in-code lists remain the fallback: anything you omit (or a malformed entry) safely keeps the default, and a broken pack can never break startup. Set `KC7_DISABLE_CONTENT_PACK` to ignore the pack entirely. You can edit the pack **in the browser** from **Manage Scenario** (choose the `content_pack` type) — saves are validated first (it flags typo'd keys and wrong value shapes). Changes take effect the next time the game is generated.

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

**Using real adversary data (TTPs & hashes)** 🆕 — the configs ship with fictitious tradecraft, but you can swap in real, historical, open-intel values. A malware config may declare a `hashes:` list (each a bare sha256 or a `{sha256, source, reference, first_seen}` mapping with provenance) that becomes that family's file indicators (correct answers); families that declare none keep using the random pool, so existing scenarios are unchanged. Command-line entries (`recon_processes`, `c2_processes`, `post_exploit_commands`) accept optional `technique`/`source` annotations for provenance. Fully-commented starter templates live alongside the configs — `malware/TEMPLATE_real_family.yaml.example`, `actors/TEMPLATE_real_actor.yaml.example`, and `intel_packs/TEMPLATE_real_intel.yaml.example` (these `.example` files are ignored by the loader). See **`app/game_configs/REAL_INTEL_SOURCING.md`** for where to source the data (MITRE ATT&CK, Atomic Red Team, abuse.ch) and the safety rules (inert strings only, defang). The fastest path is **Import Intel Pack** on Manage Scenario, which maps an ATT&CK group + techniques + hashes onto a validated actor with provenance enforced.

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
| Collection | `hands_on_keyboard:operator` 🆕 | T1059 | Interactive operator post-exploitation commands run via C2 |
| Exfiltration | `exfiltration:email_collection` 🆕 | T1114.002 | Stolen-credential mailbox access + bulk mail download |
| Cloud | `cloud:session_hijacking` 🆕 | T1539 | Impossible-travel session/token replay |
| | `cloud:token_theft` 🆕 | T1528 | Alias of session hijacking (token replay) |
| | `cloud:exfiltration_via_storage` 🆕 | T1530 | Public storage bucket + mass object reads |

> These technique strings, their ATT&CK mappings, and the log tables each one writes are defined centrally in `app/server/modules/attacks/attack_registry.py` — the single source of truth used for validation and documentation.

Actors can also carry **attribution metadata** 🆕 for attribution exercises: `attribution` (group name), `aliases`, `attack_group_id` (MITRE `G####`, format-validated), `origin`, and `motivation`. These are validated at startup and surfaced in the scenario preview and the **instructor-key** PDF (never the player packet), so analysts can be asked to identify the actor from its TTPs. They're config/display metadata — no database schema change.

#### Scenario Config Validation 🆕
When a game starts, every actor / company / malware YAML is validated **before any Azure connection is made**. If a config has a problem, generation stops immediately with a clear, aggregated message naming the file and field — instead of failing deep inside data generation. It catches:

- Unknown or misspelled fields, with a "did you mean?" suggestion.
- Invalid `attacks:` entries — e.g. `remote_exploit` instead of a real technique string — again with a suggestion.
- Missing required fields and wrong value types (a date that isn't `YYYY-MM-DD`, an `attacks` value that isn't a list, etc.).
- Hard cross-references — a watering-hole technique with no `watering_hole_domains`, or a `malware:` name with no matching malware config.
- Registry integrity — the attack registry self-checks that it stays in sync with the `AttackTypes` enum and that every technique carries a well-formed MITRE ATT&CK id (so a typo'd id fails fast).

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
| `mitigation_awards` | Per-indicator award records (source of truth for indicator points) |
| `score_adjustments` 🆕 | Manual +/- score changes and penalties (reconcilable by the Score Audit) |
| `challenge_gating` 🆕 | Optional per-challenge hint, timed unlock, and prerequisite rules |
| `hint_reveals` 🆕 | Records that a player revealed a hint (so the cost is charged once) |
| `user_badges` 🆕 | Achievement badges a player has earned (catalog lives in code) |
| `notebook_entries` 🆕 | Each player's private investigation notes, IOCs, and timeline events |
| `decoy_indicators` 🆕 | Admin-seeded benign red-herring indicators (with a reason) for discrimination training |
| `game_events` 🆕 | Notable moments (first blood / badge / rank-up) for the live event ticker |
| `query_logs` 🆕 | Player KQL console queries (text, rows, timing, status) for the facilitator query feed |
| `app_settings` 🆕 | GUI-managed feature-flag overrides (applied live + at startup) |
| `scheduled_game` 🆕 | Auto start/stop times for unattended events |
| `game_run_logs` 🆕 | History of each data-generation run (timing, status, per-table row counts) |
| `admin_audit` 🆕 | Append-only log of privileged admin actions |
| `game_rounds` | Named password-protected game sessions |
| `participations` | Player ↔ round membership |
| `malicious_indicators` | Admin-seeded indicators for scoring |
| `adx_config` | GUI-managed ADX connection settings |

> These are the application's own SQLite tables. The simulated security logs that **players query in KQL** are separate and live in Azure Data Explorer — see below.
> New side-tables auto-create on startup via `db.create_all` (no migration), and new columns on existing tables are added by an idempotent `_run_db_migrations()` — so upgrading an existing database is seamless.

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
| `SecurityAlerts` | Simulated EDR/email alerts, including realistic false positives. Carries structured `hostname`, `username`, and `technique_id` (MITRE ATT&CK) columns alongside the description, so alerts join cleanly to host/identity telemetry and to techniques |

New tables are created automatically on game start (registered in `LogUploader.CUSTOM_TYPES`); no manual ADX schema setup is required.

The uploader batches rows in a shared queue and flushes when it fills. The queue is **thread-safe** 🆕: a flush atomically swaps the queue out under a lock and ingests the snapshot outside it, so generation never blocks on Azure HTTP and no rows are dropped while a flush is in flight. Independent tables in a flush are ingested **concurrently** (each its own ingestion call), so initialization isn't gated by sequential per-table latency — the biggest win at high employee/wave counts. No configuration needed; behavior is automatic.

---

## 🔐 Security Notes

- Default credentials are `admin` / `admin` — **change before exposing to any network**
- Set `KC7_SECRET_KEY` to a fixed value in production so sessions survive app restarts
- Set `KC7_SECURITY_SALT` to a long random string in production
- ADX client secrets entered via the GUI are stored in the local SQLite database
- **Real-world intel safety** 🆕 — `ALLOW_REAL_INDICATORS` and `ALLOW_REAL_C2_INFRASTRUCTURE` (in `config.py`) are **off by default**. Keep them off unless your indicators are inert (synthetic, sinkholed, or defanged) — never live C2 a player could reach or blocklist. Seed "malware" files only ever contain the harmless EICAR test string (enforced via `app/server/modules/safety/safety.py`); real malware hashes are used as indicator strings only, never as payloads. A `defang()` helper renders real IOCs inertly for display.

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
