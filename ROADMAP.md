# KC7 Content & Realism Roadmap

A plan for making it easier to author new game content and for making the
generated game data more realistic — including auto-populating challenge
questions/answers, auto-generating the game guide, and helping admins spin up a
believable scenario story quickly.

> **Guiding principle:** every item below is designed to be *additive*. New
> capabilities should sit alongside the current engine without changing the
> behavior of existing actors, attacks, tables, or configs. (Same discipline used
> when the advanced attack types were added — new enum entries, new tables, new
> generators, new dispatch branches, nothing existing modified.)

---

## Where we are today (grounded observations)

**Two-tier content system.** Gameplay/scoring content — challenges, teams, users,
rounds, indicators — has full admin-GUI CRUD plus CSV import (`/admin/...` routes
in `views.py`, backed by the `Challenge`, `GameRound`, etc. models). But the
*scenario* content that actually drives realism — actors, malware, the company —
is hand-edited YAML under `app/game_configs/` with **no GUI and no validation**
(see the `# TODO: there should be some validation of actor configs prior to
creation` in `game_functions.create_actors`).

**Authoring is full of silent footguns.** `Actor(**actor_config)` throws a cryptic
`TypeError` on any unknown/typo'd key, and a misspelled attack string (e.g.
`identity:kerberoastng`) fails *silently* — it just never dispatches, with no error
to tell the author why their technique "didn't work."

**Adding a technique touches multiple places.** A new attack means editing the
`AttackTypes` enum *and* appending an `if AttackTypes.X.value in actor.get_attacks()`
branch to the dispatch chain in `generate_activity_new` (and sometimes `Actor.py`) —
easy to half-wire.

**Realism content is hardcoded in Python.** Believable detail lives in flat
constant lists — `LEGIT_USER_COMMANDLINES`, `LEGIT_SYSTEM_COMMANDLINES`, the
SPN/discovery/persistence constants, the Alexa and corncob wordlists — none of which
a non-developer can edit.

**Techniques fire independently.** Each attack runs as its own daily activity
against randomly-picked employees, so the telemetry is a pile of unrelated events
rather than one connected intrusion a player can pivot through.

**The static guide is already drifting.** `summary.txt` narrates a company called
"GlobalGoodwill" while `company.yaml` defines "Contoso" — a concrete symptom of
hand-maintained narrative getting out of sync with the scenario config.

**The key enabling fact for automation.** The engine *knows the ground truth at
generation time*: every actor has known domains, IPs, sender emails, malware
hashes, and file names, and each generator picks the exact compromised user/host
and writes the precise C2 IP into the telemetry. Anything the engine writes, it can
also emit as an answer key or narrate in a guide.

---

## The ten improvements (from analysis)

### Making authoring easier

1. **Config validation at load with human-readable errors.** A schema layer
   (pydantic/cerberus) run on each YAML before construction. Catches unknown/typo'd
   keys, attack strings that aren't real `AttackTypes` members, and unmet
   cross-references (`watering_hole:*` with no `watering_hole_domains`,
   `delivery:supply_chain` with no partners, a `malware:` name with no matching
   config). Use **Pydantic** models and run the schema at **startup, before any ADX
   connection**, so a typo like `remote_exploit` for `remote_exploitation` fails
   immediately with an explicit pointer to the offending file and field — not deep
   into generation after the engine has already started talking to Azure.
   *Highest leverage, lowest risk.*

2. **Attack registry to replace the hardcoded `if`-chain.** A single mapping of
   attack string → `{generator_fn, required_config_fields, tables_written,
   description, attack_id}`. The dispatch loop iterates `actor.get_attacks()` and
   calls registered handlers. One source of truth that powers validation (#1), the
   GUI (#3), docs, and auto-challenges (#11).

3. **"Manage Scenario" admin page**, mirroring the existing challenges editor.
   List / create / edit / **clone** actors and malware via form or in-browser YAML
   editor, validated before save. Clone-an-existing-actor is the biggest single
   authoring speed-up. The challenge CSV-import route is a ready template.
   *Status: ✅ done — `/admin/manage_scenario` lists every actor/malware config with a
   summary and edits/clones/deletes them in an in-browser YAML editor. Every save runs
   through the config validator (#1) first, so invalid configs are rejected with inline
   errors and never written; strict filename/path sanitization confines writes to the
   config dirs. Backed by the unit-tested `scenario_admin.py`; linked from the sidebar
   and the Manage Game tools panel. (Company-config editing + a structured form view
   are possible future additions.)*

4. **Externalize realism content into editable data packs.** Move the hardcoded
   command/SPN/wordlist constants to YAML/JSON content packs so non-developers can
   extend realism without touching code. Feeds the scenario wizard (#13).

5. **Dry-run preview.** Build on `ADX_DEBUG_MODE` (which already prints instead of
   uploading): run one day for one actor and show per-table row counts plus sample
   rows, so an author can sanity-check a scenario before a full game run.

### Making it more realistic

6. **Model campaigns as a connected kill chain** *(biggest realism lever).* Thread
   phishing → execution → discovery → lateral movement → persistence → exfil through
   the *same* compromised host, user, C2 infrastructure, and timeline, so the data
   reads as one huntable narrative instead of scattered events.
   *Status: 🚧 v1 shipped (opt-in, `CAMPAIGN_MODE_ENABLED`, off by default). A campaign
   context (`build_campaign` in `advanced_attacks_controller`) pins ONE compromised host
   + ONE C2 IP per actor, deterministic by actor name so it's stable across the whole
   activity window; `dispatch_actor_attacks` sets it around the run, and
   `_targeted_employees`/`_actor_ip` honor it, so every post-compromise stage
   (kerberoasting, lateral movement, log clearing, persistence, cloud) threads to the
   same host/infra — a single pivotable intrusion. This also advances cross-table
   identity consistency (#7). Remaining: explicit stage ordering with dwell/jitter
   between stages (#8), threading initial access (email/watering-hole) into the same
   campaign, and persisting the campaign so a shared session_id/malware-hash flows
   through too. **Update:** stage dwell shipped — see #8.*

7. **Consistent entity identities across tables.** Ensure the same
   hostname/username/src_ip/session_id actually resolves across `ProcessEvents`,
   `SecurityEvents`, `AuthenticationEvents`, and the cloud logs. Stable, recurring
   per-campaign C2 infra reads far more like a real actor than fresh-random values.

8. **Event-driven behavioral timing (dwell & beacon jitter).** Move from rigid
   sequential waves toward an event-driven model where each stage fires a *staggered
   time delta* off the previous event rather than a predictable loop — a user clicks
   a phishing email hours after receipt, a C2 agent sleeps before secondary
   discovery, exfil runs low-and-slow, activity clusters in operational hours with
   weekend gaps. Builds directly on the existing working-hours/bimodal timing and the
   `Trigger` click-delays, formalizing them into a per-stage behavioral state machine.
   *Status: 🚧 the per-stage piece shipped with the campaign model (#6): in campaign mode
   each post-compromise stage reads a shared campaign clock that the dispatch advances by
   a randomized in-working-hours dwell after every stage (`advance_campaign_clock`), so
   the kill chain unfolds in order over time instead of all stages picking a random hour.
   Remaining: beacon jitter, low-and-slow exfil pacing, and explicit weekend/holiday gaps.*

9. **Map every attack to MITRE ATT&CK.** Store the technique ID on each attack
   (T1558.003 Kerberoasting, T1021.002 SMB/admin-share lateral movement, T1070.001
   log clearing, T1547.001 Run-key persistence, …). Grounds authoring in a known
   framework, lets you pull realistic artifacts from ATT&CK / Atomic Red Team, and
   gives a teaching/scoring hook.

10. **Richer benign baseline.** Deepen the default actor's noise — realistic
    parent/child process trees, varied user-agents tied to OS, proxy/DNS chatter —
    so malicious activity has to be hunted out of believable background.

---

## New capability: auto-generated content

All three of these are unlocked by the "engine knows the ground truth" fact above.

11. **Auto-populate challenge questions & answers.** As each generator writes an
    event chain, it also emits an *answer-key record* (e.g. `C2 IP for the
    BluePhoenix intrusion = 45.66.77.88`, `compromised user = jdoe2`,
    `malware sha256 = …`). A challenge-builder turns those into `Challenge` rows via
    the existing model and bulk insert (the CSV importer already does this kind of
    bulk creation). Question templates per attack type ("What IP address did the
    actor use for C2 against `{user}`?") fill in from the answer key.
    - **Constraint:** scoring is exact case-insensitive string match
      (`Challenge.check_answer`), so auto-answers must be deterministic and
      unambiguous (IPs, hashes, hostnames, domains — all good). Provide multiple
      accepted forms via the existing `;`-separated answer field where needed.
    - **Depends on:** attack registry (#2), kill-chain/identity work (#6, #7) for
      answers that span stages.
    *Status: ✅ done — a pure `build_challenges()` turns scenario facts into `Challenge`
    dicts via per-fact/per-technique templates (malicious IPs, domains, phishing senders,
    malware families/hashes, attribution+aliases, and de-duped MITRE ATT&CK ids from the
    registry), with `;`-separated multi-accept answers (the #21 normalizer handles
    submission formatting). `/admin/generate_challenges` gathers the live ground truth
    (DB actors + YAML attribution + generated malware) and bulk-creates the non-duplicate
    ones; GET previews (text/JSON), and there's a preview + Auto-generate button on Manage
    Challenges. Best run after a game has generated (most facts only exist post-run).
    Per-event answers that need generator instrumentation (e.g. the exact compromised
    host/SPN) are a follow-up; campaign mode (#6) already makes those deterministic.*

12. **Auto-generate the game guide & instructor key.** Assemble a guide from the
    scenario config — company profile, actor cast, campaign timelines, techniques
    used (with ATT&CK IDs), and learning objectives — producing both a player-facing
    intel brief and an instructor answer key. Generated-from-config means it can't
    drift the way `summary.txt` has. Template-driven by default; optional LLM pass
    to polish the prose.
    - **Depends on:** ATT&CK tagging (#9), campaign model (#6), answer-key emission
      (#11).

13. **Scenario story wizard for admins.** A guided flow: pick an archetype
    (espionage, ransomware, insider, supply-chain), targets, timeline, and
    techniques → scaffold a consistent set of company + actor + malware configs +
    campaign + matching challenges + guide, all validated. Optional LLM-assisted
    authoring of themes, subjects, and narrative. This is the capstone that ties
    authoring (#1–#5) and realism (#6–#10) together.
    - **Depends on:** validation (#1), registry (#2), content packs (#4), GUI (#3),
      auto-challenges (#11), auto-guide (#12).

47. **Scenario PDF export (admin).** The PDF deliverable form of #12: an admin export
    that assembles the scenario framing (company, actors + their ATT&CK techniques from
    the registry, timeline) and the challenge set into a polished PDF, in two variants —
    a **player packet** (no answers) and an **instructor answer key** (with answers, and
    the reveal pivot once #11 lands). Renders with a pure-Python library
    (`fpdf2`/`reportlab`), lazy-imported and guarded so a missing package can't break the
    app. Mirrors the existing CSV export routes; options for round scope, include/exclude
    answers, and grouping by category or kill-chain phase. Also retires the stale
    `summary.txt` narrative by generating it from live config.

---

## Engine completeness & enhancements (from code audit)

14. **Complete the partially-wired techniques.** Several techniques already have
    generators or primitives but aren't first-class dispatched attacks:
    - ✅ `watering_hole:phishing` — **now dispatched** in `generate_activity_new`
      (calls `actor_stages_watering_hole(link_type="phishing")`, a drive-by to a fake
      login that routes through the credential-capture trigger).
    - ✅ `delivery:supply_chain` — **now triggers email on its own** (added to the email
      dispatch gate), so a supply-chain-only actor sends from compromised partner
      addresses instead of nothing.
    - ✅ Hands-on-keyboard post-exploitation (`hands_on_keyboard:operator`, T1059 →
      ProcessEvents) and email/data exfiltration (`exfiltration:email_collection`,
      T1114.002 → AuthenticationEvents + InboundBrowsing) are **now first-class
      standalone techniques**, no longer only follow-ons to an email-malware detonation.
      Added `AttackTypes` members, registry specs (new `Execution` / `Exfiltration`
      kill-chain phases), standalone generators, and `ATTACK_DISPATCH` entries. Both are
      campaign-aware — when campaign mode is on they operate against the pinned host and
      reuse the pinned C2 IP/domain (#6), so they slot cleanly into the kill chain.

    *Benefit: completes the documented technique menu with no new infrastructure. ✅ Done
    — all three wired; the registry⇄enum and dispatch⇄enum self-checks keep them in sync.*

15. **Per-technique detection fidelity.** The engine already models alert
    true/false-positive rates (`TP_RATE_HOST_ALERTS`, `FP_RATE_*`, etc.). Extend this
    so each technique carries a realistic detection profile — some noisy (service
    install, impossible-travel sign-in), some deliberately quiet (log clearing,
    Kerberoasting) — giving players authentic visibility gaps to work around.
    *Benefit: cheap realism win; makes hunts feel real.*

---

## Performance & architecture (scale & robustness)

> Generation already runs in a background **daemon thread** (`/admin/start_game` →
> `threading.Thread(..., daemon=True)`), so the web request itself doesn't block.
> These items address what that thread *doesn't* give you: durability, out-of-process
> isolation, and throughput at large employee/wave counts.

16. **Decouple generation from the Flask process.** Today generation runs in-process
    in a daemon thread that shares the GIL with the web server and dies with it (no
    retry, no durability, hard to script or test). Two complementary moves:
    - **CLI entrypoint** (`click` / `argparse`) that runs a full generation from a
      config set headlessly — great for reproducible runs, CI, and the dry-run
      preview (#5). *Low effort, high value; do first.*
    - **Task queue** (Celery + Redis) so Flask only *starts and monitors* generation
      while a separate worker does the heavy lifting durably. *Larger; do when you
      need concurrent games or crash-resilient long runs.*

17. **Concurrent ADX uploads.** `LogUploader` batches and ingests one table at a time
    (`send_request` → per-table `ingest_from_dataframe` in a loop), so initialization
    is gated by sequential HTTP latency to Azure. Push independent table groups
    (passive DNS, endpoint, email, cloud) concurrently with `concurrent.futures`.
    *Caveat:* the singleton `LOG_UPLOADER` queue is shared across every module, so the
    queue and its flush must be made thread-safe and per-table ingestion kept intact.
    *Medium effort; biggest win at high employee/wave counts.*

---

## Scoreboard & scoring

Grounded in the current scoring path (`submit_answer`, `update_deny_list`,
`calculate_time_weighted_points` / `calculate_round_time_weighted_points`,
`/get_score`, and the `Users` / `Team` / `Solve` / `AnswerAttempt` models).

### Correctness (bug fixes — do first)

18. **Team double-credit — resolved by decision (no change).** `Solve` is unique per
    `(challenge_id, user_id)`, and `submit_answer` adds to `current_user.team.score` on
    every first-per-*user* solve, so two members solving the same challenge credit the
    team twice. **Owner decision: this is intended** — every correct solve earns points
    for both the individual and the team, and a team's total is the sum of its members'
    solves. Not treated as a bug; no change shipped. *If redundant-solve inflation
    becomes a concern later, the option remains to credit the team once per challenge
    while still awarding the individual.*

19. **Consistent tie-break timestamps.** Player `last_score_time` updates on every
    score; `team.last_score_time` is only set once (when `None`). `/get_score`
    tie-breaks both ascending, so players are ranked by *most recent* score and teams
    by *first* score. Pick one rule (CTF convention: earliest to reach the current
    total wins) and apply it to both. *Status: ✅ done — `submit_answer` and
    `update_deny_list` now set `team.last_score_time = now` on every score, matching the
    player rule.*

20. **Recompute scores from source of truth.** Totals are denormalized counters on
    `Users`/`Team` with no way to rebuild them. `Solve.points_awarded` and
    `AnswerAttempt` already log everything, so add a recalculate-from-records function
    (and ideally derive the board from records) so corrected answers / deleted solves /
    changed challenge values can't silently desync standings. *Status: 🚧 a
    **non-destructive reconciliation** ships at `/admin/score_audit` — it recomputes
    challenge points from `Solve` **plus indicator points from `MitigationAward`** and
    flags desync (negative delta). The indicator-award gap is now closed: a
    `MitigationAward` row is written for every correct indicator (the indicator
    equivalent of `Solve`), so the recompute is **exact for games run since**. The
    destructive **rebuild** also shipped: `?apply=1` overwrites every score and
    `last_score_time` from the records (`compute_rebuild`). #20 complete.*

### Answer matching

21. **Answer normalization & defanging.** `Challenge.check_answer` only does
    `strip().lower()` + `;`-alternates, so `http://bad.com`, `bad.com`, and `bad.com/`
    are scored differently despite identical analysis. Canonicalize *both* sides before
    comparing: refang analyst notation (`hxxp`→`http`, `[.]`/`(.)`/`[dot]`→`.`,
    `[at]`→`@`), drop URL scheme and trailing slash, lowercase, trim. Backward-compatible
    by construction (normalizing both sides can only *add* matches, never reject a
    previously-correct answer). Apply the same normalizer to indicator scoring in
    `update_deny_list` for consistency.
    - *Later layers:* an optional per-challenge `answer_type` (url/domain/ip/sha256/
      email/text) with type-specific normalizers, and a carefully-bounded optional
      regex escape hatch (explicit opt-in, match timeout — guard against ReDoS, since
      a request-thread can't be signal-interrupted safely).

### Scoring design

22. **Per-challenge timing, first-blood, optional dynamic scoring.** Global
    time-weighting decays since *game start*, shared across all challenges, so late
    joiners are permanently penalized and after 24h there's no speed incentive. Add
    per-challenge decay from publish time, first-blood bonuses, and an optional
    CTFd-style dynamic value (worth less as more teams solve it). *Optional modes;
    changes game balance — gate behind config.* *Status: ✅ done — a CTFd-style
    quadratic dynamic value + first-blood bonus shipped as a pure module
    (`scoring/dynamic_scoring.py`), wired into `submit_answer` behind
    `DYNAMIC_SCORING_ENABLED` (off by default; tunable via `DYNAMIC_SCORING_MINIMUM`,
    `DYNAMIC_SCORING_DECAY`, `FIRST_BLOOD_BONUS_PCT`). Disabled = current time-weighted
    scoring, unchanged. Per-challenge decay from publish time remains a future refinement.*

23. **Mitigation submission precision.** `update_deny_list` rewards correct new
    indicators but never penalizes wrong ones, inviting spraying the indicator box.
    Consider optional small penalties, rate-limiting, or an attempt cap. *Optional;
    penalties can discourage learners — keep configurable.*

### Scoreboard UX & integrity

24. **Live auto-refresh standings.** `/get_score` is poll-only; push real-time updates
    (SSE/websocket or a persisted live view) so the room sees movement.

25. **Richer visualization.** Progress by kill-chain phase/category, a score-over-time
    line per team, first-blood markers, and rank numbers with movement deltas.

26. **Anti-cheat surfacing.** `AnswerAttempt` logs every submission — flag identical
    answer strings across teams in tight windows or impossibly fast solves on the admin
    live feed to catch answer-sharing.

27. **Fix `/get_score` N+1 + cache.** It loads all users and touches `p.team.name` per
    row (lazy load per player) on every poll. Eager-load/aggregate and cache a few
    seconds before adding auto-refresh load. *Status: 🚧 N+1 fixed —
    `joinedload(Users.team)` eliminates the per-player team query; the short cache is
    intentionally deferred until live auto-refresh (#24) actually adds poll load.*

---

## Admin & operations

Complements the GUI that already exists (users, teams, challenges, rounds, indicators,
ADX config, live answer feed). These fill the remaining gaps: observing/controlling
generation, operating the scoreboard, facilitator analytics, multi-event lifecycle,
and ops hardening. Several adjacent admin needs are already tracked elsewhere —
scenario authoring GUI (#3), dry-run preview (#5), auto-generated challenges (#11),
score recompute (#20), anti-cheat surfacing (#26).

### Generation control & observability

28. **Generation run console.** Today it's start/stop/restart with a progress bar and
    console `print`s. Add a "Validate configs" button (surface the validator's
    file+field errors before a run), stream per-day/per-actor progress and logs into
    the UI, allow cancel/pause mid-run, and keep a **run history** (timestamp,
    duration, rows ingested per table).
    *Status: ✅ done — a `GameRunLog` row is recorded for each generation
    (started/finished, duration, status, error, scenario window, days, **per-table row
    counts**) and surfaced at `/admin/run_history` (+ a Manage Game link). The Manage Game
    page now shows a **streamed progress log** (via `GAME_PROGRESS["log"]` polled through
    `/admin/game_status`, which also reports live per-table counts), and **Stop cancels a
    running generation** mid-run (the day loop checks `cancel_requested` and records a
    `cancelled` run). Config validation already runs at the start of generation (#1).
    (Pause/resume not implemented — Stop+restart covers it.)*

29. **Scheduled game start/stop.** Auto-launch or end a game at a set time (fits the
    existing scheduled-task support) for unattended events.

### Scoreboard operations

30. **Manual score adjustments.** Award bonus/penalty points or correct a score from the
    admin UI, written through an audit trail (see #37).

31. **Edit accepted answers + re-grade.** Let an admin fix a challenge's accepted answers
    and re-grade past `AnswerAttempt`s so early submissions aren't unfairly marked wrong.
    Pairs with answer normalization (#21).

### Challenge tooling

32. **Hints & gating.** Optional hints with a point cost, timed challenge unlocks, and
    prerequisite chains (a challenge unlocks after another is solved).

33. **Answer tester.** A "test this answer" control so an author can confirm a question
    grades correctly (including normalization/alternates) before publishing.

### Facilitator analytics

34. **Analytics dashboard.** Beyond the live feed: score-over-time per team, solve rates
    by challenge/category/ATT&CK phase, difficulty calibration (challenges nobody solves),
    engagement (active vs. idle players), and ADX ingestion health (queue depth, errors).

### Lifecycle & multi-event

35. **Multiple concurrent scenarios.** Today it's effectively one company and one game
    session (`Company.query.first()`, `GameSession` id=1). Support parallel
    events/scenarios plus a scenario template library (save/clone a whole scenario).

36. **Reset / archive / export a game.** One-click reset, archive a finished event, and
    export full game state (scores, solves, configs) for records or replay.

### Ops hardening

37. **Admin-action audit log.** Record privileged actions (score edits, config changes,
    user/role changes, game start/stop) for accountability.

38. **Access & resilience.** Force-change the default `admin`/`admin` password on first
    login, add finer roles (read-only **facilitator/observer**, **grader**) alongside
    Admin/Player, and provide DB + config backup/restore.

---

## Real-world intel & attribution

Turn fictitious actors (BluePhoenix, MarketMasters) into emulations of real threat
groups so analysts can perform **attribution** — clustering intrusions by an actor's
techniques, tooling, malware families, and infrastructure habits. Builds on the
ATT&CK tagging already in the registry, data packs (#4), the campaign/identity work
(#6/#7), and answer normalization (#21).

**Guiding constraint:** realism for attribution comes from *pattern consistency*, not
from shipping live IOCs. Use real TTPs and real *historical* hashes, but keep
infrastructure inert and never ship real malware binaries.

### Safety guardrails (do first — non-negotiable)

39. **Inert indicators & no live infrastructure.** A config toggle controls whether
    actor infrastructure is *synthetic but modeled* on the real actor (TLDs, registrars,
    hosting ASNs, naming/cert patterns) or drawn from *historical / sinkholed / defanged*
    real indicators — never live C2 a player could browse to or blocklist on a real
    network. Keep the existing EICAR-only seed-file invariant (`write_seed_files`); real
    hashes appear only as indicator strings, never as real payloads. Every real IOC
    carries provenance (source + report URL).
    *Status: ✅ done — `ALLOW_REAL_INDICATORS` / `ALLOW_REAL_C2_INFRASTRUCTURE` config
    toggles (default OFF); the EICAR seed-file invariant is centralized in
    `safety.py` (`EICAR_TEST_STRING` + `seed_file_content_is_inert()`, `write_seed_files`
    now sources the constant); `defang()` renders real IOCs inertly (round-trips with the
    existing `refang`); `check_safety_invariants()` warns when a toggle is on. Per-IOC
    provenance enforcement arrives with intel-packs (#43).*

### Actor & TTP modeling

40. **Actor attribution metadata.** Extend actor configs with group name + aliases
    (e.g. "APT29 / Cozy Bear / Midnight Blizzard"), ATT&CK Group ID (`G####`), suspected
    origin, and motivation, plus the ATT&CK techniques that group actually uses.
    *Status: ✅ done — actor configs accept `attribution`, `aliases`, `attack_group_id`
    (validated as `G####`), `origin`, and `motivation`, with **no DB schema change** (the
    metadata is read from the YAML by the validator, preview, and PDF rather than stored
    on the `Actor` table). The techniques the group uses are derived from the actor's
    `attacks` via the registry. Demonstrated on BluePhoenix/MarketMasters; surfaced in
    the scenario preview and the instructor-key PDF (excluded from the player packet).
    This also unblocks the actor-side of #46 — `attack_group_id` format is now validated.*

41. **Real TTP tooling & command lines.** Populate `post_exploit_commands` and the
    malware `recon_processes`/`c2_processes` with the emulated group's real tooling and
    command-line patterns, sourced from ATT&CK and Atomic Red Team.

42. **Real malware families + historical hashes.** Replace fictitious families with real
    ones per actor; seed `malware.hashes` with genuine open-intel sample hashes (they
    flow straight into `get_malicious_indicators()` as correct answers), each with
    provenance. Strings only — never real binaries.

### Sourcing, clustering & scoring

43. **Intel-pack ingestion.** A content-pack format + importer that maps actor → ATT&CK
    group + techniques + tooling + indicator templates + historical hashes. Built from
    open-licensed sources: **MITRE ATT&CK** STIX (Groups `G####`, Software `S####`) and
    **abuse.ch** (ThreatFox / MalwareBazaar / URLhaus), which tag samples by malware
    family and actor. Extends data packs (#4); avoid hard dependence on licensed feeds
    (e.g. VirusTotal).
    *Status: ✅ Format + importer shipped (`modules/intel_packs/intel_pack.py`). An intel
    pack is a portable YAML bundle — group name/aliases, ATT&CK group id (`G####`), the
    group's technique ids, plus historical hashes/indicators with **provenance**. The
    importer maps the pack onto a validated **actor config**: it carries the attribution
    metadata (#40) and selects the subset of techniques the game can generate via the
    registry's ATT&CK reverse lookup (`attacks_for_attack_id`), noting the rest. Safety
    (#39) is enforced — provenance is **required**, indicators are **defanged** unless
    `ALLOW_REAL_INDICATORS` is on, hashes are strings only, and the result passes the
    config validator before it's written. Admin route `/admin/import_intel_pack`
    (Preview / Import &amp; save) lives on the Manage Scenario page; a sample inert pack
    is at `app/game_configs/intel_packs/apt29_emulation.yaml`. Follow-up: live ATT&CK/
    abuse.ch fetch-and-build to auto-populate packs, and feeding pack hashes/indicators
    into generated telemetry (needs malware-hash injection + infra reuse, #44).*

44. **Actor-consistent infrastructure reuse (the core attribution enabler).** Have each
    actor reuse infrastructure patterns and malware families across campaigns — same ASN
    ranges, TLD/registrar/cert fingerprints, reused hashes — so two intrusions can be
    clustered to one actor. Builds directly on the campaign model (#6) and cross-table
    identity consistency (#7). Without reuse, there is nothing to attribute.
    *Status: ✅ v1 shipped (opt-in `INFRA_REUSE_ENABLED`). Audit of the generators found
    domains were already actor-consistent (stable per-actor TLDs + theme words) and
    malware hashes already reused per family (`assign_hash_to_malware`) — the missing
    piece was IPs, which were minted fully random (`fake.ipv4_public()`) and so had no
    network neighborhood to pivot on. `modules/infrastructure/infra_reuse.py` now gives
    each actor a small, **stable set of "owned" /16 ranges** (ASN-like prefixes) derived
    deterministically from the actor name, in globally-routable public space; the single
    IP-creation chokepoint (`IP.__init__`) draws from those ranges when the flag is on,
    avoiding the actor's existing addresses (collision-safe) and falling back to the
    original random generator on default actors / flag-off / any error — so behavior is
    unchanged by default. `actor_infrastructure_fingerprint()` exposes the ranges + TLDs
    for the preview, auto-challenges, and #45. Campaign C2 selection (#6) inherits the
    fingerprint for free. Follow-ups: registrar/cert fingerprint reuse, feeding real
    pack indicators (#43) into the owned ranges, and an "ASN/network range" auto-challenge
    (#11) + the attribution scoring mechanic (#45).*

45. **Attribution scoring mechanic.** A challenge category whose answer is the threat
    actor name/alias; the normalizer (#21) already accepts aliases via `;`-separated
    forms. Players attribute from TTP + indicator overlap, then corroborate against the
    referenced report.

46. **Validator extension.** Grow the config validator (#1) to check that an actor's
    declared ATT&CK group/technique IDs exist and that intel-pack references resolve.
    *Status: 🚧 ATT&CK technique-id validation shipped — the registry now self-validates
    that every technique carries a well-formed MITRE id (`assert_attack_ids_wellformed`,
    wired into the validation pre-flight so a typo'd id fails fast), and a reusable
    `validate_attack_ids()` helper is ready for actor-declared techniques. The actor
    ATT&CK-group and intel-pack reference checks await the attribution metadata (#40) and
    intel-packs (#43).*

---

## Phased plan

Effort key: **S** ≈ days · **M** ≈ 1–2 weeks · **L** ≈ multi-week.
Risk is the chance of disturbing existing behavior.

### Phase 0 — Foundations already in place ✅
- 9 advanced attack types added (Kerberoasting, PsExec lateral, log clearing,
  automated recon, cloud session hijacking/token theft, cloud storage exfil,
  scheduled-task & registry-run persistence).
- 3 new telemetry tables (`SecurityEvents`, `CloudSignInLogs`, `CloudStorageLogs`),
  auto-created via `LogUploader.CUSTOM_TYPES`.
- Demonstrated on the BluePhoenix and MarketMasters actors.
- **Attack registry (#2) + MITRE ATT&CK tagging (#9)** — single source of truth in
  `app/server/modules/attacks/attack_registry.py` describing every technique's phase,
  ATT&CK id/name, description, ADX tables, and required actor-config fields. A
  self-check keeps it in sync with the `AttackTypes` enum.
- **Config validation (#1)** — dependency-free validator
  (`app/server/modules/config_validation/`) runs at the top of `start_game()` *before
  any ADX connection*. Catches unknown/typo'd keys (with "did you mean"), invalid
  attack strings, missing required fields, bad types, and hard cross-references
  (watering-hole without domains, malware referenced with no config). Shipped configs
  validate clean; failures abort with an aggregated file+field message.

### Phase 1 — Authoring guardrails (unblocks everything else)
| # | Item | Effort | Risk | Notes |
|---|------|--------|------|-------|
| 1 | Config validation + clear errors | S–M | Very low | ✅ **Done** — validates before ADX; clear file+field errors |
| 2 | Attack registry | M | Low | ✅ **Done** — single source of truth + **registry-driven dispatch** (declarative `ATTACK_DISPATCH` table replaces the if-chain) |
| 9 | ATT&CK tagging on attacks | S | Very low | ✅ **Done** — ATT&CK id/name per attack in the registry |
| 5 | Dry-run preview | S | Very low | ✅ **Done** — `/admin/preview_scenario` + CLI; registry-driven tables/active-days/volume (execution-based row counts a future add-on) |
| 14 | Complete partially-wired techniques | S | Very low | ✅ Done — `watering_hole:phishing` + supply-chain dispatch, plus standalone `hands_on_keyboard:operator` (T1059) and `exfiltration:email_collection` (T1114.002) now first-class, dispatched, and campaign-aware |

### Phase 2 — Auto-generated content
| # | Item | Effort | Risk | Notes |
|---|------|--------|------|-------|
| 11 | Answer-key emission + challenge auto-population | M | Low | ✅ **Done** — `/admin/generate_challenges` builds `Challenge`s from live ground truth (IOCs, hashes, attribution, ATT&CK ids) + preview/button |
| 4 | Externalize realism content into data packs | M | Low | Decouples content from code |

### Phase 3 — Realistic campaigns
| # | Item | Effort | Risk | Notes |
|---|------|--------|------|-------|
| 6 | Kill-chain / campaign model | L | Medium | ✅ **Done** (opt-in) — pins one host + C2 across post-compromise stages, which now unfold in order with dwell; initial-access threading + DB persistence are future polish |
| 7 | Cross-table identity consistency | M | Medium | Stable per-campaign infra & entities |
| 8 | Event-driven behavioral timing (dwell & jitter) | S–M | Low | 🚧 stage dwell shipped — campaign clock advances an in-working-hours dwell between stages so the kill chain unfolds in order; beacon jitter / low-and-slow exfil pending |
| 10 | Richer benign baseline | M | Low | Deepen default-actor noise/process trees |
| 15 | Per-technique detection fidelity | S–M | Low | Tune noisy vs. silent techniques (alert FP/TP rates) |

### Phase 4 — Authoring experience
| # | Item | Effort | Risk | Notes |
|---|------|--------|------|-------|
| 3 | "Manage Scenario" admin GUI (+ clone) | M–L | Low | ✅ **Done** — `/admin/manage_scenario` lists/edits/clones/deletes actor & malware YAML in-browser; validates before save |
| 12 | Auto-generated game guide & instructor key | M | Low | From config; ends `summary.txt` drift |
| 47 | Scenario PDF export (admin) | M | Low | ✅ **Done** — `/admin/export/scenario_pdf`; player packet + instructor key; reportlab guarded |
| 13 | Scenario story wizard | L | Low | Capstone; depends on most prior items |

### Phase 5 — Performance & architecture (as scale demands)
| # | Item | Effort | Risk | Notes |
|---|------|--------|------|-------|
| 16a | Generation CLI entrypoint | S–M | Low | Headless, reproducible runs; supports #5 preview |
| 17 | Concurrent ADX uploads | M | Medium | Make shared queue thread-safe; keep per-table ingestion |
| 16b | Task queue (Celery + Redis) | L | Medium | Out-of-process, durable, crash-resilient generation |

> This phase is **demand-driven**, not sequential — pull it forward the moment large
> employee/wave counts make generation slow or fragile. It's independent of the
> content and realism tracks.

### Phase 6 — Scoreboard & scoring (independent track)
| # | Item | Effort | Risk | Notes |
|---|------|--------|------|-------|
| 21 | Answer normalization & defang | S–M | Very low | ✅ **Done** — universal normalizer wired into `check_answer` + indicator scoring; type/regex layers pending |
| 18 | Team double-credit | — | — | ✅ Decision: intended behavior (both team & player earn per solve); no change |
| 19 | Consistent tie-break timestamps | S | Low | ✅ **Done** — teams now update `last_score_time` on every score (same rule as players: earliest to reach total wins) |
| 20 | Recompute scores from solves | M | Low | ✅ **Done** — `/admin/score_audit` reconciles (challenge+indicator) vs stored; awards recorded (`mitigation_awards`); `?apply=1` destructively rebuilds scores + times from records |
| 27 | `/get_score` N+1 + cache | S | Low | 🚧 N+1 fixed (eager-load `Users.team`) ✅; short cache deferred until live auto-refresh (#24) adds poll load |
| 24 | Live auto-refresh standings | S–M | Low | SSE / poll / persisted live view |
| 25 | Richer visualization | M | Low | Phase breakdown, score-over-time, first blood, ranks |
| 26 | Anti-cheat surfacing | M | Low | Pattern-flag from `AnswerAttempt` |
| 22 | First-blood / dynamic scoring | M | Medium | ✅ **Done** — `dynamic_scoring` module; opt-in via `DYNAMIC_SCORING_ENABLED` (off by default), tunable min/decay/first-blood% |
| 23 | Mitigation submission precision | S | Medium | Optional penalties/rate-limit; keep configurable |

### Phase 7 — Admin & operations (independent track)
| # | Item | Effort | Risk | Notes |
|---|------|--------|------|-------|
| 38 | Ops hardening (default-pw, roles, backup) | S–M | Low | Security basics; force the password change early |
| 37 | Admin-action audit log | S–M | Low | Underpins #30 and trust |
| 30 | Manual score adjustments | S | Low | Needs audit log (#37) |
| 33 | Answer tester | S | Very low | ✅ **Done** — `/admin/test_answer`; `explain_match` shows normalized forms + which accepted answer matched |
| 28 | Generation run console & history | M | Low | ✅ **Done** — run history + per-table row counts, streamed progress log, and Stop-to-cancel mid-run |
| 31 | Edit answers + re-grade | M | Low | Re-grade `AnswerAttempt`; pairs with #21 |
| 34 | Facilitator analytics dashboard | M | Low | Builds on `Solve`/`AnswerAttempt` |
| 32 | Hints & challenge gating | M | Low | Schema additions; player-facing |
| 29 | Scheduled game start/stop | S | Low | Uses scheduling support |
| 36 | Reset / archive / export game | M | Medium | Touches game state; guard carefully |
| 35 | Multiple concurrent scenarios | L | Medium | Removes single-company/session assumption |

### Phase 8 — Real-world intel & attribution (independent track)
| # | Item | Effort | Risk | Notes |
|---|------|--------|------|-------|
| 39 | Inert-indicator safety controls | S | Low | ✅ **Done** — safety toggles (off by default), centralized EICAR invariant + `defang()` + advisory checks |
| 40 | Actor attribution metadata | S | Low | ✅ **Done** — attribution/aliases/group-id/origin/motivation on actor config; validated; surfaced in preview + instructor-key PDF |
| 46 | Validator extension (ATT&CK / intel refs) | S | Very low | 🚧 ATT&CK-id validation done (registry self-check in pre-flight + `validate_attack_ids`); actor-group/intel-pack refs await #40/#43 |
| 42 | Real malware families + historical hashes | M | Low | Inert hashes-as-strings only; provenance |
| 41 | Real TTP tooling & command lines | M | Low | From ATT&CK / Atomic Red Team |
| 43 | Intel-pack ingestion (ATT&CK STIX + abuse.ch) | M–L | Low | ✅ Format + importer + admin route + sample pack (provenance-required, defang-safe, validated); live feed-fetch is the follow-up |
| 44 | Actor-consistent infra reuse (clustering) | M | Medium | ✅ v1: stable per-actor /16 ranges (opt-in `INFRA_REUSE_ENABLED`, collision-safe, fallback-on-error); domains/hashes already consistent. Registrar/cert reuse + ASN challenge are follow-ups |
| 45 | Attribution scoring mechanic | M | Low | Actor-name answers; aliases via #21 |

---

## Recommended starting point

**Done:** the foundational, lowest-risk items — **config validation (#1)**, the
**attack registry (#2)**, and **ATT&CK tagging (#9)** — are implemented (see Phase 0).
Authoring is now safe and self-documenting, and the registry is in place to drive the
rest of the plan.

**Next, in value-to-risk order:**

1. **Dry-run preview (#5)** — lowest risk; the registry already exposes the tables
   each actor's attacks will write, so a preview can report expected row counts/tables
   without a full run.
2. **Complete the partially-wired techniques (#14)** — ✅ **done.** `watering_hole:phishing`
   and `delivery:supply_chain` are dispatched, and data-exfil (`exfiltration:email_collection`)
   and hands-on-keyboard (`hands_on_keyboard:operator`) are now first-class standalone,
   campaign-aware techniques with registry specs + dispatch entries.
3. **Registry-driven dispatch** — ✅ **done.** The hardcoded `if`-chain in
   `generate_activity_new` is replaced by a single declarative `ATTACK_DISPATCH` table +
   `dispatch_actor_attacks()` loop. The email collapse (`email:phishing` /
   `email:malware_delivery` / `delivery:supply_chain` → one `gen_actor_email`) and the
   cloud-session collapse (`session_hijacking` / `token_theft` → one call) are preserved
   via per-entry trigger groups. Proven behaviorally identical to the old chain across
   all 16 single attacks, every collapse case, the full set, and 20k random subsets;
   `assert_dispatch_covers_enum()` guards against a forgotten technique. Adding a
   technique is now a one-line table entry.

If realism is the priority instead, the **campaign / kill-chain model (#6)** is the
larger but higher-impact build, since auto-generated challenges and guides are most
compelling when they describe a single connected intrusion.

---

## Dependency map (quick reference)

```
#2 Attack registry ──┬─► #1 Validation
                     ├─► #9 ATT&CK tagging
                     ├─► #3 Scenario GUI
                     └─► #11 Auto-challenges ──► #12 Auto-guide ──┬─► #13 Scenario wizard
                                                                  └─► #47 Scenario PDF export (admin)
#6 Kill-chain model ─┬─► #7 Identity consistency
                     ├─► #8 Dwell/jitter
                     └─► (richer answers for #11/#12)
#4 Content packs ────► #13 Scenario wizard
#5 Dry-run preview ──► (supports all authoring)
#10 Benign baseline ─► (independent realism gain)
#16/#17 Performance & architecture ─► (independent track; pull forward as scale demands)
#18–#27 Scoreboard & scoring ─► (independent track; #21 normalization → #20 recompute → #24/#25 live UX)
#28–#38 Admin & operations ─► (independent track; #37 audit underpins #30; do #38 ops hardening first)
#39–#46 Real-world intel & attribution ─► (#39 safety first → #40/#43 → #44 clustering[needs #6/#7] → #45 scoring)
```
