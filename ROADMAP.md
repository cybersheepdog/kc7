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
   config). *Highest leverage, lowest risk.*

2. **Attack registry to replace the hardcoded `if`-chain.** A single mapping of
   attack string → `{generator_fn, required_config_fields, tables_written,
   description, attack_id}`. The dispatch loop iterates `actor.get_attacks()` and
   calls registered handlers. One source of truth that powers validation (#1), the
   GUI (#3), docs, and auto-challenges (#11).

3. **"Manage Scenario" admin page**, mirroring the existing challenges editor.
   List / create / edit / **clone** actors and malware via form or in-browser YAML
   editor, validated before save. Clone-an-existing-actor is the biggest single
   authoring speed-up. The challenge CSV-import route is a ready template.

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

7. **Consistent entity identities across tables.** Ensure the same
   hostname/username/src_ip/session_id actually resolves across `ProcessEvents`,
   `SecurityEvents`, `AuthenticationEvents`, and the cloud logs. Stable, recurring
   per-campaign C2 infra reads far more like a real actor than fresh-random values.

8. **Stage-to-stage dwell and beacon jitter.** Add realistic dwell (hours/days
   between stages), jittered C2 beacons, low-and-slow exfil, and weekend gaps —
   mostly new use of the existing `Clock` helpers.

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

### Phase 1 — Authoring guardrails (unblocks everything else)
| # | Item | Effort | Risk | Notes |
|---|------|--------|------|-------|
| 1 | Config validation + clear errors | S–M | Very low | Start here; immediate author relief |
| 2 | Attack registry | M | Low | Single source of truth; enables 3, 9, 11, 12 |
| 9 | ATT&CK tagging on attacks | S | Very low | Add as a field in the registry |
| 5 | Dry-run preview | S | Very low | Extends `ADX_DEBUG_MODE` |

### Phase 2 — Auto-generated content
| # | Item | Effort | Risk | Notes |
|---|------|--------|------|-------|
| 11 | Answer-key emission + challenge auto-population | M | Low | Generators emit answer rows; builder creates `Challenge`s |
| 4 | Externalize realism content into data packs | M | Low | Decouples content from code |

### Phase 3 — Realistic campaigns
| # | Item | Effort | Risk | Notes |
|---|------|--------|------|-------|
| 6 | Kill-chain / campaign model | L | Medium | Biggest realism payoff; thread one intrusion end-to-end |
| 7 | Cross-table identity consistency | M | Medium | Stable per-campaign infra & entities |
| 8 | Dwell time & beacon jitter | S–M | Low | Reuse `Clock` helpers |
| 10 | Richer benign baseline | M | Low | Deepen default-actor noise/process trees |

### Phase 4 — Authoring experience
| # | Item | Effort | Risk | Notes |
|---|------|--------|------|-------|
| 3 | "Manage Scenario" admin GUI (+ clone) | M–L | Low | Mirror challenges editor |
| 12 | Auto-generated game guide & instructor key | M | Low | From config; ends `summary.txt` drift |
| 13 | Scenario story wizard | L | Low | Capstone; depends on most prior items |

---

## Recommended starting point

The two items that compound the most with essentially zero risk to existing
behavior are **config validation (#1)** and the **attack registry (#2)** — together
they make authoring safe and self-documenting and directly unblock ATT&CK tagging
(#9), challenge auto-population (#11), the auto-guide (#12), and the scenario wizard
(#13). If realism is the priority instead, the **campaign / kill-chain model (#6)**
is the larger but higher-impact build, since auto-generated challenges and guides
are most compelling when they describe a single connected intrusion.

---

## Dependency map (quick reference)

```
#2 Attack registry ──┬─► #1 Validation
                     ├─► #9 ATT&CK tagging
                     ├─► #3 Scenario GUI
                     └─► #11 Auto-challenges ──► #12 Auto-guide ──► #13 Scenario wizard
#6 Kill-chain model ─┬─► #7 Identity consistency
                     ├─► #8 Dwell/jitter
                     └─► (richer answers for #11/#12)
#4 Content packs ────► #13 Scenario wizard
#5 Dry-run preview ──► (supports all authoring)
#10 Benign baseline ─► (independent realism gain)
```
