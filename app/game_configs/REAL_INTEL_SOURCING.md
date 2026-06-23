# Sourcing real TTPs & malware hashes (#41 / #42)

This game ships with **fictitious** actors, malware, command lines, and hashes. To raise
realism you can replace them with real, *historical*, open-intel values so analysts hunt
genuine adversary tradecraft and identify real sample hashes as answers. The scaffolding
to do this is in place — this guide is where to get the data and how to drop it in safely.

Nothing here requires code changes: you edit (or import) config files, and the game uses
them. The pieces:

| Goal | Where the data goes | Template |
| --- | --- | --- |
| Real malware family + command lines (#41) | `malware/<family>.yaml` | `malware/TEMPLATE_real_family.yaml.example` |
| Real post-exploitation commands per actor (#41) | `actors/<group>.yaml` → `post_exploit_commands` | `actors/TEMPLATE_real_actor.yaml.example` |
| Real historical sample hashes (#42) | `malware/<family>.yaml` → `hashes` | (same malware template) |
| All of the above in one bundle | import an **intel pack** | `intel_packs/TEMPLATE_real_intel.yaml.example` |

The `*.yaml.example` templates are **ignored** by every loader and the validator (only
`*.yaml` is loaded), so they are safe to keep in place as references.

## Where to get each piece (all open-licensed)

- **Groups, techniques, and software → MITRE ATT&CK.** Use the group page (`G####`) for
  aliases, origin, motivation, and the list of technique ids; use the software page
  (`S####`) for the malware the group uses. Bulk data is the ATT&CK STIX dataset.
  - Groups: https://attack.mitre.org/groups/
  - Software: https://attack.mitre.org/software/
  - STIX bundles: https://github.com/mitre-attack/attack-stix-data

- **Command lines per technique → Atomic Red Team.** Each ATT&CK technique has "atomics"
  with real, observed command-line invocations — ideal for `recon_processes`,
  `c2_processes`, and `post_exploit_commands`.
  - https://github.com/redcanaryco/atomic-red-team

- **Sample hashes, family tags, first-seen → abuse.ch.** Per-sample and per-IOC pages give
  the sha256, the malware family, and the date first seen — paste these into `hashes`
  with a `reference` URL.
  - MalwareBazaar (samples): https://bazaar.abuse.ch/
  - ThreatFox (IOCs): https://threatfox.abuse.ch/
  - URLhaus (malicious URLs): https://urlhaus.abuse.ch/

Avoid building hard dependencies on licensed/closed feeds (e.g. VirusTotal) — the intel
pack format is designed around the open sources above.

## How the data flows once dropped in

- **Technique ids → game techniques.** An actor's `attacks:` uses the game's technique
  strings. The intel-pack importer maps real ATT&CK ids (e.g. `T1558.003`) to those
  strings automatically via the registry reverse lookup, keeping what the game can
  generate and noting the rest.
- **Hashes → answers.** A malware family's declared `hashes` become that family's file
  indicators and flow into `get_malicious_indicators()` as correct answers. Families that
  declare none keep getting random pool hashes, so existing scenarios are unchanged.
- **Provenance.** Each hash entry may be a mapping `{sha256, source, reference, first_seen,
  family}`; the provenance is preserved (available to the scenario guide / answer key) and
  is **required** by the intel-pack importer.

## Safety rules (non-negotiable)

- **Strings only — never binaries.** Hashes are inert identifiers used as quiz answers;
  they are never executed or downloaded. Do not commit real malware to this repo. Seed
  files stay EICAR.
- **Keep infrastructure inert.** Domains/IPs are **defanged** unless `ALLOW_REAL_INDICATORS`
  is on, and real C2 stays off unless `ALLOW_REAL_C2_INFRASTRUCTURE` is on (see `config.py`
  and `app/server/modules/safety/safety.py`). Prefer historical, sinkholed, or RFC 5737
  documentation ranges until you have confirmed an IOC is inert.
- **Validate before running.** Saving via Manage Scenario (or game start) runs the config
  validator: it rejects unknown keys and malformed hashes. The intel-pack importer
  additionally enforces provenance and runs the validator before writing.
