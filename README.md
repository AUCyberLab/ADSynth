# ADSynth: A Tool to Synthesize Realistic Active Directory Attack Graphs

ADSynth generates synthetic Active Directory attack graphs based on set-to-set mapping, an intrinsic property of AD systems. It models the structure of AD graphs, security permissions, and common administration misconfigurations following design guidelines from Microsoft and other organizations, producing realistic graphs at security levels ranging from vulnerable to extremely secure.

ADSynth can generate classic on-premises AD, **hybrid identity environments** that include on-prem AD federated with Microsoft Entra ID (Azure AD). ADSynth also generates AD with non-human identities, AI agent identities, schema-validated invariants, and end-to-end reproducibility tooling.

See our [project website](https://aucyberlab.github.io/adsynthesizer/) for details and the underlying paper.

## Features

- **Classic on-prem AD generation** — users, groups, computers, OUs, GPOs, ACL-based permissions, tier-based placement, and configurable misconfigurations.
- **Azure / Entra ID generation** — tenants, subscriptions, management groups, roles, users, groups, service principals, applications, key vaults, and VMs with RBAC.
- **Hybrid AD + Entra synthesis** — multiple tenants per domain, per-link sync identities, and three sync modes (PHS, PTA, ADFS federation).
- **Non-human identities (NHIs)** — service principals, managed identities, automation accounts, and AI agents with hygiene priors (owner type, lifecycle, privilege bands).
- **Semantic invariant validation** — four schema-level invariants (I1–I4) automatically checked over the generated graph.
- **Reproducibility bundles** — config snapshot, 8-component seed vector, graph statistics, and SHA-256 manifest per run.
- **AI-driven parameter generation** — describe an organisation in natural language and have Azure OpenAI synthesise a full parameter set.
- **Multiple output formats** — Neo4j JSONL (importable via APOC) and BloodHound Community Edition OpenGraph zip.

## Requirements

- Python 3.8+
- Dependencies in `requirements.txt` (`tabulate`, `neo4j==4.4.10`)
- Optional: Neo4j 4.x with APOC for graph import; BloodHound CE for visualisation; Azure OpenAI credentials for `smartparams`.

## Installation

```
$ git clone https://github.com/AUCyberLab/ADSynth.git
$ cd ADSynth
$ pip install -r requirements.txt
```

## Quick Start

ADSynth provides **two entry points**:

| Entry point | Best for |
|---|---|
| `python -m adsynth` | Interactive exploration; classic / Azure-only / hybrid generation; importing into Neo4j. |
| `python run.py` | Reproducible batch runs of the hybrid pipeline with seed vectors and BloodHound export. |

### Interactive CLI

```
$ cd ADSynth
$ python -m adsynth
```

(From any other working directory: `PYTHONPATH=<YOUR-PATH>/ADSynth python -m adsynth`.)

This opens a `cmd` prompt. Typical session:

```
(Cmd) setparams adsynth/experiment_params/secure_1k.json
(Cmd) generate_hybrid_v2
(Cmd) exit
```

### Batch / scripted CLI

```
$ python run.py --seed 42 --output-dir generated_datasets --run-id my-run
```

Produces under `generated_datasets/my-run/`:

- `graph.jsonl` — Neo4j-format graph (one node/edge per line)
- `<run-id>_bloodhound.zip` — BloodHound CE import bundle
- `config.json`, `seed.json`, `graph_stats.json`, `manifest.json` — reproducibility bundle

Re-run an identical graph with `python run.py --seed-file generated_datasets/my-run/seed.json --config generated_datasets/my-run/config.json`.

## Interactive command reference

All commands of the `python -m adsynth` prompt:

### Configuration

| Command | What it does |
|---|---|
| `setdomain <FQDN>` | Set the AD domain (default `TESTLAB.LOCALE`). |
| `adconfig` | Choose a preset security level: `Low`, `High`, or `Customized` (recommended — uses parameters from `setparams`). |
| `setparams <path>` | Load a parameter JSON file. Template at `params_template.json`; parameter docs in `params_list.xlsx` or on the [website](https://aucyberlab.github.io/adsynthesizer/). Ten ready-made presets ship under `adsynth/experiment_params/` — see below. |
| `smartparams` | Generate a full parameter set from a natural-language org description via Azure OpenAI. Requires `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`, and `AZURE_OPENAI_DEPLOYMENT_NAME` in `.env`. Outputs to `adsynth/experiment_params/ai_generated_*.json`. |

### Graph generation

| Command | Generates |
|---|---|
| `generate` | Classic on-prem AD graph (users, groups, computers, OUs, GPOs, ACLs, sessions). |
| `generate_azure` | Azure-only / Entra-ID graph (tenants, subscriptions, roles, users, groups, service principals, key vaults, VMs, RBAC, misconfig edges). |
| `generate_hybrid` | Combined on-prem AD + Entra tenant with sync (v1 implementation). |
| `generate_hybrid_v2` | **Paper-aligned hybrid pipeline (recommended).** Seven phases: on-prem AD → multi-tenant Entra with posture / orgType → per-link `SyncIdentity` plus PHS / PTA / ADFS infrastructure → non-human identities (service principals, managed identities, automation accounts, AI agents) → `SYNCED_TO` user mappings → semantic invariant validation (I1–I4) → JSON export. |

### Neo4j integration

| Command | What it does |
|---|---|
| `neo4jconfig` | Configure Neo4j connection (URL, user, password, encryption). |
| `connect` | Test the configured connection. |
| `cleardb` | Wipe all nodes/edges from Neo4j in 10 000-row batches and reset schema constraints. |
| `importdb` | Import a generated JSON file into Neo4j via APOC. Requires APOC installed — see `docs/Neo4J_guides.pdf`. |

### Misc

| Command | What it does |
|---|---|
| `about` | Print version banner. |
| `help [topic]` | List commands or describe one. |
| `exit` | Quit. |

## Batch CLI (`run.py`)

The hybrid v2 pipeline as a non-interactive script with full reproducibility support.

```
python run.py [options]
  --config PATH         Hybrid configuration JSON (merged with defaults).
  --seed INT            Global seed (default: 42). Expanded into 8 sub-seeds.
  --seed-file PATH      Load a previously written seed.json (overrides --seed).
  --output-dir DIR      Output directory (default: generated_datasets).
  --run-id STR          Run identifier (default: run-YYYYMMDD-HHMMSS-<uuid6>).
  --no-validate         Skip semantic invariant checks.
  --registry-info       Print the schema registry summary and exit.
```

The 8-component seed vector covers domains, tenants, users, groups, NHIs, sync links, and misconfigurations independently, so each subgraph can be reseeded without disturbing the others. The `manifest.json` records SHA-256 digests of every artefact in the bundle.

## Parameter presets

Ten ready-made parameter sets ship under `adsynth/experiment_params/`:

| File | Purpose |
|---|---|
| `secure_{1k,5k,10k,50k,100k}.json` | High-LAPS, modern-OS, low-misconfig baselines at 1 k – 100 k users. |
| `vul_{1k,5k,10k,50k,100k}.json` | Low-LAPS, legacy-OS, high-misconfig baselines at 1 k – 100 k users. |
| `ai_generated_*.json` | Outputs from `smartparams`. |

> The current `secure_*` and `vul_*` presets are tuned for the on-prem pipeline (`generate`). The Azure and hybrid pipelines (`generate_azure`, `generate_hybrid`, `generate_hybrid_v2`) require parameter files that include the `AZRole`, `AZUser`, `AZGroup`, `AZSubscription`, `AZMisconfig`, etc. sections — use the built-in defaults, `smartparams`, or `params_template.json` as a starting point.

## Hybrid mode in detail

Hybrid mode models a federated identity environment in which one or more on-prem AD domains synchronise with one or more Microsoft Entra ID tenants. For every sync link the pipeline emits:

- a **`SyncIdentity`** node with `linkKey`, `syncMode`, `ownerType`, `lifecycle`;
- an **`EntraConnect`** (or `PTAAgent` or `ADFS`) **server** that hosts the sync agent;
- a **sync mode** drawn from the configured distribution: PHS (default 60 %), PTA (20 %), ADFS (10 %), Mixed (10 %);
- the corresponding edges: `SYNC_LINK`, `SERVICES_LINK`, `SYNCS_TO`, `RUNS_ON`, `HAS_PTA_AGENT`, `IS_FEDERATED_WITH`, and for PHS/Mixed, per-user `SYNCED_TO`.

Four semantic invariants (`adsynth/hybrid_system/invariant_validators.py`) are checked on every run:

- **I1** — every sync link has exactly one `SyncIdentity` running on an Entra Connect server.
- **I2** — every PTA link has a `PTAAgent` server linked by `HAS_PTA_AGENT`.
- **I3** — every ADFS link has an `ADFS` server linked by `IS_FEDERATED_WITH`.
- **I4** — every PHS / Mixed link emits `SYNCED_TO` user mappings.

Non-human identities are sized per tenant via `N_generic(t) = clamp(⌊0.14·U_t⌋, 6, 2500)` and split across service principals, managed identities, automation accounts, and AI agents.

## Output formats

### Neo4j JSONL (default)

One JSON object per line — a node or a relationship — matching the [Neo4j APOC export format](https://neo4j.com/labs/apoc/4.1/export/json/).

- **Node** — `{"id":"0","labels":["Base","User"],"properties":{…},"type":"node"}`. Ignore the `Base` label; the next label is the type.
- **Edge** — `{"type":"relationship","id":"r_258","label":"MemberOf","start":{"id":…,"labels":[…]},"end":{"id":…,"labels":[…]},"properties":{…}}`.

Import into Neo4j with APOC (see `docs/Neo4J_guides.pdf`) and visualise in [BloodHound](https://bloodhound.readthedocs.io/en/latest/).

### BloodHound CE OpenGraph zip

`run.py` automatically emits a BloodHound CE-compatible zip alongside the JSONL. To re-export an existing `graph.jsonl`:

```
python bloodhound_exporter.py --jsonl <path-to-graph.jsonl> \
                              --output-dir <out-dir> \
                              --run-id my-run
```

Upload the resulting `*_bloodhound.zip` via BloodHound CE → **Upload Files**.

## Testing

```
python tests/test_week2.py    # 48 tests — topology generators
python tests/test_week3.py    # 60 tests — principals, NHIs, invariants
```

Both suites include CLI end-to-end checks against `run.py` and exercise the deterministic-seed contract.

## Project layout

```
adsynth/
  ADSynth.py              Interactive CLI (MainMenu cmd loop)
  DATABASE.py             In-memory node/edge stores + RUN_ID / TENANT_METADATA
  adsynth_templates/      Default config + admin / permission / server templates
  azure_ad_system/        Entra ID entities (tenants, roles, users, SPs, …)
  default_ad_system/      Classic on-prem AD entities
  azure_ai/               smartparams Azure OpenAI integration
  generators/             Hybrid v2 generators (domain, tenant, sync_link, user, …)
  hybrid_system/          Hybrid schema registry, invariants, config, bundles
  synthesizer/            Phase-level synthesis (objects, sessions, misconfig, NHI, …)
  experiment_params/      Ready-made parameter presets (secure_*, vul_*, ai_*)
  helpers/, utils/        Names pools, parameter access, DN helpers, …
run.py                    Batch CLI for the hybrid v2 pipeline
bloodhound_exporter.py    Stand-alone BloodHound CE exporter
params_template.json      Parameter template for setparams
params_list.xlsx          Parameter documentation
docs/Neo4J_guides.pdf     Neo4j + APOC installation guide
tests/                    Test suites (test_week2.py, test_week3.py)
```

## Acknowledgements

We acknowledge prior work on AD synthesis from DBCreator, ADSimulator, Microsoft, and others. References are inlined at the top of the relevant files.
