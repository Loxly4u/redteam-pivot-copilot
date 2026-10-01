# Red Team Pivot Copilot (Lab-Only, Human-in-the-Loop)

A reasoning copilot for red team lateral-movement planning. It analyzes a
provided engagement state (hosts, services, credentials already discovered
through your own authorized tooling) and suggests advisory next steps,
mapped to MITRE ATT&CK technique IDs — for a human operator to review and
decide on.

## Scope & safety

**This tool does not scan, connect to, exploit, or otherwise interact with
any real network or host.** It is a pure reasoning/decision-support layer
over data you provide. Specifically:

- No network sockets are opened. No exploit code is included or executed.
- Input is a static JSON file describing engagement state — not a live feed
  from a scanner.
- Every suggestion is advisory text with a rationale and MITRE ATT&CK
  mapping. Nothing is auto-executed.
- The `--interactive` approval flow only **records your decision** (approved
  / rejected + optional note) to a log file. "Approved" means *you* will
  carry out that step manually, outside this tool, using tools you're
  authorized to use.

**Only use this against systems and in engagements you own or have
explicit written authorization to test.** This is a portfolio/demonstration
project illustrating a human-in-the-loop AI-assisted red team workflow
pattern, not a production offensive tool.

## Why

Fully autonomous "AI red team agents" that chain recon → exploit →
lateral movement without human review are a real safety concern — they can
cause unintended damage, violate scope agreements, or behave unpredictably
against production systems. This project demonstrates the alternative
pattern: **AI as co-pilot, human as the only one who can act**. The AI
reasons over discovered state and explains *why* a step might be relevant;
a human operator decides whether to actually do it, and does so themselves.

## Architecture

```
engagement.json (hosts, services, credentials, reachability)
        │
        ▼
┌───────────────────┐
│  graph.py          │  Loads engagement state into a NetworkGraph model
└───────────────────┘
        │
        ▼
┌───────────────────┐
│  suggestions.py     │  Reasons over graph state -> advisory Suggestions
└───────────────────┘      (MITRE ATT&CK technique ID + rationale + risk)
        │
        ▼
┌───────────────────┐
│  cli.py             │  Lists suggestions; --interactive gates each one
└───────────────────┘      behind an explicit human approve/reject prompt
        │
        ▼
┌───────────────────┐
│  engagement_log.py  │  Records approve/reject decisions (never executes)
└───────────────────┘
```

## Setup

Requires Python 3.9+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Usage

List advisory suggestions for the included sample lab engagement:

```bash
pivot-copilot suggest --input sample_data/engagement.json
```

Review and approve/reject each suggestion interactively:

```bash
pivot-copilot suggest --input sample_data/engagement.json --interactive --log-output decisions.json
```

Get machine-readable output:

```bash
pivot-copilot suggest --input sample_data/engagement.json --json-only
```

## Input format

The engagement JSON describes what you've already discovered in your lab
(see `sample_data/engagement.json` for a full example):

```json
{
  "hosts": [
    {
      "hostname": "fileserver-01",
      "ip": "10.10.2.10",
      "os": "Windows Server 2019",
      "compromised": false,
      "tags": ["internal"],
      "services": [
        {"name": "smb", "port": 445, "version": "SMBv1", "vulnerable": true, "notes": "..."}
      ]
    }
  ],
  "credentials": [
    {"username": "svc_backup", "cred_type": "password", "value_ref": "label-only, never a real secret",
     "source_host": "ext-web-01", "privilege": "user"}
  ],
  "edges": [{"from": "ext-web-01", "to": "fileserver-01"}]
}
```

`edges` describe network reachability discovered so far (which compromised
host can reach which other host) — the engine only suggests steps against
hosts reachable from an already-compromised host, reflecting realistic
lateral movement constraints. If no edges are given, all uncompromised
hosts are considered reachable (flat lab network).

`value_ref` is a label/reference only — never put real secrets in this
file; it exists purely to describe engagement state for reasoning purposes.

## Suggestion logic

The engine currently reasons about:

- **Vulnerable services** (`vulnerable: true`) → `T1210` Exploitation of Remote Services
- **Credential reuse** against SMB/RDP/SSH → `T1021.00x` Remote Services
- **Domain controller tags** → `T1018` Remote System Discovery (prioritization nudge)

Suggestions are sorted by risk (high → low) so the most actionable items
surface first.

## Testing

```bash
pytest -v
```

24 unit tests cover the graph model, suggestion generation logic, the
engagement decision log, and the CLI (including the interactive approval
flow and a regression guard ensuring output never claims to execute
anything).

## Project structure

```
redteam-pivot-copilot/
├── src/pivot_copilot/
│   ├── graph.py            # Engagement state model (hosts/services/creds)
│   ├── suggestions.py      # Advisory suggestion/reasoning engine
│   ├── engagement_log.py   # Human approve/reject decision log
│   └── cli.py              # CLI with human-in-the-loop approval gate
├── tests/
├── sample_data/engagement.json
├── requirements.txt
└── pyproject.toml
```

## License

MIT
