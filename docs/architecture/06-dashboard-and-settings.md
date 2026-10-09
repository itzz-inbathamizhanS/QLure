# 6. Dashboard and settings

The dashboard is where an operator reviews sessions and changes the few settings that are safe to
change. It is built with FastAPI and HTMX, so pages update without a full reload.

## How it runs

- A separate process (in Docker, the `dashboard` service) on port **9000** inside the container,
  published as `127.0.0.1:9000`. Running it natively, you choose the port (we used 9100).
- It is **not** on the decoy network. It cannot reach a decoy, and no decoy can reach it.
- It reads `logs/` and writes `data/` (the database and the settings file). The one exception is
  Clear All, which also empties the logs (see below).
- It has no control over Docker. Changes that need a restart are saved, but the operator restarts
  the decoys by hand.

## Login

`dashboard/auth.py` uses one shared admin password, set with `QLURE_DASHBOARD_PASSWORD`.

- If the variable is not set, a random password is generated at start-up and printed in the logs.
- Login sets a signed cookie (`qlure_admin`) that expires after **8 hours**.
- The password is compared with a constant-time check.

## Pages

| Page | Route | What it shows |
|---|---|---|
| Sessions list | `/` | Every session with its verdict, score, service, rule and ATT&CK chips. Filters and sorting. Live indicator. |
| Actors list | `/actors` | Actors, the sessions linked to each, and their combined verdict |
| Actor | `/actor/{id}` | One actor's sessions, shared honeytokens and passwords, rule hits and the kill-chain strip |
| Session | `/session/{id}` | Story, explanation, rule cards, evidence timeline with hashes, review labels. SSH sessions also show **Terminal replay** |
| ATT&CK matrix | `/attack` | Mapped techniques by tactic, with rule-hit and session counts. A seen technique links to its highest-scoring session |
| Evidence export | `/session/{id}/evidence.json` | JSON of the session's events, with the hash-chain check result |
| Printable report | `/session/{id}/report` | A print-ready page for the same session |
| Indicator export | `/export` | Download page for the IOC files, with `?min=suspicious` for Suspicious sessions too |
| Indicator downloads | `/export.csv`, `/export.json`, `/export.txt` | CSV, STIX 2.1 and blocklist downloads. Login required; allowed in judge mode. See [EXPORT.md](../EXPORT.md) |
| Scanner | `/scanner` | Domain TLS and post-quantum check (standard scan), with PDF report |
| Settings | `/config` | Approved ports, fake content, rule weights, thresholds, allowlist, retention |
| Refresh | `/refresh` (POST) | Re-reads the database so new findings appear (**Re-run correlation**) |
| Review label | `/session/{id}/label` (POST) | The operator marks a session malicious or benign, and marks evidence |
| Health | `/healthz` | Public JSON: status, store check, event and session counts, last stored event time, live state, version. Counts and times only, no paths |
| Metrics | `/metrics` | Prometheus text (gauges for events, sessions by verdict, actors, honeytoken hits, last live pass). Login required unless `QLURE_METRICS_PUBLIC=1` |

The sessions list also has the **PQC chart** (share of SSH sessions offering a post-quantum key
exchange, split by verdict). See [page 8](08-extras-pqc-and-ml.md). `/healthz` answers 503 when the
store cannot be read; `/metrics` answers 503 in the same case.

### Public metrics (`QLURE_METRICS_PUBLIC=1`)

By default `/metrics` needs the admin login. With `QLURE_METRICS_PUBLIC=1` the guard in
`dashboard/app.py` skips the login for `/metrics` only, so anyone who can reach the port can read
it. The response holds counts and times only: event, session (by verdict), actor and honeytoken-hit
totals, and the time of the last live pass. It has no IP addresses, payloads or secrets (see
`metrics_text` in `dashboard/data.py`).

- Keep `QLURE_METRICS_PUBLIC` unset unless the dashboard is bound to localhost or a trusted scrape
  network.
- **Never expose it to the internet.**
- `/healthz` is public by design and needs no variable. It also holds only counts, times and the
  version.

## Live feed

With `QLURE_LIVE` unset or not `0`, the dashboard runs one correlation pass every
`QLURE_LIVE_INTERVAL` seconds (default 10, never less than 2) in a background task. The sessions
list asks for its rows every 5 seconds, so a new finding appears within about 15 seconds of its
events reaching the store. The indicator above the list says:

- **Live** with the time of the last finished pass (UTC);
- **first pass not run yet**, or **the last pass failed, see the server log**;
- **correlation paused in judge mode, new rows still appear** in judge mode;
- **Auto-update is off (`QLURE_LIVE=0`)** when the loop is disabled.

The live feed only correlates. It never reads the JSONL logs, so the forwarder must keep the store
current (the `forwarder` service in Docker, or `qlure forward` natively). A pass and a manual
**Re-run correlation** never overlap.

## Theme

The sidebar has a **Dark mode** / **Light mode** button. The choice is saved in the browser's local
storage under `qlure-theme`. Without a saved choice, the page follows the system setting.

## Settings: what may change

`qlure/settings.py` defines what the settings page accepts. Only these can change:

| Area | Examples | Notes |
|---|---|---|
| Fake content | company name, FTP banner | Written to `runtime/content.json`, read read-only by the web and banner decoys |
| Rule tuning | weights per rule, suspicious and noteworthy thresholds | Applies at once on the next correlation |
| Allowlist | up to 50 IPs and 50 User-Agents | Gives a −100 suppressor, so use with care |
| Retention | 0 to 365 days (0 = no stated policy) | Saved and audited. Informational only: nothing deletes data because of it. Old data is removed by hand with `qlure prune` ([RETENTION.md](../RETENTION.md)) |
| Decoy ports and enable flags | which decoys are on (`enabled`, `port`) | Saved and audited, but needs a manual restart |
| Alerts | `alerts.webhook_url`, `alerts.min_verdict` | Not on the page. Read by `qlure alert` only; the URL is masked in the audit trail and cannot be rolled back ([ALERTS.md](../ALERTS.md)) |

Validation rejects anything else. Each rule-tuning value has a range (for example thresholds
from 1 to 99 and 2 to 100), and the suspicious threshold must stay below the noteworthy one.

**Never settable from the dashboard:** outbound network, command execution, executable uploads,
host folders, or the Docker configuration.

### Audit and undo

Every change, accepted or refused, is written to `config_audit` with a timestamp and the values
before and after. `/config/rollback/{audit_id}` restores an earlier state. Nothing is silently lost.

### Judge mode

A read-only mode for when someone else is reviewing the work. While it is on, settings cannot be
changed (except the judge mode switch itself), labels cannot be saved, and Clear All is refused.
The background live pass is skipped, and the indicator says so. **Re-run correlation** still
works, and the downloads still work, because they only read the store. It is a UI mode, not a
lock: the same admin can switch it off on the settings page.

## What the dashboard can change

The dashboard cannot edit an event in place: no code path updates a stored event, and an edit to
a kept row breaks the hash chain (see [page 4](04-storage-and-integrity.md)).

Clear All is the exception. It deletes every row in `events`, `sessions`, `actors`, `findings`,
`forwarder_state`, `labels` and `checkpoints`, and it empties the JSONL logs. It is refused in
judge mode and always audited. After a clear, `verify` passes with 0 events, because there is no
history left to check. Clearing is a deliberate wipe, not a hidden rewrite, but it does mean the
dashboard's admin can destroy the evidence it holds.
