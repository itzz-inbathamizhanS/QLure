# 6. Dashboard and settings

The dashboard is where an operator reviews sessions and changes the few settings that are safe to
change. It is built with FastAPI and HTMX, so pages update without a full reload.

## How it runs

- A separate process (in Docker, the `dashboard` service) on port **9000** inside the container,
  published as `127.0.0.1:9000`. Running it natively, you choose the port (we used 9100).
- It is **not** on the decoy network. It cannot reach a decoy, and no decoy can reach it.
- It reads `logs/` read-only and writes only `data/` (the database and the settings file).
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
| Sessions list | `/` | Every session with its verdict, score and service. Filters and sorting. |
| Actors list | `/actors` | Actors, the sessions linked to each, and their combined verdict |
| Actor | `/actor/{id}` | One actor's sessions, shared honeytokens and passwords, and rule hits |
| Session | `/session/{id}` | The explanation, rule cards, evidence timeline with hashes, review labels |
| Evidence export | `/session/{id}/evidence.json` | JSON of the session's events, with the hash-chain check result |
| Printable report | `/session/{id}/report` | A print-ready page for the same session |
| Settings | `/config` | Approved ports, fake content, rule weights, thresholds, allowlist, retention |
| Refresh | `/refresh` (POST) | Re-reads the database so new findings appear |
| Review label | `/session/{id}/label` (POST) | The operator marks a session malicious or benign, and marks evidence |

The sessions list also has the **PQC chart** (share of SSH sessions offering a post-quantum key
exchange, split by verdict). See [page 8](08-extras-pqc-and-ml.md).

## Settings: what may change

`qlure/settings.py` defines what the settings page accepts. Only these can change:

| Area | Examples | Notes |
|---|---|---|
| Fake content | company name, FTP banner | Written to `runtime/content.json`, read read-only by the web and banner decoys |
| Rule tuning | weights per rule, suspicious and noteworthy thresholds | Applies at once on the next correlation |
| Allowlist | up to 50 IPs and 50 User-Agents | Gives a −100 suppressor, so use with care |
| Retention | 1 to 365 days | Saved and audited. No code currently deletes old data based on it, so treat it as a stated policy only |
| Decoy ports and enable flags | which decoys are on | Saved and audited, but needs a manual restart |

Validation rejects anything else. Each rule-tuning value has a range (for example thresholds
from 1 to 99 and 2 to 100), and the suspicious threshold must stay below the noteworthy one.

**Never settable from the dashboard:** outbound network, command execution, executable uploads,
host folders, or the Docker configuration.

### Audit and undo

Every change, accepted or refused, is written to `config_audit` with a timestamp and the values
before and after. `/config/rollback/{audit_id}` restores an earlier state. Nothing is silently lost.

### Judge mode

A read-only mode. Everything is visible, nothing can be changed. Use it when someone else is
reviewing the work.

## Why it is read-only where it is

The dashboard reads logs and writes only to `data/`. A compromised dashboard therefore cannot
rewrite the evidence, because the hash chain (see [page 4](04-storage-and-integrity.md)) would
show it.
