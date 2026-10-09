# Reviewer walkthrough (about 5 minutes)

QLure runs fake services (a web portal, a REST API, an SSH-like shell, a fake Docker Engine API, and
FTP, MySQL and Redis banner listeners) and records what visitors do. Events are hash-chained,
grouped into sessions, scored by eleven readable rules (R1 to R11), and shown on a dashboard with
their evidence.

## What changed since the audit

- Dashboard: live feed on Sessions (Live indicator, correlation every 10 s), `/attack` ATT&CK
  matrix, SSH "Terminal replay" panel, dark and light toggle in the sidebar.
- Downloads: `/export` with CSV, STIX 2.1 and blocklist files; `?min=suspicious` adds Suspicious sessions.
- Ops: public `/healthz`, `/metrics` (login unless `QLURE_METRICS_PUBLIC=1`); `qlure export`, `qlure alert`, `qlure prune`.
- Decoys: fake Docker Engine API on port 2375 (service `docker`); R5 labels its container patterns. Seven services, still R1 to R11.
- Sample data: `tools/seed_demo.py` (10 sessions, 7 actors) and `tools/demo_scenario.py` (15 labelled steps, four attacker personas and one benign visitor).
- Open: the hosted snapshot is not rebuilt yet (P4.5). The live feed does not forward, so run the forwarder (`python tools/run_live.py` starts decoys, forwarder and dashboard in one command, localhost only).

**Safety promise.** Every planted secret is fake and listed in `decoys/honeytokens.yaml`. The
decoys execute nothing: the fake shell only records text, the Docker API only returns fixed JSON,
and database and Redis replies are fixed.
The demo sends traffic only to `127.0.0.1`, from documentation addresses (198.51.100.x, 203.0.113.x).
Docker publishes every port on `127.0.0.1` only. Started directly with Python, the web and API
servers listen on localhost; the SSH and banner listeners bind `0.0.0.0` unless you set
`QLURE_BIND_HOST=127.0.0.1` (or pass `--host 127.0.0.1`), as the commands below do.

## Fastest path (no Docker, sample data)

From the repository root, with Python 3.12 or later:

```bash
pip install -e '.[dev]'
python tools/seed_demo.py --db data/demo.db
QLURE_DB=data/demo.db QLURE_LOGS=data/demo-logs QLURE_DASHBOARD_PASSWORD=choose-a-strong-password \
  python -m uvicorn dashboard.app:app --port 9100
```

Open http://127.0.0.1:9100 and log in with your password. The seed generates the traffic in-process
(no network, no Docker), then forwards, correlates and verifies it. It refuses to replace an existing
`--db` unless you pass `--force`. In PowerShell, use `$env:NAME = "value"`.

## Live path (your own requests, local decoys)

Start the decoys in four terminals from the repository root. Events go to `logs/`.

```bash
python -m uvicorn decoys.web.app:app --host 127.0.0.1 --port 8080
python -m uvicorn decoys.api.app:app --host 127.0.0.1 --port 8081
QLURE_BIND_HOST=127.0.0.1 python -m decoys.ssh.server          # port 2222
QLURE_BIND_HOST=127.0.0.1 python -m decoys.banners.listeners   # ports 2121, 3306, 6379 (3306 and 6379 must be free)
python -m uvicorn decoys.dockerapi.app:app --host 127.0.0.1 --port 2375   # optional fake Docker API
```

In a fifth terminal, send the 15 labelled steps, then score them. Each persona (scanner,
credential stuffer, full chain, data store) sends from its own documentation address, and the
benign visitor sends from another, so the run shows several visitors rather than one. The
summary prints an expected verdict per persona from the rule weights alone; `qlure correlate`
has the final say.

```bash
python tools/demo_scenario.py        # --list shows the steps; --dry-run sends nothing
qlure forward --logs logs --db data/qlure.db
qlure correlate --db data/qlure.db
qlure verify --logs logs --db data/qlure.db
```

Restart the dashboard on this store (`QLURE_DB=data/qlure.db QLURE_LOGS=logs`) and reload Sessions.
The live feed re-scores the store every 10 seconds, but new lines only reach the store through
`qlure forward`, so keep running it (or `forward --follow`) while you demo.

## Docker path

```bash
mkdir -p logs data/ssh runtime
QLURE_DASHBOARD_PASSWORD=choose-a-strong-password docker compose up -d --build
python tools/demo_scenario.py --no-proxy-header
```

The dashboard is at http://127.0.0.1:9000 (a random password is printed in `docker compose logs
dashboard` if you leave it unset). The gateway adds the PROXY header, hence `--no-proxy-header`.
The `forwarder` container keeps `data/qlure.db` current; run `qlure correlate` and `qlure verify`
on the host (`sudo` if `logs/` is unreadable, as the README shows). On Windows the store sits in a
Docker volume, so use the dashboard there.

## Five-minute click-through (seeded data)

The seed produces 10 sessions for 7 actors: 4 Noteworthy, 4 Suspicious, 2 Benign. Session IDs and
times change on every run, so this list uses visitor address, service and score.

1. **Sessions (`/`).** The verdict bar reads 4 / 4 / 2. Rows show service and rule chips, plus
   ATT&CK technique chips. Four rows carry a **honeytoken** badge: web, SSH and API from
   `198.51.100.77`, and Redis from `203.0.113.91`. "Honeytokens touched" reads 5. The **Live**
   indicator above the list shows that the list refreshes itself.
2. **Honeytoken banner (top of Sessions, unfiltered).** It names the most recent planted secret
   used (`ht-redis-001`), the visitor, the actor, and links to the session.
3. **Session `198.51.100.77`, web, score 100.** The **Story** panel is one paragraph built only from
   this session's rule hits. Each rule card under "Why this session's own verdict" gives its
   threshold, a "Q-Lure saw" measured value and evidence event IDs. R7 names the planted database
   password `ht-db-001`. The timeline shows each raw event with its `prev` and `hash`. Then open
   **Evidence file (JSON)** and **Printable report**. The same visitor's SSH session (score 95)
   has a **Terminal replay** panel: eight commands in order, each with the decoy's own reply.
4. **Actors (`/actors`).** Open the actor of `198.51.100.77` (web and SSH, combined score 100). Its
   **Kill chain** strip shows Recon reached, Credential not reached, Misuse reached, each with a
   first-event time. No seeded actor reaches all three stages, so R10 does not fire. The actor of
   `203.0.113.44` (web, FTP and API sessions guessing the same password) is Suspicious at 45, with
   only Credential reached.
5. **Scanner (`/scanner`), optional.** Scan a public domain, then **Download PDF report**. This is
   the only PDF in the dashboard, and it needs internet access. Skip it offline.
6. **Settings (`/config`).** Only safe settings exist. The **Judge mode (read-only)** switch makes
   settings and data clearing read-only and disables the "Mark malicious" and "Mark benign"
   buttons on session pages. Every change appears in the change history. Turn judge mode back off
   afterwards. The **Dark mode** button at the bottom of the sidebar switches the theme.
7. **ATT&CK matrix (`/attack`).** Techniques by tactic. Seen techniques are highlighted and link to
   the highest-scoring session that shows them; unseen ones are dimmed and say so.
8. **Export (`/export`).** Three downloads from the same store: CSV, STIX 2.1 bundle and blocklist.
   By default only Noteworthy sessions are included, so the blocklist holds `198.51.100.77` and
   `203.0.113.91`. With **Include Suspicious sessions** (`?min=suspicious`), `198.51.100.23` and
   `203.0.113.44` are added.

## Why you can trust it

- **Hash-chained evidence.** `qlure verify --logs logs --db data/qlure.db` prints
  `chain verified: N events intact` when the store matches the JSONL archive. Editing one archived
  line prints `VERIFY FAILED at event <id>: JSONL line was edited after it was stored` and exits 1.
  Tests for edited and deleted lines are in `tests/store/`.
- **Explainable rules.** Each rule adds a fixed weight. Verdicts: 0 to 29 Benign, 30 to 59
  Suspicious, 60 or more Noteworthy only with two rule families or one high-confidence rule.
  R1 service sweep (20) · R2 path enumeration (25) · R3 brute force (30) · R4 default credentials
  (15) · R5 injection payload (40) · R6 scanner tool (15) · R7 honeytoken use (60) · R8 post-login
  discovery (35) · R9 sensitive file access (25) · R10 kill-chain progression (25) · R11 data-store
  abuse (30). Definitions and ATT&CK labels: [qlure_rules.md](../qlure_rules.md).
- **ML is a second opinion only.** The learned model (`qlure/ml/`) shows a score and its three
  biggest factors beside the rules, and never changes a verdict or score. No model ships, so the
  seeded dashboard says "no model trained".
- **Honeytokens.** Eight fake secrets, each value containing "decoy". Some are accepted by another
  decoy (the web `/.env` password, the backup file's SSH login, the shell's `~/.bash_history` API
  key), so one attacker's sessions can link. Any use is logged and scored by R7.
- **Judge mode.** Read-only for settings, labels and data clearing; only the judge switch itself
  can change. The background live pass pauses, but **Re-run correlation** still works, and
  downloads still work. Every settings change is audited and can be rolled back.

## Tests and checks (measured 2026-10-09)

```bash
python -m pytest -q                                              # 619 passed, 2 xfailed
python -m pytest -q tests/correlate/test_attack_coverage.py -v   # 48 passed, 2 xfailed
ruff check .                                                     # All checks passed
qlure schema --check                                             # exit 0: schema is current
```

The two xfailed attack rows are known gaps, listed in [docs/ATTACK_COVERAGE.md](ATTACK_COVERAGE.md).
Planned work and task status are in [docs/ROADMAP.md](ROADMAP.md).

## Honest limits

Read [docs/architecture/10-known-limits.md](architecture/10-known-limits.md) before quoting numbers:

- The seed is synthetic traffic from our own scripts. It shows the pipeline, not real-world accuracy.
- Recall is not proven: the first real tool run caught very few attack sessions.
- In the seed, the API session from `198.51.100.77` is a separate actor (Noteworthy, 60). It is not
  joined to that visitor's web and SSH actor (score 100). Sessions never link by IP alone.
- The credential stage appears only in the credential-stuffing actor, and R10 never fires in the seed.
- The live feed only correlates. New events reach the store through the forwarder.
- The canary honeytoken `ht-canary-001` raises no alert. The Docker API is a fixed fake: a
  container it "creates" cannot be listed or inspected.
- No learned model ships, and there is no held-out data from outside the team.
