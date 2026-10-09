# Reviewer walkthrough (about 5 minutes)

QLure runs fake services (a web portal, a REST API, an SSH-like shell, and FTP, MySQL and Redis
banner listeners) and records what visitors do. Events are hash-chained, grouped into sessions,
scored by eleven readable rules (R1 to R11), and shown on a dashboard with their evidence.

**Safety promise.** Every planted secret is fake and listed in `decoys/honeytokens.yaml`. The
decoys execute nothing: the fake shell only records text, and database and Redis replies are fixed.
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

In a fifth terminal, send the 13 labelled steps, then score them:

```bash
python tools/demo_scenario.py        # --list shows the steps; --dry-run sends nothing
qlure forward --logs logs --db data/qlure.db
qlure correlate --db data/qlure.db
qlure verify --logs logs --db data/qlure.db
```

Restart the dashboard on this store (`QLURE_DB=data/qlure.db QLURE_LOGS=logs`) and reload Sessions.

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
   `198.51.100.77`, and Redis from `203.0.113.91`. "Honeytokens touched" reads 5.
2. **Honeytoken banner (top of Sessions, unfiltered).** It names the most recent planted secret
   used (`ht-redis-001`), the visitor, the actor, and links to the session.
3. **Session `198.51.100.77`, web, score 100.** The **Story** panel is one paragraph built only from
   this session's rule hits. Each rule card under "Why this session's own verdict" gives its
   threshold, a "Q-Lure saw" measured value and evidence event IDs. R7 names the planted database
   password `ht-db-001`. The timeline shows each raw event with its `prev` and `hash`. Then open
   **Evidence file (JSON)** and **Printable report**.
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
   afterwards. The **Dark mode** button in the top bar switches the theme.

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
- **Judge mode.** Read-only: no label changes, no data clearing, and only the judge switch itself
  can change. Every settings change is audited and can be rolled back.

## Tests and checks (measured 2026-10-09)

```bash
python -m pytest -q                                              # 442 passed, 2 xfailed
python -m pytest -q tests/correlate/test_attack_coverage.py -v   # 45 passed, 2 xfailed
ruff check . && ruff format --check .                            # all checks passed
qlure schema --check                                             # exit 0: schema is current
```

The two xfailed attack rows are known gaps, listed in [docs/ATTACK_COVERAGE.md](ATTACK_COVERAGE.md).
Planned work is in [docs/ROADMAP.md](ROADMAP.md).

## Honest limits

Read [docs/architecture/10-known-limits.md](architecture/10-known-limits.md) before quoting numbers:

- The seed is synthetic traffic from our own scripts. It shows the pipeline, not real-world accuracy.
- Recall is not proven: the first real tool run caught very few attack sessions.
- In the seed, the API session from `198.51.100.77` is a separate actor (Noteworthy, 60). It is not
  joined to that visitor's web and SSH actor (score 100). Sessions never link by IP alone.
- The credential stage appears only in the credential-stuffing actor, and R10 never fires in the seed.
- No learned model ships, and there is no held-out data from outside the team.
