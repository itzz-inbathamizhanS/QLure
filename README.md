# Q-Lure

Decoy services and defensive threat observation, with post-quantum evidence protection.
Team IRAVORA VOID · Horizon 2K26 · Track 02, Problem C01.

Q-Lure runs fake but harmless services, records everything visitors do as structured
events, groups the events into sessions, scores each session with readable rules, and
shows the investigator why a session was flagged.

## Status

Phases 0 to 4 are in place:

- Event schema in `qlure/events/` (Pydantic), exported to `docs/event.schema.json`, and `emit(event)`,
  the one helper every decoy uses to validate and append events to `logs/<service>.jsonl`.
- Five decoys, all behind one nginx gateway on an `internal: true` network:
  web portal (8080), REST API (8081), SSH-like server with a fake shell (2222),
  and FTP / MySQL / Redis listeners (2121, 3306, 6379).
- Honeytokens (`decoys/honeytokens.yaml`) planted in one decoy and accepted in another:
  `/backup/config.bak` on the web portal gives the SSH password, the SSH shell's
  `~/.bash_history` gives the API key, and the API logs its use.
- A forwarder tails the JSONL files into SQLite (`data/qlure.db`, WAL mode) and chains every event
  by SHA-256. `qlure verify` checks the chain against the JSONL archive and fails at the first
  edited, deleted or removed event.
- A correlation engine (`qlure correlate`) groups events into sessions and actors, applies the ten
  rules in `qlure/rules/rules.yaml`, scores each session and writes a plain-language explanation
  that names every rule, its threshold, the measured value and the evidence events. Verdicts follow
  the design doc: 0 to 29 Benign, 30 to 59 Suspicious, 60 and over Noteworthy only with two rule
  families or one high-confidence rule. An IP address alone never links sessions; raw TCP banner
  sessions, which have no client fingerprint, are the one exception (same IP within 30 minutes).
- Decoys cannot reach the internet, run read-only as a non-root user, and publish ports on
  127.0.0.1 only.

- A dashboard on `http://127.0.0.1:9000` (`dashboard/`): sessions list with filters and sorting,
  a session page with the explanation, rule cards, an evidence timeline (raw events and hashes),
  review labels, a JSON evidence export that carries the hash-chain check, and a printable report.
  A settings page (`qlure/settings.py`) allows only safe changes: approved ports, fake content,
  scoring weights and an allowlist. Every change, accepted or refused, is audited and can be undone.
  There is no setting for outbound network, command execution, executable uploads or host folders.
  Judge mode makes everything read-only. Port and content settings are saved and audited but are
  not yet pushed into running decoys; rule weights, thresholds and the allowlist apply at once.

Next phases: evaluation on real captures (5), post-quantum extra (6).

## Run it

With Docker:

```sh
docker compose up -d --build
curl -i http://localhost:8080/login
curl http://localhost:8080/backup/config.bak        # the planted SSH login
ssh -p 2222 deploy@localhost                        # use the password from that file
curl -H "X-API-Key: <key from ~/.bash_history>" http://localhost:8081/api/v1/users
cat logs/*.jsonl
qlure verify                                        # forwarder keeps data/qlure.db up to date
qlure correlate                                     # scored sessions, most suspicious first
```

Open `http://127.0.0.1:9000` for the dashboard. Set the password with `QLURE_DASHBOARD_PASSWORD`
before `docker compose up`; if you do not, a random one is printed in `docker compose logs dashboard`.
The dashboard is not on the decoy network, reads the logs read-only and writes only `data/`.

Ports 3306 and 6379 must be free on your machine (stop a local MySQL or Redis first).

Without Docker (Python 3.12), run any one decoy:

```sh
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
uvicorn decoys.web.app:app --port 8080
uvicorn decoys.api.app:app --port 8081
```

The SSH and banner decoys expect the gateway's PROXY header, so run those through Docker.

Events land in `logs/web.jsonl` (set `QLURE_LOG_DIR` to change the folder). Check any log file
against the schema with:

```sh
qlure validate logs/*.jsonl
```

## Develop

```sh
pytest -q                 # tests
ruff check . && ruff format --check .
qlure schema              # re-export docs/event.schema.json after changing the schema
```

The event schema is the shared contract: fields are only ever added, never renamed.

## Layout

```
docker-compose.yml   all services, networks and limits
gateway/             nginx: the only container with a route to the decoys (HTTP and raw TCP)
decoys/              web, api, ssh, banners, fakefs, honeytokens.yaml   (Inbathamizhan S)
qlure/events/        event schema + emit()                              (all, Prasanna Kumar Reddy)
qlure/store/         forwarder, SQLite store, hash chain                (Prasanna Kumar Reddy)
qlure/correlate/     sessions, actors, rules, scoring, explanations     (Bharadhwaj M)
qlure/rules/         rules R1 to R10 in YAML                            (Bharadhwaj M)
qlure/pqc/           ML-DSA signing, SSH KEX fingerprint (extra)
qlure/cli.py         qlure schema | validate | forward | verify | correlate (capture, replay, eval to come)
dashboard/           session view and settings dashboard, FastAPI + HTMX (Prasanna Kumar Reddy)
captures/            real captured sessions: tuning/ and heldout/
tests/               pytest, one folder per module
docs/                event schema and design notes
```

## Safety

- Emulate, never execute: no `exec`, `eval`, `subprocess` or real database in `decoys/`.
- Decoy containers are read-only, non-root, drop all capabilities and sit on an `internal: true`
  network with no internet access.
- No real secrets anywhere. Every planted value is listed in `decoys/honeytokens.yaml` and is fake.
- Logs and raw captures hold visitor IPs and typed text, so they stay out of git.
- Evaluation uses only real interactions captured against our own decoys, never simulated datasets.
