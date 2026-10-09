# Run QLure on a Windows PC

A step-by-step guide for running QLure locally. Everything stays on your own computer: the decoys
listen on `127.0.0.1` only, and all data is fake. Pick **one** path:

| Path | Needs | Time | Shows |
|---|---|---|---|
| **A. Sample data** (recommended first) | Python | 3 min | The dashboard filled with sample attacks |
| **B. Live, no Docker** | Python, 6 terminals | 10 min | Your own requests hitting the decoys |
| **C. Docker** | Docker Desktop | 10 min | The full stack with the nginx gateway |

## 0. One-time setup

1. Install **Python 3.12 or newer** from https://www.python.org/downloads/ . Tick
   **"Add python.exe to PATH"** in the installer. Check with `python --version`.
2. Install **Git** from https://git-scm.com/download/win .
3. Open **Command Prompt** (not PowerShell, to keep the commands below simple) and get the code:

```
cd /d D:\
git clone https://github.com/itzz-inbathamizhanS/QLure.git
cd QLure
```

   Already cloned? Update it instead: `cd /d D:\QLure` then `git pull`.

4. Create a private Python environment and install QLure:

```
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -e ".[decoys,dashboard]"
```

   Use exactly `.[decoys,dashboard]`. Do **not** use `.[dev]` on Windows: it also installs the
   optional post-quantum library (`liboqs-python`), which has to compile a native library and often
   fails on Windows. QLure works without it. If you want to run the tests, add
   `pip install "pytest>=9.0.3,<10" ruff`.

5. Every new Command Prompt window needs `.venv\Scripts\activate` again (the prompt shows `(.venv)`).

## Path A: sample data (fastest)

```
python tools\seed_demo.py --db data\demo.db
set QLURE_DB=data\demo.db
set QLURE_LOGS=data\demo-logs
set QLURE_DASHBOARD_PASSWORD=choose-a-password
python -m uvicorn dashboard.app:app --host 127.0.0.1 --port 9100
```

Open http://127.0.0.1:9100 and log in with the password you chose. If you leave
`QLURE_DASHBOARD_PASSWORD` unset, the dashboard prints a random one in the window.

The seed creates 100 events in 10 sessions across 7 fake actors (4 Noteworthy, 4 Suspicious,
2 Benign) and prints `chain verified: 100 events`. Re-running it needs `--force`.

Stop it with **Ctrl+C**.

## Path B: live, without Docker

Open **six** Command Prompt windows, each in `D:\QLure` with `.venv\Scripts\activate` first.

| Window | Command |
|---|---|
| 1 web decoy | `python -m uvicorn decoys.web.app:app --host 127.0.0.1 --port 8080` |
| 2 API decoy | `python -m uvicorn decoys.api.app:app --host 127.0.0.1 --port 8081` |
| 3 SSH decoy | `set QLURE_BIND_HOST=127.0.0.1` then `python -m decoys.ssh.server` (port 2222) |
| 4 FTP, MySQL, Redis | `set QLURE_BIND_HOST=127.0.0.1` then `python -m decoys.banners.listeners` (ports 2121, 3306, 6379) |
| 5 fake Docker API (optional) | `python -m uvicorn decoys.dockerapi.app:app --host 127.0.0.1 --port 2375` |
| 6 your work window | the steps below |

Ports 3306 and 6379 must be free. If you run a real MySQL or Redis, stop it first or skip window 4.
Windows may show a firewall prompt: choose **Cancel / do not allow**, everything is localhost.

In window 6, send the 13 labelled attack steps, then score and check them:

```
python tools\demo_scenario.py
python -m qlure.cli forward --logs logs --db data\qlure.db
python -m qlure.cli correlate --db data\qlure.db
python -m qlure.cli verify --logs logs --db data\qlure.db
```

`python tools\demo_scenario.py --list` shows the steps; `--dry-run` sends nothing.

Then start the dashboard on this data (in window 6, or a seventh window):

```
set QLURE_DB=data\qlure.db
set QLURE_LOGS=logs
set QLURE_DASHBOARD_PASSWORD=choose-a-password
python -m uvicorn dashboard.app:app --host 127.0.0.1 --port 9100
```

The live feed re-scores the store every 10 seconds, but new log lines only reach the store through
`forward`. For a live demo, run this in another window and leave it running:

```
python -m qlure.cli forward --logs logs --db data\qlure.db --follow
```

Stop everything with **Ctrl+C** in each window.

## Path C: Docker

Start **Docker Desktop** first and wait until it says it is running.

```
copy .env.example .env
```

Edit `.env` and set `QLURE_DASHBOARD_PASSWORD=choose-a-password` and a long random
`QLURE_DASHBOARD_SECRET`. Then:

```
docker compose up -d --build
```

The dashboard is at http://127.0.0.1:9000 . The decoys are published on `127.0.0.1` ports 8080,
8081, 2121, 2222, 3306, 6379 and 2375. Send the demo traffic through the gateway (it adds the
header itself, so tell the script not to):

```
python tools\demo_scenario.py --no-proxy-header
```

Check the containers with `docker compose ps` and logs with `docker compose logs -f dashboard`.
On Windows the override file `docker-compose.override.yml` is picked up automatically: it keeps the
database in a Docker volume because SQLite cannot run on a Windows bind mount.

Stop and remove everything:

```
docker compose down
```

Add `-v` only if you also want to delete the saved data.

## What to look at (5 minutes)

Log in, then open:

| Page | What to see |
|---|---|
| `/` Sessions | Verdicts, ATT&CK chips, honeytoken badge, the Live indicator |
| a Noteworthy session | The written Story, rule cards with evidence, SSH Terminal replay |
| `/actors` and an actor | The recon, credential, misuse strip |
| `/attack` | ATT&CK matrix of the techniques seen |
| `/export` | Download CSV, STIX or a blocklist |
| `/config` | Settings; the light/dark toggle is in the sidebar |
| `/healthz` | Public health JSON (no login) |

More detail is in `docs/REVIEWER.md`.

## Useful commands

```
python -m qlure.cli verify --logs logs --db data\qlure.db        # check the evidence chain
python -m qlure.cli export --db data\qlure.db --format csv       # also: stix, blocklist
python -m qlure.cli alert --db data\qlure.db --dry-run           # webhook alerts, prints only
python -m qlure.cli prune --db data\qlure.db --logs logs --older-than 30d --dry-run
python -m pytest -q                                              # needs the test tools above
```

## Troubleshooting

| Problem | Fix |
|---|---|
| `python` is not recognised | Reinstall Python and tick "Add to PATH", then open a new window |
| `pip install` fails building `liboqs` | You used `.[dev]`; use `pip install -e ".[decoys,dashboard]"` |
| `Address already in use` / port busy | `netstat -ano \| findstr LISTENING \| findstr ":8080"` shows the PID; `taskkill /PID <number> /F`. If the owner is Docker Desktop, run `docker compose down` instead of killing it |
| `.venv\Scripts\activate` blocked in PowerShell | Use Command Prompt, or run `Set-ExecutionPolicy -Scope Process Bypass` first |
| Dashboard login rejected | The password is the value of `QLURE_DASHBOARD_PASSWORD` set in that same window before starting |
| Dashboard shows "No data yet" | Run Path A's seed, or run `forward` and `correlate` after sending traffic |
| `qlure` command not found | Use `python -m qlure.cli ...` as in this guide, with the environment activated |
| Everything looks stale after `git pull` | Run `pip install -e ".[decoys,dashboard]"` again |

## Clean up

Close the windows (or Ctrl+C), run `docker compose down` if you used Docker, then check nothing is
left listening:

```
netstat -ano | findstr LISTENING | findstr ":9000 :9100 :8080 :8081 :2222 :2121 :3306 :6379 :2375"
```

It should print nothing.
