# 9. Operations runbook

Everything here runs from the project folder, `D:\QLure` on Windows. Commands are for PowerShell
unless marked otherwise.

The hosted read-only demo on Render (sample data, no live decoys) is described in
[DEPLOY_RENDER.md](../DEPLOY_RENDER.md).

## First-time setup

Create the runtime folders (the compose file mounts them):

```bash
mkdir logs, data, runtime
```

## Start the decoys

```bash
docker compose up -d --build gateway web api ssh banners dockerapi
```

Check they are up:

```bash
docker compose ps -a
```

The `dashboard` and `forwarder` services can be started with the rest, but on Windows they hit a
bind-mount permission problem. Run the dashboard natively instead.

## Start the dashboard natively

Set a password first, then start uvicorn:

```bash
$env:QLURE_DASHBOARD_PASSWORD = "choose-a-strong-password"
```

```bash
python -m uvicorn dashboard.app:app --port 9100
```

Open http://127.0.0.1:9100 and log in.

## Keep the dashboard current

The dashboard reads the database, which needs filling from the logs. Run these, or a loop of them
every 10 seconds:

```bash
python -m qlure.cli forward --logs logs --db data/qlure.db
```

```bash
python -m qlure.cli correlate --db data/qlure.db
```

On a brand-new database, run them once, in that order, so the database and tables exist.

With the dashboard running, the live feed also re-runs correlation every 10 seconds (`QLURE_LIVE=0`
turns that off). It does not forward, so keep the forwarder running as well.

## Export, alerts and retention (manual)

```bash
python -m qlure.cli export --db data/qlure.db --format csv --out data/indicators.csv
python -m qlure.cli alert --db data/qlure.db --state data/alert-state.json --dry-run
python -m qlure.cli prune --db data/qlure.db --logs logs --older-than 30d --dry-run
```

`export` only reads the store and `alert --dry-run` sends nothing. `prune` is permanent: run it
with `--dry-run` first, then with `--yes`, and run `qlure verify` afterwards. Details are in
[EXPORT.md](../EXPORT.md), [ALERTS.md](../ALERTS.md) and [RETENTION.md](../RETENTION.md).

## Check the stack

| What | Command or place | Healthy looks like |
|---|---|---|
| Containers | `docker compose ps -a` | six decoy containers `Up`: gateway, web, api, ssh, banners, dockerapi |
| Web decoy | http://127.0.0.1:8080/login | HTTP 200 (this writes one event) |
| Dashboard | http://127.0.0.1:9100 | login page loads |
| Dashboard health | http://127.0.0.1:9100/healthz | JSON with `"status": "ok"` and `"db": "ok"`; no login needed |
| Forwarder | `python -m qlure.cli forward --logs logs --db data/qlure.db` | `stored N new events` |
| Correlation | `python -m qlure.cli correlate --db data/qlure.db` | session and actor counts |
| Hash chain | `python -m qlure.cli verify` (see the CLI help) | no mismatch reported; config audit line reports the chained changes |
| Egress watchdog | `docker compose logs egress-watch`, `data/egress.jsonl` | no lines while only visitors connect in; any alert means a decoy opened an outbound connection |
| Raw logs | `Get-ChildItem logs` | one `.jsonl` per service that has been visited |

## Generate test events

Every request below is real traffic against the decoys, so it is recorded. Run them only when you
want them counted.

Benign browsing:

```bash
curl.exe -s -o NUL -w "%{http_code}" http://127.0.0.1:8080/login
```

Planted-secret chain (reads the SSH password from the backup file, then uses the API key):

```bash
curl.exe -s http://127.0.0.1:8080/backup/config.bak
```

Injection pattern (rule R5, score 40):

```bash
curl.exe -s "http://127.0.0.1:8080/?id=1' OR '1'='1"
```

Sensitive file read (rule R9, score 25). Together with R5, this gives two families and a
Noteworthy verdict:

```bash
curl.exe -s http://127.0.0.1:8080/.env
```

Planted key used against the API (rule R7, score 60, high confidence, so Noteworthy by itself):

```bash
curl.exe -s -H "X-AWS-Access-Key: AKIAQLUREDECOY000001" http://127.0.0.1:8081/
```

Banner probe (MySQL greeting on port 3306, read and closed):

```bash
$c = New-Object System.Net.Sockets.TcpClient('127.0.0.1',3306); $s = $c.GetStream(); $b = New-Object byte[] 256; $s.Read($b,0,256) | Out-Null; $c.Close()
```

## Stop everything

Stop the dashboard and any refresh loop first, then:

```bash
docker compose down
```

Find the native processes with:

```bash
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'uvicorn dashboard.app|qlure.cli' }
```

## Clean start (keeps history safe)

Never delete runtime state. Move it instead, so it can be recovered:

```bash
$b = "backup-$(Get-Date -Format yyyyMMdd-HHmmss)"; New-Item -ItemType Directory $b; foreach ($d in 'logs','data','runtime') { Move-Item $d "$b\$d"; New-Item -ItemType Directory $d }
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Dashboard empty after traffic | forwarder or correlate not run since | run both commands again |
| Port 3306 or 6379 busy | a local MySQL or Redis is running | stop it, or change the published port |
| Dashboard port differs from the README | the README says 9000 (container); native run used 9100 | use the port you started |
| New event type not showing | rule weight or threshold unchanged | check `qlure/rules/rules.yaml` and the settings page |
| Banner events missing | the banners service may not write every probe | check `logs/` for a new file, then `correlate` |
