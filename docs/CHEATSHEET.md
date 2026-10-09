# Q-Lure Commands & Operations Cheat Sheet

This document contains the essential PowerShell and Docker commands used to build, test, run, and manage the Q-Lure system.

---

## 1. Docker & System Management
*These commands manage the entire decoy infrastructure and the dashboard.*

**Start the System (Detached Mode):**
```powershell
docker compose -p qlure-live up -d
```
*Starts the decoys (gateway, web, api, ssh, banners, dockerapi), the egress watchers, the forwarder and the dashboard in the background.*

**Stop the System:**
```powershell
docker compose -p qlure-live down
```
*Safely shuts down all containers and networks.*

**Force Rebuild a Specific Container (e.g., Dashboard):**
```powershell
docker compose -p qlure-live up -d --build dashboard
```
*Use this if you make changes to the Python code or HTML templates and need to update the running container.*

**View Live Logs for a Container:**
```powershell
docker logs -f qlure-live-forwarder-1
```
*Streams the live background logs. Replace `forwarder` with `web`, `api`, `dashboard` or `dockerapi` to see other services.*

**Check the decoys and the dashboard:**
```powershell
docker compose -p qlure-live ps -a
curl.exe -s http://127.0.0.1:9000/healthz
```
*`/healthz` is public and returns JSON (`status`, `db`, event and session counts, `live`). Use `http://127.0.0.1:9100` for a native dashboard. `/metrics` needs a login unless `QLURE_METRICS_PUBLIC=1`, which makes it readable by anyone who can reach the port. Use it only on localhost or a trusted scrape network, never on the internet.*

---

## 2. Running the Live Attacks (PowerShell)
*This is the script used to simulate a real hacker attacking the decoys.*

**Launch the Attack Interface:**
```powershell
powershell -ExecutionPolicy Bypass -File tools\demo-attack.ps1
```
*This opens the interactive attack menu.*

**Key Attack Scenarios in the Script:**
- `1` **Recon scan:** Fires multiple `curl` commands at hidden paths (e.g., `/.env`, `/wp-admin/`) to trigger **R2 (Path Enumeration)**.
- `2` **Brute-force login:** Rapidly POSTs multiple fake passwords to `/login` to trigger **R3 (Brute Force)**.
- `3` **Find the leaked file:** Reads `/backup/config.bak` to trigger **R9 (Sensitive file access)** and capture the planted SSH password for option `4`.
- `4` **Use stolen SSH creds:** Logs in to the SSH decoy with the planted password (**R7, honeytoken use**).
- `5` **Use stolen API key:** Calls the API with the planted key (**R7**).
- `7` **SQL injection probe:** An injection pattern on the web page (**R5**).
- `8` **Path Traversal:** Requests `/download?file=../../../../etc/passwd` (answered from the fake file tree only).
- `9` **Scanner user agent:** The same page with a scanner's browser string (**R6**).
- `11` **FTP banner probe:** FTP login attempts on the FTP decoy.
- `12` **Database probes:** MySQL and Redis ports.
- `A` **Run All Automated:** Runs steps 1, 2, 3, 7, 8, 9, 11 and 12 in one go without prompting.

**Labelled harmless steps (Python, loopback only):**
```powershell
python tools/demo_scenario.py --list
python tools/demo_scenario.py --dry-run
python tools/demo_scenario.py
```
*Thirteen fixed steps against `127.0.0.1`. `--list` shows them, `--dry-run` sends nothing, and any non-loopback `--target` is refused. Add `--no-proxy-header` when the gateway is in front (Docker).*

---

## 3. Wiping Data (The "Clean Slate")
*If you need to manually wipe the database and logs via the terminal instead of the UI button.*

**Delete the SQLite Database inside the container:**
```powershell
docker exec qlure-live-dashboard-1 rm -f /var/lib/qlure/qlure.db /var/lib/qlure/qlure.db-shm /var/lib/qlure/qlure.db-wal
```

**Clear all Raw JSON Event Logs from the Host:**
```powershell
Get-ChildItem -Path "logs\*.jsonl" | ForEach-Object { Set-Content $_.FullName $null }
```
*(This safely empties the log files without deleting the files themselves, keeping Docker volume mounts intact).*

**Restart the stack to generate fresh tables:**
```powershell
docker compose -p qlure-live restart
```

**Remove only old events, the safe way:**
```powershell
python -m qlure.cli prune --db data/qlure.db --logs logs --older-than 30d --dry-run
python -m qlure.cli prune --db data/qlure.db --logs logs --older-than 30d --yes
python -m qlure.cli verify --logs logs --db data/qlure.db
```
*`prune` is permanent and needs `--yes`. It leaves a retention anchor, so `verify` still passes. See [RETENTION.md](RETENTION.md).*

---

## 4. Python Backend (Correlations, Rules and Exports)
*Commands to test the Python logic locally (requires the Python environment: `pip install -e '.[dev]'`).*

**Move events into the store and score them:**
```powershell
python -m qlure.cli forward --logs logs --db data/qlure.db
python -m qlure.cli correlate --db data/qlure.db
```
*`forward` copies new JSONL lines into `events`. `correlate` rebuilds `sessions`, `actors` and `findings` (scores).*

**Check log files against the event schema:**
```powershell
python -m qlure.cli validate logs\web.jsonl logs\api.jsonl
```
*Prints `valid/total` events and one line per bad event on stderr. Exits 1 if any line is invalid. List the files explicitly: PowerShell does not expand `*.jsonl` for this command.*

**Check the hash chain:**
```powershell
python -m qlure.cli verify --logs logs --db data/qlure.db
```

**Export indicators (read-only):**
```powershell
python -m qlure.cli export --db data/qlure.db --format csv --out data/indicators.csv
python -m qlure.cli export --db data/qlure.db --format stix --min-verdict suspicious --out data/indicators.json
python -m qlure.cli export --db data/qlure.db --format blocklist
```
*`csv`, `stix` (STIX 2.1) and `blocklist`. The default floor is `noteworthy`. The dashboard **Export** page has the same files. See [EXPORT.md](EXPORT.md).*

**Webhook alerts (off by default, operator side):**
```powershell
python -m qlure.cli alert --db data/qlure.db --state data/alert-state.json --dry-run
```
*Prints the payloads without sending. Without `--dry-run`, the URL comes from `--url`, `QLURE_ALERT_WEBHOOK` or the settings file. See [ALERTS.md](ALERTS.md).*

**Train the Machine Learning Model:**
```powershell
python -m qlure.cli ml train captures\tuning
```
*Trains the logistic-regression second opinion on labelled tuning captures and writes `data/model.json`. It refuses `heldout` folders and fewer than 10 sessions.*

**Evaluate on labelled captures:**
```powershell
python -m qlure.cli eval captures\tuning
```

**Sample data for a fresh clone (no Docker):**
```powershell
python tools/seed_demo.py --db data/demo.db
```
*Builds 10 sessions for 7 actors from the real decoys, in-process. `--force` replaces existing sample data.*
