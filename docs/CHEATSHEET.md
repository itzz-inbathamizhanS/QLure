# Q-Lure Commands & Operations Cheat Sheet

This document contains all the essential PowerShell and Docker commands used to build, test, run, and manage the Q-Lure system. 

---

## 1. Docker & System Management
*These commands manage the entire decoy infrastructure and the dashboard.*

**Start the System (Detached Mode):**
```powershell
docker compose -p qlure-live up -d
```
*Spins up the entire network (web, api, ssh, banners, gateway, dashboard, and forwarder) in the background.*

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
*Streams the live background logs. Replace `forwarder` with `web`, `api`, or `dashboard` to see other services.*

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
- `3` **Find the leaked file:** Uses regex to extract the planted SSH password from `/backup/config.bak` to set up **R7 (Honeytoken)**.
- `8` **Path Traversal:** Attempts to download `../../../../etc/passwd`.
- `A` **Run All Automated:** Instantly runs all attacks sequentially without prompting.

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

---

## 4. Python Backend (Correlations & Rules)
*Advanced commands to test the python logic locally (requires python environment setup).*

**Manually trigger the Correlation Engine:**
```powershell
qlure correlate
```
*Reads the `events` table and builds `sessions`, `actors`, and assigns `findings` (scores).*

**Train the Machine Learning Model:**
```powershell
qlure model train
```
*Reads the historical sessions in the database, extracts behavioral features, and trains the Logistic Regression algorithm, saving it to `model.json`.*
