# Manual guide: run, demo and clean up Q-Lure

Step-by-step commands to rebuild, run and demo the Q-Lure stack on Windows, and to stop it and
clean up later. Run every command from the project folder, `D:\QLure`, in PowerShell or Command
Prompt. Nothing here pushes to GitHub.

## 1. Before you start

1. Start Docker Desktop and wait until it reports that it's running.
2. Check that the project's settings file exists. It holds the dashboard password:
   ```bash
   dir .env
   ```
   The password is the `QLURE_DASHBOARD_PASSWORD` value. Open `.env` in an editor to read it. Don't paste it into chat or commit it.

## 2. Build and start the stack

```bash
docker compose up -d --build
```

Check that the containers are up:

```bash
docker ps --format "{{.Names}}	{{.Status}}"
```

You should see the web, api, ssh, banners, dockerapi, forwarder and dashboard containers, the
egress-watch containers, and the gateway.

## 3. Open the dashboard

1. Open **http://127.0.0.1:9000** in a browser.
2. Sign in with the `QLURE_DASHBOARD_PASSWORD` value from `.env`.
3. Open **Sessions**. It may be empty until you send attacks.

The dashboard only accepts connections from this computer.

## 4. Decoy ports

These are on 127.0.0.1 and reach the decoys through the gateway:

| Port | Decoy |
|---|---|
| 8080 | Web |
| 8081 | REST API |
| 2222 | SSH |
| 2121 | FTP |
| 3306 | MySQL |
| 6379 | Redis |
| 2375 | Fake Docker Engine API |

If the gateway fails to start, another program is probably using one of these ports. Find it with:

```bash
Get-NetTCPConnection -LocalPort 2222
```

Stop that program yourself, then run `docker compose up -d` again.

## 5. Send the demo attacks

```bash
tools\attack_all.bat --no-proxy-header
```

The script sends 15 harmless steps from 5 attacker types. The forwarder container loads the new
events on its own, so you don't need to run the forward, correlate or verify commands by hand.

To check the steps without sending anything:

```bash
python tools\demo_scenario.py --dry-run
```

To run one step, for example the SSH login:

```bash
python tools\demo_scenario.py --only ssh-login --no-proxy-header
```

Refresh **Sessions** on the dashboard after the script finishes.

## 6. Read the results

1. Open the top session in **Sessions**.
2. Check its verdict and score.
3. Open the rule cards. Each names the rule, what it needs, and what the decoy saw.
4. Check the timeline for honeytoken hits (R7).
5. On an SSH session, open **Terminal replay** to see the commands in order.
6. Open **Evidence file (JSON)** to check the hash chain.

The rule definitions are in `qlure/rules/rules.yaml`.

## 7. Stop the stack

```bash
docker compose down
```

This removes the containers and networks. It keeps the data volumes, so the stored events remain.

## 8. Clean up later

Only run these after you've decided you don't need the stored data.

1. Check what's left:
   ```bash
   docker volume ls
   ```
   ```bash
   docker images qlure-decoy
   ```
2. Remove the data volumes. This deletes every stored event:
   ```bash
   docker volume rm qlure_qlure-data qlure-live_qlure-data
   ```
3. Remove the decoy image:
   ```bash
   docker image rm qlure-decoy:phase1
   ```

The project folders `data\`, `logs\` and `runtime\`, and the `.env` file, stay on disk until you
delete them yourself.

## 9. If something fails

- **Dashboard does not load.** Run `docker ps`. If `qlure-dashboard-1` is missing, run
  `docker compose up -d` again and check `docker logs qlure-dashboard-1`.
- **The attack script says no decoy is listening.** The gateway isn't running, or another program
  holds a port. See section 4.
- **Sessions stay empty after the attacks.** Check that the forwarder container is running with
  `docker ps`, and read its logs with `docker logs qlure-forwarder-1`.
- **Anything else.** Run `python tools\demo_scenario.py --list` to confirm the scenario runs at all.
