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

## 5. Running the attacks

Start the stack first, since it is stopped after `docker compose down`:

```bash
docker compose up -d --build
```

Wait until the dashboard answers at http://127.0.0.1:9000 before you start the attacks.

### 5a. Manual walkthrough (live, in front of reviewers)

Use these steps to show a live attack by hand. Each one is harmless and goes only to 127.0.0.1.

1. **Sign in to the dashboard.** Open http://127.0.0.1:9000 and sign in with `QLURE_DASHBOARD_PASSWORD` from `.env`.
2. **Failed logins.** Open http://localhost:8080/login in a browser and enter a few wrong usernames and passwords, for example three or four attempts. Each attempt is logged.
3. **Honeytoken file.** Open http://localhost:8080/backup/config.bak. It is a planted fake config file. Opening it records a honeytoken hit (R7).
4. **SSH session.** In a terminal run:
   ```bash
   ssh -p 2222 deploy@localhost
   ```
   Use the planted deploy password from `decoys/honeytokens.yaml` if the decoy asks for one. Type a few harmless commands such as `ls` and `whoami`, then type `exit`.
5. **Process the events.** In Docker mode the forwarder container does this on its own, so skip this step.
   The commands below write to `data\qlure.db` on this computer, which the Docker dashboard does not read.
   Run them only for a local run without Docker:
   ```bash
   python -m qlure.cli forward --logs logs --db data\qlure.db
   ```
   ```bash
   python -m qlure.cli correlate --db data\qlure.db
   ```
6. **Check the flagged sessions.** Refresh **Sessions** on the dashboard. The browser session should show failed-login rules, the honeytoken session should show R7, and the SSH session should show R7 and R8 or R9. Open the top session and follow section 6.

If the honeytoken page doesn't load, run the matching scripted step instead:

```bash
python tools\demo_scenario.py --only web-lfi --no-proxy-header
```

### 5b. Manual steps for each decoy

Run these one at a time in a terminal. Each one is harmless, and each goes only to 127.0.0.1. The
values for the API key, the SSH password and the Redis password are in `decoys\honeytokens.yaml`,
so copy them from there rather than from this guide.

1. **Web portal, port 8080: login page.**
   ```bash
   curl -i http://127.0.0.1:8080/login
   ```
   The visitor sees a login page.

2. **Web portal: planted files.**
   ```bash
   curl -i http://127.0.0.1:8080/.env
   ```
   ```bash
   curl -i http://127.0.0.1:8080/backup/
   ```
   ```bash
   curl -i http://127.0.0.1:8080/.git/config
   ```
   The visitor sees a planted `.env`, a backup folder listing, and a git config. The git config
   holds a planted deploy token.

3. **Web portal: phpMyAdmin-style login.**
   ```bash
   curl -i http://127.0.0.1:8080/phpmyadmin/
   ```
   The visitor sees a phpMyAdmin-style login form.

4. **Web portal: upload sink.**
   ```bash
   curl -i -X POST -d "test=1" http://127.0.0.1:8080/upload
   ```
   The visitor gets a fixed **403 Forbidden** page. Nothing is stored.

5. **REST API, port 8081: no key.**
   ```bash
   curl -i http://127.0.0.1:8081/api/v1/users
   ```
   The visitor gets **401**, "Invalid or missing API key".

6. **REST API: with the planted key.** Copy the `ht-api-001` value from `decoys\honeytokens.yaml` into `KEY`:
   ```bash
   curl -i -H "x-api-key: KEY" http://127.0.0.1:8081/api/v1/users
   ```
   The visitor gets a fixed JSON list of users.

7. **SSH-like server, port 2222.**
   ```bash
   ssh -p 2222 deploy@127.0.0.1
   ```
   Use the deploy password from `decoys\honeytokens.yaml`. The visitor sees an SSH login, then a
   fake shell. Type `ls` and `exit` to finish. You type the password yourself at the prompt.

   If SSH prints **REMOTE HOST IDENTIFICATION HAS CHANGED**, the decoy's host key changed since
   your last run. Remove the old entry and try again:
   ```bash
   ssh-keygen -R "[127.0.0.1]:2222"
   ```

8. **FTP banner, port 2121.** The Windows `ftp` command can't set a port, so use curl:
   ```bash
   curl -v --user anonymous:guest ftp://127.0.0.1:2121/
   ```
   The visitor sees the greeting `220 ProFTPD 1.3.8 Server (Veltrix Files)`. The login attempt gets
   **331** (password needed), then **530 Login incorrect**.

9. **MySQL banner, port 3306.**
   ```bash
   curl -v telnet://127.0.0.1:3306
   ```
   The visitor sees a MySQL 8.0 server greeting. **Access denied** appears only after a client sends a login. Press `Ctrl+C` to stop.

10. **Redis banner, port 6379.** With `redis-cli` installed:
    ```bash
    redis-cli -p 6379 PING
    ```
    The visitor gets `-NOAUTH Authentication required.` Then copy the `redis_password` value from
    `decoys\honeytokens.yaml` and send it:
    ```bash
    redis-cli -p 6379 AUTH PASSWORD
    ```
    ```bash
    redis-cli -p 6379 INFO
    ```
    After `AUTH` succeeds, the visitor sees fixed server details (Redis 7.0.15).

    If `redis-cli` is not installed, send the same commands over a raw connection in Git Bash.
    Replace `PASSWORD` with the value from `decoys\honeytokens.yaml`:
    ```bash
    printf "PING\r\n" | timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/6379; cat >&3; timeout 3 cat <&3'
    ```
    ```bash
    printf "AUTH PASSWORD\r\nINFO server\r\n" | timeout 6 bash -c 'exec 3<>/dev/tcp/127.0.0.1/6379; cat >&3; timeout 4 cat <&3'
    ```

11. **Fake Docker API, port 2375.**
    ```bash
    curl -i http://127.0.0.1:2375/version
    ```
    The visitor gets fixed Docker Engine JSON.
    ```bash
    curl -i -X POST -H "Content-Type: application/json" -d "{\"Image\":\"alpine\"}" http://127.0.0.1:2375/containers/create
    ```
    The visitor gets **201** with a fake container id. Nothing is created.
    ```bash
    curl -i -X POST "http://127.0.0.1:2375/images/create?fromImage=alpine&tag=latest"
    ```
    The visitor gets status lines such as "Downloaded newer image for alpine:latest". No id is returned.

### 5c. Automated attack script

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
