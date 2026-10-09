# Demo guide

Two ways to show Q-Lure: a hosted snapshot on Vercel, or a live run on your own machine.
Both use the same dashboard, so the same walkthrough works for either.

| | Hosted (Vercel) | Live (localhost) |
|---|---|---|
| URL | https://qlure-dashboard.vercel.app/login | http://127.0.0.1:9100/login |
| Data | Fixed snapshot: 66 events, 8 sessions, 3 noteworthy | Whatever the decoys have recorded |
| Shows attacks happening? | No, it shows the results | Yes, you can send attacks and watch them appear |
| Needs | A browser | Docker Desktop, Python 3.12 or later |
| Password | Set by the project owner on Vercel | The one you set in your terminal |

Never put the real password in this repo or in chat. Use a placeholder such as
`choose-a-strong-password` in your own notes.

## Walkthrough (either setup)

Give each step about a minute.

1. **Sessions.** Eight sessions in total: three noteworthy, one suspicious, four benign. Point out
   the verdict mix bar and the score column.
2. **Top noteworthy session.** Open it. Show the verdict and the rule cards. Each card shows what
   the rule needs and what Q-Lure saw. Then show the evidence hashes and the timeline, which
   includes the honeytoken hits.
3. **Evidence.** From the session page, open **Printable report** and **Evidence file (JSON)**.
   The JSON includes the hash-chain check.
4. **Actors.** Open the actor page. One actor reaches a combined score of 100 across the web, API,
   and SSH decoys, with the kill-chain explanation.
5. **Settings.** Show the list of things that cannot be configured, then the change history.
   Do not change anything during the demo. Changes are audited and can be rolled back.
6. **Phone width.** Resize the window to about 390 px wide. The layout should stay on screen with
   no sideways scrolling.

## Domain scanner (both setups)

Use this to show the second part of the dashboard, with no decoys needed.

1. Open **Scanner** in the sidebar.
2. Enter `example.com`, leave the scan type on **Standard**, and click **Run scan**. Point out the
   key exchange (hybrid post-quantum), the certificate, the checks table, and the findings. Each finding
   names its evidence.
3. For a domain you control, choose **Full (owned domain)** after publishing the DNS TXT record that
   **Check DNS record** shows. Full scans stay off until `QLURE_DASHBOARD_SECRET` is set on the server.
4. Explain the limits: no ports or IP addresses, private addresses are refused, and nothing is saved.

## Show it on Vercel

1. Open https://qlure-dashboard.vercel.app/login.
2. Sign in with the project password.
3. Follow the walkthrough above.

Notes:

- The hosted site shows a fixed snapshot. New attacks will not appear while you present.
- The sidebar reads **Hosted demo** when the app runs on Vercel.
- Settings changes are stored on the Vercel instance and may reset at any time. Avoid making
  changes in front of an audience.
- Use only the main link above. Older deployment URLs serve older builds.

### For maintainers: redeploying

Run these from the `vercel-deploy` folder. The Vercel CLI must be logged in (`vercel login`).

```bash
npx vercel deploy --prod --yes --scope <team-id>
```

The team ID is in `vercel-deploy/.vercel/project.json` (`orgId`). Run the command from inside
`vercel-deploy` so the project link is used.

If you change anything under `dashboard/` or `qlure/`, rebuild `vercel-deploy/bundle.tar.xz`
first. The bundle must contain the `dashboard/` and `qlure/` folders and `data/qlure.db`, with no
`__pycache__` folders. Keep the database file as it is so the demo data stays the same.

## Show it on localhost

### Option A: hosted-equivalent data, no Docker

This shows exactly the data on Vercel, on your own machine.

1. Extract the demo database from the bundle into a folder outside the repo:

```bash
mkdir demo-data
```

```bash
tar -xf vercel-deploy/bundle.tar.xz -C demo-data data/qlure.db
```

2. Start the dashboard with the hosted banner on. Run these from `D:\QLure`, one per line in
   PowerShell:

```bash
$env:VERCEL = "1"
```

```bash
$env:QLURE_DASHBOARD_PASSWORD = "choose-a-strong-password"
```

```bash
$env:QLURE_DB = "demo-data/data/qlure.db"
```

```bash
python -m uvicorn dashboard.app:app --port 9103
```

3. Open http://127.0.0.1:9103/login and follow the walkthrough.
4. Stop the server with Ctrl+C.

Set `QLURE_LOGS`, `QLURE_SETTINGS`, and `QLURE_MODEL` to empty folders inside `demo-data` if
you want the server to keep its runtime files out of the repo.

### Option B: live demo with real decoys

Use this to show attacks arriving and being scored while the audience watches.

1. First time only, create the runtime folders:

```bash
mkdir logs, data, runtime
```

2. Start the five decoy containers:

```bash
docker compose up -d --build gateway web api ssh banners
```

3. Check they are running:

```bash
docker compose ps -a
```

   Five services should show `Up`.

4. In a second terminal, set a password and start the dashboard on port 9100. The commands below
   are for PowerShell. In Command Prompt (`cmd.exe`), use `set NAME=value` instead of
   `$env:NAME = "value"`:

```bash
$env:QLURE_DASHBOARD_PASSWORD = "choose-a-strong-password"
```

```bash
python -m uvicorn dashboard.app:app --port 9100
```

5. Open http://127.0.0.1:9100 and sign in. Keep the Sessions page on screen.

6. Send the attacks one at a time, pausing between them. Each request is recorded permanently in
   the local logs, so run only what you want counted.

   Benign browsing:

```bash
curl.exe -s -o NUL -w "%{http_code}" http://127.0.0.1:8080/login
```

   Planted-secret chain (reads the SSH password from the backup file):

```bash
curl.exe -s http://127.0.0.1:8080/backup/config.bak
```

   Injection pattern (rule R5):

```bash
curl.exe -s "http://127.0.0.1:8080/?id=1' OR '1'='1"
```

   Sensitive file read (rule R9). With R5, this gives a noteworthy verdict:

```bash
curl.exe -s http://127.0.0.1:8080/.env
```

7. Move the events into the database and score them. Run these in order:

```bash
python -m qlure.cli forward --logs logs --db data/qlure.db
```

```bash
python -m qlure.cli correlate --db data/qlure.db
```

8. Reload the Sessions page, or click **Re-run correlation**. The new sessions appear with their
   rules and verdicts. Open one to show the evidence and timeline.

To keep the dashboard current during a longer demo, repeat step 7 every 10 seconds.

### Manual threat walkthrough (no scripts)

Use this instead of the curl commands above, or after them. Do each step by hand, so the audience
sees the attacker's view. Each request is recorded, so run it only when you want it counted.
Mention the honeytoken IDs in brackets to the audience; they are fake values built for the demo.

1. **Browse normally.** In your browser, open http://127.0.0.1:8080/login. This is benign.
2. **Guess passwords.** On the login page, try `admin` / `admin`, then `admin` / `password123`,
   then `admin` / `letmein`. Five or more failed logins triggers R3 (brute force). Trying
   `admin` / `admin` also triggers R4 (default credentials).
3. **Read the leaked files.** Open http://127.0.0.1:8080/.env and then
   http://127.0.0.1:8080/backup/config.bak. Reading these sensitive files triggers R9. The backup
   file contains the SSH login for `deploy` [ht-ssh-001].
4. **Log in over SSH with the stolen password.** In a terminal, run:

```bash
ssh -p 2222 deploy@127.0.0.1
```

   Enter the password `Deploy-Decoy-2026`. If asked to trust the host key, type `yes`.
5. **Look around, as an attacker would.** In the fake shell, run at least three discovery commands,
   for example `whoami`, `id`, `uname -a`, `ps`, and `ip`. Three or more triggers R8 (post-login
   discovery). Then read the shell history to find an API key:

```bash
cat ~/.bash_history
```

   Note the API key in the history [ht-api-001]. Leave the shell with `exit`. Nothing runs on
   the host; the shell only emulates commands.
6. **Use the stolen API key.** In a terminal, run:

```bash
curl.exe -H "X-API-Key: qlk_decoy_7f3a9c21e5d84b0a" http://127.0.0.1:8081/api/v1/users
```

   Using a planted key triggers R7 (honeytoken use, high confidence), so this session is
   noteworthy by itself.
7. **Score and show it.** Run the `forward` and `correlate` commands, then reload the dashboard.
   The web, SSH, and API sessions link to one actor, because the same planted secrets connect
   them. Open the actor page to show the combined verdict and the kill-chain explanation.

| Step | Expected rule | What the audience sees on the dashboard |
|---|---|---|
| 2 | R3, and R4 for `admin` / `admin` | Credential rules on the web session |
| 3 | R9 | Sensitive file reads in the timeline |
| 5 | R8 | Discovery commands in the SSH session |
| 6 | R7 | Honeytoken `ht-api-001` used in the API session |
| 7 | R10 possible | Kill-chain progression on the actor page |

The exact verdicts depend on what else has been recorded in the same database. If a session scores
lower than expected, check the rule cards on its page to see which rules fired.

## Troubleshooting

| Problem | Fix |
|---|---|
| `unknown shorthand flag: '.'` | Remove the trailing full stop from the command. Use `docker compose ps -a`. |
| A decoy is not `Up` | Run `docker compose up -d --build gateway web api ssh banners` again. |
| Port 9100 already in use | Find the process with `netstat -ano \| findstr :9100`, or start on another port such as 9101. |
| Port 3306 or 6379 in use | Stop any local MySQL or Redis first. |
| The dashboard shows no new sessions | Run the `forward` and then the `correlate` command, then reload the page. |
| The login page says "Hosted demo" on localhost | `VERCEL` is still set in this terminal. Close it or run `Remove-Item Env:VERCEL`. |
