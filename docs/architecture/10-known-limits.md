# 10. Known limits and first results

This page is the honest picture. Read it before quoting any number from the project.

## First real-tool evaluation (2026-10-09)

Run against our own decoy stack, with real tools (see
[docs/eval-results-2026-10-09.md](../eval-results-2026-10-09.md) for the full write-up).

| | Tuning (13 runs) | Heldout (6 runs) |
|---|---|---|
| Sessions | 5,431 (5,428 malicious, 3 benign) | 13 (11 malicious, 2 benign) |
| Precision | 1.00 | not measured (no Noteworthy flags) |
| Recall | **0.0015** | **0.00** |
| False positives | 0 | 0 |

**What this means:**

- Precision is clean and there were no false positives on the real benign sessions recorded.
- Recall is very low. On this first real run the engine missed almost every attack session.
- This is a real finding, not a bug in the evaluation code. Each miss has an explanation.

**Why:** session fragmentation. Nikto changes its User-Agent on almost every request, which split
one 41-second scan into 1,671 one-request sessions. `nmap -sV` across six ports is six sessions.
Each piece is below the threshold alone. The burst rule and the actor-level effective verdict were
added in response, and they changed the Nikto result. Tools that keep one identity for the whole
run were scored correctly, including the full honeytoken chain, the directory brute forces and the
credential-stuffing run.

## Limits of the design

- **Recall is unproven at scale.** Tuning used 13 runs from one operator on one network path.
- **No held-out data from outsiders.** The heldout folder has 6 runs, all from the same team.
  Results from it do not show how the rules generalise.
- **Thresholds are starting points.** `rules.yaml` says so. They were tuned on the tuning captures
  only, which is the right order, but they still need checking against new data.
- **No learned model ships.** It needs real labelled captures to train, and it refuses to train on
  too few. See [page 8](08-extras-pqc-and-ml.md).
- **Sessions do not link by IP alone.** This prevents merging unrelated visitors, but it also means
  a determined actor who changes fingerprints can still split their activity across sessions. In
  the seed, the API session from `198.51.100.77` is its own actor, not part of the web and SSH
  actor, for the same reason.
- **Banner dialogues are short scripts.** FTP, MySQL and Redis answer a login and a few commands
  with fixed replies (rule R11 judges Redis commands), but they do not run a real protocol and
  never execute a query or store data.
- **The database honeytoken `ht-db-001` is only checked on logins.** The web `/login` and FTP
  `USER`/`PASS` record it as honeytoken use (rule R7), but there is no MySQL login that accepts it.
- **The API accepts only the planted keys.** Other requests get fixed responses.
- **The Docker API is a fixed fake.** It answers Docker Engine JSON and returns a fake id for
  container create and exec, but nothing is created, pulled, started or stored. There is no real
  daemon behind it, so a reviewer cannot list or inspect a container it "created".
- **The canary honeytoken raises no alert.** `ht-canary-001` (the URL in `app/backup.sh` on the SSH
  decoy) is planted only. The honeytokens file says a fetch of it would be the alert, but no code
  watches for that, so no rule reacts to it and it never triggers R7. `ht-git-001` and
  `ht-sshkey-001` are planted only in the same way.
- **The live feed correlates only.** The Sessions page re-runs correlation every
  `QLURE_LIVE_INTERVAL` seconds (default 10). It never reads the JSONL files, so new events reach
  the store only when the forwarder runs (the `forwarder` service in Docker, or `qlure forward`).
  With `QLURE_LIVE=0` the page updates only on Re-run correlation.
- **Judge mode pauses the live pass, not the button.** The background pass is skipped in judge
  mode, but **Re-run correlation** still writes findings. Settings, labels and Clear All are
  refused in judge mode.
- **Port settings need a manual restart.** The dashboard saves them but cannot control Docker.
- **Dashboard port.** The README says 9000 (inside Docker). A native run chooses its own port.
- **Single shared dashboard password.** There are no user accounts or per-operator audit trail.
- **Retention is manual.** `qlure prune` removes old events and their JSONL lines behind a
  hash-chain anchor. Nothing runs it, and the `retention_days` setting only states a policy. The
  limits are in [RETENTION.md](../RETENTION.md): the database and the archive cannot change in one
  atomic step (a crash between them makes `verify` fail until the same prune is run again), and
  someone who can rewrite both can still forge a shorter history unless signed checkpoints are kept
  off the host. Pruned evidence is gone, so export first.
- **Alerts are operator-side only.** `qlure alert` is not wired into the dashboard. It sends at
  most 10 posts per run with one retry each, and a failed post is tried again on the next run. The
  payload carries the source IP, so use a webhook you trust. Alert settings have no field on the
  settings page.
- **Metrics are gauges of the current store.** Clearing or pruning data lowers the counts.
  `/metrics` needs a login unless `QLURE_METRICS_PUBLIC=1`; `/healthz` is public and shows counts
  and times only.
- **The hosted demo is not rebuilt from this repository.** ROADMAP P4.5 is not done, so the Vercel
  snapshot may not show the newer pages (`/attack`, `/export`, the live indicator).
- **Two attack-coverage rows are expected failures.** `ftp-anonymous-login`: `anonymous` is not in
  the default-credential list, so R4 does not fire (a rule change is needed). `ssh-wget-pipe-sh`:
  the shell drops the `wget` error text, a reply-realism gap in `decoys/ssh/shell.py`. Both are
  `xfail(strict=True)` in `tests/correlate/test_attack_coverage.py` and listed in
  [ATTACK_COVERAGE.md](../ATTACK_COVERAGE.md).
- **Icons and panel hints are hidden on purpose.** `dashboard/static/app.css` sets `.icon` and
  `.hint` to `display: none` as part of the flat style. A missing icon is not a bug.
- **The theme choice is per browser.** The light or dark setting is saved in that browser's local
  storage. Without a saved choice, the page follows the system setting.

## Things backed by evidence

- Tampering tests in `tests/store/test_store.py` cover editing or deleting one archive line, and
  tampering with the store, each failing `verify` at that event.
- The honeytoken chain from the web portal through SSH to the API worked in the real run.
- The Nikto fragmentation was fixed by the burst rule. nmap is still six sessions, one per service,
  by design, and each is scored separately.

## What is not claimed

- No precision or recall figure beyond the table above.
- No statement that the system detects quantum attacks. The post-quantum parts are context only.
- No statement that the decoys hold against an attacker who escapes Docker.
