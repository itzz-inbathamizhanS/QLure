# QLure implementation roadmap

Goal: make QLure a stronger, easier-to-demonstrate honeypot. Plan produced by a code-level audit; every claim was checked against the source.

## Status

Checked against the repository on 2026-10-09. Done means the code, tests and docs for the task exist.

| Task | Status | Note |
|---|---|---|
| P0.1 Injection patterns and scanner agents | Done | R5 kinds log4shell, shellshock, spring4shell, ssrf, webshell; wpscan, feroxbuster, whatweb, httpx added |
| P0.2 Web login honeytoken check | Done | Web login logs `honeytoken_use` for `ht-ssh-001` and `ht-db-001`; the reply stays 401 |
| P0.3 SSH realism | Done | `/etc/shadow` and `/root` refused; `./x` missing; `>` and `>>` parsed, never written |
| P0.4 Fix demo labels | Partly done | `docs/DEMO.md` has the fresh-clone path and the missing-bundle note; `tools/demo-attack.ps1` still says no rule scores FTP (stale) |
| P1.1 Per-kind ATT&CK and R8 categories | Done | `technique_map` in `rules.yaml`; R8 download, persistence, privesc, lateral, exfil, miner |
| P1.2 API visibility | Done | `body_preview` logged; a wrong `X-API-Key` is a login attempt for R3 |
| P1.3 Fake web content | Done | fake `.git`, robots.txt, `/download` (fake tree only), phpMyAdmin, 403 for server-status and upload |
| P1.4 Banner dialogues | Done | FTP, MySQL and Redis bounded dialogues; Redis `AUTH` with `ht-redis-001` is honeytoken use |
| P1.5 Fake filesystem and honeytokens | Done | `~/.ssh/*`, `app/backup.sh`, `app/config.yaml`, `auth.log`, `/proc/cpuinfo`; 8 honeytokens |
| P1.6 R11 data-store abuse | Done | Redis CONFIG SET, SLAVEOF, MODULE LOAD, EVAL and more; R8 is SSH-only |
| P1.7 Attack-coverage test suite | Done | 50 rows: 48 pass, 2 xfail (`ftp-anonymous-login`, `ssh-wget-pipe-sh`; see `docs/ATTACK_COVERAGE.md`) |
| P2.1 Story and labels | Done | Session story, technique chips, honeytoken badge and top banner |
| P2.2 Actor kill-chain strip | Done | Recon, credential, misuse with first-event times on the actor page |
| P2.3 Scripted demo scenario | Done | `tools/demo_scenario.py`: 13 loopback-only steps, `--list` and `--dry-run`; the "3 or more Noteworthy" live run was not repeated here |
| P2.4 Sample-data seed | Done | `tools/seed_demo.py`: 10 sessions, 7 actors, 4 Noteworthy, 4 Suspicious, 2 Benign; chain verified |
| P2.5 Reviewer doc | Done | `docs/REVIEWER.md` walkthrough; `qlure_rules.md` has R11 |
| P3.1 Live feed | Done | `QLURE_LIVE`, `QLURE_LIVE_INTERVAL` (default 10 s), page polls every 5 s; correlates only, a forwarder must run |
| P3.2 ATT&CK matrix page | Done | `/attack`: techniques by tactic, seen cells link to their top session |
| P3.3 SSH terminal playback | Done | "Terminal replay" panel on SSH sessions; output preview cap is 2 KB |
| P3.4 IOC export | Done | `qlure export` (STIX 2.1, CSV, blocklist) and dashboard downloads |
| P3.5 Fake Docker Engine API decoy | Done | Service `docker` on 2375; R5 labels container deploy, escape, dropper and mining |
| P4.1 CI | Done | Attack-coverage step, `docker compose build web`, non-blocking pip-audit, Python 3.12 and 3.13; not yet run on GitHub |
| P4.2 `/healthz` and metrics | Done | `/healthz` public; `/metrics` needs login unless `QLURE_METRICS_PUBLIC=1`; export downloads included |
| P4.3 Webhook alerts | Done | Operator side only: `qlure alert`, off by default. Not wired into the dashboard live feed |
| P4.4 Retention with anchor | Done | `qlure prune` with a hash-chain anchor; `qlure verify` accepts a pruned chain; manual only |
| P4.5 Rebuild the vercel bundle | Superseded | No Vercel bundle is built. The hosted demo is a Render web service from `render.yaml`, with sample data built at deploy time; see [DEPLOY_RENDER.md](DEPLOY_RENDER.md) |
| P4.6 Update architecture docs 03, 05, 10 | Done | Updated in the docs pass that added this table |

**Safety rule for every task:** every decoy reply is a fixed or fake constant. No exec, no subprocess, no file writes from attacker input, no outbound traffic. Every planted value contains "decoy" and fake keys must not parse as real keys.

Verification for every phase:

```
ruff check . && ruff format --check . && qlure schema --check && pytest -q
```

## Known facts before starting

The facts below are the audit's starting point. The ones marked as resolved were fixed by later tasks.
- **No sample data on a fresh clone** (resolved by P2.4, `tools/seed_demo.py`). The hosted demo still depends on `vercel-deploy/bundle.tar.xz`, which is not in the repo (P4.5).
- **The FTP step in `tools/demo-attack.ps1` detects nothing** (resolved by P1.4: FTP attempts are scored by R3 and R4; the script's own text is stale).
- **ATT&CK labels exist per rule** (shown in `session.html`), but R5 only ever shows T1190 and R10 shows none (resolved by P1.1 for R5; R10 still has no label, by design).
- Verdict thresholds: Suspicious at 30 or more, Noteworthy at 60 or more.

## A. Attack coverage gaps (ranked by demo value, all low risk unless noted)
1. Reusing the leaked SSH password on the web login is not flagged as honeytoken use (R7).
2. No patterns for Log4Shell, Shellshock, Spring4Shell, SSRF or webshell upload.
3. No fake `.git`, LFI or upload responses on the web decoy.
4. Unrealistic SSH replies: `cat /etc/shadow` should say "Permission denied"; `>>` redirects echo literally.
5. No privilege-escalation, lateral-movement or miner labels in R8.
6. API 401 brute force and JSON request bodies are invisible to the rules.
7. FTP, MySQL and Redis credentials and commands are not parsed (medium risk: protocol replies must stay fake).
8. No sample data for first-time reviewers.

## B. Lanes (no shared files, so agents can work in parallel)
| Lane | Owner | Files |
|---|---|---|
| F1 | qlure-fixer | `qlure/rules/rules.yaml`, `qlure/correlate/rules.py`, `qlure/settings.py` |
| F2 | qlure-fixer | `decoys/web/app.py`, `decoys/api/app.py`, `decoys/ssh/*.py`, `decoys/banners/listeners.py` |
| C1 | qlure-coder | `decoys/fakefs/fs.yaml`, `decoys/honeytokens.yaml`, `decoys/web/templates/*` |
| C2 | qlure-coder | `dashboard/templates/*`, `dashboard/data.py`, `dashboard/app.py`, `dashboard/static/*` |
| C3 | qlure-coder | `tools/*`, `docs/*`, `qlure_rules.md`, `README.md` |
| C4 | qlure-coder | `tests/correlate/test_attack_coverage.py`, `tests/decoys/*` |
| S | qlure-setup | `.github/workflows/ci.yml`, `docker-compose*.yml`, `gateway/nginx.conf`, `pyproject.toml` |
| D | qlure-deploy | vercel bundle |

New honeytoken IDs (fixed now so lanes do not wait on each other): `ht-git-001` (git remote URL token), `ht-sshkey-001` (fake private-key placeholder), `ht-redis-001` (Redis password), `ht-canary-001` (canary URL).

## Phase 0: quick wins (hours)
- **P0.1 Injection patterns and scanner agents** (F1, S). Add R5 kinds `log4shell`, `shellshock`, `spring4shell`, `ssrf`, `webshell`; add scanner agents wpscan, feroxbuster, whatweb, httpx. Proof: `pytest -q tests/correlate/test_rules.py`.
- **P0.2 Web login honeytoken check** (F2, S). `decoys/web/app.py` calls `honeytokens.find("ssh_password", ...)` and emits a honeytoken-use event; reply stays 401. Proof: `pytest -q tests/decoys/test_web.py`.
- **P0.3 SSH realism** (F2, S). `/etc/shadow` and `/root/*` reply "Permission denied"; `./x` replies "No such file or directory"; `>` and `>>` are parsed and never write anything. Proof: `pytest -q tests/decoys/test_shell.py`.
- **P0.4 Fix demo labels** (C3, S). Mark the FTP step as "logged, scored after P1.4" in `tools/demo-attack.ps1`; note the missing bundle in `docs/DEMO.md`.

## Phase 1: detection and coverage
- **P1.1 Per-kind ATT&CK and R8 categories** (F1, M, after P0.1). Add a `technique_map` (T1190, T1059.004, T1505.003); R8 categories download T1105, persistence T1098.004/T1053.003, privesc T1548.003, lateral T1021.004, exfil T1048, miner T1496. Proof: `pytest -q tests/correlate`.
- **P1.2 API visibility** (F2, M). Add `body_preview`; a wrong `X-API-Key` emits a login attempt so R3 catches key brute force. Proof: `pytest -q tests/decoys/test_api.py`.
- **P1.3 Fake web content** (F2 + C1, M). `/.git/HEAD` and `/.git/config` with `ht-git-001`, `/robots.txt`, `/download?file=` returning fake text only (never the host filesystem), fake phpmyadmin login, `/server-status` 403, `POST /upload` 403 with the body logged and never stored. Proof: `pytest -q tests/decoys/test_web.py`.
- **P1.4 Banner dialogues** (F2, M). FTP USER→331, PASS→530 with a login-attempt event; MySQL parses the username and replies access-denied; Redis reads up to 8 commands (10 s limit), `AUTH` with `ht-redis-001` is honeytoken use, everything else gets a fixed reply and is never executed. Proof: `pytest -q tests/decoys/test_banners.py`.
- **P1.5 Fake filesystem and honeytokens** (C1, M). `~/.ssh/*` (with `ht-sshkey-001`), `app/backup.sh`, `app/config.yaml`, `/var/log/auth.log` excerpt, `/proc/cpuinfo`. Every value contains "decoy". Proof: `pytest -q tests/decoys/test_honeytokens.py`.
- **P1.6 R11 data-store abuse rule** (F1, M, after P1.1 and P1.4). Detects Redis `CONFIG SET`, `SLAVEOF`, `MODULE LOAD`, `EVAL`; R8 must skip non-SSH commands. Proof: `pytest -q tests/correlate`.
- **P1.7 Attack-coverage test suite** (C4, M, can start now with xfail markers). One parametrized test per row of section A. Proof: `pytest -q tests/correlate/test_attack_coverage.py`.

Done when every gap in section A is green in P1.7 or documented in `docs/architecture/10-known-limits.md`, and `qlure eval` on the tuning captures does not get worse.

## Phase 2: demo and dashboard polish
- **P2.1 Story and labels** (C2, M, after P1.1). Deterministic "story" paragraph per session, technique chips and a honeytoken badge on the session list, top banner when a honeytoken is used.
- **P2.2 Actor kill-chain strip** (C2, S, after P2.1). recon → credential → misuse with timestamps.
- **P2.3 Scripted demo scenario** (C3, M). `tools/demo_scenario.py` plus a labelled JSONL; refuses any target except `127.0.0.1` or `::1`. Proof: `--dry-run` lists the steps; a live run produces 3 or more Noteworthy findings.
- **P2.4 Sample-data seed** (C3 + C2, M). `tools/seed_demo.py` runs the decoys in-process into a temp logs dir, then forward and correlate, plus an empty-state hint in the dashboard. Proof: Sessions and Actors pages are non-empty.
- **P2.5 Reviewer doc** (C3, S). `docs/REVIEWER.md`: a 5-minute walkthrough; update `docs/DEMO.md` and `qlure_rules.md` (add R11).

Done when a reviewer sees labelled attacks within 5 minutes of a fresh clone (seed, then dashboard).

## Phase 3: new features (reviewer-demo shortlist)
1. **P3.1 Live feed** (C2, M, after P2.1). Background loop reusing the forward/refresh logic and an htmx poll; a new attack appears within 15 s.
2. **P3.2 ATT&CK matrix page** (C2, M, after P1.1).
3. **P3.3 SSH terminal playback** (C2 + F2, S). Replay command and output per session; raise the output preview cap to 2 KB.
4. **P3.4 IOC export** (C3/C2, M). STIX 2.1 bundle, CSV and plain blocklist, read-only. Test the bundle shape.
5. **P3.5 Fake Docker Engine API decoy** (F2 + S, L). Fixed `/version` and `/containers` JSON, create returns 403, nothing is executed. Needs a new service value in the schema (`qlure schema --check`).

Other ideas (not scheduled): campaign clustering across actors, honeytoken rotation, a canary link that raises an alert (`ht-canary-001` is planted only), ML drift check, low-and-slow detection. Webhook alerts, `/healthz` and metrics were moved into Phase 4 (P4.2, P4.3).

## Phase 4: hardening, ops, CI, docs
- **P4.1** CI: attack-coverage job, `docker compose build` smoke test, `pip-audit` (S). Status: done (not yet run on GitHub).
- **P4.2** `/healthz` and metrics on the dashboard (C2, S).
- **P4.3** Webhook alerts, off by default (fixer, M).
- **P4.4** Retention enforcement with a checkpoint anchor so the hash chain stays valid (fixer, L, do last). Proof: `pytest -q tests/store` and `qlure verify`.
- **P4.5** Rebuild the vercel bundle from the seeded database (D, S, after P2.4).
- **P4.6** Update `docs/architecture` 03, 05 and 10 (C3, S).

## Risk register
1. **New patterns cause false positives.** Add benign cases to P1.7, compare `qlure eval captures/tuning` before and after, keep weights unchanged.
2. **Decoy realism turns into real capability** (stored uploads, executed Redis commands). Replies are constants only; tests assert no disk writes or subprocesses; watch-egress keeps running.
3. **Parallel agents edit the same file.** Use the lane table; `data.py` and `index.html` are sequential inside C2.
4. **A schema or service change breaks the store or filters.** Run `qlure schema --check` and the dashboard tests in the same task.
5. **Fake keys look real or trip secret scanners.** Keep the "decoy" marker, use key bodies that do not parse, and keep the honeytoken tests.

## If only one day is left
P0.1 → P0.2 → P0.3 → P1.1 → P1.5 → P2.4 → P2.1 → P2.5 → the green subset of P1.7. Skip Phase 3 except P3.3 if time remains.
