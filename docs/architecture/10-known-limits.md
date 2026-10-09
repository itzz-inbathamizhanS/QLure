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
  a determined actor who changes fingerprints can still split their activity across sessions.
- **Banner dialogues are short scripts.** FTP, MySQL and Redis answer a login and a few commands
  with fixed replies (rule R11 judges Redis commands), but they do not run a real protocol and
  never execute a query or store data.
- **The database honeytoken `ht-db-001` is planted but not accepted.** Using it triggers no rule
  beyond reading it in `/.env`.
- **The API accepts only the planted keys.** Other requests get fixed responses.
- **Port settings need a manual restart.** The dashboard saves them but cannot control Docker.
- **Dashboard port.** The README says 9000 (inside Docker). A native run chooses its own port.
- **Single shared dashboard password.** There are no user accounts or per-operator audit trail.
- **Retention is a setting only.** Nothing deletes old data based on the retention value yet.

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
