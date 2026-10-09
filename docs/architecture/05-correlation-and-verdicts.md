# 5. Correlation and verdicts

This is how a pile of events becomes a verdict an investigator can check. It runs in three
stages: sessions, actors, then rules and scores.

## Stage 1: sessions (`qlure/correlate/sessions.py`)

A session is a run of events that look like one visitor on one service.

- Events with the same `(src_ip, client_fp, service)` belong together as long as the gap between
  them is under **10 minutes**.
- Events that share the decoy's own session id (a cookie or an SSH connection) always stay together.
- **Burst rule:** a long, very tight run from the same `(src_ip, service)` stays together even when
  `client_fp` changes on every request. Real scanners do this (Nikto puts a test name in its
  User-Agent). The run needs gaps under **1 second** and at least **6 events**. This keeps one
  scan from becoming thousands of one-request sessions.
- An IP address alone never joins two sessions, so unrelated visitors behind one address are not
  merged.

## Stage 2: actors (`qlure/correlate/actors.py`)

An actor is a group of sessions that are probably the same visitor. Sessions link only on strong
evidence:

- they **used** the same honeytoken (`honeytoken_use`, `login_success` or `api_call`);
- they tried the same **non-default** password, or the same list of two or more usernames;
- they share a client fingerprint **from the same IP within 30 minutes**. Banner-only sessions
  have no fingerprint, so banner sessions from one IP within 30 minutes count as one client.

A session that only *read* a honeytoken links to the users of it, but a lone reader does not
link to anything else.

## Stage 3: rules and scores (`qlure/correlate/rules.py`, `engine.py`)

Ten rules, each with a weight, a family and a confidence. The full list is in
[qlure/rules/rules.yaml](../../qlure/rules/rules.yaml).

| Rule | Name | Weight | Family | Confidence | Fires when |
|---|---|---|---|---|---|
| R1 | Service sweep | 20 | recon | medium | 3 or more services within 60 seconds (actor level) |
| R2 | Path enumeration | 25 | recon | medium | 15 or more distinct 404 paths, or a known scanner path |
| R3 | Brute force | 30 | credential | medium | 5 or more failed logins, or 3 or more usernames |
| R4 | Default credentials | 15 | credential | low | any pair from the default-credential list |
| R5 | Injection payload | 40 | exploit | high | any SQL injection, XSS, traversal or command pattern |
| R6 | Scanner tool | 15 | recon | medium | a known scanner User-Agent, or a banner grab with no follow-up |
| R7 | Honeytoken use | 60 | misuse | high | any planted key or password is used |
| R8 | Post-login discovery | 35 | misuse | high | 3 or more discovery commands, or a download or persistence command |
| R9 | Sensitive file access | 25 | misuse | medium | any read of `/.env`, `/backup/*`, `id_rsa` or `/etc/shadow` |
| R10 | Kill-chain progression | 25 | chain | high | 3 or more families in order: recon, then credential, then misuse |

R1 and R10 are actor-level: they look across all of an actor's sessions.

### Scoring

1. **Raw score** = sum of the weights of the rules that fired.
2. **Suppressors** subtract points when the traffic looks benign:
   - only requests to `/`, `/robots.txt`, `/favicon.ico` or `/health` (−50);
   - a failed login followed by a success (−30);
   - an allowlisted IP or User-Agent (−100);
   - fewer than 3 requests (−20).
   Suppressors do not apply when a high-confidence rule fired, so a honeytoken use is never hidden.
3. **Clamp** the result to 0 to 100.

### Verdicts

From `verdict_for()` in `engine.py`:

| Score | Verdict | Extra condition |
|---|---|---|
| 0 to 29 | **Benign** | none |
| 30 to 59 | **Suspicious** | none |
| 60 and over | **Suspicious** | only one rule family, and no high-confidence rule fired |
| 60 and over | **Noteworthy** | at least two rule families, or one high-confidence rule |

So a score of 60 needs either two different families (for example R5 exploit + R9 misuse, which is
65) or one high-confidence rule (R7 honeytoken use alone is 60).

### Effective verdict

Each session also gets its actor's combined score (`actor_score`), counting every rule hit across
all of the actor's sessions once. The **effective verdict** is the more serious of the session's own
verdict and its actor's, but only if the session fired at least one rule itself. A bystander who
only reused a guessed password is not swept up by someone else's verdict. A session that is the
only evidence its actor has cannot reach Noteworthy on its own.

### Explanations

`explain.py` writes the sentence an investigator reads. For each rule it names the threshold, the
measured value and the evidence events. Nothing is generated, so the same evidence always gives the
same explanation.

## Reading a finding

When you open a session on the dashboard, read it in this order:

1. **Verdict and score**: is it Benign, Suspicious or Noteworthy?
2. **Rule cards**: which rules fired, with threshold, measured value and weight.
3. **Actor**: is this session linked to others? The effective verdict may come from them.
4. **Evidence timeline**: the raw events and their hashes. Use the evidence export to confirm the
   chain is intact (see [page 4](04-storage-and-integrity.md)).
5. **Learned opinion** (if a model is trained): a second score that never changes the verdict.
   A "disagrees" mark shows when it points the opposite way.
