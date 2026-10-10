# The attacker journey after a port scan, and what QLure sees

## 1. Purpose

This page follows a typical attacker from the first port scan to a foothold, at the level of
MITRE ATT&CK tactics and general behaviour. For each stage it says what slows the attacker down,
and which QLure rules and ATT&CK IDs record the activity. It is for defenders who want to know
what QLure can and cannot see, and what to fix first. It contains no exploit steps.

Rule ids, names, weights and ATT&CK IDs are taken from [qlure/rules/rules.yaml](../qlure/rules/rules.yaml)
and [qlure_rules.md](../qlure_rules.md). Where a rule's ATT&CK ID depends on what it matched, the
`technique_map` in the same file decides it.

## 2. The journey

| Stage | What the attacker does (high level) | What stops or slows it (defender) | What QLure records (rule ids, ATT&CK ids) |
|---|---|---|---|
| **Identify services** | Connects to open ports and asks each service what it is and which version it runs (banners, version detection). | Offer only the services you need. Keep banners and version strings to what the service must send. Put admin and database ports behind a firewall or VPN, so they do not answer the internet. | `connect` and `banner` events. **R1** Service sweep (T1046): one visitor touches 3 or more services within 60 seconds. **R6** Scanner tool (T1595.002): a banner grab with no follow-up on FTP, MySQL or Redis. |
| **Research** | Off the target, matches the versions seen to known weaknesses and to default logins. | Patch, so known weaknesses no longer apply. Remove default accounts before anything is exposed. | Usually nothing: this happens away from the decoys. QLure sees the next stage, when the attacker tests what it found. |
| **Easy wins** | Tries well-known paths and default logins. Looks for exposed files (environment files, backups, version-control folders, cloud or SSH key folders), admin panels and open data stores. | No default logins. Nothing sensitive under the web root. Admin panels off the public address. Data stores never public. | **R2** Path enumeration (T1595.003): 15 or more distinct 404 paths, or any known scanner path such as `/wp-login.php`, `/phpmyadmin` or `/.git`. **R4** Default credentials (T1078.001, low confidence): a default pair from the list. **R9** Sensitive file access (T1005): a read of `/.env`, `/backup/*`, `/.git`, `/.aws`, `/.ssh`, `id_rsa`, `/etc/passwd` or `/etc/shadow`. **R6** Scanner tool (T1595.002): a scanner user agent. |
| **Credential guessing** | Repeats logins with many passwords (brute force). Tries one password on many usernames or services (stuffing, spraying). Reuses a password or secret found earlier. | MFA on every login the internet can reach. Lockout and rate limits at the real service (QLure does not do this). Unique, non-default passwords. No secrets left in files. | **R3** Brute force (T1110.001): 5 or more failed logins, or 3 or more usernames tried. **R4** (T1078.001), as above. **R7** Honeytoken use (T1552.001, weight 60, high confidence): a planted secret is used. One R7 hit makes a session Noteworthy by itself. |
| **Exploit** | Sends input that looks like an injection or a known-vulnerability string (SQL, script, path traversal, command injection, server-side request and others). Sends Redis commands that change configuration, replicate, load modules or run scripts. | Patch. Validate input and use parameterised queries in the real application. Least-privilege database accounts. A web application firewall in front of the real service (QLure is not one). No public Redis, MySQL or Docker API. | **R5** Injection payload (T1190 for most kinds; T1059.004, T1505.003, T1610, T1611, T1496 or T1105 for the container and shell kinds). QLure matches text only and never runs it. **R11** Data-store abuse (T1190; T1059 for script commands; T1485 for flush commands). One risky Redis command is Suspicious. |
| **After access** | Runs identity and system commands (discovery). Downloads a tool. Sets up a way back in (an SSH key, a scheduled job). Tries to gain more rights, reads secrets, moves to other hosts, copies data out or starts a miner. | Least privilege, so one account can do little. Outbound traffic denied by default on the real host. SSH keys reviewed and rotated. Alerts on new keys and scheduled jobs. | **R8** Post-login discovery (T1082, plus T1033 for identity commands): 3 or more discovery commands. R8 also fires on any download or persistence command (T1105, T1098.004, T1053.003). Its hit text names the category, and the IDs follow it: privilege escalation T1548.003, lateral movement T1021.004, exfiltration T1048, mining T1496. R8 counts SSH sessions only. **R9** (T1005) for secret files read. **R7** if a planted login was used. |
| **Linking the steps** | Moves between services, and may use a different visitor address for each one. Reuses one password or key in several places. | Treat a password or key reused in two places as one problem: change it everywhere. Keep the clocks of all services in sync, so timelines line up. Keep each service's own logs. | **R10** Kill-chain progression (weight 25, no ID of its own, carries the IDs of the hits it chains): recon, then credential, then misuse, in that order, with at least three families. **Actors**: sessions join only on a shared honeytoken, a shared non-default password or username list, or the same client fingerprint from the same IP within 30 minutes. An IP address alone never joins sessions. The actor page's kill-chain strip shows Recon, Credential and Misuse, each with its first-event time. |

Two points about the table:

- The kill-chain order uses three families only: recon (R1, R2, R6), credential (R3, R4) and misuse
  (R7, R8, R9). R5 and R11 belong to the exploit family, which R10 does not count and the strip
  does not show. An exploit hit still raises the session's score.
- A planted secret used to log in (R7) counts as misuse, not credential. So the Credential stage on
  the strip shows guessing only, and an actor can reach Recon and Misuse without Credential.

## 3. Worked example: three seeded visitors

The sample data comes from [tools/seed_demo.py](../tools/seed_demo.py). It drives the real decoys
with fixed traffic, from documentation addresses (198.51.100.x and 203.0.113.x). The results below
are what a fresh run produced (`python tools/seed_demo.py --db <path> --logs <path> --force`, then
`qlure correlate`). Scores and verdicts are stable from run to run. Session and actor IDs are not,
so this page uses visitor addresses. The seed has 10 sessions in 7 actors. Two visitors are benign
and have no rule hits. The Redis visitor is covered at the end of this section.

### Visitor 198.51.100.23: scanner (Suspicious, 40)

- **Stages acted out:** identify services (web only), easy wins (scanner paths), and the scanner
  user agent.
- **Seed behaviour:** a web scanner sends 16 requests to known admin, database, server-status and
  CMS paths, all with a scanner user agent.
- **Rules that fire:** R2 (T1595.003), naming `/actuator/health`, `/admin.php` and
  `/cgi-bin/test.cgi`, and R6 (T1595.002) for the scanner user agent. No exploit or injection
  payload is sent, so R5 does not fire.
- **Dashboard:** the session is Suspicious at 40. Its actor is Suspicious at 40, and the kill-chain
  strip reaches Recon only.

### Visitor 203.0.113.44: credential stuffer (Suspicious, 45 at the actor level)

- **Stages acted out:** credential guessing on three surfaces: the web login, the FTP login and
  the API key header.
- **Seed behaviour:** six web logins with default pairs and one shared password. Four FTP logins
  across four usernames, including the default pairs. Six wrong API keys, including the same
  shared password.
- **Rules that fire:** the web session has R3 (6 failed logins) and R4 (`admin/admin`, `root/toor`),
  score 45. The FTP session has R3 (4 different usernames) and R4 (`admin/admin`), score 45. The API
  session has R3 (6 failed logins), score 30.
- **Why it is one actor:** the three sessions share a password that is not on the default list.
  They have different client fingerprints, so the link comes from the password, not the address.
- **Dashboard:** the actor is Suspicious at 45, and the strip reaches Credential only.

### Visitor 198.51.100.77: full chain (Noteworthy, 100 at the actor level)

- **Stages acted out:** identify and easy wins (web), credential guessing (planted database
  password), misuse after login (planted SSH login, then commands on the fake shell), and the
  planted API key.
- **Seed behaviour, web session:** four scanner paths, then reads of a planted environment file and
  a planted backup file, then a login with the planted database password.
- **Rules that fire on the web session:** R2 (T1595.003), R9 (T1005) and R7 (`ht-db-001`,
  T1552.001). The score is 110 before the cap, so it shows 100. Verdict Noteworthy.
- **Seed behaviour, SSH session:** a login with the planted SSH password, then eight commands
  (identity, system and process checks, a download, a scheduled-job listing and a history read).
- **Rules that fire on the SSH session:** R7 (`ht-ssh-001`) and R8 with the categories discovery,
  download and persistence_cron. The IDs are T1082, T1033, T1105 and T1053.003. Score 95, Noteworthy.
- **Dashboard, actor:** the web and SSH sessions join into one actor at 100, Noteworthy. The strip
  reaches Recon and Misuse, and Credential is not reached, because the planted logins are misuse
  evidence. R10 does not fire, since no credential hit is in the actor.
- **The API session is separate.** The same visitor address sent a planted API key with a
  different client, and it became its own actor (Noteworthy, 60, R7 only). Its fingerprint differs
  from the other two sessions, and the planted key was not used anywhere else. An IP address alone
  never joins sessions. The [reviewer walkthrough](REVIEWER.md) records the same result.

The datastore visitor in the seed (a planted Redis password, then configuration and replication
commands) shows the exploit stage: R7 (`ht-redis-001`) and R11 (T1190), Noteworthy at 90. Its actor
reaches Misuse only, because R11 is in the exploit family.

## 4. What to do about it: defender checklist

Work through this for the real service, not only the decoys. QLure records; it does not protect.

1. **Patch.** Keep the web app, the database, the SSH server and the Redis or Docker hosts on
   supported, patched versions. This removes most of the exploit stage before it starts.
2. **No default or shared logins.** Change the default accounts that software ships with, and
   do not reuse a password across services. The R4 list in `rules.yaml` is the starting point of
   what attackers try first.
3. **MFA on every internet-reachable login**, including admin panels, and lockout or rate limits
   at the real service. QLure does not block or throttle.
4. **Firewall or VPN for admin and data ports.** SSH, MySQL, Redis and the Docker API are reached
   only from a VPN, a bastion or an allowlist. See
   [examples/firewall-allowlist.md](examples/firewall-allowlist.md).
5. **Nothing sensitive exposed.** Keep environment files, version-control folders, backups and key
   folders out of the web root. Check that the real server returns 404 for them, and that no backup
   file sits next to a live app.
6. **Least privilege.** The web application's database account, service accounts and shell users
   should each be able to do only their job, so that a discovery command reveals little of use.
7. **Egress limits on the real host.** Deny outbound traffic by default and allow only what the
   host needs. A host that cannot reach the internet cannot easily fetch a tool or send data out.
8. **Monitor the real service.** QLure sees only decoy traffic. Keep the real service's own logins,
   commands and outbound connections, and review them.
9. **Alerts with `qlure alert`.** Off by default. Give the webhook URL through `QLURE_ALERT_WEBHOOK`
   or `--url`, keep it secret, and test with `--dry-run` first. See [ALERTS.md](ALERTS.md).
10. **Honeytokens.** Plant the accepted values only where a legitimate user never reads, for example
    an unused backup in your own repository. The accepted values are published in this repository,
    so they are bait only, never secrets. Any use is logged and scored by R7, and a session with
    one R7 hit is Noteworthy. See checklist item 9 in
    [DEPLOY_ALONGSIDE_REAL_SERVICE.md](DEPLOY_ALONGSIDE_REAL_SERVICE.md).
11. **Keep the evidence.** Run `qlure verify` on a schedule. Retention is manual: preview with
    `qlure prune --older-than 30d --dry-run` before you delete. See [RETENTION.md](RETENTION.md).

## 5. Limits

- **QLure sees only what reaches the decoys.** An attack on the real service is not recorded, and
  neither is research done off the network.
- **Skilled attackers can tell low-interaction decoys apart.** The decoys answer with fixed text,
  fixed JSON and a shallow fake shell. A visitor who notices this learns that little is real, and
  the log then holds less useful traffic.
- **The rules are thresholds, not proof.** The weights and thresholds are starting points. They were
  tuned on sample data from our own scripts, and recall on real traffic has not been measured. The
  ATT&CK labels never change a score or a verdict.
- **Real users can reach the decoys.** A stale bookmark or a bare IP check can look like an attacker.
  Review such visitors before you act on them.
- **The real service needs its own defences.** Everything in the checklist above applies to it.
- **A decoy is not a shield.** It is bait and a sensor. It does not stop, slow or block anything.

## 6. Related docs

- [ATTACK_COVERAGE.md](ATTACK_COVERAGE.md): the test rows that check each attack against the decoys.
- [qlure_rules.md](../qlure_rules.md): rule definitions, weights and the ATT&CK labels.
- [architecture/05-correlation-and-verdicts.md](architecture/05-correlation-and-verdicts.md): how
  sessions are scored and joined into actors.
- [architecture/10-known-limits.md](architecture/10-known-limits.md): what the rules do not cover.
- [DEPLOY_ALONGSIDE_REAL_SERVICE.md](DEPLOY_ALONGSIDE_REAL_SERVICE.md): running decoys beside a real service.
- [REVIEWER.md](REVIEWER.md): the five-minute walkthrough of the seeded data.
- [ALERTS.md](ALERTS.md) and [RETENTION.md](RETENTION.md): alerts and retention.
