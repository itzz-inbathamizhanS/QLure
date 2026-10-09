# Attack coverage (P1.7)

`tests/correlate/test_attack_coverage.py` runs one row per attack from ROADMAP section A against the
real decoys (web and API test clients, the SSH shell, and the FTP, MySQL and Redis banner
listeners). Each row then correlates what the decoy logged. A row checks four things:

1. The decoy replies the way the real service would (status, banner or text).
2. The event is written to the decoy's own log, with the planted-secret ID where one is used.
3. The expected rules fire, with their ATT&CK IDs on the hit.
4. The session verdict is at least the minimum stated for that row.

Benign control rows must fire no rule and must stay Benign.

Two rows are `xfail(strict=True)`: they fail today and are listed under Known gaps. A strict xfail
turns green-to-red if the gap is fixed, so the marker must then be removed.

## How to run

```
python -m pytest -q tests/correlate/test_attack_coverage.py -v
```

Current result: 45 rows pass, 2 rows are xfailed (47 total).

## Coverage table

Verdict bands: 0 to 29 Benign, 30 to 59 Suspicious, 60 and over Noteworthy (see `qlure_rules.md`).
"Minimum verdict" is the least serious verdict the row accepts. Rows marked "Benign" only assert
that the rule fires, because that rule alone scores below the Suspicious line.

| Attack technique | Decoy | What the attacker sees | Event | Rule(s) | ATT&CK | Expected verdict | Test id |
|---|---|---|---|---|---|---|---|
| Directory brute force with gobuster user agent (16 paths) | web | 16 x 404 page | http_request | R2, R6 | T1595.002, T1595.003 | Suspicious | `web-dir-bruteforce` |
| Hunting `/.env` and `/backup/config.bak` | web | 200 with fake AWS key and planted SSH password | file_read | R9 | T1005 | Benign | `web-env-backup-hunt` |
| Reading `/.git/config` | web | 200 git config with fake token in remote URL | file_read (ht-git-001) | R2, R9 | T1005, T1595.003 | Suspicious | `web-git-config` |
| Path traversal and `/download` LFI | web | 302 for `?f=`, 200 with fake `/etc/passwd` | http_request, file_read | R5, R9 | T1005, T1190 | Noteworthy | `web-traversal-download` |
| SQL injection in query | web | 302 to `/login` | http_request | R5 | T1190 | Suspicious | `web-sqli` |
| Reflected XSS in query | web | 302 to `/login` | http_request | R5 | T1190 | Suspicious | `web-xss` |
| Command injection in query | web | 302 to `/login` | http_request | R5 | T1059.004 | Suspicious | `web-command-injection` |
| Log4Shell `${jndi:}` lookup | web | 302 to `/login` (text matched only, nothing fetched) | http_request | R5 | T1190 | Suspicious | `web-log4shell` |
| Shellshock in User-Agent on `/cgi-bin` | web | 404 page | http_request | R2, R5 | T1190, T1595.003 | Noteworthy | `web-shellshock` |
| Spring4Shell `class.module.classLoader` parameter | web | 302 to `/login` | http_request | R5 | T1190 | Suspicious | `web-spring4shell` |
| SSRF to cloud metadata address | web | 404 page | http_request | R5 | T1190 | Suspicious | `web-ssrf` |
| PHP webshell body POSTed to `/upload` | web | 403 Forbidden | http_request | R5 | T1505.003 | Suspicious | `web-webshell-upload` |
| Login brute force, 6 usernames | web | 401 login page each time | login_attempt | R3 | T1110.001 | Suspicious | `web-login-bruteforce` |
| Default credentials `admin` / `admin` | web | 401 login page | login_attempt | R4 | T1078.001 | Benign | `web-default-creds` |
| Planted SSH password reused on web login | web | 401 login page | login_attempt, honeytoken_use (ht-ssh-001) | R7 | T1552.001 | Noteworthy | `web-leaked-ssh-password` |
| phpMyAdmin probe and `root` / `root` login | web | phpMyAdmin login form again (200) | http_request, login_attempt | R2, R4 | T1078.001, T1595.003 | Suspicious | `web-phpmyadmin-login-probe` |
| WPScan user agent probing WordPress paths | web | 404 pages | http_request | R2, R6 | T1595.002 | Suspicious | `web-wpscan-agent` |
| feroxbuster user agent probing scanner paths | web | 403, then 404 pages | http_request | R2, R6 | T1595.002 | Suspicious | `web-feroxbuster-agent` |
| Benign: normal browse of `/` | web | 302 to `/login` | http_request | none | none | Benign | `benign-browse-root` |
| Benign: normal GET of `/login` | web | 200 login form | http_request | none | none | Benign | `benign-login-page` |
| Benign: normal Firefox GET of `/robots.txt` | web | 200 robots.txt | http_request | none | none | Benign | `benign-firefox-agent` |
| API key brute force, 6 wrong keys | api | 401 invalid API key each time | login_attempt | R3 | T1110.001 | Suspicious | `api-wrong-key-bruteforce` |
| Planted API key reused on `/api/v1/users` | api | 200 fake user list | api_call, honeytoken_use (ht-api-001) | R7 | T1552.001 | Noteworthy | `api-planted-key-reuse` |
| SQL injection in a JSON body | api | 401 (no key) or 405 (wrong method) | http_request | R5 | T1190 | Suspicious | `api-json-sqli` |
| IDOR-style walk of user IDs 1 to 20 with planted key | api | 200 for IDs 1 to 3, 404 for 4 to 20 | honeytoken_use, http_request | R2, R7 | T1552.001, T1595.003 | Noteworthy | `api-idor-enumeration` |
| Benign: single GET of `/api/v1/orders` with curl, no key | api | 401 JSON | http_request | none | none | Benign | `benign-api-get` |
| SSH password guessing, 6 pairs including `root` / `toor` | ssh | Permission denied each time | login_attempt | R3, R4 | T1078.001, T1110.001 | Suspicious | `ssh-brute-force` |
| Login with planted SSH password | ssh | shell accepted | login_success, honeytoken_use (ht-ssh-001) | R7 | T1552.001 | Noteworthy | `ssh-honeytoken-login` |
| Discovery: `whoami`, `id`, `uname -a`, `ls` | ssh | fake identity and kernel output | command | R7, R8 | T1033, T1082 | Noteworthy | `ssh-discovery-commands` |
| Download piped to shell: `wget ... -O- \| sh` | ssh | empty reply (see Known gaps) | command | R7, R8 | T1105 | Noteworthy | `ssh-wget-pipe-sh` |
| Persistence: append to `~/.ssh/authorized_keys` | ssh | silent write, no output | command | R7, R8 | T1098.004 | Noteworthy | `ssh-authorized-keys-persistence` |
| Persistence: `crontab -l` | ssh | existing crontab entry | command | R7, R8 | T1053.003 | Noteworthy | `ssh-crontab-persistence` |
| Privilege escalation: `sudo -l`, plus `wget` | ssh | "not in the sudoers file" | command | R7, R8 | T1548.003 | Noteworthy | `ssh-sudo-privilege-escalation` |
| Miner drop: `wget` xmrig, then run with stratum pool | ssh | wget cannot resolve host, `./xmrig: No such file` | command | R7, R8 | T1105, T1496 | Noteworthy | `ssh-miner-drop-xmrig` |
| Lateral movement: `ssh` to another host, plus `wget` | ssh | "Network is unreachable" | command | R7, R8 | T1021.004 | Noteworthy | `ssh-lateral-movement` |
| Exfiltration: `nc` to external host, plus `wget` | ssh | "nc: Network is unreachable" | command | R7, R8 | T1048 | Noteworthy | `ssh-exfil-nc` |
| `cat /etc/shadow` | ssh | `cat: /etc/shadow: Permission denied` | command | R7 | none | Noteworthy | `ssh-cat-shadow-denied` |
| FTP default login `root` / `root` | ftp | 530 Login incorrect | login_attempt | R4 | T1078.001 | Benign | `ftp-default-login` |
| FTP anonymous login (xfail) | ftp | 530 Login incorrect | login_attempt | R4 (expected, not fired) | T1078.001 | Benign | `ftp-anonymous-login` |
| FTP repeated failures, 4 usernames in one session | ftp | 530 Login incorrect each time | login_attempt | R3 | T1110.001 | Suspicious | `ftp-repeated-failures` |
| MySQL default pair `root` / `root` | mysql | Access denied (1045) | login_attempt | R4 | T1078.001 | Benign | `mysql-default-pair` |
| Redis AUTH with planted password, then PING | redis | +OK, +PONG | honeytoken_use (ht-redis-001) | R7 | T1552.001 | Noteworthy | `redis-planted-auth` |
| Redis `CONFIG SET dir` without auth | redis | `-NOAUTH Authentication required.` | command | R11 (not R8) | T1190 | Suspicious | `redis-config-set` |
| Redis `SLAVEOF` to external host | redis | `-NOAUTH Authentication required.` | command | R11 (not R8) | T1190 | Suspicious | `redis-slaveof` |
| Redis `MODULE LOAD` | redis | `-NOAUTH Authentication required.` | command | R11 (not R8) | T1190 | Suspicious | `redis-module-load` |
| Redis `EVAL` | redis | `-NOAUTH Authentication required.` | command | R11 (not R8) | T1059 | Suspicious | `redis-eval` |
| Redis AUTH with planted password, then `CONFIG SET` | redis | +OK, +OK | honeytoken_use, command | R7, R11 | T1190 | Noteworthy | `redis-planted-auth-config-set` |

Rows for the SSH shell that run post-login commands also carry R7, because the SSH decoy accepts
only the planted password. That is why they are Noteworthy by construction.

## Known gaps

Both rows are `xfail(strict=True)`. The test id is the same as in the table.

- **`ftp-anonymous-login`**: the FTP decoy records an anonymous login as a login attempt, but
  `anonymous` is not in the default-credential list in `qlure/rules/rules.yaml`, so R4 does not
  fire. Expected fix: add the anonymous pair to the list (a rule change, not made here).
- **`ssh-wget-pipe-sh`**: detection is correct (R7, R8, T1105, Noteworthy). The reply is empty
  because the decoy's pipe handling drops the `wget` error text (`wget: unable to resolve host
  address ...`), which a real shell prints on stderr. This is a reply-realism gap in
  `decoys/ssh/shell.py`, not a detection gap.

## Other limits seen while writing the rows

These are not xfails. The rows assert current behaviour, and the points below explain the
minimum verdicts.

- R9 alone scores 25 and R4 alone scores 15, so a single sensitive-file read or default login
  stays Benign. Rows `web-env-backup-hunt`, `web-default-creds`, `ftp-default-login` and
  `mysql-default-pair` assert only Benign.
- Sessions with fewer than three requests lose 20 points unless a high-confidence rule fired
  (`too_few_requests` suppressor). This is why the WPScan and feroxbuster rows send three requests.
- The FTP decoy ends a session after 8 commands (`MAX_COMMANDS`), so the FTP brute-force row uses
  4 attempts in one session.
