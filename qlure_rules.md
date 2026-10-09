# Q-Lure Detection Rules

Each session is scored by the rules defined in `qlure/rules/rules.yaml`. A rule adds its weight to the session score. The overall verdict of a session depends on its total score:

- **0 to 29:** Benign
- **30 to 59:** Suspicious
- **60 and over:** Noteworthy (only when the session has two rule families or one high-confidence rule)

## Rule Definitions

| Rule | Name | Family | Weight | Confidence | What it detects |
|---|---|---|---|---|---|
| **R1** | Service sweep | recon | 20 | medium | One visitor touches several services within 60 seconds |
| **R2** | Path enumeration | recon | 25 | medium | Many distinct 404 paths, or a known scanner path such as `/wp-login.php` or `/.git` |
| **R3** | Brute force | credential | 30 | medium | Many failed logins, or many different usernames tried |
| **R4** | Default credentials | credential | 15 | low | A default username and password pair, such as `admin` / `admin` |
| **R5** | Injection payload | exploit | 40 | high | SQL injection or similar patterns in a request. Kinds: `sqli`, `xss`, `traversal`, `command_injection`, `log4shell` (`${jndi:` incl. `${${lower:j}ndi:` obfuscation), `shellshock` (`() { :;};`), `spring4shell` (`class.module.classLoader`), `ssrf` (169.254.169.254, metadata.google.internal, `gopher://`, `file://`), `webshell` (`<?php`, `<?=`, `eval(base64_decode`). The finding lists every kind seen. Text only is matched, nothing is executed or fetched |
| **R6** | Scanner tool | recon | 15 | medium | A scanner user agent (sqlmap, nikto, nmap, wpscan, feroxbuster, whatweb, httpx and others, case-insensitive substring), or a banner grab with no follow-up |
| **R7** | Honeytoken use | misuse | 60 | high | A planted fake secret is used, such as the API key or SSH password |
| **R8** | Post-login discovery | misuse | 35 | high | After SSH login: several discovery commands, or a download or persistence command |
| **R9** | Sensitive file access | misuse | 25 | medium | A sensitive file is read, such as `.env` or `config.bak` |
| **R10** | Kill-chain progression | chain | 25 | high | Activity moves through several families (recon, credential, misuse) |

## ATT&CK labels

Labels only: they never change a weight, threshold or verdict. They are defined in `technique_map` in `qlure/rules/rules.yaml`.

**R5** - a hit carries the union of the IDs for the kinds actually matched:

| Kind | ATT&CK |
|---|---|
| `sqli`, `xss`, `traversal`, `lfi`, `injection`, `log4shell`, `spring4shell`, `shellshock`, `ssrf` | T1190 |
| `command_injection` | T1059.004 |
| `webshell` | T1505.003 |

**R8** - the hit's `measured` text lists the command categories seen (`[categories: ...]`) and `attack` is the union of their IDs. Which commands count toward the threshold is unchanged.

| Category | Examples | ATT&CK |
|---|---|---|
| discovery | whoami, id, uname, ps, ls | T1082 (+ T1033 for whoami, id, w) |
| download | wget, curl, tftp, scp | T1105 |
| persistence_ssh_key | authorized_keys | T1098.004 |
| persistence_cron | crontab, cron | T1053.003 |
| privilege_escalation | sudo, su, `find -perm -4000` | T1548.003 |
| lateral_movement | ssh or scp to another host | T1021.004 |
| exfiltration | nc, netcat, tar piped to base64 | T1048 |
| crypto_mining | xmrig, minerd, stratum+tcp | T1496 |

**R10** carries the union of the IDs of the recon, credential and misuse hits it chains.

## Important Notes
> [!NOTE]
> - **R7 alone** makes a session Noteworthy, because it has the largest weight.
> - **R10** fires only when an actor's activity goes through several families, in kill-chain order. Sessions are joined into actors in `qlure/correlate/actors.py`, which is what links the web, SSH and API sessions; R10 then checks that joined activity.
> - An IP address alone never links sessions.
> - Thresholds and weights can be changed on the dashboard's settings page. The change is saved at once, but stored findings only change after Refresh (Re-run correlation) or `qlure correlate`.
