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

## Important Notes
> [!NOTE]
> - **R7 alone** makes a session Noteworthy, because it has the largest weight.
> - **R10** fires only when an actor's activity goes through several families, in kill-chain order. Sessions are joined into actors in `qlure/correlate/actors.py`, which is what links the web, SSH and API sessions; R10 then checks that joined activity.
> - An IP address alone never links sessions.
> - Thresholds and weights can be changed on the dashboard's settings page. The change is saved at once, but stored findings only change after Refresh (Re-run correlation) or `qlure correlate`.
