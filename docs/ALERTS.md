# Webhook alerts (off by default)

`qlure alert` posts one small JSON message per new Noteworthy session to a webhook. It runs on
the operator host only. Decoy containers never make outbound calls and nothing here changes that
(`watch-egress` keeps running).

## Configure

Give the URL one of three ways (first wins): `--url`, the `QLURE_ALERT_WEBHOOK` environment
variable, or the `alerts.webhook_url` setting (empty means off). `alerts.min_verdict` is
`noteworthy` (default) or `suspicious`.

- Slack: create an Incoming Webhook and use its `https://hooks.slack.com/services/...` URL.
- Discord: append `/slack` to the channel webhook URL, so Discord reads the `text` field.
- Generic: any http(s) endpoint that accepts a JSON POST. A 2xx reply counts as delivered.

The URL is a secret. It is validated (http/https only, at most 500 characters, no `user:pass@`),
audited like other settings, and shown only as `scheme://host/...` in audit rows, logs, CLI
output and `settings.masked()`. Rolling back the setting is refused; set it again instead.

## Run

```
qlure alert --db data/qlure.db --state data/alert-state.json --dry-run   # print, send nothing
qlure alert --db data/qlure.db --state data/alert-state.json
```

Cron: `*/5 * * * * cd /opt/qlure && QLURE_ALERT_WEBHOOK=... qlure alert --db data/qlure.db`.
Exit codes: 0 nothing to do or all sent, 1 configuration error, 2 some posts failed (they retry
on the next run; each post is tried twice at most, 5 second timeout).

Safety: redirects are not followed; file:, gopher: and other schemes are refused; a host that
resolves to loopback, link-local or a cloud metadata address is refused unless
`QLURE_ALERT_ALLOW_PRIVATE=1`. At most 10 alerts go out per run; a final "+K more" message says
how many are waiting. Sent session ids are kept in the state file (atomic write, newest 5000).

## Payload

```json
{
  "text": "QLure Noteworthy (score 88) from 198.51.100.77 on web; rules R1, R3; /session/ab12...",
  "verdict": "Noteworthy", "score": 88, "actor": "9f3c2a1b",
  "source_ip": "198.51.100.77", "services": ["web"],
  "rule_ids": ["R1", "R3"], "attack_ids": ["T1190"], "honeytoken_ids": ["ht-api-001"],
  "first_seen": "2026-10-09T10:00:00+00:00", "last_seen": "2026-10-09T10:04:00+00:00",
  "dashboard_path": "/session/ab12...", "qlure_version": "0.1.0"
}
```

## Privacy

No request bodies, passwords, credentials or honeytoken secret values are sent; honeytoken IDs
only. The source IP is included, so use a webhook you trust. The path has no host: add your own
dashboard address when reading it.

## Follow-up

Wiring this into the dashboard live feed is not done yet. The dashboard would call
`alerts.notify_new_noteworthy(...)` after each correlate cycle, in a thread, skipped in judge mode.
