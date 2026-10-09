# IOC export (P3.4)

`qlure export` turns the decoy-observed indicators in the store into a file you can review or
share. It only reads the database (opened with `mode=ro`), so running it never changes the store.

```
qlure export --db data/qlure.db --format stix|csv|blocklist [--min-verdict suspicious|noteworthy] [--out FILE]
```

- Without `--out` the output goes to stdout.
- `--min-verdict` defaults to `noteworthy` for every format. A session counts when its effective
  verdict (its own, or its actor's if that is higher and the session has its own rule hit) is at
  or above the minimum.
- A missing database prints an error and exits 1. No findings give an empty but valid output and
  exit 0.

## Dashboard downloads

The dashboard has an **Export** page (`/export`) with the same three files as downloads:

| Route | File name | Same as |
|---|---|---|
| `/export.csv` | `qlure-indicators-YYYYMMDD.csv` | `--format csv` |
| `/export.json` | `qlure-indicators-YYYYMMDD.json` (STIX 2.1, `application/stix+json`) | `--format stix` |
| `/export.txt` | `qlure-indicators-YYYYMMDD.txt` | `--format blocklist` |

- Each route takes `?min=suspicious` to include Suspicious sessions. Without it, or with
  `min=noteworthy`, only Noteworthy sessions are exported. Any other value is refused with 400.
- Login is required. A download only reads the store, so it still works in judge mode.
- If the store cannot be read, the download answers 503 with a short message.

## Formats

- **csv**: one row per indicator. Columns: `type, value, first_seen, last_seen, sessions, actor,
  verdict, rules, attack_ids`. Types are `ipv4`, `ipv6`, `url-path`, `user-agent`,
  `credential-hash`, `honeytoken-id` and `sha256`. Lists inside a cell are separated by `;`.
  Any text cell that starts with `=`, `+`, `-`, `@`, tab or carriage return gets a single quote
  (`'`) in front, so a spreadsheet reads it as text (OWASP CSV injection). Blocklist and STIX
  output are not changed.
- **blocklist**: plain text, one IP per line, deduplicated and sorted, with a
  `# generated ... by QLure (decoy-observed, review before blocking)` header. Loopback,
  link-local and private addresses are skipped. Documentation ranges (192.0.2.0/24,
  198.51.100.0/24 and 203.0.113.0/24) are kept, so the demo's visitors appear.
- **stix**: a STIX 2.1 bundle. It holds an identity for QLure, indicators (`ipv4-addr:value`,
  `ipv6-addr:value` and `file:hashes.'SHA-256'` patterns), attack-pattern objects with
  `mitre-attack` references, and `indicates` relationships. IDs are UUIDv5 over the indicator
  value, so two runs over the same database are byte-identical. Confidence comes from the
  verdict: 85 for Noteworthy, 50 for Suspicious.

## What is never exported

- Passwords. A credential is exported only as the SHA-256 of the string (`credential-hash`).
- Honeytoken secret values. Only the `ht-...` ID is exported (`honeytoken-id`).
- Query strings and request bodies. Only the URL path is exported (`url-path`), and the body
  is represented by its SHA-256 (`sha256`) for requests without a credential.

## Limits

- `url-path`, `user-agent`, `credential-hash` and `honeytoken-id` have no STIX 2.1 pattern here,
  so they appear in the CSV only.
- Values come from visitors. Open a CSV as text or import it into a spreadsheet instead of
  double-clicking it. The quote prefix covers the usual formula cases, not every spreadsheet
  feature.
- The `rules` and `attack_ids` of an indicator are the union over the sessions where it was seen.
- Exports are a snapshot of the store as it is when you download. Pruned events
  (`qlure prune`, see [RETENTION.md](RETENTION.md)) are gone from later exports, so export
  first if you need the evidence.
