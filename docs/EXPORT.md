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

## Formats

- **csv**: one row per indicator. Columns: `type, value, first_seen, last_seen, sessions, actor,
  verdict, rules, attack_ids`. Types are `ipv4`, `ipv6`, `url-path`, `user-agent`,
  `credential-hash`, `honeytoken-id` and `sha256`. Lists inside a cell are separated by `;`.
- **blocklist**: plain text, one IP per line, deduplicated and sorted, with a
  `# generated ... by QLure (decoy-observed, review before blocking)` header. Loopback,
  link-local and private addresses are skipped. Documentation ranges (198.51.100.x, 203.0.113.x)
  are kept because the demo seed uses them.
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
- Values come from visitors. CSV cells that start with `=` may be read as formulas by a
  spreadsheet, so open the CSV as text or import it instead of double-clicking it.
- The `rules` and `attack_ids` of an indicator are the union over the sessions where it was seen.
- The dashboard does not have a download route yet. That is a later task.
