# 4. Storage and integrity

The stored record is the thing an investigator relies on, so it is built to show if anyone
changed it.

## The database: `data/qlure.db`

SQLite in WAL mode. Its tables (from `qlure/store/db.py`):

| Table | Holds | Written by |
|---|---|---|
| `events` | Every event, with its hash chain fields and the raw JSON | forwarder |
| `forwarder_state` | How far into each JSONL file the forwarder has read | forwarder |
| `sessions` | Session grouping and its events | correlate |
| `actors` | Actor grouping and their sessions | correlate |
| `findings` | Each session's score, verdict, rule hits and explanation | correlate |
| `honeytokens` | The planted secret list, as loaded | correlate |
| `config_audit` | Every settings change, accepted or refused, and its undo | dashboard |
| `checkpoints` | Signed snapshots of the hash chain (optional) | `qlure sign` |
| `retention_anchors` | Append-only record of each `qlure prune`: last removed seq and hash | `qlure prune` |
| `labels` | Operator review labels (malicious or benign) and evidence marks | dashboard |

The `events` table keeps the full canonical JSON in `raw` plus the indexed columns used for
queries (`session_id`, `honeytoken_id`, `ts`).

## The hash chain

Each event is linked to the one before it:

```
hash_n = SHA-256( hash_{n-1} + "\n" + canonical_json(event_n) )
```

- **Canonical JSON** means sorted keys, no spaces, and the `prev_hash` and `hash` fields left out
  (`qlure/store/chain.py`). The same event always gives the same bytes.
- The first event links to a genesis value of 64 zeros.

What this gives you:

- Changing any field of any event changes its hash, and every hash after it.
- Deleting an event breaks the link after it.
- Inserting an event breaks the link after it.

## Verifying it: `qlure verify`

`qlure/store/verify.py` recomputes the chain in two ways:

1. From the database, walking `events` in order.
2. Against the JSONL archive in `logs/`, which the decoys wrote and the database never touches.

It reports the first place they disagree. A tampered row, a missing row, or a removed line in the
archive all stop the check at that point.

## Retention

`qlure prune` removes a contiguous prefix of old events and pins the cut with a retention anchor;
`verify` accepts a chain that starts at the anchor and reports how many events were pruned. See
[RETENTION.md](../RETENTION.md).

## Signing checkpoints (optional)

`qlure keygen` makes an ML-DSA-65 key pair. `qlure sign` signs the current chain head and stores
the signature in `checkpoints`. This answers a harder question than `verify`: if someone rewrote
the whole database and the archive together, a re-chained history would still pass `verify`, but
it would not match the signed checkpoint.

Keep the `.key` file off the decoy host and pin the `.pub` file. See [page 8](08-extras-pqc-and-ml.md).

## Why the forwarder is separate

The forwarder is the main writer to `events`, but not the only one: the dashboard's Clear All
deletes from it (and empties the logs). That wipe is audited, and `verify` then has nothing to
check. The forwarder reads the JSONL files read-only and remembers
how far it got in `forwarder_state`, so a restart resumes where it stopped. Inserts use
`INSERT OR IGNORE` on the unique `event_id`, so an event seen twice is stored once.
