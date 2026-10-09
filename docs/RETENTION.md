# Retention: `qlure prune`

Retention is manual. Nothing runs it for you. The `retention_days` setting (the "Keep data for
(days)" field on the settings page, 0 to 365) is informational only: changing it deletes nothing
(0 means no stated policy).

```
qlure prune --db data/qlure.db --logs logs --older-than 30d --dry-run   # preview
qlure prune --db data/qlure.db --logs logs --older-than 30d --yes       # do it
```

Cron example (weekly, Sunday 03:00; stop nothing, the command takes the store write lock):

```
0 3 * * 0  cd /opt/qlure && qlure prune --older-than 30d --yes && qlure verify
```

## Rules

- `--older-than` is `Nd` or `Nw`, at least `1d`.
- Without `--yes` (or `--dry-run`) it refuses. The dry run prints the counts, the oldest and
  newest event kept and the new anchor.
- The newest 100 events are never removed.
- It refuses if `qlure verify` already fails. An anchor must not bless a damaged store.
- Only a contiguous prefix of the chain (by `seq`) is removed. It stops at the first event that
  is not old enough, so no hole is ever punched in the middle. The chain follows forwarding
  order, so an old event that sits behind a newer one stays until the newer one ages out.

## Design

The chain is `hash_n = SHA-256(hash_{n-1} + "\n" + event_n)`. Retained events keep their
original `prev_hash` and `hash`, so nothing is re-chained. What is needed is a pinned starting
point, the **retention anchor** (table `retention_anchors`, created on connect, so old databases
migrate on first use):

| Field | Meaning |
|---|---|
| `upto_seq`, `upto_hash` | the last removed event |
| `ts`, `cutoff`, `pruned`, `total_pruned` | when, the age cut, this run, all runs |
| `prev_anchor`, `hash` | SHA-256 over the row, linked to the previous anchor |

`qlure verify` then requires: the anchors are linked, unedited, and strictly increasing in
`seq`; the first retained event's `prev_hash` equals the newest anchor's `upto_hash`; the
rest of the chain checks as before. Output: `chain verified: N events intact, M pruned before
<date> (anchor ok)`; with nothing pruned it prints `chain verified: N events intact`.

In one `BEGIN IMMEDIATE` transaction (the forwarder's lock, so a forwarder pass cannot
interleave) it deletes the events, deletes sessions, findings and actors made only of removed
events (rebuild the rest with `qlure correlate`), inserts the anchor, rewrites each JSONL file
atomically without the removed lines (all other bytes unchanged), reduces the
`forwarder_state` offsets by the bytes removed, and writes a `data.prune` row to the
tamper-evident config audit chain, which commits everything.

Operator labels are left alone. After Clear All with anchors present, the forwarder continues
the chain from the newest anchor, so verify stays valid.

## Signed checkpoints

Checkpoints are never deleted. For a checkpoint at or before the cut, `verify` still checks the
ML-DSA signature and the key, but not that the event still exists. A checkpoint exactly at an
anchor's `seq` must match the anchor hash, which gives the anchor a signed pin. Sign
(`qlure sign --head`) just before pruning so the cut point is pinned by a signature.

## Limits

- Someone with write access to the database who also rewrites the archive can still forge a
  consistent, shorter history, including a fresh anchor; only signed checkpoints off the host
  defend against that. Pruned evidence is gone: export first if you need it.
- The DB and the files cannot change in one atomic step. If the process dies between the file
  replace and the commit, `verify` fails; run the same prune again to finish.
- A decoy appending during the rewrite is carried over, but the window is not zero. Prune off
  hours or pause the decoys for a strict guarantee.
- Prune is command-line only. The dashboard has no prune button and never runs it. Its Clear All
  is a different, full wipe (it also drops signed checkpoints).