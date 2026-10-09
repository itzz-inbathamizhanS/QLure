# First real-capture evaluation (2026-10-09)

Run by Inbathamizhan S from this machine (one operator, one network path), using the real
tools below against our own running decoy stack (`docker compose up -d --build`). No simulated
or generated events: every number here comes from `qlure eval` on sessions the decoys actually
logged. Raw captures stay local per `captures/README.md`; only each run's `run.json` (who, tool,
label, split, start, end, event count) is committed, under `captures/tuning/` and
`captures/heldout/`.

## What was captured

**Benign** (5 runs): a real Chromium browser (desktop, mobile and macOS user agents) logging in
and browsing, a typo'd login, and a legitimate SSH session with the planted password.

**Malicious** (14 runs): `nmap -sV` against all six ports, `nikto`, `dirb` and `gobuster`
directory brute force, `hydra` password guessing against the web login and against SSH, the full
honeytoken chain end to end with `curl` and `sshpass` (config.bak → SSH password → bash_history →
API key → API call, which worked), SQL-injection- and path-traversal-style query strings and a
dirty login body via `curl`, raw credential stuffing, blind probes of ten API paths with no key,
raw-socket probes of the FTP/MySQL/Redis banners, and `sqlmap` (it gave up after one request
because our login always answers 401, so that run carries almost no signal).

## Results

| | tuning (13 runs) | heldout (6 runs) |
|---|---|---|
| sessions | 5431 (5428 malicious, 3 benign) | 13 (11 malicious, 2 benign) |
| precision | 1.00 | not measured (no Noteworthy flags) |
| recall | **0.0015** | **0.00** |
| false positives | 0 | 0 |

Precision is clean and false positives are zero on every real benign session we recorded. Recall
is the honest, unflattering number: on this first real-tool run, the rule engine missed almost
every attack session. That is a real finding, not a bug in the eval code, every miss comes with
an explanation (`qlure eval` prints one per miss).

## Why recall is this low: session fragmentation

Sessions group by `(src_ip, client_fp, service)` with a 10-minute gap, and `client_fp` is a hash
of the User-Agent and a few other headers. Two real tools defeat that:

- **Nikto** puts its test name inside the User-Agent on almost every request
  (`Nikto/2.1.5 ... (Test:map_codes)`, `(Test:001390)`, ...), so `client_fp` changes on nearly
  every request. One 41-second Nikto run became **1,671 separate one-request "sessions"**, each
  one far too small to cross any threshold alone, even though `R6` (scanner tool) correctly fired
  on every one of them.
- **`nmap -sV`** against six ports is inherently six separate sessions (one per service), each
  with only a handful of connect/banner events, again below threshold alone.

Design never links sessions by IP alone (deliberately, to avoid merging unrelated visitors behind
one NAT address), so none of these fragments recombine into the one actor they really are. Tools
that keep one identity for the whole run score correctly: the full honeytoken chain, the dirb and
gobuster brute forces, and the credential-stuffing run were each flagged, and every API-enumeration
and injection-probe session was later caught once combined with other evidence on the same actor.
Hydra's single session on heldout scored 45 (`Suspicious`, "R3, R6 fired") — just under the
`Noteworthy` bar of 60.

This is the kind of result the evaluation step is for: it found a real architectural gap (session
fragmentation against tools that vary their fingerprint or hit several services at once) that no
unit test caught, because the unit tests all drove one `client_fp` per scenario.

## The learned model, on the untouched heldout split

`qlure ml train captures/tuning` (3 benign vs 5428 malicious sessions, badly imbalanced) then
`qlure eval captures/heldout --model data/model.json`:

| | caught | missed | false alarms | correct benign | precision | recall | F1 |
|---|---|---|---|---|---|---|---|
| model | 8 | 3 | 0 | 2 | 1.00 | 0.73 | 0.84 |

The model is not gated by the "two rule families or one high-confidence rule" bar the rules use,
so it caught 8 of the 11 heldout attack sessions the rules missed entirely, with no false alarms
on the two benign sessions. That is a genuinely useful second opinion on exactly the kind of
fragmented session the rules struggle with, though both the training set (3 real benign sessions)
and the test set (2) are far too small to trust the 0.73 as a general number.

## What this does and does not show

- **Does show:** the hash chain, honeytoken chain, event schema, capture/replay/eval tools and
  the dashboard all work correctly end to end against real, unscripted tool traffic. Zero false
  positives on real benign use, across two separate recording sessions.
- **Does not show:** that the system meets the 0.90 precision/recall target. It does not, yet,
  against this one class of traffic. It also does not show how the system performs with multiple
  real visitors at once or testers outside the team, which the plan calls for before quoting any
  number to judges.

## Recommended next step

Session grouping needs a second path for same-IP, same-service, low-event sessions, or
`client_fp` needs to look only at headers tools do not routinely rotate, rather than widening the
existing IP-based actor merge (which was deliberately kept narrow). That is a correlation-engine
design change, not a weight or threshold tweak, so it is not made here; tuning-split weights and
thresholds were left as they were, to avoid fitting the rules to this one capture.

## Update, same day: fixed the session-fragmentation bug

`qlure/correlate/sessions.py` now also merges a long, tight-gap run of events from one
`(src_ip, service)` even when `client_fp` changes every request, as long as the run is at least
6 events with no gap over 1 second (`BURST_GAP`, `MIN_BURST_EVENTS`). The gap is five times the
slowest gap measured in the real Nikto run above (max 0.17s across 5,812 gaps); the minimum run
length is far below that run's length and well above a one-off coincidence of two visitors behind
one address clicking within a second of each other, which a new test drives through the real
decoy to confirm it still never merges (`tests/correlate/test_burst.py`). All 115 tests pass.

Re-running `qlure eval` on the same captures, nothing re-recorded:

| | before | after |
|---|---|---|
| tuning sessions | 5431 | **18** |
| tuning recall | 0.0015 | **0.27** |
| tuning precision | 1.00 | 1.00 (unchanged) |
| heldout sessions | 13 | 11 |
| heldout recall | 0.00 | 0.00 (unchanged) |

The Nikto run that was 1,671 one-request sessions is now one 30-second, 5,813-event session that
scores Noteworthy. That confirms the fix: it did exactly what it was built for.

Heldout recall is still 0 because its remaining misses are a different, deeper issue: `nmap -sV`
against six ports and the one `sqlmap` request each produce a handful of events per service, and
a verdict is decided per session, never per actor, so even a perfectly merged, perfectly
attributed thin session can still sit under the Noteworthy bar alone. Fixing that means scoring an
actor across its sessions, which is a bigger change to the finding model (one finding per session
today, in the database schema and the dashboard both) and was deliberately left for later rather
than rushed here.
