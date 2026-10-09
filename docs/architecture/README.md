# Q-Lure architecture guide

Start here. These pages explain how Q-Lure is built, in the order you would need to understand it.

| # | Page | Read it to learn |
|---|---|---|
| 1 | [Overview](01-overview.md) | What the project is, its parts, and how they fit together |
| 2 | [Data flow](02-data-flow.md) | What happens to one visitor request, from the decoy to the dashboard |
| 3 | [Decoys](03-decoys.md) | Each fake service, what it exposes and what it logs |
| 4 | [Storage and integrity](04-storage-and-integrity.md) | The SQLite database, the hash chain and how tampering is detected |
| 5 | [Correlation and verdicts](05-correlation-and-verdicts.md) | How events become sessions, actors, scores and verdicts |
| 6 | [Dashboard and settings](06-dashboard-and-settings.md) | What the operator sees and changes, and how changes are audited |
| 7 | [Security model](07-security-model.md) | How the decoys are isolated and what must never happen |
| 8 | [Extras: post-quantum and learned model](08-extras-pqc-and-ml.md) | The optional signing, key-exchange fingerprinting and second-opinion model |
| 9 | [Operations runbook](09-operations-runbook.md) | How to start, check, trigger test events and stop the stack |
| 10 | [Known limits](10-known-limits.md) | What the project does not do yet, and the first real-run results |

## Source of truth

- The reference README is at the repository root: [README.md](../../README.md).
- The event contract is [event.schema.json](../event.schema.json). Fields are only ever added, never renamed.
- The rules and thresholds are in [qlure/rules/rules.yaml](../../qlure/rules/rules.yaml).
- The fake secrets are in [decoys/honeytokens.yaml](../../decoys/honeytokens.yaml).

If a page here disagrees with the code, the code wins. Please update the page.

## Words used throughout

- **Visitor**: whoever connects to a decoy. Often an attacker, sometimes a tester or a normal browser.
- **Event**: one thing a visitor did to one decoy, stored as one JSON line.
- **Session**: a group of events that look like one continuous visit.
- **Actor**: a group of sessions that are probably the same person or tool.
- **Rule hit**: one of eleven fixed checks (R1 to R11) that a session or actor triggered.
- **Score**: the sum of rule weights, capped by suppressors, from 0 to 100.
- **Verdict**: Benign, Suspicious or Noteworthy, from the score and the rule families.
- **Honeytoken**: a fake password or key planted in one decoy and accepted by another.
