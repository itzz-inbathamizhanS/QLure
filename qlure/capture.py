"""Capture runs: a labelled slice of the real events the decoys logged while a test ran.

`start` records who runs which tool and when. `stop` copies the events logged in that window
into `captures/<split>/<run>/` with a run log. The label and the split are chosen when the run
is recorded, before anyone looks at scores.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from qlure.events import Event

STATE = Path("data/capture-active.json")
LABELS = ("benign", "malicious")
SPLITS = ("tuning", "heldout")


class CaptureError(Exception):
    pass


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "-", text).strip("-").lower() or "x"


def start(
    who: str,
    tool: str,
    label: str,
    split: str,
    *,
    src_ip: str | None = None,
    state: Path = STATE,
    now: datetime | None = None,
) -> dict[str, Any]:
    if label not in LABELS:
        raise CaptureError(f"label must be one of {', '.join(LABELS)}")
    if split not in SPLITS:
        raise CaptureError(f"split must be one of {', '.join(SPLITS)}")
    if state.exists():
        active = json.loads(state.read_text(encoding="utf-8"))
        raise CaptureError(f"a capture is already running ({active['run_id']}); stop it first")
    moment = now or datetime.now(UTC)
    run = {
        "run_id": f"{moment:%Y%m%dT%H%M%S%f}-{_slug(who)}-{_slug(tool)}",
        "who": who,
        "tool": tool,
        "label": label,
        "split": split,
        "src_ip": src_ip,
        "start": moment.isoformat(),
    }
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(json.dumps(run, indent=2), encoding="utf-8")
    return run


def parse_interactions(text: str) -> dict[str, int]:
    """'web=12,ssh=1' -> {'web': 12, 'ssh': 1}. Counts come from the packet capture."""
    out: dict[str, int] = {}
    for part in filter(None, (p.strip() for p in text.split(","))):
        name, _, number = part.partition("=")
        if not number.isdigit():
            raise CaptureError(f"bad interaction count: {part!r}")
        out[name.strip()] = int(number)
    return out


def stop(
    logs: Path,
    captures: Path,
    *,
    interactions: dict[str, int] | None = None,
    state: Path = STATE,
    now: datetime | None = None,
) -> Path:
    if not state.exists():
        raise CaptureError("no capture is running")
    run = json.loads(state.read_text(encoding="utf-8"))
    began = datetime.fromisoformat(run["start"])
    ended = now or datetime.now(UTC)

    kept: list[tuple[datetime, str]] = []
    for path in sorted(logs.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            event = Event.model_validate_json(line)
            if not began <= event.ts <= ended:  # real arrival time, also for replayed events
                continue
            if run["src_ip"] and event.src_ip != run["src_ip"]:
                continue
            kept.append((event.ts, line))
    # Sort on the parsed time: the JSON text drops ".000000", so string order is not time order.
    kept.sort(key=lambda pair: pair[0])
    lines = [line for _, line in kept]

    target = captures / run["split"] / run["run_id"]
    target.mkdir(parents=True, exist_ok=False)
    (target / "events.jsonl").write_text("".join(f"{ln}\n" for ln in lines), encoding="utf-8")
    run |= {"end": ended.isoformat(), "event_count": len(lines)}
    if interactions:
        run["expected_interactions"] = interactions
    (target / "run.json").write_text(json.dumps(run, indent=2), encoding="utf-8")
    state.unlink()
    return target


def export_labels(conn: sqlite3.Connection, run_dir: Path) -> int:
    """Write the dashboard labels of this run's sessions to `labels.json` beside its events."""
    ids = {
        Event.model_validate_json(line).event_id
        for line in (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    out = []
    for row in conn.execute(
        "SELECT l.session_id, l.label, l.evidence_event_ids, s.event_ids FROM labels l"
        " JOIN sessions s ON s.session_id = l.session_id"
    ):
        if ids.intersection(json.loads(row["event_ids"])):
            out.append(
                {
                    "session_id": row["session_id"],
                    "label": row["label"],
                    "evidence": json.loads(row["evidence_event_ids"] or "[]"),
                    "event_ids": json.loads(row["event_ids"]),
                }
            )
    (run_dir / "labels.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    return len(out)
