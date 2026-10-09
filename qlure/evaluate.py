"""`qlure eval`: measure the correlation engine on labelled real captures.

Every number comes from the run directories under the given folder (see `qlure.capture`).
Nothing is generated. A metric whose inputs are missing is reported as "not measured",
never as a pass.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from qlure.correlate.engine import correlate
from qlure.correlate.model import Finding
from qlure.correlate.rules import load_config
from qlure.events import Event

INTERACTION_ACTION = {
    "web": "http_request",
    "api": "http_request",
    "ssh": "connect",
    "ftp": "connect",
    "mysql": "connect",
    "redis": "connect",
}
TARGETS = {
    "precision": (">=", 0.90),
    "recall": (">=", 0.90),
    "event_coverage": ("==", 1.0),
    "false_positives": ("==", 0),
    "evidence_completeness": (">=", 0.95),
    "explanation_quality": ("==", 1.0),
}


@dataclass
class Run:
    path: Path
    meta: dict[str, Any]
    events: list[Event]
    labels: list[dict[str, Any]] = field(default_factory=list)


def load_runs(root: Path) -> list[Run]:
    runs = []
    for meta_path in sorted(root.rglob("run.json")):
        folder = meta_path.parent
        events = [
            Event.model_validate_json(line)
            for line in (folder / "events.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        labels_path = folder / "labels.json"
        labels = json.loads(labels_path.read_text(encoding="utf-8")) if labels_path.exists() else []
        runs.append(Run(folder, json.loads(meta_path.read_text(encoding="utf-8")), events, labels))
    return runs


def _ratio(num: int, den: int) -> float | None:
    return None if den == 0 else num / den


def _why_missed(finding: Finding, noteworthy: int) -> str:
    rules = ", ".join(sorted({h.rule_id for h in finding.hits}, key=lambda r: int(r[1:])))
    if not finding.hits:
        return "no rule fired"
    if finding.score < noteworthy:
        return f"score {finding.score} is below {noteworthy}; only {rules} fired"
    return (
        f"score {finding.score} but held at {finding.verdict}: "
        f"one family and no high-confidence rule ({rules})"
    )


def _explains_everything(finding: Finding) -> bool:
    text = finding.explanation
    if not finding.hits:
        return False
    return all(
        hit.rule_id in text
        and hit.threshold in text
        and hit.measured in text
        and hit.evidence
        and hit.evidence[0] in text
        for hit in finding.hits
    )


def evaluate(root: Path) -> dict[str, Any]:
    runs = load_runs(root)
    events: dict[str, Event] = {}
    run_of: dict[str, Run] = {}
    for run in runs:
        for event in run.events:
            events[event.event_id] = event
            run_of[event.event_id] = run
    result = correlate(list(events.values()))
    noteworthy = load_config()["verdicts"]["noteworthy"]

    session_labels: dict[str, dict[str, Any]] = {}
    for run in runs:
        for entry in run.labels:
            session_labels[entry["session_id"]] = entry
    by_events = [(set(entry.get("event_ids", [])), entry) for run in runs for entry in run.labels]

    rows = []
    mixed = 0
    for finding in result.findings:
        ids = set(finding.session.event_ids)
        labels = {run_of[i].meta["label"] for i in ids}
        entry = session_labels.get(finding.session.session_id) or next(
            (e for seen, e in by_events if ids & seen), None
        )
        if entry:
            label = entry["label"]
        else:
            label = "malicious" if "malicious" in labels else "benign"
            mixed += len(labels) > 1
        rows.append((finding, label, entry))

    tp = sum(1 for f, label, _ in rows if label == "malicious" and f.verdict == "Noteworthy")
    fn = sum(1 for f, label, _ in rows if label == "malicious" and f.verdict != "Noteworthy")
    fp = sum(1 for f, label, _ in rows if label == "benign" and f.verdict == "Noteworthy")
    tn = sum(1 for f, label, _ in rows if label == "benign" and f.verdict != "Noteworthy")
    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = (
        None
        if precision is None or recall is None or precision + recall == 0
        else (2 * precision * recall / (precision + recall))
    )

    # Event coverage: interactions in the packet capture that have a logged event.
    expected_total = logged_total = 0
    for run in runs:
        for service, expected in (run.meta.get("expected_interactions") or {}).items():
            action = INTERACTION_ACTION.get(service)
            logged = sum(
                1 for e in run.events if e.service.value == service and e.action.value == action
            )
            expected_total += expected
            logged_total += min(logged, expected)

    marked = linked = 0
    for finding, _, entry in rows:
        if not entry or not entry.get("evidence"):
            continue
        in_finding = {i for hit in finding.hits for i in hit.evidence}
        marked += len(entry["evidence"])
        linked += len(in_finding & set(entry["evidence"]))

    flagged = [f for f, _, _ in rows if f.verdict == "Noteworthy"]
    explained = sum(1 for f in flagged if _explains_everything(f))

    benign_total = fp + tn
    misses = [
        {
            "session_id": f.session.session_id,
            "run": sorted({run_of[i].meta["run_id"] for i in f.session.event_ids})[0],
            "kind": "missed attack" if label == "malicious" else "false alarm",
            "verdict": f.verdict,
            "score": f.score,
            "reason": _why_missed(f, noteworthy) if label == "malicious" else f.explanation,
        }
        for f, label, _ in rows
        if (label == "malicious") != (f.verdict == "Noteworthy")
    ]
    metrics = {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "event_coverage": _ratio(logged_total, expected_total),
        "false_positives": fp,
        "false_positives_per_100_benign": None if benign_total == 0 else 100 * fp / benign_total,
        "evidence_completeness": _ratio(linked, marked),
        "explanation_quality": _ratio(explained, len(flagged)),
    }
    return {
        "root": str(root),
        "runs": len(runs),
        "events": len(events),
        "sessions": len(rows),
        "mixed_label_sessions": mixed,
        "confusion": {"tp": tp, "fn": fn, "fp": fp, "tn": tn},
        "metrics": metrics,
        "targets": {k: _meets(k, metrics[k]) for k in TARGETS},
        "misses": misses,
    }


def _meets(name: str, value: float | None) -> str:
    if value is None:
        return "not measured"
    op, target = TARGETS[name]
    ok = value >= target if op == ">=" else value == target
    return "met" if ok else "missed"


def _fmt(value: float | None, percent: bool = False) -> str:
    if value is None:
        return "not measured"
    return f"{value:.0%}" if percent else f"{value:.2f}"


ROWS = [
    ("precision", "precision", False, "0.90 or more"),
    ("recall", "recall", False, "0.90 or more"),
    ("f1", "F1", False, ""),
    ("event_coverage", "event coverage", True, "100%"),
    ("false_positives", "false positives", None, "0 on benign"),
    ("false_positives_per_100_benign", "  per 100 benign", False, ""),
    ("evidence_completeness", "evidence completeness", True, "95% or more"),
    ("explanation_quality", "explanation quality", True, "100%"),
]


def render(report: dict[str, Any]) -> str:
    m, c = report["metrics"], report["confusion"]
    lines = [
        f"Evaluated {report['runs']} runs, {report['events']} events, "
        f"{report['sessions']} sessions from {report['root']}",
        "",
        "                    predicted Noteworthy   not Noteworthy",
        f"actually malicious  {c['tp']:>20}   {c['fn']:>14}",
        f"actually benign     {c['fp']:>20}   {c['tn']:>14}",
        "",
    ]
    for key, label, percent, target in ROWS:
        value = m[key] if percent is not None else str(m[key])
        shown = value if percent is None else _fmt(m[key], percent)
        status = f"[{report['targets'][key]}]" if key in TARGETS else ""
        goal = f"target {target}" if target else ""
        lines.append(f"{label:<22} {shown:>13}   {goal:<22} {status}".rstrip())
    if report["mixed_label_sessions"]:
        lines += [
            "",
            f"warning: {report['mixed_label_sessions']} session(s) mix events from runs with "
            "different labels; label them in the dashboard",
        ]
    if report["misses"]:
        lines += ["", "Misses and false alarms:"]
        for miss in report["misses"]:
            lines.append(
                f"- {miss['kind']}: {miss['session_id']} in run {miss['run']}: "
                f"{miss['verdict']} {miss['score']}. {miss['reason']}"
            )
    return "\n".join(lines)
