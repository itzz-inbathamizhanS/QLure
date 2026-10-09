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


def _actor_flagged(finding: Finding) -> bool:
    """True when this session only counts as Noteworthy because of its actor's combined score."""
    return finding.effective_verdict == "Noteworthy" and finding.verdict != "Noteworthy"


def _explains_everything(finding: Finding) -> bool:
    hits, text = (
        (finding.actor_hits, finding.actor_explanation)
        if _actor_flagged(finding)
        else (finding.hits, finding.explanation)
    )
    if not hits:
        return False
    return all(
        hit.rule_id in text
        and hit.threshold in text
        and hit.measured in text
        and hit.evidence
        and hit.evidence[0] in text
        for hit in hits
    )


def labelled(root: Path) -> tuple[list[Run], dict[str, Run], list[tuple[Finding, str, Any]], int]:
    """Correlate every run in `root` and attach a label to each session.

    Returns (runs, event_id -> run, [(finding, label, label entry)], mixed-label session count).
    """
    runs = load_runs(root)
    events: dict[str, Event] = {}
    run_of: dict[str, Run] = {}
    for run in runs:
        for event in run.events:
            events[event.event_id] = event
            run_of[event.event_id] = run
    result = correlate(list(events.values()))

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

    return runs, run_of, rows, mixed


def evaluate(root: Path, model: Any = None) -> dict[str, Any]:
    runs, run_of, rows, mixed = labelled(root)
    events = {e.event_id: e for run in runs for e in run.events}
    noteworthy = load_config()["verdicts"]["noteworthy"]

    tp = sum(
        1 for f, label, _ in rows if label == "malicious" and f.effective_verdict == "Noteworthy"
    )
    fn = sum(
        1 for f, label, _ in rows if label == "malicious" and f.effective_verdict != "Noteworthy"
    )
    fp = sum(1 for f, label, _ in rows if label == "benign" and f.effective_verdict == "Noteworthy")
    tn = sum(1 for f, label, _ in rows if label == "benign" and f.effective_verdict != "Noteworthy")
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
        # The same hits the verdict rests on: the actor's when only the actor made it Noteworthy.
        hits = finding.actor_hits if _actor_flagged(finding) else finding.hits
        in_finding = {i for hit in hits for i in hit.evidence}
        marked += len(entry["evidence"])
        linked += len(in_finding & set(entry["evidence"]))

    flagged = [f for f, _, _ in rows if f.effective_verdict == "Noteworthy"]
    explained = sum(1 for f in flagged if _explains_everything(f))

    benign_total = fp + tn
    misses = [
        {
            "session_id": f.session.session_id,
            "run": sorted({run_of[i].meta["run_id"] for i in f.session.event_ids})[0],
            "kind": "missed attack" if label == "malicious" else "false alarm",
            "verdict": f.effective_verdict,
            "score": f.score,
            "reason": _why_missed(f, noteworthy) if label == "malicious" else f.explanation,
        }
        for f, label, _ in rows
        if (label == "malicious") != (f.effective_verdict == "Noteworthy")
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
        "model": _model_report(model, runs, rows),
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


def _model_report(model: Any, runs: list[Run], rows: list[Any]) -> dict[str, Any] | None:
    """How the learned model does on the same labelled sessions, or None without a model."""
    if model is None:
        return None
    seen = {run.meta["run_id"] for run in runs}
    overlap = sorted(set(model.meta.get("run_ids", [])) & seen)
    tp = fp = fn = tn = 0
    disagreements = []
    for finding, label, _ in rows:
        flagged = model.probability(finding.session) >= 0.5
        malicious = label == "malicious"
        tp += flagged and malicious
        fp += flagged and not malicious
        fn += (not flagged) and malicious
        tn += (not flagged) and not malicious
        if flagged != (finding.effective_verdict == "Noteworthy"):
            disagreements.append(
                {
                    "session_id": finding.session.session_id,
                    "label": label,
                    "rules": finding.effective_verdict,
                    "model": round(model.probability(finding.session), 2),
                }
            )
    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = None
    if precision is not None and recall is not None and precision + recall:
        f1 = 2 * precision * recall / (precision + recall)
    return {
        "valid": not overlap,
        "trained_on_runs_seen_again": overlap,
        "confusion": {"tp": tp, "fn": fn, "fp": fp, "tn": tn},
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "disagreements_with_rules": disagreements,
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
    mod = report.get("model")
    if mod:
        c2 = mod["confusion"]
        lines += [
            "",
            "Learned model (second opinion, flags at 50% or more):",
            f"  caught {c2['tp']}, missed {c2['fn']}, false alarms {c2['fp']}, "
            f"correct benign {c2['tn']}",
            f"  precision {_fmt(mod['precision'])}   recall {_fmt(mod['recall'])}   "
            f"F1 {_fmt(mod['f1'])}",
            f"  disagrees with the rules on {len(mod['disagreements_with_rules'])} sessions",
        ]
        if not mod["valid"]:
            lines.append(
                f"  NOT VALID: {len(mod['trained_on_runs_seen_again'])} of these runs were in the "
                "training data; evaluate on held-out runs only"
            )
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
