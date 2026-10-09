"""qlure command line.

Event schema, forwarder and verify, correlation, capture/replay/eval, and signed checkpoints.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from pydantic import ValidationError

from qlure import capture as capture_runs
from qlure import evaluate as evaluation
from qlure import replay as replay_requests
from qlure.correlate import store as correlate_store
from qlure.correlate.ioc import IOCSet, match_event
from qlure.events import Event, json_schema
from qlure.ml import model as ml_model
from qlure.pqc import signing
from qlure.store import db, forwarder
from qlure.store.verify import verify, verify_config
from qlure.watch.egress import watch as watch_egress

SCHEMA_PATH = Path("docs/event.schema.json")
DEFAULT_LOGS = Path("logs")
DEFAULT_DB = Path("data/qlure.db")


def _schema(args: argparse.Namespace) -> int:
    text = json.dumps(json_schema(), indent=2) + "\n"
    if args.check:
        current = args.out.read_text(encoding="utf-8") if args.out.exists() else ""
        if current != text:
            print(f"{args.out} is out of date; run `qlure schema`", file=sys.stderr)
            return 1
        return 0
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text, encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


def _validate(args: argparse.Namespace) -> int:
    bad = 0
    total = 0
    for path in args.files:
        with path.open(encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                total += 1
                try:
                    Event.model_validate_json(line)
                except ValidationError as exc:
                    bad += 1
                    print(f"{path}:{lineno}: {exc.errors()[0]['msg']}", file=sys.stderr)
    print(f"{total - bad}/{total} events valid")
    return 1 if bad else 0


def _forward(args: argparse.Namespace) -> int:
    conn = db.connect(args.db)
    if args.follow:
        forwarder.follow(conn, args.logs)
        return 0
    stored, rejected = forwarder.forward_once(conn, args.logs)
    print(f"stored {stored} new events, rejected {rejected} invalid lines")
    return 0


def _verify(args: argparse.Namespace) -> int:
    conn = db.connect(args.db)
    checked, problem = verify(conn, args.logs)
    if problem is not None:
        print(
            f"VERIFY FAILED at event {problem.event_id} (#{problem.seq}): {problem.reason}",
            file=sys.stderr,
        )
        return 1
    print(f"chain verified: {checked} events intact")
    config_checked, legacy, config_problem = verify_config(conn)
    if config_problem is not None:
        print(
            f"VERIFY FAILED at config change #{config_problem.audit_id}: {config_problem.reason}",
            file=sys.stderr,
        )
        return 1
    note = f", {legacy} legacy row(s) from before chaining" if legacy else ""
    print(f"config audit verified: {config_checked} change(s) chained{note}")
    count = conn.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0]
    if not count:
        print("no signed checkpoints yet (see `qlure sign`)")
        return 0
    if not args.pub.exists():
        print(f"{count} signed checkpoints exist but were not checked: {args.pub} not found")
        return 0
    try:
        result = signing.verify_checkpoints(conn, args.pub)
    except signing.SigningUnavailable as exc:
        print(f"{count} signed checkpoints exist but were not checked: {exc}")
        return 0
    if result.problem:
        print(f"VERIFY FAILED: {result.problem}", file=sys.stderr)
        return 1
    print(f"{result.checked} {signing.ALGORITHM} checkpoints verified")
    return 0


def _keygen(args: argparse.Namespace) -> int:
    try:
        private, public = signing.keygen(args.out)
    except signing.SigningUnavailable as exc:
        print(f"keygen: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {private} (keep it off the decoy host) and {public}")
    return 0


def _sign(args: argparse.Namespace) -> int:
    try:
        made = signing.sign(
            db.connect(args.db), args.key, args.pub, every=args.every, include_head=args.head
        )
    except (signing.SigningUnavailable, FileNotFoundError) as exc:
        print(f"sign: {exc}", file=sys.stderr)
        return 1
    print(f"signed {made} new checkpoints")
    return 0


def _correlate(args: argparse.Namespace) -> int:
    result = correlate_store.run(db.connect(args.db))
    print(f"{len(result.sessions)} sessions, {len(result.actors)} actors")
    for f in result.findings[: args.top]:
        rules = ",".join(sorted({h.rule_id for h in f.hits}, key=lambda r: int(r[1:]))) or "-"
        where = f"{f.session.service:<6} {f.session.src_ip:<15}"
        print(f"{f.verdict:<10} {f.score:>3}  {f.actor_id}  {where} {rules}")
    if args.iocs:
        _print_ioc_context(result.sessions, IOCSet.load(args.iocs))
    return 0


def _print_ioc_context(sessions, iocs: IOCSet) -> None:
    """IOC matches are shown as context for the analyst. They never change a score."""
    print(f"IOC context ({len(iocs)} indicators, not scored):")
    matched = 0
    for session in sessions:
        hits = {
            hit
            for event in session.events
            for hit in match_event(event.model_dump(mode="json", exclude_none=True), iocs)
        }
        if hits:
            matched += 1
            values = ", ".join(sorted(f"{h.indicator_type}={h.value}" for h in hits))
            print(f"  {session.session_id} ({session.service}): {values}")
    print(f"{matched} session(s) matched an indicator")


def _watch_egress(args: argparse.Namespace) -> int:
    print(f"watching {args.proc_net} every {args.interval}s; alerts -> {args.out}", flush=True)
    try:
        watch_egress(args.out, args.proc_net, args.interval, args.iterations)
    except KeyboardInterrupt:
        pass
    return 0


def _capture(args: argparse.Namespace) -> int:
    try:
        if args.action == "start":
            run = capture_runs.start(
                args.who, args.tool, args.label, args.split, src_ip=args.src_ip, state=args.state
            )
            print(f"capture {run['run_id']} started ({args.label}, {args.split})")
        elif args.action == "stop":
            interactions = capture_runs.parse_interactions(args.interactions or "")
            target = capture_runs.stop(
                args.logs, args.captures, interactions=interactions, state=args.state
            )
            count = len((target / "events.jsonl").read_text(encoding="utf-8").splitlines())
            print(f"saved {count} events to {target}")
        else:
            count = capture_runs.export_labels(db.connect(args.db), args.run)
            print(f"wrote {count} labelled sessions to {args.run / 'labels.json'}")
    except (capture_runs.CaptureError, FileExistsError, FileNotFoundError) as exc:
        print(f"capture: {exc}", file=sys.stderr)
        return 1
    return 0


def _replay(args: argparse.Namespace) -> int:
    try:
        requests = replay_requests.load(args.file)
        summary = replay_requests.run(
            requests, args.web, args.api, os.environ.get("QLURE_REPLAY_TOKEN", "")
        )
    except replay_requests.ReplayError as exc:
        print(f"replay: {exc}", file=sys.stderr)
        return 1
    print(f"sent {summary.sent} requests, {summary.failed} failed")
    return 1 if summary.failed else 0


def _ml(args: argparse.Namespace) -> int:
    if "heldout" in {part.lower() for part in args.folder.resolve().parts}:
        print(
            "ml: train on tuning captures only; held-out data stays for evaluation", file=sys.stderr
        )
        return 1
    _, _, rows, _ = evaluation.labelled(args.folder)
    runs = {run.meta["run_id"] for run in evaluation.load_runs(args.folder)}
    try:
        model = ml_model.train(
            [f.session for f, _, _ in rows],
            [int(label == "malicious") for _, label, _ in rows],
            sorted(runs),
        )
    except ml_model.NotEnoughData as exc:
        print(f"ml: {exc}", file=sys.stderr)
        return 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(model.to_json(), encoding="utf-8")
    print(f"trained on {model.meta['sessions']} sessions from {len(runs)} runs; wrote {args.out}")
    return 0


def _eval(args: argparse.Namespace) -> int:
    model = ml_model.load(args.model) if args.model else None
    if args.model and model is None:
        print(f"eval: no usable model at {args.model}", file=sys.stderr)
        return 1
    report = evaluation.evaluate(args.folder, model)
    print(evaluation.render(report))
    if args.json:
        args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if args.strict and any(v != "met" for v in report["targets"].values()):
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="qlure")
    sub = parser.add_subparsers(dest="command", required=True)

    p_schema = sub.add_parser("schema", help="export the event JSON Schema")
    p_schema.add_argument("--out", type=Path, default=SCHEMA_PATH)
    p_schema.add_argument("--check", action="store_true", help="fail if the file is stale")
    p_schema.set_defaults(func=_schema)

    p_validate = sub.add_parser("validate", help="check JSONL event files against the schema")
    p_validate.add_argument("files", type=Path, nargs="+")
    p_validate.set_defaults(func=_validate)

    p_corr = sub.add_parser("correlate", help="group stored events into sessions and score them")
    p_corr.add_argument("--db", type=Path, default=DEFAULT_DB)
    p_corr.add_argument("--top", type=int, default=20, help="how many findings to print")
    p_corr.add_argument("--iocs", type=Path, default=None, help="STIX-like indicators JSON")
    p_corr.set_defaults(func=_correlate)

    p_watch = sub.add_parser("watch-egress", help="alert when a decoy opens outbound connections")
    p_watch.add_argument("--proc-net", type=Path, default=Path("/proc/net"))
    p_watch.add_argument("--out", type=Path, default=Path("data/egress.jsonl"))
    p_watch.add_argument("--interval", type=float, default=5.0)
    p_watch.add_argument("--iterations", type=int, default=None, help="stop after N polls")
    p_watch.set_defaults(func=_watch_egress)

    p_key = sub.add_parser("keygen", help="make an ML-DSA-65 key pair for signing checkpoints")
    p_key.add_argument("--out", type=Path, default=Path("data/signing"))
    p_key.set_defaults(func=_keygen)

    p_sign = sub.add_parser("sign", help="sign hash-chain checkpoints with ML-DSA-65")
    p_sign.add_argument("--db", type=Path, default=DEFAULT_DB)
    p_sign.add_argument("--key", type=Path, default=Path("data/signing.key"))
    p_sign.add_argument("--pub", type=Path, default=Path("data/signing.pub"))
    p_sign.add_argument("--every", type=int, default=signing.DEFAULT_EVERY)
    p_sign.add_argument("--head", action="store_true", help="also sign the newest event")
    p_sign.set_defaults(func=_sign)

    p_cap = sub.add_parser("capture", help="record a labelled capture run from the decoy logs")
    p_cap.add_argument("action", choices=["start", "stop", "labels"])
    p_cap.add_argument("run", type=Path, nargs="?", help="run folder (for `labels`)")
    p_cap.add_argument("--who", default="")
    p_cap.add_argument("--tool", default="")
    p_cap.add_argument("--label", choices=capture_runs.LABELS)
    p_cap.add_argument("--split", choices=capture_runs.SPLITS)
    p_cap.add_argument("--src-ip", help="keep only events from this visitor address")
    p_cap.add_argument(
        "--interactions", help="packet-capture counts for coverage, e.g. web=12,ssh=1"
    )
    p_cap.add_argument("--logs", type=Path, default=DEFAULT_LOGS)
    p_cap.add_argument("--captures", type=Path, default=Path("captures"))
    p_cap.add_argument("--db", type=Path, default=DEFAULT_DB)
    p_cap.add_argument("--state", type=Path, default=capture_runs.STATE)
    p_cap.set_defaults(func=_capture)

    p_rep = sub.add_parser("replay", help="send a HAR, JSONL or CSV request file to the decoys")
    p_rep.add_argument("file", type=Path)
    p_rep.add_argument("--web", default="http://127.0.0.1:8080")
    p_rep.add_argument("--api", default="http://127.0.0.1:8081")
    p_rep.set_defaults(func=_replay)

    p_ml = sub.add_parser("ml", help="train the learned second-opinion model on tuning captures")
    p_ml.add_argument("action", choices=["train"])
    p_ml.add_argument("folder", type=Path)
    p_ml.add_argument("--out", type=Path, default=ml_model.DEFAULT_PATH)
    p_ml.set_defaults(func=_ml)

    p_eval = sub.add_parser("eval", help="precision, recall and more on labelled captures")
    p_eval.add_argument("folder", type=Path)
    p_eval.add_argument("--json", type=Path, help="also write the report as JSON")
    p_eval.add_argument("--model", type=Path, help="also score the learned model (model.json)")
    p_eval.add_argument("--strict", action="store_true", help="exit 1 unless every target is met")
    p_eval.set_defaults(func=_eval)

    for name, func, help_text in (
        ("forward", _forward, "copy new JSONL events into the store"),
        ("verify", _verify, "check the hash chain against the JSONL archive"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--logs", type=Path, default=DEFAULT_LOGS)
        p.add_argument("--db", type=Path, default=DEFAULT_DB)
        if name == "forward":
            p.add_argument("--follow", action="store_true", help="keep running")
        if name == "verify":
            p.add_argument("--pub", type=Path, default=Path("data/signing.pub"))
        p.set_defaults(func=func)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
