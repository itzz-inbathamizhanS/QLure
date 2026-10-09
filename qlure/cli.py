"""qlure command line.

`schema`, `validate`, `forward` and `verify` so far; capture, replay and eval arrive later.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from qlure.events import Event, json_schema
from qlure.store import db, forwarder
from qlure.store.verify import verify

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
    checked, problem = verify(db.connect(args.db), args.logs)
    if problem is None:
        print(f"chain verified: {checked} events intact")
        return 0
    print(
        f"VERIFY FAILED at event {problem.event_id} (#{problem.seq}): {problem.reason}",
        file=sys.stderr,
    )
    return 1


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

    for name, func, help_text in (
        ("forward", _forward, "copy new JSONL events into the store"),
        ("verify", _verify, "check the hash chain against the JSONL archive"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--logs", type=Path, default=DEFAULT_LOGS)
        p.add_argument("--db", type=Path, default=DEFAULT_DB)
        if name == "forward":
            p.add_argument("--follow", action="store_true", help="keep running")
        p.set_defaults(func=func)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
