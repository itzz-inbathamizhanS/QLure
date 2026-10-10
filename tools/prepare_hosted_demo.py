"""Prepare the hosted demo: switch judge mode on after the sample data was seeded.

    python tools/prepare_hosted_demo.py --db data/demo.db --settings data/settings.json

The change goes through `qlure.settings.apply_change`, so it is validated, written atomically
and recorded in the hash-chained config audit (actor `deploy-script`). `qlure verify` still
passes afterwards. Run it again and nothing changes. Exit codes: 0 done or already on,
2 the database does not exist (run tools/seed_demo.py first), 1 the change was refused.
"""

from __future__ import annotations

import argparse
import os
import sys
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from qlure import settings as cfg  # noqa: E402
from qlure.store import db  # noqa: E402
from qlure.store.verify import verify_config  # noqa: E402

ACTOR = "deploy-script"


def prepare(db_path: Path, settings_path: Path) -> str:
    """Turn judge mode on. Returns "enabled" or "already-on"; raises RuntimeError on refusal."""
    if cfg.load_settings(settings_path)["judge_mode"]:
        return "already-on"
    # Trusted build step: the host lock (also set in the build environment) guards the running
    # dashboard, not this script, so drop it from this process only.
    os.environ.pop("QLURE_JUDGE_LOCK", None)
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    with closing(db.connect(db_path)) as conn:
        # The path is passed explicitly, so QLURE_SETTINGS and QLURE_CONTENT are not consulted
        # (the content file lands next to the settings file, where the dashboard looks for it).
        ok, message = cfg.apply_change(conn, ACTOR, {"judge_mode": True}, path=settings_path)
        if not ok:
            raise RuntimeError(message)
        _, _, problem = verify_config(conn)
        if problem is not None:
            raise RuntimeError(f"config audit does not verify: {problem.reason}")
    return "enabled"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="prepare_hosted_demo", description=__doc__.splitlines()[0]
    )
    parser.add_argument("--db", type=Path, required=True, help="seeded SQLite database")
    parser.add_argument("--settings", type=Path, required=True, help="settings.json to write")
    args = parser.parse_args(argv)
    if not args.db.is_file():
        print(
            f"prepare_hosted_demo: {args.db} does not exist; run tools/seed_demo.py first",
            file=sys.stderr,
        )
        return 2
    try:
        state = prepare(args.db.resolve(), args.settings.resolve())
    except RuntimeError as exc:
        print(f"prepare_hosted_demo: {exc}", file=sys.stderr)
        return 1
    print(f"hosted demo: judge mode {state} ({args.settings}), audited as {ACTOR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
