"""emit(): the only way a decoy writes an event."""

from __future__ import annotations

import os
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from qlure.events.schema import Event

_lock = threading.Lock()


def log_dir() -> Path:
    return Path(os.environ.get("QLURE_LOG_DIR", "logs"))


def emit(event: dict[str, Any], directory: Path | None = None) -> Event:
    """Validate an event, stamp `event_id` and `ts`, and append it to `<service>.jsonl`.

    Raises pydantic.ValidationError if the event does not match the schema, so a
    decoy can never write a malformed line.
    """
    data = dict(event)
    data.setdefault("event_id", uuid.uuid4().hex)
    data.setdefault("ts", datetime.now(UTC))
    validated = Event.model_validate(data)

    target_dir = directory or log_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    line = validated.model_dump_json(exclude_none=True) + "\n"
    path = target_dir / f"{validated.service.value}.jsonl"
    with _lock, path.open("a", encoding="utf-8") as fh:
        fh.write(line)
    return validated
