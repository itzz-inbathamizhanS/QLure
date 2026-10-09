import pytest

from qlure.events import Event


@pytest.fixture
def log_dir(tmp_path, monkeypatch):
    """Point every emit() call at a fresh directory for the test."""
    monkeypatch.setenv("QLURE_LOG_DIR", str(tmp_path))
    return tmp_path


@pytest.fixture
def read_events(log_dir):
    """Return a function that reads and validates one service's log file."""

    def read(service: str) -> list[Event]:
        path = log_dir / f"{service}.jsonl"
        if not path.exists():
            return []
        return [Event.model_validate_json(line) for line in path.read_text().splitlines()]

    return read
