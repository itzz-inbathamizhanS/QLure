import pytest


@pytest.fixture
def log_dir(tmp_path, monkeypatch):
    """Point every emit() call at a fresh directory for the test."""
    monkeypatch.setenv("QLURE_LOG_DIR", str(tmp_path))
    return tmp_path
