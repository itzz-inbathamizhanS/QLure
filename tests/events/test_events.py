import json

import pytest
from pydantic import ValidationError

from qlure.cli import main as cli
from qlure.events import Action, Event, Service, emit


def _event(action, service=Service.WEB, **extra):
    return {
        "service": service,
        "src_ip": "192.0.2.10",
        "src_port": 51515,
        "session_id": "s1",
        "action": action,
        **extra,
    }


def test_emit_every_action_type_writes_a_valid_line(log_dir):
    for action in Action:
        emit(_event(action))
    lines = (log_dir / "web.jsonl").read_text().splitlines()
    assert len(lines) == len(Action) == 10
    events = [Event.model_validate_json(line) for line in lines]
    assert [e.action for e in events] == list(Action)
    assert len({e.event_id for e in events}) == 10
    assert all(e.ts.tzinfo is not None for e in events)


def test_emit_writes_one_file_per_service(log_dir):
    emit(_event(Action.CONNECT, Service.SSH))
    emit(_event(Action.BANNER, Service.REDIS))
    assert sorted(p.name for p in log_dir.iterdir()) == ["redis.jsonl", "ssh.jsonl"]


def test_emit_rejects_invalid_events_without_writing(log_dir):
    with pytest.raises(ValidationError):
        emit(_event("rm -rf"))
    with pytest.raises(ValidationError):
        emit(_event(Action.CONNECT, src_ip="not-an-ip"))
    with pytest.raises(ValidationError):
        emit(_event(Action.CONNECT, unknown_field=1))
    assert not (log_dir / "web.jsonl").exists()


def test_pqc_fields_only_on_ssh(log_dir):
    emit(
        _event(Action.CONNECT, Service.SSH, pqc_capable=True, kex_offered=["mlkem768x25519-sha256"])
    )
    with pytest.raises(ValidationError):
        emit(_event(Action.CONNECT, Service.WEB, pqc_capable=True))


def test_committed_json_schema_is_current(monkeypatch, request):
    monkeypatch.chdir(request.config.rootpath)
    assert cli(["schema", "--check"]) == 0


def test_validate_command_flags_bad_lines(log_dir, capsys):
    emit(_event(Action.CONNECT))
    path = log_dir / "web.jsonl"
    assert cli(["validate", str(path)]) == 0
    with path.open("a") as fh:
        fh.write(json.dumps({"action": "connect"}) + "\n")
    assert cli(["validate", str(path)]) == 1
    assert "1/2 events valid" in capsys.readouterr().out
