"""Capture, replay and eval, on a tiny capture recorded from the real decoys."""

import json

import pytest
from fastapi.testclient import TestClient

from decoys.web.app import app as web_app
from qlure import capture, evaluate, replay
from qlure.cli import main
from qlure.correlate.engine import correlate
from qlure.events import Event

FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"


def visit(ip, agent, paths, logins=0):
    client = TestClient(web_app, client=(ip, 40404))
    client.headers["user-agent"] = agent
    for path in paths:
        client.get(path)
    for i in range(logins):
        client.post("/login", data={"username": "ops", "password": f"guess-{i}"})


def record(tmp_path, ip, label, tool, agent, paths, logins=0, interactions=None):
    state = tmp_path / "active.json"
    capture.start("tester", tool, label, "heldout", src_ip=ip, state=state)
    visit(ip, agent, paths, logins)
    return capture.stop(
        tmp_path / "logs", tmp_path / "captures", interactions=interactions, state=state
    )


@pytest.fixture
def recorded(tmp_path, monkeypatch):
    """Three attacks (one too quiet to catch) and three ordinary visits, all through the decoy."""
    monkeypatch.setenv("QLURE_LOG_DIR", str(tmp_path / "logs"))
    scan = ["/wp-login.php", "/phpmyadmin/", "/backup/config.bak", "/.env"]
    runs = {
        "m1": record(
            tmp_path, "198.51.100.1", "malicious", "nikto", "Nikto/2.5.0", scan, 6, {"web": 10}
        ),
        "m2": record(
            tmp_path, "198.51.100.2", "malicious", "hydra", "Hydra/9.5", ["/backup/config.bak"], 6
        ),
        "m3": record(tmp_path, "198.51.100.3", "malicious", "probe", FIREFOX, ["/wp-login.php"]),
        "b1": record(tmp_path, "203.0.113.1", "benign", "browse", FIREFOX, ["/login"]),
        "b2": record(tmp_path, "203.0.113.2", "benign", "typo", "Safari/17", ["/login"], 1),
        "b3": record(tmp_path, "203.0.113.3", "benign", "browse", "Edge/130", ["/login", "/"]),
    }
    return tmp_path / "captures", runs


def test_capture_keeps_only_the_labelled_window_and_visitor(tmp_path, monkeypatch):
    monkeypatch.setenv("QLURE_LOG_DIR", str(tmp_path / "logs"))
    visit("198.51.100.9", FIREFOX, ["/login"])  # before the run: must not be included
    run = record(tmp_path, "198.51.100.4", "benign", "browse", FIREFOX, ["/login"])
    visit("198.51.100.5", FIREFOX, ["/login"])  # another visitor after the run
    meta = json.loads((run / "run.json").read_text())
    events = [Event.model_validate_json(x) for x in (run / "events.jsonl").read_text().splitlines()]
    assert meta["label"] == "benign" and meta["split"] == "heldout" and meta["who"] == "tester"
    assert {e.src_ip for e in events} == {"198.51.100.4"} and len(events) == meta["event_count"]


def test_capture_refuses_bad_state(tmp_path):
    state = tmp_path / "active.json"
    with pytest.raises(capture.CaptureError):
        capture.stop(tmp_path, tmp_path, state=state)
    capture.start("a", "t", "benign", "tuning", state=state)
    with pytest.raises(capture.CaptureError):
        capture.start("b", "t", "benign", "tuning", state=state)
    with pytest.raises(capture.CaptureError):
        capture.start("b", "t", "good", "tuning", state=tmp_path / "other.json")


def test_eval_matches_the_numbers_worked_out_by_hand(recorded):
    root, _ = recorded
    report = evaluate.evaluate(root)
    # Hand count: m1 and m2 are caught, m3 (one request) is missed, the three visits are quiet.
    assert report["confusion"] == {"tp": 2, "fn": 1, "fp": 0, "tn": 3}
    m = report["metrics"]
    assert m["precision"] == 1.0
    assert m["recall"] == pytest.approx(2 / 3)
    assert m["f1"] == pytest.approx(0.8)
    assert m["false_positives"] == 0 and m["false_positives_per_100_benign"] == 0
    assert m["event_coverage"] == 1.0  # m1 sent 10 requests and 10 http_request events exist
    assert m["explanation_quality"] == 1.0
    assert m["evidence_completeness"] is None  # nobody marked evidence yet
    assert report["targets"]["recall"] == "missed" and report["targets"]["precision"] == "met"
    assert report["targets"]["evidence_completeness"] == "not measured"
    (miss,) = report["misses"]
    assert miss["kind"] == "missed attack" and "run" in miss and "m3" not in miss["run"]
    assert "probe" in miss["run"] and "below" in miss["reason"]


def test_coverage_counts_a_missing_event(recorded):
    root, runs = recorded
    meta_path = runs["m1"] / "run.json"
    meta = json.loads(meta_path.read_text())
    meta["expected_interactions"] = {"web": 12}  # the packet capture saw two more requests
    meta_path.write_text(json.dumps(meta))
    assert evaluate.evaluate(root)["metrics"]["event_coverage"] == pytest.approx(10 / 12)


def test_evidence_completeness_from_marked_events(recorded):
    root, runs = recorded
    events = [
        Event.model_validate_json(x) for x in (runs["m1"] / "events.jsonl").read_text().splitlines()
    ]
    finding = correlate(events).findings[0]
    in_hits = {i for h in finding.hits for i in h.evidence}
    other = (runs["b1"] / "events.jsonl").read_text().splitlines()[0]
    outside = Event.model_validate_json(other).event_id  # evidence marked on the wrong session
    inside = sorted(in_hits)[:3]
    (runs["m1"] / "labels.json").write_text(
        json.dumps(
            [
                {
                    "session_id": finding.session.session_id,
                    "label": "malicious",
                    "evidence": [*inside, outside],
                    "event_ids": finding.session.event_ids,
                }
            ]
        )
    )
    assert evaluate.evaluate(root)["metrics"]["evidence_completeness"] == pytest.approx(3 / 4)


def test_a_benign_label_on_a_noteworthy_session_is_a_false_alarm(recorded):
    root, runs = recorded
    meta_path = runs["m2"] / "run.json"
    meta = json.loads(meta_path.read_text())
    meta["label"] = "benign"
    meta_path.write_text(json.dumps(meta))
    report = evaluate.evaluate(root)
    assert report["confusion"]["fp"] == 1
    assert report["metrics"]["false_positives_per_100_benign"] == pytest.approx(100 / 4)
    assert any(m["kind"] == "false alarm" for m in report["misses"])


def test_eval_cli_prints_the_table_and_strict_fails_on_missed_targets(recorded, capsys, tmp_path):
    root, _ = recorded
    out = tmp_path / "report.json"
    assert main(["eval", str(root), "--json", str(out)]) == 0
    text = capsys.readouterr().out
    assert "precision" in text and "missed attack" in text
    assert json.loads(out.read_text())["confusion"]["tp"] == 2
    assert main(["eval", str(root), "--strict"]) == 1


HAR = {
    "log": {
        "entries": [
            {
                "startedDateTime": "2025-03-01T10:00:00Z",
                "request": {
                    "method": "GET",
                    "url": "http://shop.example/wp-login.php",
                    "headers": [{"name": "User-Agent", "value": "sqlmap/1.8"}],
                },
            },
            {
                "startedDateTime": "2025-03-01T09:59:00Z",
                "request": {
                    "method": "POST",
                    "url": "http://shop.example/login",
                    "headers": [{"name": "User-Agent", "value": "sqlmap/1.8"}],
                    "postData": {"text": "username=a&password=b"},
                },
            },
        ]
    }
}


def test_replay_keeps_original_times_for_har_jsonl_and_csv(
    tmp_path, log_dir, monkeypatch, read_events
):
    monkeypatch.setenv("QLURE_REPLAY_TOKEN", "replay-secret")
    har = tmp_path / "t.har"
    har.write_text(json.dumps(HAR))
    jsonl = tmp_path / "t.jsonl"
    jsonl.write_text(
        '{"ts": 1740823200, "method": "GET", "path": "/.env", '
        '"headers": {"User-Agent": "curl/8"}}\n'
    )
    csv_file = tmp_path / "t.csv"
    csv_file.write_text(
        "timestamp,method,url,user_agent,body\n2025-03-01T10:05:00+00:00,GET,/admin,Wget/1.21,\n"
    )
    client = TestClient(web_app, client=("198.51.100.20", 40404), follow_redirects=False)
    for path in (har, jsonl, csv_file):
        summary = replay.run(
            replay.load(path), "http://testserver", "http://testserver", "replay-secret", client
        )
        assert summary.failed == 0
    events = read_events("web")
    requests = [e for e in events if e.action.value == "http_request"]
    assert len(requests) == 4 and all(e.replay_ts is not None for e in requests)
    stamps = [e.replay_ts.isoformat() for e in requests]
    assert stamps[0].startswith("2025-03-01T09:59:00")  # sorted by original time, POST first
    assert stamps[1].startswith("2025-03-01T10:00:00")
    assert "x-qlure-replay-token" not in json.dumps(requests[0].request)


def test_visitors_cannot_choose_their_own_replay_time(log_dir, monkeypatch, read_events):
    visitor = TestClient(web_app, client=("198.51.100.21", 40404))
    headers = {"x-qlure-replay-ts": "2020-01-01T00:00:00+00:00", "x-qlure-replay-token": "guess"}
    visitor.get("/login", headers=headers)
    monkeypatch.setenv("QLURE_REPLAY_TOKEN", "real-token")
    visitor.get("/login", headers=headers)
    assert all(e.replay_ts is None for e in read_events("web"))


def test_replay_needs_a_token_and_a_known_format(tmp_path):
    with pytest.raises(replay.ReplayError):
        replay.run([], "http://x", "http://x", "")
    bad = tmp_path / "t.txt"
    bad.write_text("x")
    with pytest.raises(replay.ReplayError):
        replay.load(bad)


def test_eval_reports_missing_capture_data_without_a_traceback(tmp_path, capsys):
    run_dir = tmp_path / "run-1"
    run_dir.mkdir()
    (run_dir / "run.json").write_text("{}", encoding="utf-8")
    assert main(["eval", str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert err.startswith("eval: capture data missing")
    assert "qlure capture" in err
    assert "Traceback" not in err
