"""The learned second opinion, on runs recorded from the real decoys."""

import json

import pytest
from fastapi.testclient import TestClient

from dashboard.app import create_app
from decoys.web.app import app as web_app
from qlure import capture, evaluate
from qlure.cli import main
from qlure.correlate import store as correlate_store
from qlure.correlate.engine import correlate
from qlure.events import Event
from qlure.ml import model as ml
from qlure.ml.features import FEATURES, extract
from qlure.store import db, forwarder

FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
SAFARI = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/17.5"
SCAN = [
    "/wp-login.php",
    "/phpmyadmin/",
    "/.git/config",
    "/backup/config.bak",
    "/.env",
    "/xmlrpc.php",
]


def visit(ip, agent, paths, logins=0, users=("ops",)):
    client = TestClient(web_app, client=(ip, 40404))
    client.headers["user-agent"] = agent
    for path in paths:
        client.get(path)
    for i in range(logins):
        client.post("/login", data={"username": users[i % len(users)], "password": f"pw-{i}"})


def record(root, split, ip, label, tool, agent, paths, logins=0, users=("ops",)):
    state = root / "state.json"
    capture.start("tester", tool, label, split, src_ip=ip, state=state)
    visit(ip, agent, paths, logins, users)
    return capture.stop(root / "logs", root / "captures", state=state)


def make_capture(tmp_path, monkeypatch, split="tuning", offset=0):
    """Eight attacks of different kinds and eight ordinary visits, all through the decoy."""
    monkeypatch.setenv("QLURE_LOG_DIR", str(tmp_path / "logs"))
    for i in range(8):
        ip = f"198.51.100.{offset + i + 1}"
        agent = ("curl/8.5.0", "python-requests/2.31", "Nikto/2.5.0", "Hydra/9.5")[i % 4]
        if i % 2 == 0:
            record(tmp_path, split, ip, "malicious", "scan", agent, SCAN, 3)
        else:
            record(tmp_path, split, ip, "malicious", "guess", agent, ["/login"], 8, ("a", "b", "c"))
    for i in range(8):
        ip = f"203.0.113.{offset + i + 1}"
        agent = (FIREFOX, SAFARI)[i % 2]
        paths = ["/login"] if i % 3 else ["/login", "/"]
        record(tmp_path, split, ip, "benign", "browse", agent, paths, 1 if i % 4 == 0 else 0)
    return tmp_path / "captures" / split


def sessions_and_labels(root):
    _, _, rows, _ = evaluate.labelled(root)
    return (
        [f.session for f, _, _ in rows],
        [int(label == "malicious") for _, label, _ in rows],
        rows,
    )


@pytest.fixture
def tuning(tmp_path, monkeypatch):
    return make_capture(tmp_path, monkeypatch)


def test_features_have_one_number_per_name_and_no_tool_or_address(tuning):
    sessions, _, _ = sessions_and_labels(tuning)
    assert all(len(extract(s)) == len(FEATURES) for s in sessions)
    assert not any("agent" in f or "ip" in f.split("_") for f in FEATURES)
    assert "pqc" not in " ".join(FEATURES)


def test_training_separates_attacks_from_ordinary_visits_and_is_repeatable(tuning):
    sessions, labels, _ = sessions_and_labels(tuning)
    first = ml.train(sessions, labels, ["r1"])
    again = ml.train(sessions, labels, ["r1"])
    assert first.weights == again.weights and first.bias == again.bias  # no randomness
    scores = [first.probability(s) for s in sessions]
    attacks = [p for p, y in zip(scores, labels, strict=True) if y]
    benign = [p for p, y in zip(scores, labels, strict=True) if not y]
    assert min(attacks) > max(benign)  # on its own training sessions
    assert first.meta["malicious"] == 8 and first.meta["benign"] == 8


def test_every_score_comes_with_its_biggest_factors(tuning):
    sessions, labels, _ = sessions_and_labels(tuning)
    model = ml.train(sessions, labels, ["r1"])
    brute = next(s for s, y in zip(sessions, labels, strict=True) if y and len(s.events) > 12)
    text = model.explain(brute)
    assert text.startswith("Model: ") and "Biggest factors" in text and "malicious" in text


def test_too_little_or_one_sided_data_is_refused(tuning):
    sessions, labels, _ = sessions_and_labels(tuning)
    with pytest.raises(ml.NotEnoughData):
        ml.train(sessions[:4], labels[:4], [])
    with pytest.raises(ml.NotEnoughData):
        ml.train(sessions, [1] * len(sessions), [])


def test_model_file_round_trips_and_unfit_files_are_ignored(tuning, tmp_path):
    sessions, labels, _ = sessions_and_labels(tuning)
    model = ml.train(sessions, labels, ["r1"])
    path = tmp_path / "model.json"
    path.write_text(model.to_json())
    loaded = ml.load(path)
    assert loaded and loaded.probability(sessions[0]) == model.probability(sessions[0])
    data = json.loads(path.read_text())
    data["features"] = data["features"][:-1]
    path.write_text(json.dumps(data))
    assert ml.load(path) is None and ml.load(tmp_path / "missing.json") is None


def test_cli_trains_on_tuning_only_and_eval_flags_reused_runs(
    tuning, tmp_path, monkeypatch, capsys
):
    out = tmp_path / "model.json"
    assert main(["ml", "train", str(tuning), "--out", str(out)]) == 0
    held = tmp_path / "held" / "heldout"
    held.mkdir(parents=True)
    assert main(["ml", "train", str(held), "--out", str(out)]) == 1
    assert "tuning captures only" in capsys.readouterr().err

    # The model on the runs it learned from: numbers must be marked as not valid.
    assert main(["eval", str(tuning), "--model", str(out)]) == 0
    assert "NOT VALID" in capsys.readouterr().out

    # Fresh runs it never saw: valid, and it still separates them.
    fresh = make_capture(tmp_path / "second", monkeypatch, split="heldout", offset=50)
    report = evaluate.evaluate(fresh, ml.load(out))
    model_report = report["model"]
    assert model_report["valid"] is True
    assert model_report["recall"] == 1.0 and model_report["precision"] == 1.0


def test_dashboard_shows_the_score_and_flags_disagreement(tuning, tmp_path, monkeypatch):
    sessions, labels, _ = sessions_and_labels(tuning)
    model_path = tmp_path / "model.json"
    model_path.write_text(ml.train(sessions, labels, ["r1"]).to_json())
    monkeypatch.setenv("QLURE_MODEL", str(model_path))
    monkeypatch.setenv("QLURE_DASHBOARD_PASSWORD", "pw")
    monkeypatch.setenv("QLURE_SETTINGS", str(tmp_path / "settings.json"))

    logs = tmp_path / "logs"
    conn = db.connect(tmp_path / "q.db")
    forwarder.forward_once(conn, logs)
    correlate_store.run(conn)
    rows = conn.execute("SELECT ml_score, ml_why FROM findings").fetchall()
    assert all(r["ml_score"] is not None and r["ml_why"].startswith("Model:") for r in rows)

    client = TestClient(create_app(tmp_path / "q.db", logs))
    client.post("/login", data={"password": "pw"})
    assert "Model" in client.get("/").text
    sid = conn.execute("SELECT session_id FROM findings ORDER BY ml_score DESC").fetchone()[0]
    page = client.get(f"/session/{sid}").text
    assert "Model second opinion" in page and "never changes the verdict" in page

    # Without a model the pages say so and the rules are unaffected.
    monkeypatch.setenv("QLURE_MODEL", str(tmp_path / "none.json"))
    correlate_store.run(conn)
    assert (
        conn.execute("SELECT COUNT(*) FROM findings WHERE ml_score IS NOT NULL").fetchone()[0] == 0
    )
    assert "No model trained yet" in client.get(f"/session/{sid}").text


def test_the_model_never_changes_a_verdict(tuning, tmp_path, monkeypatch):
    events = [
        Event.model_validate_json(line)
        for path in sorted((tmp_path / "logs").glob("*.jsonl"))
        for line in path.read_text().splitlines()
    ]
    without = [(f.session.session_id, f.verdict, f.score) for f in correlate(events).findings]
    sessions, labels, _ = sessions_and_labels(tuning)
    model_path = tmp_path / "model.json"
    model_path.write_text(ml.train(sessions, labels, ["r1"]).to_json())
    monkeypatch.setenv("QLURE_MODEL", str(model_path))
    with_model = [(f.session.session_id, f.verdict, f.score) for f in correlate(events).findings]
    assert with_model == without
