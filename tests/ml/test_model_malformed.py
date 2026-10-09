"""A malformed model.json is treated as no model: load returns None and /refresh never 500s."""

import json

import pytest
from fastapi.testclient import TestClient

from dashboard.app import create_app
from qlure.ml import model as ml
from qlure.ml.features import FEATURES

PASSWORD = "test-password"


def _good() -> dict:
    k = len(FEATURES)
    return {
        "version": ml.VERSION,
        "features": list(FEATURES),
        "mean": [0.0] * k,
        "scale": [1.0] * k,
        "weights": [0.0] * k,
        "bias": 0.0,
        "meta": {"sessions": 10},
    }


def _mutations():
    k = len(FEATURES)
    yield "not an object", []
    yield "missing mean", {key: v for key, v in _good().items() if key != "mean"}
    yield "missing meta", {key: v for key, v in _good().items() if key != "meta"}
    yield "short weights", {**_good(), "weights": [0.0] * (k - 1)}
    yield "text in mean", {**_good(), "mean": ["x"] * k}
    yield "zero scale", {**_good(), "scale": [0.0] * k}
    yield "bool bias", {**_good(), "bias": True}
    yield "meta not a dict", {**_good(), "meta": "oops"}


@pytest.mark.parametrize("label,payload", list(_mutations()), ids=lambda v: str(v)[:20])
def test_malformed_model_loads_as_none(tmp_path, label, payload):
    path = tmp_path / "model.json"
    path.write_text(json.dumps(payload))
    assert ml.load(path) is None, label


def test_truncated_or_binary_file_loads_as_none(tmp_path):
    path = tmp_path / "model.json"
    path.write_text(json.dumps(_good())[:40])
    assert ml.load(path) is None
    path.write_bytes(b"\xff\xfe\x00")
    assert ml.load(path) is None


def test_a_well_formed_model_still_loads(tmp_path):
    path = tmp_path / "model.json"
    path.write_text(json.dumps(_good()))
    assert ml.load(path) is not None


def test_refresh_survives_a_malformed_model(tmp_path, monkeypatch):
    model_file = tmp_path / "model.json"
    model_file.write_text(json.dumps({**_good(), "scale": [0.0] * len(FEATURES)}))
    monkeypatch.setenv("QLURE_MODEL", str(model_file))
    monkeypatch.setenv("QLURE_SETTINGS", str(tmp_path / "settings.json"))
    monkeypatch.setenv("QLURE_DASHBOARD_PASSWORD", PASSWORD)
    client = TestClient(create_app(tmp_path / "q.db", tmp_path / "logs"))
    client.post("/login", data={"password": PASSWORD}, follow_redirects=False)
    r = client.post("/refresh", follow_redirects=False)
    assert r.status_code == 303
