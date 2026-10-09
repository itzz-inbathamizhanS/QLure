"""The docker decoy (port 2375) is known to settings and to the evaluator."""

from __future__ import annotations

from qlure import evaluate, settings


def test_settings_default_lists_docker_decoy():
    assert settings.APPROVED_PORTS["docker"] == [2375]
    assert settings.defaults()["decoys"]["docker"] == {"enabled": True, "port": 2375}


def test_settings_accepts_docker_and_rejects_other_port():
    ok = settings.Settings(decoys={"docker": settings.Decoy(port=2375)})
    assert ok.decoys["docker"].port == 2375
    try:
        settings.Settings(decoys={"docker": settings.Decoy(port=2376)})
    except ValueError as exc:
        assert "approved" in str(exc)
    else:
        raise AssertionError("port 2376 must be refused")


def test_evaluate_maps_docker_to_http_request():
    assert evaluate.INTERACTION_ACTION["docker"] == "http_request"
