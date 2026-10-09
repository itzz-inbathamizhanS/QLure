from helpers import finding_for, hits_of, run, web

from qlure.correlate.explain import explain
from qlure.correlate.model import Finding, RuleHit, Session


def test_r5_catches_double_and_single_encoded_traversal(read_events):
    web("198.51.100.60").get("/files?name=%252e%252e")
    web("198.51.100.61").get("/files?name=%2e%2e")
    result = run(read_events)
    assert "R5" in hits_of(finding_for(result, "198.51.100.60", "web"))
    assert "R5" in hits_of(finding_for(result, "198.51.100.61", "web"))


def test_explain_uses_configured_noteworthy_threshold(monkeypatch):
    from qlure.correlate import explain as mod

    hit = RuleHit("R1", "x", "recon", 20, "medium", (), "m", "t", ())
    finding = Finding(Session.__new__(Session), "a", 70, "Suspicious", [hit])
    base = {"verdicts": {"suspicious": 30, "noteworthy": 60}}
    monkeypatch.setattr(mod, "load_config", lambda: base)
    assert "Held at Suspicious" in explain(finding)
    monkeypatch.setattr(mod, "load_config", lambda: {"verdicts": {"noteworthy": 90}})
    assert "Held at Suspicious" not in explain(finding)
