from fastapi.testclient import TestClient

from decoys import honeytokens
from decoys.api.app import app
from tests.correlate.helpers import finding_for, hits_of, run

IP = "198.51.100.7"


def _client() -> TestClient:
    return TestClient(app, client=(IP, 40404))


def test_wrong_keys_score_brute_force(log_dir, read_events):
    client = _client()
    for i in range(5):
        assert client.get("/api/v1/users", headers={"X-API-Key": f"guess-{i}"}).status_code == 401
    attempts = [e for e in read_events("api") if e.action == "login_attempt"]
    assert len(attempts) == 5
    assert attempts[0].credential.username == "api-key"
    assert attempts[0].credential.password == "guess-0"
    finding = finding_for(run(read_events), IP, "api")
    assert "R3" in hits_of(finding)


def test_presented_key_is_capped(log_dir, read_events):
    _client().get("/api/v1/users", headers={"Authorization": "Bearer " + "k" * 5000})
    [attempt] = [e for e in read_events("api") if e.action == "login_attempt"]
    assert len(attempt.credential.password) <= 128


def test_json_sqli_body_is_logged_and_fires_r5(log_dir, read_events):
    client = _client()
    resp = client.post("/api/v1/users", content='{"id": "1\' OR 1=1--", "role":"admin"}')
    assert resp.status_code in (401, 405)
    http = read_events("api")[0]
    assert '"role":"admin"' in http.request["body_preview"]
    assert len(http.request["body_preview"]) <= 2048
    assert "R5" in hits_of(finding_for(run(read_events), IP, "api"))


def test_valid_honeytoken_still_works(log_dir, read_events):
    key = honeytokens.get("ht-api-001")["value"]
    assert _client().get("/api/v1/users", headers={"X-API-Key": key}).status_code == 200
    actions = [e.action for e in read_events("api")]
    assert actions == ["http_request", "api_call", "honeytoken_use"]


def test_missing_credentials_emit_no_login_attempt(log_dir, read_events):
    assert _client().get("/api/v1/users").status_code == 401
    assert "login_attempt" not in [e.action for e in read_events("api")]
